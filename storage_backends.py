"""
storage_backends.py — Storage backends for FasterFS performance demo.

Three backends with identical read_chunk(idx) interface:
  LocalCSV  — direct pandas read from disk (baseline)
  MinIO     — S3 GET via boto3, no caching
  FasterFS  — eBPF-informed hot cache, falls back to MinIO
"""

import io
import os
import time
import pickle
import logging
from pathlib import Path
from typing import Optional

import boto3
import pandas as pd
from botocore.config import Config
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)

MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "http://127.0.0.1:9000")
MINIO_ACCESS   = os.environ.get("MINIO_ACCESS", "admin")
MINIO_SECRET   = os.environ.get("MINIO_SECRET", "adminpass123")
MINIO_BUCKET   = os.environ.get("MINIO_BUCKET", "fasterfs")
CHUNK_ROWS     = 1000
HOT_THRESHOLD  = 2

# Platform-aware cache dir: /tmp/fasterfs_cache on Linux/macOS
if os.name == 'nt':
    CACHE_DIR = Path(os.environ.get("TEMP", "C:\\temp")) / "fasterfs_cache"
else:
    CACHE_DIR = Path("/tmp/fasterfs_cache")

# Platform-aware LOBSTER paths — use file location, not home(), so root can run this
_base_dir = Path(__file__).parent.parent
LOBSTER_MSG = _base_dir / "LOBSTER_SampleFile_AAPL_2012-06-21_50" / "AAPL_2012-06-21_34200000_37800000_message_50.csv"
LOBSTER_OB  = _base_dir / "LOBSTER_SampleFile_AAPL_2012-06-21_50" / "AAPL_2012-06-21_34200000_37800000_orderbook_50.csv"


def _s3():
    return boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS,
        aws_secret_access_key=MINIO_SECRET,
        config=Config(connect_timeout=5, read_timeout=30,
                      retries={"max_attempts": 2}),
    )


def chunk_key(idx: int) -> str:
    return f"lobster/chunk_{idx:04d}.pkl"


# ── Upload ────────────────────────────────────────────────────────────────────

_df_cache: Optional[pd.DataFrame] = None

def _load_df() -> pd.DataFrame:
    global _df_cache
    if _df_cache is not None:
        return _df_cache
    msg = pd.read_csv(LOBSTER_MSG, header=None,
                      names=["time","type","order_id","size","price","direction"])
    msg["mid"] = msg["price"] * 1e-4  # approximate mid from message prices

    # Load orderbook for proper bid/ask
    ob_cols = []
    for i in range(1, 6):   # first 5 levels only for size
        ob_cols += [f"ask{i}", f"ask_sz{i}", f"bid{i}", f"bid_sz{i}"]
    # full 50-level file has 200 cols, we read all then take first 20
    ob = pd.read_csv(LOBSTER_OB, header=None,
                     usecols=range(20), names=ob_cols)
    ob[["ask1","ask2","ask3","ask4","ask5"]] *= 1e-4
    ob[["bid1","bid2","bid3","bid4","bid5"]] *= 1e-4
    ob["mid"] = (ob["ask1"] + ob["bid1"]) / 2
    ob["spread"] = ob["ask1"] - ob["bid1"]

    df = pd.concat([msg[["time","type","size","direction"]], ob], axis=1)
    _df_cache = df
    return df


def upload_chunks(progress_cb=None) -> int:
    """Split LOBSTER data into chunks and upload to MinIO."""
    client = _s3()
    try:
        client.head_bucket(Bucket=MINIO_BUCKET)
    except ClientError:
        client.create_bucket(Bucket=MINIO_BUCKET)

    df = _load_df()
    n = len(df)
    total = (n + CHUNK_ROWS - 1) // CHUNK_ROWS
    uploaded = 0

    for i in range(0, n, CHUNK_ROWS):
        chunk = df.iloc[i:i + CHUNK_ROWS]
        key   = chunk_key(i // CHUNK_ROWS)
        data  = pickle.dumps(chunk, protocol=4)
        client.put_object(Bucket=MINIO_BUCKET, Key=key,
                          Body=data, ContentLength=len(data))
        uploaded += 1
        if progress_cb:
            progress_cb(uploaded, total)

    log.info(f"Uploaded {uploaded} chunks to MinIO bucket '{MINIO_BUCKET}'")
    return uploaded


def chunks_exist() -> bool:
    try:
        r = _s3().list_objects_v2(Bucket=MINIO_BUCKET, Prefix="lobster/", MaxKeys=1)
        return r.get("KeyCount", 0) > 0
    except Exception:
        return False


def count_chunks() -> int:
    try:
        r = _s3().list_objects_v2(Bucket=MINIO_BUCKET, Prefix="lobster/", MaxKeys=1000)
        return r.get("KeyCount", 0)
    except Exception:
        return 0


# ── Backends ──────────────────────────────────────────────────────────────────

class LocalCSVBackend:
    name = "local_csv"

    def __init__(self):
        self._df = None

    def _ensure(self):
        if self._df is None:
            self._df = _load_df()

    def read_chunk(self, idx: int) -> Optional[pd.DataFrame]:
        self._ensure()
        s = idx * CHUNK_ROWS
        return self._df.iloc[s:s + CHUNK_ROWS].copy()

    def num_chunks(self) -> int:
        self._ensure()
        return (len(self._df) + CHUNK_ROWS - 1) // CHUNK_ROWS


class MinIOBackend:
    name = "minio"

    def __init__(self):
        self._client = _s3()

    def read_chunk(self, idx: int) -> Optional[pd.DataFrame]:
        key = chunk_key(idx)
        try:
            resp = self._client.get_object(Bucket=MINIO_BUCKET, Key=key)
            return pickle.loads(resp["Body"].read())
        except Exception as e:
            log.warning(f"MinIO read {key}: {e}")
            return None

    def num_chunks(self) -> int:
        return count_chunks()


class FasterFSBackend:
    """
    eBPF-informed hot cache.
    Mirrors the kernel chunk_hotness map in Python: once access_count > HOT_THRESHOLD,
    copies chunk to local disk. Subsequent reads bypass MinIO entirely.
    When real eBPF is running, the kernel detects the same patterns independently.
    """
    name = "fasterfs"

    def __init__(self):
        self._minio = MinIOBackend()
        self._access_count: dict[int, int] = {}
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, idx: int) -> Path:
        return CACHE_DIR / f"chunk_{idx:04d}.pkl"

    def read_chunk(self, idx: int) -> Optional[pd.DataFrame]:
        self._access_count[idx] = self._access_count.get(idx, 0) + 1
        count = self._access_count[idx]

        cp = self._cache_path(idx)
        if cp.exists():
            with open(cp, "rb") as f:
                return pickle.load(f)

        df = self._minio.read_chunk(idx)
        if df is not None and count >= HOT_THRESHOLD:
            try:
                with open(cp, "wb") as f:
                    pickle.dump(df, f, protocol=4)
            except Exception:
                pass
        return df

    def write_hot_chunks(self):
        """
        Called by the eBPF ring buffer consumer when a HOT_CHUNK event arrives.
        eBPF signals that something crossed the hotness threshold; Python identifies
        the specific chunk indices and writes uncached ones to local disk.
        """
        for chunk_idx, count in list(self._access_count.items()):
            if count >= HOT_THRESHOLD:
                cp = self._cache_path(chunk_idx)
                if not cp.exists():
                    df = self._minio.read_chunk(chunk_idx)
                    if df is not None:
                        try:
                            with open(cp, "wb") as f:
                                pickle.dump(df, f, protocol=4)
                            log.info(f"[eBPF trigger] cached chunk {chunk_idx}")
                        except Exception as e:
                            log.warning(f"[eBPF trigger] cache write failed chunk {chunk_idx}: {e}")

    def num_chunks(self) -> int:
        return self._minio.num_chunks()

    def cache_stats(self) -> dict:
        n = self._minio.num_chunks()
        cached = sum(1 for i in range(n) if self._cache_path(i).exists())
        total_reads = sum(self._access_count.values())
        cache_reads = sum(max(0, v - HOT_THRESHOLD + 1)
                         for v in self._access_count.values() if v > HOT_THRESHOLD)
        return {
            "total_chunks": n,
            "cached_chunks": cached,
            "cache_hit_pct": round(cache_reads / total_reads * 100, 1) if total_reads > 0 else 0.0,
        }

    def clear_cache(self):
        for p in CACHE_DIR.glob("chunk_*.pkl"):
            p.unlink(missing_ok=True)
        self._access_count.clear()
