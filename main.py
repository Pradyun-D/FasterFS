"""
main.py — FasterFS Dashboard
FastAPI server: REST API + WebSocket
"""

import io
import os
import sys
import json
import time
import socket
import struct
import asyncio
import logging
import platform
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).parent))

from storage_backends import (
    LocalCSVBackend, MinIOBackend, FasterFSBackend,
    upload_chunks, chunks_exist, _load_df, MINIO_BUCKET, CACHE_DIR,
)
from benchmark import run_benchmark, run_throughput
from ebpf_cache import EBPFCache

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger("fasterfs")

# ── eBPF loader (optional, requires root) ─────────────────────────────────────
_ebpf_loader = None
if os.geteuid() == 0:
    try:
        from ebpf.loader import get_ebpf
        _ebpf_loader = get_ebpf()
        _ebpf_loader.load()
        log.info("eBPF programs loaded")
    except Exception as e:
        log.warning(f"eBPF load skipped: {e}")

_ebpf_cache = EBPFCache(_ebpf_loader)

# ── Global FasterFS backend (shared with ring buffer consumer) ─────────────────
# A single instance is kept alive so the ring buffer consumer can call
# write_hot_chunks() on the same object that benchmarks use.
_fasterfs_backend = FasterFSBackend()

if _ebpf_loader and getattr(_ebpf_loader, "loaded", False):
    try:
        from ebpf.loader import start_ringbuf_consumer

        def _on_hot_event(event: dict):
            """eBPF HOT_CHUNK event → write hot chunks to local disk cache."""
            _fasterfs_backend.write_hot_chunks()

        start_ringbuf_consumer(_on_hot_event)
        log.info("eBPF ring buffer consumer started — eBPF now drives caching")
    except Exception as e:
        log.warning(f"Ring buffer consumer skipped: {e}")

# ── Shared state ─────────────────────────────────────────────────────────────
_df: Optional[pd.DataFrame] = None
_ob_frames: list[dict] = []
_ob_idx   = 0
_ws_clients: list[WebSocket] = []

_benchmark_running = False
_benchmark_result: Optional[dict] = None

_throughput_running = False
_throughput_result: Optional[dict] = None

_distributed_bmark_running = False
_distributed_bmark_result: Optional[dict] = None

_sort_state: dict = {"status": "idle"}

# Sort constants
_SORT_RECORD_SIZE = 64   # 8-byte key + 56-byte value
_SORT_MB_PER_NODE = 50
_SORT_RECORDS = (_SORT_MB_PER_NODE * 1024 * 1024) // _SORT_RECORD_SIZE

# ── Cluster / node registry ───────────────────────────────────────────────────
# Each node registers itself here when it starts up.
# On the primary node, this accumulates all nodes.
# On client nodes, this just has their own entry.
_nodes: dict[str, dict] = {}  # node_id → {hostname, ip, port, ebpf, os, last_seen}
NODE_ID   = os.environ.get("NODE_ID", socket.gethostname())
NODE_PORT = int(os.environ.get("PORT", 8000))
PRIMARY   = os.environ.get("PRIMARY_URL", "")  # e.g. "http://192.168.1.10:8000"
IS_PRIMARY = not bool(PRIMARY)

def _my_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def _self_node_info() -> dict:
    return {
        "node_id":        NODE_ID,
        "hostname":       socket.gethostname(),
        "ip":             _my_ip(),
        "port":           NODE_PORT,
        "ebpf_enabled":   _ebpf_loader is not None and getattr(_ebpf_loader, "loaded", False),
        "os":             platform.system(),
        "last_seen":      time.time(),
        "is_primary":     IS_PRIMARY,
        "minio_external": f"http://{_my_ip()}:9000",
    }

def _register_with_primary():
    """Client nodes call this to register themselves with the primary node."""
    if IS_PRIMARY or not PRIMARY:
        return
    import httpx
    info = _self_node_info()
    for attempt in range(5):
        try:
            httpx.post(f"{PRIMARY}/api/nodes/register", json=info, timeout=5)
            log.info(f"Registered with primary at {PRIMARY}")
            return
        except Exception as e:
            log.warning(f"Register attempt {attempt+1} failed: {e}")
            time.sleep(2)

STATIC_DIR = Path(__file__).parent / "static"
FPGA_DIR   = Path("/home/swrj/Desktop/FasterFS/fpga-trading-systems")


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _df, _ob_frames
    # Register self
    _nodes[NODE_ID] = _self_node_info()

    log.info("Loading LOBSTER data...")
    _df = _load_df()
    _ob_frames = _build_ob_frames(_df)
    log.info(f"Loaded {len(_df)} rows → {len(_ob_frames)} OB frames")

    threading.Thread(target=_ensure_minio, daemon=True).start()
    threading.Thread(target=_register_with_primary, daemon=True).start()
    asyncio.create_task(_ws_broadcast_loop())
    asyncio.create_task(_heartbeat_loop())
    yield
    if _ebpf_loader:
        _ebpf_loader.unload()


def _build_ob_frames(df: pd.DataFrame, every: int = 30) -> list[dict]:
    frames = []
    for i in range(0, len(df), every):
        r = df.iloc[i]
        asks = [{"price": round(float(r.get(f"ask{l}", 0)), 2),
                 "size":  int(r.get(f"ask_sz{l}", 0))} for l in range(1, 6)]
        bids = [{"price": round(float(r.get(f"bid{l}", 0)), 2),
                 "size":  int(r.get(f"bid_sz{l}", 0))} for l in range(1, 6)]
        frames.append({
            "time":   round(float(r["time"]), 3),
            "mid":    round(float(r.get("mid", 0)), 4),
            "spread": round(float(r.get("spread", 0)), 4),
            "asks":   asks,
            "bids":   bids,
        })
    return frames


def _ensure_minio():
    if not chunks_exist():
        log.info("Uploading LOBSTER chunks to MinIO...")
        try:
            upload_chunks()
            log.info("Upload complete")
        except Exception as e:
            log.warning(f"MinIO upload failed: {e}")


# ── Heartbeat ─────────────────────────────────────────────────────────────────

async def _heartbeat_loop():
    """Client nodes ping primary every 5s; primary prunes stale nodes."""
    import httpx
    while True:
        await asyncio.sleep(5)
        _nodes[NODE_ID] = _self_node_info()  # refresh self
        if not IS_PRIMARY and PRIMARY:
            try:
                async with httpx.AsyncClient() as c:
                    await c.post(f"{PRIMARY}/api/nodes/register",
                                 json=_self_node_info(), timeout=3)
            except Exception:
                pass
        # Prune nodes not seen in 15s
        cutoff = time.time() - 15
        stale = [nid for nid, n in _nodes.items() if n.get("last_seen", 0) < cutoff]
        for nid in stale:
            if nid != NODE_ID:
                _nodes.pop(nid, None)


# ── WebSocket broadcast ───────────────────────────────────────────────────────

async def _ws_broadcast_loop():
    global _ob_idx
    while True:
        if _ws_clients and _ob_frames:
            frame  = _ob_frames[_ob_idx % len(_ob_frames)]
            _ob_idx += 1
            stats  = _ebpf_cache.get_stats()
            payload = json.dumps({
                "type": "tick",
                "ob":   frame,
                "ebpf": {
                    "reads":     stats["reads"],
                    "hot":       stats["hot_chunks"],
                    "lat_us":    stats["avg_lat_us"],
                    "hit_pct":   stats["cache_hit_pct"],
                    "tcp":       stats["connections_tuned"],
                    "sim":       stats.get("simulation", True),
                },
            })
            dead = []
            for ws in list(_ws_clients):
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                _ws_clients.remove(ws)
        await asyncio.sleep(0.15)


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="FasterFS", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def root():
    return (STATIC_DIR / "index.html").read_text()


@app.get("/kernel", response_class=HTMLResponse)
async def kernel_page():
    return (STATIC_DIR / "kernel.html").read_text()


@app.get("/demos", response_class=HTMLResponse)
async def demos_page():
    p = STATIC_DIR / "demos.html"
    return p.read_text() if p.exists() else HTMLResponse("<h1>Coming soon</h1>", 200)


@app.get("/fs", response_class=HTMLResponse)
async def fs_page():
    p = STATIC_DIR / "fs.html"
    return p.read_text() if p.exists() else HTMLResponse("<h1>Coming soon</h1>", 200)


@app.get("/notebook", response_class=HTMLResponse)
async def notebook_page():
    p = STATIC_DIR / "notebook.html"
    return p.read_text() if p.exists() else HTMLResponse("<h1>Coming soon</h1>", 200)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    _ws_clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


# ── API ───────────────────────────────────────────────────────────────────────

@app.get("/api/status")
async def api_status():
    minio_ok = False
    try:
        import boto3
        from botocore.config import Config
        c = boto3.client("s3", endpoint_url="http://127.0.0.1:9000",
                         aws_access_key_id="admin", aws_secret_access_key="adminpass123",
                         config=Config(connect_timeout=2, retries={"max_attempts": 1}))
        c.head_bucket(Bucket=MINIO_BUCKET)
        minio_ok = True
    except Exception:
        pass

    return {
        "minio":       minio_ok,
        "ebpf":        _ebpf_loader is not None and getattr(_ebpf_loader, "loaded", False),
        "simulation":  _ebpf_cache.get_stats().get("simulation", True),
        "data_rows":   len(_df) if _df is not None else 0,
        "chunks_ready": chunks_exist(),
    }


@app.get("/api/midprice")
async def api_midprice():
    if _df is None:
        return JSONResponse({"error": "loading"}, 503)
    every = 100
    sub = _df.iloc[::every]
    times, mids = [], []
    for _, r in sub.iterrows():
        t = float(r["time"])
        h, m, s = int(t // 3600), int((t % 3600) // 60), int(t % 60)
        times.append(f"{h:02d}:{m:02d}:{s:02d}")
        mids.append(round(float(r.get("mid", 0)), 2))
    return {"labels": times, "values": mids}


@app.get("/api/ebpf/stats")
async def api_ebpf_stats():
    return _ebpf_cache.get_stats()


@app.get("/api/ebpf/histogram")
async def api_ebpf_histogram():
    return _ebpf_cache.get_latency_histogram()


@app.get("/api/ebpf/tcp")
async def api_tcp():
    return _ebpf_cache.get_tcp_comparison()


@app.get("/api/reference/latency")
async def api_ref_latency():
    out = {}
    for name, fname in [("UDP Gateway (P14)", "project14_latency.csv"),
                        ("UART Gateway (P9)", "project9_latency.csv")]:
        try:
            df = pd.read_csv(FPGA_DIR / fname)
            v  = df.iloc[:, 0].dropna().values.astype(float)
            bins   = [500, 1000, 2000, 5000, 10000, 20000, 50000]
            labels = ["<500ns","500ns-1μs","1-2μs","2-5μs","5-10μs","10-20μs","20-50μs",">50μs"]
            counts = [0] * len(labels)
            for x in v:
                for i, b in enumerate(bins):
                    if x < b:
                        counts[i] += 1
                        break
                else:
                    counts[-1] += 1
            out[name] = {
                "p50": round(float(np.percentile(v, 50)), 1),
                "p95": round(float(np.percentile(v, 95)), 1),
                "p99": round(float(np.percentile(v, 99)), 1),
                "n":   len(v),
                "histogram": {"labels": labels, "counts": counts},
            }
        except Exception as e:
            out[name] = {"error": str(e)}
    return out


@app.post("/api/benchmark/run")
async def api_run_benchmark(request: Request):
    global _benchmark_running, _benchmark_result
    if _benchmark_running:
        return {"status": "already_running"}

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    start_chunk = int(body.get("start_chunk", 0))
    end_chunk   = body.get("end_chunk", None)
    if end_chunk is not None:
        end_chunk = int(end_chunk)

    _benchmark_running = True
    _benchmark_result  = None

    def _run():
        global _benchmark_result, _benchmark_running
        bench_fasterfs = FasterFSBackend()
        try:
            _benchmark_result = run_benchmark(
                LocalCSVBackend(), MinIOBackend(), bench_fasterfs,
                start_chunk=start_chunk, end_chunk=end_chunk,
            )
            # Merge benchmark access counts into global backend so /api/ebpf/chunks
            # shows real per-chunk hotness from the benchmark run
            for idx, cnt in bench_fasterfs._access_count.items():
                _fasterfs_backend._access_count[idx] = (
                    _fasterfs_backend._access_count.get(idx, 0) + cnt
                )
        except Exception as e:
            log.error(f"Benchmark error: {e}", exc_info=True)
            _benchmark_result = {"error": str(e)}
        finally:
            _benchmark_running = False

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "started"}


@app.get("/api/benchmark/result")
async def api_benchmark_result():
    if _benchmark_running:
        return {"status": "running"}
    if _benchmark_result is None:
        return {"status": "not_started"}
    return {"status": "complete", "result": _benchmark_result}


# ── Cluster API ───────────────────────────────────────────────────────────────

@app.post("/api/nodes/register")
async def api_nodes_register(info: dict):
    """Nodes call this to announce themselves to the primary."""
    info["last_seen"] = time.time()
    node_id = info.get("node_id", info.get("hostname", "unknown"))
    _nodes[node_id] = info
    log.info(f"Node registered: {node_id} @ {info.get('ip')}:{info.get('port')}")
    return {"ok": True}


@app.get("/api/cluster")
async def api_cluster():
    """Returns all known nodes and cluster-level stats."""
    nodes = list(_nodes.values())
    ebpf_stats = _ebpf_cache.get_stats()
    return {
        "nodes":        nodes,
        "node_count":   len(nodes),
        "ebpf_nodes":   sum(1 for n in nodes if n.get("ebpf_enabled")),
        "primary":      NODE_ID,
        "is_primary":   IS_PRIMARY,
        "global_ebpf":  ebpf_stats,
        "minio_endpoint": os.environ.get("MINIO_ENDPOINT", "http://127.0.0.1:9000"),
    }


@app.get("/api/ebpf/chunks")
async def api_ebpf_chunks():
    """
    Returns per-chunk hotness for kernel visualization.
    Uses FasterFSBackend._access_count (per-chunk-index, accurate) since the BPF
    chunk_hotness map keys are per-TCP-connection and cannot be mapped to chunk indices
    without HTTP header parsing in eBPF (known limitation).
    """
    n = 92
    access = _fasterfs_backend._access_count
    cache_dir = Path("/tmp/fasterfs_cache")
    ebpf_live = bool(_ebpf_loader and getattr(_ebpf_loader, "loaded", False))
    result = []
    for i in range(n):
        cached = (cache_dir / f"chunk_{i:04d}.pkl").exists()
        result.append({
            "id":     i,
            "count":  access.get(i, 0),
            "cached": cached,
        })
    return {"chunks": result, "simulation": not ebpf_live}


@app.get("/api/fs/files")
async def api_fs_files():
    """Lists MinIO objects and local cache state per node."""
    minio_objects = []
    try:
        import boto3
        from botocore.config import Config
        c = boto3.client("s3", endpoint_url="http://127.0.0.1:9000",
                         aws_access_key_id="admin", aws_secret_access_key="adminpass123",
                         config=Config(connect_timeout=2, retries={"max_attempts": 1}))
        r = c.list_objects_v2(Bucket=MINIO_BUCKET, Prefix="lobster/", MaxKeys=200)
        for obj in r.get("Contents", []):
            minio_objects.append({
                "key": obj["Key"],
                "size": obj["Size"],
                "last_modified": obj["LastModified"].isoformat(),
            })
    except Exception as e:
        minio_objects = [{"error": str(e)}]

    # Local cache files
    cached = []
    for p in sorted(CACHE_DIR.glob("chunk_*.pkl")):
        cached.append({"name": p.name, "size": p.stat().st_size})

    return {
        "node_id": NODE_ID,
        "minio_objects": minio_objects,
        "minio_count": len(minio_objects),
        "local_cache": cached,
        "cached_count": len(cached),
    }


# ── Throughput API (Demo B per-node) ─────────────────────────────────────────

@app.post("/api/benchmark/throughput")
async def api_run_throughput(request: Request):
    """
    Demo B per-node benchmark: sustained MinIO reads, no cache.
    Body: {start_chunk, end_chunk, target_mb}
    """
    global _throughput_running, _throughput_result
    if _throughput_running:
        return {"status": "already_running"}

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    start_chunk = int(body.get("start_chunk", 0))
    end_chunk   = body.get("end_chunk", None)
    if end_chunk is not None:
        end_chunk = int(end_chunk)
    target_mb = float(body.get("target_mb", 600))

    _throughput_running = True
    _throughput_result  = None

    def _run():
        global _throughput_result, _throughput_running
        try:
            _throughput_result = run_throughput(
                MinIOBackend(),
                start_chunk=start_chunk,
                end_chunk=end_chunk,
                target_mb=target_mb,
            )
        except Exception as e:
            log.error(f"Throughput error: {e}", exc_info=True)
            _throughput_result = {"error": str(e)}
        finally:
            _throughput_running = False

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "started"}


@app.get("/api/benchmark/throughput/result")
async def api_throughput_result():
    if _throughput_running:
        return {"status": "running"}
    if _throughput_result is None:
        return {"status": "not_started"}
    return {"status": "complete", "result": _throughput_result}


# ── Distributed Benchmark API (Demo B coordinator) ────────────────────────────

def _chunk_assignments(nodes: list, total: int = 92) -> list:
    """Assign non-overlapping chunk ranges to nodes."""
    n = len(nodes)
    assignments = []
    for i, node in enumerate(nodes):
        start = (i * total) // n
        end   = ((i + 1) * total) // n
        assignments.append({"node": node, "start": start, "end": end})
    return assignments


def _node_base_url(node: dict) -> str:
    return f"http://{node['ip']}:{node['port']}"


@app.post("/api/benchmark/distributed")
async def api_distributed_benchmark(node_count: int = 0, target_mb: float = 600):
    """
    Demo B coordinator: fire /api/benchmark/throughput on each node with its
    proportional share of target_mb. Measure wall-clock from start to all done.

    Each node reads its chunk partition from its LOCAL MinIO (no cache) repeatedly
    until it has read target_mb × (its_chunks / 92) MB. All nodes run in parallel.
    Wall-clock time should scale as 1/N with N nodes.
    """
    global _distributed_bmark_running, _distributed_bmark_result
    if _distributed_bmark_running:
        return {"status": "already_running"}

    nodes = list(_nodes.values())
    if node_count > 0:
        nodes = nodes[:node_count]
    if not nodes:
        return {"error": "no_nodes"}

    assignments = _chunk_assignments(nodes)
    total_chunks = 92
    _distributed_bmark_running = True
    _distributed_bmark_result  = None

    def _run():
        global _distributed_bmark_result, _distributed_bmark_running
        import httpx
        try:
            t_wall = time.perf_counter()

            # Fire throughput benchmark on each node with proportional target
            for a in assignments:
                base  = _node_base_url(a["node"])
                n_chunks = a["end"] - a["start"]
                node_target_mb = target_mb * (n_chunks / total_chunks)
                try:
                    httpx.post(f"{base}/api/benchmark/throughput",
                               json={"start_chunk": a["start"],
                                     "end_chunk":   a["end"],
                                     "target_mb":   round(node_target_mb, 1)},
                               timeout=10)
                except Exception as e:
                    log.warning(f"Could not start throughput on {a['node']['node_id']}: {e}")

            # Poll until all nodes report complete (max 300s)
            per_node: dict[str, dict] = {}
            pending  = {a["node"]["node_id"]: a for a in assignments}
            deadline = time.time() + 300
            while pending and time.time() < deadline:
                time.sleep(0.5)
                for nid in list(pending):
                    a    = pending[nid]
                    base = _node_base_url(a["node"])
                    try:
                        r = httpx.get(f"{base}/api/benchmark/throughput/result", timeout=5)
                        d = r.json()
                        if d.get("status") == "complete":
                            per_node[nid] = d.get("result", {})
                            del pending[nid]
                    except Exception:
                        pass

            wall_s = time.perf_counter() - t_wall
            # Aggregate: total MB read across all nodes / wall-clock time
            total_mb = sum(v.get("bytes_mb", 0) for v in per_node.values())
            agg_mbps = round(total_mb / wall_s, 2) if wall_s > 0 else 0

            _distributed_bmark_result = {
                "status":               "complete",
                "wall_clock_s":         round(wall_s, 2),
                "aggregate_mbps":       agg_mbps,
                "total_mb":             round(total_mb, 1),
                "node_count":           len(nodes),
                "per_node":             per_node,
                "assignments": [
                    {"node_id":    a["node"]["node_id"],
                     "start_chunk": a["start"], "end_chunk": a["end"]}
                    for a in assignments
                ],
            }
        except Exception as e:
            log.error(f"Distributed benchmark error: {e}", exc_info=True)
            _distributed_bmark_result = {"status": "error", "error": str(e)}
        finally:
            _distributed_bmark_running = False

    threading.Thread(target=_run, daemon=True).start()
    return {
        "status":     "started",
        "node_count": len(nodes),
        "target_mb":  target_mb,
        "assignments": [
            {"node_id": a["node"]["node_id"],
             "start":   a["start"], "end": a["end"],
             "target_mb": round(target_mb * (a["end"] - a["start"]) / total_chunks, 1)}
            for a in assignments
        ],
    }


@app.get("/api/benchmark/distributed/result")
async def api_distributed_benchmark_result():
    if _distributed_bmark_running:
        return {"status": "running"}
    if _distributed_bmark_result is None:
        return {"status": "not_started"}
    return _distributed_bmark_result


# ── Sort API ──────────────────────────────────────────────────────────────────

def _minio_client(endpoint: Optional[str] = None):
    import boto3
    from botocore.config import Config
    ep = endpoint or os.environ.get("MINIO_ENDPOINT", "http://127.0.0.1:9000")
    return boto3.client(
        "s3", endpoint_url=ep,
        aws_access_key_id="admin", aws_secret_access_key="adminpass123",
        config=Config(connect_timeout=10, read_timeout=120, retries={"max_attempts": 2}),
    )


def _ensure_bucket(client):
    try:
        client.head_bucket(Bucket=MINIO_BUCKET)
    except Exception:
        client.create_bucket(Bucket=MINIO_BUCKET)


@app.post("/api/sort/generate")
async def api_sort_generate():
    """Generate _SORT_MB_PER_NODE MB of random sortable records on this node."""
    def _gen():
        t0 = time.perf_counter()
        n = _SORT_RECORDS
        keys = np.random.randint(0, 256, size=(n, 8), dtype=np.uint8)
        vals = np.random.randint(0, 256, size=(n, 56), dtype=np.uint8)
        records = np.hstack([keys, vals])   # shape (n, 64)
        data = records.tobytes()

        c = _minio_client()
        _ensure_bucket(c)
        c.put_object(Bucket=MINIO_BUCKET,
                     Key=f"sort/node_{NODE_ID}/data.bin",
                     Body=data, ContentLength=len(data))
        elapsed = time.perf_counter() - t0
        log.info(f"sort/generate: {n} records ({_SORT_MB_PER_NODE}MB) in {elapsed:.2f}s")
        return {"ok": True, "records": n, "mb": _SORT_MB_PER_NODE, "time_s": round(elapsed, 2)}

    import concurrent.futures
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, _gen)
    return result


@app.post("/api/sort/sort_partition")
async def api_sort_sort_partition():
    """Download this node's partition from local MinIO, sort by key, upload sorted result."""
    def _sort():
        t0 = time.perf_counter()
        c = _minio_client()
        obj = c.get_object(Bucket=MINIO_BUCKET, Key=f"sort/partition_{NODE_ID}.bin")
        data = obj["Body"].read()

        records = np.frombuffer(data, dtype=np.uint8).reshape(-1, 64)
        n = len(records)

        # Sort by first 8 bytes (key) lexicographically
        keys = records[:, :8].copy()
        idx = np.lexsort(keys.T[::-1])
        sorted_records = records[idx]
        sorted_data = sorted_records.tobytes()

        c.put_object(Bucket=MINIO_BUCKET,
                     Key=f"sort/sorted_{NODE_ID}.bin",
                     Body=sorted_data, ContentLength=len(sorted_data))

        elapsed = time.perf_counter() - t0
        log.info(f"sort/sort_partition: sorted {n} records in {elapsed:.2f}s")
        return {"ok": True, "records": n, "time_s": round(elapsed, 2)}

    import concurrent.futures
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, _sort)
    return result


@app.post("/api/sort/run")
async def api_sort_run():
    """Primary coordinator: orchestrate generate → partition → sort across all nodes."""
    global _sort_state
    if _sort_state.get("status") == "running":
        return {"status": "already_running"}

    nodes = list(_nodes.values())
    if not nodes:
        return {"error": "no_nodes"}

    _sort_state = {
        "status":     "running",
        "node_count": len(nodes),
        "mb_sorted":  len(nodes) * _SORT_MB_PER_NODE,
        "phases": {
            "gen":   {"running": False, "done": False, "time_s": None},
            "part":  {"running": False, "done": False, "time_s": None},
            "sort":  {"running": False, "done": False, "time_s": None},
        },
        "total_s": None,
    }

    def _coordinator():
        global _sort_state
        import httpx
        from concurrent.futures import ThreadPoolExecutor as TPE

        def _post_node(url):
            try:
                return httpx.post(url, timeout=120).json()
            except Exception as e:
                log.warning(f"POST {url} failed: {e}")
                return {"error": str(e)}

        def _update_phase(name, **kw):
            _sort_state["phases"][name].update(kw)

        try:
            t_total = time.perf_counter()

            # ── Phase 1: Generate (truly parallel across all nodes) ───────────
            _update_phase("gen", running=True)
            t0 = time.perf_counter()

            gen_urls = [f"{_node_base_url(n)}/api/sort/generate" for n in nodes]
            with TPE(max_workers=len(nodes)) as pool:
                list(pool.map(_post_node, gen_urls))

            _update_phase("gen", running=False, done=True,
                          time_s=round(time.perf_counter() - t0, 2))

            # ── Phase 2: Partition (on primary) ───────────────────────────────
            _update_phase("part", running=True)
            t0 = time.perf_counter()
            n_nodes = len(nodes)

            # Download data from each node's MinIO and partition
            all_records = []
            for node in nodes:
                minio_ep = node.get("minio_external", f"http://{node['ip']}:9000")
                try:
                    c = _minio_client(minio_ep)
                    obj = c.get_object(Bucket=MINIO_BUCKET,
                                       Key=f"sort/node_{node['node_id']}/data.bin")
                    data = obj["Body"].read()
                    recs = np.frombuffer(data, dtype=np.uint8).reshape(-1, 64)
                    all_records.append(recs)
                except Exception as e:
                    log.warning(f"Could not download data from {node['node_id']}: {e}")

            if all_records:
                all_recs = np.concatenate(all_records, axis=0)
                total_n = len(all_recs)
                # Partition by first byte of key
                bucket_size = 256 / n_nodes
                partitions = [[] for _ in range(n_nodes)]
                first_bytes = all_recs[:, 0].astype(int)
                for i, node in enumerate(nodes):
                    lo = int(i * bucket_size)
                    hi = int((i + 1) * bucket_size) if i < n_nodes - 1 else 256
                    mask = (first_bytes >= lo) & (first_bytes < hi)
                    partitions[i] = all_recs[mask]

                # Upload partition to each node's MinIO
                for i, node in enumerate(nodes):
                    minio_ep = node.get("minio_external", f"http://{node['ip']}:9000")
                    try:
                        c = _minio_client(minio_ep)
                        part_data = partitions[i].tobytes() if len(partitions[i]) else b'\x00' * 64
                        c.put_object(Bucket=MINIO_BUCKET,
                                     Key=f"sort/partition_{node['node_id']}.bin",
                                     Body=part_data, ContentLength=len(part_data))
                    except Exception as e:
                        log.warning(f"Could not upload partition to {node['node_id']}: {e}")

            _update_phase("part", running=False, done=True,
                          time_s=round(time.perf_counter() - t0, 2))

            # ── Phase 3: Sort (truly parallel across all nodes) ───────────────
            _update_phase("sort", running=True)
            t0 = time.perf_counter()

            sort_urls = [f"{_node_base_url(n)}/api/sort/sort_partition" for n in nodes]
            with TPE(max_workers=len(nodes)) as pool:
                list(pool.map(_post_node, sort_urls))

            _update_phase("sort", running=False, done=True,
                          time_s=round(time.perf_counter() - t0, 2))

            total_s = round(time.perf_counter() - t_total, 2)
            _sort_state.update({"status": "complete", "total_s": total_s})
            log.info(f"Distributed sort complete in {total_s}s across {n_nodes} nodes")

        except Exception as e:
            log.error(f"Sort coordinator error: {e}", exc_info=True)
            _sort_state["status"] = "error"
            _sort_state["error"] = str(e)

    threading.Thread(target=_coordinator, daemon=True).start()
    return {"status": "started", "node_count": len(nodes)}


@app.get("/api/sort/result")
async def api_sort_result():
    return _sort_state


# ── Node bootstrap API ────────────────────────────────────────────────────────

@app.post("/api/node/sync_chunks")
async def api_sync_chunks(source_url: str = "", start_chunk: int = 0, end_chunk: int = 92):
    """
    Download chunks [start_chunk, end_chunk) from source_url MinIO and
    upload them to this node's local MinIO. Used by client nodes to bootstrap
    their local MinIO with their assigned chunk partition (Option 2 setup).
    """
    def _sync():
        import boto3
        from botocore.config import Config
        src_ep = source_url or os.environ.get("MINIO_ENDPOINT", "http://127.0.0.1:9000")
        src = boto3.client("s3", endpoint_url=src_ep,
                           aws_access_key_id="admin", aws_secret_access_key="adminpass123",
                           config=Config(connect_timeout=10, read_timeout=120,
                                         retries={"max_attempts": 2}))
        dst = _minio_client()
        _ensure_bucket(dst)

        synced, failed = 0, 0
        for i in range(start_chunk, end_chunk):
            key = f"lobster/chunk_{i:04d}.pkl"
            try:
                obj = src.get_object(Bucket=MINIO_BUCKET, Key=key)
                data = obj["Body"].read()
                dst.put_object(Bucket=MINIO_BUCKET, Key=key,
                               Body=data, ContentLength=len(data))
                synced += 1
                if synced % 10 == 0:
                    log.info(f"sync_chunks: {synced}/{end_chunk - start_chunk}")
            except Exception as e:
                log.warning(f"sync_chunks: failed {key}: {e}")
                failed += 1

        return {"ok": True, "synced": synced, "failed": failed,
                "range": {"start": start_chunk, "end": end_chunk}}

    import concurrent.futures
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, _sync)
    return result


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port,
                reload=False, log_level="info")
