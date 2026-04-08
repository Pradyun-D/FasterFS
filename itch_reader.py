"""
itch_reader.py — Load LOBSTER AAPL CSV data, parse order book, provide
chunked access for benchmark + live WebSocket replay.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Generator

DATA_DIR = Path("/home/swrj/Desktop/FasterFS/LOBSTER_SampleFile_AAPL_2012-06-21_50")
MSG_FILE = DATA_DIR / "AAPL_2012-06-21_34200000_37800000_message_50.csv"
OB_FILE  = DATA_DIR / "AAPL_2012-06-21_34200000_37800000_orderbook_50.csv"

PRICE_UNIT = 1e-4   # prices are in $0.0001 units
CHUNK_ROWS = 1000   # rows per MinIO object


# ─── Load ─────────────────────────────────────────────────────────────────────

def load_messages() -> pd.DataFrame:
    df = pd.read_csv(MSG_FILE, header=None,
                     names=["time", "type", "order_id", "size", "price", "direction"])
    df["price_usd"] = df["price"] * PRICE_UNIT
    return df


def load_orderbook() -> pd.DataFrame:
    # 50 levels × (ask_price, ask_size, bid_price, bid_size) = 200 columns
    cols = []
    for lvl in range(1, 51):
        cols += [f"ask{lvl}", f"ask_sz{lvl}", f"bid{lvl}", f"bid_sz{lvl}"]
    df = pd.read_csv(OB_FILE, header=None, names=cols)
    # Convert price columns to USD
    for lvl in range(1, 51):
        df[f"ask{lvl}"] = df[f"ask{lvl}"] * PRICE_UNIT
        df[f"bid{lvl}"] = df[f"bid{lvl}"] * PRICE_UNIT
    return df


def load_combined() -> pd.DataFrame:
    """Merge messages + orderbook into one frame indexed by time."""
    msgs = load_messages()
    ob   = load_orderbook()
    df   = pd.concat([msgs, ob], axis=1)
    df["mid"] = (df["ask1"] + df["bid1"]) / 2
    df["spread"] = df["ask1"] - df["bid1"]
    return df


# ─── Chunking ─────────────────────────────────────────────────────────────────

def get_chunks(df: pd.DataFrame, chunk_size: int = CHUNK_ROWS) -> list[pd.DataFrame]:
    """Split DataFrame into fixed-size chunks for MinIO upload."""
    n = len(df)
    return [df.iloc[i:i + chunk_size].copy() for i in range(0, n, chunk_size)]


def chunk_key(idx: int) -> str:
    return f"lobster/aapl_chunk_{idx:04d}.csv"


def num_chunks(df: pd.DataFrame, chunk_size: int = CHUNK_ROWS) -> int:
    return (len(df) + chunk_size - 1) // chunk_size


# ─── Order book snapshots (for WebSocket replay) ──────────────────────────────

def order_book_snapshots(df: pd.DataFrame, every_n: int = 50) -> Generator:
    """Yield order book state every `every_n` rows for WebSocket streaming."""
    for i in range(0, len(df), every_n):
        row = df.iloc[i]
        bids = []
        asks = []
        for lvl in range(1, 6):
            asks.append({
                "price": round(float(row[f"ask{lvl}"]), 2),
                "size":  int(row[f"ask_sz{lvl}"])
            })
            bids.append({
                "price": round(float(row[f"bid{lvl}"]), 2),
                "size":  int(row[f"bid_sz{lvl}"])
            })
        yield {
            "time":   round(float(row["time"]), 3),
            "mid":    round(float(row["mid"]), 4),
            "spread": round(float(row["spread"]), 4),
            "asks":   asks,   # sorted ask1 (tightest) first
            "bids":   bids,   # sorted bid1 (tightest) first
            "type":   int(row["type"]),
        }


# ─── Mid-price series (for chart) ────────────────────────────────────────────

def mid_price_series(df: pd.DataFrame, downsample: int = 200) -> dict:
    """Return time + mid arrays downsampled for the price chart."""
    sampled = df.iloc[::downsample]
    # Convert time from seconds-after-midnight to HH:MM:SS
    times = []
    for t in sampled["time"]:
        h = int(t // 3600)
        m = int((t % 3600) // 60)
        s = int(t % 60)
        times.append(f"{h:02d}:{m:02d}:{s:02d}")
    return {
        "labels": times,
        "values": [round(v, 4) for v in sampled["mid"].tolist()],
        "min":    round(float(sampled["mid"].min()), 2),
        "max":    round(float(sampled["mid"].max()), 2),
    }


# ─── Lazy singleton ──────────────────────────────────────────────────────────

_df: pd.DataFrame | None = None

def get_df() -> pd.DataFrame:
    global _df
    if _df is None:
        _df = load_combined()
    return _df
