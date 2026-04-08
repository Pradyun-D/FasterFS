"""
benchmark.py — FasterFS storage performance benchmark.

Two benchmark modes:

1. run_benchmark() — Demo A (caching speedup)
   Shows cold → warm → hot cache warming. 5 passes across all backends.
   Measures latency reduction from eBPF-informed local disk cache.

2. run_throughput() — Demo B (node scaling / bandwidth aggregation)
   Reads chunks from MinIO repeatedly until target_mb is reached.
   No cache involved — measures raw distributed read bandwidth.
   With N nodes each reading 1/N of the data in parallel, wall-clock
   time should scale as 1/N (linear throughput scaling).

Supports chunk_range (start_chunk, end_chunk) so each node in a
distributed benchmark reads only its assigned partition.
"""

import time
import logging
import numpy as np
from typing import Callable, Optional

log = logging.getLogger(__name__)

TOTAL_CHUNKS = 92


def _run_pass(backend, label: str,
              start_chunk: int = 0,
              end_chunk: Optional[int] = None,
              progress_cb: Optional[Callable] = None) -> dict:
    """Read a range of chunks once, record timing. Returns latency stats."""
    n_total = backend.num_chunks()
    if end_chunk is None:
        end_chunk = n_total
    end_chunk = min(end_chunk, n_total)
    chunks = list(range(start_chunk, end_chunk))

    if not chunks:
        return {"error": "empty_range", "backend": backend.name,
                "start_chunk": start_chunk, "end_chunk": end_chunk}

    times_ms = []
    bytes_read = 0

    t_total_start = time.perf_counter()
    for pos, i in enumerate(chunks):
        t0 = time.perf_counter()
        chunk = backend.read_chunk(i)
        t1 = time.perf_counter()
        if chunk is not None:
            times_ms.append((t1 - t0) * 1000)
            bytes_read += chunk.memory_usage(deep=True).sum()
        if progress_cb:
            progress_cb(pos + 1, len(chunks))

    total_ms = (time.perf_counter() - t_total_start) * 1000

    if not times_ms:
        return {"error": "all_reads_failed", "backend": backend.name}

    arr = np.array(times_ms)
    return {
        "label":           label,
        "backend":         backend.name,
        "n_chunks":        len(times_ms),
        "start_chunk":     start_chunk,
        "end_chunk":       end_chunk,
        "total_ms":        round(total_ms, 1),
        "avg_ms":          round(float(arr.mean()), 3),
        "p50_ms":          round(float(np.percentile(arr, 50)), 3),
        "p95_ms":          round(float(np.percentile(arr, 95)), 3),
        "p99_ms":          round(float(np.percentile(arr, 99)), 3),
        "min_ms":          round(float(arr.min()), 3),
        "max_ms":          round(float(arr.max()), 3),
        "throughput_mbps": round(bytes_read / total_ms / 1000, 2) if total_ms > 0 else 0,
    }


def run_throughput(minio_backend,
                   start_chunk: int = 0,
                   end_chunk: Optional[int] = None,
                   target_mb: float = 600) -> dict:
    """
    Demo B benchmark: sustained read throughput from MinIO (no cache).

    Reads the assigned chunk partition from MinIO repeatedly until
    target_mb bytes have been read. Reports wall-clock time and MB/s.

    With N nodes each given a proportional target_mb (= total_mb × chunks/92),
    all running in parallel, wall-clock time scales as 1/N.
    """
    n_total = minio_backend.num_chunks()
    if end_chunk is None:
        end_chunk = n_total
    end_chunk = min(end_chunk, n_total)
    chunks = list(range(start_chunk, end_chunk))

    if not chunks:
        return {"error": "empty_range", "start_chunk": start_chunk, "end_chunk": end_chunk}

    target_bytes = target_mb * 1024 * 1024
    bytes_read = 0
    n_passes = 0

    t_start = time.perf_counter()
    while bytes_read < target_bytes:
        for i in chunks:
            chunk = minio_backend.read_chunk(i)
            if chunk is not None:
                bytes_read += chunk.memory_usage(deep=True).sum()
        n_passes += 1

    duration_s = time.perf_counter() - t_start
    bytes_mb = bytes_read / 1024 / 1024

    log.info(f"Throughput: {bytes_mb:.1f} MB in {duration_s:.2f}s = "
             f"{bytes_mb/duration_s:.1f} MB/s "
             f"(chunks {start_chunk}–{end_chunk}, {n_passes} passes)")

    return {
        "duration_s":      round(duration_s, 2),
        "bytes_mb":        round(bytes_mb, 1),
        "throughput_mbps": round(bytes_mb / duration_s, 2),
        "n_passes":        n_passes,
        "chunk_range":     {"start": start_chunk, "end": end_chunk, "count": len(chunks)},
    }


def run_benchmark(local_backend, minio_backend, fasterfs_backend,
                  start_chunk: int = 0,
                  end_chunk: Optional[int] = None,
                  progress_cb: Optional[Callable] = None) -> dict:
    """
    Full benchmark over a chunk range:
      - 1 pass: Local CSV    (disk baseline, no network)
      - 1 pass: Plain MinIO  (raw network cost)
      - 3 passes: FasterFS   (cold → warm → hot cache)

    start_chunk / end_chunk let distributed benchmarks assign each node
    a non-overlapping slice of the 92 chunks.
    """
    n_total = fasterfs_backend.num_chunks()
    if end_chunk is None:
        end_chunk = n_total
    end_chunk = min(end_chunk, n_total)

    log.info(f"Benchmark starting: chunks {start_chunk}–{end_chunk} "
             f"({end_chunk - start_chunk} chunks)")

    # Cold start: clear only the cache for this range
    fasterfs_backend.clear_cache()

    results = {}

    log.info("Pass: Local CSV...")
    results["local"] = _run_pass(local_backend, "Local CSV",
                                 start_chunk, end_chunk)

    log.info("Pass: Plain MinIO...")
    results["minio"] = _run_pass(minio_backend, "MinIO (plain)",
                                 start_chunk, end_chunk)

    log.info("FasterFS Pass 1 (cold)...")
    results["pass1"] = _run_pass(fasterfs_backend, "FasterFS — cold",
                                 start_chunk, end_chunk, progress_cb)

    log.info("FasterFS Pass 2 (warm — cache writing)...")
    results["pass2"] = _run_pass(fasterfs_backend, "FasterFS — warm",
                                 start_chunk, end_chunk, progress_cb)

    log.info("FasterFS Pass 3 (hot — serving from cache)...")
    results["pass3"] = _run_pass(fasterfs_backend, "FasterFS — hot",
                                 start_chunk, end_chunk, progress_cb)

    # Speedup calculations
    p1_avg = results["pass1"].get("avg_ms", 1)
    p3_avg = results["pass3"].get("avg_ms", p1_avg)
    minio_avg = results["minio"].get("avg_ms", p1_avg)

    results["speedup"] = {
        "pass1_vs_pass3":  round(p1_avg / p3_avg, 1) if p3_avg > 0 else 0,
        "minio_vs_pass3":  round(minio_avg / p3_avg, 1) if p3_avg > 0 else 0,
    }

    results["cache"] = fasterfs_backend.cache_stats()
    results["chunk_range"] = {"start": start_chunk, "end": end_chunk,
                              "count": end_chunk - start_chunk}

    log.info(f"Benchmark complete. "
             f"Speedup minio→cache: {results['speedup']['minio_vs_pass3']}x | "
             f"chunks {start_chunk}–{end_chunk}")
    return results
