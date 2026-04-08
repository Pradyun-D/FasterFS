"""
ebpf/loader.py — Compile, attach, and read FasterFS eBPF programs.
Requires root. Uses subprocess to drive clang, tc, bpftool.
"""

import os
import mmap
import select
import struct
import json
import time
import subprocess
import threading
import logging
from pathlib import Path
from typing import Optional, Callable

log = logging.getLogger(__name__)

EBPF_DIR    = Path(__file__).parent
MONITOR_C   = EBPF_DIR / "fasterfs_monitor.bpf.c"
MONITOR_O   = EBPF_DIR / "fasterfs_monitor.bpf.o"
SOCKOPTS_C  = EBPF_DIR / "fasterfs_sockopts.bpf.c"
SOCKOPTS_O  = EBPF_DIR / "fasterfs_sockopts.bpf.o"
BPF_PIN      = "/sys/fs/bpf/fasterfs_sockopts"
BPF_PROGS    = "/sys/fs/bpf/fasterfs_progs"
BPF_MAPS     = "/sys/fs/bpf/fasterfs_maps"
CGROUP_PATH  = "/sys/fs/cgroup"
IFACE        = "lo"
HOT_THRESHOLD = 3


def _run(cmd: list[str], check=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _parse_map_array(entries: list) -> dict:
    """Parse bpftool JSON array dump → {key_int: value_int}."""
    result = {}
    for e in entries:
        # bpftool uses "formatted" with plain ints when BTF is available
        fmt = e.get("formatted", {})
        k = fmt.get("key", e.get("key"))
        v = fmt.get("value", e.get("value"))
        # If still a list of hex strings, decode manually
        if isinstance(k, list):
            k = int.from_bytes(bytes(int(x, 16) for x in k), "little")
        if isinstance(v, list):
            v = int.from_bytes(bytes(int(x, 16) for x in v), "little")
        result[int(k)] = int(v)
    return result


# ── Compile ───────────────────────────────────────────────────────────────────

def compile_programs() -> bool:
    log.info("Compiling eBPF programs...")
    for src, obj in [(MONITOR_C, MONITOR_O), (SOCKOPTS_C, SOCKOPTS_O)]:
        try:
            _run(["clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86",
                  f"-I{EBPF_DIR}", "-c", str(src), "-o", str(obj)])
            log.info(f"[+] Compiled {obj.name}")
        except subprocess.CalledProcessError as e:
            log.error(f"Compile failed {src.name}: {e.stderr}")
            return False
    return True


# ── TC attach ─────────────────────────────────────────────────────────────────

def attach_tc() -> bool:
    """
    Load both TC programs together via `bpftool prog loadall` + pinmaps,
    so egress and ingress share a single set of BPF maps (critical for
    flow_timestamps handoff). Then attach each pinned prog via tc filter.
    """
    try:
        # Tear down any previous attach
        subprocess.run(["tc", "qdisc", "del", "dev", IFACE, "clsact"],
                       capture_output=True)
        # Clear old pins
        subprocess.run(["rm", "-rf", BPF_PROGS, BPF_MAPS], capture_output=True)

        # Load ALL programs from one object file — shared map instances
        _run(["bpftool", "prog", "loadall", str(MONITOR_O), BPF_PROGS,
              "pinmaps", BPF_MAPS])
        log.info(f"[+] eBPF programs pinned at {BPF_PROGS}, maps at {BPF_MAPS}")

        # Attach via tc using pinned program paths
        _run(["tc", "qdisc", "add", "dev", IFACE, "clsact"])
        _run(["tc", "filter", "add", "dev", IFACE, "ingress",
              "bpf", "pinned", f"{BPF_PROGS}/fasterfs_ingress", "da"])
        _run(["tc", "filter", "add", "dev", IFACE, "egress",
              "bpf", "pinned", f"{BPF_PROGS}/fasterfs_egress",  "da"])
        log.info("[+] TC filters attached to lo (shared maps)")
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"TC attach failed: {e.stderr}")
        return False


def detach_tc():
    subprocess.run(["tc", "qdisc", "del", "dev", IFACE, "clsact"],
                   capture_output=True)


# ── SOCK_OPS attach ───────────────────────────────────────────────────────────

def attach_sockops() -> bool:
    try:
        subprocess.run(["rm", "-f", BPF_PIN], capture_output=True)
        _run(["bpftool", "prog", "load", str(SOCKOPTS_O), BPF_PIN])
        _run(["bpftool", "cgroup", "attach", CGROUP_PATH,
              "sock_ops", "pinned", BPF_PIN])
        log.info(f"[+] SOCK_OPS attached to {CGROUP_PATH}")
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"SOCK_OPS attach failed: {e.stderr}")
        return False


def detach_sockops():
    try:
        subprocess.run(["bpftool", "cgroup", "detach", CGROUP_PATH,
                        "sock_ops", "pinned", BPF_PIN], capture_output=True)
        subprocess.run(["rm", "-f", BPF_PIN], capture_output=True)
    except Exception:
        pass


# ── Map reads ─────────────────────────────────────────────────────────────────

def read_global_stats() -> dict:
    """Read global_stats: [reads, hot_events, total_lat_ns, bytes]"""
    try:
        r = _run(["bpftool", "map", "dump", "pinned",
                  f"{BPF_MAPS}/global_stats", "-j"])
        m = _parse_map_array(json.loads(r.stdout))
        reads     = m.get(0, 0)
        hot_evts  = m.get(1, 0)
        total_lat = m.get(2, 0)
        total_b   = m.get(3, 0)
        return {
            "reads":        reads,
            "hot_events":   hot_evts,
            "hot_chunks":   hot_evts,
            "total_lat_ns": total_lat,
            "avg_lat_us":   round(total_lat / reads / 1000, 1) if reads > 0 else 0,
            "bytes_observed": total_b,
            "ebpf_loaded":  True,
            "simulation":   False,
        }
    except Exception as e:
        log.debug(f"read_global_stats: {e}")
        return {"ebpf_loaded": False, "reads": 0, "hot_events": 0,
                "hot_chunks": 0, "avg_lat_us": 0}


def read_sockops_stats() -> dict:
    try:
        r = _run(["bpftool", "map", "dump", "name", "sockops_stats", "-j"])  # not pinned, use name
        m = _parse_map_array(json.loads(r.stdout))
        return {
            "connections_tuned": m.get(0, 0),
            "nodelay_set":       m.get(1, 0),
            "quickack_set":      m.get(2, 0),
        }
    except Exception as e:
        log.debug(f"read_sockops_stats: {e}")
        return {"connections_tuned": 0}


def count_hot_chunks() -> int:
    try:
        r = _run(["bpftool", "map", "dump", "pinned",
                  f"{BPF_MAPS}/chunk_hotness", "-j"])
        entries = json.loads(r.stdout)
        hot = 0
        for e in entries:
            fmt = e.get("formatted", {})
            v = fmt.get("value", e.get("value", 0))
            if isinstance(v, list):
                v = int.from_bytes(bytes(int(x, 16) for x in v), "little")
            if int(v) > HOT_THRESHOLD:
                hot += 1
        return hot
    except Exception:
        return 0


def cache_hit_pct() -> float:
    """Estimate cache hit % from hot_events / total reads."""
    try:
        gs = read_global_stats()
        reads = gs.get("reads", 0)
        hot   = gs.get("hot_events", 0)
        if reads == 0:
            return 0.0
        # Hot events = reads that were served from cache
        return round(min(100.0, hot / reads * 100), 1)
    except Exception:
        return 0.0


# ── Ring buffer consumer ─────────────────────────────────────────────────────

def _bpf_obj_get(path: str) -> int:
    """
    Call bpf(BPF_OBJ_GET) to get a valid fd for a pinned BPF map.
    Regular os.open() on /sys/fs/bpf/* returns EIO — BPF pinned files
    must be opened via the bpf() syscall.
    """
    import ctypes, ctypes.util
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    NR_bpf    = 321       # x86_64
    BPF_OBJ_GET = 7

    class _Attr(ctypes.Structure):
        _fields_ = [
            ("pathname",   ctypes.c_uint64),
            ("bpf_fd",     ctypes.c_uint32),
            ("file_flags", ctypes.c_uint32),
        ]

    path_buf = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = _Attr()
    attr.pathname = ctypes.cast(path_buf, ctypes.c_void_p).value

    fd = libc.syscall(NR_bpf, BPF_OBJ_GET, ctypes.byref(attr), ctypes.sizeof(attr))
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), path)
    return fd


def start_ringbuf_consumer(on_hot_event: Callable[[dict], None]) -> Optional[threading.Thread]:
    """
    Poll the BPF ring buffer for HOT_CHUNK events emitted by the TC ingress hook.
    Uses mmap to implement the ring buffer consumer protocol directly.

    Ring buffer layout (kernel ABI):
      offset 0            : producer page  — u64 prod_pos at byte 0 (read-only)
      offset PAGE_SIZE    : consumer page  — u64 cons_pos at byte 0 (read-write)
      offset 2*PAGE_SIZE  : data ring      — RING_SIZE bytes

    Each record: [u32 len_flags][u32 pg_off][data][padding to 8-byte align]
    len_flags bits: 0-29 = length, 30 = DISCARD, 31 = BUSY

    on_hot_event is called with {'chunk_key': int, 'latency_ns': int} for each
    hot event. The FasterFS server uses this to write hot chunks to local disk.
    """
    RING_PATH   = f"{BPF_MAPS}/events"
    RING_SIZE   = 1 << 20        # 1 MB — must match BPF definition
    PAGE_SIZE   = mmap.PAGESIZE
    BUSY_BIT    = 1 << 31
    DISCARD_BIT = 1 << 30
    HDR_SZ      = 8              # u32 len_flags + u32 pg_off

    # struct chunk_event: u64 chunk_key + u64 latency_ns + u32 bytes + u8 is_hot + u8[3] pad
    EVENT_FMT  = "<QQIBxxx"
    EVENT_SIZE = struct.calcsize(EVENT_FMT)   # 24 bytes

    def _consumer():
        try:
            fd = _bpf_obj_get(RING_PATH)
        except OSError as e:
            log.warning(f"[ringbuf] bpf_obj_get failed: {e}")
            return

        try:
            # Kernel ring buffer mmap layout (matches libbpf ring_buffer.c):
            #   offset 0           → consumer page (PROT_READ|PROT_WRITE) — u64 cons_pos
            #   offset PAGE_SIZE   → producer page (PROT_READ only)       — u64 prod_pos
            #   offset 2*PAGE_SIZE → data ring     (PROT_READ only)       — records
            cons_map = mmap.mmap(fd, PAGE_SIZE, mmap.MAP_SHARED,
                                 mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
            prod_map = mmap.mmap(fd, PAGE_SIZE, mmap.MAP_SHARED,
                                 mmap.PROT_READ, offset=PAGE_SIZE)
            data_map = mmap.mmap(fd, RING_SIZE, mmap.MAP_SHARED,
                                 mmap.PROT_READ, offset=2 * PAGE_SIZE)
        except Exception as e:
            log.warning(f"[ringbuf] mmap failed: {e}")
            os.close(fd)
            return

        log.info("[ringbuf] consumer started — eBPF now drives caching")
        mask = RING_SIZE - 1

        while True:
            try:
                select.select([fd], [], [], 0.5)

                prod = struct.unpack_from("<Q", prod_map, 0)[0]
                cons = struct.unpack_from("<Q", cons_map, 0)[0]

                while cons != prod:
                    offset    = cons & mask
                    len_flags = struct.unpack_from("<I", data_map, offset)[0]

                    if len_flags & BUSY_BIT:
                        break   # producer still writing this record

                    length = len_flags & ~(BUSY_BIT | DISCARD_BIT)

                    if not (len_flags & DISCARD_BIT) and length >= EVENT_SIZE:
                        try:
                            chunk_key, lat_ns, nbytes, is_hot = struct.unpack_from(
                                EVENT_FMT, data_map, offset + HDR_SZ)
                            if is_hot:
                                on_hot_event({"chunk_key": chunk_key, "latency_ns": lat_ns})
                        except Exception:
                            pass

                    cons += HDR_SZ + ((length + 7) & ~7)
                    struct.pack_into("<Q", cons_map, 0, cons)

            except Exception as e:
                log.warning(f"[ringbuf] consumer error: {e}")
                time.sleep(0.5)

    t = threading.Thread(target=_consumer, daemon=True, name="ebpf-ringbuf")
    t.start()
    return t


# ── High-level ────────────────────────────────────────────────────────────────

class FasterFSeBPF:
    def __init__(self):
        self.loaded = False

    def load(self) -> bool:
        if os.geteuid() != 0:
            log.warning("Not root — eBPF disabled")
            return False
        if not MONITOR_O.exists() or not SOCKOPTS_O.exists():
            if not compile_programs():
                return False
        ok = attach_tc() and attach_sockops()
        self.loaded = ok
        return ok

    def unload(self):
        detach_tc()
        detach_sockops()
        self.loaded = False

    def stats(self) -> dict:
        gs = read_global_stats()
        ss = read_sockops_stats()
        hot = count_hot_chunks()
        hit = cache_hit_pct()
        return {
            **gs, **ss,
            "hot_chunks":     hot,
            "cache_hit_pct":  hit,
            "total_chunks":   92,
            "cached_chunks":  hot,
        }


_instance: Optional[FasterFSeBPF] = None

def get_ebpf() -> FasterFSeBPF:
    global _instance
    if _instance is None:
        _instance = FasterFSeBPF()
    return _instance
