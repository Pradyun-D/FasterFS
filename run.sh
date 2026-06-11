#!/usr/bin/env bash
# run.sh — Start FasterFS: MinIO + eBPF + Dashboard
# Usage: sudo ./run.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'; AMBER='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'

log()  { echo -e "${AMBER}[FasterFS]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

# ── 1. MinIO ──────────────────────────────────────────────────────────────────
log "Starting MinIO..."
MINIO_BIN=$(which minio 2>/dev/null || echo "/usr/local/bin/minio")

if pgrep -f "minio server" > /dev/null 2>&1; then
  ok "MinIO already running"
else
  mkdir -p /tmp/fasterfs-minio-data
  MINIO_ROOT_USER=admin MINIO_ROOT_PASSWORD=adminpass123 \
    nohup "$MINIO_BIN" server /tmp/fasterfs-minio-data \
      --address :9000 --console-address :9001 \
      > /tmp/fasterfs-minio.log 2>&1 &
  sleep 2

  if pgrep -f "minio server" > /dev/null 2>&1; then
    ok "MinIO started on :9000 (console :9001)"
  else
    err "MinIO failed to start — check /tmp/fasterfs-minio.log"
  fi
fi

# ── 2. Bucket setup ───────────────────────────────────────────────────────────
MC_BIN=$(which mc 2>/dev/null || find /home/swrj/Desktop/FasterFS -name mc -type f 2>/dev/null | head -1)
if [ -n "$MC_BIN" ]; then
  "$MC_BIN" alias set local http://127.0.0.1:9000 admin adminpass123 > /dev/null 2>&1 || true
  "$MC_BIN" mb local/fasterfs > /dev/null 2>&1 || true
  ok "MinIO bucket 'fasterfs' ready"
fi

# ── 3. BPF filesystem ─────────────────────────────────────────────────────────
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  log "Mounting BPF filesystem..."
  mount -t bpf bpf /sys/fs/bpf && ok "BPF filesystem mounted" || err "BPF mount failed"
else
  ok "BPF filesystem already mounted"
fi

# ── 4. Compile eBPF programs ──────────────────────────────────────────────────
log "Compiling eBPF programs..."
cd "$SCRIPT_DIR/ebpf"
if make 2>&1; then
  ok "eBPF programs compiled"
else
  err "eBPF compile failed — dashboard will use simulation mode"
fi
cd "$SCRIPT_DIR"

# ── 5. Dashboard server ───────────────────────────────────────────────────────
log "Starting FasterFS dashboard on http://localhost:8000 ..."
echo ""
echo "  Dashboard:    http://localhost:8000"
echo "  MinIO API:    http://localhost:9000"
echo "  MinIO Console: http://localhost:9001  (admin/adminpass123)"
echo ""

# Run with sudo if eBPF loading is desired; else as current user
if [ "$(id -u)" = "0" ]; then
  "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/main.py"
else
  log "Not root — eBPF will use simulation mode. Use 'sudo ./run.sh' for real eBPF."
  "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/main.py"
fi
