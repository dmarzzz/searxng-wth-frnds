#!/usr/bin/env bash
# scripts/demo-2-peers.sh — bring up two swf-node peers on this laptop.
#
# Each peer gets its own config dir, knowledge dir, port, and node
# name. They're hand-pinned to each other via `swf-peer add` so the
# demo doesn't depend on mDNS round-tripping over loopback (which is
# flaky). Logs tail to runs/peer-{a,b}/server.log; Ctrl-C tears down.
#
# Quickstart:
#     bash scripts/demo-2-peers.sh
#     # in another shell:
#     curl -sS http://127.0.0.1:7777/.well-known/indrex | jq
#     curl -sS http://127.0.0.1:7778/.well-known/indrex | jq

set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
mkdir -p "$ROOT/runs/peer-a" "$ROOT/runs/peer-b"

# Detect the swf-node invocation: prefer the console script, fall back
# to `python -m swf` from the active venv.
if command -v swf-node >/dev/null; then
    SWF_NODE=(swf-node)
elif [ -x "$ROOT/.venv/bin/swf-node" ]; then
    SWF_NODE=("$ROOT/.venv/bin/swf-node")
elif [ -x "$ROOT/.venv/bin/python" ]; then
    SWF_NODE=("$ROOT/.venv/bin/python" -m swf)
else
    echo "swf-node not on PATH and no .venv/ present. Run scripts/dev.sh first." >&2
    exit 1
fi

start_peer() {
    local name=$1 port=$2 dir=$3
    SWF_CONFIG_DIR="$dir/config" \
    SWF_KNOWLEDGE_DIR="$dir/knowledge" \
    SWF_STATE_DIR="$dir/state" \
    SWF_PORT="$port" \
    SWF_NODE_NAME="$name" \
    SWF_BIND=127.0.0.1 \
    SWF_NO_MDNS=1 \
    "${SWF_NODE[@]}" > "$dir/server.log" 2>&1 &
    echo $! > "$dir/pid"
    echo "[$name] pid=$(cat "$dir/pid")  http://127.0.0.1:$port  config=$dir/config"
}

cleanup() {
    echo
    echo "==> tearing down peers"
    for d in "$ROOT/runs/peer-a" "$ROOT/runs/peer-b"; do
        if [ -f "$d/pid" ]; then
            kill "$(cat "$d/pid")" 2>/dev/null || true
            rm -f "$d/pid"
        fi
    done
}
trap cleanup EXIT INT TERM

start_peer peer-a 7777 "$ROOT/runs/peer-a"
start_peer peer-b 7778 "$ROOT/runs/peer-b"

# Give them a beat to bind.
sleep 1

# Detect swf-peer the same way we found swf-node.
if command -v swf-peer >/dev/null; then
    SWF_PEER=(swf-peer)
elif [ -x "$ROOT/.venv/bin/swf-peer" ]; then
    SWF_PEER=("$ROOT/.venv/bin/swf-peer")
else
    SWF_PEER=("$ROOT/.venv/bin/python" -m swf.peer_cli)
fi

echo
echo "==> wiring peers to each other"
SWF_CONFIG_DIR="$ROOT/runs/peer-a/config" \
    "${SWF_PEER[@]}" add peer-b http://127.0.0.1:7778 || true
SWF_CONFIG_DIR="$ROOT/runs/peer-b/config" \
    "${SWF_PEER[@]}" add peer-a http://127.0.0.1:7777 || true

echo
echo "==> tailing logs (Ctrl-C to tear down)"
tail -F "$ROOT/runs/peer-a/server.log" "$ROOT/runs/peer-b/server.log"
