#!/usr/bin/env bash
# scripts/doctor.sh — wraps `swf-node doctor` and `swf-peer health`.
# Convenience for ops; the underlying commands do the real work.

set -euo pipefail

if ! command -v swf-node >/dev/null; then
    echo "swf-node not on PATH; install via scripts/install.sh" >&2
    exit 1
fi

swf-node doctor
echo
echo "==== peer health ===="
swf-peer health || true
