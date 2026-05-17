#!/usr/bin/env bash
# scripts/dev.sh — set up an editable dev environment.
#
# Prefers `uv` if available (fast); falls back to vanilla venv + pip.
# Idempotent. Run from the repo root or any subdir.

set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

if command -v uv >/dev/null; then
    echo "==> uv detected; using fast path"
    uv venv .venv
    # shellcheck disable=SC1091
    source .venv/bin/activate
    uv pip install -e '.[dev,community-full]'
else
    echo "==> uv not found; falling back to python -m venv (slower)"
    echo "    install uv with: pipx install uv  (or curl -LsSf https://astral.sh/uv/install.sh | sh)"
    python3 -m venv .venv
    # shellcheck disable=SC1091
    source .venv/bin/activate
    python -m pip install --upgrade pip
    pip install -e '.[dev,community-full]'
fi

echo
echo "Activated $(python --version) in .venv"
echo
echo "Next:"
echo "  pytest -q             # ~26s, ~700 tests"
echo "  swf-node --check      # smoke test"
echo "  swf-node              # start the daemon"
