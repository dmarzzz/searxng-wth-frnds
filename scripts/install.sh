#!/usr/bin/env bash
# scripts/install.sh — one-line operator install for swf-node.
#
#   curl -fsSL https://raw.githubusercontent.com/dmarzzz/searxng-wth-frnds/main/scripts/install.sh | bash
#
# Pin a tag/branch/commit by setting SWF_NODE_REF (default: main):
#
#   curl -fsSL https://raw.githubusercontent.com/dmarzzz/searxng-wth-frnds/main/scripts/install.sh | SWF_NODE_REF=v0.8.0 bash
#
# Installs swf-node via pipx (so the daemon's deps stay in their own
# venv and don't pollute the user site-packages) directly from git
# (v0.8.0 ships via Docker + git-install; PyPI publish is deferred).
# Idempotent: re-runs upgrade in place. Falls back to `pip install
# --user` only if pipx can't be installed.

set -euo pipefail

if ! command -v python3 >/dev/null; then
    echo "swf-node needs Python 3.10+. Install it first." >&2
    exit 1
fi

PYV=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYV_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "$(python3 -c 'import sys; print(sys.version_info.major)')" -lt 3 ] || [ "$PYV_MINOR" -lt 10 ]; then
    echo "swf-node needs Python 3.10+ (found ${PYV})." >&2
    exit 1
fi

if ! command -v pipx >/dev/null; then
    echo "==> pipx not found; installing via 'python3 -m pip install --user pipx'…"
    python3 -m pip install --user --quiet pipx
    python3 -m pipx ensurepath
    # ensurepath modifies shell rc files but doesn't take effect in
    # this process; prepend the user-bin dir so the rest of the
    # script can find pipx.
    export PATH="${HOME}/.local/bin:${PATH}"
fi

SWF_NODE_REF="${SWF_NODE_REF:-main}"
echo "==> installing swf-node from git (ref=${SWF_NODE_REF})…"
pipx install --force "git+https://github.com/dmarzzz/searxng-wth-frnds.git@${SWF_NODE_REF}"

echo
echo "Installed: $(swf-node version 2>/dev/null || echo 'swf-node')"
echo
echo "Next:"
echo "  swf-node init      # generate identity + config"
echo "  swf-node doctor    # verify mDNS / SearXNG / peers"
echo "  swf-node           # start the daemon on 127.0.0.1:7777"
