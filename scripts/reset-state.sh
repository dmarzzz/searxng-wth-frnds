#!/usr/bin/env bash
# scripts/reset-state.sh — nuke all swf-node state on this machine.
#
# Removes:
#   - ~/.config/swf/ (identity key, cache HMAC secret, peers.yaml,
#     config.toml)
#   - ~/.local/share/swf/ (search_cache.db, reputation.db, tickets.sqlite,
#     event log)
#   - ~/world_knowledge/ (the FTS5 indrex AND the markdown archive)
#
# Prompts before each removal. Useful after `swf-node init --force`
# rotation, or when you just want to start fresh.

set -euo pipefail

confirm() {
    local target=$1
    if [ ! -e "$target" ]; then
        echo "[skip] $target — does not exist"
        return 1
    fi
    read -r -p "remove $target ? [y/N] " ans
    case "$ans" in
        y|Y|yes) return 0 ;;
        *) echo "[skip] $target"; return 1 ;;
    esac
}

CONFIG_DIR="${SWF_CONFIG_DIR:-$HOME/.config/swf}"
STATE_DIR="${SWF_STATE_DIR:-$HOME/.local/share/swf}"
KNOWLEDGE_DIR="${SWF_KNOWLEDGE_DIR:-${RA_WORLD_KNOWLEDGE_DIR:-$HOME/world_knowledge}}"

echo "swf-node reset-state — will prompt before each removal"
echo
echo "  config:    $CONFIG_DIR"
echo "  state:     $STATE_DIR"
echo "  knowledge: $KNOWLEDGE_DIR"
echo

for d in "$CONFIG_DIR" "$STATE_DIR" "$KNOWLEDGE_DIR"; do
    if confirm "$d"; then
        rm -rf "$d"
        echo "[gone] $d"
    fi
done

echo
echo "done. run 'swf-node init' to bootstrap fresh state."
