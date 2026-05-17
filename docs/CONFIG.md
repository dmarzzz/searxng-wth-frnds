# Configuration reference

All configuration is via environment variables. swf-node does not
auto-load `.env` — point your shell at one with direnv, dotenvx, or
`set -a; source .env; set +a` before launching.

`swf-node init` writes a commented config skeleton to
`~/.config/swf/config.toml` for reference, but the daemon does not
read it (yet — that's a future TOML-loader PR). Treat `config.toml`
as documentation.

## Network

| Var | Default | Meaning |
|---|---|---|
| `SWF_BIND` | `127.0.0.1` | Interface to bind. Set `0.0.0.0` to accept LAN peers. |
| `SWF_PORT` | `7777` | TCP port for the HTTP server. |
| `SWF_NO_MDNS` | unset (off) | `1`/`true`/`yes` to disable mDNS advertising. Auto-disabled on loopback bind. |
| `SWF_FULL` | unset (off) | `1` = aggregator mode (`/graph`, `/events`, `/metrics/*` live alongside peer routes). Requires `[community-full]` extras. |

## State / paths

| Var | Default | Meaning |
|---|---|---|
| `SWF_CONFIG_DIR` | `~/.config/swf` | Identity key, peers.yaml, cache_secret.bin, config.toml. Mode 0700. |
| `SWF_KNOWLEDGE_DIR` | `~/world_knowledge` | FTS5 indrex DB + markdown archive. Created on first write. |
| `SWF_STATE_DIR` | `~/.local/share/swf` | search_cache.db, reputation.db, tickets.sqlite, event log. |

Legacy aliases (still respected; new wins): `RA_WORLD_KNOWLEDGE_DIR`
maps to `SWF_KNOWLEDGE_DIR`.

## Privacy / sharing

| Var | Default | Meaning |
|---|---|---|
| `SWF_DEFAULT_SHARE_SCOPE` | `friends` | `share_scope` set on newly-indexed user-fetched pages. One of `private`, `local_only`, `friends`, `public`. Invalid values fall back to `friends`. |
| `SWF_DISABLE_KNOWLEDGE_WRITE` | unset (off) | `1` to skip the markdown write-through to `world_knowledge/`. FTS5 still indexes content. Used in test runs. |
| `SWF_QUERY_HMAC_SECRET` | auto | 32-byte secret for HMACing query strings before they hit logs / search_results cache. Auto-generated on first launch. |

Legacy alias: `RA_WORLD_KNOWLEDGE=0` maps to `SWF_DISABLE_KNOWLEDGE_WRITE=1`.

## Auth

| Var | Default | Meaning |
|---|---|---|
| `SWF_AGENT_TOKEN` | unset (no auth on loopback) | Bearer token for the privileged routes (`/web_search`, `/local_search`, `/fetch_url`, `/fetch_urls`). When `SWF_BIND` is non-loopback and the token is unset, the daemon refuses to start. Peer routes (`/.well-known/indrex`, `/index/pages`, etc.) are Ed25519-signed and don't need a bearer. |

## Optional integrations

| Var | Default | Meaning |
|---|---|---|
| `SEARXNG_URL` | unset | If set, `SELF_PUBLIC_EGRESS` calls `<url>/search?format=json` for public web fallback. Without this, the router stops at LOCAL_INDREX + LAN_FRIEND. |
| `SWF_ALLOW_DIRECT_ENGINES` | `0` | `1` to fall back to the `ddgs` library directly when SearXNG is unreachable. Privacy: still SELF_PUBLIC_EGRESS, just no SearXNG aggregation. |

Tailscale: auto-detected via `tailscale status --json`. No env var.
Just have the binary on PATH.

## Logging

| Var | Default | Meaning |
|---|---|---|
| `SWF_LOG_LEVEL` / `LOGLEVEL` | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`. Wins over the verbose / quiet flags below. |
| `SWF_VERBOSE` / `RA_VERBOSE` | unset | When set, logger level becomes `DEBUG`. |
| `SWF_QUIET` | unset | When set, logger level becomes `WARNING`. |

Since #79, every `swf.*` module emits through `logging.getLogger(__name__)`
into a single stderr handler bootstrapped at the `swf-node` /
`swf-peer` CLI entry point. The on-the-wire shape stays grep-
compatible with the pre-#79 `sys.stderr.write("[component] ...")`
output: a custom formatter prefixes each record with the legacy
`[component]` tag derived from the logger name. Operator scripts
that gate on lines like `[peer-server] listening on http://` keep
working byte-for-byte.

## Bundles / encryption (#93)

| Var | Default | Meaning |
|---|---|---|
| `SWF_ALCHEMISTS_FILE` | `$SWF_CONFIG_DIR/.alchemists.yml`, fallback `~/.config/swf/.alchemists.yml` | Path to the Ed25519 signing-list YAML for cohort + transcript bundle authors. See SHAPE-ROTATOR-OS-SPEC.md §3.7. |
| `SWF_RESERVOIR_FILE` | `$SWF_CONFIG_DIR/.reservoir.yml`, fallback `~/.config/swf/.reservoir.yml` | Path to `.reservoir.yml` for `cohort.depth` + encrypted `transcript.batch` encryption. The hivemind sink reads this when `?encrypt=true` is requested. See SHAPE-ROTATOR-OS-SPEC.md §3.6. |
| `SWF_CONVENT_SIGNING_KEY` | `~/.config/swf/convent-signing.key` | 32-byte Ed25519 seed the convent box's hivemind sink uses to resign voxterm transcript batches. |

## Identity / discovery

| Var | Default | Meaning |
|---|---|---|
| `SWF_NODE_NAME` | `socket.gethostname()` (with trailing `.local` stripped) | The mDNS instance name + the `node` field in the well-known doc. |
| `SWF_EXTRA_PEERS` | unset | Comma-separated URL list, merged with `peers.yaml` at scrape time. Useful for hand-pinning peers without persisting to disk. |

## Feature flags (rarely touched)

| Var | Default | Meaning |
|---|---|---|
| `SWF_ENABLE_TICKETS` | `0` | §17 anonymous-ticket peer search. Off by default. |
| `SWF_ENABLE_RECEIPTS` | `0` | §16 search-result receipts. Off by default. |
| `SWF_ENABLE_DCNET` | `0` | LAN_FRIEND_DCNET delivery path (anonymous within circle). Off by default. |
| `SWF_ENABLE_PEER_TRUST` | `0` | When `1`, the pull-from-peer path skips peers with `trust_level='banned'`. When unset, every known peer pulls regardless of trust. |
| `SWF_DEBUG_PEER_VERIFY` | `0` | Verbose stderr trace for the bundle-verification path. Use with `--debug-discovery`. |

## fetch_url cache

| Var | Default | Meaning |
|---|---|---|
| `RA_CACHE_DIR` | `.ra_cache/fetch` | Directory for the `swf.web.fetch` on-disk cache. Per-process; survives restarts. |
| `RA_CACHE_TTL_SEC` | `604800` (7 days) | Cache TTL in seconds. |
| `RA_DISABLE_JINA` | `0` | `1` to skip the Jina Reader fallback (local trafilatura only). |
| `RA_BYPASS_CACHE` | `0` | `1` to force a fresh fetch on the next call. |
| `RA_CACHE_HIT_MIN` | `2` | Minimum cache rows to count as "sufficient" for the staleness auto-bypass. |
| `RA_CACHE_TTL_SEARCH` | `86400` (1 day) | Cache TTL for the `search_results` cache (separate from page cache). |

These keep the `RA_` prefix because they're tied to the `swf.web` /
`research_agent`-era cache shape; they were never renamed and the
test fixtures pin them.

## Resolution order

1. **Process environment** (real env vars; what the OS hands us).
2. **`SWF_*` over `RA_*`**: when both are set, the new name wins.
3. **Defaults baked into the source.**

The daemon does *not* parse `~/.config/swf/config.toml` at runtime
(yet). It's written by `swf-node init` as a reference for operators.

## What `swf-node init` produces

```toml
# ~/.config/swf/config.toml
# (this file is documentation only — the daemon reads env vars)

# SWF_BIND       = "127.0.0.1"
# SWF_PORT       = 7777
# SWF_NO_MDNS    = false
# SWF_FULL       = false

# SWF_CONFIG_DIR    = "~/.config/swf"
# SWF_KNOWLEDGE_DIR = "~/world_knowledge"
# SWF_STATE_DIR     = "~/.local/share/swf"

# SWF_DEFAULT_SHARE_SCOPE = "friends"
# SWF_AGENT_TOKEN         = ""

# SEARXNG_URL = "http://127.0.0.1:8888"

# SWF_LOG_LEVEL = "INFO"
```
