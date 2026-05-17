# swf-node

> 🚩 **DO NOT OPEN-SOURCE THIS REPO AS-IS.** Git history is polluted with a leaked GitHub access token (committed in the `origin` remote URL / prior commits). Rotate the token, scrub history (e.g. `git filter-repo`), and verify with a secret scan **before** flipping this repo to public.


**Self-sovereign LAN-first peer search.** A single Python daemon that
maintains a local FTS5 index of every page you fetch and shares
signed bundles with mDNS-discovered peers on your LAN. No accounts,
no API keys on the default path, no public crawler — your archive is
yours, your peers are people you've explicitly added.

```bash
# Primary install path for v0.8.0 — Docker (Linux server with mDNS):
docker run --network host \
    -v "$HOME/.config/swf:/home/swf/.config/swf" \
    -v "$HOME/world_knowledge:/home/swf/world_knowledge" \
    ghcr.io/dmarzzz/swf-node:v0.8.0

# Or install natively from git (laptop peer mode on macOS/Windows):
pipx install "git+https://github.com/dmarzzz/searxng-wth-frnds.git@v0.8.0"
swf-node init                  # generate identity + config
swf-node                       # start the daemon on 127.0.0.1:7777
```

> v0.8.0 ships via **Docker + git-install only** — the PyPI publish
> path is deferred; see [`TODO.md`](TODO.md).

If you're setting up a convent box (swf-node + hivemind sink), see
[`docs/QUICKSTART.md`](docs/QUICKSTART.md) for the full recipe.

Then point the agent of your choice at `POST http://127.0.0.1:7777/web_search`,
or treat it as a long-running search backend over HTTP.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## What it is

Each `swf-node` is one peer in a LAN-first knowledge mesh:

```
[your laptop]                    [your friend's laptop]
 swf-node ───── mDNS:7777 ────►  swf-node
 │  pages: 930                   │  pages: 4
 │  /web_search                  │  /web_search
 │  signed bundles ◄─── pull ───►│  signed bundles
 ▼                               ▼
 ~/world_knowledge/              ~/world_knowledge/
   FTS5 indrex + markdown          FTS5 indrex + markdown
```

- **Local archive** — every page you fetch lands in `~/world_knowledge/web/<host>/<date>-<slug>.md` and is FTS5-indexed for instant search.
- **Signed bundles** — each peer's `/index/pages` returns an Ed25519-signed bundle with merkle-rooted content. TOFU-pinned via `swf-peer add`.
- **mDNS auto-discovery** — peers announce themselves on the LAN with `_indrex._tcp.local.`. No coordinating server.
- **No telemetry**, no accounts, no opaque cloud dependencies. Optional [SearXNG](https://github.com/searxng/searxng) integration if you want a human web UI.

## What it isn't

- **Not a public crawler** — swf-node only indexes pages *you* fetch. There is no spidering.
- **Not a multi-tenant service** — one identity per `~/.config/swf/`, one user per node.
- **Not a public-internet service by default** — mDNS is single-LAN-broadcast-domain only. Cross-VLAN, guest Wi-Fi, or off-LAN peering needs Tailscale (auto-detected via `tailscale status`) or hand-pinning via `swf-peer add`.
- **Not security-hardened for hostile networks** — no built-in TLS, no rate limiting, no per-peer ACL beyond `peers.yaml`. Run behind Caddy/nginx if you expose it (`examples/caddy/`, `examples/nginx/`).
- **Not on Docker Desktop for laptop peer mode** — the macOS/Windows VM doesn't pass host LAN multicast to containers. Use the git-install path natively.

## Install

v0.8.0 ships via **Docker + git-install only**. PyPI publishing is
deferred — see [`TODO.md`](TODO.md). To pin a different ref, set
`SWF_NODE_REF` (default: `main`) before any `pipx install` below.

**Linux server with Docker (host networking required for mDNS) — primary path:**

```bash
docker run --network host \
    -v "$HOME/.config/swf:/home/swf/.config/swf" \
    -v "$HOME/world_knowledge:/home/swf/world_knowledge" \
    ghcr.io/dmarzzz/swf-node:v0.8.0
```

**Operator (one-line):**

```bash
curl -fsSL https://raw.githubusercontent.com/dmarzzz/searxng-wth-frnds/main/scripts/install.sh | SWF_NODE_REF=v0.8.0 bash
```

**Operator (manual, native install from git):**

```bash
pipx install "git+https://github.com/dmarzzz/searxng-wth-frnds.git@v0.8.0"   # primary recommendation
# or
uv tool install "git+https://github.com/dmarzzz/searxng-wth-frnds.git@v0.8.0"  # equivalent, faster
```

**From source (development):**

```bash
git clone https://github.com/dmarzzz/searxng-wth-frnds
cd searxng-wth-frnds
bash scripts/dev.sh                    # uv venv + editable install
```

## First run (60-second tour)

```bash
$ swf-node init
identity created: c5cd211118a50d25 at ~/.config/swf/identity.key
config written: ~/.config/swf/config.toml

$ swf-node doctor
== swf-node doctor ==
[1] core checks (--check)
[ok] identity: pubkey=… fp=c5cd211118a50d25
…
== all clear ==

$ swf-node                              # foreground; Ctrl-C to stop
[peer-server] identity c5cd211118a50d25 (existing at ~/.config/swf/identity.key)
[peer-server] listening on http://127.0.0.1:7777 · db=~/world_knowledge/index.db

# In another shell:
$ curl -sX POST http://127.0.0.1:7777/web_search \
    -H "Content-Type: application/json" \
    -d '{"q":"animal communication","top_k":5,"policy":"local_only"}' \
    | jq '.results[].canonical_url'
```

That's the full feedback loop. Pages you fetch via `/fetch_url` are indexed automatically and become searchable on the next `/web_search`.

## Running with a friend (LAN demo)

```bash
# Both machines:
swf-node                                # listens on :7777, advertises via mDNS

# On yours, after you both have nodes running:
swf-peer discover                       # browse mDNS for friends
swf-peer add alice http://alice.local:7777
swf-peer health                         # /.well-known/indrex round-trip
```

Once paired, each side's `/index/pages` ships signed bundles to the other every ~63s. The receiver verifies the merkle root + Ed25519 signature, ingests pages with `share_scope='friends'` attribution, and surfaces them in `/web_search` results with the friend's pubkey + nickname.

**Want to try it without two laptops?** `make demo-2-peers` brings up two daemons on this machine with isolated state and tails both logs.

## Backup & restore

Snapshot a convent box (indrex DB + identity + signing keys + peers config) into a single tarball, and restore it elsewhere:

```bash
# Snapshot current state. Tarball is written 0600 because it contains
# the identity seed (and, if present, the convent-signing.key).
swf-node backup --output ~/backups/convent-$(date +%Y%m%d).tar.gz

# Inverse: restore to the standard locations.
swf-node restore ~/backups/convent-20260509.tar.gz

# Or to fresh dirs (useful for migrating to a new box, or testing):
swf-node restore ~/backups/convent-20260509.tar.gz \
    --target-config-dir /tmp/restored/config \
    --target-knowledge-dir /tmp/restored/world_knowledge
```

The backup uses the SQLite online-backup API for the indrex DB, so it's safe to run while the daemon is serving. Each captured file's sha256 is recorded in `manifest.json` and verified on restore — a tampered or partial archive aborts before any state is overwritten. By default `swf-node restore` refuses to overwrite an existing indrex DB; pass `--force` to opt in.

## Privacy posture

- **Default `share_scope` for newly-indexed pages is `friends`.** This means: any peer you `swf-peer add` will, on the next pull cycle, receive every page you fetch from that point on. If you want stricter behavior, set `SWF_DEFAULT_SHARE_SCOPE=private` before starting the daemon. Existing pages keep whatever scope they were indexed with.
- **No telemetry.** swf-node makes zero outbound calls except (a) explicit fetches you trigger via `/fetch_url`, (b) peer pulls on the configured cadence, (c) the optional SearXNG fallback if you set `SEARXNG_URL`.
- **Identity is per-config-dir, not per-machine.** Don't sync `~/.config/swf/` across boxes — peers TOFU your pubkey on first add, and rotation breaks all cached trust until they re-add you.
- **Threat model**: see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Disclosure path: [`SECURITY.md`](SECURITY.md).

## How agents use it

The intended pattern is HTTP, not in-process imports. Any agent that can `POST` JSON works:

```bash
curl -sX POST http://127.0.0.1:7777/web_search \
    -H "Content-Type: application/json" \
    -d '{"q":"<your query>","top_k":10}'
```

Endpoints (see [`docs/HTTP_API.md`](docs/HTTP_API.md) for the full reference):

- `POST /web_search` — full router (cache → local indrex → friend pull → public egress)
- `POST /local_search` — local indrex only, no network
- `POST /fetch_url` — fetch + extract + write-through to `world_knowledge` + index
- `POST /fetch_urls` — batched fetch
- `GET  /index/pages` — Ed25519-signed bundle for peer pull
- `GET  /graph` — node+edge JSON for visualization
- `GET  /events` — server-sent event stream (peer pulls, IP changes, scrape progress)
- `GET  /health`, `GET /metrics/snapshot`, `GET /metrics/series`

The companion repo [`research-swarm`](https://github.com/dmarzzz/research-swarm) is one such agent — a DSPy ReAct loop that calls `swf-node` for search and fetch.

## What's in this repo

```
searxng-wth-frnds/                         (binary: swf-node)
├── src/swf/                                core daemon
│   ├── peer_server.py                       HTTP entry; subcommand dispatch
│   ├── peer_scraper.py                      pull bundles from peers + verify
│   ├── peer_cli.py                          `swf-peer add / list / discover / …`
│   ├── discovery.py                         python-zeroconf + Tailscale
│   ├── identity.py                          Ed25519 keypair + signed handshake
│   ├── search/                              SPEC v0.3 router (cache → local → public)
│   ├── web/                                 fetch / crawl / index / providers
│   └── community_full/                      `--full` mode (metrics, slices, dcnet)
├── scripts/                                 install / dev / demo / doctor / …
├── examples/                                caddy / nginx / systemd snippets
├── docs/                                    SPEC, threat model, HTTP API, etc.
├── tests/                                   ~700 tests; HOME-isolation autouse
├── Dockerfile / docker-compose.yml          Linux-host operator deploys
└── pyproject.toml                           Python 3.10+; one console script
```

## Spec / design / docs

- [`INDREX.md`](INDREX.md) — local-indrex spec (FTS5 layout, `pages_meta`, `share_scope` policy)
- [`DESIGN.md`](DESIGN.md) — system architecture, module boundaries
- [`docs/SPEC_v0.3.md`](docs/SPEC_v0.3.md) — wire-protocol surface (peer bundles, mDNS service type, HTTP envelope)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — STRIDE per-module + scope summary
- [`CHANGELOG.md`](CHANGELOG.md) — release notes
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev install, test commands, PR conventions

## Stack

- **[python-zeroconf](https://github.com/python-zeroconf/python-zeroconf)** — pure-Python mDNS (no avahi or Bonjour dependency)
- **[SQLite FTS5](https://www.sqlite.org/fts5.html)** — local indrex, WAL mode, single-writer + many-readers
- **[trafilatura](https://trafilatura.readthedocs.io/)** — HTML → markdown extraction
- **[cryptography](https://cryptography.io/)** — Ed25519 signing
- **[SearXNG](https://github.com/searxng/searxng)** *(optional)* — human web UI; bind-mount `swf/local_index.py` as a SearXNG offline engine
