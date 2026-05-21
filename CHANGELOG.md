# Changelog

All notable changes to this project will be documented here. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.13.1] — 2026-05-21

### Fixed
- **Public-egress search results now land in `pages`, not just the
  FTS `search_results` cache.** `search()` previously called
  `record_search_results()` to populate the result-list cache but
  never invoked `index_page()` — so `/graph` (and therefore atlas /
  cartography / cosmos in any embedding renderer) stayed blank on
  every install whose only ingestion source was user search. The
  peer-bundle layer reads from `pages` too, so cohort peers received
  nothing from their friends' searches. Lifetime `page_added` event
  counts stayed near zero across multi-week installs that ran
  hundreds of searches.

  Fix: a bounded module-level indexer pool (`max_workers=4`) now
  submits each result URL to the existing `_get_clean_text()`
  pipeline (cache → trafilatura → Jina Reader) and feeds
  `index_page()`. The search response returns immediately; pool
  workers run in the background. Per-URL failures are isolated
  (one failed extractor or DB write doesn't abort the batch).
  Closes #19.

## [0.13.0] — 2026-05-20

### Added
- **Windows x64 PyInstaller binary** in the release matrix
  (`.github/workflows/release-binaries.yml`). Asset name follows the
  existing `(os, arch)` convention and is the only asset that carries a
  file extension: `swf-node-<version>-windows-x64.exe`. Embedding hosts
  (e.g. the Shape Rotator OS Electron app) that resolve releases by
  `(os, arch)` should append `.exe` when `os == "windows"`. We don't
  ship `windows-arm64` today — `pyrage` doesn't publish an arm64-windows
  wheel; the row in the matrix is wired so it can be added the moment
  upstream lands one. Closes #7; unblocks dmarzzz/shape-rotator-os#84.
- **Windows classifier** in `pyproject.toml`
  (`Operating System :: Microsoft :: Windows`) — runtime is verified by
  the new release-matrix smoke tests (PyInstaller `--check` + spawn +
  `/health`), which exercise the `import` graph for `zeroconf`,
  `cryptography`, `pyrage`, `pynacl`, `psutil` on `windows-latest`.
- **`docs/TROUBLESHOOTING.md` Windows section** covering the Defender
  Firewall prompt, multi-NIC interface pinning, `IPVersion.V4Only` /
  IPv6 link-local quirks, state-directory layout (`%USERPROFILE%`
  defaults + `%LOCALAPPDATA%` opt-in via `SWF_STATE_DIR`), and where
  PyInstaller `--onefile` logs land.
- **`docs/OPERATING.md` Windows firewall paragraph** with a
  `New-NetFirewallRule` snippet embedders can pre-create to suppress
  the first-bind Defender prompt.

### Changed
- The PyInstaller workflow's binary path now resolves through a
  `matrix.ext` field (`""` on POSIX, `.exe` on Windows) so the same
  step works on every leg. The `chmod +x` on the binary is now
  `|| true` — no-op on NTFS, harmless on POSIX.

## [0.12.0] — 2026-05-19

### Added
- **`GET /node/log`** endpoint (`docs/SYNC.md` §13) — generalized
  read-only window onto the in-process event ring, now spanning every
  subsystem the daemon runs (sync, mDNS discovery, peer health,
  scraper/bundle ingest, web search). Same cursor + limit contract as
  `/sync/log`; adds an optional `?category=` CSV filter
  (`sync`, `mdns`, `health`, `ingest`, `search`, `error`). Response
  schema: `swf.node.log.v1`.
- **`category` field on every event** — emitted alongside the
  existing `seq` / `kind` / `ts_ms`. Reserved at emit time; callers
  cannot overwrite it via payload. The canonical category set is
  exposed as `swf.sync.event_log.NODE_EVENT_CATEGORIES`.
- **New event kinds** (see §13.3):
  - `mdns_peer_appeared` / `mdns_peer_disappeared` (category `mdns`)
    — emitted from `discovery.browse_mdns`'s zeroconf listener, with
    a 60s per-pubkey dedupe so re-broadcasts don't spam the feed.
  - `scraper_pulled` / `scraper_error` (categories `ingest` / `error`)
    — emitted from `peer_scraper.pull_from_peer` on successful page
    ingest and on liveness / HTTP / verify failures.
  - `bundle_pulled` (category `ingest`) — emitted from
    `bundles.puller.pull_from_peer` after a tick that ingested at
    least one new bundle, with `bundle_count` and approximate
    `bytes`.
  - `web_search_started` / `web_search_completed` (category
    `search`) — emitted by the `/web_search` handler, gated on a
    truncated SHA-256 `query_hash` (the raw query is never carried
    on the ring).
- **`emit_node_event(kind, *, category, payload=None, **kwargs)`** —
  primary emitter. `payload=` is the collision-safe channel for
  payloads whose field names overlap with the function signature
  (e.g. the `scraper_pulled` event's `kind: "pages"|"bundles"`).
- **`tests/sync/test_node_log.py`** — category-filter narrowing,
  back-compat `/sync/log` still returns only `sync`, mDNS dedupe
  window, ring-failure swallow at every emit site, HTTP
  integration over `/node/log`.

### Changed
- `peer_unreachable` / `peer_reachable` are now tagged with
  `category="health"` (previously implicitly `sync`). The renderer
  distinguishes reachability state from sync wire activity.
- `GET /sync/log` is now a back-compat alias that filters
  server-side to `category=sync`. Response schema stays
  `swf.sync.log.v1`; v0.11.3 clients see no behavior change.

### Deprecated
- `swf.sync.event_log.emit_sync_event(kind, **payload)` — kept as a
  deprecated alias that auto-fills `category="sync"`. New code
  should call `emit_node_event` directly.
- `swf.sync.event_log.get_sync_events(...)` — kept as a deprecated
  alias for `get_node_events(..., categories={"sync"})`.

## [0.11.3] — 2026-05-19

### Added
- **`GET /sync/log`** endpoint (`docs/SYNC.md` §12) — read-only window
  onto an in-process sync event ring buffer. Powers the SROS renderer's
  live "network activity" feed + per-peer heartbeat pulses. Cursor
  semantics: `since_seq` (primary, monotonic), `since_ms` (fallback).
  Default limit 200, max 500. No auth — same posture as `/sync/manifest`.
- **`swf.sync.event_log`** module: 200-event ring buffer keyed by a
  hand-rolled monotonic `seq`. Emits `tick` (every sync iteration),
  `manifest_fetched` / `peer_unreachable` / `peer_reachable` (per peer),
  `pulled` (per envelope successfully applied from a remote pull), and
  `applied_local` (per `POST /sync/local_record` 201). Ring is
  per-process; restarts wipe it — it's a renderer-tail, not a journal.
- **`tests/sync/test_event_log.py`** — ring wrap, cursor filtering,
  limit caps, thread-safety smoke test, two HTTP integration tests.

### Notes
- The existing `[sync-loop] tick visited=N pulled=K applied=M` stderr
  log line is unchanged. Both pathways are useful: stderr for ops,
  ring for the renderer.

## [0.11.0] — 2026-05-19

### Added
- **`SWF_TRUST_LAN_PEERS`** env var (opt-in) — enables **LAN-trust
  mode** for single-user multi-device deployments (e.g. Shape Rotator
  OS installed on two personal laptops on the same WiFi). When set,
  the daemon:
  1. Bypasses the cohort-keys gate in `POST /sync/local_record` — the
     envelope is still self-signed by the local identity but
     `author_pubkey` is not cross-checked against `cohort-keys.json`.
  2. Relaxes single-writer-pinning in `apply_envelope`: any signed
     envelope from any author may write any `record_id`, multiple
     authors per record are accepted as a multi-writer chain, and
     no fork warnings are emitted. LWW by `wall_ts_ms` applies
     normally.
  3. Bypasses the cohort-keys whitelist on the incoming sync pull
     path (`sync_loop`) — every mDNS-discovered peer is contacted
     and every signed envelope is candidate for apply.
  - **Not bypassed**: ed25519 signature verification. Unsigned or
    tampered envelopes are still rejected with `signature_invalid`.
- **`swf.sync.is_lan_trust_mode()`** module-level helper, re-read on
  every gate check (no daemon restart required to flip the flag).
- **`docs/SYNC.md` §11** — operator-facing description: motivation,
  semantics table, security tradeoff (anyone on your LAN can write
  anything to your store), forward migration path to the planned
  multi-pubkey-per-handle cohort-keys extension.
- **`tests/sync/test_lan_trust_mode.py`** — 10 new tests covering
  truthy-value parsing, single-writer-pin relaxation, fork suppression,
  signature-verify-still-enforced, regression baselines for strict
  mode, `POST /sync/local_record` HTTP flow, and a two-peer
  integration scenario with no shared cohort-keys.

### Notes
- LAN-trust mode is **opt-in** via the env var; default behavior is
  unchanged. All 50 Phase 2 sync tests from v0.10.0 still pass
  without `SWF_TRUST_LAN_PEERS` set.

## [0.8.0] — 2026-05-02

First public release. This version is the cumulative result of the
v0.8 OSS-launch series (PRs #66 through #72).

### Added
- **`swf-node` is now the canonical name** of the binary, the package,
  and the GitHub topic. `swf-peer-server` and `swf-agent-server` stay
  as deprecated console-script aliases for one cycle.
- **CLI subcommands** for operator workflows (#69):
  - `swf-node init` — generate identity + config skeleton (idempotent;
    `--force` to rotate)
  - `swf-node doctor` — extended health check (mDNS round-trip,
    SearXNG probe, per-peer reachability)
  - `swf-node migrate` — apply additive schema migrations explicitly
  - `swf-node version` — print the installed version
- **`python -m swf`** module entry, used by the Dockerfile (#69 / #70).
- **`SWF_KNOWLEDGE_DIR`** env-var alias for the legacy
  `RA_WORLD_KNOWLEDGE_DIR` (#69).
- **`SWF_DEFAULT_SHARE_SCOPE`** env knob for the per-page `share_scope`
  populated on user-fetched pages. Default `friends` so a `--full`
  node has content to ship; set to `private` on sensitive boxes (#66).
- **`SWF_DISABLE_KNOWLEDGE_WRITE`** alias for `RA_WORLD_KNOWLEDGE=0`.
- **HTTP boundary** for agent integrations: agents call swf-node over
  HTTP (`POST /web_search`, `POST /fetch_url`, etc.) rather than
  importing modules. The companion repo
  [`research-swarm`](https://github.com/dmarzzz/research-swarm) is
  the canonical agent example.
- **`scripts/`** directory with operator + contributor entry points
  (#70): `install.sh`, `dev.sh`, `demo-2-peers.sh`, `doctor.sh`,
  `reset-state.sh`, `smoke-searxng.sh`.
- **Top-level `Dockerfile`** + **`docker-compose.yml`** (#70). Linux
  hosts use `--network host` for mDNS; macOS/Windows Docker Desktop
  is documented as best-effort.
- **`Makefile`** (#70) — `help`, `install`, `dev`, `test`, `lint`,
  `demo-2-peers`, `doctor`, `reset-state`, `smoke-searxng`, `image`,
  `clean`.
- **`examples/`** (#70) — `caddy/Caddyfile`, `nginx/swf-node.conf`,
  `systemd/swf-node.service`. Reverse-proxy snippets split peer
  routes (Ed25519-signed; safe to expose) from agent routes (require
  `Authorization: Bearer <SWF_AGENT_TOKEN>`).
- **GitHub Actions** (#68): pytest matrix on Linux + macOS × Python
  3.10/3.11/3.12, ruff lint, `swf-node --check` self-test, dependabot
  config, issue + PR templates. Release workflow publishes to PyPI
  (trusted-publishing OIDC) and GHCR (multi-arch amd64+arm64) on
  `v*` tag push. Workflow yaml lands as a manual follow-up after
  `gh auth refresh -s workflow`.
- **`SECURITY.md`** disclosure path + threat-model scope summary (#67).
- **`CONTRIBUTING.md`** dev setup + PR conventions (#67).
- **Regression test** for the `public_egress.py` direct-DDG-fallback
  silent import bug (#67).

### Changed
- **Package name** in `pyproject.toml` is now `swf-node` (was
  `searxng-wth-frnds`). The wheel is `swf_node-0.8.0-py3-none-any.whl`.
- **`__version__`** is sourced from `importlib.metadata.version("swf-node")`
  with a legacy `searxng-wth-frnds` fallback. Eliminates the prior
  0.5.0/0.7.0 drift that was leaking into `/health` and
  `/.well-known/indrex` (#67).
- **`web/*` modules moved** from `src/research_agent/web/` to
  `src/swf/web/` (#66). `swf-node` no longer imports anything from
  the `research_agent` namespace; the agent lives in its own repo.
- **Docs rewritten** for the new naming and architecture (#71): README
  leads with `pipx install swf-node` and the LAN-first scope; DESIGN
  + INDREX reference `swf/web/`; `.env.example` documents the new
  SWF_-prefixed knobs (legacy RA_-prefixed still supported).

### Fixed
- **`pages_meta` was never populated** by the user-fetched ingest path,
  which meant peer bundles always shipped zero pages (the bundle
  builder filters by `share_scope IN ('friends','public')`, and
  `LEFT JOIN` NULLs collapse to `private`). Now `swf.web.index.index_page`
  calls `migration.set_meta(...)` after the FTS insert with
  `source_type='user_fetched'`, `content_hash=<CID>`, and
  `share_scope=_default_share_scope()`. (#66)
- **`public_egress.py` direct-DDG fallback** imported
  `record_search_results` from the now-extracted `research_agent`
  namespace; surrounding `except Exception: pass` silently disabled
  search-result indexing for the SearXNG-unreachable branch added in
  PR #63. Now imports from `swf.web.index` and logs on failure
  instead of swallowing. (#67)
- **`README.md` filename** (was `ReadMe.md`); broke `pip install`
  long-description metadata on case-sensitive filesystems (#67).
- **14 test files** referenced `research_agent.web.*` in
  `monkeypatch.setattr` and `del sys.modules[...]` strings. Tests now
  pass on a fresh clone without the sibling `research-swarm` repo
  installed (#67).

### Removed
- **`src/research_agent/`** (#66 + #67) — the vendored copy of the
  standalone [`research-swarm`](https://github.com/dmarzzz/research-swarm)
  repo. The two had drifted; agent-side files were stale, and the
  `web/*` modules were swf-node infrastructure mislabeled.
- **`src/swf/agent_server.py`** (#66) — the legacy ThreadingHTTPServer
  that exposed a text-blob `/web_search` on port 7780. swf-node's
  `peer_server` already serves the SPEC v0.3 structured `/web_search`
  envelope on the same port as everything else.
- **`research-agent` and `swf-agent-server-legacy` console scripts**
  (#66 + #67) — followed the deleted code.
- **Unused base deps** `dspy`, `arxiv`, `python-dotenv` (#67) — they
  were `research_agent` artifacts.
- **`examples/seed_questions.py`** + **`schema/research-trace-v0.1.yaml`**
  (#70) — relocated to the `research-swarm` repo where their consumer
  lives.

### Migration notes
- `pip uninstall searxng-wth-frnds && pipx install swf-node` is the
  clean upgrade path. The console scripts (`swf-node`, `swf-peer`,
  `swf-peer-server`, `swf-agent-server`) are unchanged.
- If you have a populated `~/world_knowledge/index.db` from before
  the `pages_meta` fix, run `swf-node migrate` once to confirm the
  schema. Pages indexed pre-fix will not have `pages_meta` rows and
  thus won't ship in peer bundles; you can either keep them private
  (no action) or run a one-shot backfill SQL (see PR #66 for the
  pattern).
- Set `SWF_DEFAULT_SHARE_SCOPE=private` if you don't want
  newly-indexed pages auto-shared with peers.
