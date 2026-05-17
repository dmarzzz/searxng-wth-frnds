# Changelog

All notable changes to this project will be documented here. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
