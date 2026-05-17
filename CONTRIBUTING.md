# Contributing to swf-node

Thanks for thinking about contributing. swf-node is small and the bar
for being useful here is low.

## Quick start

```bash
git clone https://github.com/dmarzzz/searxng-wth-frnds
cd searxng-wth-frnds
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,community-full]'
pytest -q                       # ~25s, 600+ tests, mock-only
swf-node --check                # self-test (DB schema, identity, mDNS)
swf-node                        # start the daemon on 127.0.0.1:7777
```

The `dev` extra pulls `pytest`, `pytest-cov`, and `ruff`.
`community-full` pulls `pynacl` for the aggregator-mode dcnet
primitives — only needed if you're running with `--full`.

## Running tests

```bash
pytest -q                       # default: skips searxng_live + slow markers
pytest -q -m searxng_live       # also runs tests that need a real
                                 # SearXNG container (see
                                 # docker-compose.searxng-test.yml)
pytest -q -m integration        # multi-peer wire-protocol tests
pytest -q -k "fanout"           # match by name substring
```

There is a HOME-isolation autouse fixture in `tests/conftest.py` so
running pytest never touches your real `~/.config/swf/` or
`~/world_knowledge/`. If a test fails for you on a fresh checkout,
that's a bug worth reporting.

## Pull requests

- **One topic per PR.** Refactors and feature work go in separate PRs.
- **Conventional commit prefix on the PR title:** `feat(p2p):`,
  `fix(search):`, `refactor(web):`, `docs:`, `chore:`, `test:`. The
  GitHub repo squash-merges, so the PR title becomes the commit
  message.
- **Run `swf-node --check` before opening a PR.** It catches schema
  drift and missing identity files faster than a CI roundtrip.
- **Run `ruff check src/ tests/`** if you have ruff installed. CI
  will, so no surprise.
- **Tests for behavior changes.** If you fix a bug, write the test
  that would have caught it. The two recent cases (PR #66's
  pages_meta gap, PR #67's public_egress import) both shipped with
  regression tests for exactly this reason.
- **No drive-by formatting.** If you reformat unrelated lines, split
  the formatting into its own PR so the meaningful diff stays
  readable.

## What `swf-node --check` does

It's a self-test that verifies:

- `~/.config/swf/identity.key` exists and is mode 0600
- `~/world_knowledge/index.db` is reachable and on a current schema
- mDNS registration round-trips (we can hear our own broadcast)
- if `SEARXNG_URL` is set, that endpoint answers

Exit code `0` means ready-to-run. Anything else dumps the failing
check to stderr.

## Architecture

The single source of truth lives in three docs:

- `INDREX.md` — the local-indrex spec (FTS5 layout, `pages_meta`,
  `share_scope` policy).
- `DESIGN.md` — system architecture and module boundaries.
- `docs/SPEC_v0.3.md` — the wire-protocol surface (peer bundles,
  Ed25519 signing, mDNS service type, HTTP endpoints).

If you're touching peer-protocol code, read `docs/SPEC_v0.3.md` first.

## Common patterns

- `from swf.search import migration` — schema bootstrapping. Runtime-
  applied on every connection that opens `indrex.db` for write. Add
  columns via `ALTER TABLE`, never with non-additive changes.
- `from swf.event_bus import emit` — append a structured event to
  `events` for the `/events` SSE stream and the network-view UI.
- `from swf.web.index import index_page` — the only sanctioned way
  to write to the `pages` FTS5 + `pages_meta` + `page_cids` triple.
  See PR #66 for why.

## Reporting bugs

Open a GitHub issue with:

1. The output of `swf-node --check`.
2. The version: `swf-node version`.
3. What you expected to happen vs. what happened.
4. The minimum reproduction (a couple of `curl` lines or a small
   script is enough).

Security-relevant reports go to `SECURITY.md`'s disclosure path, not
the public issue tracker.
