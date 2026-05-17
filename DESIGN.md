# Design

## Principles

1. **Self-sovereign by default.** The daemon must work with zero API keys out of the box. Reliance on third-party search infra is a failure mode, not a feature.
2. **Reject paid intermediaries over the public web.** Exa, Tavily, Brave Search API, Google CSE, Kagi, SerpAPI — these rent-seek on top of what is already public. Not acceptable as defaults; not shipped at all.
3. **API keys only when data is irreplaceable.** Two explicit exceptions: **GitHub** (unique code and activity signals) and **Twitter/X** (unique real-time discourse). And even for Twitter, prefer self-hostable **Nitter** before the Twitter API itself.
4. **Open source always beats proprietary**, even at a quality delta. Sovereignty > recall.
5. **Every crawl accumulates durable local state.** Every fetched page writes through to `world_knowledge/` so the knowledge base grows. Callers prefer local lookup before going online.
6. **Build toward the Vitalik-style local stack.** The North Star is the April 2026 self-sovereign LLM setup: local model as the default handler, remote resources used sparingly and privately.

## Architecture

```
src/swf/                                  swf-node — the daemon
├── peer_server.py                          HTTP entry; subcommand dispatch
├── peer_scraper.py                         pull bundles from peers + verify
├── peer_cli.py                             `swf-peer add / list / discover / …`
├── discovery.py                            python-zeroconf + Tailscale + peers.yaml
├── identity.py                             Ed25519 keypair + signed handshake
├── canonical.py                            URL canonicalization (RFC 3986 + tracking-strip)
├── cid.py                                  IPFS CIDv1 over cleaned content
├── fanout.py                               local + friends + DDG merger
├── indrex.py                               FTS5 query primitive (single source of truth)
├── indrex_graph.py                         /graph node+edge snapshot
├── event_bus.py                            SSE event stream for /events
├── slice.py / slice_consume.py             signed slice exchange (peer bundle)
├── search/                                 SPEC v0.3 router stack
│   ├── route.py / router.py                  cache → local → public path selection
│   ├── policy.py                             per-policy public_egress / privacy decisions
│   ├── local_indrex.py                       LOCAL_INDREX adapter
│   ├── local_cache.py                        LOCAL_CACHE FTS5
│   ├── public_egress.py                      SearXNG primary + DDG-direct fallback
│   ├── lan_friend_direct.py                  LAN_FRIEND_DIRECT_PLACEHOLDER
│   ├── lan_friend_dcnet.py                   LAN_FRIEND_DCNET (anonymous tickets)
│   ├── friend_responder.py                   /friend_search handler
│   ├── migration.py                          additive `pages_meta` schema migrations
│   ├── audit.py / response.py / sufficiency.py  envelope, invariants, sufficiency calc
│   └── tickets.py / receipts.py              §17 ticket flow, §16 receipt flow
├── web/                                    fetch / crawl / index / providers
│   ├── fetch.py                              trafilatura → Jina Reader fallback
│   ├── crawl.py                              extract_links, fetch_urls_parallel
│   ├── providers.py                          DDG / Nitter / SearXNG fan-out
│   ├── knowledge.py                          ~/world_knowledge/ write-through
│   └── index.py                              FTS5 writer (pages + pages_meta + page_cids)
└── community_full/                         `--full` mode: metrics, slice agg, dcnet
```

The agent layer (DSPy ReAct loops, prompt templates, critic passes)
lives in a separate repo, [`research-swarm`](https://github.com/dmarzzz/research-swarm).
Agents talk to swf-node over HTTP — never via in-process imports.

## Search provider stack

Priority order (all optional, all work without a key):

| Provider | Role | Requires |
|---|---|---|
| **SearXNG** | Primary. Meta-search over Google/Bing/etc. anonymized. | `SEARXNG_URL` env var — point at self-hosted (`docker-compose up`) or public instance |
| **DDG** | Free fallback. Always available. | nothing (via `ddgs`) |
| **Nitter** | Twitter/X search without Twitter API. | `NITTER_URL` env var — self-host or public instance |

Fan-out mode (default): all configured providers run in parallel, results merge-deduped. First-hit mode (`RA_SEARCH_MODE=first`) stops at first non-empty.

**Not shipped:** Tavily, Brave API, Exa, Google CSE, Kagi.

## Fetch layer

Two-tier extraction so Jina is a fallback, not a dependency:

1. **Primary: trafilatura.** Local HTML → clean markdown. OSS. No network dependency beyond the page itself.
2. **Fallback: Jina Reader (r.jina.ai).** Only used when trafilatura returns empty (complex SPAs, paywalls, PDFs).

Both cached on disk (`.ra_cache/fetch/`, 7-day TTL). Both also write-through to `world_knowledge/`.

## Knowledge accumulation

Every successful fetch writes to:
```
~/world_knowledge/web/<domain>/<yyyy-mm-dd>-<slug>.md
```

File frontmatter:
```yaml
---
url: https://vitalik.eth.limo/general/2026/04/02/secure_llms.html
title: My self-sovereign / local / private / secure LLM setup
fetched_at: 2026-04-18T13:02:00-04:00
content_hash: sha1:...
extractor: trafilatura  # or 'jina'
---
```

Path defaults to `~/world_knowledge/` but configurable via `RA_WORLD_KNOWLEDGE_DIR`.

## Local index

SQLite FTS5 at `~/world_knowledge/index.db`:

```sql
CREATE VIRTUAL TABLE pages USING fts5(
    url UNINDEXED,
    title,
    content,
    fetched_at UNINDEXED
);
```

New tool: `local_search(query)`. Agent-facing behavior:

- Runs this first on every research pass.
- Only falls out to `web_search` if local results are thin or stale.

The dream: after ~months of accumulated use, the agent answers most questions without ever touching the network.

## TODO

- **Raw HTML archival.** Currently cache only the cleaned markdown. Parallel full-HTML archive per page would let us re-extract with better tools later and keep an offline-replayable copy.
- **Periodic re-indexing.** `pages` table rebuild from `world_knowledge/web/` on demand.
- **Local embedding index.** FTS5 gives keyword search; an optional embedding index (e.g. sqlite-vec) would enable semantic-similar retrieval.
- **Nitter instance health-check + rotation.** Public instances fail often. Ship a list and auto-rotate.
- **SearXNG docker-compose.** Ship a one-liner so non-docker-native users can get it running.

## Deprecated (from earlier rounds)

These were shipped in R2 and no longer default-registered in `build_agent`. Functions remain callable for edge cases; consolidated behind `web_search site:<domain>` plus the reranker:

- `hackernews_search`
- `reddit_search`
- `wikipedia_search`
- `ethresear_search`

Kept:
- `arxiv_search`, `arxiv_fetch_paper` — bounded academic domain, proper case for a direct API.
- `semantic_scholar_search` — same rationale; free at our use volume.
- `github_search` — explicit key exception.
