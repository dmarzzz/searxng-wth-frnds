# HTTP API reference

Every endpoint is served by `swf-node` on a single port (default
`127.0.0.1:7777`). Auth split:

- **Peer routes** — `/.well-known/indrex`, `/search`, `/index/cursor`,
  `/index/pages`, `/digest/urls`, `/slices/*`, `/community/*`. Responses
  are Ed25519-signed; consumers TOFU-pin pubkeys. No bearer required.
- **Agent routes** — `/web_search`, `/local_search`, `/fetch_url`,
  `/fetch_urls`. When `SWF_BIND` is non-loopback, these require
  `Authorization: Bearer ${SWF_AGENT_TOKEN}`.
- **Aggregator routes** — `/graph`, `/events`, `/metrics/snapshot`,
  `/metrics/series`. Read-only; no auth on the daemon side. Reverse-proxy
  if you expose them publicly.

All POST bodies are JSON. All responses are JSON unless otherwise
noted (SSE for `/events`).

## Health + introspection

### `GET /health`

Liveness probe. Always 200 if the daemon is running.

```json
{"ok": true, "version": "0.8.0"}
```

### `GET /.well-known/indrex`

Signed handshake doc. Other peers fetch this to learn your pubkey and
capabilities.

```json
{
  "name": "alice-mbp.lan",
  "version": "0.8.0",
  "protocol": "searxng-wth-frnds/v0.4",
  "capabilities": ["search", "signed-handshake"],
  "stats": {"pages": 930, "cached_urls": 10572},
  "pubkey": "_whbFQ1xew2…",
  "fingerprint": "6d4a982cabc9751e",
  "ts": "2026-05-02T14:11:01Z",
  "sig": "sJClMJjlt6T…",
  "body_hash": "puwctAk5T…"
}
```

## Search (agent surface)

### `POST /web_search`

The full router. Walks LOCAL_CACHE → LOCAL_INDREX → LAN_FRIEND_DCNET
(if enabled) → SELF_PUBLIC_EGRESS depending on policy + sufficiency.
Returns the SPEC v0.3 §11 envelope.

**Request:**
```json
{
  "q": "animal communication",
  "policy": "default",
  "top_k": 10,
  "caller": "research-swarm",
  "request_id": "req_abc123",
  "confirm_public_egress": false
}
```

**Response (abridged):**
```json
{
  "schema": "swf.search_response.v1",
  "status": "ok",
  "delivery_path": "LOCAL_INDREX",
  "origin_paths": ["LOCAL_INDREX"],
  "privacy_level": "local_only",
  "network_used_this_request": false,
  "results": [
    {
      "result_id": "res_…",
      "canonical_url": "https://plato.stanford.edu/entries/animal-communication",
      "title": "Animal Communication",
      "snippet": "…",
      "score": 0.39,
      "rank": 1,
      "delivery_path": "LOCAL_INDREX",
      "origin_path": "LOCAL_INDREX",
      "freshness": {"fetched_at_ms": 1777110858818},
      "verification": {"content_hash": "bafkreigklzj27cefig5zr…"},
      "safety": {"share_scope": "friends"}
    }
  ],
  "attempts": [
    {"path": "LOCAL_CACHE", "status": "miss", "duration_ms": 3, ...},
    {"path": "LOCAL_INDREX", "status": "ok", "results_count": 5, "duration_ms": 56, ...}
  ]
}
```

Errors return `{"error": "<message>"}` with HTTP 400 (validation),
401 (auth), 413 (oversize body), 500 (unhandled).

### `POST /local_search`

Local indrex only; no network. Same envelope as `/web_search`.

### `POST /search` (legacy alias)

Deprecated alias of `/local_search`. Returns the SPEC envelope.

### `POST /friend_search`

The friend-responder side: when *another* peer's `/web_search`
escalates to `LAN_FRIEND_DIRECT_PLACEHOLDER` or `LAN_FRIEND_DCNET`,
they hit this endpoint on you. Filters to `share_scope IN ('friends','public')`
and skips `sensitivity_label='high'` rows. See SPEC §21.

## Fetch (agent surface)

### `POST /fetch_url`

Fetch a single URL through swf-node's pipeline (cache → trafilatura →
Jina Reader fallback). Writes through to `world_knowledge/` and
indexes into FTS5.

**Request:**
```json
{"url": "https://example.com/page", "start_char": 0, "max_chars": 16000}
```

**Response:** plain-text markdown (the cleaned content), preceded by
a one-line metadata header `[fetch_url offset=0 total=N extractor=trafilatura]`.

### `POST /fetch_urls`

Same idea, batched. Body: `{"urls": [...], "max_chars_each": 6000}`.
Response is a concatenation of per-URL blocks with separators.

## Peer protocol

### `GET /index/cursor`

Returns the high-water cursor of this peer's `/index/pages` stream.

```json
{"cursor": 931, "epoch_id": "638c85ce86ae4136a4a4c2222dade08f"}
```

`epoch_id` rotates whenever the indrex DB is rebuilt; consumers reset
their pull cursor to 0 when it changes (P2P-review #2).

### `GET /index/pages?since=N&limit=M`

The signed bundle a consumer pulls.

**Response:**
```json
{
  "schema": "swf.index_pages.v1",
  "pubkey": "<producer pubkey>",
  "since": 0,
  "until": 5,
  "epoch_id": "638c…",
  "pages": [
    {"url": "...", "title": "...", "host": "...", "topic": "",
     "fetched_at": "2026-04-18T14:16:33", "content_cid": "bafkr…"}
  ],
  "merkle_root": "<hex>",
  "sig": "<base64>"
}
```

Filter: only rows with `share_scope IN ('friends','public')`,
`source_type != 'peer_ingest'`, `deleted_at_ms IS NULL`. Empty `pages`
arrays are still signed and ship — the cursor advances regardless of
whether anything was shareable in the window.

### `GET /digest/urls?recipient_pk=<base64>`

Bloom-filter URL-membership digest, salted per recipient. Used by the
opportunistic-pull machinery to skip overlap before paying the bundle
round-trip.

### `GET /slices/head` / `GET /slices/<seq>`

Aggregator slice exchange. `--full` mode only.

### `POST /community/slice`

`--full` mode: peers push slice updates here. Aggregator-only.

## Aggregator routes (`--full` mode)

### `GET /graph?lens=topic`

Node + edge JSON for the network-view UI. Joins `pages_meta` for
attribution + the `peers` table for nickname/color.

```json
{
  "nodes": [
    {"id": "https://...", "title": "...", "host": "...",
     "topic": "", "source_pubkey": "<pubkey>",
     "source_label": "self" | "alice", ...}
  ],
  "edges": [...]
}
```

### `GET /events?since=<event_id>`

Server-sent event stream. Each line is one event:

```
event: peer_pull_started
data: {"pubkey": "ZsrmcGVVt3o0…", "nickname": "alice", "since": 4}

event: peer_pull_completed
data: {"pubkey": "ZsrmcGVVt3o0…", "stored": 0, "until": 4}
```

Replays history from `events` table on `?since=N`, then streams live.

### `GET /metrics/snapshot`

```json
{
  "ts_ms": 1777731052699,
  "values": {
    "process.cpu_percent": 0.3,
    "process.rss_bytes": 335953920.0,
    "process.num_fds": 130.0,
    "peers.count_known": 1.0,
    "peers.count_active": 1.0,
    "pages.count_total": 930.0,
    "events.lag_secs": 0.7,
    "web_search.total": 42.0,
    "web_search.errors": 0.0,
    "slice_scrape.total": 12.0,
    "slice_scrape.errors": 0.0
  }
}
```

### `GET /metrics/series?names=...&from=<ms>&until=<ms>&step=<ms>`

Time-bucketed series for the metrics tab. Caps span × step so a
malicious caller can't bucket months of data into 1ms steps.

## Search-feedback (reputation)

### `POST /search_feedback`

Internal; called by the search router after a result is accepted /
rejected by the user. Bumps `provider_scores` rows.

## Admin

### `POST /admin/peers/trust`

Set `trust_level` on a peer. Only honored when `SWF_ENABLE_PEER_TRUST=1`.

### `GET /admin/pending` / `GET /admin/peers`

Removed in #43 PR C. Returns 410 with a deprecation note for old
clients.

## Auth: how the bearer is checked

For loopback binds (`SWF_BIND=127.0.0.1`), agent routes accept any
caller. For non-loopback binds:

1. If `SWF_AGENT_TOKEN` is unset, the daemon refuses to start.
2. On each agent-route request, the daemon compares
   `request.headers["Authorization"]` against `Bearer ${SWF_AGENT_TOKEN}`
   in constant time.
3. Mismatch → 401.

Peer routes never require the bearer.
