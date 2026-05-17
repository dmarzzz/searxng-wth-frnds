# SWF Search Router

This is the implementer's-eye-view of the search router that lives under
`src/swf/search/`. The user-facing spec is `docs/SPEC_v0.3.md`; this doc
is for people writing or reviewing the code.

If you're integrating against the HTTP API, jump to **[Calling the
router from a client](#calling-the-router-from-a-client)**.

---

## What ships

The router answers `web_search(q, policy_name="default")` from the most
private route that can satisfy the query. Every response carries
**honest path metadata** — it tells you exactly how the answer was
delivered, where the underlying data originally came from, and whether
this request touched the network. Privacy claims aren't downgraded
silently; if a cached entry came from public egress, the response says
so and emits a warning.

```
┌──────────────────────────────────────────────────────────────┐
│  POST /web_search  → swf-node :7777                          │
│                                                              │
│   ┌─────────────┐                                            │
│   │ swf.search  │  build QueryContext (HMAC, intent, freshness, sensitivity) │
│   │  .router    │  ↓                                         │
│   │             │  walk policy.route_order                   │
│   │  web_search │  ↓                                         │
│   └─────┬───────┘                                            │
│         │                                                    │
│   1. LOCAL_CACHE                ── HMAC-keyed result-bundle replay  │
│         │                          (swf.search.local_cache)        │
│         ↓                                                          │
│   2. LOCAL_INDREX               ── ~/world_knowledge/index.db FTS5 │
│         │                          (swf.search.local_indrex)       │
│         ↓                                                          │
│   3. LAN_FRIEND_DIRECT_         ── plain-HTTP fan-out to peers     │
│      PLACEHOLDER                   (swf.search.lan_friend_direct)  │
│         │                          ↑ peer side: friend_responder   │
│         ↓                                                          │
│   4. LAN_FRIEND_DCNET           ── (Phase 4 — DC-net library)      │
│         │                                                          │
│         ↓                                                          │
│   5. SELF_PUBLIC_EGRESS         ── local SearXNG + engine allowlist│
│                                    (swf.search.public_egress)      │
│                                    confirm gate via §15+§26        │
└──────────────────────────────────────────────────────────────┘

After the route returns results, every result with a provider_pubkey
gets `provider.provider_score_local` populated (Phase 5 reputation).
The router does NOT re-rank by default; clients call
`reputation.rerank()` themselves.
```

The router uses a `RouteHandler` registry: each route is one entry in
`router._HANDLERS`. New routes plug in by appending. The §11
`SearchResponse` envelope is the same regardless of which route
delivered it.

---

## The honest-path invariant

Every `SearchResponse` constructor runs `validate_invariants()`. The
spec calls these out in §29.2; in code they live at
`src/swf/search/response.py:230-...`. The hard rules:

| Invariant | What it stops |
|---|---|
| `SELF_PUBLIC_EGRESS` ⇒ `public_egress_used_this_request=true` | Public results disguised as private |
| `LOCAL_CACHE` requires non-empty `origin_paths` | Cache as origin laundromat |
| `LOCAL_CACHE` ⇒ `network_used_this_request=false` | "Cached" but actually called the wire |
| `LOCAL_CACHE` + public origin ⇒ `privacy_level=local_replay_of_public_result` | Replaying public results without the warning label |
| `LAN_FRIEND_DIRECT_PLACEHOLDER` ⇒ `privacy_level=not_anonymous_placeholder` | Dev placeholder claiming anonymity |
| `LAN_FRIEND_DCNET` ⇒ `privacy_level=anonymous_within_lan_circle_query_visible` | DCNET claiming any other privacy level |
| `LAN_FRIEND_DCNET` + ticket required ⇒ ticket accepted | Dropping the rate-limit gate |
| `local_only` ⇒ no non-local origins, no network, no public-egress flag | The big one — "I never left the device" must mean it |
| `dominant_origin_path` must be in `origin_paths` | Sanity |
| Per-result `origin_path` must be in `response.origin_paths` | Mixing in untracked origins |

Violations raise `InvariantError`. **Always construct via
`SearchResponse.make(**kwargs)` rather than `SearchResponse(...)`** —
`make()` runs the checks before returning.

---

## Module map

```
src/swf/search/
├── __init__.py            re-exports + module docstring (port-divergence note)
├── response.py            DeliveryPath / OriginPath / PrivacyLevel / Status
│                           enums; SearchResult / SearchAttempt / SearchResponse
│                           dataclasses; validate_invariants() (§29.2)
├── policy.py              frozen SearchPolicy + §29.1 consistency checks +
│                           BUILT_IN_POLICIES (§9.1–9.4)
├── query.py               QueryContext, normalization, HMAC, §10 inference
├── route.py               RouteHandler / RouteOutcome contracts
├── migration.py           pages_meta sidecar (§13.1 share_scope + sensitivity)
├── local_indrex.py        LOCAL_INDREX route — FTS5 over the existing pages
│                           table + LEFT JOIN pages_meta + page_cids
├── local_cache.py         LOCAL_CACHE route — SQLite-backed HMAC-keyed cache
│                           at ~/.local/share/swf/search_cache.db
├── public_egress.py       SELF_PUBLIC_EGRESS — local SearXNG client with
│                           explicit engine allowlist (§22.1) and honest
│                           failure-mode classification
├── lan_friend_direct.py   LAN_FRIEND_DIRECT_PLACEHOLDER — plain-HTTP
│                           fan-out to peers' /friend_search endpoint
├── friend_responder.py    server side of /friend_search — §13.3
│                           share_scope filter + §13.3 URL safety guards
├── reputation.py          §29.10 local provider scores; SQLite at
│                           ~/.local/share/swf/reputation.db; lazy decay
├── tickets.py             §27 anonymous-ticket data layer (envelopes,
│                           nullifier store, issuer-key registry; the
│                           crypto stays in `verify_signature` as
│                           NotImplementedError per §27.10)
├── sufficiency.py     §14 heuristic (min_results, unique_hosts, scores,
│                       freshness)
└── router.py          §15 orchestration: walks policy.route_order,
                        applies sufficiency, builds the SearchResponse
```

The wiring layer is `src/swf/peer_server.py`'s `POST /web_search`
handler (Phase 1 hook).

---

## Calling the router from a client

```bash
curl -s -X POST http://127.0.0.1:7777/web_search \
  -H "Content-Type: application/json" \
  -d '{"q": "differential privacy", "policy": "default", "top_k": 5}'
```

Response (truncated; see §11.1 for the full schema):

```json
{
  "schema": "swf.search_response.v1",
  "status": "ok",
  "request_id": "req_…",
  "delivery_path": "LOCAL_INDREX",
  "origin_paths": ["LOCAL_INDREX"],
  "dominant_origin_path": "LOCAL_INDREX",
  "privacy_level": "local_only",
  "network_used_this_request": false,
  "public_egress_used_this_request": false,
  "policy": {"requested": "default", "effective": "default", "routing_goal": "balanced"},
  "attempts": [
    {"path": "LOCAL_CACHE", "status": "miss", "reason": "not_in_cache", "duration_ms": 1, …},
    {"path": "LOCAL_INDREX", "status": "ok", "results_count": 3, "duration_ms": 4, …}
  ],
  "results": [
    {
      "result_id": "res_…",
      "canonical_url": "https://example.com/dp1",
      "display_url": "example.com/dp1",
      "title": "Differential privacy primer",
      "snippet": "differential «privacy» bounds tutorial",
      "score": 1.0,
      "rank": 1,
      "delivery_path": "LOCAL_INDREX",
      "origin_path": "LOCAL_INDREX",
      "safety": {"share_scope": "private", "html_sanitized": true, "url_validated": true},
      …
    }
  ],
  "debug": {"query_hmac": "hmac-sha256:…", "sufficiency": {"sufficient": true, "reason": "thresholds_met"}}
}
```

Request body fields:

| field | type | default | meaning |
|---|---|---|---|
| `q` | string (required) | — | raw query text |
| `policy` | string | `"default"` | one of `default`, `private_circle`, `local_only`, `dev_placeholder_friends` (or any custom YAML-loaded policy) |
| `top_k` | int | `10` | clamped to `[1, 50]` |
| `caller` | string \| null | `null` | opaque attribution tag, written to logs (HMAC-redacted) |
| `request_id` | string \| null | autogen | the response echoes it; clients use this for retry idempotency |
| `confirm_public_egress` | bool | `false` | client's "I really do want to send this query to the public web" flag. Required to proceed past `public_egress.mode=confirm` policies |

### The confirmation flow (§15 + §26)

Some policies (e.g. `dev_placeholder_friends`) set
`public_egress.mode=confirm`. When the router exhausts the private
routes and is about to call `SELF_PUBLIC_EGRESS`, it returns
`status=confirmation_required` instead of silently calling SearXNG.
The client must retry the same request with
`confirm_public_egress=true` to proceed.

The same status fires when a private route fails *suspiciously*
(timeout / 5xx / malformed response from SearXNG-style adapters), per
the §26 downgrade-protection table. `debug.proposed_path` names the
route the user would land on if they confirm; `debug.reason` is the
human-readable cause (`public_egress_requires_confirmation` vs
`private_route_failed_suspiciously`).

Wall behavior: render this as an explicit prompt — a soft popup or an
inline banner — never as a silent retry. The whole point of the
`confirm` mode is informed consent.

Errors:

| status | when |
|---|---|
| `400` | missing `q`, non-int `top_k`, malformed JSON |
| `200` with `status="error"` | unknown policy, empty query (the response shape itself is honest about the failure) |
| `200` with `status="no_results"` | every route exhausted, no acceptable result |
| `500` with `error` | unexpected exception in router |

The HTTP-layer 400 vs the response-shape error case is intentional: an
unknown policy is a *router* error — it can build a proper response that
documents the failure — while an empty `q` is a *protocol* error and
short-circuits before the router runs.

### Companion routes

`POST /friend_search` — peer-to-peer endpoint. Fan-out clients
(`LAN_FRIEND_DIRECT_PLACEHOLDER`) hit this on each known peer.
Request body: `{q, top_k?, qid?}`. Response: `swf.friend_search.bundle.v1`
shape with `results[]`. The responder applies §13.3
`share_scope IN ('friends','public')` + `sensitivity_label != 'high'`
filters and refuses unsafe URLs (`file://`, `localhost`, RFC1918
hosts, `.local` / `.lan` TLDs). No encryption — that's the §20.2
RESPONSE_V1 territory of Phase 4.

`POST /search_feedback` — local-only reputation bumps. Body:
`{provider_pubkey, event, notes?}`. Returns the new score. Known
events: `open`, `save`, `click_through`, `user_marked_useful`,
`user_marked_useless`, `signature_verified`, `verification_failed`,
`malformed_response`, `claim_violated`, `receipt_validated`. Wall
hooks this on user clicks/saves/explicit ratings. Local-only; never
leaves the device.

### Single-binary note

The spec (§23.1) places the router on its own port `127.0.0.1:7780`.
We host on `swf-node:7777` instead — one binary, one identity. If you're
porting this to a separate process, the only thing that changes is the
URL; the request/response shape is identical.

---

## Built-in policies

Source: `src/swf/search/policy.py` (`_build_default`, `_build_private_circle`,
`_build_local_only`, `_build_dev_placeholder`).

| name | route_order | public_egress | DCNET | placeholder | best for |
|---|---|---|---|---|---|
| `default` | LOCAL_CACHE → LOCAL_INDREX → DCNET → SELF_PUBLIC | allow | yes | no | normal browsing — try private first, fall back to public |
| `private_circle` | LOCAL_CACHE → LOCAL_INDREX → DCNET | deny | yes | no | "private mode" — never touches public engines |
| `local_only` | LOCAL_CACHE → LOCAL_INDREX | deny | no | no | air-gapped — never leaves the device |
| `dev_placeholder_friends` | LOCAL_CACHE → LOCAL_INDREX → PLACEHOLDER → SELF_PUBLIC | confirm | no | yes | local development without the DC-net stack |

Custom policies via YAML:

```yaml
search_policies:
  my_policy:
    route_order: [LOCAL_CACHE, LOCAL_INDREX]
    allow:
      local_cache: true
      local_indrex: true
      self_public_egress: false
    public_egress:
      mode: deny
    cache:
      allow_result_cache: true
      allowed_origin_paths: [LOCAL_INDREX]
    friend_query_visibility:
      allow_query_visible_to_friends: false
    anonymous_tickets:
      require_for_lan_friend_search: false
    routing_goal: privacy_first
```

Loaded with `SearchPolicy.parse_all(yaml.safe_load(...))`. The parser
runs §29.1 consistency checks; impossible combos (`route_order`
mentioning a route that's `allow`-disabled, `placeholder` enabled in a
non-`dev_*` policy, cache origins that broaden the route policy)
raise `PolicyError` at parse time.

---

## Cache semantics (the §5 invariant)

The cache is the privacy-laundering risk of the whole system. The
contract:

1. **Keyed by HMAC-of-normalized-query**, not by raw query (§24
   `raw_queries: false` default). The HMAC secret is persistent at
   `~/.config/swf/cache_secret.bin` (mode 0600), generated on first
   use with `O_EXCL`.
2. **Per-origin TTL** (§12.3): `LOCAL_INDREX` 168h, friend routes 24h,
   public 12h.
3. **`policy.cache.allowed_origin_paths` is a strict subset gate.**
   When the active policy says "only LOCAL_INDREX origins may be
   replayed," a cached entry whose origin set includes anything else
   is refused entirely — no partial replay. (We previously did
   intersection-not-subset; the red-team caught that as a laundering
   path.)
4. **On replay, `delivery_path` becomes LOCAL_CACHE and `origin_path`
   keeps the original.** §11.4 result-level metadata preserves the
   provenance.
5. **`privacy_level` is derived from origins on replay**, not from the
   stored value. A SELF_PUBLIC_EGRESS origin in a replayed entry
   forces `local_replay_of_public_result` (and a warning) regardless
   of what was stored.

If you're adding a new route in Phase 2+, the only change to the cache
is: include your new origin in the `policy.cache.allowed_origin_paths`
of any policy that wants it cacheable. The `local_cache.store()` call
inside the router is already shaped to receive arbitrary origins.

---

## Indrex semantics (§13)

The local indrex lives at `~/world_knowledge/index.db` and is owned (on
the writer side) by `research_agent.web.index`. It's an FTS5 virtual
table called `pages` plus a `page_cids` sidecar.

The spec asks for six columns on §13.1's `documents` table:
`share_scope`, `sensitivity_label`, `source_type`, `content_hash`,
`fetched_at_ms`, `deleted_at_ms`. FTS5 virtual tables don't support
`ALTER TABLE ADD COLUMN`, so we add a parallel sidecar `pages_meta(url
PRIMARY KEY, share_scope, sensitivity_label, source_type, content_hash,
fetched_at_ms, deleted_at_ms, updated_at)` and join on URL. Schema
defaults: `share_scope='private'`, `sensitivity_label='unknown'`,
`source_type='user_fetched'`; the three timestamp/hash columns are
nullable.

| column | role |
|---|---|
| `share_scope` | §13.3 friend-responder gate (`friends` / `public` only) |
| `sensitivity_label` | §13.3 friend-responder drops `high` |
| `source_type` | **chained-provenance gate** — friend responder MUST refuse `peer_ingest` rows so a curious peer can't re-broadcast someone else's archive through us. Allowed values: `user_fetched`, `peer_ingest`, `manual_import` |
| `content_hash` | §11.4 `verification.content_hash` (SHA-256 of cleaned content). LOCAL_INDREX falls back to the legacy `page_cids.content_cid` when null |
| `fetched_at_ms` | §11.4 `freshness.fetched_at_ms`; feeds the §14 staleness check |
| `deleted_at_ms` | tombstone — when non-NULL, BOTH LOCAL_INDREX and the friend responder skip the row. Deletes propagate without a vacuum cycle |

The migration is **idempotent and forward-only**. On a legacy DB that
already has the old 4-column `pages_meta`, `ensure_schema()` runs
`ALTER TABLE ADD COLUMN` for each missing extension column; existing
rows take the safe defaults (`source_type='user_fetched'`, others
NULL). Subsequent calls are no-ops.

`local_indrex.search()` does:

```sql
SELECT p.url, p.title, snippet(...), p.fetched_at, bm25(pages) AS rank,
       COALESCE(m.share_scope,       'private')      AS share_scope,
       COALESCE(m.sensitivity_label, 'unknown')      AS sensitivity_label,
       COALESCE(m.source_type,       'user_fetched') AS source_type,
       m.content_hash, m.fetched_at_ms, m.deleted_at_ms,
       pc.content_cid
FROM   pages p
LEFT JOIN pages_meta m ON m.url = p.url
LEFT JOIN page_cids  pc ON pc.url = p.url
WHERE  pages MATCH :safe_q
  AND  (m.deleted_at_ms IS NULL)
ORDER  BY rank
LIMIT  :top_k
```

The friend responder adds two more guards in its WHERE clause:
`m.source_type != 'peer_ingest'` (chained-provenance gate) and
`m.deleted_at_ms IS NULL` (tombstones).

The `pages_meta` table is created **once per (process, db_path)** at the
first search call. Subsequent calls fast-return without touching the
write lock. Don't call `_ensure_meta_table_writable_once` inside any
hot path; it's already idempotent and cached.

### Safe FTS5 query builder (§13.4)

`build_safe_fts_query(user_q)`:

1. Splits on whitespace.
2. Strips embedded `"`, leading `^`/`-`, trailing `*` from each token.
3. Wraps each cleaned token in `"…"` (FTS5 phrase).
4. AND-joins them.

So `"latest" CVE openssl 2026 OR ^foo*` becomes
`"latest" AND "CVE" AND "openssl" AND "2026" AND "OR" AND "foo"`. The
literal "OR" inside a phrase is a phrase token, not an operator.
Column-filter syntax (`title:secret`) is defanged because the colon is
inside the phrase quote.

The user can't access prefix search, NEAR groups, or column filters by
default. A "raw FTS" mode would be a future opt-in.

---

## Sufficiency

`sufficiency.check(results, ctx)` decides whether a route's result-set
is good enough or whether the router should try the next route.
Defaults from §14.1:

- `min_results = 3`
- `min_unique_hosts = 2`
- `min_top_score = 0.25`
- `min_mean_score = 0.18` (top-3)
- `require_fresh_for_freshness_queries = true`
- `allow_single_exact_hit = true` (a navigational hit at score ≥ 0.50
  short-circuits everything else)

`Sufficiency` carries a `reason` string; the router writes it into
`response.debug.sufficiency` so the wall / API client can display
*why* a fall-through happened. `freshness_not_met` is the most useful
one: a `latest cve` query falls through LOCAL_INDREX so the router can
try the next route (Phase 2 SELF_PUBLIC_EGRESS).

Score normalization uses `1 / (1 + |bm25|)` so values are in `(0, 1]`
with 1 = best (FTS5's bm25 is negative, lower-is-better; this maps
monotonically into the §11.4 score range).

---

## Phase plan

| phase | ships | status |
|---|---|---|
| 0 | data models + invariants | ✅ PR #13 |
| 1 | LOCAL_CACHE, LOCAL_INDREX, sufficiency, router, /web_search route | ✅ PR #15 |
| 2 | SELF_PUBLIC_EGRESS via local SearXNG, downgrade-confirmation | ✅ PR #16 |
| 3 | LAN_FRIEND_DIRECT_PLACEHOLDER + friend responder | ✅ PR #16 |
| 4 | LAN_FRIEND_DCNET adapter | blocked: vetted DC-net library |
| 5 | local reputation scoring + /search_feedback route | ✅ PR #17 |
| 6A | anonymous-ticket data layer (envelopes, nullifier store, issuer keys) | ✅ PR #18 |
| 6B–C | ticket issuance + redemption flow (Privacy Pass crypto) | blocked: vetted PP library |
| 6D–J | receipts, service proofs, threshold issuer | builds on 6B–C |
| 7 | side-channel review, timing audits, peer collusion sims | gates final ship |

Phases 4 and 6B+ are intentionally not shipped: spec §27.3 / §27.10 forbid hand-rolling the blind-signature primitive, and we don't have a vetted Python Privacy Pass implementation pinned yet. The data and integration surface for both is in place — `tickets.verify_signature()` raises `NotImplementedError` so a future PR landing the real crypto is a single-file swap, and the router's `_HANDLERS` dict already has a slot reserved for the DCNET handler.

---

## Tests

`tests/search/` mirrors the module layout. Coverage:

- `test_response.py` — every §29.2 invariant; happy + violation paths.
- `test_policy.py` — built-ins, parser rejections, dev-prefix gate.
- `test_query.py` — normalization, HMAC stability, intent inference.
- `test_migration.py` — sidecar schema, defaults, upsert semantics.
- `test_local_indrex.py` — FTS escape, share_scope propagation, ranking.
- `test_local_cache.py` — round-trip, miss reasons, mixed-origin block,
   secret persistence.
- `test_sufficiency.py` — every threshold + freshness path.
- `test_public_egress.py` — SearXNG response parsing, every failure-mode
   classification (timeout/5xx/malformed = suspicious; refused/4xx = benign).
- `test_lan_friend_direct.py` — friend responder share_scope filter,
   URL safety guards, multi-peer fan-out aggregation + dedup.
- `test_reputation.py` — score bumps, decay (incl. half-life math),
   bulk read, enrichment, rerank (with input-not-mutated guarantee).
- `test_tickets.py` — store/list/spend round-trip, atomic double-spend,
   nullifier vacuum, issuer-key registry, all eight rejection paths,
   verify_signature explicitly raising.
- `test_router.py` — orchestration end-to-end: cache replay, policy
   gates, confirmation flow, Phase 2/3 route wiring.

Run the search-only suite with `pytest tests/search`. The full
package suite is `pytest`.

As of Phase 6A: **153 tests in tests/search/, 298 total.**

---

## Operational notes

- **Cache file:** `~/.local/share/swf/search_cache.db` (WAL).
  `local_cache.vacuum_expired()` is safe to call from a periodic hook.
- **Cache secret file:** `~/.config/swf/cache_secret.bin` (mode 0600).
  Deleting it rotates the secret — all existing cache entries become
  unreachable until natural expiry. Useful for paranoia / forensics.
- **Indrex:** `~/world_knowledge/index.db` is shared with the agent's
  writer. The router's only writes to it are the one-time
  `pages_meta` schema bootstrap. The friend responder is the
  read-only consumer that needs to filter on `share_scope` /
  `sensitivity_label`.
- **Reputation file:** `~/.local/share/swf/reputation.db` (WAL).
  Lazy decay on `score_for`; `decay_all()` materializes drift back
  to the table on a cron-style hook. Local-only — never networked.
- **Tickets file:** `~/.local/share/swf/tickets.sqlite` (WAL).
  `vacuum_expired_nullifiers()` cleans the spent-nullifier registry
  past its retention window.
- **SearXNG dependency:** `SELF_PUBLIC_EGRESS` calls `SWF_SEARXNG_URL`
  (default `http://127.0.0.1:8888`). The route degrades gracefully
  when SearXNG isn't running — `error / searxng_unreachable` with
  `suspicious_failure=false` so the operator's "I haven't started
  docker" state isn't conflated with an attack.
- **Live SearXNG tests (TODO-14):** the mocked Phase 2 suite is the
  fast default; the opt-in live suite catches upstream JSON-shape
  drift. Run locally with
  `docker compose -f docker-compose.searxng-test.yml up -d && pytest -m searxng_live`.
  CI runs them automatically via `.github/workflows/searxng-live.yml`.
- **Friend peers:** `LAN_FRIEND_DIRECT_PLACEHOLDER` sources peer URLs
  from (in priority order): `SWF_FRIEND_PEERS` env, the live mDNS
  scraper's snapshot when `--full` is up, then `peers.yaml`.
- **Concurrency:** `ThreadingHTTPServer` lets multiple `/web_search`
  requests run in parallel. SQLite WAL handles the readers; the
  bootstrap-once pattern keeps writers off the hot path.

---

## Pointers

- Spec: `docs/SPEC_v0.3.md`
- Conflict notes: `docs/SPEC_v0.3_INTEGRATION_NOTES.md`
- Phase 0 PR: #13
- Phase 1 PR: #15
- Open architecture/red-team review: see commit message of
  `9b1c828 fix(search): address red-team + architecture review findings`.
