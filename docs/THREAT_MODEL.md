# Threat model — per-module STRIDE

## Executive summary

If you run `swf-node` on your LAN at a hackerspace, what's the worst
case? Roughly:

**The daemon protects:**

- *Provenance.* You can't be tricked into believing a public-web result
  came from local indrex (or a friend) — every result carries a
  `delivery_path` + `origin_paths` pair that the response-construction
  guard validates (§29.2). A silent public downgrade is the canonical
  thing this codebase is designed to prevent.
- *Public-egress consent.* Queries don't fall back to SearXNG (or DDG-direct)
  unless the policy explicitly allows it; tools like the agent-server
  surface a `confirmation_required` envelope when policy + sufficiency
  signal a privacy downgrade.
- *Peer-bundle authenticity.* Every `/index/pages` bundle is Ed25519-
  signed and the consumer verifies the merkle root + signature before
  ingesting. Pubkeys are TOFU-pinned via `swf-peer add`; subsequent
  rotations invalidate the trust until you re-add.
- *Query HMAC in logs.* Raw queries don't appear in `events` /
  `audit.log`; they're hashed with `SWF_QUERY_HMAC_SECRET` so an
  attacker reading state files can't reconstruct what you searched.

**The daemon does NOT protect:**

- *Host compromise.* If your laptop is rooted, your identity key and
  `~/world_knowledge` are gone. swf-node has 0600 on the key file and
  that's the limit.
- *Hostile LAN majority.* Trust is per-peer TOFU; if every peer you've
  added is malicious, swf-node's machinery is doing exactly what you
  told it to.
- *Traffic-analysis from a network observer.* Packet sizes and
  timings are not blinded. mDNS broadcasts your existence to anyone
  on the same broadcast domain.
- *DoS from a single LAN peer.* PR #62 added scoring + pruning, but
  if a peer can saturate your link, they can saturate your link.
- *Malicious agent (your own).* `/web_search` will issue whatever the
  caller asks; if your agent is compromised, swf-node faithfully
  serves the compromise.

The rest of this doc is the per-module STRIDE table for reviewers
auditing specific code paths.

---

Companion to `SPEC_v0.3.md` §7. The spec describes the threat model in
prose; this doc maps each module under `src/swf/search/` to the specific
threats it answers, in STRIDE form (Spoofing, Tampering, Repudiation,
Information Disclosure, Denial of Service, Elevation of privilege).
Empty rows are omitted — most modules have a small attack surface and
don't carry every STRIDE leg.

**In scope** (§7.1, lines 218–228 of the spec):

- Silent public downgrade: a query must never fall back to public egress
  without metadata or required confirmation.
- Result provenance confusion: cached public results must not be
  re-labeled as `local_only`.
- LAN requester identification: the real DC-net path must hide which
  active peer issued a query (Phase 4; not yet shipped).
- Query spam against friend responders: tickets gate the DC-net path.
- Receipt spam: positive receipts must be scarce + one-time-use.
- Malformed peer responses: invalid, oversized, or unverifiable peer
  output is rejected, not relayed.
- Provider archive leakage: friend responders search only shareable
  rows, never the full private archive.

**Out of scope** (§7.2, lines 230–240): host compromise, browser
compromise, local malware, query privacy from friend peers (§7.3:
DCNET hides *who* asked, not *what*), provider anonymity, WAN
anonymity, global sybil resistance, malicious majority of LAN peers,
and colluding receipt inflation beyond quota limits.

Mitigations cite the commit they shipped in (`git log --oneline`
short SHA + the merge PR number where applicable). The reference
spec is `docs/SPEC_v0.3.md`; line numbers below are against that
file.

---

## `response.py` — envelope dataclasses + §29.2 invariants

| Threat | Mitigation | Where |
|---|---|---|
| **Tampering** (mislabeling): a delivery path is constructed inconsistent with its origin (e.g. `LOCAL_CACHE` with no `origin_paths`, or `LAN_FRIEND_DCNET` not labeled `anonymous_within_lan_circle_query_visible`) — directly addresses §7.1 "result provenance confusion" + "silent public downgrade". | `validate_invariants()` runs on every `SearchResponse.make(...)` and refuses to construct an envelope that breaks the §29.2 rules. The §6 privacy-level → origin-path coupling is enforced (e.g. `local_only` rejects any non-local origin, the symmetric `public_egress_used_this_request` ↔ `SELF_PUBLIC_EGRESS` check, the cache-replay-of-public-result rule). | `response.py:209-336`; shipped in `6fe2a7a` (Phase 0); symmetric egress check added in `e84eb34` (red-team pass-2, PR #22); construction guard in `57a1e34` (PR #25, TODO-10). |
| **Information disclosure** (downstream): a peer- or web-supplied string is rendered as HTML by a UI without escaping. | All result string fields are explicitly marked untrusted in the docstring; `safety.html_sanitized` is a UI signal, not a security gate. The doc on `SearchResult` (line 118) names the contract. | `response.py:117-118`. |
| **Repudiation**: an operator denies that a query went out to the public web. | `origin_paths` and `public_egress_used_this_request` are part of the response; the invariant pair forces `SELF_PUBLIC_EGRESS` to appear in `origin_paths` whenever the flag is set, so the audit trail can't be silently dropped on `NO_RESULT`. | `response.py:253-258`; shipped in `e84eb34`. |

## `policy.py` — policy parser + §29.1 consistency

| Threat | Mitigation | Where |
|---|---|---|
| **Elevation** (config): a non-`dev_*` policy enables `lan_friend_direct_placeholder` and silently runs the unauthenticated transport in production. | `_check_consistency` rejects placeholder transport unless the policy name is `dev` or `dev_*`. Underscore-anchored prefix (red-team #3): `developer`, `devops` don't slip through. | `policy.py:196-203`; shipped in `9b1c828`. |
| **Tampering**: route order in policy YAML places `SELF_PUBLIC_EGRESS` before all private routes, defeating §15's "private routes first" rule and the §26 confirmation gate. | Consistency check refuses any `route_order` where `SELF_PUBLIC_EGRESS` precedes every private route. | `policy.py:229-251`; red-team finding #4, shipped in `e84eb34`. |
| **Information disclosure** (cache laundering): `cache.allowed_origin_paths` is broader than the policy's allowed routes, so the cache layer would replay results from a route this policy bans (e.g. cached public-egress results survive a switch to `private_circle`). | Consistency check refuses cache origin paths whose corresponding `allow.*` flag is false; also bans `LOCAL_CACHE`/`NO_RESULT`/`MIXED` from `cache.allowed_origin_paths`. | `policy.py:255-279`. |
| **Tampering**: `public_egress.mode=allow` combined with `allow.self_public_egress=false` is a contradiction the operator probably didn't mean. | Rejected at parse time with an explicit message. | `policy.py:206-211`. |

## `query.py` — QueryContext, normalization, HMAC

| Threat | Mitigation | Where |
|---|---|---|
| **Information disclosure** (logs): raw query strings appear in cache rows, audit events, and access logs. §24 says `raw_queries: false` by default. | `hmac_query()` returns an HMAC-SHA256 prefixed `hmac-sha256:...`; the cache key is the HMAC, the query-id reported in debug + audit is the HMAC. Per-process random secret by default — log entries within one `swf-node` lifetime can be joined, but plaintext does not survive a process restart. Persistent caches inject their own stable secret loaded from a 0600 file (see `local_cache.py`). HTTP access-log redaction is shipped separately in `20af8f7`. | `query.py:97-125`. |
| **Spoofing** (request id collisions): two concurrent requests collide on the request id, allowing one's audit data to be attributed to another. | `make_request_id()` uses 13 bytes (104 bits) of `secrets.token_hex` plus a time-prefixed convention so logs sort by creation time without collisions. | `query.py:177-183`. |

## `local_cache.py` — HMAC-keyed result-bundle cache

| Threat | Mitigation | Where |
|---|---|---|
| **Information disclosure** (cache laundering): a tightened policy (e.g. `private_circle`) replays a result that a previous looser policy stored from public egress. Directly addresses §7.1 "result provenance confusion". | `lookup()` does a strict subset check — every cached origin must be in `policy.cache.allowed_origin_paths` or the row is treated as a miss. Per-result origin double-check after rebuild as belt-and-suspenders. | `local_cache.py:198-223`; red-team finding #2, shipped in `9b1c828`. |
| **Information disclosure** (secrets at rest): the cache HMAC secret ends up world-readable on disk. | `_load_or_create_secret()` uses `O_EXCL` + mode 0600 on first create; on read, it auto-repairs any non-0600 mode it finds. | `local_cache.py:74-109`; red-team #5/#6, shipped in `9b1c828`. |
| **Tampering** (cross-policy origin TTL): a multi-origin cache row outlives any individual origin's TTL. | `store()` takes the **shortest** per-origin TTL when `origin_paths` is mixed; stops 168h `LOCAL_INDREX` rows from carrying co-resident 24h friend rows. | `local_cache.py:251-262`; red-team pass-3 finding B, shipped in `4eca278`. |
| **Information disclosure** (rep score persistence): §29.10 requires reputation scores stay local; serializing a result with `provider.provider_score_local` populated would persist them in `results_json` and out to backups. | `_serialize_result()` strips `provider_score_local` before write; the router re-enriches from live `reputation.db` on cache replay. | `local_cache.py:294-319`; red-team pass-3 finding A, shipped in `4eca278`. |
| **Tampering** (malformed cache rows): a corrupt row (bad JSON, unknown enum value) crashes the lookup or returns garbage. | Each parse step is fenced; one bad result row is dropped without poisoning the rest of the entry. | `local_cache.py:185-223`. |
| **Denial of service** (disk growth): the cache file grows unboundedly under a long-running reader because SQLite's auto-checkpoint is skipped. | `vacuum_expired()` issues `PRAGMA wal_checkpoint(TRUNCATE)` after the DELETE so the on-disk file is reclaimed. | `local_cache.py:344-364`; resource audit F3/F4, shipped in `4eca278`. |

## `local_indrex.py` + `migration.py` — LOCAL_INDREX search + sidecar metadata

| Threat | Mitigation | Where |
|---|---|---|
| **Elevation** (FTS injection): a hostile query exploits FTS5's boolean / NEAR / column / prefix syntax to bypass the user's intended scope. | `build_safe_fts_query()` strips embedded `"`, leading `^`/`-`, trailing `*` and AND-joins phrase-quoted tokens; the FTS5 advanced surface is never exposed by default. §13.4. | `local_indrex.py:38-59`. |
| **Information disclosure** (no row by default is shareable): a fresh DB without `pages_meta` could leak `private` rows to friends if the friend responder didn't gate. | The migration defaults `share_scope='private'` + `sensitivity_label='unknown'` for every existing page. The friend responder uses an `INNER JOIN` so missing-meta rows are invisible to peers; `local_indrex` itself uses `LEFT JOIN` because the local user is allowed to search their own private archive. | `migration.py:30-39`; `local_indrex.py:70-86`; `friend_responder.py:148-166`. |
| **Denial of service** (writer contention on hot search path): every search call took the writer lock to `CREATE TABLE IF NOT EXISTS pages_meta`, racing with the indexer. | One-shot bootstrap per (process, db_path) keyed in `_meta_bootstrap_done`; subsequent calls fast-return without taking the write lock. | `local_indrex.py:218-247`; architecture review #6/#8, shipped in `9b1c828`. |
| **Tampering**: caller passes a non-existent DB path. | `search()` returns `IndrexResultSet([], status="no_indrex")` — silent miss, never an exception that crashes the router. | `local_indrex.py:140-142`. |

## `sufficiency.py` + `router.py` — route walker + §14 sufficiency + §15 + §26

| Threat | Mitigation | Where |
|---|---|---|
| **Tampering** (silent public downgrade): the router falls through to `SELF_PUBLIC_EGRESS` without metadata or confirmation. Directly addresses §7.1 "silent public downgrade". | (a) `policy.public_egress.mode=confirm` returns `Status.CONFIRMATION_REQUIRED` before running the public route; the client must retry with `confirm_public_egress=true`. (b) When a private route fails *suspiciously* (timeout, malformed response — see `public_egress` + `lan_friend_direct`), the router escalates to `confirmation_required` even if `mode=allow`, per §15 + §26. | `router.py:151-187`. |
| **Repudiation**: a `NO_RESULT` reply silently consumes a public-egress flag without disclosing it. | When any attempt sets `public_egress_used`, the final `NO_RESULT` response includes `SELF_PUBLIC_EGRESS` in `origin_paths`. | `router.py:196-201`; live fuzz F5, shipped in `e84eb34`. |
| **Information disclosure** (rep score → cache): `_maybe_cache` would store enriched results including `provider_score_local`. | Reputation enrichment happens in `_build_response`, AFTER the call to `_maybe_cache`, and the cache strips it on serialize anyway (see `local_cache.py`). | `router.py:160-171,254-260`. |
| **Tampering** (sufficiency floor): too-permissive thresholds make `LOCAL_INDREX` fire for navigational queries that should reach the web. | Sufficiency uses both score and source-diversity floors (`min_unique_hosts=2`, `min_top_score=0.25`, `min_mean_score=0.18`); freshness-required queries on `LOCAL_INDREX` always fail until Phase 2 attaches `served_at_ms`. | `sufficiency.py:18-99`. |
| **Spoofing** (unknown policy): caller asks for a policy name that doesn't exist; default falls through. | `web_search` returns an explicit `Status.ERROR` envelope with the policy name that was requested; never silently substitutes `default`. | `router.py:120-123,380-412`. |

## `public_egress.py` — SELF_PUBLIC_EGRESS via local SearXNG (§22)

| Threat | Mitigation | Where |
|---|---|---|
| **Information disclosure** (engine fanout): SearXNG's default engine list silently includes engines we don't trust. | Explicit `DEFAULT_ENGINES = ("duckduckgo", "brave")`, passed in the query string on every request. The §22 rule "never front a third-party SearXNG" is enforced by the absence of any `network_mode=external_searxng` adapter. | `public_egress.py:38-41`. |
| **Elevation** (SSRF via SearXNG): a misbehaving engine returns `javascript:`, `file://`, `data:`, localhost, or RFC1918 URLs that the router would relay as "public" results. | Every row passes through `friend_responder._is_safe_url`; unsafe rows are silently dropped. The `safety.url_validated=True` claim is preserved for the rest. | `public_egress.py:178-184`; red-team #2, shipped in `e84eb34` (PR #22). |
| **Denial of service** (response amplification): a hostile/misconfigured SearXNG returns a 100 MB JSON body and balloons RSS. | Hard cap `MAX_SEARXNG_BYTES = 2 MiB`; the read takes one byte past the limit to detect overrun and rejects as `upstream_response_too_large` + `suspicious=true`. | `public_egress.py:46,118-130`; resource audit F2, shipped in `4eca278`; body cap added to friend route too in `57a1e34` (TODO-5). |
| **Tampering** (suspicious downgrade): a transient SearXNG outage looks like an attacker forcing public egress. | The handler distinguishes benign "SearXNG not running" (Connection refused → `suspicious=False`) from suspicious states (timeout, 5xx, malformed response → `suspicious=True`); the router uses that to decide whether to require confirmation per §26. | `public_egress.py:131-167`. |
| **Information disclosure** (privacy_level Tor mismatch): code currently labels every successful run `public_from_self`. We must not label `public_from_self_tor` until a Tor SOCKS adapter + DNS-leak self-test ships (see TODO-7). | Single source for `PrivacyLevel.PUBLIC_FROM_SELF` here; no code path yet writes the `_TOR` variant. | `public_egress.py:223`; TODO-7 owns the upgrade. |

## `lan_friend_direct.py` + `friend_responder.py` — LAN_FRIEND_DIRECT_PLACEHOLDER (§17 / §21)

| Threat | Mitigation | Where |
|---|---|---|
| **Information disclosure** ("provider archive leakage", §7.1): a friend asks us a query and we return a row from our private archive. | `friend_responder._PAGES_SQL` uses `INNER JOIN pages_meta` with `share_scope IN ('friends','public')` and excludes `sensitivity_label='high'`. Private rows are physically excluded by SQL, not by post-filter. | `friend_responder.py:148-166`. |
| **Elevation** (SSRF): a peer crafts a row with a private-LAN URL (or hex-encoded loopback IP, or a hostname that resolves to localhost) and we relay it back to the asking peer. | `_is_safe_url` rejects non-http(s) schemes, literal `localhost`, RFC1918 / link-local / loopback / multicast / reserved IPs in every numeric obfuscation form (decimal int, hex, octal, IPv4-mapped IPv6, IPv6 link-local), `.local` / `.lan` / `.internal` / `.intranet` / `.corp` / `.home` TLDs, and percent-encoded private literals. Optional `SWF_SSRF_STRICT_DNS=1` turns on `getaddrinfo` resolution check (off by default to avoid breaking flaky-DNS archived URLs). | `friend_responder.py:50-145`; red-team pass-2, shipped in `e84eb34`. |
| **Information disclosure** (privacy claim): the placeholder sees the requester's IP. The privacy_level claim must reflect that. | §29.2 invariant 4 forces `LAN_FRIEND_DIRECT_PLACEHOLDER` → `not_anonymous_placeholder`; the route emits a warning in the response. The route is gated to `dev`/`dev_*` policies (see `policy.py`). | `lan_friend_direct.py:217,229-235`; `response.py:260-266`. |
| **Denial of service** (response bloat): peer-supplied titles/snippets push response well past `max_response_bytes`. | `respond()` measures with `json.dumps(item, ensure_ascii=True)` (not `repr`, which undercounts non-ASCII by ~2.6×) and breaks the loop at the cap. Per-field caps too (`MAX_QUERY_BYTES=512`, `MAX_TOP_K=8`, `MAX_SNIPPET_CHARS=240`). | `friend_responder.py:33-39,251-262`; red-team pass-3 finding C, shipped in `4eca278`. |
| **Spoofing**: the placeholder transport has no signing. | Acknowledged in module docstring; `verification_status="not_checked"` on every result. The mitigation is "don't enable this in production" — `policy._check_consistency` enforces the `dev`/`dev_*` gate. Real signing arrives with §20.2 `RESPONSE_V1` in Phase 4 (TODO-1). | `lan_friend_direct.py:179-181`; `policy.py:196-203`. |
| **Denial of service** (rate limiting): §21.1 lists `max_rounds_per_minute` and `max_cpu_ms_per_query`. Today neither is enforced — see TODO-9. | Not yet shipped; placeholder transport is dev-only so the open hole is acceptable until Phase 4. Real DCNET path will key the limiter off the anonymous-ticket nullifier (TODO-9 + TODO-2). | TODO-9 in `docs/TODO.md`. |
| **Tampering** (suspicious downgrade): every LAN peer errors at once — possible LAN-blocking attack. | Marked `suspicious=True`; router escalates to `confirmation_required` per §26. | `lan_friend_direct.py:201-206`. |

## `reputation.py` — local provider scores (§29.10)

| Threat | Mitigation | Where |
|---|---|---|
| **Information disclosure** (network leak): provider scores leak off-device via cache, friend response, or audit log. | Scores are local-only by spec (§29.10). `local_cache._serialize_result` strips `provider_score_local` before write; the friend responder doesn't include rep in its bundle; the score store is a sibling SQLite file. | `reputation.py:1-17`; `local_cache.py:294-302`. |
| **Tampering** (race on bump): two concurrent `bump()` calls on the same provider lose updates. | `BEGIN IMMEDIATE` on a fresh connection serializes the read-modify-write; explicit `ROLLBACK` on inner exception releases the writer lock promptly. | `reputation.py:184-219`; red-team pass-2 finding #3 + pass-3 finding D, shipped in `4eca278`. |
| **Tampering** (unbounded swing): a stream of negative or positive events drives a provider to 0 or 1. | Hard caps `MIN_SCORE=0.05`, `MAX_SCORE=0.95`; per-event deltas are bounded (largest is ±0.12 for `claim_violated`). 30-day half-life pulls all scores back toward 0.5. | `reputation.py:42-71,102-108`. |
| **Tampering** (unknown event injection): caller passes an event name not in `EVENT_DELTA`. | Unknown events are silent no-ops, not implicit zero-deltas with side-effects. | `reputation.py:176-178`. |
| **Denial of service** (disk growth): rapid bumps churn the WAL. | `decay_all()` issues `PRAGMA wal_checkpoint(TRUNCATE)` after the batch. | `reputation.py:253-258`. |

## `tickets.py` — Phase 6A anonymous-ticket data layer (§27)

| Threat | Mitigation | Where |
|---|---|---|
| **Spoofing** (forged ticket): a peer submits a ticket whose blind signature was not actually issued. | The data layer refuses to verify: `verify_signature()` raises `NotImplementedError("plug in a vetted Privacy Pass library")`. §27.10 says **do not invent a new blind-signature scheme**. The router's `LAN_FRIEND_DCNET` path therefore emits `route_not_implemented` — fail-closed. | `tickets.py` module docstring + `verify_signature`; tracked as TODO-2 in `docs/TODO.md`. |
| **Tampering** (double-spend): a ticket is presented twice. | `try_spend(nullifier)` is `INSERT OR FAIL` on a UNIQUE index; the second attempt returns False with no race. Spent nullifiers persist for `DEFAULT_NULLIFIER_RETENTION_MS = 7 days`. | `tickets.py:145-155` (table) + `try_spend_nullifier`. |
| **Spoofing** (untrusted issuer): a ticket signed by an issuer key the local peer never registered for this circle/epoch. | Issuer-key registry: `issuer_keys` table is keyed by `(issuer_key_id, circle_id, epoch_id)` with `valid_from_ms` / `valid_until_ms` window. Validation fails with `TicketRejection.UNTRUSTED_ISSUER` when the issuer isn't registered or its window doesn't cover the request. | `tickets.py:157-165`. |
| **Tampering** (epoch rollover races): a ticket from a previous epoch arrives during the changeover. | §27.6 gives a 10-minute previous-epoch grace window and 5-minute clock-skew tolerance; constants exposed at the top of the module. | `tickets.py:58-62`. |
| **Information disclosure** (token at rest): unblinded tokens stored at `~/.local/share/swf/tickets.sqlite` — §27.13 wants 0600 file permissions. | DB lives under user-only `~/.local/share/swf/`; mode inheritance enforced at directory create time. (Phase 6 may tighten with explicit `os.chmod` like `local_cache._load_or_create_secret`.) | `tickets.py:169-184`. |
| **Information disclosure** (tracking via persistent shape): see §27.30 ("timing distinguishability"). Not yet measured; benchmark is TODO-11. | Open. | TODO-11 in `docs/TODO.md`. |

## `audit.py` — structured `search_completed` event (§24)

This module does not exist yet. The router currently builds a response
but does not emit the structured `search_completed` event the spec
mandates (request_id, query_hmac, policy, delivery_path, origin_paths,
public_egress_used, duration_ms — and **only** those fields).

**See TODO-4** in `docs/TODO.md`. Until it lands, the audit-trail
threats below remain partially open:

| Threat | Status |
|---|---|
| **Repudiation**: an operator denies that a search ran or that public egress was used. | Partially mitigated by the response itself (which carries `origin_paths`/`public_egress_used_this_request`) and by HTTP access logs (with query strings redacted, `20af8f7`); a structured emit is still required. |
| **Information disclosure** (audit-log leak): a future audit emit could write the raw query into the event. | The §24 schema is **field-allowlist**: only the listed fields. The TODO-4 PR will land an emit that uses `query_hmac` rather than `raw_query`. |

---

## Known gaps (spec-blocked)

These threats are **not** addressed in this version. They are blocked
on a vetted external dependency and are tracked in `docs/TODO.md`.

| Threat | Why open | Tracked |
|---|---|---|
| **LAN requester identification** (§7.1, line 224): the placeholder LAN transport reveals the requester's IP. The real DC-net path that would hide which active peer issued the query is **not yet implemented**. The route currently emits `route_not_implemented` rather than running anything weak. | No vetted Python DC-net implementation exists; §2 lists DC-net as a non-goal for this version's formal crypto proof. The `RouteHandler` interface is ready and `validate_invariants` already enforces the `anonymous_within_lan_circle_query_visible` label that any future DCNET adapter must use. | TODO-1 (Phase 4) in `docs/TODO.md`. |
| **Query spam** (§7.1, line 225): friend responders can be flooded with queries. The data layer for anonymous query tickets ships in `tickets.py` (Phase 6A, `fec5493`), but the `verify_signature` function deliberately raises until a vetted RFC 9474 / RFC 9578 binding lands. | §27.3 + §27.10 forbid hand-rolling the blind-signature primitive. The router fails closed — `LAN_FRIEND_DCNET` returns `route_not_implemented`, never accepts an unverified ticket. | TODO-2 (Phase 6B+) in `docs/TODO.md`. |
| **Receipt spam** (§7.1, line 226): anonymous positive receipts are not yet implemented. The `reputation.bump(.., "receipt_validated")` hook exists but is unused. | Same Privacy Pass library blocker as TODO-2. | TODO-3 (Phase 6D-J) in `docs/TODO.md`. |
| **Tor/WAN privacy claim**: code never labels a request `public_from_self_tor` because the SOCKS adapter + DNS-leak self-test for `network.mode=tor_socks5` is not yet implemented (§22.1). | No code path mints the label, so the privacy claim cannot be falsely advertised. | TODO-7 in `docs/TODO.md`. |
| **Friend-responder rate limiting** (§21.1): `max_rounds_per_minute` and `max_cpu_ms_per_query` are not enforced. | The placeholder transport is gated to `dev`/`dev_*` policies (see `policy.py:196-203`), so the open hole is bounded to development; the real DCNET path will key its rate limiter off the ticket nullifier (depends on TODO-2). | TODO-9 in `docs/TODO.md`. |
| **Timing distinguishability** (§27.30): per-request timing may leak which route was used or whether tickets were required. Not measured. | Phase 7 hardening item. | TODO-11 in `docs/TODO.md`. |
| **Audit emit** (§24): structured `search_completed` event not yet emitted. | Pure docs-time-already debt. | TODO-4 in `docs/TODO.md`. |

The spec's §7.2 out-of-scope list (host compromise, browser
compromise, local malware, query privacy from friend peers, provider
anonymity, WAN anonymity, global sybil resistance, malicious majority
of LAN peers, colluding receipt inflation beyond quota) is the
boundary of what any future PR in this repo can address.
