# Hardening checklist

What needs to be true before this stack is safe for adversarial use.
Most items map to specific spec sections (§7, §24, §27.30, §29.x).
Each item is **scoped** (which module owns it) and **testable** (how
you'd verify it's done) so reviewers can hold this PR to the mark.

If a row's `Status` reads "needs library," the work is blocked on a
specific external dependency that's spec-mandated; we should not
hand-roll a substitute. See **§13. Spec-blocked items** at the bottom.

---

## 1. Privacy invariants — already enforced, keep enforced

| Item | Where | Status |
|---|---|---|
| `SearchResponse` always built via `make()` | `response.py:160` | ✅ tests pin it |
| §29.2 invariants run on every response | `validate_invariants` | ✅ |
| `local_only` ⇒ no non-local origins, no network, no public-egress flag | `response.py:266-281` | ✅ |
| `LOCAL_CACHE` requires non-empty origin_paths | `response.py:243-247` | ✅ |
| Cache replay of public origin labels `local_replay_of_public_result` | `response.py:299-306` | ✅ |
| Cache lookup uses **strict subset** against `policy.cache.allowed_origin_paths` | `local_cache.py:179-183` | ✅ (red-team #2) |
| Per-result `origin_path` in `response.origin_paths` | `response.py:312-317` | ✅ |

**Risk if any of these regresses:** privacy laundering. CI must keep
`tests/search/test_response.py` green and the response-construction
invocations all going through `make()`. The grep guard lives in
`tests/search/test_construction_guard.py` — it walks the package on
every `pytest` invocation and fails loudly on any direct
`SearchResponse(...)` outside `response.py`.

---

## 2. Logging redaction (§24)

| Item | Where | Status |
|---|---|---|
| `q=…` stripped from HTTP access logs | `peer_server.log_request` | ✅ PR #14 |
| Body of `POST /web_search` never logged | search routes | ✅ |
| `query_hmac` is the only query identifier in `events.search_completed` | `audit.emit` (called from every `router.web_search` branch) | ✅ TODO-4 |
| Snippets, full URLs, peer IPs, ticket nullifiers, receipt nullifiers all NOT logged | n/a | ✅ by absence |
| Logs scrubbed before shipping anywhere remote (telemetry, support) | n/a | TODO; doc'd |

**Action:** the `swf.search.audit` emitter writes only the §24-allowed
fields and is fired once per `web_search()` from every router branch
(success / error / no_results / confirmation_required). The audit
logger has `propagate=False` so it doesn't leak into the root
logger; operators wire a handler via `audit.add_handler()` to route
the stream to a sink (file, syslog, etc.).

---

## 3. HTTP layer

| Item | Where | Status |
|---|---|---|
| `POST /web_search` rejects oversized bodies | `peer_server._read_json_body(max_bytes=64 KiB)` on /web_search, /friend_search, /search_feedback (returns 413); legacy slice/contribute keep 10 MB | ✅ |
| `POST /friend_search` enforces §21.1 limits | `friend_responder.respond` | ✅ |
| Top-level type validation on every JSON field (no traceback leak) | `peer_server.do_POST` for /web_search, /friend_search, /search_feedback | ✅ (red-team pass-2 + pass-3) |
| `confirm_public_egress` strict bool | `peer_server` /web_search | ✅ (red-team pass-2 F7) |
| Slow-loris read timeout | `peer_server._read_json_body` (15s) | ✅ (leak audit F1) |
| `top_k` clamped at HTTP boundary | `peer_server.do_POST` | ✅ |
| `policy_name` validated (router returns `unknown_policy` rather than crashing) | `router.web_search` | ✅ |
| `/search_feedback` requires `_check_token` on non-loopback | `peer_server` /search_feedback | ✅ (load-test caught crash regression — fixed) |
| Bind defaults to loopback unless operator opts into LAN | `peer_server.main` | ✅ |
| Admin endpoints require token when bound non-loopback | `peer_server._check_token` | ✅ |

**Done.** SPEC-v0.3 search routes pass `max_bytes=65536` to
`_read_json_body`; oversized bodies return HTTP 413 before the
socket reads. Legacy slice/contribute paths still take the 10 MB
ceiling, gated by their own validation.

---

## 4. SQLite + concurrency

| Item | Where | Status |
|---|---|---|
| WAL mode on every read/write opener | all DB modules | ✅ |
| `pages_meta` schema bootstrap is one-shot per process | `local_indrex._ensure_meta_table_writable_once` | ✅ |
| Cache HMAC secret created with `O_EXCL` | `local_cache._load_or_create_secret` | ✅ |
| Cache HMAC secret repaired if mode-leaked | same | ✅ |
| Nullifier double-spend is race-free | `tickets.try_spend_nullifier` | ✅ (UNIQUE PRIMARY KEY + INSERT OR IGNORE) |
| Reputation bump uses `BEGIN IMMEDIATE` for serialized RMW | `reputation.bump` | ✅ (pass-2 #3 + pass-3 D) |
| All writers use a `timeout=` so locked DBs don't deadlock | most modules use `timeout=2.0` | ✅ |
| WAL files truncated after vacuum | `local_cache.vacuum_expired`, `reputation.decay_all`, `tickets.vacuum_expired_nullifiers` (`PRAGMA wal_checkpoint(TRUNCATE)`) | ✅ (leak audit F3) |
| Nullifier table opportunistically vacuumed (every 1024 spends) | `tickets.try_spend_nullifier` | ✅ (pass-3 F) |
| Cache table auto-vacuum | `local_cache.store` callers | TODO (vacuum is opt-in via `vacuum_expired()`) |

**Risk if regressed:** under concurrent /web_search load, a writer
holding a lock can starve readers. WAL is the load-bearing mitigation;
removing it would require revisiting every concurrency test.

---

## 5. Privacy Pass / blind tokens (§27)

| Item | Where | Status |
|---|---|---|
| Envelope dataclass shape matches spec § 27.10 | `tickets.TicketEnvelope` | ✅ |
| Storage schemas match spec § 27.13 | `tickets._CREATE` | ✅ |
| Nullifier construction is deterministic | `tickets.nullifier_for` | ✅ |
| `verify_signature` raises `NotImplementedError` so callers can't silently no-op | `tickets.py` | ✅ by design |
| Real RFC 9474 / 9578 implementation pinned | n/a | **needs library** |
| Issuance flow (§27.9) | n/a | **needs library** |
| Spend-context binds `qid + round_id + route` | `tickets.nullifier_for` | partial — extend when issuance lands |
| Nullifier comparisons use constant-time compare | `tickets.is_spent` | ⚠️ uses `==` via SQL; safe (server-side, constant rounds) but document |
| Issuance logs DO NOT carry token preimages | n/a | ✅ (no logger emits them) |
| Token storage file mode 0600 | `~/.local/share/swf/tickets.sqlite` inherits parent mode | ⚠️ verify on first-run setup |

**Action:** when a vetted Privacy Pass dep is selected, replace
`tickets.verify_signature` and the `nullifier_for` body. The data
layer + tests don't change.

---

## 6. DC-net (§17)

| Item | Where | Status |
|---|---|---|
| `FriendSearchTransport` interface (§17) | `lan_friend_direct.HANDLER` shape matches | ✅ |
| Active circle reporting (§17.1) | n/a | **needs library** |
| Min anonymity set ≥ 3 enforced before reporting `LAN_FRIEND_DCNET` | n/a | **needs library** |
| §29.2 invariant: DCNET ⇒ `anonymous_within_lan_circle_query_visible` | `response.py:255-263` | ✅ (already enforced even though no DCNET handler exists) |
| Membership-fixed-for-round assertion | n/a | **needs library** |

**Risk:** if Phase 4 ships without these, DCNET responses could claim
anonymity falsely. The §29.2 invariants make that *constructively
impossible* — any DCNET response missing the right privacy_level
raises `InvariantError`. Keep that as the load-bearing safety net
until the DC-net library lands.

---

## 7. Side channels

| Item | Where | Status |
|---|---|---|
| Per-request timing not leaking which route was used (within same `delivery_path`) | `bench/search_timing.py` | ✅ measured (TODO-11). Same-`delivery_path` scenarios stay within a 5ms p95 budget. Cross-`delivery_path` differences are inherent — see the row below — and documented as not-a-leak. |
| Per-request timing not leaking ticket-required vs not | `bench/search_timing.py` | ✅ measured (TODO-11). Empty-query / unknown-policy rejections short-circuit before route walking, by design (no ticket logic ran). Phase 6B will add a real ticket-required scenario when issuance lands. |
| Timing microbenchmark + JSON report | `bench/search_timing.py`, `bench/timing_report.json` | ✅ (TODO-11) — N=500 (or N=50 with `--quick`) per scenario, asserts same-`delivery_path` p95 within 5ms, smoke-tested by `tests/search/test_timing_smoke.py` |
| Cache-hit vs miss timing distinguishable | `local_cache.lookup` | ⚠️ inherent — cache hit is faster than indrex query. Document; mitigate at the wall by always rendering after a fixed minimum delay |
| HMAC compares use `secrets.compare_digest` | `query.hmac_query` (just generates) | ✅ |
| Nullifier registry returns same shape on hit vs miss | `tickets.try_spend_nullifier` | ✅ |
| Issuer-key registry returns same shape on missing-key vs invalid-sig | `tickets.validate_envelope` | ⚠️ rejection enum varies — by design, but could be collapsed for adversarial-peer paths |

**Status:** TODO-11 shipped a microbenchmark in `bench/search_timing.py`
that measures `web_search()` latency distributions per route + failure
mode and asserts no two same-`delivery_path` scenarios diverge by more
than 5 ms at p95. The bench is opt-in (not a unit test); CI runs it
quickly via the smoke test in `tests/search/test_timing_smoke.py`.

**Caveat — inherent cross-route differences:** different
`delivery_path`s legitimately differ in latency (a cache replay is
faster than an indrex query, which is faster than a friend fan-out).
The spec doesn't model that as a leak — a passive observer of timing
already knows the policy + route_order. The bench therefore only
asserts WITHIN a single delivery_path; cross-route differences are
documented as expected.

---

## 8. Issuance side-channels (§27.30)

If a single peer is the issuer, that peer learns:

- **how often** every member requests tickets,
- **how many tickets** every member holds at any moment,
- **timing** of issuance requests.

| Mitigation | Status |
|---|---|
| Issue tickets in batches at epoch start | spec'd, not implemented |
| Equal quota buckets across members | spec'd, not implemented (§27.7) |
| Allow prefetch | spec'd, not implemented |
| Threshold issuance (§27.5.3) | spec marks as v2 |

**This is a known privacy gap for v1.** Document on every issuance
endpoint that "the issuer can correlate issuance timing." If you want
stronger guarantees, run threshold issuance — that's why §27.5.3
exists.

---

## 9. Friend-responder safety (§13.3, §21.1)

| Item | Where | Status |
|---|---|---|
| Only `share_scope IN ('friends','public')` rows | `friend_responder._PAGES_SQL` | ✅ |
| Drop `sensitivity_label='high'` | same | ✅ |
| Refuse non-`http/https` schemes (file:/javascript:/data:/ftp:, case-insensitive) | `friend_responder._is_safe_url` | ✅ |
| Block IPv4 + IPv6 loopback in every encoding (literal, %-encoded, decimal long-form, hex, IPv4-mapped IPv6) | same — uses `ipaddress.ip_address` | ✅ (pass-2 #1) |
| Block RFC 1918 (`10.x`, `192.168.x`, `172.16-31.x`), link-local (`169.254.x`, `fe80::`), multicast, reserved | same | ✅ (pass-2 #1) |
| Block `.local` / `.lan` / `.internal` / `.intranet` / `.corp` / `.home` TLDs | same | ✅ |
| Optional DNS-resolution check (`SWF_SSRF_STRICT_DNS=1`) | same | ✅ — env-gated for paranoid deploys |
| `max_query_bytes`, `max_top_k`, `max_response_bytes`, `max_snippet_chars` | `friend_responder` constants | ✅ |
| `max_response_bytes` measured against actual `json.dumps(ensure_ascii=True)` size, not `repr` | `friend_responder.respond` | ✅ (pass-3 C — fixed undercount on emoji titles) |
| Refuse rows where `pages_meta` is missing (no INNER JOIN match) | `_PAGES_SQL` uses INNER JOIN | ✅ — safe-by-default |
| Refuse rows whose `source_type='peer_ingest'` (chained-provenance attack) | `_PAGES_SQL` adds `m.source_type != 'peer_ingest'` | ✅ (TODO-8) |
| Refuse rows whose `deleted_at_ms IS NOT NULL` (tombstones) | `_PAGES_SQL` adds `m.deleted_at_ms IS NULL` | ✅ (TODO-8) |
| Rate limit per peer | `friend_responder._rate_limit_check` — sliding 60s token bucket keyed by source IP, capped at `MAX_ROUNDS_PER_MINUTE=20`; checked before any DB work; `source_ip` plumbed from `peer_server` `client_address[0]` | ✅ (TODO-9) |
| `max_cpu_ms_per_query` cap | `friend_responder.respond` — wall-clock budget (`MAX_CPU_MS_PER_QUERY=100`) measured with `time.monotonic()`; short-circuits with `reason="cpu_budget_exceeded"` after SQL or mid per-row loop, bundle stays well-shaped | ✅ (TODO-9) |

**Risk if a row leaks via this path:** a peer could exfiltrate a
`private` row via friend search, defeating the trust circle. The
INNER JOIN + share_scope filter is the load-bearing rule; do not
relax it without an explicit CHECK constraint in `pages_meta`. The
`source_type != 'peer_ingest'` gate is the second load-bearing rule —
without it a curious peer can re-broadcast someone else's archive
through us (chained provenance), even though every row here passes
the share_scope check.

---

## 10. Reputation system (§29.10)

| Item | Where | Status |
|---|---|---|
| Score capped `[MIN_SCORE, MAX_SCORE]` | `reputation._clamp` | ✅ |
| Decay pulls toward neutral with bounded half-life | `reputation._decayed` | ✅ |
| Unknown event names are no-ops, not exceptions | `reputation.bump` | ✅ |
| Read-modify-write atomic under concurrent bumps | `reputation.bump` (BEGIN IMMEDIATE + explicit rollback) | ✅ (red-team pass-2 #3 + pass-3 D) |
| `/search_feedback` requires `_check_token` on non-loopback bind | `peer_server` /search_feedback | ✅ |
| Reputation NEVER persists into the search cache | `local_cache._serialize_result` strips `provider_score_local` | ✅ (pass-3 #A) |
| Re-rank weight conservative enough that one bad actor can't dominate | `reputation.rerank` | ✅ — 0.30 weight + score capping limits worst-case shift |
| Anonymous receipts cannot be replayed across users | requires Phase 6D | **needs library** |

---

## 11. Public egress hygiene (§22, §29.11)

| Item | Where | Status |
|---|---|---|
| Explicit engine allowlist (don't trust SearXNG's default fanout) | `public_egress.search` | ✅ |
| SearXNG response body capped at 2 MiB | `public_egress.MAX_SEARXNG_BYTES` | ✅ (leak audit F2) |
| SearXNG-supplied URLs validated against SSRF (file:// / javascript: / private-IP) | `public_egress` reuses `friend_responder._is_safe_url` | ✅ (red-team pass-2 #2) |
| Confirmation flow on `mode=confirm` | `router.web_search` | ✅ |
| Confirmation flow on suspicious private-route failure | same | ✅ |
| §29.2 invariant 1b: `public_egress_used_this_request=true` ⇒ `SELF_PUBLIC_EGRESS in origin_paths` | `response.validate_invariants` | ✅ (pass-2 / live-fuzz F5) |
| Third-party SearXNG explicitly NOT labeled `SELF_PUBLIC_EGRESS` | n/a | ✅ — code only ever calls `SWF_SEARXNG_URL` (default loopback) |

**Out of scope:** Tor adapter (§22.1 `network.mode=tor_socks5`) and
the `public_from_self_tor` privacy level are intentionally not
implemented. The router's enum value remains in `PrivacyLevel` so
future deployments that ship a vetted SOCKS+leak-check adapter can
register it; today no code path emits it.

---

## 12. Operational

| Item | Owner | Status |
|---|---|---|
| Pre-commit hook for `validate_invariants` regression | CI | TODO |
| Mode 0700 enforcement on `~/.config/swf/` and `~/.local/share/swf/` directories | `swf.paths.ensure_dir` (called from every `db_path()` / `secret_path()` / `_identity_dir()`); creates new dirs at 0700 and re-chmods existing looser dirs on first access | ✅ |
| Documented backup / rotation for cache + reputation + tickets DBs | docs | TODO |
| `swf-node --check` self-test that runs all `validate_invariants` cases | `peer_server._run_self_check` | ✅ TODO-12 |
| Prom-style metrics for route-distribution, sufficiency-fail-by-reason | n/a | future |

---

## 13. Spec-blocked items (do NOT ship a hand-rolled substitute)

These wait on a vetted external dependency. **Spec §27.10 is explicit:
do not invent a new blind-signature scheme.** Same applies to DC-net.

- **Phase 4 LAN_FRIEND_DCNET adapter.** Needs a vetted DC-net
  implementation (none currently in the Python ecosystem). Until
  then: route stays `route_not_implemented`, no client trust is
  given to DCNET claims.
- **Phase 6B query-ticket issuance.** Needs RFC 9474 / 9578 Python
  implementation. The data and validation surface (§27.10, §27.13)
  is in place; only `tickets.verify_signature` body is a stub.
- **Phase 6C cross-peer nullifier sync.** The single-peer registry
  already prevents local double-spend; cross-peer requires the
  signature-verifying receiver, which is gated on Phase 6B.
- **Phase 6D-J anonymous receipts.** Same rationale — receipts
  share the blind-token primitive.

When the dep is settled:

1. Replace `tickets.verify_signature` body with the library call.
   Its signature stays the same: `(envelope, issuer_key) -> bool`.
2. Adjust `tickets.nullifier_for` if the library prescribes a
   different canonical token encoding.
3. Wire `LAN_FRIEND_DCNET` handler into `router._HANDLERS`. The §29.2
   invariants are already in place; the handler just runs the
   transport.

The data tests in `tests/search/test_tickets.py` already encode the
expected envelope/rejection shapes. A real library plug-in should not
require those tests to change.

---

## Pointers

- Spec: `docs/SPEC_v0.3.md` — §7 threat model, §24 logging, §27.30
  side channels, §29 module responsibilities.
- Implementer's guide: `docs/SEARCH_ROUTER.md`.
- Policy cookbook: `docs/SEARCH_POLICY_COOKBOOK.md`.
- Original red-team + arch review: commit `9b1c828` (Phase 1).
- This checklist tracks v1 hardening only. WAN extensions are
  explicit non-goals (§2).
