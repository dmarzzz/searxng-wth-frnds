# SPEC v0.3 — integration notes against current code

Companion to `docs/SPEC_v0.3.md`. First-pass reconciliation between
the spec and what already lives in this repo as of 2026-04-28.

Skim this before starting Phase 0 / Phase 1.

---

## ✅ Already aligned

- **mDNS discovery on `_indrex._tcp.local.`** matches spec §18 `peer_discovery.mdns`.
  Hardened recently:
  - LAN-IP advertisement (PR #4) — UDP-connect trick to find the real
    egress IP rather than `127.0.0.1` from `socket.gethostbyname`.
  - Sleep/wake recovery (PR #10) — drop dead peers after ~30 errors,
    rebuild Zeroconf if no successful pull for 90s.
  - Self-loop guard (PR #3) — author-pubkey + loopback-port filter.
- **Ed25519 envelope signing for slices** matches the family of
  primitives the spec uses for §19 identity separation. Replay protection
  shipped (PR #11): UNIQUE index on `(contributor, slice_root)` plus a
  pre-check in `_submit` and an INSERT OR IGNORE in `_apply` — same
  shape as the spec's `spent_ticket_nullifiers` pattern (§27.13).
- **`~/world_knowledge/index.db` FTS5 indrex** matches §13 *structurally*
  — see schema gap below.
- **Slice scrape + community.db aggregator** is orthogonal to the
  search-router layer the spec adds. Lives under the router; no conflict.

---

## ⚠️ Conflicts to resolve before Phase 0/1

### 1. API port collision

- Spec §23.1 says the router binds `127.0.0.1:7780`.
- Today's `swf-node` binds `7777` and serves slice scrape, `/graph`, SSE
  on the same port.

**Decision needed:** run the search router on a separate port, or fold
both onto `7777`? If folded, the spec's port number needs a one-line edit.

### 2. Indrex path

- Spec §30 config example: `~/world_knowledge/indrex.sqlite`.
- Reality: `~/world_knowledge/index.db`. Used by `swf.indrex`,
  `swf.community_slice`, and `research_agent`.

**Action:** keep the existing path; edit `docs/SPEC_v0.3.md` §30 in a
follow-up PR. Do NOT migrate the file — it'd break three call sites.

### 3. Indrex schema gap (`share_scope`, `sensitivity_label`)

- Spec §13.1 requires `share_scope` (private | local_only | friends |
  public) and `sensitivity_label` (unknown | low | medium | high) on
  every page.
- Reality: today's `pages` table has neither column.

**Action (Phase 1):** schema migration that adds both columns with
sensible defaults (`share_scope = 'private'`, `sensitivity_label =
'unknown'`) for existing rows. Friend-responder filtering depends on
this — until the migration lands, the friend route MUST refuse to
answer rather than risk leaking private content.

### 4. `local_friends` SearXNG engine

- Spec §4 lists `local_friends` as an existing SearXNG engine. We don't
  have a SearXNG engine plugin yet — only `swf/local_friends.py` and the
  source-arg router in `swf/search_router.py` (which today returns
  `{q, sources, results}`, NOT the spec's `SearchResponse` envelope).

**Action:** Phase 1 will subsume the existing source-arg router. The
SearXNG-engine-side may not be needed at all if the router speaks
to SearXNG directly via `public_egress.py` (§29.11).

### 5. `SearchResponse` envelope is breaking-incompatible

Today's response from `swf/peer_server.py:/search`:

```json
{ "q": "...", "sources": [...], "results": [...] }
```

Spec §11 wants:

```json
{
  "schema": "swf.search_response.v1",
  "status": "ok",
  "delivery_path": "...",
  "origin_paths": [...],
  "privacy_level": "...",
  "network_used_this_request": false,
  "public_egress_used_this_request": false,
  ...
}
```

**Action:** Phase 0 should introduce the new envelope on a NEW route
(`POST /web_search` per §23.2) without touching the existing `/search`.
Migrate callers in a later phase, then deprecate `/search`.

### 6. Privacy Pass / blind-token crypto

No existing code. Phase 6A onward is greenfield. Likely a separate
sub-module under `src/swf/anonymous_tickets/` with its own dependency
on a vetted Privacy-Pass library — do not write blind signatures by
hand (spec §27.10).

### 7. Logging defaults

Spec §24 mandates `raw_queries: false` by default. Today's `peer_server`
logs request lines including the query string in `[peer-server] 192.168.1.X - "GET /search?q=..."`.

**Action:** override the access logger to redact `q=...` to
`q=<hmac-prefix>` before Phase 0 ships, OR move all search routes off
the access-logging codepath.

---

## Suggested merge order

1. **Phase 0** can land with no integration risk — pure data models
   (`search_response.py`, `search_policy.py`, invariant checker, tests).
2. **Phase 1** lands with the indrex schema migration (§3 above) and
   the new `/web_search` route (§5 above), gated behind a config flag
   so existing `/search` callers keep working.
3. **Phase 2** (`SELF_PUBLIC_EGRESS`) needs the SearXNG instance
   running locally — already supported by the existing docker-compose.
4. **Phase 3+** (LAN friend search) requires the §3 share_scope
   migration to be in place AND verified, otherwise friend responders
   risk leaking private rows.

---

## Out of scope for this doc

- Wall visualizer changes — see chat for a separate proposal.
- WAN extensions — explicitly non-goal per §2.
