# SYNC — Phase 2 cohort-profile sync protocol

Status: **DRAFT** (Phase 2 spec; not yet implemented).
Codename: **swf-node sync v1**.
Audience: the implementer building this on top of the existing
`swf.bundles` substrate; reviewers auditing the design.

This document specifies an **eventually-consistent, signed-record sync
protocol** that swf-node uses to gossip cohort-member profile records
over the LAN. It is the substrate the Shape Rotator OS Electron app
reads from when it renders "who's in the cohort, what do they have on
their pages." Each cohort member runs their own swf-node; this protocol
is what gets edits one peer makes onto every other peer's disk.

Cross-references throughout: `DESIGN.md` (architecture),
`docs/HTTP_API.md` (existing endpoint surface), `docs/CONFIG.md`
(env vars + state dirs), `docs/THREAT_MODEL.md` (per-module STRIDE),
and the existing **bundle substrate** (`src/swf/bundles/`, issue #93)
which this spec deliberately reuses and extends.

---

## 1. Goals + non-goals

### 1.1 Goals

- **Eventually-consistent** convergence of a set of signed records
  across all online peers on the LAN. After a finite quiescent window
  (no new writes), every peer holds the same per-`record_id` latest
  version.
- **Single-writer-per-record.** Every record has exactly one author
  pubkey, fixed for the life of the record. The author is the only
  party allowed to mutate it. This is enforced cryptographically
  (signature over canonical envelope) and structurally (the
  `record_authors` table pins the expected author).
- **Cohort-trust LAN.** Trust is per-pubkey, distributed out of band as
  a static `cohort-keys.json` shipped with the Electron app (see §8).
  No web-of-trust, no TOFU; if your pubkey isn't on the list, your
  records are dropped on the floor.
- **Wall-clock LWW on conflict.** Multiple online edits to the same
  record by the same author produce a deterministic winner via
  `wall_ts_ms` (with a content-hash tiebreaker on ms collision).
- **History as backup.** Every accepted envelope is appended forever to
  a local sqlite table. The "current view" is the latest envelope per
  `record_id`; restoring a prior version means signing a fresh envelope
  whose `content` is a prior snapshot.
- **Fits the existing swf-node substrate.** This reuses the bundle
  envelope shape (`swf.bundles.envelope`), the canonicalization rule,
  the Ed25519 keys already present (`swf.identity`), the existing mDNS
  service type (`_indrex._tcp.local.`), the sqlite indrex DB
  (`swf.indrex.db_path()`), and the established HTTP-server style
  (`swf.peer_server`). It adds three new endpoints under `/sync/`,
  one new SQL table (`record_authors`), and one new bundle `kind`.

### 1.2 Non-goals

- **Not a CRDT for live multi-write.** Two cohort members editing
  *the same* record on the same wall second from two different boxes
  is a misuse pattern. The spec resolves it deterministically (one
  envelope wins, the other is appended to history but not surfaced)
  but the user-facing semantics is "edit your own profile."
- **Not a public-internet protocol.** Wire traffic is unauthenticated
  HTTP on the LAN; the protocol's confidentiality story is "your LAN
  is the trust boundary." See §2.
- **Not a transport for arbitrary mutable state.** Records carry small
  JSON content (think profile bio, geo, interest tags, social handles).
  Large blobs (photos, ML weights) belong elsewhere; the protocol
  enforces a 64 KiB envelope cap (§3.5).
- **Not key-management.** The cohort-keys file is distributed out of
  band today. Rotation, revocation, web-of-trust introductions —
  enumerated in §9 (Open questions).
- **Not Windows.** Mac + Linux only for now. Matches the swf-node
  binary release matrix.

### 1.3 What scale this targets

~50 peers on the same LAN, ~100s of records total (cohort size × a few
record types per member), ~1 edit per record per day in the steady
state and bursty ~10/min during a "hackerspace day" cohort onboarding.
A peer is expected to come online, sync in seconds, and stay online
for the day.

---

## 2. Threat model

This protocol layers on top of the existing swf-node threat model
(`docs/THREAT_MODEL.md` §0). Threats specific to sync:

### 2.1 In scope

| Threat | Mitigation |
|---|---|
| **Forgery** — peer A signs an envelope claiming to be peer B. | The cohort-keys file pins `record_id → expected_author_pubkey`. The receiver verifies (a) the envelope signature against `author_pubkey`, (b) that `author_pubkey == record_authors[record_id]`. Mismatch → drop. |
| **Tampering** — bytes mutated in transit. | Ed25519 signature covers the canonical bytes of the envelope minus the `signature` field. Any mutation invalidates the signature. |
| **Replay** — same envelope received twice (e.g. two different peers each forward it). | `content_hash` dedup. Receiver computes the canonical-bytes sha256, looks it up in `records.content_hash`; if present, drop silently and **do not propagate**. |
| **Stale-clock injection** — author backdates `wall_ts_ms` to a far past to lose an LWW race. | The author who backdates their own envelope only hurts themselves; LWW is per-record and they're the only writer. No threat to other peers. |
| **Future-clock injection** — author or attacker sets `wall_ts_ms` to far future to win every LWW race forever. | Envelopes with `wall_ts_ms > now + 5min` are dropped at receive time, and a `clock_skew` warning is surfaced in the `/sync/record/` response so the peer's UI flags the misbehaving author. |
| **Record-author hijack** — peer attempts to publish an envelope for a `record_id` they don't own. | `record_authors` is one-author-per-record, set on first observation from cohort-keys. A second author for the same `record_id` is rejected. |
| **Gossip-flood** — peer hammers `/sync/manifest` to exhaust resources. | Per-peer pull rate-limit (1 manifest req / 5s, see §4.6). Manifest response is small (O(N) records × small constant). Polling cadence is bounded by §4.6. |
| **Body-size DoS** — peer ships oversized envelopes. | 64 KiB cap per envelope; 4 MiB cap per `/sync/record/` response page; receiver enforces both before parsing. |

### 2.2 Out of scope

- **Cohort-key exfiltration / private-key compromise.** If an
  attacker steals a cohort member's Ed25519 private key, they can
  impersonate them until the cohort-keys file is updated. Rotation is
  open (§9.1).
- **Hostile cohort majority.** If most pubkeys on the cohort-keys
  list are malicious, sync faithfully gossips their misinformation.
  This is the existing swf-node posture (`docs/THREAT_MODEL.md` line 32).
- **Network observer.** mDNS + HTTP on the LAN are in clear; a passive
  attacker on the same broadcast domain sees who's a cohort member
  and what records exist. They cannot forge records. They can correlate
  edits to wall-clock times.
- **Cross-LAN sync.** This spec is LAN-only. WAN sync (Tailscale,
  manually-pinned peers) is supported by the existing peer-discovery
  paths (`swf.discovery`) but the rate-limit defenses are designed for
  LAN latencies; a WAN deployment should set a more aggressive
  `SWF_SYNC_POLL_INTERVAL_SECS` (§4.6).

---

## 3. Record envelope

### 3.1 Schema

```json
{
  "magic": "swf-sync-v1",
  "kind": "person",
  "record_id": "amiller",
  "author_pubkey": "ed25519:<hex>",
  "wall_ts_ms": 1716345678000,
  "prev_hash": "sha256:<hex>" ,
  "content": {
    "name": "Andrew",
    "geo": "NYC",
    "handles": {"github": "amiller"}
  },
  "content_hash": "sha256:<hex>",
  "signature": "ed25519:<hex>"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `magic` | string | yes | Locked literal `"swf-sync-v1"`. Distinguishes sync envelopes from `swf-bundle-v1` (existing bundle substrate). |
| `kind` | string | yes | One of `BUNDLE_KINDS` (§3.2). |
| `record_id` | string | yes | Stable per record. 1–128 chars, `[a-z0-9._-]+`. Cohort members typically use their canonical handle (`amiller`). |
| `author_pubkey` | string | yes | `ed25519:<64 hex chars>`. Matches the format already locked in `swf.bundles.envelope` §3.7. |
| `wall_ts_ms` | int | yes | Unix epoch millis at the moment of signing. Must be ≥ 0. The LWW key (§5). |
| `prev_hash` | string \| null | yes | `sha256:<hex>` of the immediately-prior accepted envelope's `content_hash` for the same `record_id`, or `null` if this is v0. Forms a per-record append-only hash chain. |
| `content` | object | yes | The canonical record JSON. Opaque to swf-node — sync neither inspects nor mutates it. |
| `content_hash` | string | yes | `sha256:<hex>` of the canonical bytes of `content` alone (§3.4). Surfaced at this level so the manifest is cheap (§4.1) without re-canonicalizing `content` on every list. Receiver MUST verify it matches the computed value. |
| `signature` | string | yes | `ed25519:<hex>` over the canonical bytes of the envelope **minus** the `signature` field (§3.4). |

### 3.2 Allowed `kind` values

Phase 2 ships exactly one kind:

- **`person`** — a cohort member's profile record. `record_id` is the
  member's handle (e.g. `amiller`).

Future kinds (NOT in Phase 2 scope, but the protocol must accept new
strings without a schema bump):

- `place` — a venue / hackerspace.
- `event` — a scheduled gathering.

Receivers MUST drop envelopes with unknown `kind` and surface a
`kind_unknown` warning in the response (§4.4). Receivers MUST NOT
fail the rest of the sync because of one bad-kind envelope.

### 3.3 Canonicalization rule

JSON Canonicalization Scheme (JCS) is overkill for our payloads; we
follow the rule already locked in `swf.bundles.envelope.canonicalize`:

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"),
           ensure_ascii=False).encode("utf-8")
```

Applied at TWO levels:

1. **Envelope canonicalization** — for signing, content-id, and dedup.
   Drop the `signature` field, then run the rule.
2. **Content canonicalization** — for `content_hash`. Run the rule on
   `content` alone.

Both produce deterministic bytes across all peers. Both reject
non-string keys at the dict level (JSON-native — no special casing).

### 3.4 Signing payload

`signature` covers:

```
canonicalize({k: v for k, v in envelope.items() if k != "signature"})
```

This is byte-identical to the existing `swf.bundles.signing.sign_envelope`
contract — the implementer reuses that helper. The `signature` field
must be omitted before canonicalization, not set to `null` or empty
string; canonicalization with `sort_keys` does not skip null values.

`content_hash` is independent: `sha256(canonicalize(envelope["content"]))`.
The receiver MUST recompute and reject on mismatch (defense against a
buggy producer that signs an envelope with stale `content_hash`).

### 3.5 Size limits

- Envelope canonical bytes: ≤ **64 KiB**. Hard cap. A producer that
  needs more should fragment at the application layer.
- `record_id` length: ≤ 128 chars.
- `content` depth: ≤ 8 levels of nesting. Defense against pathological
  JSON the canonicalizer could spend O(depth²) on.

Receiver enforces all three before computing the signature.

### 3.6 Compatibility with `swf-bundle-v1`

The existing bundle substrate (`swf.bundles`, issue #93) uses
`magic: "swf-bundle-v1"` and a `version: int` field with strict-greater
monotonicity. Sync envelopes use `magic: "swf-sync-v1"` and a
`wall_ts_ms: int` LWW field with the §5 tiebreaker. The two are
**distinct protocols** sharing a storage substrate (§6) but never
confused on the wire — the `magic` field is the first thing every
verifier checks.

The implementer SHOULD reuse `swf.bundles.envelope.canonicalize` and
`swf.bundles.signing.{sign_envelope, verify_envelope_signature}`
verbatim — they're already canonicalization-rule and signature-scheme
agnostic to the schema above them.

---

## 4. Sync wire protocol

All endpoints live under `/sync/` on the existing swf-node HTTP port
(`SWF_PORT`, default 7777). They are **peer routes** in the
`docs/HTTP_API.md` sense: Ed25519-signed payloads, no bearer required,
authentication is at the envelope level. The HTTP layer is plain — the
LAN is the trust boundary.

All POST bodies (none in Phase 2) and responses are JSON unless
otherwise noted.

### 4.1 `GET /sync/manifest`

Returns this peer's view of every record it holds.

**Request:** no parameters.

**Response (200):**

```json
{
  "schema": "swf.sync.manifest.v1",
  "node_pubkey": "ed25519:<hex>",
  "generated_at_ms": 1716345700000,
  "records": {
    "amiller": {
      "kind": "person",
      "author_pubkey": "ed25519:<hex>",
      "latest_content_hash": "sha256:<hex>",
      "latest_wall_ts_ms": 1716345678000
    },
    "halcyon": {
      "kind": "person",
      "author_pubkey": "ed25519:<hex>",
      "latest_content_hash": "sha256:<hex>",
      "latest_wall_ts_ms": 1716345550000
    }
  },
  "manifest_hash": "sha256:<hex>"
}
```

`manifest_hash` is `sha256(canonicalize(records))` — the same
canonicalization rule (§3.3) applied to the `records` object. Diff
algorithm (§4.3) short-circuits when manifest hashes match.

Records are keyed by `record_id`. Inside, only the minimum to drive
the diff is exposed; full envelopes come from `/sync/record/`.

**Error responses:** the manifest endpoint is always 200 unless the
backing sqlite is unavailable (500 with `{"error": "sync_store_unavailable"}`).

### 4.2 `GET /sync/record/<record_id>?since=<ts>&limit=<n>`

Returns one or more signed envelopes for `record_id`, newest-first by
`wall_ts_ms`, terminating when either:

- the next envelope has `wall_ts_ms <= since` (caller has it), OR
- the chain's root is reached (`prev_hash: null`), OR
- `limit` envelopes have been returned (default 100, max 1000).

**Request parameters:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `since` | int | `0` | Returns envelopes with `wall_ts_ms > since`. |
| `limit` | int | `100` | 1–1000. |

**Response (200):**

```json
{
  "schema": "swf.sync.record.v1",
  "record_id": "amiller",
  "envelopes": [
    { /* envelope §3.1 */ },
    { /* envelope §3.1 */ }
  ],
  "more": false,
  "warnings": []
}
```

- `envelopes` is in `wall_ts_ms DESC` order. The newest is index 0.
- `more` is `true` iff there are older envelopes the caller hasn't
  seen and `limit` was the cutoff (not the `since` cursor). Callers
  paginate by calling again with `since=<some-older-ts>`.
- `warnings` carries non-fatal observations (`stale_clock`,
  `kind_unknown`, etc. — see §4.4).

**Error responses:**

| Status | Body | When |
|---|---|---|
| 400 | `{"error": "invalid_record_id"}` | `record_id` fails the §3.1 regex. |
| 400 | `{"error": "invalid_since"}` | `since` not parseable as non-negative int. |
| 400 | `{"error": "invalid_limit"}` | `limit` outside [1, 1000]. |
| 404 | `{"error": "not_found", "record_id": "<r>"}` | No envelopes exist for this record on this peer. |
| 500 | `{"error": "sync_store_unavailable"}` | SQLite open / read failure. |

### 4.3 Diff algorithm (caller side)

Pseudocode for peer A syncing against peer B. Runs on every poll tick
(§4.6) and on every `peer_announced` mDNS event for an unknown pubkey.

```
def sync_with(peer_b):
    # 1. Manifest exchange (one round-trip).
    remote = http_get(peer_b.url + "/sync/manifest")
    if remote is None:                      # peer offline; backoff
        record_peer_failure(peer_b)
        return
    local  = build_local_manifest()
    if remote.manifest_hash == local.manifest_hash:
        return                              # converged; nothing to do

    # 2. Per-record diff.
    for record_id, remote_meta in remote.records.items():
        local_meta = local.records.get(record_id)

        # New record we don't have at all.
        if local_meta is None:
            pull_record(peer_b, record_id, since=0)
            continue

        # Same latest hash → equal; skip.
        if remote_meta.latest_content_hash == local_meta.latest_content_hash:
            continue

        # Remote has newer (or divergent) versions; pull them.
        if remote_meta.latest_wall_ts_ms > local_meta.latest_wall_ts_ms:
            pull_record(peer_b, record_id, since=local_meta.latest_wall_ts_ms)
        elif remote_meta.latest_wall_ts_ms < local_meta.latest_wall_ts_ms:
            # Remote is older. They'll pull from us on their tick.
            # (Single round-trip convergence: B does the same diff in
            #  reverse and pulls newer-than-its-latest from us.)
            continue
        else:
            # Same wall_ts_ms, different content_hash → ms collision.
            # Apply LWW tiebreaker (§5). Newer-by-tiebreaker side pulls;
            # older side does nothing this round.
            if remote_meta.latest_content_hash > local_meta.latest_content_hash:
                pull_record(peer_b, record_id, since=local_meta.latest_wall_ts_ms - 1)

def pull_record(peer_b, record_id, since):
    page = http_get(peer_b.url + f"/sync/record/{record_id}?since={since}")
    if page is None: return
    for env in page.envelopes:
        if not verify_envelope(env): continue   # §4.4
        if env.wall_ts_ms - now_ms() > 5*60*1000: skip("clock_skew", env)
        apply_envelope(env)                     # §5 LWW + write to store
    if page.more:
        oldest = page.envelopes[-1].wall_ts_ms
        pull_record(peer_b, record_id, since=oldest - 1)  # walk older
```

**Single round-trip convergence.** Both A and B run this loop on their
own tick. After A→B and B→A complete, both peers have every envelope
newer than the other's latest-per-record. They converge in *one round
of bidirectional polling*.

### 4.4 Envelope verification

Every envelope a peer receives goes through, in order. First failure
wins; envelope is dropped.

1. **Shape** — `magic == "swf-sync-v1"`, all required fields present,
   each field's type + regex matches §3.1.
2. **Size cap** — canonical bytes ≤ 64 KiB.
3. **Author whitelist** — `author_pubkey` is in `cohort-keys.json`
   (§8). Not in list → drop. Surface `author_not_in_cohort` warning.
4. **Record-author pin** — `record_authors[record_id]` either matches
   `author_pubkey` (existing record) or is unset (first observation —
   pin to this author). Mismatch → drop. Surface `record_author_mismatch`
   warning.
5. **Signature** — Ed25519 verify the canonical-minus-signature bytes.
   Reuses `swf.bundles.signing.verify_envelope_signature`. Fail → drop.
6. **Content-hash sanity** — recompute `sha256(canonicalize(content))`;
   compare to `envelope.content_hash`. Mismatch → drop.
7. **Clock-skew** — `wall_ts_ms ≤ now_ms() + 5 min`. Future → drop.
   Surface `stale_clock` warning with `{author: <pk>, skew_ms: <int>}`.
8. **prev_hash chain** — if a prior envelope for this `record_id`
   exists on this peer with content_hash `H_prev`, the incoming
   envelope's `prev_hash` SHOULD equal `sha256:H_prev`. Mismatch is
   **non-fatal** (a peer might have an older state than the author);
   surface a `prev_hash_unexpected` warning but still apply the
   envelope. Rationale: enforcing strict chain on a pull-side peer
   would prevent catching up after missing intermediate edits. The
   chain is mostly for human-auditable history, not consensus.
9. **LWW + dedup** — see §5.

Warnings surface in the `warnings` array of the `/sync/record/`
response when this peer is the one *serving* the data and the caller
sent something the peer wouldn't fully accept. Locally-generated
warnings (peer A's verifier rejecting peer B's envelope) are logged
+ counted as metrics (`sync.envelope_rejected.<reason>`) but not
returned over the wire.

### 4.5 `GET /sync/peers` (introspection)

Returns the list of peer pubkeys this node has synced with in the
last 24h, with last-success timestamp. Used by the Electron UI to
show "who's online." NOT used by the sync algorithm itself.

```json
{
  "schema": "swf.sync.peers.v1",
  "peers": [
    {"pubkey": "ed25519:<hex>", "last_synced_ms": 1716345700000,
     "last_status": "ok"},
    {"pubkey": "ed25519:<hex>", "last_synced_ms": 1716340000000,
     "last_status": "manifest_timeout"}
  ]
}
```

### 4.6 Polling cadence + mDNS-push trigger

**Default polling interval:** `SWF_SYNC_POLL_INTERVAL_SECS=30` (env
override). Each tick:

1. Enumerate every known cohort peer (intersection of cohort-keys.json
   pubkeys and `discover_all_peers()` results).
2. For each peer, run the §4.3 diff. Sequential, not parallel — keeps
   the manifest-request rate bounded per peer.
3. Skip peers in their per-peer exponential backoff window (same
   backoff mechanism as `swf.peer_scraper`).

**mDNS-push trigger:** when a new pubkey appears via mDNS (handled by
`swf.discovery`'s existing `_ip_change_hooks`-style mechanism — add a
parallel `_peer_announced_hooks`), kick off an immediate sync with
that peer outside the poll cadence. Bounded by:

- Same per-peer rate-limit (1 manifest req / 5s; in-flight dedup).
- A startup grace window (don't kick a sync for the first 2s after
  daemon start — let the user's identity-key load complete).

**Rate-limit per peer:** the manifest endpoint is cheap, but we still
cap per-peer manifest fetches at **1 per 5 seconds** to avoid storm
patterns when many peers announce simultaneously. Implementation: an
in-memory `dict[pubkey, last_attempt_ms]` in the sync subsystem.
Excess attempts return early without a request.

**No active gossip.** This is pull-only. Every peer is responsible for
polling every other peer. With 50 peers and a 30s tick, that's
50 × 49 / 2 = 1225 manifest requests per minute LAN-wide. Each manifest
is O(100) records × O(200 bytes) = ~20 KB. ~25 MB/min LAN-wide
manifest traffic in the steady state. Acceptable.

**Push trigger (optional Phase 2.1):** on a local write
(record this peer owns and just edited), the sync subsystem MAY post
a no-body `POST /sync/record/<record_id>/announce` to every peer to
kick their poll forward. Not in Phase 2 critical path; tracked as a
follow-up because the 30s tick is already fast enough for the
hackerspace UX.

---

## 5. Conflict resolution

### 5.1 Rules

Given two envelopes `A`, `B` for the same `record_id`, the receiver
keeps the one with:

1. Higher `wall_ts_ms` wins.
2. **Tiebreaker on ms collision** (`A.wall_ts_ms == B.wall_ts_ms`):
   lexicographically larger `content_hash` wins. Deterministic across
   peers (every peer computes the same `content_hash`).

If both `wall_ts_ms` and `content_hash` are equal, the envelopes are
**byte-identical** modulo signature — and since canonicalization +
signing are deterministic, the signatures match too. This is a
duplicate; dedup (§5.3) handles it.

### 5.2 Pseudocode

```python
def apply_envelope(env: Envelope) -> ApplyResult:
    # Always append to the history table — every accepted envelope
    # is forever (§7).
    cid = sha256(canonicalize(env, drop_signature=True))
    inserted = records.insert_or_ignore(
        content_hash=env.content_hash,
        record_id=env.record_id,
        wall_ts_ms=env.wall_ts_ms,
        author_pubkey=env.author_pubkey,
        envelope_json=canonical(env, drop_signature=False),
        cid=cid,
    )
    if not inserted:
        # §5.3 — duplicate; no-op.
        return "duplicate"

    # Current-view computation is a query, not a mutation. The latest
    # envelope per record_id is whichever wins the LWW + tiebreaker:
    #
    #   SELECT envelope_json FROM records
    #    WHERE record_id = ?
    #    ORDER BY wall_ts_ms DESC, content_hash DESC
    #    LIMIT 1
    #
    # No "current-view cache table" — the index makes this cheap.
    return "applied"
```

### 5.3 Replay defense (dedup)

`records.content_hash` is `UNIQUE` (within `record_id` — see §6).
A second envelope with the same `content_hash` for the same
`record_id` is dropped at the `INSERT OR IGNORE` level. The
canonicalization rule guarantees that byte-identical envelopes
produce identical `content_hash` values across peers, so this dedup
works LAN-wide.

**Propagation suppression.** If a sync pull returns an envelope we
already have (dedup → `was_new=False`), we MUST NOT re-broadcast
it. Otherwise gossip storms in any cyclic LAN graph (and 50-peer LANs
are densely cyclic). Mirrors the `was_new` gating in
`swf.bundles.propagation` (issue #93 phase 6 docstring).

### 5.4 Clock-skew defense (recap)

`wall_ts_ms > now_ms() + 5 min` → drop + warn. The 5-minute window:

- Permissive enough that no real NTP-synced LAN trips it.
- Tight enough that a malicious author can't grant themselves an
  unbounded LWW future-win.
- Surfaced to the UI so the cohort can socially correct a peer with
  a wonky clock before their edits start losing races.

A future hardening pass could replace wall-clock LWW with a hybrid
logical clock (HLC), but Phase 2 ships wall-clock to keep the
implementation tight; see §9.4.

---

## 6. Storage schema

All new tables live in the existing indrex DB
(`swf.indrex.db_path()`, typically `~/world_knowledge/index.db`). Same
file as the existing `bundles` table from issue #93. Rationale: one
sqlite file means one WAL log, one backup target, one consistent
read-write story. Sync is small (KBs per record × low hundreds of
records); colocating with bundles is fine.

The `swf.bundles` table is **NOT** reused for sync envelopes — its
`version` column has strict-greater monotonicity (§3.6) that
contradicts the LWW semantics. Sync gets its own tables. Both can
coexist; their `magic` fields disambiguate them on the wire.

### 6.1 DDL

```sql
-- Per-record append-only log. One row per accepted envelope.
CREATE TABLE IF NOT EXISTS sync_records (
    record_id        TEXT NOT NULL,
    content_hash     TEXT NOT NULL,           -- sha256:<hex>
    wall_ts_ms       INTEGER NOT NULL,
    author_pubkey    TEXT NOT NULL,           -- ed25519:<hex>
    kind             TEXT NOT NULL,
    prev_hash        TEXT,                    -- sha256:<hex> or NULL
    envelope_json    TEXT NOT NULL,           -- canonical bytes incl. signature
    received_at_ms   INTEGER NOT NULL,        -- wall-clock at insert time
    PRIMARY KEY (record_id, content_hash)
);

-- Driving index for the LWW + manifest queries.
CREATE INDEX IF NOT EXISTS idx_sync_records_lww
    ON sync_records(record_id, wall_ts_ms DESC, content_hash DESC);

-- Insertion-order cursor (for future cross-record replication, parallel
-- to the bundles puller's rowid cursor — see swf/bundles/puller.py).
CREATE INDEX IF NOT EXISTS idx_sync_records_received
    ON sync_records(received_at_ms);

-- One-author-per-record pin. First insertion sets it; subsequent
-- envelopes with a different author for the same record_id are rejected
-- at the application level (§4.4 step 4).
CREATE TABLE IF NOT EXISTS sync_record_authors (
    record_id     TEXT PRIMARY KEY,
    author_pubkey TEXT NOT NULL,
    pinned_at_ms  INTEGER NOT NULL
);
```

### 6.2 Query patterns

**Manifest build** (called per `/sync/manifest`):

```sql
SELECT record_id, kind, author_pubkey,
       content_hash AS latest_content_hash,
       wall_ts_ms   AS latest_wall_ts_ms
  FROM sync_records r1
 WHERE wall_ts_ms = (SELECT MAX(wall_ts_ms) FROM sync_records r2
                      WHERE r2.record_id = r1.record_id)
   AND content_hash = (SELECT MAX(content_hash) FROM sync_records r3
                        WHERE r3.record_id = r1.record_id
                          AND r3.wall_ts_ms = r1.wall_ts_ms)
 ORDER BY record_id ASC;
```

The `idx_sync_records_lww` covers this — the planner picks (record_id,
wall_ts_ms DESC, content_hash DESC) and the inner correlated subquery
hits the same index. For 50 records this is microseconds; for 50,000
it's still milliseconds. We don't need a materialized "current view"
table.

**Current view for one record:**

```sql
SELECT envelope_json
  FROM sync_records
 WHERE record_id = ?
 ORDER BY wall_ts_ms DESC, content_hash DESC
 LIMIT 1;
```

**Pull-side stream** (`/sync/record/<record_id>?since=<ts>`):

```sql
SELECT envelope_json
  FROM sync_records
 WHERE record_id = ?
   AND wall_ts_ms > ?
 ORDER BY wall_ts_ms DESC, content_hash DESC
 LIMIT ?;
```

### 6.3 WAL + concurrency

The sync subsystem follows the same pattern as `swf.bundles.store`:
`PRAGMA journal_mode=WAL` is set best-effort on the writer connection;
read queries run on short-lived connections. There's one writer (the
sync apply loop); contention is between the writer and the HTTP
read serving manifest/record requests. WAL handles that without
blocking either side.

### 6.4 Schema migration + idempotency

`ensure_sync_schema(conn)` runs at every sync-subsystem entry point
(daemon boot, first HTTP request, test harness setup), mirroring
`swf.bundles.store.ensure_schema` (§2 of #93 phase 1). Idempotent via
`CREATE ... IF NOT EXISTS`.

No data migration from v0 (no prior tables exist). The v0 markdown
import (§10) populates this schema fresh.

---

## 7. History + restore

### 7.1 History

Every accepted envelope is **forever**. The `sync_records` table
grows by ~1 row per edit per record per cohort member. Steady-state
estimate: 50 members × 1 edit/day = 50 rows/day = 18,250 rows/year.
At ~2 KB per row (envelope JSON), that's ~36 MB/year. Manageable.

Eviction is **out of scope for Phase 2**. §9.2 flags it as a future
question; the working assumption is "never evict, the user's disk is
their archive."

### 7.2 History API

`GET /sync/record/<record_id>/history?limit=<n>` returns every
envelope for `record_id`, newest-first.

```json
{
  "schema": "swf.sync.record_history.v1",
  "record_id": "amiller",
  "envelopes": [ /* full envelopes, wall_ts_ms DESC, content_hash DESC */ ],
  "more": false
}
```

Auth: same as other peer routes (none on loopback, signed envelopes
end-to-end). The Electron app calls this to render a "version history"
sidebar. Limit default 50, max 1000.

### 7.3 Restore

There is no special-purpose restore endpoint. The semantics are:

> "Restore" = author signs a new envelope whose `content` is a prior
> snapshot, and whose `wall_ts_ms` is `now`.

The author retrieves the prior content via `GET /sync/record/<r>/history`,
picks the version they want, copies the `content` into a fresh
envelope, bumps `prev_hash` to the current latest's `content_hash`,
sets `wall_ts_ms = now`, signs, and POSTs (or — since there's no POST
in Phase 2 — saves locally; the sync loop picks it up via the local
`sync_records` insert path).

**UI affordance:** the Electron app's profile-editor exposes a "Show
history" affordance per record. Each historical entry has a "Restore"
button that pre-populates the editor with that version's `content`.
The user reviews + saves; saving signs a fresh envelope. The "restore"
is implemented entirely at the UI layer; the protocol just gives the
UI the history it needs.

### 7.4 Local-write path

Since this spec doesn't define a `POST /sync/record/<r>`, how does a
cohort member's *own* edit get into the sync_records table? Two
options for the implementer to pick from (issue tagged in §9.5):

**Option A (recommended) — internal writer API.** The Electron app
talks to swf-node over a separate non-sync mechanism (e.g. a new
`POST /sync/local_record` route gated by `SWF_AGENT_TOKEN`) to submit
a freshly-signed envelope. Bind-mode aware: on loopback bind, no
auth; on LAN bind, the agent-token is required, matching the existing
`/web_search` pattern from `docs/HTTP_API.md`.

**Option B — file-drop directory.** Electron writes a signed envelope
file to `$SWF_STATE_DIR/sync_inbox/`; swf-node tails the directory and
applies envelopes from there. Simpler in transport terms, but
introduces a filesystem coordination concern (inotify on Linux, FSEvents
on Mac).

Phase 2 picks **Option A** for symmetry with the existing
`/bundles` POST path (`peer_server._do_bundles_post`). The new route
is documented in §11 as part of the migration plan.

---

## 8. Bootstrap

### 8.1 First launch (no peers, no records)

1. `swf-node` boots. `get_or_create_identity()` produces the
   Ed25519 keypair under `~/.config/swf/identity.{key,pub}` if absent
   (existing behavior — `swf.identity`).
2. The sync subsystem runs `ensure_sync_schema(conn)` on the indrex
   DB. The two new tables exist; both are empty.
3. The peer's pubkey is advertised over mDNS via the existing
   `_indrex._tcp.local.` service type (§8.5). No new service type.
4. The poll loop wakes up every `SWF_SYNC_POLL_INTERVAL_SECS`
   (default 30s). With no cohort peers visible yet, it does nothing.

### 8.2 Cohort-keys file (`cohort-keys.json`)

Distributed out of band — shipped with the Electron app. JSON file
under `$SWF_CONFIG_DIR/cohort-keys.json`:

```json
{
  "schema": "swf.cohort_keys.v1",
  "cohort_id": "shape-rotator-2025-cohort-3",
  "generated_at_ms": 1716000000000,
  "members": [
    {"handle": "amiller",
     "pubkey": "ed25519:<hex>",
     "added_at_ms": 1715000000000},
    {"handle": "halcyon",
     "pubkey": "ed25519:<hex>",
     "added_at_ms": 1715000000000}
  ]
}
```

**Resolution order** (mirrors `swf.bundles.alchemists._candidate_paths`):

1. `$SWF_COHORT_KEYS_FILE` (env override).
2. `$SWF_CONFIG_DIR/cohort-keys.json`.
3. `~/.config/swf/cohort-keys.json`.

A missing file is **not** a daemon failure: sync logs a warning,
authenticates no envelopes, and waits. The cohort-keys file is updated
out of band (Electron app push, manual edit, eventual signed-introduction
mechanism — see §9.1). On file change (`st_mtime_ns` poll, same
pattern as `swf.bundles.alchemists.load_alchemists_cached`), the loaded
list refreshes within one poll tick.

The `handle` field is a UX helper — it's the cohort member's
human-readable name, mirrored into the manifest UI. The protocol
itself doesn't consume `handle`; only `pubkey` is consulted.

### 8.3 Author pinning

The first time a peer accepts a valid envelope for `record_id = R`,
it inserts `(R, author_pubkey)` into `sync_record_authors`. From then
on, every envelope for `R` must have the same `author_pubkey`. This
mirrors single-writer-per-record semantics (§1.1) at the storage layer.

**What about cohort-key membership changes?** If a member is removed
from `cohort-keys.json`, their author pin stays — their existing
records remain in the local store (history is forever) but new
envelopes signed by that key are dropped at the cohort-key whitelist
check (§4.4 step 3). Re-adding the member resumes ingestion.

**What about a member whose `record_id` collides with another's?**
Out of scope. `cohort-keys.json` is curated by the cohort lead; the
handle column is unique by convention. A future hardening pass
could enforce uniqueness server-side (§9.6).

### 8.4 Identity key handling

The local node's identity key (`swf.identity.get_or_create_identity()`)
is generated on first daemon boot if absent. The pubkey appears in the
`/.well-known/indrex` response (existing peer-handshake path) and is
also the `author_pubkey` of envelopes the local user signs.

The cohort lead's process for adding this user to the cohort:

1. User boots `swf-node`. Pubkey is in `~/.config/swf/identity.pub`.
2. User copies pubkey to the cohort lead (out of band — Slack DM,
   PR against the cohort-keys repo, etc.).
3. Cohort lead updates `cohort-keys.json`, pushes a new Electron
   release (or just the JSON file).
4. Other peers' `cohort-keys.json` refreshes; user's envelopes start
   passing the whitelist check on every peer.

No TOFU step. The cohort-keys file is the trust root.

### 8.5 mDNS posture

**Decision: extend the existing `_indrex._tcp.local.` service type.
Do not introduce a new service type.**

Justification:

- swf-node's mDNS layer already advertises one service per running
  node (`swf.discovery._SERVICE_TYPE`). Adding a second service type
  doubles the mDNS announce traffic + introduces a coordination
  question (which one is canonical for "swf-node is here?").
- The existing TXT record carries `pk` (pubkey) and `proto` (protocol
  version string). Sync-capable peers are identified by a new TXT
  key, `sync` (boolean), with value `"v1"` when the peer speaks this
  spec. Older peers omit the key and are skipped by sync.
- Peer-discovery union (`swf.discovery.discover_all_peers`) returns
  the union of mDNS + Tailscale + peers.yaml peers; sync filters
  on the `sync` TXT key + cohort-keys membership. Two filters, no
  new wire surface.

`docs/CONFIG.md` will gain an `SWF_SYNC_DISABLE` env var (default
unset; set to `1` to suppress sync entirely while leaving search +
bundles intact). When set, the TXT record's `sync` key is omitted.

---

## 9. Decisions (formerly "open questions")

These are the design calls that need to land before implementation
can be unambiguous. Each was an open question in an earlier draft;
the resolutions below are calibrated for **the 10-week, 50-person
Shape Rotator OS cohort with a known-trust LAN model**, and assume
ship-and-iterate beats speculative complexity. Phase 3 (post-cohort)
can revisit anything here.

### 9.1 Key rotation — DEFER

Phase 2 does **not** implement a `rotation` record kind. Over 10
weeks, key-rotation events are rare; the cost of designing for
concurrent-rotation + lost-key + cohort-disagreement edge cases is
too high for what's almost certainly zero real usage.

**Phase 2 recovery procedure for a lost key** (documented, not
automated):

1. Member generates a new Ed25519 key locally.
2. Member opens a PR against the cohort's `cohort-keys.json` updating
   their entry's `pubkey` field (handle stays the same).
3. Once merged + the Electron app re-fetches the file, the new key
   takes over as the expected author for the member's `record_id`.
4. Historical envelopes signed by the old key remain visible (history
   never breaks). New writes must use the new key.
5. Mismatch handling: incoming envelopes signed by the OLD key after
   the rotation are accepted into history but NOT applied as latest
   (since `record_authors[record_id]` now points at the new key, the
   sig check fails). Practical effect: the rotated-out key can no
   longer overwrite the member's record. That's the desired
   behavior.

Phase 3 adds a proper `rotation` envelope if the cohort produces
empirical demand.

### 9.2 Eviction of historical envelopes — NEVER (Phase 2 scope)

History is forever per §7.1. For the cohort math (50 people × ~100
edits/member × 4 KiB/envelope) the worst case is 20 MiB total over
the 10-week program — not a problem. Premature pruning would also
break the "restore" affordance the user explicitly asked for, which
is the entire reason history was specified in the first place.

If a multi-year archive ever becomes a storage concern (multi-cohort
swf-node, year-3 audit), a future phase can introduce author-signed
tombstone envelopes. The protocol stays open to that — `record_type`
already has space for new kinds. We just don't ship it now.

### 9.3 Max envelope size — keep the 64 KiB cap

Profile records' worst case (full personal-API + multi-paragraph
bio + 6–8 links) lands well under 8 KiB. The 64 KiB ceiling is
defensive, not a target. Rich content (long-form notes, research
docs, presentations) should NOT travel through the sync substrate
— it belongs in the existing `world_knowledge` markdown archive and
referenced from a sync record via URL.

Implementer guidance: reject envelopes with `len(canonical_form) >
65536` at receive time with a 413 status. Do not negotiate higher
caps — if a cohort member wants to share a long doc, the answer is
"publish to world_knowledge, link from your profile."

### 9.4 Wall-clock LWW with 5-minute future window — final for Phase 2

We use wall-clock `wall_ts_ms`. Envelopes with `wall_ts_ms` more
than **5 minutes** in the future relative to the receiver's local
clock are rejected (status 400, code `clock_too_far_ahead`). Modern
machines on NTP have sub-second skew; 5 minutes catches both
malicious backdating and "my battery died and the clock reset to
2001" with margin.

HLC (Hybrid Logical Clock) is **not** added in Phase 2. We accept
that two members editing the same minute will see LWW based on
whichever wall clock was higher; for "edit your own profile" from
a SINGLE device that's acceptable.

The well-known failure mode of wall-clock LWW (research finding
from `docs/PROTOCOL_RESEARCH.md` §1, citing Cassandra / DynamoDB
operational experience) is that data can be silently discarded when
peer clocks disagree more than the network round-trip. For our
cohort:
- Same-author-multi-device clock-skew loss is real but bounded by
  the §9.9 fork policy (quarantine + log) — a near-tied edit from
  a second device is preserved in history regardless of which one
  "wins" current view.
- Inter-author concurrency is rare-to-impossible because
  single-writer-per-record means only ONE author is editing each
  record.

If post-cohort usage shows skew-driven loss, Phase 3 adds an HLC
layer where `wall_ts_ms` becomes the high bits and a per-author
logical counter becomes the low bits — backward-compatible because
the existing field becomes `(hlc_high, hlc_low)` and old envelopes
get `hlc_low = 0`.

### 9.5 Local-write endpoint — confirmed Option A (`POST /sync/local_record`)

The Electron app pushes profile edits to swf-node via HTTP. The
route is agent-bearer-gated (matches the `/web_search` /
`/local_search` / `/fetch_url` auth-split rules in `docs/HTTP_API.md`).
The file-drop alternative is rejected: it has worse error semantics,
no way to surface "envelope rejected because signature failed," and
no obvious atomic boundary.

### 9.6 record_id collisions — protocol-level enforcement (defense in depth)

Two layers, both required:

1. **`cohort-keys.json` validator** rejects duplicate `handle`
   values at parse time. Phase 2 ships this in
   `swf.cohort_keys.load()`.
2. **Server-side first-envelope pinning.** When swf-node receives
   the first valid envelope for a previously-unknown `record_id`,
   it pins `record_authors[record_id] = author_pubkey` and persists
   it. Subsequent envelopes for the same `record_id` from a
   DIFFERENT author are rejected with status 409 and code
   `record_id_owned_by_other_author`.

Social convention alone is not enough — accidental collision (two
new cohort members claiming the same handle in a 24-hour window) is
plausible and the protocol should fail loudly, not silently let one
overwrite the other.

### 9.7 Active push (`/sync/record/<r>/announce`) — DEFER

Phase 2 ships 30-second polling only. Sub-second propagation is a
nice-to-have but not a need-to-have for "I updated my bio." Adding
push semantics (per-record listeners, idempotency for repeated
announces, exponential backoff on retry, dead-peer detection)
doubles the protocol surface area for a UX gain nobody has yet
asked for.

If cohort usage shows people complaining about edit-propagation
latency, Phase 2.1 lands the announce route. The spec leaves the
endpoint name reserved.

### 9.8 Cohort-keys distribution — JSON-in-repo for the cohort program

Phase 2 ships hand-edited `cohort-keys.json` in the Electron app
repo. New cohort member sends pubkey via Matrix → admin opens PR →
next Electron release pulls the updated file in. Frequency: handful
of PRs over 10 weeks.

The Phase 3 design (signed introductions / web-of-trust) targets
**after** the cohort completes the 10-week program. No commitment
to ship inside the program; we want real usage data on how often
new members join + how often keys rotate before designing the
trust-graph mechanics.

### 9.9 Single-writer fork policy — quarantine + log + don't replicate

Research finding (`docs/PROTOCOL_RESEARCH.md` §1, footgun #2): when
the same author publishes two divergent chains for the same
`record_id` — typically from two devices that didn't sync first —
every protocol in the survey (Hypercore, SSB, Matrix) handles it
differently, and several **silently corrupt the chain**. This is
the single most pressing finding from the research pass; the spec
MUST state a policy before the first multi-device client lands.

**Detection.** When swf-node receives a valid envelope E whose
`author_pubkey` matches `record_authors[record_id]` AND `prev_hash`
points at a hash that swf-node has seen, but the `wall_ts_ms` is
LOWER than an envelope already in the chain at that depth (i.e. E
is a competing sibling of an envelope at the same prev_hash slot),
we have a fork.

More precisely: a fork is **two envelopes E1 and E2 with the same
`prev_hash` and the same `record_id` and the same `author_pubkey`
but different `content_hash`**.

**Phase 2 response** (modeled on SSB's forked-feed handling):

1. **Persist both envelopes** in `sync_records` (history is never
   lost — neither version is deleted).
2. **Set a `forked: TRUE` column** on the affected `record_id` in
   the `record_authors` table.
3. **Stop replicating** the affected `record_id` outbound — peers
   that don't yet know about the fork shouldn't get it from us.
4. **Log a `RECORD_FORK_DETECTED` event** with both content_hashes,
   the author, and the timestamps. Surface in `/health` as
   `forked_records: [...]`.
5. **Refuse to apply** EITHER envelope as the "latest view" for
   that record until the author resolves it: when the author next
   writes a new envelope (with `prev_hash` pointing at one of the
   two forked siblings, or with a fresh `prev_hash: null` if they
   want to reset), that NEW envelope becomes the latest and the
   `forked: TRUE` flag clears.

**UX implication** for the Electron app: when a user opens an app
on a second device and edits their record before the second device
has synced, the second device's edit will fork. The Electron app
SHOULD wait for the swf-node `/sync/manifest` to settle (one sync
cycle, ~30s on cold start) before allowing edits — and SHOULD
warn the user if any of their records are flagged `forked: TRUE`
in `/health`. (Phase 2 ships the protocol-level detection +
quarantine; Electron UX warning is a follow-up.)

This policy preserves the audit trail (you can always see what
happened), avoids silent corruption, and gives the author a clean
escape hatch (just write another envelope to resolve).

### 9.10 Replay + dedup — by content_hash, NOT signature bytes

Research finding (`docs/PROTOCOL_RESEARCH.md` §1, footgun #4):
Ed25519 has a signature-malleability gotcha — non-canonical `S`
values are accepted by some libraries (incl. older releases of
PyNaCl / cryptography). If you dedup by `signature_bytes`, an
attacker who replays a malleable variant of the SAME envelope will
pass dedup AND verify — silent double-acceptance.

**Phase 2 dedup rule:** the `sync_records` table has a UNIQUE
INDEX on `(record_id, content_hash)`. Replay attempts hit the
INSERT OR IGNORE path. This is correct regardless of signature
canonicalization because `content_hash` covers the canonical
serialized envelope MINUS the signature field (§3.3) — a malleable
signature variant has the same `content_hash`, so it dedupes.

(The signature is still verified before we even compute
`content_hash`. The point is: dedup must use the content-side
identity, not the signature-side identity.)

### 9.11 Things we still don't know

These genuinely remain open (no decision yet):

- **Phase 3 entry criteria.** What signal triggers building active
  push, HLC, key rotation, web-of-trust? Probably "cohort program
  ends + we want to keep using this." Re-open before then.
- **Multi-LAN sync.** Spec is LAN-only today. If a cohort member
  works remotely, their swf-node doesn't see anyone else's. Bridging
  via Matrix or a relay is plausibly Phase 4.
- **Cross-cohort isolation.** If swf-node ever hosts records for
  multiple cohorts on the same machine (mentor in multiple programs,
  etc.), how do `cohort-keys.json` boundaries express that? Out of
  scope for Phase 2; flag if it comes up.
- **Scale-out diff algorithm.** If `record_id` count ever exceeds
  ~10k, manifest-diff becomes wasteful and the Negentropy /
  Willow-style range-based set reconciliation becomes the right
  answer (`docs/PROTOCOL_RESEARCH.md` §2). Not needed for the
  cohort scale; flag if records become document-class state.

---

## 10. Migration from v0

### 10.1 What v0 looks like

Before this spec lands, cohort profile data lives in a directory of
markdown files: `cohort-data/<handle>.md`. The files are hand-edited;
there is no signing, no sync, no append-only history. The Electron
app reads the directory at startup.

### 10.2 What v1 brings

A peer running this spec emits signed envelopes for each
`cohort-data/<handle>.md` that the local user is the author of (i.e.
the handle matches the local pubkey's `cohort-keys.json` entry). The
v0 directory is **not deleted** by the migration — it becomes the
seed for the initial sync_records insert, and afterwards it's left
alone as a human-readable mirror.

### 10.3 Migration script

A one-shot CLI sub-command:

```
swf-node sync migrate-v0 [--cohort-data-dir PATH] [--dry-run]
```

Behavior:

1. Locate the v0 markdown directory. Default: `$SWF_KNOWLEDGE_DIR/../cohort-data/`
   (configurable via `--cohort-data-dir`). Optional `SWF_COHORT_DATA_DIR`
   env override.
2. For each `<handle>.md` file:
   - If `handle` matches the local node's `cohort-keys.json` entry
     for the local pubkey, parse the markdown's frontmatter +
     body into a `content` object, sign a `kind=person` envelope
     with `wall_ts_ms = file_mtime_ms`, `prev_hash = null` (first
     version), and insert it via the sync-apply path. The envelope
     gets gossiped to peers on the next tick.
   - If `handle` is some other member's, **do not** sign anything
     for them — wait for them to publish their own v1 envelope. Drop
     the file from the v0 read path going forward; the Electron UI
     should fall back to "no profile yet" rather than serving the
     stale v0 content.
3. `--dry-run` prints what would be migrated without writing.

### 10.4 Electron app data-source switch

The Electron app's profile-renderer changes its source of truth from
"read `cohort-data/<handle>.md`" to "query swf-node's
`/sync/record/<handle>` or local sync_records." This is a UI-side
change; the swf-node migration is a one-way switch (no rollback once
envelopes are signed, because v1 envelopes immortalize the v0 content
under the local author's pubkey).

### 10.5 What gets lost

v0 markdown files for members whose pubkey isn't on the local
`cohort-keys.json` are orphaned. They're left on disk for manual
review but stop being rendered. The expectation is that every cohort
member runs the migration on their own laptop; the LAN converges
within one polling tick.

---

## 11. LAN-trust mode

> Added in v0.11.0. Opt-in dev flag for single-user multi-device
> deployments. **Not for production cohorts.**

### 11.1 Motivation

The cohort-keys gate (§4.4 step 3, §8.2) and the single-writer pin
(§9.6) are the right defaults for a multi-user cohort where each
handle has a stable owner and writes must not collide. They are too
strict for the most common Shape Rotator OS testing scenario today:

> A single user has SROS installed on multiple personal laptops on
> the same WiFi. Each laptop runs its own swf-node with its own
> Ed25519 keypair. The user wants any peer they discover via mDNS
> on the LAN to be trusted to write any record.

The proper long-term fix is **multi-pubkey-per-handle in cohort-keys**
(§8.2 extended so each handle carries a list of authorized pubkeys
rather than a single one). That's a bigger change for a follow-up
release. LAN-trust mode is the simpler dev-mode flag that unblocks the
two-laptop testing path today.

### 11.2 Activation

Set the env var `SWF_TRUST_LAN_PEERS=1` (or `true`, `yes`, `on` —
case-insensitive) on the swf-node process. Re-read on every gate
check; no daemon restart required.

```bash
SWF_TRUST_LAN_PEERS=1 swf-node
```

The `swf.sync.is_lan_trust_mode()` helper is the single source of
truth — every gate site consults it fresh.

### 11.3 Semantics

When LAN-trust is on, the daemon relaxes **three** gates and keeps
**one**:

| Gate                                                          | Default mode | LAN-trust mode |
| ------------------------------------------------------------- | ------------ | -------------- |
| Envelope shape + size + content-hash (§3.5, §4.4 steps 1–2,6) | enforced     | enforced       |
| **Cohort-keys author whitelist** (§4.4 step 3, §8.2)          | enforced     | **bypassed**   |
| **Single-writer-pin per record_id** (§4.4 step 4, §9.6)       | enforced     | **bypassed**   |
| **Fork detection** (§9.9)                                     | active       | **suspended**  |
| **Ed25519 signature verify** (§4.4 step 5)                    | enforced     | **enforced**   |
| Clock-skew window (§4.4 step 7, §9.4)                         | enforced     | enforced       |
| Replay dedup on `(record_id, content_hash)` (§5.3, §9.10)     | active       | active         |

Concretely:

1. **`POST /sync/local_record`** (§7.4) skips the cohort-keys gate.
   The `author_pubkey` is still derived from the local identity and
   the envelope is still self-signed, the agent-bearer token is
   still required, and the apply-path signature verify still runs.
   The 503 `no_cohort_keys` and 403 `not_authorized_author` /
   `author_not_in_cohort` responses are not emitted in this mode.

2. **`apply_envelope`** (§4.4) accepts an envelope from any
   `author_pubkey` that produces a valid signature. The
   `sync_record_authors` row is still inserted on first observation
   (informational), but a later envelope from a different author
   for the same `record_id` is **accepted as part of the chain**
   rather than rejected with `record_id_owned_by_other_author`.
   LWW by `(wall_ts_ms, content_hash)` applies normally — the
   latest write wins regardless of which key signed it.

3. **Fork detection** (§9.9) is suspended. The notion of a fork is a
   single-writer-per-record concept; once we allow multiple authors
   per `record_id` the sibling query is meaningless. No
   `RECORD_FORK_DETECTED` log line is emitted, no `forked=1` flag
   is set, and `build_manifest` does not suppress the record.

4. **`sync_loop`** (§4.3) drops the cohort-keys filter on peer
   discovery and on the apply path. Every mDNS-discovered peer is
   contacted; every signed envelope from any peer is candidate for
   apply. The pull path still runs the full shape + signature
   pipeline on each envelope.

### 11.4 Security tradeoff

> **Anyone on your LAN can write anything to your store.**

The cohort-keys file is the access-control root in the default mode
— without it, a hostile peer on the same WiFi can send a signed
envelope with their own keypair claiming to be `amiller` and your
store will accept it (since signature verify passes and there is no
allowlist to consult).

You should run LAN-trust mode **only when**:

- The LAN you are connected to is trusted (home WiFi, personal
  hotspot, isolated lab VLAN). The threat surface is anyone with
  L2 reach who can answer mDNS queries.
- You are deploying SROS on devices you personally own and the
  intent is "auto-merge across my laptops" rather than "share with
  others."
- The data you are syncing is not so sensitive that an untrusted
  observer rebroadcasting a forged envelope would matter.

Do **NOT** run LAN-trust on:

- Coffee-shop WiFi or any open access point.
- Office / co-working networks where you don't control L2.
- Networks where you ship swf-node bound to `0.0.0.0`. (Default
  bind is loopback, but if you've reverse-proxied with no auth in
  front, LAN-trust expands the attack surface.)

### 11.5 Migration path

When the multi-pubkey-per-handle cohort-keys extension lands
(tracked in the follow-up issue), the proper deployment pattern for
"my two laptops" becomes:

```json
{
  "schema": "swf.cohort_keys.v2",
  "members": [
    {"handle": "myself",
     "pubkeys": ["ed25519:<laptop1>", "ed25519:<laptop2>"]}
  ]
}
```

…and `SWF_TRUST_LAN_PEERS` is no longer needed for that scenario. We
keep the flag in v0.11+ for legitimate dev / debugging use cases
(integration tests, ephemeral demo nets) but the typical path
graduates back to the cohort-keys gate.

### 11.6 Test coverage

`tests/sync/test_lan_trust_mode.py` covers:

- `is_lan_trust_mode()` truthy / falsy value parsing.
- `apply_envelope` accepts an unknown-author envelope under
  LAN-trust; same envelope is rejected with `author_not_in_cohort`
  without LAN-trust.
- Two envelopes from different keys for the same `record_id` are
  both stored, no fork is set, LWW picks the higher-`wall_ts_ms`
  winner.
- Sibling envelopes (same `prev_hash`, different `content_hash`)
  are accepted as a chain — no `RECORD_FORK_DETECTED`.
- Tampered envelope is still rejected with `signature_invalid`.
- `POST /sync/local_record` returns 201 (not 503) under LAN-trust
  with no cohort-keys file present.
- Two-peer integration: peer A and peer B with separate identities
  and **no shared cohort-keys** successfully sync a record via
  `sync_with_peer` under LAN-trust.

---

## 12. Sync event ring buffer + `/sync/log` endpoint

> Added in v0.11.3. Powers the SROS renderer's live "network activity"
> feed + per-peer heartbeat pulses.

### 12.1 Motivation

The sync subsystem is a quiet background loop. Operators see one
`logger.info("tick visited=N pulled=K applied=M")` line every 30s on
stderr and nothing else. That's adequate for ops but useless for a
renderer trying to draw a pulse-on-activity visualization.

§12 adds a tiny in-process ring buffer of recent sync events surfaced
over a read-only HTTP endpoint. The renderer polls it on a short
interval (a few seconds) and uses the event stream to drive its
graphical state — per-peer heartbeat pulses, a scrolling activity
feed, a `pulled` flash when an envelope lands.

### 12.2 The ring buffer

Module: `swf.sync.event_log`. Module-level state:

```python
_RING_MAXLEN = 200
_event_ring: deque[dict] = deque(maxlen=_RING_MAXLEN)
_event_lock = threading.Lock()
_event_seq = 0  # monotonic counter
```

Design constraints:

- **Per-process.** The ring is in-memory only. Restarts wipe it. This
  is intentional — durable history of the sync substrate lives in
  `sync_records` (§6), and §7's `/sync/record/<id>/history` route
  serves it. The ring is a renderer-tail for live activity, not a
  journal.
- **Bounded.** `maxlen=200` keeps memory trivial (~200 small dicts).
  On a busy node the oldest events fall off; the renderer is expected
  to poll fast enough to never lose state.
- **Lock-minimal.** The emit path is on the sync hot loop. The
  critical section is: bump `_event_seq`, build dict, append. No
  JSON encoding, no I/O, no logging. `get_sync_events` snapshots the
  deque under the lock then filters outside.
- **Monotonic seq.** Events carry a hand-rolled `seq` int that
  increments on every emit. The renderer uses `seq` as its cursor;
  `ts_ms` is informational and collision-prone, `seq` is total.

### 12.3 Event shape

All events are flat JSON dicts with three reserved fields plus
kind-specific payload:

```json
{
  "seq": 17,
  "kind": "pulled",
  "ts_ms": 1731974400123,
  "peer_pubkey": "ed25519:abc…",
  "peer_url": "http://10.0.0.42:6651",
  "record_id": "amiller",
  "wall_ts_ms": 1731974398555,
  "content_hash": "sha256:…"
}
```

Caller payload keys that collide with `seq` / `kind` / `ts_ms` are
silently dropped — the ring's reserved fields are the source of
truth.

### 12.4 Event kinds

| Kind                  | Where emitted                                           | Payload                                                                                       |
| --------------------- | ------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `tick`                | End of every `sync_loop._tick()` iteration              | `visited`, `pulled`, `applied`, `duration_ms`                                                 |
| `manifest_fetched`    | Per peer in `sync_with_peer` on a successful manifest fetch | `peer_pubkey`, `peer_url`, `record_count`                                                  |
| `peer_unreachable`    | On the `reachable → unreachable` transition (or the first-ever unreachable observation for a peer). Manifest-fetch failure on a peer that's already in the `unreachable` state is SILENT to avoid spamming the feed every tick while a peer sleeps. | `peer_pubkey`, `peer_url`, `reason`               |
| `peer_reachable`      | On the `unreachable → reachable` transition (FIRST successful manifest fetch after a prior `peer_unreachable` for the same pubkey) | `peer_pubkey`, `peer_url`                       |
| `pulled`              | Per envelope where `apply_envelope(...).was_new=True` from a remote pull | `peer_pubkey`, `peer_url`, `record_id`, `wall_ts_ms`, `content_hash`        |
| `applied_local`       | On `POST /sync/local_record` returning 201              | `record_id`, `wall_ts_ms`, `content_hash`                                                     |

Notes:

- `tick` fires every loop iteration **even when nothing changed** —
  that's the renderer's heartbeat for the subsystem itself.
- `manifest_fetched` carries `record_count` so the renderer can size
  a per-peer pulse by traffic load without us emitting one event per
  remote record_id.
- `pulled` is emitted only for `was_new=True` apply results. Replays
  (`was_new=False`) would spam the feed.
- Both `peer_reachable` and `peer_unreachable` are **edge** events as
  of v0.12.1: each fires only on a state transition, never on the
  steady-state observation. A peer that stays down across many sync
  ticks emits exactly one `peer_unreachable` (when it first goes down)
  and stays silent until it recovers (one `peer_reachable`). This
  contains the renderer's traffic feed when a cohort member's laptop
  closes for an hour. Implementation: see `_record_peer_status` in
  `src/swf/sync/sync_loop.py` — the helper diffs the prior state and
  only emits on change.
- The very first contact with a peer never emits `peer_reachable`; the
  natural `manifest_fetched` event suffices as a positive heartbeat.

### 12.5 `GET /sync/log`

```
GET /sync/log?since_seq=<int>&since_ms=<int>&limit=<int>
```

No auth — same posture as `/sync/manifest`. The ring is per-process
and the event payloads describe sync activity that is already
inferable from `/sync/manifest`, so there's no incremental disclosure.

Query parameters:

| Parameter   | Type | Default | Notes                                                            |
| ----------- | ---- | ------- | ---------------------------------------------------------------- |
| `since_seq` | int  | absent  | Return events with `seq > since_seq`. Primary cursor.            |
| `since_ms`  | int  | absent  | Return events with `ts_ms > since_ms`. Fallback. Ignored if `since_seq` is set. |
| `limit`     | int  | 200     | Max events in the response. Clamped to 500.                      |

Bad input (`since_seq=-1`, `since_seq=abc`, `limit=0`) returns 400
with a structured `{"error": "invalid_<field>"}` body. `limit` >
max clamps silently to 500.

Response:

```json
{
  "schema": "swf.sync.log.v1",
  "node_pubkey": "<own pubkey base64url>",
  "tail_seq": 217,
  "events": [
    {"seq": 218, "kind": "tick", "ts_ms": 1731974430000,
     "visited": 1, "pulled": 0, "applied": 0, "duration_ms": 23},
    ...
  ]
}
```

`tail_seq` is the highest `seq` currently in the ring (or 0 when
empty). It's a separate field — not just `events[-1].seq` — so a
client polling with `since_seq=tail_seq` gets an empty `events` list
on a quiet node and still knows where to resume on the next poll.
This means the renderer's poll loop is:

```text
cursor = 0
while running:
    body = GET /sync/log?since_seq=cursor
    render(body.events)
    cursor = body.tail_seq
    sleep(poll_interval)
```

### 12.6 Persistence + ops

The ring is **not durable**. Restarting `swf-node` clears the buffer
and resets `_event_seq` to 0. This is by design:

- The renderer is a debug surface, not a system-of-record. Lost
  events on a restart are acceptable.
- Persisting would require a separate sqlite table, schema migrations,
  and a vacuum policy — none of which buys anything for the live-feed
  use case.
- The durable view of "what was synced" is `sync_records` itself,
  queryable via `/sync/manifest` and `/sync/record/<id>/history`.

The existing `[sync-loop] tick visited=N pulled=K applied=M` stderr
log line is **unchanged**. Both pathways are useful: stderr for ops
tailing journalctl, ring for the renderer. The two emit sites are
independent — neither blocks the other.

### 12.7 Test coverage

`tests/sync/test_event_log.py` covers:

- Ring wraps at `_RING_MAXLEN`; the oldest events are dropped.
- `since_seq` returns strictly newer events; `since_seq=0` returns
  everything; `since_seq=tail` returns empty.
- `since_ms` returns events strictly after the threshold.
- `since_seq` takes precedence when both cursors are passed.
- `limit` caps the response slice (newest tail); `limit=0` empty;
  large `limit` no-op.
- Caller payload cannot overwrite reserved fields.
- Thread-safety smoke test: 4 emitter threads × 100 emits + 1
  reader, no exceptions, seq monotonic and unique.
- HTTP integration: spin a real `peer_server`, `POST /sync/local_record`,
  `GET /sync/log`, assert the `applied_local` event surfaces with
  the right `record_id` + `content_hash`. `since_seq=tail_seq` returns
  an empty events list.
- HTTP input validation: negative / non-numeric cursors → 400;
  `limit=0` → 400; `limit=99999` clamps silently.

---

## 13. Generalized node event log + `/node/log` endpoint

> Added in v0.12.0. The SROS Network tab renders a single unified
> stream of "what the daemon is doing right now" — mDNS discovery,
> peer health, sync activity, bundle puller, web search.

### 13.1 Motivation

§12 covered the sync subsystem only. The renderer's Network tab grew
to want one stream: mDNS appearance + disappearance, peer health
edges, sync ticks, scraper pulls, bundle puller, and web-search
activity. Maintaining one ring per subsystem would multiply the
state and force the renderer to poll N endpoints.

v0.12.0 generalizes the v0.11.3 sync ring to a node-wide ring:

- The same `deque[dict]`, the same `_event_seq` counter, the same
  lock. No new state, no new background timers.
- Every event carries a `category` field so the renderer (or
  endpoint) can slice the stream cheaply.
- `/sync/log` keeps working — it's now an alias for
  `/node/log?category=sync` (filtered server-side), so v0.11.3
  clients see no behavior change.

### 13.2 Event categories

Every event in the ring carries `"category": "<name>"` alongside the
existing `seq` / `kind` / `ts_ms` reserved fields:

| Category   | Meaning                                                                                                | Example kinds                                                       |
| ---------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| `sync`     | Sync-loop wire activity (the v0.11.3 events; back-compat surface for `/sync/log`)                       | `tick`, `manifest_fetched`, `pulled`, `applied_local`               |
| `mdns`     | LAN-local mDNS service browser observations                                                            | `mdns_peer_appeared`, `mdns_peer_disappeared`                       |
| `health`   | Per-peer reachability transitions                                                                      | `peer_unreachable`, `peer_reachable`                                |
| `ingest`   | Successful pulls of remote content (peer pages, bundles)                                               | `scraper_pulled`, `bundle_pulled`                                   |
| `search`   | `/web_search` lifecycle                                                                                | `web_search_started`, `web_search_completed`                        |
| `error`    | Pull/scrape/verify failures the renderer wants to surface as a fault state, distinct from `unreachable` | `scraper_error`                                                     |

Notes:

- `peer_unreachable` is `health`, not `error`: unreachable is a
  reachability **state**, not a fault. The renderer renders the two
  differently — a peer that's offline shows as muted; a peer that's
  shipping malformed bundles shows as red.
- The category is **not validated** at emit time (the hot path stays
  cheap). New emit sites are expected to use the canonical names
  enumerated in `swf.sync.event_log.NODE_EVENT_CATEGORIES`.
- Events emitted before v0.12.0 lack `category`. The ring is
  per-process, so a running daemon never holds a mix; the filter is
  defensive on the read side.

### 13.3 Event kinds (v0.12.0 additions)

| Kind                    | Category | Where emitted                                                                                                       | Payload                                                                                  |
| ----------------------- | -------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `mdns_peer_appeared`    | `mdns`   | `discovery.browse_mdns` listener add-callback, on a non-self pubkey, gated by a 60s per-pubkey dedupe window         | `peer_pubkey`, `peer_name`, `peer_url`, `txt_record_summary`                              |
| `mdns_peer_disappeared` | `mdns`   | `discovery.browse_mdns` listener remove-callback (zeroconf TTL expiry or explicit unregister)                       | `peer_pubkey`, `peer_name`                                                                |
| `scraper_pulled`        | `ingest` | `peer_scraper.pull_from_peer` after a successful `ingest_bundle` that stored at least one new row                    | `peer_pubkey`, `peer_url`, `count`, `kind_pulled` (always `"pages"` for the indrex puller; field is `kind_pulled` not `kind` because the latter is reserved for the event-type name) |
| `scraper_error`         | `error`  | `peer_scraper.pull_from_peer` on liveness-probe / HTTP / verify failures                                            | `peer_pubkey`, `peer_url`, `error`                                                        |
| `bundle_pulled`         | `ingest` | `bundles.puller.pull_from_peer` after a tick that ingested at least one new bundle                                  | `peer_pubkey`, `peer_url`, `bundle_count`, `bytes`                                        |
| `web_search_started`    | `search` | `/web_search` handler, immediately before invoking the router                                                       | `query_hash` (truncated SHA-256 of the query), `started_at_ms`                            |
| `web_search_completed`  | `search` | `/web_search` handler, after the router returns or raises                                                           | `query_hash`, `hit_count`, `duration_ms`, `source` (`"local"`, `"federated"`, `"error"`)  |

The raw query string is **never** included in a `search` event — only
the truncated hash. Queries can be sensitive; the ring is a renderer
observability surface, not an audit log.

The mDNS dedupe is per-pubkey, 60 seconds: zeroconf re-broadcasts a
service every ~25s by default, and without the gate the appear feed
would pulse on every re-announce. A `mdns_peer_disappeared` clears
the dedupe stamp so a real reconnect re-fires `mdns_peer_appeared`
immediately.

### 13.4 `GET /node/log`

```
GET /node/log?since_seq=<int>&since_ms=<int>&limit=<int>&category=<csv>
```

No auth — same posture as `/sync/log` / `/sync/manifest`. Query
parameters:

| Parameter   | Type | Default | Notes                                                                                                              |
| ----------- | ---- | ------- | ------------------------------------------------------------------------------------------------------------------ |
| `since_seq` | int  | absent  | Return events with `seq > since_seq`. Primary cursor.                                                              |
| `since_ms`  | int  | absent  | Return events with `ts_ms > since_ms`. Fallback. Ignored if `since_seq` is set.                                    |
| `limit`     | int  | 200     | Max events in the response. Clamped to 500.                                                                        |
| `category`  | csv  | absent  | Comma-separated list of categories to include (e.g. `sync,mdns`). Absent or empty → all categories.                |

Response:

```json
{
  "schema": "swf.node.log.v1",
  "node_pubkey": "<own pubkey base64url>",
  "tail_seq": 217,
  "events": [
    {"seq": 218, "kind": "mdns_peer_appeared", "category": "mdns",
     "ts_ms": 1731974430000,
     "peer_pubkey": "ed25519:...", "peer_name": "kettle",
     "peer_url": "http://10.0.0.42:6651",
     "txt_record_summary": "node=kettle port=6651 proto=searxng-wth-frnds/v0.3 v=0.12.0"},
    ...
  ]
}
```

`tail_seq` is the highest `seq` currently in the ring (or 0 when
empty). It's emitted independent of the filtered window so a
category-filtered poll still advances the cursor.

Bad input matches `/sync/log`'s behavior: negative or non-numeric
`since_seq` / `since_ms` → 400; `limit=0` → 400; `limit > max`
clamps to 500. Unknown category names are silently ignored on the
filter (the response simply has nothing from them); we don't 400 on
unknown values so a renderer polling a node from a future version
can opt into a category before the node has anything to emit for it.

### 13.5 Back-compat: `/sync/log`

`/sync/log` is unchanged from §12 from a client's perspective:

- Returns `{"schema": "swf.sync.log.v1", ...}` (not `swf.node.log.v1`).
- Same cursor + limit semantics.
- Filters events server-side to `category=sync`, so v0.11.3 clients
  that don't expect mDNS or search events on this endpoint don't
  start seeing them after the daemon upgrade.

Internally `/sync/log` is `/node/log` with a fixed `categories =
{"sync"}` filter; both routes share parsing via
`_parse_event_log_qs`.

### 13.6 Observability, not journaling

The same "this is per-process, restarts wipe it" disclaimer from
§12.6 applies to the node ring as a whole. Durable history for the
sync substrate still lives in `sync_records` (§6); for the bundle
substrate, in the `bundles` table; for the scraper, in the indrex
DB itself. The ring is the renderer's live tail, not an audit
mechanism.

The existing per-subsystem `logger.info` lines (sync-loop `tick`,
scraper `tick`, bundle puller `tick`) are unchanged. Every emit site
in v0.12.0 wraps the ring emission in `try/except` so a ring failure
never breaks the daemon's actual work.

### 13.7 Test coverage

`tests/sync/test_node_log.py` covers:

- `?category=` filter narrows results to the requested slice.
- Unknown category in `?category=` returns an empty events list
  (filter behaves as a server-side intersection).
- New event kinds (`mdns_peer_appeared`, `scraper_pulled`,
  `web_search_started`, etc.) are emitted and queryable through
  `/node/log`.
- Back-compat: `/sync/log` without `?category=` still returns ONLY
  `category=sync` events, even when other categories are present in
  the ring.
- `emit_sync_event` alias tags emitted events with
  `category="sync"`.
- `emit_node_event` accepts an explicit `category`.
- Ring-buffer failures inside emit sites don't crash the daemon
  (mDNS appear/disappear, scraper/bundle/web-search emits all wrap
  `try/except`).

---

## Appendix A: cross-references

- `DESIGN.md` — `src/swf/` module map; sync code lives under
  `src/swf/sync/` (new package).
- `docs/HTTP_API.md` — adds the `/sync/*` routes to the "peer routes"
  section; updates the auth-split summary.
- `docs/CONFIG.md` — adds `SWF_SYNC_POLL_INTERVAL_SECS`,
  `SWF_SYNC_DISABLE`, `SWF_COHORT_KEYS_FILE`, `SWF_COHORT_DATA_DIR`.
- `docs/THREAT_MODEL.md` — adds a "sync subsystem" STRIDE row.
- `src/swf/bundles/envelope.py` — reused for `canonicalize`. New
  module `src/swf/sync/envelope.py` thin-wraps it with the
  `swf-sync-v1` magic constant.
- `src/swf/bundles/signing.py` — reused for `sign_envelope` +
  `verify_envelope_signature`. No fork.
- `src/swf/identity.py` — reused for `get_or_create_identity` +
  `verify`.
- `src/swf/discovery.py` — extended to add `_peer_announced_hooks`
  parallel to `_ip_change_hooks`.
- `src/swf/peer_server.py` — adds `/sync/*` handlers parallel to the
  existing `/bundles/*` handlers.

## Appendix B: implementer's checklist

1. New package `src/swf/sync/` with modules: `envelope.py`,
   `store.py`, `verify.py`, `cohort_keys.py`, `protocol.py`,
   `puller.py`.
2. `sync_records` + `sync_record_authors` table creation via
   `ensure_sync_schema(conn)`; called from `peer_server` at boot
   and from every sync HTTP handler defensively.
3. `/sync/manifest`, `/sync/record/<r>`, `/sync/record/<r>/history`,
   `/sync/peers` HTTP routes in `peer_server.py`. Patterns match the
   existing `/bundles` handlers byte-for-byte.
4. Sync puller daemon thread (parallel to
   `swf.bundles.puller.start_puller`). Per-peer manifest fetch
   on a 30s tick; per-peer 5s rate-limit; per-peer exponential
   backoff via the existing `peers` table.
5. mDNS-announce hook in `swf.discovery` to wake the sync subsystem
   on a freshly-discovered peer.
6. `POST /sync/local_record` route for the Electron app's local
   writes (agent-bearer-gated on non-loopback bind).
7. `swf-node sync migrate-v0` CLI sub-command.
8. Metrics: `sync.envelopes_received`, `sync.envelopes_rejected.<reason>`,
   `sync.peers_synced`, `sync.manifest_diff_count` —
   exported via the existing `/metrics/snapshot` aggregator route
   when `--full` mode is on (parallel to the `bundles.puller_*`
   gauges).
9. Tests: shape validation, signature round-trip, LWW tiebreaker,
   prev_hash chain warning, clock-skew rejection, replay dedup,
   author-pin enforcement, manifest diff convergence
   (two-peer-in-one-process harness; mirrors the existing
   `tests/test_peer_server_bundles_*.py` style).
