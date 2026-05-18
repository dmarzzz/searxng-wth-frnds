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

## 9. Open questions

Decisions the maintainer should weigh in on before Phase 3 / hardening.

### 9.1 Key rotation + cohort-key updates

How does a member rotate their Ed25519 key without losing every record
they've ever authored?

Sketch: a `rotation` record kind — the old key signs an envelope
attesting `new_pubkey = X`, the receiver updates
`sync_record_authors[r] = X` for every `r` owned by the rotating
member, and the `cohort-keys.json` is updated out of band to point at
the new key. Edge cases (concurrent rotation + edit, lost old key, …)
need a real design.

**Question:** is this worth shipping in Phase 3, or can we get away
with "lost key → cohort-keys.json update + manual import of historical
envelopes under the new author"?

### 9.2 Eviction of historical envelopes

History is forever per §7.1, but on a multi-year cohort that's still
hundreds of MB. Should there be a `prune_history(record_id, keep_last_n)`
operation? If so, is it author-only (the author signs a tombstone
envelope) or cohort-wide (a quorum vote)?

**Question:** what's the right archive story? Do we ever delete?

### 9.3 Max envelope size

64 KiB cap per §3.5 is generous for profile records. But cohort
members occasionally want to include rich content (a markdown bio,
a list of links). Do we need a higher cap (256 KiB? 1 MiB?), or
should rich content stay out of sync entirely and live in a separate
swf-node primitive (e.g. the existing world_knowledge markdown
archive, referenced from a sync record by URL)?

**Question:** what's the policy on rich content in `content`?

### 9.4 Hybrid logical clock vs. wall-clock LWW

Wall-clock LWW has the known failure mode of clock skew. A 5-minute
window (§5.4) catches the obvious cases but not subtler ones. A hybrid
logical clock (Lamport timestamp combined with wall-clock) would be
robust to skew but adds protocol complexity. Phase 2 ships wall-clock;
Phase 3 hardening could revisit.

**Question:** is the 5-minute window the right value? Should we add
HLC in Phase 3 or accept wall-clock as the final story?

### 9.5 Local-write endpoint (`POST /sync/local_record`)

§7.4 picks Option A (HTTP-driven local writes) over the file-drop
alternative. Confirm? The route should be agent-bearer-gated like
`/web_search` per `docs/HTTP_API.md` auth-split rules.

### 9.6 `record_id` collisions

The protocol enforces single-writer-per-`record_id`, but it does NOT
enforce that two different members can't claim the same `record_id`
(e.g. both want `record_id="halcyon"`). Today this is prevented by
social convention + the `cohort-keys.json` `handle` field. Should the
protocol enforce it?

**Question:** add a `cohort-keys.json` validator that rejects duplicate
handles? Add a server-side check on first envelope for a `record_id`
that pins the handle to the author and refuses subsequent
mismatched-handle envelopes?

### 9.7 Active push (`/sync/record/<r>/announce`)

Phase 2.1 stub in §4.6. Worth shipping in Phase 2 itself for the
hackerspace-edit UX (sub-second propagation instead of 30s tick), or
defer to a follow-up?

### 9.8 Cohort-keys file format + distribution

Today: hand-edited JSON file shipped with the Electron app, updated
via PR. Phase 3+: signed-introduction web-of-trust where existing
cohort members can vouch for new ones with a signed envelope. The
Phase 3 design is open.

**Question:** what's the rollout from "JSON in repo" → "signed
introductions"? Do we ship Phase 3 alongside swf-node v1.0 or
sometime after?

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
