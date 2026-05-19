"""Apply / accept logic + manifest queries for the sync substrate.

Implements spec §5 (LWW + dedup + clock-skew), §9.9 (fork detection),
and §6.2 (manifest + record-pull queries).

The substrate splits cleanly:
  * `apply_envelope(conn, envelope, *, cohort_keys, now_ms=None)` runs
    the full receive pipeline (verify → pin → fork-detect → insert).
    Returns an `ApplyResult` so callers know whether the envelope was
    new, was a duplicate, was rejected, and (if so) why.
  * `build_manifest(conn)` returns the structure the HTTP layer
    serializes for `GET /sync/manifest`.
  * `latest_envelope(conn, record_id)` and `get_record_envelopes` /
    `get_record_history` cover the record-pull endpoint.

The apply path NEVER raises on legitimate input — every rejection path
returns a structured result so the HTTP layer can map to a status code
without try/except.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from .cohort_keys import CohortKeys
from .envelope import (
    canonicalize,
    validate_shape,
    verify_envelope_signature,
)
from .schema import ensure_schema

# Imported lazily inside `apply_envelope` to keep the circular-import
# surface small — `__init__.py` re-exports from this module.

logger = logging.getLogger(__name__)

# Clock-skew window: envelopes more than 5 minutes in the future are
# dropped (spec §9.4). Configurable via env so tests can shrink it.
_DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000


# ── apply result ──────────────────────────────────────────────────────


@dataclass
class ApplyResult:
    """Outcome of `apply_envelope`.

    `ok` is True iff the envelope passed every verification gate. When
    `ok` is True, `was_new` says whether the envelope was inserted
    (False = duplicate dedup hit, spec §5.3) and `became_latest` says
    whether the envelope is now the current view for `record_id`
    (LWW winner, spec §5.1).

    `reason` carries a structured rejection tag for the HTTP layer to
    map to status codes:
        "shape_invalid"             → 400
        "kind_unknown"              → 400 (with a warning, per spec §3.2)
        "envelope_too_large"        → 413
        "content_too_deep"          → 400
        "content_hash_mismatch"     → 400
        "author_not_in_cohort"      → 403
        "record_author_mismatch"    → 403
        "signature_invalid"         → 403
        "clock_too_far_ahead"       → 400
        "record_id_owned_by_other_author" → 409
        "fork_detected"             → 200 (we still accept the envelope,
                                          but mark the record forked)
        "ok"                        → 200/201
    """

    ok: bool
    reason: str
    was_new: bool = False
    became_latest: bool = False
    fork_detected: bool = False
    content_hash: str = ""


# ── helpers ───────────────────────────────────────────────────────────


def _now_ms() -> int:
    return int(time.time() * 1000)


def _pinned_author_row(
    conn: sqlite3.Connection,
    record_id: str,
) -> tuple[str, int] | None:
    """Return `(author_pubkey, forked)` for `record_id`, or None if not
    pinned yet. `forked` is 0 / 1."""
    try:
        row = conn.execute(
            "SELECT author_pubkey, forked FROM sync_record_authors WHERE record_id=?",
            (record_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    return str(row[0]), int(row[1] or 0)


def pinned_author(conn: sqlite3.Connection, record_id: str) -> str | None:
    """Public read of the pinned author for `record_id`, or None."""
    row = _pinned_author_row(conn, record_id)
    return row[0] if row else None


def is_record_forked(conn: sqlite3.Connection, record_id: str) -> bool:
    row = _pinned_author_row(conn, record_id)
    return bool(row and row[1])


def _pin_author(
    conn: sqlite3.Connection,
    record_id: str,
    author_pubkey: str,
    now_ms: int,
) -> None:
    """Insert the author pin if one doesn't exist. Idempotent — a
    second call with the same `(record_id, author_pubkey)` is a no-op.
    Mismatched author is the caller's responsibility to handle BEFORE
    calling this (the rejection happens in `apply_envelope`)."""
    conn.execute(
        "INSERT OR IGNORE INTO sync_record_authors "
        "(record_id, author_pubkey, pinned_at_ms, forked) VALUES (?, ?, ?, 0)",
        (record_id, author_pubkey, now_ms),
    )


def _mark_forked(conn: sqlite3.Connection, record_id: str) -> None:
    """Flip the `forked` column for `record_id`. Idempotent."""
    conn.execute(
        "UPDATE sync_record_authors SET forked=1 WHERE record_id=?",
        (record_id,),
    )


def _clear_fork(conn: sqlite3.Connection, record_id: str) -> None:
    """Clear the `forked` flag — used when the author writes a fresh
    envelope that resolves the fork (spec §9.9 step 5).
    """
    conn.execute(
        "UPDATE sync_record_authors SET forked=0 WHERE record_id=?",
        (record_id,),
    )


def latest_envelope(
    conn: sqlite3.Connection,
    record_id: str,
) -> dict[str, Any] | None:
    """Return the current-view envelope for `record_id`, or None.

    Spec §6.2 query: ORDER BY `wall_ts_ms DESC, content_hash DESC` LIMIT 1.
    Returns the full envelope JSON as a dict (re-parsed from
    `envelope_json`).
    """
    try:
        row = conn.execute(
            "SELECT envelope_json FROM sync_records WHERE record_id=? "
            "ORDER BY wall_ts_ms DESC, content_hash DESC LIMIT 1",
            (record_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        return None


def get_record_envelopes(
    conn: sqlite3.Connection,
    record_id: str,
    *,
    since_ms: int = 0,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return up to `limit` envelopes for `record_id` with
    `wall_ts_ms > since_ms`, newest-first by
    `(wall_ts_ms DESC, content_hash DESC)`. Spec §4.2 / §6.2."""
    limit = max(1, min(int(limit), 1000))
    try:
        rows = conn.execute(
            "SELECT envelope_json FROM sync_records "
            "WHERE record_id=? AND wall_ts_ms > ? "
            "ORDER BY wall_ts_ms DESC, content_hash DESC LIMIT ?",
            (record_id, int(since_ms), limit),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    out: list[dict[str, Any]] = []
    for r in rows:
        try:
            out.append(json.loads(r[0]))
        except (TypeError, ValueError):
            continue
    return out


def get_record_history(
    conn: sqlite3.Connection,
    record_id: str,
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Every envelope for `record_id`, newest-first. Spec §7.2."""
    limit = max(1, min(int(limit), 1000))
    try:
        rows = conn.execute(
            "SELECT envelope_json FROM sync_records WHERE record_id=? "
            "ORDER BY wall_ts_ms DESC, content_hash DESC LIMIT ?",
            (record_id, limit),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    out: list[dict[str, Any]] = []
    for r in rows:
        try:
            out.append(json.loads(r[0]))
        except (TypeError, ValueError):
            continue
    return out


def build_manifest(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return the manifest body for `GET /sync/manifest` (spec §4.1).

    Output shape:
        {
          "records": {
            "<record_id>": {
              "kind": "<kind>",
              "author_pubkey": "ed25519:<hex>",
              "latest_content_hash": "sha256:<hex>",
              "latest_wall_ts_ms": <int>
            }, ...
          },
          "manifest_hash": "sha256:<hex>"   # over canonical(records)
        }

    The HTTP layer wraps this with `schema`, `node_pubkey`, and
    `generated_at_ms`. We keep the wrapping there so this function is
    cheap to unit-test.

    Records flagged `forked=1` in `sync_record_authors` are OMITTED
    from outbound replication (spec §9.9 step 3). They're still
    queryable via `/sync/record/<r>/history` for the UI.
    """
    records: dict[str, dict[str, Any]] = {}
    try:
        rows = conn.execute(
            """
            SELECT r.record_id, r.kind, r.author_pubkey,
                   r.content_hash, r.wall_ts_ms,
                   COALESCE(a.forked, 0) AS forked
              FROM sync_records r
              LEFT JOIN sync_record_authors a USING(record_id)
             WHERE r.wall_ts_ms = (
                    SELECT MAX(wall_ts_ms) FROM sync_records r2
                     WHERE r2.record_id = r.record_id
                   )
               AND r.content_hash = (
                    SELECT MAX(content_hash) FROM sync_records r3
                     WHERE r3.record_id = r.record_id
                       AND r3.wall_ts_ms = r.wall_ts_ms
                   )
             ORDER BY r.record_id ASC
            """,
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []

    for row in rows:
        if int(row["forked"] if isinstance(row, sqlite3.Row) else row[5] or 0):
            # Spec §9.9 step 3: do NOT advertise forked records to
            # peers. They stay in the local store + history.
            continue
        record_id = row[0] if not isinstance(row, sqlite3.Row) else row["record_id"]
        records[record_id] = {
            "kind": row[1] if not isinstance(row, sqlite3.Row) else row["kind"],
            "author_pubkey": (
                row[2] if not isinstance(row, sqlite3.Row) else row["author_pubkey"]
            ),
            "latest_content_hash": (
                row[3] if not isinstance(row, sqlite3.Row) else row["content_hash"]
            ),
            "latest_wall_ts_ms": int(
                row[4] if not isinstance(row, sqlite3.Row) else row["wall_ts_ms"]
            ),
        }

    # Manifest hash: sha256 of canonical(records). Same canonicalization
    # rule everywhere (spec §4.1).
    canon_records = canonicalize(records, drop_signature=False)
    manifest_hash = "sha256:" + hashlib.sha256(canon_records).hexdigest()
    return {"records": records, "manifest_hash": manifest_hash}


# ── apply ─────────────────────────────────────────────────────────────


def apply_envelope(
    conn: sqlite3.Connection,
    envelope: dict[str, Any],
    *,
    cohort_keys: CohortKeys,
    now_ms: int | None = None,
    clock_skew_ms: int = _DEFAULT_CLOCK_SKEW_MS,
) -> ApplyResult:
    """Verify + apply a single envelope. Spec §4.4 + §5 + §9.9.

    Pipeline (first failure wins; envelope is dropped except for fork
    detection which still stores the envelope but flags the record):

      1. Shape validation (§4.4 step 1; envelope size cap §4.4 step 2
         folded in).
      2. Author whitelist — `author_pubkey` must be in
         `cohort_keys.pubkeys` (§4.4 step 3).
      3. Record-author pin — `sync_record_authors[record_id]` must
         either match `author_pubkey` (existing record) or be unset
         (first observation; we pin to this author). Mismatch → 409
         `record_id_owned_by_other_author` (§4.4 step 4 / §9.6).
      4. Signature verify (§4.4 step 5).
      5. Content-hash sanity is already enforced by `validate_shape`
         (§4.4 step 6).
      6. Clock-skew (§4.4 step 7 / §9.4).
      7. Fork detection (§9.9): if a sibling envelope exists with the
         same `(record_id, author_pubkey, prev_hash)` and a different
         `content_hash`, we set `forked=1` on the author row, log
         `RECORD_FORK_DETECTED`, and STILL store the new envelope (so
         history is preserved). Outbound replication is suppressed by
         `build_manifest` which omits forked records.
      8. LWW + dedup (§5): INSERT OR IGNORE on (record_id, content_hash).
         A re-apply of the same envelope is a no-op. After insert we
         check whether THIS envelope is the new latest by
         `(wall_ts_ms DESC, content_hash DESC)` and report it via
         `became_latest`.

    `cohort_keys` is the trust root — see §8.2. An empty list means no
    cohort is known; every envelope is rejected with
    `author_not_in_cohort` (the daemon stays up, just can't accept
    anything). The HTTP layer should also map "no cohort known" to
    a 503 BEFORE calling this — spec §8.2.

    `clock_skew_ms` defaults to 5 min per §9.4; tests inject a small
    value to exercise the reject path deterministically.

    LAN-trust mode (spec §11; `SWF_TRUST_LAN_PEERS=1`) relaxes two
    gates:
      * Step 2 (author whitelist): any author_pubkey accepted.
      * Step 3 (single-writer pin) and step 7 (fork detection): the
        first-write pin is still recorded for history, but a sibling
        envelope from a different author is accepted as part of the
        chain rather than rejected with `record_id_owned_by_other_author`
        or flagged with `RECORD_FORK_DETECTED`. Multiple authors per
        record_id are valid; LWW by wall_ts_ms still applies.
    Signature verification (step 4) is NEVER skipped — that's the
    wire-integrity check.
    """
    # Re-read env on every call so tests + operators can flip the flag
    # at runtime without bouncing the daemon. Import is lazy to avoid
    # a circular reference (`__init__.py` re-exports from this module).
    from . import is_lan_trust_mode
    lan_trust = is_lan_trust_mode()

    if now_ms is None:
        now_ms = _now_ms()

    # 1. Shape.
    ok, reason = validate_shape(envelope)
    if not ok:
        return ApplyResult(ok=False, reason=reason)

    record_id = envelope["record_id"]
    author_pubkey = envelope["author_pubkey"]
    wall_ts_ms = int(envelope["wall_ts_ms"])
    ch = envelope["content_hash"]

    # 2. Author whitelist. Bypassed in LAN-trust mode (§11) — any
    # signed envelope from any peer is acceptable. Signature verify
    # below remains the wire-integrity gate.
    if not lan_trust and not cohort_keys.is_known_pubkey(author_pubkey):
        return ApplyResult(ok=False, reason="author_not_in_cohort", content_hash=ch)

    # Schema must exist before we touch the tables.
    ensure_schema(conn)

    # 3. Record-author pin / collision check.
    #
    # Default mode (§9.6): the first author observed for a `record_id`
    # is pinned; subsequent writes from a different author are
    # rejected with `record_id_owned_by_other_author`.
    #
    # LAN-trust mode (§11): we still record the first author so the
    # `sync_record_authors` table reflects history, but a different
    # author claiming the same record_id is NOT rejected — multiple
    # authors per record_id are valid. The pin row is left at the
    # first observer's pubkey (informational only).
    pinned = _pinned_author_row(conn, record_id)
    if pinned is None:
        # First-observation pin. Spec §9.6: also enforce that this
        # author is allowed to own a record at all (it is — they're in
        # cohort_keys.pubkeys). Pinning here matches the cohort-keys
        # validator's defense-in-depth pair: the YAML guards against
        # duplicate handles, and we guard against late conflicting
        # `record_id` claims that didn't trip the YAML check.
        _pin_author(conn, record_id, author_pubkey, now_ms)
    else:
        pinned_pubkey, _was_forked = pinned
        if pinned_pubkey != author_pubkey and not lan_trust:
            return ApplyResult(
                ok=False,
                reason="record_id_owned_by_other_author",
                content_hash=ch,
            )

    # 4. Signature verify. Spec §4.4 step 5; we also pin to the
    # cohort_keys-known pubkey to defeat malleability + spoofing.
    if not verify_envelope_signature(envelope, expected_pubkey=author_pubkey):
        return ApplyResult(ok=False, reason="signature_invalid", content_hash=ch)

    # 6. Clock-skew. Spec §9.4 / §4.4 step 7.
    if wall_ts_ms > now_ms + clock_skew_ms:
        return ApplyResult(ok=False, reason="clock_too_far_ahead", content_hash=ch)

    # 7. Fork detection. Spec §9.9: "two envelopes E1 and E2 with the
    # same prev_hash and the same record_id and the same author_pubkey
    # but different content_hash". We check BEFORE the insert so we
    # know if this envelope creates a new fork; the existing-fork case
    # is also covered (we still persist the envelope; build_manifest
    # suppresses outbound).
    #
    # LAN-trust mode (§11): fork detection is a single-writer-per-record
    # concept. Since LAN-trust allows multiple authors per record_id,
    # the notion of "fork" doesn't apply — all entries are part of one
    # multi-author chain reconciled by LWW. We skip the sibling query
    # and never set `fork_detected`.
    prev_hash = envelope.get("prev_hash")
    fork_detected = False
    sibling_hashes: set[str] = set()
    if not lan_trust:
        try:
            siblings = conn.execute(
                "SELECT content_hash FROM sync_records "
                "WHERE record_id=? AND author_pubkey=? AND "
                "      ((prev_hash IS NULL AND ? IS NULL) OR prev_hash=?)",
                (record_id, author_pubkey, prev_hash, prev_hash),
            ).fetchall()
        except sqlite3.OperationalError:
            siblings = []
        sibling_hashes = {s[0] for s in siblings}
        # A sibling with a different content_hash IS a fork. (Same-hash
        # is just dedup, handled below.)
        if any(h != ch for h in sibling_hashes):
            fork_detected = True

    # 8. Insert (idempotent on (record_id, content_hash)).
    envelope_json = canonicalize(envelope, drop_signature=False).decode("utf-8")
    cur = conn.execute(
        "INSERT OR IGNORE INTO sync_records ("
        "  record_id, content_hash, wall_ts_ms, author_pubkey, kind, "
        "  prev_hash, envelope_json, received_at_ms"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            record_id,
            ch,
            wall_ts_ms,
            author_pubkey,
            envelope["kind"],
            prev_hash,
            envelope_json,
            now_ms,
        ),
    )
    was_new = bool(cur.rowcount)

    if fork_detected:
        _mark_forked(conn, record_id)
        # Structured log line per spec §9.9 step 4. We log every
        # detection (not just the first) so an operator running tail
        # -f sees the trail; the build_manifest suppression is the
        # actual protocol-level effect.
        logger.warning(
            "RECORD_FORK_DETECTED record_id=%s author=%s prev_hash=%s "
            "content_hashes=%s",
            record_id, author_pubkey[:20] + "…",
            prev_hash, sorted(sibling_hashes | {ch}),
        )
    elif was_new and pinned and pinned[1]:
        # If we're storing a new (non-sibling) envelope that the
        # author signed for the same record after a fork, the new
        # envelope is the resolution (spec §9.9 step 5). Clear the
        # flag iff this envelope's prev_hash points at one of the
        # forked siblings OR resets the chain (prev_hash null).
        # Simpler approximation: any non-sibling new envelope from
        # the pinned author resolves the fork. Conservative — the
        # author can always re-fork with a fresh sibling.
        _clear_fork(conn, record_id)

    # 9. became_latest: is this envelope now the (wall_ts_ms, ch)
    # winner for the record? Cheap query against the LWW index.
    became_latest = False
    if was_new:
        try:
            top_row = conn.execute(
                "SELECT content_hash, wall_ts_ms FROM sync_records "
                "WHERE record_id=? ORDER BY wall_ts_ms DESC, content_hash DESC "
                "LIMIT 1",
                (record_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            top_row = None
        if top_row is not None:
            became_latest = (str(top_row[0]) == ch and int(top_row[1]) == wall_ts_ms)

    conn.commit()
    return ApplyResult(
        ok=True,
        reason="ok",
        was_new=was_new,
        became_latest=became_latest,
        fork_detected=fork_detected,
        content_hash=ch,
    )
