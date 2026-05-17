"""SQLite storage for verified bundle envelopes.

Phase 1 of #93. Bundles live in a NEW table inside the existing local
indrex DB (`~/world_knowledge/index.db`, resolved by
`swf.indrex.db_path()`). The table is fully encapsulated — removal is
`DROP TABLE bundles` and a `rm -rf src/swf/bundles/`. No existing
search modules touch it; no modules outside `swf.bundles` should
reach into it directly.

Schema (issue #93, phase 1):

    CREATE TABLE IF NOT EXISTS bundles (
        cid           TEXT PRIMARY KEY,           -- sha256 hex of canonical bytes
        kind          TEXT NOT NULL,
        record_id     TEXT NOT NULL,
        version       INTEGER NOT NULL,
        author_pubkey TEXT NOT NULL,
        signed_at     TEXT NOT NULL,
        prev_cid      TEXT,
        encryption_alg TEXT,                      -- 'age-v1' or NULL
        envelope_json TEXT NOT NULL,              -- the entire signed envelope, verbatim
        received_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_bundles_kind_record_version
        ON bundles(kind, record_id, version DESC);
    CREATE INDEX IF NOT EXISTS idx_bundles_kind_signed_at
        ON bundles(kind, signed_at DESC);

Public surface:
    - ensure_schema(conn)
    - insert(envelope, *, conn=None)        -> (cid, was_new)
    - get_by_cid(conn, cid)                 -> dict | None
    - list_(conn, *, kind=..., record_id=..., since_version=..., limit=...) -> list[dict]
    - latest_version(conn, *, kind, record_id) -> int | None

`insert` is the canonical write path: it computes the CID via
`envelope.cid_for` (sha256 of the same canonical bytes that were
signed), opens (or accepts) an indrex.db connection, runs
`ensure_schema`, and INSERT-OR-IGNOREs on `cid`. Idempotent on the
same envelope — the second call returns `was_new=False`.
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
from typing import Any

from swf.indrex import db_path

from .envelope import canonicalize, cid_for

_CREATE_BUNDLES = """
CREATE TABLE IF NOT EXISTS bundles (
    cid            TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    record_id      TEXT NOT NULL,
    version        INTEGER NOT NULL,
    author_pubkey  TEXT NOT NULL,
    signed_at      TEXT NOT NULL,
    prev_cid       TEXT,
    encryption_alg TEXT,
    envelope_json  TEXT NOT NULL,
    received_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
)
"""

_CREATE_IDX_KIND_RECORD_VERSION = """
CREATE INDEX IF NOT EXISTS idx_bundles_kind_record_version
    ON bundles(kind, record_id, version DESC)
"""

_CREATE_IDX_KIND_SIGNED_AT = """
CREATE INDEX IF NOT EXISTS idx_bundles_kind_signed_at
    ON bundles(kind, signed_at DESC)
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Idempotently create the `bundles` table and its indexes.

    Mirrors the pattern in `swf.search.migration.ensure_schema` —
    safe to call on every connection / process boot. We also enable
    WAL mode best-effort; the indrex DB already runs in WAL via the
    search migration but bundle-only callers may open the DB before
    that fires.
    """
    with contextlib.suppress(sqlite3.DatabaseError):
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_CREATE_BUNDLES)
    conn.execute(_CREATE_IDX_KIND_RECORD_VERSION)
    conn.execute(_CREATE_IDX_KIND_SIGNED_AT)
    conn.commit()


def _open_writer() -> sqlite3.Connection:
    """Open a writer connection to the indrex DB. WAL means readers
    don't block. Caller is responsible for `.close()`.
    """
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def insert(
    envelope: dict[str, Any],
    *,
    conn: sqlite3.Connection | None = None,
) -> tuple[str, bool]:
    """Persist `envelope` to the bundles table. Idempotent on `cid`.

    Returns `(cid, was_new)`:
      - `cid` is `sha256(canonical_bytes_minus_signature_field).hexdigest()`,
        i.e. the same bytes that the alchemist signed. This makes
        verification and content-addressing share a single input.
      - `was_new` is True if a row was inserted, False if the same CID
        was already present (in which case nothing was changed).

    NOTE: this function does NOT verify the envelope. Callers should
    run `swf.bundles.verify.verify_bundle` first; the table is the
    canonical store for *already-verified* bundles, which means a
    `cid` collision implies content equality.

    `conn` is optional. When omitted, a writer connection is opened
    against `swf.indrex.db_path()` for the duration of the call. When
    provided (e.g. the HTTP write path in phase 2 wants transactional
    bundling), the caller owns the lifetime and the commit.
    """
    own_conn = conn is None
    if own_conn:
        conn = _open_writer()

    try:
        ensure_schema(conn)
        cid = cid_for(envelope)
        author = envelope.get("author") or {}
        encryption = envelope.get("encryption") or None
        # canonicalize(drop_signature=False) preserves the signature
        # too — we want the *full* signed envelope on disk so callers
        # can re-emit it verbatim.
        envelope_json = canonicalize(envelope, drop_signature=False).decode("utf-8")

        cur = conn.execute(
            "INSERT OR IGNORE INTO bundles ("
            "  cid, kind, record_id, version, author_pubkey, signed_at, "
            "  prev_cid, encryption_alg, envelope_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cid,
                envelope["kind"],
                envelope["record_id"],
                int(envelope["version"]),
                author.get("pubkey", ""),
                author.get("signed_at", ""),
                envelope.get("prev_cid"),
                (encryption or {}).get("alg") if encryption else None,
                envelope_json,
            ),
        )
        was_new = bool(cur.rowcount)
        if own_conn:
            conn.commit()
        return cid, was_new
    finally:
        if own_conn:
            conn.close()


def _row_to_envelope(row: sqlite3.Row | tuple) -> dict[str, Any]:
    """Inverse of `insert`: return the full envelope dict from a row.

    We stored the canonical-with-signature JSON verbatim, so this is
    just a JSON load. We deliberately avoid reconstructing the
    envelope from the broken-out columns (kind, version, …) — they
    exist for indexing, not for rebuilding the wire form.
    """
    try:
        s = row["envelope_json"]
    except (TypeError, IndexError):
        s = row[8]
    return json.loads(s)


def get_by_cid(conn: sqlite3.Connection, cid: str) -> dict[str, Any] | None:
    """Return the envelope dict for `cid`, or None if not found.

    Caller is expected to have a connection to the indrex DB (use
    `swf.indrex.db_path()` and `sqlite3.connect`). We do NOT call
    `ensure_schema` here — read paths shouldn't trigger DDL on every
    fetch. The HTTP route layer (phase 2) opens a connection once at
    boot and runs `ensure_schema` then.
    """
    if not cid:
        return None
    try:
        row = conn.execute(
            "SELECT envelope_json FROM bundles WHERE cid=?",
            (cid,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    return _row_to_envelope(row)


def list_(
    conn: sqlite3.Connection,
    *,
    kind: str | None = None,
    record_id: str | None = None,
    since_version: int | None = None,
    received_since: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List bundles matching the filters.

    Ordering: `(kind, record_id, version DESC)`-friendly when both
    filters are given (latest version first). For broad scans across
    all records of a kind, results are ordered by `signed_at DESC`
    (the index `idx_bundles_kind_signed_at` covers this). The HTTP
    layer in phase 2 will refine paging; phase 1 just exposes a
    workable read path for tests.

    `since_version=None` (the default) returns every version. When
    set, the filter is strict-greater (`version > since_version`) so
    the caller can use it as a cursor: pass the highest `version`
    they've already consumed and they get only what's newer. Note
    that `version=0` is a legitimate value, which is why we use
    None-rather-than-0 as the "no cursor" sentinel.

    `received_since=None` (the default) is the legacy version-based
    cursor mode. When set, the function instead runs in *rowid mode*:
    return bundles with `rowid > received_since`, ordered by `rowid
    ASC`. Callers that need rowid-based pagination should use
    `list_with_rowid` instead — it returns `(envelope, rowid)` tuples
    so the caller can advance its high-water. `received_since` is
    mutually exclusive with `since_version`/`record_id` filtering at
    the HTTP layer; this function tolerates both being set (the
    request layer enforces the contract) and rowid mode wins.

    `limit` is clamped to `[1, 1000]`.
    """
    if received_since is not None:
        return [
            env for env, _rowid in list_with_rowid(
                conn, kind=kind, received_since=received_since, limit=limit,
            )
        ]

    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000

    where: list[str] = []
    args: list[Any] = []
    if since_version is not None:
        where.append("version > ?")
        args.append(int(since_version))
    if kind is not None:
        where.append("kind = ?")
        args.append(kind)
    if record_id is not None:
        where.append("record_id = ?")
        args.append(record_id)

    if record_id is not None:
        order = "version DESC"
    else:
        order = "signed_at DESC"

    sql = "SELECT envelope_json FROM bundles"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {order} LIMIT ?"
    args.append(limit)

    try:
        rows = conn.execute(sql, args).fetchall()
    except sqlite3.OperationalError:
        return []
    return [_row_to_envelope(r) for r in rows]


def list_with_rowid(
    conn: sqlite3.Connection,
    *,
    kind: str | None = None,
    received_since: int = 0,
    limit: int = 100,
) -> list[tuple[dict[str, Any], int]]:
    """List bundles with rowid > `received_since`, returning
    `(envelope, rowid)` tuples in rowid ASC order.

    This is the cross-record insertion-order cursor used by the
    pull-side replication puller (#93 phase 6 follow-up). The HTTP
    `GET /bundles?received_since=` route uses it to compute
    `next_received_since` without a second query. The puller stores
    the highest rowid it has seen from each peer in `swf_kv` so a
    subsequent tick resumes exactly past the last consumed bundle.

    `limit` is clamped to `[1, 1000]`. Optional `kind` filter narrows
    by bundle kind for callers that only care about one stream.
    Returns `[]` on a missing `bundles` table — read-side defensiveness
    matches `list_`.
    """
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000

    where: list[str] = ["rowid > ?"]
    args: list[Any] = [int(received_since)]
    if kind is not None:
        where.append("kind = ?")
        args.append(kind)
    sql = (
        "SELECT rowid AS rid, envelope_json FROM bundles WHERE "
        + " AND ".join(where)
        + " ORDER BY rowid ASC LIMIT ?"
    )
    args.append(limit)

    try:
        rows = conn.execute(sql, args).fetchall()
    except sqlite3.OperationalError:
        return []
    out: list[tuple[dict[str, Any], int]] = []
    for r in rows:
        env = _row_to_envelope(r)
        try:
            rid = int(r["rid"])
        except (TypeError, IndexError):
            rid = int(r[0])
        out.append((env, rid))
    return out


def latest_version(
    conn: sqlite3.Connection,
    *,
    kind: str,
    record_id: str,
) -> int | None:
    """Largest `version` seen for `(kind, record_id)`, or None if no
    bundles exist.

    Used by the verifier to enforce strict-greater monotonicity at the
    envelope level. Note: for `transcript.batch`, the spec (§3.5) says
    "Batches MUST be append-only — `version` increments are NOT used;
    `batch_index` does." We still enforce envelope-level version
    monotonicity here — the spec's append-only semantics live inside
    the payload as `batch_index`, which is opaque to swf-node. See
    `swf.bundles.verify` for the full discussion.
    """
    try:
        row = conn.execute(
            "SELECT MAX(version) AS v FROM bundles WHERE kind=? AND record_id=?",
            (kind, record_id),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    try:
        v = row["v"]
    except (TypeError, IndexError):
        v = row[0]
    return int(v) if v is not None else None
