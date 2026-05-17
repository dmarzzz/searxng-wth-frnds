"""Indrex schema migration for SPEC v0.3 §13.1.

The spec describes a regular `documents` table with `share_scope`,
`sensitivity_label`, `source_type`, `content_hash`, `fetched_at_ms`,
and `deleted_at_ms` columns. Our existing layout keeps page text in an
FTS5 virtual table named `pages` (created by `swf.web.index`)
plus a `page_cids` sidecar. **FTS5 virtual tables don't support
`ALTER TABLE ADD COLUMN`**, so this migration adds the metadata as a
sibling sidecar — `pages_meta(url, share_scope, sensitivity_label,
source_type, content_hash, fetched_at_ms, deleted_at_ms, updated_at)` —
and is read via LEFT JOIN.

Defaults match §13.1: `share_scope = 'private'` (private until the user
explicitly says otherwise), `sensitivity_label = 'unknown'`,
`source_type = 'user_fetched'`. The friend-responder filter (Phase 3)
reads from this table; Phase 1's LOCAL_INDREX route doesn't need to
filter by share_scope (the user can search their own private archive)
but DOES filter on `deleted_at_ms IS NULL` so tombstoned rows never
surface.

**Privacy semantics for `source_type`:**
- `user_fetched` — this peer fetched the row directly. Default; OK to share.
- `peer_ingest` — the row came from another peer (e.g. via friend
  search). The friend responder MUST NOT re-share these (chained
  provenance attack — TODO-8); see `friend_responder._PAGES_SQL`.
- `manual_import` — hand-imported by the user (e.g. archive load).

`deleted_at_ms` is a tombstone: when non-NULL, both LOCAL_INDREX and
the friend responder skip the row. Set by callers when a page is
removed / redacted; the FTS row may persist until a future GC pass.

`content_hash` is SHA-256 of the cleaned page content (caller-computed)
and feeds §11.4's `verification.content_hash`. `fetched_at_ms` feeds
§11.4's `freshness.fetched_at_ms` and the §14 staleness check.

Idempotent. Safe to call on every connection — also safe on a database
that already has the older minimal `pages_meta` (4-column) schema:
each missing column is added via `ALTER TABLE ADD COLUMN`.
"""
from __future__ import annotations

import contextlib
import sqlite3
from datetime import datetime, timezone

ALLOWED_SHARE_SCOPES = ("private", "local_only", "friends", "public")
ALLOWED_SENSITIVITY = ("unknown", "low", "medium", "high")
ALLOWED_SOURCE_TYPES = ("user_fetched", "peer_ingest", "manual_import")

DEFAULT_SHARE_SCOPE = "private"
DEFAULT_SENSITIVITY = "unknown"
DEFAULT_SOURCE_TYPE = "user_fetched"

_CREATE = """
CREATE TABLE IF NOT EXISTS pages_meta (
    url               TEXT PRIMARY KEY,
    share_scope       TEXT NOT NULL DEFAULT 'private'
                          CHECK(share_scope IN ('private','local_only','friends','public')),
    sensitivity_label TEXT NOT NULL DEFAULT 'unknown'
                          CHECK(sensitivity_label IN ('unknown','low','medium','high')),
    source_type       TEXT NOT NULL DEFAULT 'user_fetched'
                          CHECK(source_type IN ('user_fetched','peer_ingest','manual_import')),
    content_hash      TEXT,
    fetched_at_ms     INTEGER,
    deleted_at_ms     INTEGER,
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
)
"""

# (column_name, DDL fragment after ADD COLUMN). All four §13.1 extension
# columns; the older minimal schema lacked all of these, so on a legacy
# DB each ALTER fires once.
#
# NOTE: SQLite cannot add a NOT NULL column without a literal DEFAULT.
# `source_type` carries `DEFAULT 'user_fetched'`, which both satisfies
# that constraint and gives every pre-existing row the safe default.
# A CHECK constraint applied via ALTER is enforced for new writes (which
# is what we want); rows backfilled to the default already satisfy it.
_EXTENSION_COLUMNS: tuple[tuple[str, str], ...] = (
    (
        "source_type",
        "TEXT NOT NULL DEFAULT 'user_fetched' "
        "CHECK(source_type IN ('user_fetched','peer_ingest','manual_import'))",
    ),
    ("content_hash", "TEXT"),
    ("fetched_at_ms", "INTEGER"),
    ("deleted_at_ms", "INTEGER"),
    # Issue #43 PR A: peer-ingest attribution. Five columns carry where a
    # row came from when `source_type='peer_ingest'`. NULL on `self`-fetched
    # rows. `bundle_root` + `bundle_sig` let us prove provenance later
    # without refetching — the (root, sig, peer-pubkey) triple is what
    # the puller verified at scrape time.
    ("source_pubkey", "TEXT"),
    ("source_label", "TEXT"),
    ("scraped_at", "TEXT"),
    ("bundle_root", "TEXT"),
    ("bundle_sig", "TEXT"),
)


# Issue #43 PR A: per-peer state. The puller tracks `last_pull_cursor`
# (the largest source-side rowid we've pulled) so re-pulls don't
# re-ingest the universe. Keyed by ed25519 pubkey (base64url).
#
# P2P-review #2: peers gain `last_seen_epoch`. The producer signs an
# `epoch_id` (random UUID minted once per indrex.db) into every
# bundle; if the peer rebuilds its DB or rotates identity-and-DB,
# the new epoch_id makes the consumer reset `last_pull_cursor=0` and
# re-ingest from scratch. Without it, a peer whose rowids reset to 1
# would never re-share rows 1..N because our cursor stayed at N.
_CREATE_PEERS = """
CREATE TABLE IF NOT EXISTS peers (
    pubkey            TEXT PRIMARY KEY,
    nickname          TEXT NOT NULL DEFAULT '',
    signature_color   TEXT NOT NULL DEFAULT '',
    signature_freq    REAL NOT NULL DEFAULT 0,
    last_seen_at      TEXT,
    last_pull_cursor  INTEGER NOT NULL DEFAULT 0,
    last_seen_epoch   TEXT NOT NULL DEFAULT '',
    trust_level       TEXT NOT NULL DEFAULT 'known'
                          CHECK(trust_level IN ('known','trusted','banned'))
)
"""

_PEERS_EXTENSION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("last_seen_epoch", "TEXT NOT NULL DEFAULT ''"),
    # P2P-review #8: peer backoff / quarantine. consecutive_failures
    # counts http_error / verify-rejection rounds in a row. On
    # success it resets to 0. next_attempt_at is the wall-clock
    # ISO-8601 below which the scraper skips this peer entirely
    # (exponential backoff: 60s × 2^min(failures, 6) capped at 1h).
    ("consecutive_failures", "INTEGER NOT NULL DEFAULT 0"),
    ("next_attempt_at", "TEXT NOT NULL DEFAULT ''"),
    # geth/reth-style positive score: monotonic counter of clean
    # pulls. Combined with consecutive_failures gives the eviction
    # heuristic ("never worked + repeatedly broken" → evict).
    ("successful_pulls", "INTEGER NOT NULL DEFAULT 0"),
)


# P2P-review #2: tiny key/value store inside indrex.db for node-level
# state that doesn't fit anywhere else. Today's only key is
# `node_epoch_id` — a stable random UUID minted on first read,
# regenerated whenever the DB is rebuilt.
_CREATE_KV = """
CREATE TABLE IF NOT EXISTS swf_kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
"""


# Issue #43 PR B: events table moves to indrex.db. Append-only,
# auto-pruning happens elsewhere (a vacuum job can delete WHERE id <
# now()-N). The wall subscribes via /events SSE for live updates and
# uses since=<id> to replay from a checkpoint.
_CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    kind         TEXT    NOT NULL,
    payload_json TEXT    NOT NULL
)
"""

_CREATE_EVENTS_KIND_IDX = """
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind, id)
"""

# Issue #65: when a peer bundle contains a URL the local node already
# has in `pages`, the dedup branch in ingest_bundle skips `set_meta`
# entirely, so peer attribution for overlapping URLs never lands.
# The chosen fix is Option B from the issue: a join table that records
# every peer who has vouched for a URL, independent of `pages_meta`'s
# single-attribution `source_pubkey`. `pages_meta.source_pubkey` keeps
# its primary-attribution semantics (first-write-wins, with the
# user_fetched-vs-peer_ingest guard in `set_meta`); `page_contributors`
# accumulates the long tail.
_CREATE_PAGE_CONTRIBUTORS = """
CREATE TABLE IF NOT EXISTS page_contributors (
    url            TEXT NOT NULL,
    source_pubkey  TEXT NOT NULL,
    source_label   TEXT NOT NULL DEFAULT '',
    scraped_at     TEXT NOT NULL DEFAULT '',
    bundle_root    TEXT NOT NULL DEFAULT '',
    bundle_sig     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(url, source_pubkey)
)
"""

_CREATE_PAGE_CONTRIBUTORS_URL_IDX = """
CREATE INDEX IF NOT EXISTS idx_page_contributors_url
    ON page_contributors(url)
"""


def _existing_columns(conn: sqlite3.Connection) -> set[str]:
    """Return the set of column names currently on `pages_meta`. Empty
    set if the table doesn't exist."""
    try:
        rows = conn.execute("PRAGMA table_info(pages_meta)").fetchall()
    except sqlite3.OperationalError:
        return set()
    cols: set[str] = set()
    for r in rows:
        # PRAGMA table_info: (cid, name, type, notnull, dflt_value, pk)
        try:
            cols.add(r["name"])
        except (TypeError, IndexError):
            cols.add(r[1])
    return cols


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create `pages_meta` + `peers` if missing, then ALTER `pages_meta`
    to add any extension columns (§13.1: source_type, content_hash,
    fetched_at_ms, deleted_at_ms; Issue #43 PR A: source_pubkey,
    source_label, scraped_at, bundle_root, bundle_sig) that are absent.

    Idempotent — safe to call on a DB that has the old 4-column shape,
    the §13.1 8-column shape, the post-#43 13-column shape, or no
    `pages_meta` at all."""
    # Pass-5 #5: enable WAL once per DB (the PRAGMA persists at the
    # database level, so re-issuing it on every connection was a
    # non-trivial transaction that collided with concurrent writers).
    # Best-effort — a fresh DB or a non-WAL fallback is fine.
    with contextlib.suppress(sqlite3.DatabaseError):
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_CREATE)
    conn.execute(_CREATE_PEERS)
    conn.execute(_CREATE_EVENTS)
    conn.execute(_CREATE_EVENTS_KIND_IDX)
    conn.execute(_CREATE_KV)
    conn.execute(_CREATE_PAGE_CONTRIBUTORS)
    conn.execute(_CREATE_PAGE_CONTRIBUTORS_URL_IDX)
    # Idempotently add new columns to peers (legacy DBs predate
    # last_seen_epoch). PRAGMA table_info(peers) tells us what's
    # already there.
    try:
        peer_cols_rows = conn.execute("PRAGMA table_info(peers)").fetchall()
        peer_cols = set()
        for r in peer_cols_rows:
            try:
                peer_cols.add(r["name"])
            except (TypeError, IndexError):
                peer_cols.add(r[1])
    except sqlite3.OperationalError:
        peer_cols = set()
    _idempotent_add_columns(conn, "peers", peer_cols, _PEERS_EXTENSION_COLUMNS)
    _idempotent_add_columns(
        conn, "pages_meta", _existing_columns(conn), _EXTENSION_COLUMNS,
    )


def _idempotent_add_columns(
    conn: sqlite3.Connection,
    table: str,
    have: set[str],
    columns: tuple[tuple[str, str], ...],
) -> None:
    """ALTER TABLE ADD COLUMN, race-safe.

    SQLite has no `ADD COLUMN IF NOT EXISTS`. We pre-check via PRAGMA
    table_info, but #78: the test suite (and event_bus running on a
    daemon thread alongside the main thread) sometimes runs two
    ensure_schema calls concurrently against the same DB. Both read
    PRAGMA, both see the column missing, both ALTER — the second
    errors with `duplicate column name: <name>` and stderr fills with
    backtraces from event_bus's emit path. Worse: when the failed
    ALTER is part of a larger script, the surrounding work is rolled
    back, which is the actual cause of the cascading test failures.

    Catching `OperationalError` whose message contains "duplicate
    column name" is safe: the post-condition (column exists) is
    already satisfied by whichever caller won the race. Anything else
    propagates, so genuinely-broken ALTERs still surface."""
    for name, ddl in columns:
        if name in have:
            continue
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            if "duplicate column name" in msg:
                # Another ensure_schema beat us to it. Post-condition
                # holds; nothing to do.
                continue
            raise


def set_meta(
    conn: sqlite3.Connection,
    url: str,
    *,
    share_scope: str | None = None,
    sensitivity_label: str | None = None,
    source_type: str | None = None,
    content_hash: str | None = None,
    fetched_at_ms: int | None = None,
    deleted_at_ms: int | None = None,
    source_pubkey: str | None = None,
    source_label: str | None = None,
    scraped_at: str | None = None,
    bundle_root: str | None = None,
    bundle_sig: str | None = None,
) -> None:
    """Upsert the metadata for `url`. Caller writes the URL into `pages`
    separately (swf.web's `index_page` owns that path).

    A field passed as None means "leave existing value alone (or default
    on first insert)". The naive ON-CONFLICT-DO-UPDATE pattern would
    overwrite with defaults, so we split the path: try INSERT first
    (filling in defaults for omitted fields), then UPDATE only the
    columns the caller actually specified.
    """
    if share_scope is not None and share_scope not in ALLOWED_SHARE_SCOPES:
        raise ValueError(f"bad share_scope: {share_scope!r}")
    if sensitivity_label is not None and sensitivity_label not in ALLOWED_SENSITIVITY:
        raise ValueError(f"bad sensitivity_label: {sensitivity_label!r}")
    if source_type is not None and source_type not in ALLOWED_SOURCE_TYPES:
        raise ValueError(f"bad source_type: {source_type!r}")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur = conn.execute(
        "INSERT OR IGNORE INTO pages_meta("
        "  url, share_scope, sensitivity_label, source_type, "
        "  content_hash, fetched_at_ms, deleted_at_ms, "
        "  source_pubkey, source_label, scraped_at, "
        "  bundle_root, bundle_sig, updated_at"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (url,
         share_scope or DEFAULT_SHARE_SCOPE,
         sensitivity_label or DEFAULT_SENSITIVITY,
         source_type or DEFAULT_SOURCE_TYPE,
         content_hash,
         fetched_at_ms,
         deleted_at_ms,
         source_pubkey,
         source_label,
         scraped_at,
         bundle_root,
         bundle_sig,
         now),
    )
    if cur.rowcount:
        # New row — INSERT handled it.
        return
    # Existing row — patch only the explicitly-provided fields.
    sets, args = [], []
    if share_scope is not None:
        sets.append("share_scope=?")
        args.append(share_scope)
    if sensitivity_label is not None:
        sets.append("sensitivity_label=?")
        args.append(sensitivity_label)
    if source_type is not None:
        sets.append("source_type=?")
        args.append(source_type)
    if content_hash is not None:
        sets.append("content_hash=?")
        args.append(content_hash)
    if fetched_at_ms is not None:
        sets.append("fetched_at_ms=?")
        args.append(fetched_at_ms)
    if deleted_at_ms is not None:
        sets.append("deleted_at_ms=?")
        args.append(deleted_at_ms)
    if source_pubkey is not None:
        sets.append("source_pubkey=?")
        args.append(source_pubkey)
    if source_label is not None:
        sets.append("source_label=?")
        args.append(source_label)
    if scraped_at is not None:
        sets.append("scraped_at=?")
        args.append(scraped_at)
    if bundle_root is not None:
        sets.append("bundle_root=?")
        args.append(bundle_root)
    if bundle_sig is not None:
        sets.append("bundle_sig=?")
        args.append(bundle_sig)
    sets.append("updated_at=?")
    args.append(now)
    args.append(url)
    # Pass-5 finding #9: a peer-ingest UPDATE must NEVER overwrite a
    # row that was originally user_fetched. Without this guard, a
    # scraper race between the agent's index_page (which calls
    # set_meta with source_type='user_fetched') and ingest_bundle
    # (peer_ingest) could flip the attribution and leak the URL out
    # via the friend-responder. The WHERE clause is no-op for any
    # other transition.
    where = "WHERE url=?"
    if source_type == "peer_ingest":
        where += " AND source_type != 'user_fetched'"
    conn.execute(f"UPDATE pages_meta SET {', '.join(sets)} {where}", args)


def get_node_epoch_id(conn: sqlite3.Connection) -> str:
    """P2P-review #2: stable per-DB epoch UUID. Minted on first read
    and persisted in `swf_kv`. A fresh DB (rowids reset, identity
    re-keyed, etc) gets a new epoch the next time this is called,
    which makes consumers reset their per-peer cursors to 0.

    Idempotent within a DB lifetime; the value never changes once
    written. Must be called inside `ensure_schema`-ready connection."""
    row = conn.execute(
        "SELECT value FROM swf_kv WHERE key='node_epoch_id'",
    ).fetchone()
    if row is not None:
        try:
            return row["value"]
        except (TypeError, IndexError):
            return row[0]
    import uuid
    epoch = uuid.uuid4().hex
    conn.execute(
        "INSERT OR IGNORE INTO swf_kv(key, value) VALUES(?, ?)",
        ("node_epoch_id", epoch),
    )
    conn.commit()
    # Re-read in case a concurrent writer raced us.
    row = conn.execute(
        "SELECT value FROM swf_kv WHERE key='node_epoch_id'",
    ).fetchone()
    if row is None:
        return epoch
    try:
        return row["value"]
    except (TypeError, IndexError):
        return row[0]


def get_meta(conn: sqlite3.Connection, url: str) -> dict[str, object]:
    """Return the metadata dict for `url`, with documented defaults when
    the row is missing — every existing page is treated as `private` +
    `unknown` + `user_fetched` until the user labels it.

    Keys returned (always six):
      - share_scope (str)        default 'private'
      - sensitivity_label (str)  default 'unknown'
      - source_type (str)        default 'user_fetched'
      - content_hash (str | None)   default None
      - fetched_at_ms (int | None)  default None
      - deleted_at_ms (int | None)  default None
    """
    row = conn.execute(
        "SELECT share_scope, sensitivity_label, source_type, "
        "       content_hash, fetched_at_ms, deleted_at_ms "
        "FROM pages_meta WHERE url=?",
        (url,),
    ).fetchone()
    if row is None:
        return {
            "share_scope": DEFAULT_SHARE_SCOPE,
            "sensitivity_label": DEFAULT_SENSITIVITY,
            "source_type": DEFAULT_SOURCE_TYPE,
            "content_hash": None,
            "fetched_at_ms": None,
            "deleted_at_ms": None,
        }
    # row may be a Row (with names) or a tuple depending on connection setup
    try:
        return {
            "share_scope": row["share_scope"],
            "sensitivity_label": row["sensitivity_label"],
            "source_type": row["source_type"],
            "content_hash": row["content_hash"],
            "fetched_at_ms": row["fetched_at_ms"],
            "deleted_at_ms": row["deleted_at_ms"],
        }
    except (TypeError, IndexError):
        return {
            "share_scope": row[0],
            "sensitivity_label": row[1],
            "source_type": row[2],
            "content_hash": row[3],
            "fetched_at_ms": row[4],
            "deleted_at_ms": row[5],
        }


def add_contributor(
    conn: sqlite3.Connection,
    url: str,
    *,
    source_pubkey: str,
    source_label: str = "",
    scraped_at: str = "",
    bundle_root: str = "",
    bundle_sig: str = "",
) -> bool:
    """Record a peer's contribution of `url` in `page_contributors`.
    Returns True if a new row was inserted, False if the (url, pubkey)
    pair was already present (in which case the latest scraped_at /
    bundle_root / bundle_sig are still refreshed so the row reflects
    the most recent observation).

    Independent of `pages_meta`. Multiple peers can contribute the
    same URL — each one gets a row. Used by `ingest_bundle` so peer
    attribution is recorded for URLs the local node already has in
    `pages` (Issue #65)."""
    if not url or not source_pubkey:
        return False
    cur = conn.execute(
        "INSERT OR IGNORE INTO page_contributors("
        "  url, source_pubkey, source_label, scraped_at, "
        "  bundle_root, bundle_sig"
        ") VALUES(?, ?, ?, ?, ?, ?)",
        (url, source_pubkey, source_label, scraped_at,
         bundle_root, bundle_sig),
    )
    if cur.rowcount:
        return True
    conn.execute(
        "UPDATE page_contributors SET "
        "  source_label=?, scraped_at=?, bundle_root=?, bundle_sig=? "
        "WHERE url=? AND source_pubkey=?",
        (source_label, scraped_at, bundle_root, bundle_sig,
         url, source_pubkey),
    )
    return False


def list_contributors(
    conn: sqlite3.Connection, url: str,
) -> list[dict[str, str]]:
    """Return `[{source_pubkey, source_label, scraped_at}, ...]` for
    `url`, ordered by scraped_at DESC (most recent first). Used by
    `indrex_graph.snapshot()` to populate the per-node contributors
    list."""
    if not url:
        return []
    try:
        rows = conn.execute(
            "SELECT source_pubkey, source_label, scraped_at "
            "FROM page_contributors WHERE url=? "
            "ORDER BY scraped_at DESC",
            (url,),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    out: list[dict[str, str]] = []
    for r in rows:
        try:
            out.append({
                "source_pubkey": r["source_pubkey"],
                "source_label": r["source_label"] or "",
                "scraped_at": r["scraped_at"] or "",
            })
        except (TypeError, IndexError):
            out.append({
                "source_pubkey": r[0],
                "source_label": r[1] or "",
                "scraped_at": r[2] or "",
            })
    return out
