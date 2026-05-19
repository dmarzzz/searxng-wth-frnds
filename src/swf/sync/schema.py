"""SQLite schema for the sync substrate (spec §6).

Two tables live in the existing indrex DB (`swf.indrex.db_path()`),
colocated with the `bundles` table:

  * `sync_records` — one row per accepted envelope. Append-only. The
    "current view" is the latest row per `record_id` by
    `(wall_ts_ms DESC, content_hash DESC)`.
  * `sync_record_authors` — one-author-per-record pin (spec §9.6) plus
    a `forked` flag set when fork detection trips (spec §9.9).

`ensure_schema(conn)` is idempotent and safe to call on every
connection / process boot, mirroring `swf.bundles.store.ensure_schema`.
WAL mode is enabled best-effort so the sync apply path and the HTTP
read path never block each other.
"""
from __future__ import annotations

import contextlib
import sqlite3

_CREATE_SYNC_RECORDS = """
CREATE TABLE IF NOT EXISTS sync_records (
    record_id        TEXT NOT NULL,
    content_hash     TEXT NOT NULL,
    wall_ts_ms       INTEGER NOT NULL,
    author_pubkey    TEXT NOT NULL,
    kind             TEXT NOT NULL,
    prev_hash        TEXT,
    envelope_json    TEXT NOT NULL,
    received_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (record_id, content_hash)
)
"""

# UNIQUE INDEX on (record_id, content_hash) per spec §9.10. The PRIMARY
# KEY above already enforces this; the explicit index ensures the dedup
# path uses an index even if the planner picks differently.
_CREATE_IDX_DEDUP = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_records_dedup
    ON sync_records(record_id, content_hash)
"""

# Drives the LWW + manifest queries (spec §6.2).
_CREATE_IDX_LWW = """
CREATE INDEX IF NOT EXISTS idx_sync_records_lww
    ON sync_records(record_id, wall_ts_ms DESC, content_hash DESC)
"""

# Insertion-order cursor for the puller — mirrors the bundles puller
# rowid cursor, kept here for future cross-record replication.
_CREATE_IDX_RECEIVED = """
CREATE INDEX IF NOT EXISTS idx_sync_records_received
    ON sync_records(received_at_ms)
"""

# Author pin. The `forked` column is part of the Phase 2 fork policy
# (spec §9.9) — when a fork is detected the row gets `forked=1`, and
# outbound replication for the record is suspended until the author
# writes a fresh envelope to resolve.
_CREATE_AUTHORS = """
CREATE TABLE IF NOT EXISTS sync_record_authors (
    record_id      TEXT PRIMARY KEY,
    author_pubkey  TEXT NOT NULL,
    pinned_at_ms   INTEGER NOT NULL,
    forked         INTEGER NOT NULL DEFAULT 0
)
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Idempotently create the sync tables + indexes.

    Mirrors the pattern in `swf.bundles.store.ensure_schema` — safe to
    call on every connection / process boot. WAL mode is enabled
    best-effort; the indrex DB usually runs in WAL via the search
    migration but a sync-only caller may open the DB before that
    fires (e.g. test harness with a tmp `SWF_KNOWLEDGE_DIR`).
    """
    with contextlib.suppress(sqlite3.DatabaseError):
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_CREATE_SYNC_RECORDS)
    conn.execute(_CREATE_IDX_DEDUP)
    conn.execute(_CREATE_IDX_LWW)
    conn.execute(_CREATE_IDX_RECEIVED)
    conn.execute(_CREATE_AUTHORS)
    # Best-effort migration: older DBs may not have the `forked` column.
    # `ALTER TABLE … ADD COLUMN` is idempotent if we swallow the
    # "duplicate column" error.
    with contextlib.suppress(sqlite3.OperationalError):
        conn.execute(
            "ALTER TABLE sync_record_authors ADD COLUMN forked INTEGER NOT NULL DEFAULT 0"
        )
    conn.commit()
