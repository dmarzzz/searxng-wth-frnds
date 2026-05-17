"""Cross-PR cleanup: pin that ensure_schema is forward-compatible
on a legacy DB that predates the post-#43 columns.

A `peers` table created in the original PR-A shape (no
`last_seen_epoch`, no `consecutive_failures`, no `next_attempt_at`)
must be migrated by a single `ensure_schema` call without losing
data."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf.search import migration


def _legacy_peers_schema(conn: sqlite3.Connection) -> None:
    """Approximate the PR-A peers table shape — no extension columns."""
    conn.execute(
        "CREATE TABLE peers ("
        "  pubkey TEXT PRIMARY KEY,"
        "  nickname TEXT NOT NULL DEFAULT '',"
        "  signature_color TEXT NOT NULL DEFAULT '',"
        "  signature_freq REAL NOT NULL DEFAULT 0,"
        "  last_seen_at TEXT,"
        "  last_pull_cursor INTEGER NOT NULL DEFAULT 0,"
        "  trust_level TEXT NOT NULL DEFAULT 'known'"
        "    CHECK(trust_level IN ('known','trusted','banned'))"
        ")"
    )


def test_ensure_schema_adds_all_extensions_to_legacy_peers(tmp_path):
    """Run ensure_schema on a DB whose `peers` table still has the
    PR-A shape. Verify all three extension columns appear and the
    existing rows survive."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    _legacy_peers_schema(conn)
    conn.execute(
        "INSERT INTO peers(pubkey, nickname, last_pull_cursor) "
        "VALUES(?,?,?)", ("pk_alice", "alice", 42),
    )
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(db))
    migration.ensure_schema(conn)
    conn.commit()

    # All three extension columns now present.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()}
    assert "last_seen_epoch" in cols
    assert "consecutive_failures" in cols
    assert "next_attempt_at" in cols
    # Pre-existing data survives.
    row = conn.execute(
        "SELECT pubkey, nickname, last_pull_cursor "
        "FROM peers WHERE pubkey=?", ("pk_alice",),
    ).fetchone()
    assert row == ("pk_alice", "alice", 42)
    # Defaults applied to the new columns.
    extras = conn.execute(
        "SELECT last_seen_epoch, consecutive_failures, next_attempt_at "
        "FROM peers WHERE pubkey=?", ("pk_alice",),
    ).fetchone()
    assert extras == ("", 0, "")
    conn.close()


def test_ensure_schema_idempotent_on_current_shape(tmp_path):
    """Calling ensure_schema twice on an already-current DB is a
    no-op — the second call's `name in peer_cols` short-circuit
    must skip every ALTER."""
    db = tmp_path / "fresh.db"
    conn = sqlite3.connect(str(db))
    migration.ensure_schema(conn)
    cols_first = {r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()}
    migration.ensure_schema(conn)  # second call
    cols_second = {r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()}
    assert cols_first == cols_second
    conn.close()


def test_swf_kv_table_created(tmp_path):
    """P2P #2's swf_kv lands during ensure_schema regardless of
    what shape the rest of the DB is in."""
    db = tmp_path / "kv.db"
    conn = sqlite3.connect(str(db))
    migration.ensure_schema(conn)
    row = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name='swf_kv'",
    ).fetchone()
    conn.close()
    assert row is not None


def test_get_node_epoch_id_works_on_legacy_db(tmp_path):
    """A legacy DB upgraded via ensure_schema should mint and
    persist an epoch_id on the first call."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    _legacy_peers_schema(conn)
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(db))
    migration.ensure_schema(conn)
    e1 = migration.get_node_epoch_id(conn)
    e2 = migration.get_node_epoch_id(conn)
    conn.close()
    assert e1 and e1 == e2
    assert len(e1) == 32
