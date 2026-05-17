"""Indrex sidecar-table migration tests."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf.search.migration import (
    ALLOWED_SOURCE_TYPES,
    DEFAULT_SENSITIVITY,
    DEFAULT_SHARE_SCOPE,
    DEFAULT_SOURCE_TYPE,
    ensure_schema,
    get_meta,
    set_meta,
)


@pytest.fixture
def conn(tmp_path: Path):
    db = tmp_path / "index.db"
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    yield c
    c.close()


def test_ensure_schema_is_idempotent(conn):
    ensure_schema(conn)
    ensure_schema(conn)  # no error
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='pages_meta'"
    ).fetchall()
    assert len(rows) == 1


def test_get_meta_returns_defaults_for_missing_url(conn):
    ensure_schema(conn)
    m = get_meta(conn, "https://never.seen/")
    # All six §13.1 fields are returned with documented defaults.
    assert m["share_scope"] == DEFAULT_SHARE_SCOPE
    assert m["sensitivity_label"] == DEFAULT_SENSITIVITY
    assert m["source_type"] == DEFAULT_SOURCE_TYPE
    assert m["content_hash"] is None
    assert m["fetched_at_ms"] is None
    assert m["deleted_at_ms"] is None


def test_set_meta_upsert(conn):
    ensure_schema(conn)
    set_meta(conn, "https://a.example/1", share_scope="friends",
             sensitivity_label="medium")
    m = get_meta(conn, "https://a.example/1")
    assert m["share_scope"] == "friends"
    assert m["sensitivity_label"] == "medium"
    # Defaults still applied to fields the caller didn't specify.
    assert m["source_type"] == DEFAULT_SOURCE_TYPE

    # Upsert: only sensitivity changes; share_scope is preserved.
    set_meta(conn, "https://a.example/1", sensitivity_label="high")
    m2 = get_meta(conn, "https://a.example/1")
    assert m2["share_scope"] == "friends"
    assert m2["sensitivity_label"] == "high"


def test_invalid_share_scope_rejected(conn):
    ensure_schema(conn)
    with pytest.raises(ValueError, match="share_scope"):
        set_meta(conn, "https://x/", share_scope="moon")


def test_invalid_sensitivity_rejected(conn):
    ensure_schema(conn)
    with pytest.raises(ValueError, match="sensitivity_label"):
        set_meta(conn, "https://x/", sensitivity_label="critical")


def test_check_constraints_enforce_enums(conn):
    ensure_schema(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO pages_meta(url, share_scope, sensitivity_label) "
            "VALUES(?, ?, ?)",
            ("https://x/", "moon", "unknown"),
        )


# ─── TODO-8: §13.1 schema extensions ────────────────────────────────────


def test_schema_has_all_six_phase3_columns(conn):
    """ensure_schema gives us every §13.1 column on a fresh DB."""
    ensure_schema(conn)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(pages_meta)")}
    for required in ("url", "share_scope", "sensitivity_label",
                     "source_type", "content_hash",
                     "fetched_at_ms", "deleted_at_ms"):
        assert required in cols, f"missing column: {required}"


def test_default_source_type_is_user_fetched(conn):
    """Inserting without an explicit source_type lands on 'user_fetched',
    the SAFE default — peer-ingested rows must be EXPLICITLY marked, never
    silently."""
    ensure_schema(conn)
    set_meta(conn, "https://a/", share_scope="friends")
    assert get_meta(conn, "https://a/")["source_type"] == "user_fetched"


def test_set_meta_round_trip_all_fields(conn):
    """Every new field round-trips through set_meta / get_meta."""
    ensure_schema(conn)
    set_meta(
        conn, "https://full.example/x",
        share_scope="friends",
        sensitivity_label="low",
        source_type="peer_ingest",
        content_hash="sha256:deadbeef",
        fetched_at_ms=1_700_000_000_000,
        deleted_at_ms=None,
    )
    m = get_meta(conn, "https://full.example/x")
    assert m == {
        "share_scope": "friends",
        "sensitivity_label": "low",
        "source_type": "peer_ingest",
        "content_hash": "sha256:deadbeef",
        "fetched_at_ms": 1_700_000_000_000,
        "deleted_at_ms": None,
    }


def test_set_meta_partial_update_preserves_other_fields(conn):
    """Updating one new field doesn't trash the others."""
    ensure_schema(conn)
    set_meta(conn, "https://p/", source_type="peer_ingest",
             content_hash="sha256:cafe", fetched_at_ms=1_111)
    set_meta(conn, "https://p/", deleted_at_ms=2_222)
    m = get_meta(conn, "https://p/")
    assert m["source_type"] == "peer_ingest"
    assert m["content_hash"] == "sha256:cafe"
    assert m["fetched_at_ms"] == 1_111
    assert m["deleted_at_ms"] == 2_222


def test_invalid_source_type_rejected(conn):
    ensure_schema(conn)
    with pytest.raises(ValueError, match="source_type"):
        set_meta(conn, "https://x/", source_type="lol_attacker")


def test_source_type_check_constraint_enforced(conn):
    ensure_schema(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO pages_meta(url, share_scope, sensitivity_label, source_type) "
            "VALUES(?, ?, ?, ?)",
            ("https://x/", "private", "unknown", "lol_attacker"),
        )


def test_allowed_source_types_match_spec():
    """If the spec ever extends this set, this test will catch a drift."""
    assert ALLOWED_SOURCE_TYPES == (
        "user_fetched", "peer_ingest", "manual_import",
    )


def test_idempotent_migration_on_legacy_minimal_schema(conn):
    """A DB that already has the OLD 4-column `pages_meta` (pre-TODO-8)
    must converge to the new 8-column shape on the next ensure_schema —
    without losing existing rows."""
    # Build the legacy minimal table that shipped with PR #15.
    conn.execute("""
        CREATE TABLE pages_meta (
            url               TEXT PRIMARY KEY,
            share_scope       TEXT NOT NULL DEFAULT 'private',
            sensitivity_label TEXT NOT NULL DEFAULT 'unknown',
            updated_at        TEXT NOT NULL DEFAULT 'legacy'
        )
    """)
    conn.execute(
        "INSERT INTO pages_meta(url, share_scope, sensitivity_label) "
        "VALUES(?, ?, ?)",
        ("https://legacy.example/old", "friends", "low"),
    )
    conn.commit()

    # Run the migration — must not error, must not drop the row.
    ensure_schema(conn)

    cols = {r["name"] for r in conn.execute("PRAGMA table_info(pages_meta)")}
    for added in ("source_type", "content_hash",
                  "fetched_at_ms", "deleted_at_ms"):
        assert added in cols

    # Existing row preserved with safe defaults backfilled by ALTER.
    m = get_meta(conn, "https://legacy.example/old")
    assert m["share_scope"] == "friends"
    assert m["sensitivity_label"] == "low"
    assert m["source_type"] == "user_fetched"      # safe default
    assert m["content_hash"] is None
    assert m["fetched_at_ms"] is None
    assert m["deleted_at_ms"] is None

    # And running ensure_schema AGAIN is still a no-op (idempotent).
    ensure_schema(conn)
    cols2 = {r["name"] for r in conn.execute("PRAGMA table_info(pages_meta)")}
    assert cols2 == cols


def test_idempotent_migration_when_some_extension_columns_exist(conn):
    """A partially-migrated DB (e.g. someone hand-added one column) still
    converges to the full shape without errors."""
    conn.execute("""
        CREATE TABLE pages_meta (
            url               TEXT PRIMARY KEY,
            share_scope       TEXT NOT NULL DEFAULT 'private',
            sensitivity_label TEXT NOT NULL DEFAULT 'unknown',
            updated_at        TEXT NOT NULL DEFAULT 'legacy'
        )
    """)
    # Hand-add only one of the four extension columns.
    conn.execute("ALTER TABLE pages_meta ADD COLUMN content_hash TEXT")
    conn.commit()

    ensure_schema(conn)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(pages_meta)")}
    for added in ("source_type", "content_hash",
                  "fetched_at_ms", "deleted_at_ms"):
        assert added in cols
