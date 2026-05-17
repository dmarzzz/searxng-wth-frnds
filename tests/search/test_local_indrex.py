"""LOCAL_INDREX tests against a freshly-built indrex."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf.search import local_indrex
from swf.search.local_indrex import build_safe_fts_query
from swf.search.migration import ensure_schema, set_meta

# ─── safe FTS builder ──────────────────────────────────────────────────

def test_safe_fts_quotes_each_token():
    assert build_safe_fts_query("hello world") == '"hello" AND "world"'


def test_safe_fts_strips_operators_and_double_quotes():
    # leading "-" / "^" + trailing "*" + embedded `"` all get cleaned
    out = build_safe_fts_query('-foo* ^bar "baz"')
    assert out == '"foo" AND "bar" AND "baz"'


def test_safe_fts_empty_returns_empty_phrase():
    assert build_safe_fts_query("") == '""'
    assert build_safe_fts_query("   ") == '""'


# ─── end-to-end indrex query ───────────────────────────────────────────

@pytest.fixture
def indrex_db(tmp_path: Path) -> Path:
    """Build a tiny FTS5 indrex matching the production schema."""
    db = tmp_path / "world_knowledge" / "index.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE VIRTUAL TABLE pages USING fts5(
              url UNINDEXED, title, content,
              fetched_at UNINDEXED,
              tokenize='porter unicode61')"""
    )
    conn.execute(
        """CREATE TABLE page_cids (
               url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
               computed_at TEXT NOT NULL)"""
    )
    rows = [
        ("https://example.com/merkle",
         "Merkle proof primer", "merkle proof primer body text",
         "2026-04-01T00:00:00Z"),
        ("https://docs.example.org/dp",
         "Differential privacy survey", "differential privacy budget body",
         "2026-04-02T00:00:00Z"),
        ("https://arxiv.org/abs/2306.00001",
         "Differential privacy bounds", "lower bounds on dp queries",
         "2026-04-03T00:00:00Z"),
        ("https://other.example.net/xyz",
         "Unrelated post", "this paragraph mentions cats",
         "2026-04-04T00:00:00Z"),
    ]
    for url, title, content, ts in rows:
        conn.execute(
            "INSERT INTO pages(url, title, content, fetched_at) VALUES(?,?,?,?)",
            (url, title, content, ts),
        )
    conn.commit()
    # Apply the migration on a separate writable connection (mirrors prod).
    ensure_schema(conn)
    set_meta(conn, "https://docs.example.org/dp", share_scope="friends",
             sensitivity_label="low")
    set_meta(conn, "https://other.example.net/xyz",
             sensitivity_label="high")  # high-sensitivity row
    conn.commit()
    conn.close()
    return db


def test_indrex_returns_local_indrex_origin(indrex_db: Path):
    rs = local_indrex.search("differential privacy", db=indrex_db)
    assert rs.attempt.status == "ok"
    assert len(rs.results) >= 2
    for r in rs.results:
        assert r.delivery_path.value == "LOCAL_INDREX"
        assert r.origin_path.value == "LOCAL_INDREX"
        assert 0 < r.score <= 1.0


def test_indrex_propagates_share_scope_into_safety(indrex_db: Path):
    rs = local_indrex.search("differential privacy", db=indrex_db)
    by_url = {r.canonical_url: r for r in rs.results}
    # docs.example.org/dp was set to share_scope=friends
    assert by_url["https://docs.example.org/dp"].safety.share_scope == "friends"
    # arxiv row had no metadata row → default 'private'
    assert by_url["https://arxiv.org/abs/2306.00001"].safety.share_scope == "private"


def test_indrex_missing_db_returns_no_results(tmp_path: Path):
    rs = local_indrex.search("anything", db=tmp_path / "nonexistent.db")
    assert rs.results == []
    assert rs.attempt.status == "no_indrex"


def test_indrex_empty_query_returns_no_results(indrex_db: Path):
    rs = local_indrex.search("", db=indrex_db)
    assert rs.results == []
    assert rs.attempt.status == "empty_query"


def test_indrex_results_are_ordered_by_score(indrex_db: Path):
    rs = local_indrex.search("differential privacy", db=indrex_db)
    scores = [r.score for r in rs.results]
    assert scores == sorted(scores, reverse=True)


def test_indrex_top_k_caps_at_50(indrex_db: Path):
    rs = local_indrex.search("differential", db=indrex_db, top_k=999)
    assert len(rs.results) <= 50


# ── TODO-8: §13.1 freshness + verification flow-through ────────────────


@pytest.fixture
def indrex_with_phase3_meta(tmp_path: Path) -> Path:
    """A tiny indrex where every row has the §13.1 extension columns
    populated, so we can assert the fields land in §11.4's
    freshness.fetched_at_ms and verification.content_hash."""
    db = tmp_path / "world_knowledge" / "index.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE VIRTUAL TABLE pages USING fts5(
              url UNINDEXED, title, content,
              fetched_at UNINDEXED,
              tokenize='porter unicode61')"""
    )
    conn.execute(
        """CREATE TABLE page_cids (
               url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
               computed_at TEXT NOT NULL)"""
    )
    rows = [
        ("https://hash.example/full",   "Hashed",  "differential privacy full"),
        ("https://hash.example/legacy", "Legacy",  "differential privacy legacy"),
        ("https://gone.example/dead",   "Dead",    "differential privacy gone"),
    ]
    for url, title, content in rows:
        conn.execute(
            "INSERT INTO pages(url, title, content, fetched_at) VALUES(?,?,?,?)",
            (url, title, content, "2026-04-01T00:00:00Z"),
        )
    # Legacy row only has the page_cids fallback hash.
    conn.execute(
        "INSERT INTO page_cids(url, content_cid, computed_at) VALUES(?,?,?)",
        ("https://hash.example/legacy", "cid:legacy", "2026-04-01T00:00:00Z"),
    )
    ensure_schema(conn)
    set_meta(conn, "https://hash.example/full",
             share_scope="public",
             content_hash="sha256:FULL",
             fetched_at_ms=1_700_000_000_000)
    # Legacy row: no content_hash on pages_meta — should fall back to cid.
    set_meta(conn, "https://hash.example/legacy",
             share_scope="public",
             fetched_at_ms=1_700_000_001_000)
    # Tombstoned row — must not surface from LOCAL_INDREX either.
    set_meta(conn, "https://gone.example/dead",
             share_scope="public",
             deleted_at_ms=1_700_000_002_000)
    conn.commit()
    conn.close()
    return db


def test_indrex_propagates_fetched_at_ms(indrex_with_phase3_meta: Path):
    rs = local_indrex.search("differential privacy",
                             db=indrex_with_phase3_meta)
    by_url = {r.canonical_url: r for r in rs.results}
    assert by_url["https://hash.example/full"].freshness.fetched_at_ms \
        == 1_700_000_000_000
    assert by_url["https://hash.example/legacy"].freshness.fetched_at_ms \
        == 1_700_000_001_000


def test_indrex_propagates_content_hash_with_legacy_cid_fallback(
        indrex_with_phase3_meta: Path):
    rs = local_indrex.search("differential privacy",
                             db=indrex_with_phase3_meta)
    by_url = {r.canonical_url: r for r in rs.results}
    # Explicit pages_meta.content_hash takes precedence.
    assert by_url["https://hash.example/full"].verification.content_hash \
        == "sha256:FULL"
    # Legacy row had no content_hash on pages_meta — falls back to
    # page_cids.content_cid.
    assert by_url["https://hash.example/legacy"].verification.content_hash \
        == "cid:legacy"


def test_indrex_drops_tombstoned_rows(indrex_with_phase3_meta: Path):
    """LOCAL_INDREX honors `deleted_at_ms IS NULL` so tombstoned rows
    never surface to the local user either."""
    rs = local_indrex.search("differential privacy",
                             db=indrex_with_phase3_meta)
    urls = {r.canonical_url for r in rs.results}
    assert "https://gone.example/dead" not in urls
