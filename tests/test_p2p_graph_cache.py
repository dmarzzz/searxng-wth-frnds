"""P2P-review #7 — /graph snapshot caching regression tests.

Pins:
  - duplicate snapshot() within TTL returns the cached dict
  - any write that bumps `max(rowid in pages)` invalidates the entry
  - any write that bumps `max(rowid in search_results)` invalidates
  - distinct lens / own_pubkey keys are independent
  - the cache is bounded (>32 entries → LRU drop)
  - invalidate_cache() forces a fresh build
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import indrex_graph
from swf.search import migration


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "wk"))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    (tmp_path / "wk").mkdir(parents=True)
    db = tmp_path / "wk" / "index.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        """
        CREATE VIRTUAL TABLE pages USING fts5(
            url UNINDEXED, title, content, fetched_at UNINDEXED,
            tokenize='porter unicode61'
        );
        CREATE VIRTUAL TABLE search_results USING fts5(
            query_hash UNINDEXED, query UNINDEXED, url UNINDEXED,
            title, snippet, engines UNINDEXED, seen_at UNINDEXED,
            tokenize='porter unicode61'
        );
        CREATE TABLE page_cids(
            url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
            computed_at TEXT NOT NULL
        );
        """
    )
    migration.ensure_schema(conn)
    conn.commit()
    conn.close()
    indrex_graph.invalidate_cache()
    yield db
    indrex_graph.invalidate_cache()


def _add_page(db: Path, url: str, title: str = "T") -> None:
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO pages(url, title, content, fetched_at) "
        "VALUES(?,?,?,?)", (url, title, "x", "2026-04-01"),
    )
    conn.commit()
    conn.close()


def _add_search_result(db: Path, q: str, url: str) -> None:
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO search_results(query_hash, query, url, title, "
        "snippet, engines, seen_at) VALUES(?,?,?,?,?,?,?)",
        (q, q, url, "T", "s", "ddg", "2026-04-01"),
    )
    conn.commit()
    conn.close()


# ── basic cache hit ────────────────────────────────────────────────

def test_snapshot_returns_cached_dict_on_repeat_call(_isolated_state):
    _add_page(_isolated_state, "https://a/1")
    a = indrex_graph.snapshot()
    b = indrex_graph.snapshot()
    # Same OBJECT identity: cache returns the stashed dict reference.
    assert a is b


def test_distinct_lens_keys_are_independent(_isolated_state):
    _add_page(_isolated_state, "https://a/1")
    a = indrex_graph.snapshot(lens="topic")
    b = indrex_graph.snapshot(lens="domain")
    # Different lens values miss each other's cache slots.
    assert a is not b
    # Repeats hit.
    assert indrex_graph.snapshot(lens="topic") is a
    assert indrex_graph.snapshot(lens="domain") is b


def test_distinct_own_pubkey_keys_are_independent(_isolated_state):
    _add_page(_isolated_state, "https://a/1")
    a = indrex_graph.snapshot(own_pubkey="pk_a")
    b = indrex_graph.snapshot(own_pubkey="pk_b")
    assert a is not b


# ── high-water-mark invalidation ───────────────────────────────────

def test_new_page_invalidates_cache(_isolated_state):
    _add_page(_isolated_state, "https://a/1")
    a = indrex_graph.snapshot()
    _add_page(_isolated_state, "https://a/2")  # rowid bumps
    b = indrex_graph.snapshot()
    assert a is not b
    assert b["stats"]["nodes"] >= 1


def test_new_search_result_invalidates_cache(_isolated_state):
    _add_page(_isolated_state, "https://a/1")
    a = indrex_graph.snapshot()
    _add_search_result(_isolated_state, "q1", "https://a/1")
    b = indrex_graph.snapshot()
    assert a is not b


# ── invalidate_cache() forces refresh ──────────────────────────────

def test_invalidate_cache_drops_all_entries(_isolated_state):
    _add_page(_isolated_state, "https://a/1")
    a = indrex_graph.snapshot()
    indrex_graph.invalidate_cache()
    b = indrex_graph.snapshot()
    assert a is not b


# ── empty / missing DB doesn't poison the cache ───────────────────

def test_empty_db_path_returns_consistent_empty(tmp_path, monkeypatch):
    """Missing DB path → empty snapshot, no caching needed (the
    cache_key path bails to None on read error)."""
    missing = tmp_path / "missing-dir"
    snap = indrex_graph.snapshot(db_path=missing / "no.db")
    assert snap["nodes"] == []
    # Second call also empty; doesn't crash on the cache attempt.
    snap2 = indrex_graph.snapshot(db_path=missing / "no.db")
    assert snap2["nodes"] == []


# ── bounded cache size ─────────────────────────────────────────────

def test_cache_bounded_at_32_entries(_isolated_state):
    """Flooding distinct keys must NOT grow the cache without bound.
    The eviction kicks in around 32 entries."""
    _add_page(_isolated_state, "https://a/1")
    for i in range(40):
        indrex_graph.snapshot(lens=f"lens-{i}")
    assert len(indrex_graph._cache) <= 32
