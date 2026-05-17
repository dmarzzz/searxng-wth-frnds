"""P2P-review #10 — cursor vocabulary regression tests.

Pin the new names + back-compat aliases. The vocabulary docstring at
the top of `peer_scraper.py` is the canonical reference."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import peer_scraper
from swf.peer_scraper import (
    latest_cursor,
    latest_cursor_with_epoch,
    producer_high_water_mark,
    producer_high_water_with_epoch,
)
from swf.search import migration


@pytest.fixture
def indrex(tmp_path, monkeypatch):
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
        CREATE TABLE page_cids(
            url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
            computed_at TEXT NOT NULL
        );
        """
    )
    migration.ensure_schema(conn)
    conn.execute(
        "INSERT INTO pages(url, title, content, fetched_at) "
        "VALUES(?,?,?,?)", ("https://x", "T", "x", "2026-04-01"),
    )
    conn.commit()
    conn.close()
    return db


def test_back_compat_aliases_point_at_new_names():
    assert latest_cursor is producer_high_water_mark
    assert latest_cursor_with_epoch is producer_high_water_with_epoch


def test_producer_high_water_mark_returns_max_rowid(indrex):
    assert producer_high_water_mark(indrex) == 1


def test_producer_high_water_with_epoch_returns_both(indrex):
    cur, epoch = producer_high_water_with_epoch(indrex)
    assert cur == 1
    assert epoch and len(epoch) == 32


def test_module_docstring_documents_vocabulary():
    """The docstring is the authoritative vocabulary reference. A
    future refactor that drops the section would silently re-confuse
    readers; pin its presence."""
    assert "Cursor vocabulary" in peer_scraper.__doc__
    assert "producer_high_water_mark" in peer_scraper.__doc__
    assert "consumer_pull_cursor" in peer_scraper.__doc__
    assert "bundle_since" in peer_scraper.__doc__
    assert "bundle_until" in peer_scraper.__doc__
