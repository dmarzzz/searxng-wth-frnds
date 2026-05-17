"""Regression test from the local 2-node smoke run.

A fresh node started with `--full` has no FTS5 `pages` table —
swf.web.index owns its creation, and a peer-only
deployment may never run the agent. The scraper's `ingest_bundle`
path must bootstrap `pages` + `page_cids` before INSERTing or it
crashes on a fresh DB."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import peer_scraper


def test_ingest_bundle_bootstraps_fts5_pages(tmp_path):
    """Run ingest_bundle against a DB that has NO `pages` table.
    Bundle has one page; verify it lands without raising."""
    db = tmp_path / "fresh.db"
    bundle = {
        "schema": peer_scraper.BUNDLE_SCHEMA,
        "pubkey": "pk_alice", "since": 0, "until": 1,
        "pages": [{
            "url": "https://a/1", "title": "A",
            "host": "a", "topic": "",
            "fetched_at": "2026-04-01", "content_cid": "",
        }],
        "merkle_root": "x", "sig": "y",
    }
    n = peer_scraper.ingest_bundle(db, bundle, source_label="alice")
    assert n == 1
    # FTS5 `pages` and the page_cids sidecar both exist now.
    conn = sqlite3.connect(str(db))
    tables = {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','virtual table')"
        ).fetchall()
    }
    conn.close()
    assert "pages" in tables
    assert "page_cids" in tables


def test_ingest_bundle_idempotent_on_existing_pages(tmp_path):
    """When `pages` already exists, the bootstrap script's `IF NOT
    EXISTS` is a no-op — calling ingest_bundle twice in a row works."""
    db = tmp_path / "exists.db"
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
    conn.commit()
    conn.close()
    bundle = {
        "schema": peer_scraper.BUNDLE_SCHEMA,
        "pubkey": "pk", "since": 0, "until": 1,
        "pages": [{"url": "https://x/1", "title": "T", "host": "x",
                   "topic": "", "fetched_at": "", "content_cid": ""}],
        "merkle_root": "x", "sig": "y",
    }
    assert peer_scraper.ingest_bundle(db, bundle) == 1
    # Second call is dedup'd (same URL).
    assert peer_scraper.ingest_bundle(db, bundle) == 0
