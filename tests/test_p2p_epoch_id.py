"""P2P-review #2 — epoch_id binding regression tests.

The producer signs `node_epoch_id` (random UUID, persisted in
`swf_kv` once per DB) into every bundle. Consumers store the seen
epoch in `peers.last_seen_epoch`; when a future bundle's epoch
differs they reset `last_pull_cursor=0` and re-ingest from scratch.

Without this, a peer that rebuilds its indrex (rowids reset to 1)
would never re-share rows 1..N because our cursor stayed at N."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import identity, peer_scraper
from swf.peer_scraper import (
    Peer,
    build_bundle,
    latest_cursor_with_epoch,
    list_peers,
    pull_from_peer,
    signing_payload,
    update_pull_cursor,
    upsert_peer,
    verify_bundle,
)
from swf.search import migration


@pytest.fixture(autouse=True)
def _liveness_passes(monkeypatch):
    monkeypatch.setattr(peer_scraper, "liveness_check",
                        lambda url, timeout_s=None: True)


def _seed(db: Path) -> None:
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
    conn.commit()
    conn.close()


@pytest.fixture
def producer(tmp_path, monkeypatch):
    """Fixture that builds a writable indrex with one shareable page
    plus an isolated identity. Returns (db_path, identity)."""
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "wk"))
    (tmp_path / "wk").mkdir(parents=True)
    db = tmp_path / "wk" / "index.db"
    _seed(db)
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO pages(url, title, content, fetched_at) "
        "VALUES(?,?,?,?)",
        ("https://a/1", "A", "content", "2026-04-01"),
    )
    migration.set_meta(conn, "https://a/1", share_scope="friends")
    conn.commit()
    conn.close()
    ident = identity.get_or_create_identity()
    return db, ident


# ── kv epoch generation ───────────────────────────────────────────

def test_get_node_epoch_id_persists_within_db(tmp_path):
    db = tmp_path / "x.db"
    conn = sqlite3.connect(str(db))
    migration.ensure_schema(conn)
    e1 = migration.get_node_epoch_id(conn)
    e2 = migration.get_node_epoch_id(conn)
    conn.close()
    assert e1 and e1 == e2
    assert len(e1) == 32  # uuid4().hex


def test_get_node_epoch_id_changes_with_fresh_db(tmp_path):
    """A rebuilt DB mints a new epoch — that's how consumers detect
    the producer reset."""
    db1 = tmp_path / "first.db"
    conn = sqlite3.connect(str(db1))
    migration.ensure_schema(conn)
    e1 = migration.get_node_epoch_id(conn)
    conn.close()

    db2 = tmp_path / "second.db"
    conn2 = sqlite3.connect(str(db2))
    migration.ensure_schema(conn2)
    e2 = migration.get_node_epoch_id(conn2)
    conn2.close()
    assert e1 != e2


# ── bundle signs and verifies epoch_id ────────────────────────────

def test_build_bundle_includes_epoch_id(producer):
    db, ident = producer
    bundle = build_bundle(db_path=db, since=0, limit=10, ident=ident)
    assert bundle.get("epoch_id")
    assert len(bundle["epoch_id"]) == 32


def test_verify_bundle_rejects_mutated_epoch_id(producer):
    """Tampering with `epoch_id` after signing must fail the sig
    check — proves epoch_id is bound into the signing payload."""
    db, ident = producer
    bundle = build_bundle(db_path=db, since=0, limit=10, ident=ident)
    bundle["epoch_id"] = "deadbeef" * 4
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok
    assert v.reason == "sig_mismatch"


def test_verify_bundle_rejects_oversize_epoch_id(producer):
    db, ident = producer
    bundle = build_bundle(db_path=db, since=0, limit=10, ident=ident)
    bundle["epoch_id"] = "x" * 1000
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok
    assert v.reason == "bad_epoch_id"


# ── /index/cursor returns epoch_id ────────────────────────────────

def test_latest_cursor_with_epoch_returns_both(producer):
    db, _ = producer
    cur, epoch = latest_cursor_with_epoch(db)
    assert cur == 1
    assert epoch and len(epoch) == 32


def test_latest_cursor_with_epoch_zero_on_missing_db(tmp_path):
    cur, epoch = latest_cursor_with_epoch(tmp_path / "missing.db")
    assert (cur, epoch) == (0, "")


# ── pull_from_peer detects rotation and resets cursor ─────────────

def test_pull_resets_cursor_when_epoch_changes(producer, tmp_path,
                                                 monkeypatch):
    """Consumer last saw `epoch=A` from this peer with cursor=42.
    Producer rebuilds → new epoch_id `B`. Next /index/cursor returns
    `(cursor=1, epoch=B)`. Consumer detects and resets cursor to 0
    on the /index/pages call."""
    db, ident = producer
    bundle = build_bundle(db_path=db, since=0, limit=10, ident=ident)
    new_epoch = bundle["epoch_id"]

    # Local consumer-side indrex (separate from producer).
    local_dir = tmp_path / "consumer"
    local_dir.mkdir()
    monkeypatch.setenv("SWF_CONFIG_DIR", str(local_dir / "cfg"))
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(local_dir / "wk"))
    (local_dir / "wk").mkdir()
    local_db = local_dir / "wk" / "index.db"
    _seed(local_db)
    upsert_peer(local_db, pubkey=ident.pub_b64, nickname="alice")
    # Pretend we previously synced from this peer at cursor=42 under
    # an old epoch.
    update_pull_cursor(
        local_db, pubkey=ident.pub_b64, cursor=42,
        last_seen_epoch="OLD-EPOCH" + "0" * 23,
    )
    rows = list_peers(local_db)
    assert rows[0].last_pull_cursor == 42
    assert rows[0].last_seen_epoch.startswith("OLD-EPOCH")

    # Stub the HTTP transport: /index/cursor returns the producer's
    # current state; /index/pages returns the bundle.
    requested_urls: list[str] = []

    def _fake_http(url, timeout=None):
        requested_urls.append(url)
        if url.endswith("/index/cursor"):
            return {"cursor": 1, "epoch_id": new_epoch}
        # /index/pages with since=<consumer-cursor>
        return bundle

    monkeypatch.setattr(peer_scraper, "_http_get_json", _fake_http)
    peer = Peer(
        pubkey=ident.pub_b64, nickname="alice",
        last_seen_at=None, last_pull_cursor=42,
        trust_level="known", base_url="http://alice.local:7777",
        last_seen_epoch="OLD-EPOCH" + "0" * 23,
    )
    n, status = pull_from_peer(local_db, peer)
    assert status == "ok"
    assert n == 1  # one shareable page ingested
    # The /index/pages URL must have used since=0 (cursor reset).
    pages_calls = [u for u in requested_urls if "/index/pages" in u]
    assert any("since=0" in u for u in pages_calls)
    # last_seen_epoch updated to the new producer epoch.
    rows_after = list_peers(local_db)
    assert rows_after[0].last_seen_epoch == new_epoch


def test_pull_first_time_records_epoch(producer, tmp_path, monkeypatch):
    """A peer we've never synced before (last_seen_epoch=='') records
    the producer's epoch on the first successful pull."""
    db, ident = producer
    bundle = build_bundle(db_path=db, since=0, limit=10, ident=ident)
    monkeypatch.setattr(peer_scraper, "_http_get_json", lambda url, timeout=None:
                        {"cursor": 1, "epoch_id": bundle["epoch_id"]}
                        if url.endswith("/index/cursor")
                        else bundle)
    local_dir = tmp_path / "consumer2"
    local_dir.mkdir()
    monkeypatch.setenv("SWF_CONFIG_DIR", str(local_dir / "cfg"))
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(local_dir / "wk"))
    (local_dir / "wk").mkdir()
    local_db = local_dir / "wk" / "index.db"
    _seed(local_db)
    upsert_peer(local_db, pubkey=ident.pub_b64, nickname="alice")
    peer = Peer(
        pubkey=ident.pub_b64, nickname="alice",
        last_seen_at=None, last_pull_cursor=0,
        trust_level="known", base_url="http://alice.local:7777",
        last_seen_epoch="",
    )
    n, status = pull_from_peer(local_db, peer)
    assert status == "ok"
    rows = list_peers(local_db)
    assert rows[0].last_seen_epoch == bundle["epoch_id"]
