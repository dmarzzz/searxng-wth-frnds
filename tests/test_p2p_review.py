"""P2P expert review (post-pass-5) — regression tests for the fixes
to findings #1, #3, #4, #11, #12.

Each test cites the finding it guards. Numbering matches the review
output in the PR description."""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from swf import event_bus, identity, peer_scraper
from swf.peer_scraper import (
    Peer,
    build_bundle,
    ingest_bundle,
    list_peers,
    signing_payload,
    verify_bundle,
)
from swf.search import migration

# ── helpers ─────────────────────────────────────────────────────────

def _seed_indrex(db: Path) -> None:
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
def indrex(tmp_path, monkeypatch):
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    db = tmp_path / "index.db"
    _seed_indrex(db)
    return db


# ── #1 auto-seed peers from discovery ──────────────────────────────

def test_seed_peers_from_discovery_inserts_new_pubkeys(indrex, monkeypatch):
    """A fresh node's `peers` table is empty; without auto-seeding the
    scraper does nothing forever. _seed_peers_from_discovery upserts
    every DiscoveredPeer with a pubkey on each tick."""
    class _DP:
        def __init__(self, name, url, pubkey):
            self.name, self.url, self.pubkey = name, url, pubkey

    import swf.discovery
    monkeypatch.setattr(swf.discovery, "discover_all_peers", lambda: [
        _DP("alice", "http://10.0.0.2:7777", "pk_alice"),
        _DP("bob",   "http://10.0.0.3:7777", "pk_bob"),
        _DP("noise", "http://10.0.0.9:7777", None),  # filtered out
    ])
    seeded = peer_scraper._seed_peers_from_discovery(indrex)
    assert seeded == 2
    rows = list_peers(indrex)
    pks = sorted(p.pubkey for p in rows)
    assert pks == ["pk_alice", "pk_bob"]
    # signature_color is deterministic per pubkey.
    conn = sqlite3.connect(str(indrex))
    color = conn.execute(
        "SELECT signature_color FROM peers WHERE pubkey=?",
        ("pk_alice",),
    ).fetchone()[0]
    conn.close()
    assert color and color.startswith("#") and len(color) == 7


def test_seed_peers_from_discovery_idempotent(indrex, monkeypatch):
    """Calling twice doesn't create duplicates and reports 0 the
    second time."""
    class _DP:
        def __init__(self, pubkey):
            self.name = "x"
            self.url = "http://x:7777"
            self.pubkey = pubkey

    import swf.discovery
    monkeypatch.setattr(swf.discovery, "discover_all_peers",
                        lambda: [_DP("pk_x")])
    assert peer_scraper._seed_peers_from_discovery(indrex) == 1
    assert peer_scraper._seed_peers_from_discovery(indrex) == 0
    assert len(list_peers(indrex)) == 1


# ── #3 ingest respects local tombstones ────────────────────────────

def test_ingest_bundle_skips_tombstoned_urls(indrex):
    """If the user tombstoned a URL (deleted_at_ms set), a peer
    bundle MUST NOT resurrect it. P2P-review #3."""
    # Tombstone a URL locally.
    conn = sqlite3.connect(str(indrex))
    migration.set_meta(conn, "https://t/1", deleted_at_ms=1)
    conn.commit()
    conn.close()
    bundle = {
        "schema": peer_scraper.BUNDLE_SCHEMA,
        "pubkey": "pk", "since": 0, "until": 1,
        "pages": [{
            "url": "https://t/1", "title": "should-not-resurrect",
            "host": "t", "topic": "", "fetched_at": "",
            "content_cid": "",
        }],
        "merkle_root": "x", "sig": "y",
    }
    n = ingest_bundle(indrex, bundle, source_label="alice")
    assert n == 0
    conn = sqlite3.connect(str(indrex))
    fts_row = conn.execute(
        "SELECT 1 FROM pages WHERE url=?", ("https://t/1",),
    ).fetchone()
    conn.close()
    # FTS row never inserted — tombstone wins.
    assert fts_row is None


# ── #11 signing_payload binds page count ───────────────────────────

def test_signing_payload_includes_page_count():
    base = signing_payload(merkle_root_hex="aa", since=0, until=1,
                           pubkey_b64="pk", page_count=5)
    other = signing_payload(merkle_root_hex="aa", since=0, until=1,
                            pubkey_b64="pk", page_count=6)
    # Different page counts → different signing payloads → different sigs.
    assert base != other
    # Default page_count=0 keeps the old-test contract.
    legacy = signing_payload(merkle_root_hex="aa", since=0, until=1,
                             pubkey_b64="pk")
    assert legacy != base


def test_verify_bundle_rejects_signature_with_wrong_page_count(indrex):
    """A producer that signs with N pages but ships M != N must be
    rejected — this prevents equivocation about how many pages fit
    in a window. Without #11's fix the verifier would accept."""
    ident = identity.get_or_create_identity()
    # Build a real bundle with one page, then duplicate the page so
    # the count differs from what was signed.
    conn = sqlite3.connect(str(indrex))
    conn.execute(
        "INSERT INTO pages(url, title, content, fetched_at) "
        "VALUES(?, ?, ?, ?)",
        ("https://a/1", "A", "x", "2026-04-01"),
    )
    migration.set_meta(conn, "https://a/1", share_scope="friends")
    conn.commit()
    conn.close()
    bundle = build_bundle(db_path=indrex, since=0, limit=10, ident=ident)
    assert len(bundle["pages"]) == 1
    # Tamper: add a second page (changes both merkle root AND count).
    bundle["pages"].append({
        "url": "https://a/1", "title": "A2", "host": "a",
        "topic": "", "fetched_at": "", "content_cid": "",
    })
    # Re-sign with the WRONG page_count (claiming 1 when shipping 2)
    # using the legitimate merkle root for the new pages list.
    import base64
    new_root = peer_scraper.merkle_root(bundle["pages"])
    bundle["merkle_root"] = new_root
    payload = signing_payload(
        merkle_root_hex=new_root,
        since=bundle["since"], until=bundle["until"],
        pubkey_b64=bundle["pubkey"], page_count=1,  # LIE
    )
    bundle["sig"] = base64.urlsafe_b64encode(
        ident.sign(payload),
    ).rstrip(b"=").decode("ascii")
    # Bundle has 2 pages, sig was over count=1 → mismatch.
    # (Will also fail duplicate_url check; verify the order.)
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok
    assert v.reason in ("duplicate_url", "sig_mismatch")


# ── #12 set_meta failure prevents orphan FTS row ───────────────────

def test_ingest_bundle_skips_page_when_set_meta_fails(indrex, monkeypatch):
    """If `set_meta` raises (e.g. a CHECK constraint violation), the
    FTS row must NOT be inserted — otherwise indrex_graph would
    mis-attribute the row to `is_self=True` because source_pubkey
    is NULL. P2P-review #12.

    Some tests in the suite nuke `swf.*` from sys.modules; we
    fresh-import the modules we patch so monkeypatch hits the same
    objects ingest_bundle's internal `from .search import migration`
    will resolve to."""
    import importlib
    fresh_migration = importlib.import_module("swf.search.migration")
    fresh_scraper = importlib.import_module("swf.peer_scraper")
    real_set_meta = fresh_migration.set_meta
    calls = {"n": 0}

    def _boom_set_meta(conn, url, **kw):
        calls["n"] += 1
        if url == "https://bad/2":
            raise RuntimeError("simulated meta failure")
        return real_set_meta(conn, url, **kw)

    monkeypatch.setattr(fresh_migration, "set_meta", _boom_set_meta)
    bundle = {
        "schema": fresh_scraper.BUNDLE_SCHEMA,
        "pubkey": "pk", "since": 0, "until": 2,
        "pages": [
            {"url": "https://good/1", "title": "Good Page Title",
             "host": "good", "topic": "", "fetched_at": "",
             "content_cid": ""},
            {"url": "https://bad/2", "title": "Bad Page Title",
             "host": "bad", "topic": "", "fetched_at": "",
             "content_cid": ""},
        ],
        "merkle_root": "x", "sig": "y",
    }
    n = fresh_scraper.ingest_bundle(indrex, bundle, source_label="alice")
    # Only the good page got through.
    assert n == 1
    conn = sqlite3.connect(str(indrex))
    rows = sorted(r[0] for r in conn.execute(
        "SELECT url FROM pages",
    ).fetchall())
    conn.close()
    assert rows == ["https://good/1"]
    # The bad page must NOT be in pages (no orphan FTS row).
    assert "https://bad/2" not in rows


# ── #4 events vacuum bounds the table + WAL truncates ──────────────

def test_vacuum_events_keeps_recent(indrex):
    """vacuum_events keeps only the most-recent retain_count rows."""
    for i in range(50):
        event_bus.emit("k", {"i": i})
    # Should have 50 rows.
    rows_before = event_bus.recent(limit=1000)
    assert len(rows_before) == 50
    deleted = event_bus.vacuum_events(retain_count=10, retain_days=0)
    assert deleted == 40
    rows_after = event_bus.recent(limit=1000)
    assert len(rows_after) == 10
    # The 10 kept are the most recent (highest ids).
    kept_is = sorted(r["payload"]["i"] for r in rows_after)
    assert kept_is == list(range(40, 50))


def test_vacuum_events_returns_zero_on_empty(indrex):
    deleted = event_bus.vacuum_events(retain_count=10, retain_days=0)
    assert deleted == 0


def test_emit_triggers_opportunistic_vacuum(indrex, monkeypatch):
    """The opportunistic vacuum kicks in every _VACUUM_EVERY emits.
    Verify by stubbing the threshold low and confirming
    `vacuum_events` was called."""
    calls = {"n": 0}
    real_vacuum = event_bus.vacuum_events

    def _wrap_vacuum(*args, **kw):
        calls["n"] += 1
        return real_vacuum(*args, **kw)

    monkeypatch.setattr(event_bus, "vacuum_events", _wrap_vacuum)
    monkeypatch.setattr(event_bus, "_VACUUM_EVERY", 5)
    # Reset the counter so threshold timing is predictable.
    monkeypatch.setattr(event_bus, "_emit_count", 0)
    for _ in range(15):
        event_bus.emit("k", {"x": 1})
    # 15 emits / threshold 5 = 3 vacuum calls.
    assert calls["n"] == 3
