"""P2P-review #9 — verification log context regression tests.

VerifyResult now carries since/until/page_count/declared_root[:12]/
computed_root[:12]. peer_pull_failed events propagate the same.
Operators get enough context to pin down which window broke
without crawling logs."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import event_bus, peer_scraper
from swf.peer_scraper import (
    BUNDLE_SCHEMA,
    IndrexPeer,
    VerifyResult,
    merkle_root,
    verify_bundle,
)
from swf.search import migration


@pytest.fixture(autouse=True)
def _liveness_passes(monkeypatch):
    monkeypatch.setattr(peer_scraper, "liveness_check",
                        lambda url, timeout_s=None: True)


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
    conn.commit()
    conn.close()
    return db


# ── VerifyResult dataclass shape ──────────────────────────────────

def test_verify_result_carries_context_fields():
    """Pin the new fields in the dataclass."""
    v = VerifyResult(ok=False, reason="x", since=10, until=20,
                     page_count=5, declared_root="abc",
                     computed_root="def")
    assert v.since == 10
    assert v.until == 20
    assert v.page_count == 5
    assert v.declared_root == "abc"
    assert v.computed_root == "def"


# ── verify_bundle populates context on every rejection ───────────

def _bundle(**over):
    base = {
        "schema": BUNDLE_SCHEMA,
        "pubkey": "pk", "since": 0, "until": 0,
        "pages": [], "merkle_root": "",
        "sig": "AAAA", "epoch_id": "ep",
    }
    base.update(over)
    return base


def test_verify_bundle_merkle_mismatch_includes_both_roots():
    pages = [{"url": "https://a", "title": "A", "host": "a",
              "topic": "", "fetched_at": "", "content_cid": ""}]
    real_root = merkle_root(pages)
    bundle = _bundle(pages=pages, merkle_root="0" * 64,
                     since=0, until=1)
    v = verify_bundle(bundle, expected_pubkey="pk")
    assert v.ok is False
    assert v.reason == "merkle_mismatch"
    # Truncated to 12 chars per the spec.
    assert v.declared_root == "000000000000"
    assert v.computed_root == real_root[:12]
    assert v.page_count == 1
    assert v.since == 0 and v.until == 1


def test_verify_bundle_pubkey_mismatch_carries_window():
    bundle = _bundle(pubkey="other", since=5, until=10,
                     pages=[{"url": f"https://x/{i}", "title": "T",
                             "host": "x", "topic": "",
                             "fetched_at": "", "content_cid": ""}
                            for i in range(3)])
    v = verify_bundle(bundle, expected_pubkey="pk")
    assert v.reason == "pubkey_mismatch"
    assert v.since == 5
    assert v.until == 10
    assert v.page_count == 3


def test_verify_bundle_not_a_dict_returns_zero_context():
    v = verify_bundle("not-a-bundle", expected_pubkey="pk")  # type: ignore[arg-type]
    assert v.reason == "not_a_dict"
    assert v.since == 0
    assert v.until == 0
    assert v.page_count == 0
    assert v.declared_root == ""


def test_verify_bundle_too_many_pages_records_count():
    pages = [{"url": f"u{i}", "title": "T", "host": "x", "topic": "",
              "fetched_at": "", "content_cid": ""}
             for i in range(peer_scraper.MAX_BUNDLE_PAGES + 1)]
    bundle = _bundle(pages=pages, since=0, until=0)
    v = verify_bundle(bundle, expected_pubkey="pk")
    assert v.reason == "too_many_pages"
    assert v.page_count == peer_scraper.MAX_BUNDLE_PAGES + 1


# ── peer_pull_failed event includes the same context ────────────

def test_peer_pull_failed_event_payload_has_context(indrex, monkeypatch):
    """A verify rejection must include the diagnostic fields in the
    SSE event payload — that's what the wall renders."""
    pages = [{"url": "https://a", "title": "A", "host": "a",
              "topic": "", "fetched_at": "", "content_cid": ""}]
    bogus = _bundle(
        pubkey="pk_a", pages=pages,
        merkle_root="0" * 64, since=0, until=1,
    )
    monkeypatch.setattr(peer_scraper, "_http_get_json",
                        lambda url, timeout=None: bogus)
    peer_scraper.upsert_peer(indrex, pubkey="pk_a", nickname="alice")
    rows = peer_scraper.list_peers(indrex)
    p = rows[0]
    p.base_url = "http://stub:1"
    peer_scraper.pull_from_peer(indrex, p)
    failed = event_bus.recent(kind="peer_pull_failed", limit=10)
    assert failed, "peer_pull_failed event was not emitted"
    payload = failed[0]["payload"]
    # Must include all the new context fields.
    assert payload["reason"] == "merkle_mismatch"
    assert payload["since"] == 0
    assert payload["until"] == 1
    assert payload["page_count"] == 1
    assert payload["declared_root"] == "000000000000"
    assert payload["computed_root"]


def test_peer_pull_failed_http_error_carries_minimal_context(
    indrex, monkeypatch,
):
    """An http_error has no bundle to pull `since`/`until` from, but
    we still report the puller's own `effective_since` so the
    operator knows what we asked for."""
    monkeypatch.setattr(peer_scraper, "_http_get_json",
                        lambda url, timeout=None: None)
    peer_scraper.upsert_peer(indrex, pubkey="pk", nickname="x")
    rows = peer_scraper.list_peers(indrex)
    p = rows[0]
    p.base_url = "http://offline:1"
    p.last_pull_cursor = 17
    peer_scraper.pull_from_peer(indrex, p)
    failed = event_bus.recent(kind="peer_pull_failed", limit=10)
    payload = failed[0]["payload"]
    assert payload["reason"] == "http_error"
    assert payload["since"] == 17
