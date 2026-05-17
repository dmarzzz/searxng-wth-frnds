"""P2P-review #8 — peer backoff / quarantine regression tests."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from swf import peer_scraper
from swf.peer_scraper import (
    BACKOFF_BASE_S,
    BACKOFF_MAX_S,
    IndrexPeer,
    _backoff_seconds,
    _peer_in_backoff,
    _record_pull_failure,
    _record_pull_success,
    list_peers,
    pull_from_peer,
    upsert_peer,
)
from swf.search import migration


@pytest.fixture(autouse=True)
def _liveness_passes(monkeypatch):
    """After PR #62 added a liveness probe before bundle-fetch, tests
    that stub `_http_get_json` need this so the bundle path actually
    fires. Bypassed via monkeypatch in tests that explicitly cover
    liveness-failure semantics."""
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
def indrex(tmp_path, monkeypatch):
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "wk"))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    (tmp_path / "wk").mkdir(parents=True)
    db = tmp_path / "wk" / "index.db"
    _seed(db)
    return db


# ── _backoff_seconds curve ─────────────────────────────────────────

def test_backoff_zero_failures_returns_zero():
    assert _backoff_seconds(0) == 0


def test_backoff_grows_exponentially():
    seq = [_backoff_seconds(i) for i in range(1, 8)]
    # 60, 120, 240, 480, 960, 1920, 3600 (capped)
    assert seq == [60, 120, 240, 480, 960, 1920, 3600]


def test_backoff_caps_at_one_hour():
    for f in (10, 100, 10_000):
        assert _backoff_seconds(f) == BACKOFF_MAX_S


# ── failure / success recording ────────────────────────────────────

def test_record_failure_bumps_count_and_sets_next_attempt(indrex):
    upsert_peer(indrex, pubkey="pk")
    n1 = _record_pull_failure(indrex, pubkey="pk")
    assert n1 == 1
    n2 = _record_pull_failure(indrex, pubkey="pk")
    assert n2 == 2
    rows = list_peers(indrex)
    assert rows[0].consecutive_failures == 2
    assert rows[0].next_attempt_at != ""


def test_record_failure_on_unknown_pubkey_returns_zero(indrex):
    """Recording failure on a peer that doesn't exist must NOT crash
    and must NOT silently insert a row."""
    n = _record_pull_failure(indrex, pubkey="ghost")
    assert n == 0
    assert list_peers(indrex) == []


def test_record_success_resets_counters(indrex):
    upsert_peer(indrex, pubkey="pk")
    _record_pull_failure(indrex, pubkey="pk")
    _record_pull_failure(indrex, pubkey="pk")
    _record_pull_success(indrex, pubkey="pk")
    rows = list_peers(indrex)
    assert rows[0].consecutive_failures == 0
    assert rows[0].next_attempt_at == ""


# ── _peer_in_backoff predicate ─────────────────────────────────────

def test_peer_in_backoff_false_when_no_schedule():
    p = IndrexPeer(
        pubkey="pk", nickname="", last_seen_at=None,
        last_pull_cursor=0, trust_level="known",
        next_attempt_at="",
    )
    assert _peer_in_backoff(p) is False


def test_peer_in_backoff_true_when_future():
    future = (datetime.now(timezone.utc) + timedelta(seconds=300)
              ).strftime("%Y-%m-%dT%H:%M:%SZ")
    p = IndrexPeer(
        pubkey="pk", nickname="", last_seen_at=None,
        last_pull_cursor=0, trust_level="known",
        next_attempt_at=future,
    )
    assert _peer_in_backoff(p) is True


def test_peer_in_backoff_false_when_past():
    past = (datetime.now(timezone.utc) - timedelta(seconds=300)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
    p = IndrexPeer(
        pubkey="pk", nickname="", last_seen_at=None,
        last_pull_cursor=0, trust_level="known",
        next_attempt_at=past,
    )
    assert _peer_in_backoff(p) is False


def test_peer_in_backoff_false_on_malformed_value():
    """Defensive: garbage in the DB column must NOT lock out a peer
    forever. Treat unparseable timestamps as 'not in backoff'."""
    p = IndrexPeer(
        pubkey="pk", nickname="", last_seen_at=None,
        last_pull_cursor=0, trust_level="known",
        next_attempt_at="not-a-date",
    )
    assert _peer_in_backoff(p) is False


# ── end-to-end: pull_from_peer integrates the recording ───────────

def test_pull_records_failure_on_http_error(indrex, monkeypatch):
    monkeypatch.setattr(peer_scraper, "_http_get_json",
                        lambda url, timeout=None: None)
    upsert_peer(indrex, pubkey="pk", nickname="x")
    rows_before = list_peers(indrex)
    peer = rows_before[0]
    peer.base_url = "http://offline:1"
    pull_from_peer(indrex, peer)
    rows_after = list_peers(indrex)
    assert rows_after[0].consecutive_failures == 1
    assert rows_after[0].next_attempt_at != ""


def test_pull_records_failure_on_verify_rejection(indrex, monkeypatch):
    """Even a verify rejection (which is the producer's fault) bumps
    the consumer's backoff so we don't hammer a chronically broken
    peer every 60s."""
    bogus_bundle = {
        "schema": peer_scraper.BUNDLE_SCHEMA,
        "pubkey": "wrong_pk", "since": 0, "until": 0,
        "pages": [], "merkle_root": "",
        "sig": "AAAA",
    }
    monkeypatch.setattr(peer_scraper, "_http_get_json",
                        lambda url, timeout=None: bogus_bundle)
    upsert_peer(indrex, pubkey="pk_real", nickname="x")
    rows_before = list_peers(indrex)
    peer = rows_before[0]
    peer.base_url = "http://x:1"
    n, status = pull_from_peer(indrex, peer)
    assert "verify:" in status
    rows_after = list_peers(indrex)
    assert rows_after[0].consecutive_failures == 1


def test_tick_skips_peers_in_backoff(indrex, monkeypatch):
    """A peer with `next_attempt_at` in the future MUST NOT have
    pull_from_peer called. We assert via a counter on the stub.

    Stub auto-seed + yaml-bootstrap to no-op so a real mDNS broadcast
    on the developer's LAN can't add a fresh peer that bypasses the
    backoff filter — environment-flakiness mitigation."""
    monkeypatch.setattr(peer_scraper, "_seed_peers_from_discovery",
                        lambda db_path: 0)
    monkeypatch.setattr(peer_scraper, "_bootstrap_once_from_yaml",
                        lambda db_path: 0)
    upsert_peer(indrex, pubkey="pk", nickname="x")
    # Force backoff window in the future.
    future = (datetime.now(timezone.utc) + timedelta(minutes=10)
              ).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = sqlite3.connect(str(indrex))
    conn.execute(
        "UPDATE peers SET consecutive_failures=3, next_attempt_at=? "
        "WHERE pubkey=?", (future, "pk"),
    )
    conn.commit()
    conn.close()

    calls = {"n": 0}
    monkeypatch.setattr(peer_scraper, "pull_from_peer",
                        lambda *a, **kw: (calls.__setitem__("n", calls["n"] + 1) or (0, "ok")))
    # Stub discovery so _resolve_peer_url returns something — even
    # then the backoff filter should fire BEFORE the URL lookup.
    monkeypatch.setattr(peer_scraper, "_resolve_peer_url",
                        lambda peer: "http://stubbed:1")
    peer_scraper._tick(indrex)
    assert calls["n"] == 0
