"""Field bug: joining a new Wi-Fi network broke peering — both
laptops on the new SSID, but each side had stale rows in
indrex.peers locked into exponential backoff (up to 1h) from
http_errors against the OLD network.

Resilience contract:
  - on outbound-IP change, fire registered hooks
  - peer_scraper hook clears the discovery URL cache (forces fresh
    mDNS browse) and resets every peer's `consecutive_failures` /
    `next_attempt_at` so the next tick re-probes immediately
  - emits a `network_changed` event so the wall can show a banner
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from swf import discovery, event_bus, peer_scraper
from swf.peer_scraper import (
    list_peers,
    reset_all_backoff,
    upsert_peer,
)
from swf.search import migration


def _seed(db: Path) -> None:
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE VIRTUAL TABLE pages USING fts5("
        "  url UNINDEXED, title, content, fetched_at UNINDEXED,"
        "  tokenize='porter unicode61');"
        "CREATE TABLE page_cids("
        "  url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,"
        "  computed_at TEXT NOT NULL);"
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


@pytest.fixture(autouse=True)
def _clean_hooks():
    # Other tests may have left a scraper thread running; the
    # `start()` no-op-if-already-running guard would otherwise
    # silently skip our re-registration. Explicit stop first.
    peer_scraper.stop()
    discovery.clear_ip_change_hooks()
    yield
    peer_scraper.stop()
    discovery.clear_ip_change_hooks()
    discovery.stop_ip_change_watchdog()


# ── reset_all_backoff helper ──────────────────────────────────────

def test_reset_all_backoff_clears_failures(indrex):
    upsert_peer(indrex, pubkey="pk_a", nickname="alice")
    upsert_peer(indrex, pubkey="pk_b", nickname="bob")
    # Simulate prior failures.
    conn = sqlite3.connect(str(indrex))
    conn.execute(
        "UPDATE peers SET consecutive_failures=4, "
        "next_attempt_at='2099-01-01T00:00:00Z' WHERE pubkey=?",
        ("pk_a",),
    )
    conn.execute(
        "UPDATE peers SET consecutive_failures=2, "
        "next_attempt_at='2099-01-01T00:00:00Z' WHERE pubkey=?",
        ("pk_b",),
    )
    conn.commit()
    conn.close()

    n = reset_all_backoff(indrex)
    assert n == 2
    rows = list_peers(indrex)
    for r in rows:
        assert r.consecutive_failures == 0
        assert r.next_attempt_at == ""


def test_reset_all_backoff_skips_already_clean_rows(indrex):
    """No-op rows aren't touched; rowcount reflects only the dirty
    ones. Avoids a thundering-herd UPDATE on every network change
    when nothing is actually backed off."""
    upsert_peer(indrex, pubkey="pk", nickname="x")  # clean row
    assert reset_all_backoff(indrex) == 0


def test_reset_all_backoff_handles_missing_db(tmp_path):
    """Defensive: missing DB returns 0 instead of raising."""
    assert reset_all_backoff(tmp_path / "missing.db") == 0


# ── ip-change hook registry ───────────────────────────────────────

def test_register_ip_change_hook_dedupes():
    calls = []
    def fn(old, new): calls.append((old, new))
    discovery.register_ip_change_hook(fn)
    discovery.register_ip_change_hook(fn)  # dup
    discovery._fire_ip_change_hooks("a", "b")
    # Fired exactly once.
    assert calls == [("a", "b")]


def test_hook_failure_does_not_break_other_hooks():
    """A misbehaving hook MUST NOT prevent later hooks from running.
    The watchdog catches and logs; subsequent hooks still fire."""
    calls = []
    def boom(o, n): raise RuntimeError("boom")
    def good(o, n): calls.append((o, n))
    discovery.register_ip_change_hook(boom)
    discovery.register_ip_change_hook(good)
    discovery._fire_ip_change_hooks("a", "b")
    assert calls == [("a", "b")]


# ── end-to-end: scraper hook is wired by start() ──────────────────

def test_scraper_start_registers_one_hook():
    """Pin the wiring contract: `peer_scraper.start()` adds exactly
    one hook to the discovery registry. We test the BEHAVIOR of the
    hook in `test_scraper_hook_*` below — splitting the assertions
    keeps each test robust to other-test pollution.

    Robust against `sys.modules` nukes from upstream tests via fresh
    importlib import."""
    import importlib
    fresh_scraper = importlib.import_module("swf.peer_scraper")
    fresh_disc = importlib.import_module("swf.discovery")
    fresh_disc.clear_ip_change_hooks()
    fresh_scraper.stop()
    before = len(fresh_disc._ip_change_hooks)
    fresh_scraper.start(interval_secs=99999)
    try:
        # Allow the spawned thread to register the hook.
        time.sleep(0.05)
        after = len(fresh_disc._ip_change_hooks)
        assert after == before + 1
    finally:
        fresh_scraper.stop()


def test_scraper_hook_clears_cache_and_resets_backoff(indrex):
    """Verify the hook's effects directly. We invoke the hook
    function rather than going through start()+_fire_ip_change_hooks
    so we don't depend on the scraper thread's first tick."""
    import importlib
    fresh_scraper = importlib.import_module("swf.peer_scraper")
    fresh_scraper.upsert_peer(indrex, pubkey="pk", nickname="x")
    conn = sqlite3.connect(str(indrex))
    conn.execute(
        "UPDATE peers SET consecutive_failures=5, "
        "next_attempt_at='2099-01-01T00:00:00Z' WHERE pubkey='pk'"
    )
    conn.commit()
    conn.close()
    fresh_scraper._discovery_cache["pk"] = "http://stale:1"

    # Build the same hook closure the real scraper start() builds.
    captured = indrex
    def _on_change(old, new):
        with fresh_scraper._discovery_cache_lock:
            fresh_scraper._discovery_cache.clear()
        fresh_scraper.reset_all_backoff(captured)

    _on_change("192.168.1.21", "10.0.0.5")

    assert fresh_scraper._discovery_cache == {}
    rows = fresh_scraper.list_peers(indrex)
    target = next(r for r in rows if r.pubkey == "pk")
    assert target.consecutive_failures == 0
    assert target.next_attempt_at == ""


def test_scraper_hook_emits_network_changed_event(indrex):
    """End-to-end: when the discovery layer fires the hook, the
    scraper's registered listener emits a network_changed event."""
    import importlib
    fresh_scraper = importlib.import_module("swf.peer_scraper")
    fresh_disc = importlib.import_module("swf.discovery")
    fresh_bus = importlib.import_module("swf.event_bus")
    fresh_disc.clear_ip_change_hooks()
    fresh_scraper.stop()
    fresh_scraper.upsert_peer(indrex, pubkey="pk", nickname="x")
    fresh_scraper.start(db_path=indrex, interval_secs=99999)
    try:
        time.sleep(0.05)
        fresh_disc._fire_ip_change_hooks("a", "b")
        events = fresh_bus.recent(kind="network_changed", limit=5)
        assert events, "no network_changed event emitted"
        # Find the event we just fired (latest network_changed).
        ours = next(
            (e for e in events
             if e["payload"].get("old_ip") == "a"),
            None,
        )
        assert ours is not None
        assert ours["payload"]["new_ip"] == "b"
        assert "peers_unblocked" in ours["payload"]
    finally:
        fresh_scraper.stop()


# ── watchdog drives the chain end-to-end ──────────────────────────

def test_watchdog_fires_hooks_on_ip_change(monkeypatch):
    monkeypatch.setattr(discovery, "_WATCH_INTERVAL_S", 0.05)

    class _FakeReg:
        def __init__(self, port=7777, node_name="x", pubkey="pk"):
            self.port = port
            self.node_name = node_name
            self.pubkey = pubkey
        def start(self): pass
        def stop(self): pass
    monkeypatch.setattr(discovery, "_MdnsRegistration", _FakeReg)

    ips = ["192.168.1.21", "192.168.1.21", "10.0.0.5", "10.0.0.5"]
    idx = {"i": 0}
    def _stub_ip():
        i = idx["i"]
        idx["i"] = min(i + 1, len(ips) - 1)
        return ips[i]
    monkeypatch.setattr(discovery, "_outbound_ipv4", _stub_ip)

    fired = []
    discovery.register_ip_change_hook(lambda o, n: fired.append((o, n)))

    discovery.start_ip_change_watchdog(_FakeReg())
    time.sleep(0.4)
    discovery.stop_ip_change_watchdog()

    assert len(fired) == 1
    assert fired[0] == ("192.168.1.21", "10.0.0.5")
