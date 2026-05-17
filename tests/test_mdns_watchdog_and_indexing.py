"""Field bugs from a live LAN session:

  1. UI search hit SELF_PUBLIC_EGRESS, returned results to the user,
     but nothing landed in the FTS5 `search_results` cache that
     `swf.indrex_graph` reads. The wall looked like searching did
     nothing. Fix: `public_egress.search()` now best-effort-records
     into the agent's cache after building results.

  2. mDNS kept advertising the old IP after a VPN flipped off; peers
     discovered us at the stale address and `http_error`-ed forever.
     Fix: `start_ip_change_watchdog` polls outbound IPv4 every 30s
     and re-registers on change.
"""
from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest

from swf import discovery

# ── #1 search_results cache populated from public_egress ──────────

def test_public_egress_writes_to_search_results_cache(monkeypatch, tmp_path):
    """Stub SearXNG to return two URLs; confirm the records land in
    the FTS5 search_results cache via record_search_results."""
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
    import json as _json

    from swf.search import public_egress
    from swf.search.query import build_context

    class _Resp:
        def __init__(self, body):
            self._body = body
            self.status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None): return self._body

    def _stub_urlopen(req, timeout=None):
        body = _json.dumps({"results": [
            {"url": "https://a.example/1", "title": "T1",
             "content": "snippet 1", "engines": ["duckduckgo"]},
            {"url": "https://b.example/2", "title": "T2",
             "content": "snippet 2", "engines": ["brave"]},
        ]}).encode("utf-8")
        return _Resp(body)
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        _stub_urlopen)

    ctx = build_context("test query xyz",
                        policy_name="default",
                        hmac_secret=b"x" * 32)
    out = public_egress.search(ctx)
    assert out.attempt.status == "ok"
    assert len(out.results) == 2

    # Confirm the cache row landed.
    from swf.web.index import _conn
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT url, title FROM search_results "
            "WHERE query LIKE '%test query xyz%' OR query='test query xyz'"
        ).fetchall()
    finally:
        conn.close()
    urls = sorted(r[0] for r in rows)
    assert urls == ["https://a.example/1", "https://b.example/2"]


def test_public_egress_indexing_failure_doesnt_break_search(
    monkeypatch, tmp_path,
):
    """If record_search_results raises, the search response itself
    must still come back — indexing is fire-and-forget."""
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
    import json as _json

    from swf.search import public_egress
    from swf.search.query import build_context

    class _Resp:
        def __init__(self, body):
            self._body = body
            self.status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None): return self._body

    def _stub_urlopen(req, timeout=None):
        return _Resp(_json.dumps({"results": [
            {"url": "https://a/1", "title": "T",
             "content": "", "engines": ["duckduckgo"]},
        ]}).encode("utf-8"))
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        _stub_urlopen)

    # Make the indexer blow up.
    def _boom(**kw):
        raise RuntimeError("simulated index failure")
    monkeypatch.setattr(
        "swf.web.index.record_search_results", _boom,
    )

    ctx = build_context("any q", policy_name="default",
                        hmac_secret=b"x" * 32)
    out = public_egress.search(ctx)
    # Still got results.
    assert out.attempt.status == "ok"
    assert len(out.results) == 1


def test_direct_ddg_fallback_writes_to_search_results_cache(
    monkeypatch, tmp_path,
):
    """Regression for the import bug fixed in PR #67: the direct-DDG
    fallback path (SWF_ALLOW_DIRECT_ENGINES=1, used when SearXNG is
    unreachable) used to import `record_search_results` from the
    extracted `research_agent` package, silently swallow the
    ImportError, and never index the public-egress hits. Now lives at
    `swf.web.index.record_search_results` — verify it actually fires.
    """
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
    monkeypatch.setenv("SWF_ALLOW_DIRECT_ENGINES", "1")
    # Make SearXNG unreachable (URLError with "Connection refused" in
    # the reason) so the function falls through to the direct-DDG
    # branch — see public_egress.py:257.
    import urllib.error as _ue

    from swf.search import public_egress
    from swf.search.query import build_context
    def _stub_urlopen_fail(req, timeout=None):
        raise _ue.URLError(ConnectionRefusedError("Connection refused"))
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        _stub_urlopen_fail)

    # Stub the ddgs library wherever public_egress imports it.
    class _StubDDGS:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def text(self, *a, **kw):
            return [
                {"href": "https://ddg.example/1", "title": "DDG hit 1",
                 "body": "snippet one"},
                {"href": "https://ddg.example/2", "title": "DDG hit 2",
                 "body": "snippet two"},
            ]
    import ddgs as _ddgs_mod
    monkeypatch.setattr(_ddgs_mod, "DDGS", _StubDDGS, raising=False)

    # Capture the call to record_search_results so we know the import
    # resolved and the function ran.
    captured = {}
    def _spy(**kw):
        captured.update(kw)
    monkeypatch.setattr("swf.web.index.record_search_results", _spy)

    ctx = build_context("direct ddg fallback regression",
                        policy_name="default", hmac_secret=b"x" * 32)
    out = public_egress.search(ctx)

    assert out.attempt.status == "ok"
    assert len(out.results) == 2
    # The fix: this is the assertion that would fail pre-PR-#67 because
    # the import silently raised and the indexer never fired.
    assert "query" in captured, "record_search_results was not called"
    assert captured["query"] == "direct ddg fallback regression"
    assert captured["engines"] == "ddgs_direct"
    assert len(captured["results"]) == 2


# ── #2 mDNS watchdog re-registers on IP change ────────────────────

def test_watchdog_reregisters_when_ip_changes(monkeypatch):
    """The poller is on a 30s loop; we don't actually wait. Drive it
    manually by hooking the IP-getter and the registration's
    start/stop. Verify a re-register fires when the IP flips."""
    # Use a much shorter interval so the test doesn't hang.
    monkeypatch.setattr(discovery, "_WATCH_INTERVAL_S", 0.05)

    started = []
    stopped = []

    class _FakeReg:
        def __init__(self, port=7777, node_name="x", pubkey="pk"):
            self.port = port
            self.node_name = node_name
            self.pubkey = pubkey
        def start(self):
            started.append(("start", id(self)))
        def stop(self):
            stopped.append(("stop", id(self)))

    monkeypatch.setattr(discovery, "_MdnsRegistration", _FakeReg)

    ips = ["192.168.1.21", "192.168.1.21", "10.0.0.5", "10.0.0.5"]
    idx = {"i": 0}

    def _stub_outbound():
        i = idx["i"]
        idx["i"] = min(i + 1, len(ips) - 1)
        return ips[i]
    monkeypatch.setattr(discovery, "_outbound_ipv4", _stub_outbound)

    initial = _FakeReg()
    discovery.start_ip_change_watchdog(initial)
    # Poll a few cycles — the loop is at 50ms, so 400ms is plenty.
    time.sleep(0.4)
    discovery.stop_ip_change_watchdog()

    # Exactly one re-register should have happened (when ip flipped
    # from 192.168.1.21 → 10.0.0.5). The original registration was
    # not started by the watchdog (caller did it), so `started`
    # only has the post-flip one.
    assert len(started) == 1, f"expected 1 re-start, got {started}"
    assert len(stopped) == 1


def test_watchdog_idempotent_start():
    """Calling start_ip_change_watchdog twice is a no-op."""
    discovery.stop_ip_change_watchdog()
    class _Stub:
        port = 0
        node_name = "x"
        pubkey = ""
        def stop(self): pass
    discovery.start_ip_change_watchdog(_Stub())
    t1 = discovery._watchdog_thread
    discovery.start_ip_change_watchdog(_Stub())
    t2 = discovery._watchdog_thread
    assert t1 is t2
    discovery.stop_ip_change_watchdog()


def test_watchdog_stop_joins_thread():
    """After stop, the daemon thread must exit cleanly."""
    discovery.stop_ip_change_watchdog()
    class _Stub:
        port = 0
        node_name = "x"
        pubkey = ""
        def stop(self): pass
    discovery.start_ip_change_watchdog(_Stub())
    t = discovery._watchdog_thread
    assert t is not None and t.is_alive()
    discovery.stop_ip_change_watchdog()
    assert discovery._watchdog_thread is None
    assert not t.is_alive()
