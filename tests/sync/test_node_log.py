"""Tests for the unified node event log + `/node/log` endpoint
(docs/SYNC.md §13).

The v0.12.0 generalization layers a `category` field over every
event in the ring and surfaces them over `/node/log`. `/sync/log`
stays as a back-compat alias filtered to `category="sync"`.

These tests cover:

  * `category` filter narrows results.
  * New event kinds are emitted and queryable through `/node/log`.
  * `/sync/log` still returns ONLY `category=sync` events, even when
    other categories are present in the ring.
  * `emit_sync_event` alias tags emitted events with
    `category="sync"`.
  * `emit_node_event` accepts an explicit `category`.
  * Ring-buffer failures inside emit sites don't crash the daemon
    (smoke-test the discovery + scraper emit wrappers).
"""
from __future__ import annotations

import json
import socket
import time
import urllib.request

import pytest

from swf.sync.event_log import (
    NODE_EVENT_CATEGORIES,
    emit_node_event,
    emit_sync_event,
    get_node_events,
    get_sync_events,
    reset_event_log_for_tests,
    tail_seq,
)


@pytest.fixture(autouse=True)
def _clear_ring():
    """Each test gets a fresh ring + seq counter."""
    reset_event_log_for_tests()
    yield
    reset_event_log_for_tests()


# ── category-field semantics ─────────────────────────────────────────


def test_emit_node_event_tags_category():
    emit_node_event("mdns_peer_appeared", category="mdns",
                    peer_pubkey="pk", peer_name="kettle",
                    peer_url="http://10.0.0.42:6651",
                    txt_record_summary="node=kettle")
    [evt] = get_node_events()
    assert evt["category"] == "mdns"
    assert evt["kind"] == "mdns_peer_appeared"
    assert evt["peer_pubkey"] == "pk"


def test_emit_sync_event_alias_tags_sync_category():
    """The back-compat alias must auto-fill `category="sync"`."""
    emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    [evt] = get_node_events()
    assert evt["category"] == "sync"
    assert evt["kind"] == "tick"


def test_payload_cannot_overwrite_category():
    """Reserved fields (including the new `category`) cannot be
    clobbered by **payload kwargs — the emit-time merge skips them.
    """
    emit_node_event("tick", category="sync", category_payload="bogus")
    [evt] = get_node_events()
    assert evt["category"] == "sync"
    # `category_payload` is allowed (it's not a reserved key); only
    # `category` itself is protected.
    assert evt["category_payload"] == "bogus"


def test_node_event_categories_constant_advertises_all_six():
    """Spec §13.2 enumerates six categories; the constant exposes
    them so the renderer + endpoint share a source of truth."""
    assert frozenset({
        "sync", "mdns", "health", "ingest", "search", "error",
    }) == NODE_EVENT_CATEGORIES


# ── category-filter at the read API ──────────────────────────────────


def test_get_node_events_categories_filter_narrows():
    emit_node_event("tick", category="sync")
    emit_node_event("mdns_peer_appeared", category="mdns",
                    peer_pubkey="pk")
    emit_node_event("peer_unreachable", category="health",
                    peer_pubkey="pk", peer_url="x", reason="timeout")
    emit_node_event("scraper_pulled", category="ingest",
                    payload={"peer_pubkey": "pk", "peer_url": "x",
                             "count": 3, "kind": "pages"})

    only_sync = get_node_events(categories=frozenset({"sync"}))
    assert [e["kind"] for e in only_sync] == ["tick"]

    sync_and_mdns = get_node_events(categories=frozenset({"sync", "mdns"}))
    assert {e["category"] for e in sync_and_mdns} == {"sync", "mdns"}

    unfiltered = get_node_events()
    assert len(unfiltered) == 4


def test_get_node_events_unknown_category_returns_empty():
    emit_node_event("tick", category="sync")
    out = get_node_events(categories=frozenset({"unknown-category"}))
    assert out == []


def test_get_sync_events_alias_filters_to_sync_only():
    """The back-compat reader must drop non-sync categories even when
    they're present in the ring."""
    emit_node_event("tick", category="sync")
    emit_node_event("mdns_peer_appeared", category="mdns",
                    peer_pubkey="pk")
    emit_node_event("scraper_pulled", category="ingest",
                    payload={"peer_pubkey": "pk", "peer_url": "x",
                             "count": 1, "kind": "pages"})

    syncs = get_sync_events()
    assert {e["category"] for e in syncs} == {"sync"}
    assert [e["kind"] for e in syncs] == ["tick"]


# ── ring failures must not break emit sites ──────────────────────────


def test_emit_sites_swallow_ring_failures():
    """Each emit wrapper (scraper, mDNS, bundle puller, web-search
    handler) wraps the ring call in try/except. Simulate a failing
    ring by monkeypatching `emit_node_event` to raise, then exercise
    one wrapper of each kind — none should propagate."""
    from swf import peer_scraper
    from swf.sync import event_log as _ev

    real = _ev.emit_node_event

    def _explode(*a, **kw):  # noqa: ANN001,ANN002,ANN003
        raise RuntimeError("ring is on fire")

    _ev.emit_node_event = _explode
    try:
        # scraper wrapper: helper itself catches.
        peer_scraper._emit_node(
            "scraper_pulled", category="ingest",
            payload={"peer_pubkey": "pk", "peer_url": "x",
                     "count": 1, "kind": "pages"},
        )
        # mDNS appear: emitter swallows.
        from swf.discovery import _emit_mdns_appeared
        _emit_mdns_appeared(
            instance_name="kettle-6651._indrex._tcp.local.",
            peer_pubkey="pk",
            peer_name="kettle",
            peer_url="http://10.0.0.42:6651",
            txt={"v": "0.12.0", "proto": "p"},
        )
        # mDNS disappear: emitter swallows.
        from swf.discovery import _emit_mdns_disappeared
        _emit_mdns_disappeared(peer_pubkey="pk", peer_name="kettle")
    finally:
        _ev.emit_node_event = real


# ── mDNS dedupe semantics ────────────────────────────────────────────


def test_mdns_appear_dedupes_within_60s():
    """Repeated `_emit_mdns_appeared` for the same pubkey within the
    60s window must produce exactly one ring event. A subsequent
    `_emit_mdns_disappeared` clears the stamp so the next appear
    re-fires.
    """
    from swf.discovery import (
        _emit_mdns_appeared,
        _emit_mdns_disappeared,
        reset_mdns_dedupe_for_tests,
    )
    reset_mdns_dedupe_for_tests()

    _emit_mdns_appeared(
        instance_name="kettle-6651._indrex._tcp.local.",
        peer_pubkey="pk-alpha",
        peer_name="kettle",
        peer_url="http://10.0.0.42:6651",
        txt={"v": "0.12.0"},
    )
    # Second emit within the window: dedupe should swallow it.
    _emit_mdns_appeared(
        instance_name="kettle-6651._indrex._tcp.local.",
        peer_pubkey="pk-alpha",
        peer_name="kettle",
        peer_url="http://10.0.0.42:6651",
        txt={"v": "0.12.0"},
    )
    appears_a = [
        e for e in get_node_events()
        if e["kind"] == "mdns_peer_appeared"
    ]
    assert len(appears_a) == 1

    # Real disappear clears the stamp; the next appear re-fires.
    _emit_mdns_disappeared(peer_pubkey="pk-alpha", peer_name="kettle")
    _emit_mdns_appeared(
        instance_name="kettle-6651._indrex._tcp.local.",
        peer_pubkey="pk-alpha",
        peer_name="kettle",
        peer_url="http://10.0.0.42:6651",
        txt={"v": "0.12.0"},
    )
    appears_b = [
        e for e in get_node_events()
        if e["kind"] == "mdns_peer_appeared"
    ]
    assert len(appears_b) == 2
    reset_mdns_dedupe_for_tests()


# ── HTTP /node/log integration ───────────────────────────────────────


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_get_json(url: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _spin_node(tmp_path, monkeypatch):
    """Boot a real peer_server on a free loopback port. Returns
    `(port, server, thread)`. Mirrors the helper in
    `test_event_log.py` so the two HTTP tests stay aligned without
    importing across files."""
    from swf import peer_server

    knowledge = tmp_path / "knowledge"
    config = tmp_path / "config"
    knowledge.mkdir()
    config.mkdir()
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(knowledge))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(config))
    monkeypatch.delenv("SWF_AGENT_TOKEN", raising=False)
    from swf.web.knowledge import knowledge_root
    peer_server._DB_PATH = knowledge_root() / "index.db"
    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            _http_get_json(f"http://127.0.0.1:{port}/health", timeout=0.5)
            break
        except Exception:
            time.sleep(0.05)
    else:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
        pytest.fail("peer did not come up")
    return port, server, thread


def test_node_log_endpoint_returns_all_categories(tmp_path, monkeypatch):
    """Drop a mix of categories into the ring, GET /node/log, assert
    every category is present and the schema is the new one."""
    port, server, thread = _spin_node(tmp_path, monkeypatch)
    try:
        reset_event_log_for_tests()
        emit_node_event("tick", category="sync",
                        visited=0, pulled=0, applied=0,
                        duration_ms=0)
        emit_node_event("mdns_peer_appeared", category="mdns",
                        peer_pubkey="pk-mdns",
                        peer_name="kettle", peer_url="http://x",
                        txt_record_summary="node=kettle")
        emit_node_event("scraper_pulled", category="ingest",
                        payload={"peer_pubkey": "pk", "peer_url": "x",
                                 "count": 2, "kind": "pages"})
        emit_node_event("web_search_completed", category="search",
                        query_hash="abc", hit_count=4,
                        duration_ms=120, source="local")

        body = _http_get_json(f"http://127.0.0.1:{port}/node/log")
        assert body["schema"] == "swf.node.log.v1"
        assert "tail_seq" in body
        cats = {e["category"] for e in body["events"]}
        assert cats == {"sync", "mdns", "ingest", "search"}
        assert body["tail_seq"] >= max(e["seq"] for e in body["events"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_node_log_category_filter_narrows(tmp_path, monkeypatch):
    port, server, thread = _spin_node(tmp_path, monkeypatch)
    try:
        reset_event_log_for_tests()
        emit_node_event("tick", category="sync")
        emit_node_event("mdns_peer_appeared", category="mdns",
                        peer_pubkey="pk")
        emit_node_event("scraper_pulled", category="ingest",
                        payload={"peer_pubkey": "pk", "peer_url": "x",
                                 "count": 1, "kind": "pages"})

        body = _http_get_json(
            f"http://127.0.0.1:{port}/node/log?category=mdns,ingest",
        )
        assert body["schema"] == "swf.node.log.v1"
        cats = {e["category"] for e in body["events"]}
        assert cats == {"mdns", "ingest"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_sync_log_back_compat_filters_to_sync_only(tmp_path, monkeypatch):
    """The v0.11.3 surface stays unchanged: even when the ring has
    mDNS / ingest / search events, `/sync/log` returns only sync
    events, and the schema marker is still `swf.sync.log.v1`."""
    port, server, thread = _spin_node(tmp_path, monkeypatch)
    try:
        reset_event_log_for_tests()
        emit_node_event("tick", category="sync",
                        visited=0, pulled=0, applied=0,
                        duration_ms=0)
        emit_node_event("mdns_peer_appeared", category="mdns",
                        peer_pubkey="pk")
        emit_node_event("scraper_pulled", category="ingest",
                        payload={"peer_pubkey": "pk", "peer_url": "x",
                                 "count": 1, "kind": "pages"})
        emit_node_event("web_search_started", category="search",
                        query_hash="abc", started_at_ms=0)

        body = _http_get_json(f"http://127.0.0.1:{port}/sync/log")
        assert body["schema"] == "swf.sync.log.v1"
        cats = {e["category"] for e in body["events"]}
        assert cats == {"sync"}
        # tail_seq tracks the WHOLE ring, not the filtered slice, so a
        # client polling /sync/log can still advance its cursor past
        # non-sync events emitted between polls.
        assert body["tail_seq"] >= 4
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_node_log_unknown_category_returns_empty_events(tmp_path, monkeypatch):
    port, server, thread = _spin_node(tmp_path, monkeypatch)
    try:
        reset_event_log_for_tests()
        emit_node_event("tick", category="sync")
        body = _http_get_json(
            f"http://127.0.0.1:{port}/node/log?category=does-not-exist",
        )
        assert body["events"] == []
        # tail_seq still advances so the renderer can move its cursor.
        assert body["tail_seq"] == tail_seq()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_node_log_rejects_bad_cursors(tmp_path, monkeypatch):
    """/node/log mirrors /sync/log's input validation: negative or
    non-numeric cursors return 400; limit=0 returns 400; limit
    over the cap clamps silently."""
    port, server, thread = _spin_node(tmp_path, monkeypatch)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/node/log?since_seq=-1",
        )
        try:
            urllib.request.urlopen(req, timeout=5.0)
            pytest.fail("expected HTTPError for negative since_seq")
        except urllib.request.HTTPError as exc:
            assert exc.code == 400

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/node/log?limit=0",
        )
        try:
            urllib.request.urlopen(req, timeout=5.0)
            pytest.fail("expected HTTPError for limit=0")
        except urllib.request.HTTPError as exc:
            assert exc.code == 400

        body = _http_get_json(
            f"http://127.0.0.1:{port}/node/log?limit=99999",
        )
        assert body["schema"] == "swf.node.log.v1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
