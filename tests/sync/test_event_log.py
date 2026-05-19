"""Tests for the sync event ring buffer + `/sync/log` endpoint
(docs/SYNC.md §12).

The ring is a small in-process tail surfaced over a read-only HTTP
endpoint so the SROS renderer can show a live "network activity" feed
and per-peer heartbeat pulses. These tests cover:

  * the ring buffer's wrap-at-maxlen behavior
  * since_seq / since_ms cursor filtering
  * limit caps on the returned slice
  * thread-safety smoke test (concurrent emit + read)
  * end-to-end integration: spin a real peer_server,
    POST /sync/local_record, GET /sync/log, assert the `applied_local`
    event surfaces in the response.
"""
from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request

import pytest

from swf.sync.event_log import (
    _RING_MAXLEN,
    emit_sync_event,
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


# ── ring buffer wrap ─────────────────────────────────────────────────


def test_ring_wraps_at_maxlen():
    """The deque should drop the oldest events once it fills."""
    # Emit one more than maxlen so the very first event falls off.
    for i in range(_RING_MAXLEN + 5):
        emit_sync_event("tick", visited=i, pulled=0, applied=0, duration_ms=0)
    events = get_sync_events(limit=_RING_MAXLEN + 50)
    assert len(events) == _RING_MAXLEN
    # The oldest 5 (seq 1..5) are dropped; the ring holds seq 6..205.
    assert events[0]["seq"] == 6
    assert events[-1]["seq"] == _RING_MAXLEN + 5


# ── since_seq cursor ─────────────────────────────────────────────────


def test_since_seq_returns_strictly_newer_events():
    for _ in range(10):
        emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    snapshot = get_sync_events()
    cursor = snapshot[4]["seq"]  # 5th event (seq=5)
    rest = get_sync_events(since_seq=cursor)
    assert len(rest) == 5
    assert all(e["seq"] > cursor for e in rest)
    # Exact: seq=6..10.
    assert [e["seq"] for e in rest] == [6, 7, 8, 9, 10]


def test_since_seq_zero_returns_everything():
    for _ in range(3):
        emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    assert len(get_sync_events(since_seq=0)) == 3


def test_since_seq_at_tail_returns_empty():
    for _ in range(3):
        emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    assert get_sync_events(since_seq=3) == []


# ── since_ms cursor ──────────────────────────────────────────────────


def test_since_ms_returns_strictly_after_threshold():
    emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    # Sleep enough that the next event's ts_ms is strictly greater.
    time.sleep(0.01)
    boundary = int(time.time() * 1000)
    time.sleep(0.01)
    emit_sync_event("tick", visited=1, pulled=0, applied=0, duration_ms=0)
    emit_sync_event("tick", visited=2, pulled=0, applied=0, duration_ms=0)
    rest = get_sync_events(since_ms=boundary)
    assert len(rest) == 2
    assert all(e["ts_ms"] > boundary for e in rest)


def test_since_seq_wins_over_since_ms_when_both_set():
    """If both cursors are passed, since_seq takes precedence."""
    for _ in range(5):
        emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    # since_ms=0 alone would return all 5; since_seq=3 cuts it to 2.
    rest = get_sync_events(since_seq=3, since_ms=0)
    assert len(rest) == 2
    assert all(e["seq"] > 3 for e in rest)


# ── limit cap ────────────────────────────────────────────────────────


def test_limit_caps_response_slice():
    for _ in range(20):
        emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    out = get_sync_events(limit=5)
    assert len(out) == 5
    # Tail slice → the newest 5.
    assert [e["seq"] for e in out] == [16, 17, 18, 19, 20]


def test_limit_zero_returns_empty():
    for _ in range(5):
        emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    assert get_sync_events(limit=0) == []


def test_limit_larger_than_ring_is_fine():
    for _ in range(3):
        emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    assert len(get_sync_events(limit=10000)) == 3


# ── tail_seq ─────────────────────────────────────────────────────────


def test_tail_seq_empty_returns_zero():
    assert tail_seq() == 0


def test_tail_seq_tracks_latest():
    for _ in range(7):
        emit_sync_event("tick", visited=0, pulled=0, applied=0, duration_ms=0)
    assert tail_seq() == 7


# ── reserved-field protection ────────────────────────────────────────


def test_payload_cannot_overwrite_reserved_fields():
    """Caller payloads with `seq`/`ts_ms` keys must NOT clobber the
    ring's reserved fields. `kind` is the positional arg, so the
    function signature itself blocks a caller from passing it in
    **payload."""
    emit_sync_event("tick", seq=999999, ts_ms=0, visited=4)
    evt = get_sync_events()[0]
    assert evt["seq"] == 1
    assert evt["kind"] == "tick"
    assert evt["ts_ms"] > 0
    assert evt["visited"] == 4


# ── thread-safety smoke test ─────────────────────────────────────────


def test_concurrent_emit_and_read_no_exceptions():
    """4 threads × 100 emits + 1 reader thread, no exceptions, all
    seqs unique and monotonic up to the ring window."""
    n_threads = 4
    per_thread = 100
    errors: list[BaseException] = []

    def emit_loop() -> None:
        try:
            for i in range(per_thread):
                emit_sync_event("tick", visited=i, pulled=0, applied=0,
                                duration_ms=0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def read_loop() -> None:
        try:
            for _ in range(50):
                _ = get_sync_events()
                time.sleep(0.0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=emit_loop) for _ in range(n_threads)]
    threads.append(threading.Thread(target=read_loop))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)
        assert not t.is_alive()

    assert not errors, f"thread errors: {errors}"

    # Seq monotonicity within the surviving window.
    events = get_sync_events(limit=_RING_MAXLEN)
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)  # all unique
    # Total emit count == n_threads * per_thread == 400. Ring caps at
    # 200, so we see exactly the last 200 seqs.
    assert tail_seq() == n_threads * per_thread


# ── HTTP /sync/log integration ───────────────────────────────────────


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_get_json(url: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_sync_log_endpoint_surfaces_applied_local(tmp_path, monkeypatch):
    """End-to-end: spin a real peer_server, POST /sync/local_record,
    GET /sync/log, assert the `applied_local` event surfaces."""
    from swf import peer_server
    from swf.sync import reset_cohort_keys_cache_for_tests

    knowledge = tmp_path / "knowledge"
    config = tmp_path / "config"
    knowledge.mkdir()
    config.mkdir()
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(knowledge))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(config))
    monkeypatch.delenv("SWF_COHORT_KEYS_FILE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SWF_AGENT_TOKEN", raising=False)
    # LAN-trust so we don't need a cohort-keys file for the POST.
    monkeypatch.setenv("SWF_TRUST_LAN_PEERS", "1")
    reset_cohort_keys_cache_for_tests()
    reset_event_log_for_tests()

    from swf.web.knowledge import knowledge_root
    peer_server._DB_PATH = knowledge_root() / "index.db"

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    try:
        # Wait for boot.
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                _http_get_json(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.05)
        else:
            pytest.fail("peer did not come up")

        # 1. POST a record.
        body = json.dumps({
            "record_id": "ringtest",
            "record_type": "person",
            "content": {"name": "Ring Tester", "geo": "Local"},
            "prev_hash": None,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/sync/local_record",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            assert resp.status == 201

        # 2. GET /sync/log.
        log = _http_get_json(f"http://127.0.0.1:{port}/sync/log")
        assert log["schema"] == "swf.sync.log.v1"
        assert "tail_seq" in log
        assert isinstance(log["events"], list)
        kinds = [e["kind"] for e in log["events"]]
        assert "applied_local" in kinds, f"got kinds: {kinds}"
        applied = [e for e in log["events"] if e["kind"] == "applied_local"][-1]
        assert applied["record_id"] == "ringtest"
        assert applied["wall_ts_ms"] > 0
        assert applied["content_hash"].startswith("sha256:")
        assert log["tail_seq"] >= applied["seq"]

        # 3. since_seq cursor: passing tail_seq should return empty.
        tail = log["tail_seq"]
        nxt = _http_get_json(
            f"http://127.0.0.1:{port}/sync/log?since_seq={tail}",
        )
        assert nxt["events"] == []
        assert nxt["tail_seq"] == tail
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_sync_log_endpoint_rejects_bad_cursors(tmp_path, monkeypatch):
    """/sync/log returns 400 on negative or non-numeric cursors."""
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
    try:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                _http_get_json(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.05)
        else:
            pytest.fail("peer did not come up")

        # Negative cursor → 400.
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/sync/log?since_seq=-1",
        )
        try:
            urllib.request.urlopen(req, timeout=5.0)
            pytest.fail("expected HTTPError for negative since_seq")
        except urllib.request.HTTPError as exc:
            assert exc.code == 400

        # Non-numeric cursor → 400.
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/sync/log?since_seq=abc",
        )
        try:
            urllib.request.urlopen(req, timeout=5.0)
            pytest.fail("expected HTTPError for non-numeric since_seq")
        except urllib.request.HTTPError as exc:
            assert exc.code == 400

        # limit=0 → 400.
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/sync/log?limit=0",
        )
        try:
            urllib.request.urlopen(req, timeout=5.0)
            pytest.fail("expected HTTPError for limit=0")
        except urllib.request.HTTPError as exc:
            assert exc.code == 400

        # limit > max → clamped silently (not a 400).
        body = _http_get_json(f"http://127.0.0.1:{port}/sync/log?limit=99999")
        assert body["schema"] == "swf.sync.log.v1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
