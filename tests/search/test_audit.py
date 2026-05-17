"""TODO-4 / SPEC v0.3 §24 audit emitter tests.

Pin the §24 contract: the `search_completed` event emitted by the
router carries EXACTLY the allowlisted fields and nothing else. The
logger is its own sink (propagate=False), and the router emits one
audit record per `web_search()` call regardless of which branch the
response came from.

Note: pytest's `caplog` hooks the root logger, but our audit logger
sets `propagate=False` (which is the §24 invariant we're testing). So
each test that needs to see the emitted records attaches its own
list-collecting handler via :func:`audit.add_handler`.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from swf.search import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    SearchResponse,
    Status,
    audit,
    web_search,
)

# §24's allowed fields plus the fixed "event" tag from the spec example.
_ALLOWED_KEYS: frozenset[str] = frozenset({
    "event",
    "request_id",
    "query_hmac",
    "policy",
    "delivery_path",
    "origin_paths",
    "public_egress_used",
    "duration_ms",
})


class _ListHandler(logging.Handler):
    """Collects rendered messages into a list — works with non-propagating
    loggers, which `caplog` cannot."""
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@pytest.fixture
def audit_sink():
    """Attach a list-collecting handler to the audit logger for the
    lifetime of the test, then detach it cleanly."""
    handler = _ListHandler()
    audit.add_handler(handler)
    try:
        yield handler
    finally:
        audit.AUDIT_LOGGER.removeHandler(handler)


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch):
    """Per-test indrex DB + cache DB so the router can run end-to-end
    without touching the real ~/world_knowledge or ~/.local/share/swf
    directories."""
    wk = tmp_path / "world_knowledge"
    wk.mkdir(parents=True)
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(wk))
    monkeypatch.setenv("SWF_CACHE_DB", str(tmp_path / "search_cache.db"))
    monkeypatch.setenv("SWF_CACHE_SECRET_FILE", str(tmp_path / "secret.bin"))
    monkeypatch.setenv("SWF_QUERY_HMAC_SECRET", "x" * 32)
    yield


def _make_response(**overrides) -> SearchResponse:
    """Build a minimal valid SearchResponse for emitter-only tests."""
    base = dict(
        status=Status.OK,
        request_id="req_test",
        created_ms=1_000_000,
        completed_ms=1_001_500,
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_paths=[OriginPath.LOCAL_INDREX],
        dominant_origin_path=OriginPath.LOCAL_INDREX,
        privacy_level=PrivacyLevel.LOCAL_ONLY,
        network_used_this_request=False,
        public_egress_used_this_request=False,
        friend_query_visible=False,
        policy={"requested": "default", "effective": "default",
                "routing_goal": "balanced"},
        fallbacks_tried=[],
        warnings=[],
        attempts=[],
        results=[],
        debug={"query_hmac": "hmac-sha256:abc123"},
    )
    base.update(overrides)
    return SearchResponse.make(**base)


# ─── emitted JSON shape ───────────────────────────────────────────────

def test_emit_payload_keys_match_allowlist_exactly(audit_sink):
    audit.emit(_make_response())
    assert len(audit_sink.messages) == 1
    payload = json.loads(audit_sink.messages[0])
    assert set(payload.keys()) == _ALLOWED_KEYS


def test_emit_payload_field_values(audit_sink):
    resp = _make_response(
        delivery_path=DeliveryPath.SELF_PUBLIC_EGRESS,
        origin_paths=[OriginPath.SELF_PUBLIC_EGRESS],
        dominant_origin_path=OriginPath.SELF_PUBLIC_EGRESS,
        privacy_level=PrivacyLevel.PUBLIC_FROM_SELF,
        network_used_this_request=True,
        public_egress_used_this_request=True,
    )
    audit.emit(resp)
    assert len(audit_sink.messages) == 1
    p = json.loads(audit_sink.messages[0])
    assert p["event"] == "search_completed"
    assert p["request_id"] == "req_test"
    assert p["query_hmac"] == "hmac-sha256:abc123"
    assert p["policy"] == "default"
    assert p["delivery_path"] == "SELF_PUBLIC_EGRESS"
    assert p["origin_paths"] == ["SELF_PUBLIC_EGRESS"]
    assert p["public_egress_used"] is True
    assert p["duration_ms"] == 1500


def test_emit_omits_disallowed_fields(audit_sink):
    """§24 disallowed: raw query, snippets, full friend URLs, peer IPs,
    nullifiers, local filesystem paths. Verify by absence: nothing
    outside the allowlist appears in the emitted record."""
    resp = _make_response(
        debug={
            "query_hmac": "hmac-sha256:abc123",
            "raw_query": "SHOULD NOT APPEAR",
            "peer_ip": "192.168.1.42",
            "ticket_nullifier": "null-token-shouldnt-leak",
            "receipt_nullifier": "receipt-null-shouldnt-leak",
            "local_path": "/Users/swf/.local/share/swf/cache.db",
        },
    )
    audit.emit(resp)
    payload_text = audit_sink.messages[0]
    payload = json.loads(payload_text)
    assert set(payload.keys()) == _ALLOWED_KEYS
    for forbidden in (
        "SHOULD NOT APPEAR",
        "192.168.1.42",
        "null-token-shouldnt-leak",
        "receipt-null-shouldnt-leak",
        "/Users/swf/.local/share/swf/cache.db",
        "raw_query", "peer_ip", "ticket_nullifier",
        "receipt_nullifier", "local_path",
    ):
        assert forbidden not in payload_text


def test_audit_logger_does_not_propagate():
    """§24: the audit stream is its own sink. Without an explicit
    handler attached via add_handler(), it must not surface through the
    root logger."""
    assert audit.AUDIT_LOGGER.propagate is False


def test_audit_records_do_not_reach_root_logger(caplog):
    """End-to-end propagation guard: caplog hooks root, so if anything
    surfaced there we'd see it. With propagate=False it must not."""
    with caplog.at_level(logging.DEBUG):  # whole root tree
        audit.emit(_make_response())
    audit_records = [r for r in caplog.records if r.name == "swf.search.audit"]
    assert audit_records == []


def test_add_handler_is_idempotent():
    handler = logging.NullHandler()
    audit.add_handler(handler)
    audit.add_handler(handler)
    try:
        assert audit.AUDIT_LOGGER.handlers.count(handler) == 1
    finally:
        audit.AUDIT_LOGGER.removeHandler(handler)


def test_emit_uses_custom_event_name(audit_sink):
    audit.emit(_make_response(), event="search_completed_v2")
    payload = json.loads(audit_sink.messages[0])
    assert payload["event"] == "search_completed_v2"


# ─── router wiring ────────────────────────────────────────────────────

def test_web_search_emits_exactly_one_audit_event_on_no_results(audit_sink):
    """Smoke test: a single `web_search()` call produces exactly one
    `search_completed` audit record. With no indrex seeded the router
    walks every route, returns NO_RESULTS, and emits once."""
    resp = web_search("anything", policy_name="local_only")
    assert resp.status == Status.NO_RESULTS
    assert len(audit_sink.messages) == 1
    payload = json.loads(audit_sink.messages[0])
    assert set(payload.keys()) == _ALLOWED_KEYS
    assert payload["event"] == "search_completed"
    assert payload["request_id"] == resp.request_id


def test_web_search_emits_audit_event_on_unknown_policy(audit_sink):
    resp = web_search("q", policy_name="nope_not_a_policy")
    assert resp.status == Status.ERROR
    assert len(audit_sink.messages) == 1
    payload = json.loads(audit_sink.messages[0])
    assert set(payload.keys()) == _ALLOWED_KEYS


def test_web_search_emits_audit_event_on_empty_query(audit_sink):
    resp = web_search("   ", policy_name="default")
    assert resp.status == Status.ERROR
    assert len(audit_sink.messages) == 1
    payload = json.loads(audit_sink.messages[0])
    assert payload["request_id"] == resp.request_id


def test_audit_payload_never_contains_raw_query_through_router(audit_sink):
    """End-to-end: a sensitive-looking raw query must not appear in
    the audit record, regardless of branch."""
    secret_query = "PLAINTEXT_SECRET_QUERY_TOKEN"
    web_search(secret_query, policy_name="local_only")
    assert len(audit_sink.messages) == 1
    assert secret_query not in audit_sink.messages[0]
