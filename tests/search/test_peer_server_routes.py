"""HTTP-edge tests for the SPEC v0.3 search routes on `peer_server`.

Spins up a real `_Handler` on a free localhost port and probes the
edge cases that pure-Python unit tests miss: malformed Content-Length,
HEAD/GET/OPTIONS on POST routes, oversized headers, etc. These are
what the load-test agent caught as "AttributeError on /search_feedback"
in pass-3 — putting an actual socket in the loop catches handler-level
regressions that mocks can't.
"""
from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path, monkeypatch):
    """Spin up a real swf-node `_Handler` on a free loopback port,
    isolated to tmp_path. Yields {base, port, tmp_path}."""
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "wk"))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("SWF_CACHE_DB", str(tmp_path / "cache.db"))
    monkeypatch.setenv("SWF_CACHE_SECRET_FILE", str(tmp_path / "secret.bin"))
    monkeypatch.setenv("SWF_REPUTATION_DB", str(tmp_path / "reputation.db"))
    monkeypatch.setenv("SWF_TICKETS_DB", str(tmp_path / "tickets.sqlite"))
    monkeypatch.setenv("SWF_QUERY_HMAC_SECRET", "x" * 32)

    # Don't touch sys.modules — search modules pick up env overrides
    # at call time via `db_path()` etc., and reloading swf.search
    # would invalidate any module-level references held by test files
    # that already imported it (e.g. tests/search/test_router.py).
    from swf.peer_server import _Handler
    port = _free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    yield {"base": f"http://127.0.0.1:{port}", "port": port,
           "tmp_path": tmp_path}
    srv.shutdown()
    srv.server_close()
    thr.join(timeout=3)


def _request(method: str, url: str, *, body: bytes | None = None,
             headers: dict | None = None,
             timeout: float = 3.0) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() or b""


# ─── method routing ─────────────────────────────────────────────────

def test_get_on_post_only_route_returns_404(server):
    """GET on a POST-only route → 404 (path-not-found), not 500."""
    code, _ = _request("GET", server["base"] + "/web_search")
    assert code == 404


def test_health_get_works(server):
    """GET /health is the canonical liveness probe."""
    code, body = _request("GET", server["base"] + "/health")
    assert code == 200
    assert json.loads(body)["ok"] is True


def test_unknown_path_returns_404(server):
    code, _ = _request("POST", server["base"] + "/totally_unknown_path",
                       body=b"{}",
                       headers={"Content-Type": "application/json"})
    assert code == 404


# ─── /web_search type validation ───────────────────────────────────

def test_web_search_missing_q_is_400(server):
    """Empty body `{}` → 400 because `q` validation fires; current
    handler returns 'q must be a string' (since the missing field
    type-checks to non-str). Either error string is acceptable."""
    code, body = _request("POST", server["base"] + "/web_search",
                          body=b"{}",
                          headers={"Content-Type": "application/json"})
    assert code == 400
    err = json.loads(body).get("error", "")
    assert "q" in err  # either "missing q" or "q must be a string"


def test_web_search_q_as_int_is_400_not_500(server):
    """Type-confusion regression: non-string `q` must NOT crash the
    handler (load-test pass-3 finding). Returns 400 with structured
    error."""
    code, body = _request("POST", server["base"] + "/web_search",
                          body=b'{"q":123}',
                          headers={"Content-Type": "application/json"})
    assert code == 400
    assert "q must be a string" in json.loads(body).get("error", "")


def test_web_search_top_k_as_string_is_400(server):
    code, body = _request("POST", server["base"] + "/web_search",
                          body=b'{"q":"x","top_k":"five"}',
                          headers={"Content-Type": "application/json"})
    assert code == 400


def test_web_search_top_k_as_bool_is_400(server):
    """`isinstance(True, int)` is True in Python — handler must
    explicitly reject bools so a literal `true`/`false` doesn't slip
    through as top_k=1/0."""
    code, body = _request("POST", server["base"] + "/web_search",
                          body=b'{"q":"x","top_k":true}',
                          headers={"Content-Type": "application/json"})
    assert code == 400


def test_web_search_confirm_as_string_is_400(server):
    code, body = _request("POST", server["base"] + "/web_search",
                          body=b'{"q":"x","confirm_public_egress":"yes"}',
                          headers={"Content-Type": "application/json"})
    assert code == 400


def test_web_search_oversize_body_returns_413(server):
    """TODO-5: 64 KiB body cap on search routes."""
    big = b'{"q":"' + b"A" * 70_000 + b'"}'
    code, _ = _request("POST", server["base"] + "/web_search",
                       body=big,
                       headers={"Content-Type": "application/json"})
    assert code == 413


# ─── /friend_search type validation ────────────────────────────────

def test_friend_search_q_as_int_is_400(server):
    """The pass-3 load-test caught the symmetric crash here: non-string
    `q` raised a 500 with raw traceback. Now it's a structured 400."""
    code, body = _request("POST", server["base"] + "/friend_search",
                          body=b'{"q":123}',
                          headers={"Content-Type": "application/json"})
    assert code == 400
    assert "q must be a string" in json.loads(body).get("error", "")


def test_friend_search_top_k_as_string_is_400(server):
    code, body = _request("POST", server["base"] + "/friend_search",
                          body=b'{"q":"x","top_k":"five"}',
                          headers={"Content-Type": "application/json"})
    assert code == 400


def test_friend_search_oversize_body_returns_413(server):
    big = b'{"q":"' + b"A" * 70_000 + b'"}'
    code, _ = _request("POST", server["base"] + "/friend_search",
                       body=big,
                       headers={"Content-Type": "application/json"})
    assert code == 413


# ─── /search_feedback edge cases ───────────────────────────────────

def test_search_feedback_loopback_bypass_no_token(server):
    """Loopback bind auto-allows /search_feedback without a token —
    the wall on the same machine can hit it freely."""
    code, body = _request(
        "POST", server["base"] + "/search_feedback",
        body=b'{"provider_pubkey":"ed25519:test","event":"open"}',
        headers={"Content-Type": "application/json"},
    )
    assert code == 200
    j = json.loads(body)
    assert j["new_score"] > 0.5  # bumped from default 0.5


def test_search_feedback_unknown_event_is_400(server):
    code, body = _request(
        "POST", server["base"] + "/search_feedback",
        body=b'{"provider_pubkey":"x","event":"moon_dance"}',
        headers={"Content-Type": "application/json"},
    )
    assert code == 400
    j = json.loads(body)
    assert "unknown event" in j.get("error", "")
    assert "known_events" in j


def test_search_feedback_provider_pubkey_as_int_is_400(server):
    code, body = _request(
        "POST", server["base"] + "/search_feedback",
        body=b'{"provider_pubkey":123,"event":"open"}',
        headers={"Content-Type": "application/json"},
    )
    assert code == 400


# ─── content-type / body edge ──────────────────────────────────────

def test_web_search_garbage_body_returns_400(server):
    """Malformed JSON body → 400 (missing q). The handler treats a
    parse error the same as missing-body — both reduce to {} and the
    `q` validation fires."""
    code, _ = _request("POST", server["base"] + "/web_search",
                       body=b"not valid json",
                       headers={"Content-Type": "application/json"})
    assert code == 400
