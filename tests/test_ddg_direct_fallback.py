"""SearXNG-not-running fallback: with `SWF_ALLOW_DIRECT_ENGINES=1`,
public_egress falls back to the `ddgs` Python library directly so
operators without Docker can still search the open web from the
wall UI."""
from __future__ import annotations

import urllib.error

import pytest

from swf.search import public_egress
from swf.search.query import build_context
from swf.search.response import DeliveryPath


def _ctx():
    return build_context("test query", policy_name="default",
                         hmac_secret=b"x" * 32)


def _searxng_unreachable(req, timeout=None):
    raise urllib.error.URLError("[Errno 61] Connection refused")


# ── flag defaults to OFF ──────────────────────────────────────────

def test_flag_default_off(monkeypatch):
    monkeypatch.delenv("SWF_ALLOW_DIRECT_ENGINES", raising=False)
    assert public_egress._direct_engines_enabled() is False


def test_flag_accepts_truthy(monkeypatch):
    for v in ("1", "true", "TRUE", "yes", "ON"):
        monkeypatch.setenv("SWF_ALLOW_DIRECT_ENGINES", v)
        assert public_egress._direct_engines_enabled() is True


def test_flag_rejects_falsy(monkeypatch):
    for v in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("SWF_ALLOW_DIRECT_ENGINES", v)
        assert public_egress._direct_engines_enabled() is False


# ── without the flag, searxng_unreachable is still an error ──────

def test_searxng_unreachable_without_flag_returns_error(monkeypatch):
    monkeypatch.delenv("SWF_ALLOW_DIRECT_ENGINES", raising=False)
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        _searxng_unreachable)
    out = public_egress.search(_ctx())
    assert out.attempt.status == "error"
    assert out.attempt.reason == "searxng_unreachable"
    assert out.results == []


# ── with the flag + ddgs available, fallback runs ────────────────

def test_searxng_unreachable_with_flag_falls_back_to_ddg(monkeypatch):
    monkeypatch.setenv("SWF_ALLOW_DIRECT_ENGINES", "1")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        _searxng_unreachable)

    # Stub the DDGS class to return canned hits.
    class _FakeDDGS:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def text(self, query, max_results=10):
            return [
                {"href": "https://a.example/1", "title": "A",
                 "body": "snippet a"},
                {"href": "https://b.example/2", "title": "B",
                 "body": "snippet b"},
            ]
    import ddgs
    monkeypatch.setattr(ddgs, "DDGS", _FakeDDGS)

    out = public_egress.search(_ctx())
    assert out.attempt.status == "ok"
    assert out.attempt.results_count == 2
    assert {r.canonical_url for r in out.results} == {
        "https://a.example/1", "https://b.example/2",
    }
    # Source label flags the fallback.
    assert all(r.source == "ddgs_direct" for r in out.results)
    # extras records the fallback for the wall to surface.
    assert out.extras["egress"]["adapter"] == "ddgs_direct"
    assert out.extras["egress"]["fallback_reason"] == "searxng_unreachable"
    # Privacy-level is still PUBLIC_FROM_SELF (same egress class).
    assert out.privacy_level.value == "public_from_self"
    # Warning makes the privacy-loss explicit to consumers.
    assert any("SWF_ALLOW_DIRECT_ENGINES" in w for w in out.warnings)


def test_fallback_handles_ddgs_import_error(monkeypatch):
    """If `ddgs` is missing for some reason, fail cleanly with a
    structured reason — never raise."""
    monkeypatch.setenv("SWF_ALLOW_DIRECT_ENGINES", "1")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        _searxng_unreachable)
    import sys
    monkeypatch.setitem(sys.modules, "ddgs", None)
    out = public_egress.search(_ctx())
    assert out.attempt.status == "error"
    assert "ddg_direct_unavailable" in out.attempt.reason


def test_fallback_handles_ddgs_runtime_error(monkeypatch):
    monkeypatch.setenv("SWF_ALLOW_DIRECT_ENGINES", "1")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        _searxng_unreachable)

    class _BoomDDGS:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def text(self, query, max_results=10):
            raise RuntimeError("ratelimited")
    import ddgs
    monkeypatch.setattr(ddgs, "DDGS", _BoomDDGS)

    out = public_egress.search(_ctx())
    assert out.attempt.status == "error"
    assert "ddg_direct_error" in out.attempt.reason


# ── flag does NOT bypass SearXNG when SearXNG IS reachable ───────

def test_flag_only_kicks_in_on_searxng_unreachable(monkeypatch):
    """If SearXNG is up, the flag is irrelevant — we use SearXNG.
    The fallback only fires on connection-refused."""
    monkeypatch.setenv("SWF_ALLOW_DIRECT_ENGINES", "1")
    import json as _json

    class _Resp:
        status = 200
        def __init__(self, body): self._b = body
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None): return self._b

    body = _json.dumps({"results": [
        {"url": "https://from-searxng/x", "title": "T",
         "content": "c", "engines": ["duckduckgo"]},
    ]}).encode("utf-8")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _Resp(body))

    out = public_egress.search(_ctx())
    assert out.attempt.status == "ok"
    # Adapter says searxng, NOT ddgs_direct.
    assert out.extras["egress"]["adapter"] == "searxng"
    assert all(r.source != "ddgs_direct" for r in out.results)
