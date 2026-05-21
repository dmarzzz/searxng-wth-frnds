"""Phase 2 SELF_PUBLIC_EGRESS tests.

The handler is responsible for two things:
  1. Translating a SearXNG JSON response into normalized SearchResults.
  2. Mapping every failure mode to an honest attempt status with the
     right `suspicious_failure` flag (timeout / 5xx / parse error are
     suspicious; connection-refused / 4xx are not).

We don't run a real SearXNG. urllib.request.urlopen is monkeypatched
to return synthetic responses.
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

from swf.search import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    build_context,
    public_egress,
)
from swf.search.public_egress import search


def _ctx(query: str = "decentralized search"):
    return build_context(query, policy_name="default", hmac_secret=b"x" * 32)


@pytest.fixture(autouse=True)
def _no_op_indexer(monkeypatch):
    """Default `_spawn_indexer` to a no-op so parse-only tests don't
    fire real network requests in background threads. The three
    indexing tests below override this with the inline runner.
    """
    monkeypatch.setattr(public_egress, "_spawn_indexer", lambda urls, titles: None)


class _FakeResp:
    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *_):
        return self._body


def _make_searxng_payload(rows):
    return json.dumps({
        "query": "decentralized search",
        "results": rows,
    }).encode("utf-8")


# ─── happy path ────────────────────────────────────────────────────────

def test_search_parses_searxng_results(monkeypatch):
    rows = [
        {"url": "https://duckduckgo.com/article-a",
         "title": "Decentralized search architectures",
         "content": "summary of architectures…",
         "score": 0.91, "engines": ["duckduckgo"]},
        {"url": "https://example.com/b",
         "title": "DC-net intro", "content": "snippet…",
         "score": 0.74, "engines": ["brave"]},
    ]
    body = _make_searxng_payload(rows)
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    out = search(_ctx())
    assert out.attempt.path == DeliveryPath.SELF_PUBLIC_EGRESS
    assert out.attempt.status == "ok"
    assert out.attempt.network_used is True
    assert out.attempt.public_egress_used is True
    assert out.privacy_level == PrivacyLevel.PUBLIC_FROM_SELF
    assert len(out.results) == 2
    assert out.results[0].canonical_url == "https://duckduckgo.com/article-a"
    assert out.results[0].origin_path == OriginPath.SELF_PUBLIC_EGRESS
    assert out.results[0].score == 0.91
    assert out.warnings  # public-egress warning is mandatory
    assert out.extras["egress"]["adapter"] == "searxng"
    assert "duckduckgo" in out.extras["egress"]["engines_returned"]


def test_score_clamped_to_one(monkeypatch):
    rows = [{"url": "https://x.example/1", "title": "T", "content": "c",
             "score": 5.0, "engines": ["duckduckgo"]}]
    body = _make_searxng_payload(rows)
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    out = search(_ctx())
    assert out.results[0].score == 1.0


def test_top_k_caps_results(monkeypatch):
    rows = [{"url": f"https://x.example/{i}", "title": f"T{i}",
             "content": "c", "score": 0.5} for i in range(20)]
    body = _make_searxng_payload(rows)
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    ctx = _ctx()
    out = search(ctx, top_k=5)
    assert len(out.results) == 5


# ─── failure-mode mapping ──────────────────────────────────────────────

def test_connection_refused_is_not_suspicious(monkeypatch):
    """SearXNG not running is the operator state, not an attack."""
    err = urllib.error.URLError("[Errno 61] Connection refused")
    def _raise(req, timeout=None):
        raise err
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _raise)
    out = search(_ctx())
    assert out.attempt.status == "error"
    assert out.attempt.reason == "searxng_unreachable"
    assert out.attempt.suspicious_failure is False
    assert out.results == []


def test_timeout_is_suspicious(monkeypatch):
    def _raise(req, timeout=None):
        raise TimeoutError("upstream timed out")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _raise)
    out = search(_ctx())
    assert out.attempt.status == "timeout"
    assert out.attempt.suspicious_failure is True


def test_5xx_is_suspicious(monkeypatch):
    err = urllib.error.HTTPError("http://x", 503, "Service Unavailable",
                                  hdrs={}, fp=io.BytesIO(b""))
    def _raise(req, timeout=None):
        raise err
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _raise)
    out = search(_ctx())
    assert out.attempt.status == "error"
    assert "503" in out.attempt.reason
    assert out.attempt.suspicious_failure is True


def test_4xx_is_not_suspicious(monkeypatch):
    err = urllib.error.HTTPError("http://x", 400, "Bad Request",
                                  hdrs={}, fp=io.BytesIO(b""))
    def _raise(req, timeout=None):
        raise err
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _raise)
    out = search(_ctx())
    assert out.attempt.status == "error"
    assert out.attempt.suspicious_failure is False


def test_malformed_json_is_suspicious(monkeypatch):
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(b"not json"))
    out = search(_ctx())
    assert out.attempt.status == "error"
    assert "malformed_response" in out.attempt.reason
    assert out.attempt.suspicious_failure is True


def test_empty_results_returns_no_results_status(monkeypatch):
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(_make_searxng_payload([])))
    out = search(_ctx())
    assert out.attempt.status == "no_results"
    assert out.results == []
    # network was used even though there were 0 results
    assert out.attempt.network_used is True


# ─── search → page-index pipeline ──────────────────────────────────────
#
# Regression test for the "atlas stays empty after public-egress search"
# field bug: before the fix, search() only wrote to the FTS `search_results`
# cache. The `pages` table never grew, so atlas had no towns to plot and
# the bundle layer had nothing to share with peers. Now search() also
# fans out a daemon thread that fetches + indexes each result URL.

def test_results_are_fetched_and_indexed_into_pages(monkeypatch):
    rows = [
        {"url": "https://en.wikipedia.org/wiki/Shape_rotator",
         "title": "Shape rotator", "content": "snippet",
         "score": 0.9, "engines": ["duckduckgo"]},
        {"url": "https://example.com/post",
         "title": "Post title", "content": "snippet",
         "score": 0.8, "engines": ["brave"]},
    ]
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(_make_searxng_payload(rows)))

    # Stub the extractor so the test doesn't hit the network. Return
    # content long enough to clear the 100-char floor in _index_results_async.
    fake_text = "x" * 500
    monkeypatch.setattr(
        "swf.web.fetch._get_clean_text",
        lambda url: (fake_text, "", "test-extractor"),
    )

    # Capture index_page calls so we don't depend on a writable DB inside
    # this test. The autouse SWF-state fixture would let it work end-to-end,
    # but asserting on the call args is cleaner + faster.
    calls: list[dict] = []
    def _capture(**kwargs):
        calls.append(kwargs)
    monkeypatch.setattr("swf.web.index.index_page", _capture)

    # Run search synchronously, then exec the would-be-async indexer in
    # the foreground so the test deterministically observes index_page
    # calls (no timing-flake from waiting on the daemon thread).
    # Run the would-be-async indexer inline so the test deterministically
    # observes index_page calls without waiting on a daemon thread.
    monkeypatch.setattr(
        public_egress,
        "_spawn_indexer",
        public_egress._index_results_async,
    )

    out = search(_ctx())
    assert out.attempt.status == "ok"
    assert len(out.results) == 2

    indexed_urls = sorted(c["url"] for c in calls)
    assert indexed_urls == [
        "https://en.wikipedia.org/wiki/Shape_rotator",
        "https://example.com/post",
    ]
    # Title comes from the search-result row, not the extractor (which
    # returned "" — engines usually have cleaner titles than trafilatura).
    by_url = {c["url"]: c for c in calls}
    assert by_url["https://en.wikipedia.org/wiki/Shape_rotator"]["title"] == "Shape rotator"
    assert by_url["https://example.com/post"]["title"] == "Post title"
    # Content survived the extractor and the 100-char floor.
    assert all(len(c["content"]) >= 100 for c in calls)


def test_thin_results_are_not_indexed(monkeypatch):
    # An extractor that returns under 100 chars is treated as junk and
    # skipped — keeps SPA shells / 404 pages / cookie walls out of the
    # corpus.
    rows = [{"url": "https://thin.example/", "title": "Thin",
             "content": "snippet", "score": 0.5, "engines": ["duckduckgo"]}]
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(_make_searxng_payload(rows)))
    monkeypatch.setattr(
        "swf.web.fetch._get_clean_text",
        lambda url: ("too short", "", "test-extractor"),
    )
    calls: list[dict] = []
    monkeypatch.setattr("swf.web.index.index_page",
                        lambda **kw: calls.append(kw))
    # Run the would-be-async indexer inline so the test deterministically
    # observes index_page calls without waiting on a daemon thread.
    monkeypatch.setattr(
        public_egress,
        "_spawn_indexer",
        public_egress._index_results_async,
    )
    search(_ctx())
    assert calls == []


def test_indexing_failures_dont_break_search(monkeypatch):
    # If the extractor blows up, the search response still succeeds —
    # indexing is strictly a best-effort side-effect.
    rows = [{"url": "https://boom.example/", "title": "Boom",
             "content": "snippet", "score": 0.5, "engines": ["duckduckgo"]}]
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(_make_searxng_payload(rows)))
    def _raise(_url):
        raise RuntimeError("extractor on fire")
    monkeypatch.setattr("swf.web.fetch._get_clean_text", _raise)
    # Run the would-be-async indexer inline so the test deterministically
    # observes index_page calls without waiting on a daemon thread.
    monkeypatch.setattr(
        public_egress,
        "_spawn_indexer",
        public_egress._index_results_async,
    )
    out = search(_ctx())
    assert out.attempt.status == "ok"
    assert len(out.results) == 1
