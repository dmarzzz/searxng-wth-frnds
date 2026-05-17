"""Tests for swf.indrex, swf.fanout, and the rewritten web_search.

Proves the inversion: the swarm's search path runs fully in-process.
No SearXNG running anywhere in these tests. No docker.
"""

from __future__ import annotations

import socket

import pytest


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── swf.indrex ─────────────────────────────────────────────────────────────


class TestIndrex:
    def test_query_empty_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
        from swf.indrex import query

        # Fresh dir → no DB → empty results, not crash
        assert query("anything") == []

    def test_query_finds_seeded_page(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
        import importlib
        import sys

        for mod in list(sys.modules):
            if mod in (
                "swf.indrex",
                "swf.web.knowledge",
                "swf.web.index",
            ):
                del sys.modules[mod]

        from swf.indrex import query
        from swf.web.knowledge import world_write

        world_write(
            "https://indrex-test.example.com/page",
            "The mixnet paper describes a novel privacy primitive.",
            extractor="test",
            title="Test Page",
        )
        results = query("mixnet")
        assert len(results) >= 1
        assert any("indrex-test.example.com" in r.url for r in results)
        assert any(r.source == "page" for r in results)

    def test_urls_lists_canonical(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
        import importlib
        import sys

        for mod in list(sys.modules):
            if mod in (
                "swf.indrex",
                "swf.web.knowledge",
                "swf.web.index",
            ):
                del sys.modules[mod]

        from swf.indrex import urls
        from swf.web.knowledge import world_write

        world_write("https://a.example.com/", "content a", extractor="test", title="A")
        world_write("https://b.example.com/", "content b", extractor="test", title="B")

        all_urls = urls()
        assert "https://a.example.com/" in all_urls
        assert "https://b.example.com/" in all_urls


# ── swf.fanout with stubbed engines ────────────────────────────────────────


class TestFanoutMerging:
    def test_weighted_score_biases_toward_local(self, monkeypatch):
        """Local engine weight=4 should beat DDG weight=1 when both return
        the same URL at similar positions."""
        import swf.fanout as fo

        shared_url = "https://duel.example.com/page"

        def fake_local(q, limit):
            return [(0, {"url": shared_url, "title": "local-title",
                         "snippet": "local snippet", "source": "local:page", "when": ""})]

        def fake_ddg(q, limit):
            return [(0, {"url": shared_url, "title": "ddg-title",
                         "snippet": "short", "source": "ddg", "when": ""})]

        monkeypatch.setattr(fo, "_engine_local", fake_local)
        monkeypatch.setattr(fo, "_engine_ddg", fake_ddg)
        monkeypatch.setattr(fo, "_engine_friends", lambda q, limit: [])

        results = fo.search("anything", limit=8, include_friends=False)
        assert len(results) == 1
        r = results[0]
        # Score: 4/1 + 1/1 = 5.0
        assert r.score == pytest.approx(5.0)
        # Longer snippet preferred
        assert "local snippet" in r.snippet
        # Both sources present
        assert "local:page" in r.sources
        assert "ddg" in r.sources

    def test_unique_per_engine(self, monkeypatch):
        import swf.fanout as fo

        def fake_local(q, limit):
            return [(0, {"url": "https://x.example.com/a", "title": "A",
                         "snippet": "s", "source": "local:page", "when": ""})]

        def fake_ddg(q, limit):
            return [(0, {"url": "https://y.example.com/b", "title": "B",
                         "snippet": "s", "source": "ddg", "when": ""})]

        monkeypatch.setattr(fo, "_engine_local", fake_local)
        monkeypatch.setattr(fo, "_engine_ddg", fake_ddg)
        monkeypatch.setattr(fo, "_engine_friends", lambda q, limit: [])

        results = fo.search("q", include_friends=False)
        urls = {r.url for r in results}
        assert urls == {"https://x.example.com/a", "https://y.example.com/b"}

    def test_format_results_shows_sources(self, monkeypatch):
        import swf.fanout as fo

        monkeypatch.setattr(
            fo, "_engine_local",
            lambda q, limit: [(0, {"url": "https://x.example.com/a", "title": "A",
                                   "snippet": "s", "source": "local:page", "when": ""})],
        )
        monkeypatch.setattr(fo, "_engine_friends", lambda q, limit: [])
        monkeypatch.setattr(fo, "_engine_ddg", lambda q, limit: [])

        results = fo.search("q", include_friends=False, include_ddg=False)
        out = fo.format_results(results)
        assert "local:page" in out
        assert "https://x.example.com/a" in out


# ── web_search uses fanout, no SearXNG required ───────────────────────────


class TestWebSearchInversion:
    def test_web_search_fully_in_process(self, tmp_path, monkeypatch):
        """No SearXNG running anywhere. web_search should still work via
        fanout → local + (stubbed ddg)."""
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
        monkeypatch.setenv("RA_BYPASS_CACHE", "1")  # force fresh path

        import importlib
        import sys

        for mod in list(sys.modules):
            if mod.startswith(("swf.",)):
                del sys.modules[mod]

        # Seed local content
        from swf.web.knowledge import world_write
        world_write(
            "https://in-process-test.example.com/p",
            "in-process web_search works without searxng",
            extractor="test",
            title="In Process Test",
        )

        # Stub DDG so we don't hit the network
        import swf.fanout as fo
        monkeypatch.setattr(fo, "_engine_ddg", lambda q, limit: [])
        monkeypatch.setattr(fo, "_engine_friends", lambda q, limit: [])

        from swf.web.providers import web_search
        out = web_search("in-process web_search works without searxng")

        assert "web_search NETWORK" in out or "LOCAL CACHE" in out
        assert "in-process-test.example.com" in out
        # Provenance tag should appear
        assert "local:" in out or "[local" in out

    def test_fresh_param_bypasses_cache(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
        import importlib
        import sys

        for mod in list(sys.modules):
            if mod.startswith(("swf.",)):
                del sys.modules[mod]

        # Populate cache via a direct write
        from swf.web.index import record_search_results
        record_search_results(
            query="cached query for fresh test",
            results=[
                {"url": f"https://cached{i}.example.com/", "title": f"Cached {i}",
                 "snippet": "cached snippet"}
                for i in range(5)
            ],
            engines="test",
        )

        # Stub network
        import swf.fanout as fo
        net_called = {"count": 0}

        def fake_search(*a, **kw):
            net_called["count"] += 1
            from swf.fanout import MergedResult
            return [MergedResult(url="https://net.example.com/", title="net",
                                 snippet="net", score=1.0, sources=["ddg"], whens=[])]
        monkeypatch.setattr(fo, "search", fake_search)

        from swf.web.providers import web_search
        out_cached = web_search("cached query for fresh test")
        assert "LOCAL CACHE" in out_cached
        assert net_called["count"] == 0

        out_fresh = web_search("cached query for fresh test", fresh=True)
        assert "NETWORK" in out_fresh
        assert net_called["count"] == 1
