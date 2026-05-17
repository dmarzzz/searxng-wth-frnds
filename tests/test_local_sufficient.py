"""Tests for the 0.8.1 local-sufficient gate in web_search.

Verifies: when local indrex has >= RA_LOCAL_SUFFICIENT_MIN matching
results, web_search skips the network entirely (no DDG call, no friend
fan-out).
"""

from __future__ import annotations

import importlib
import sys

import pytest


def _reset_swf_modules():
    for m in list(sys.modules):
        if m.startswith("swf.") or m.startswith("swf.web."):
            del sys.modules[m]


class TestLocalSufficientGate:
    def test_sufficient_local_skips_network(self, tmp_path, monkeypatch):
        """With 5 local hits and threshold=3, network must not be called."""
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
        monkeypatch.setenv("RA_LOCAL_SUFFICIENT_MIN", "3")
        monkeypatch.setenv("RA_BYPASS_CACHE", "0")  # cache is empty anyway
        _reset_swf_modules()

        # Seed 5 pages mentioning "quantum"
        from swf.web.knowledge import world_write
        for i in range(5):
            world_write(
                f"https://example.com/q-page-{i}",
                f"A page about quantum mechanics, entry {i}.",
                extractor="test",
                title=f"Quantum Page {i}",
            )

        # Stub the network engines so any accidental call would be obvious
        import swf.fanout as fo
        ddg_calls = {"count": 0}
        friends_calls = {"count": 0}

        def spy_ddg(q, limit):
            ddg_calls["count"] += 1
            return []

        def spy_friends(q, limit):
            friends_calls["count"] += 1
            return []

        monkeypatch.setattr(fo, "_engine_ddg", spy_ddg)
        monkeypatch.setattr(fo, "_engine_friends", spy_friends)

        from swf.web.providers import web_search
        out = web_search("quantum mechanics")

        assert "LOCAL INDREX" in out, out[:300]
        assert "no network" in out
        assert ddg_calls["count"] == 0, "DDG was called despite sufficient local"
        assert friends_calls["count"] == 0, "friends were called despite sufficient local"

    def test_insufficient_local_falls_through_to_network(self, tmp_path, monkeypatch):
        """With 1 local hit and threshold=3, network should be called."""
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
        monkeypatch.setenv("RA_LOCAL_SUFFICIENT_MIN", "3")
        monkeypatch.setenv("RA_BYPASS_CACHE", "1")  # force fresh path
        _reset_swf_modules()

        from swf.web.knowledge import world_write
        world_write(
            "https://example.com/only-one",
            "Only one page mentions obscuretopic.",
            extractor="test",
            title="Obscure Topic",
        )

        import swf.fanout as fo
        ddg_calls = {"count": 0}

        def spy_ddg(q, limit):
            ddg_calls["count"] += 1
            return [
                (0, {"url": "https://example.com/ddg-result",
                     "title": "DDG hit", "snippet": "from ddg",
                     "source": "ddg", "when": ""})
            ]

        monkeypatch.setattr(fo, "_engine_ddg", spy_ddg)
        monkeypatch.setattr(fo, "_engine_friends", lambda q, limit: [])

        from swf.web.providers import web_search
        out = web_search("obscuretopic")

        assert "NETWORK" in out, out[:300]
        # DDG was called at least once (once in the sufficient-gate check
        # with include_ddg=False it's skipped, then the real fanout fires it).
        assert ddg_calls["count"] >= 1

    def test_disabled_by_zero_threshold(self, tmp_path, monkeypatch):
        """RA_LOCAL_SUFFICIENT_MIN=0 disables the gate entirely."""
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
        monkeypatch.setenv("RA_LOCAL_SUFFICIENT_MIN", "0")
        monkeypatch.setenv("RA_BYPASS_CACHE", "1")
        _reset_swf_modules()

        from swf.web.knowledge import world_write
        for i in range(10):
            world_write(
                f"https://example.com/lots-{i}",
                "plenty of content locally",
                extractor="test",
                title=f"Local {i}",
            )

        import swf.fanout as fo
        ddg_calls = {"count": 0}
        monkeypatch.setattr(
            fo, "_engine_ddg",
            lambda q, limit: (ddg_calls.__setitem__("count", ddg_calls["count"] + 1) or []),
        )
        monkeypatch.setattr(fo, "_engine_friends", lambda q, limit: [])

        from swf.web.providers import web_search
        out = web_search("plenty")
        # Gate disabled → network is called despite rich local
        assert ddg_calls["count"] >= 1
        assert "NETWORK" in out
