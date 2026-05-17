"""Regression coverage for issue #89: the SELF_PUBLIC_EGRESS gate must
respect the client's `confirm_public_egress` flag whenever the active
policy isn't a hard DENY.

Before #89, the gate only fired for `mode=confirm`. That meant the
built-in `default` policy (`mode=allow`) silently overrode an unchecked
visualizer toggle: the query reached the public web even when the
client said `confirm_public_egress=false`. The router now treats the
client flag as authoritative for non-DENY policies.

The five tests below pin the new contract:

  a. `default` (mode=allow) + `confirm_public_egress=False`
     → `confirmation_required`, no urlopen call.
  b. `default` (mode=allow) + `confirm_public_egress=True`
     → egress proceeds, urlopen is called, status=ok.
  c. `mode=deny` (`local_only`/`private_circle`)
     → SELF_PUBLIC_EGRESS never runs, regardless of client flag.
  d. `dev_placeholder_friends` (mode=confirm) + `confirm=False`
     → `confirmation_required` (preserves existing behavior).
  e. `dev_placeholder_friends` (mode=confirm) + `confirm=True`
     → egress proceeds (preserves existing behavior).
"""
from __future__ import annotations

import json as _json
import sqlite3
from pathlib import Path

import pytest

from swf.search import (
    DeliveryPath,
    Status,
    public_egress,
    web_search,
)

# ─── shared fixtures ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch):
    """Per-test indrex/cache/secret isolation. Mirrors the convention in
    `tests/search/test_router.py`: never touches real `~/world_knowledge`
    or `~/.local/share/swf` directories."""
    wk = tmp_path / "world_knowledge"
    wk.mkdir(parents=True)
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(wk))
    monkeypatch.setenv("SWF_CACHE_DB", str(tmp_path / "search_cache.db"))
    monkeypatch.setenv("SWF_CACHE_SECRET_FILE", str(tmp_path / "secret.bin"))
    monkeypatch.setenv("SWF_QUERY_HMAC_SECRET", "x" * 32)
    yield


def _seed_empty_indrex():
    """Build an empty FTS5 indrex DB. The router's LOCAL_INDREX route is
    enabled but the queries below never match — forcing the walk past
    LOCAL_CACHE / LOCAL_INDREX into the SELF_PUBLIC_EGRESS gate."""
    import os

    db = Path(os.environ["RA_WORLD_KNOWLEDGE_DIR"]) / "index.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE VIRTUAL TABLE pages USING fts5("
        "url UNINDEXED, title, content, fetched_at UNINDEXED, "
        "tokenize='porter unicode61')"
    )
    conn.execute(
        "CREATE TABLE page_cids (url TEXT PRIMARY KEY, "
        "content_cid TEXT NOT NULL, computed_at TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *_):
        return self._body


def _ok_payload() -> bytes:
    """Synthetic SearXNG payload — three rows, distinct hosts so §14
    sufficiency (`min_unique_hosts=2`) is satisfied."""
    return _json.dumps({
        "results": [
            {"url": f"https://host{i}.example/{i}", "title": f"T{i}",
             "content": "snippet", "score": 0.7,
             "engines": ["duckduckgo"]}
            for i in range(3)
        ]
    }).encode("utf-8")


# ─── (a) default policy (mode=allow) — gate must fire on confirm=False
#
# This is the bug from #89. Before the fix, the request silently
# egressed; now it must return `confirmation_required` and never call
# urlopen.

def test_default_policy_blocks_egress_when_confirm_false(monkeypatch):
    _seed_empty_indrex()
    blocked = {"called": False}

    def _urlopen(req, timeout=None):
        blocked["called"] = True
        raise AssertionError(
            "urlopen must NOT be called when confirm_public_egress=False "
            "under default policy (issue #89)"
        )
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _urlopen)

    resp = web_search("xyz unknown topic", policy_name="default",
                      confirm_public_egress=False)

    assert resp.status == Status.CONFIRMATION_REQUIRED
    assert resp.delivery_path == DeliveryPath.NO_RESULT
    assert resp.public_egress_used_this_request is False
    assert blocked["called"] is False
    # The SELF_PUBLIC_EGRESS handler never ran, so it must not be in
    # attempts. Fallback reason names the gate.
    paths_in_attempts = {a.path for a in resp.attempts}
    assert DeliveryPath.SELF_PUBLIC_EGRESS not in paths_in_attempts
    assert resp.fallback_reason == "public_egress_requires_confirmation"


# ─── (b) default policy (mode=allow) — egress proceeds when client confirms

def test_default_policy_proceeds_when_confirm_true(monkeypatch):
    _seed_empty_indrex()
    calls = {"n": 0}

    def _urlopen(req, timeout=None):
        calls["n"] += 1
        return _FakeResp(_ok_payload())
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _urlopen)

    resp = web_search("xyz unknown topic", policy_name="default",
                      confirm_public_egress=True)

    assert resp.status == Status.OK
    assert resp.delivery_path == DeliveryPath.SELF_PUBLIC_EGRESS
    assert resp.public_egress_used_this_request is True
    assert calls["n"] >= 1


# ─── (c) hard DENY policies — the route is filtered out before the gate

@pytest.mark.parametrize("policy_name", ["local_only", "private_circle"])
@pytest.mark.parametrize("confirm", [False, True])
def test_deny_policy_never_egresses_regardless_of_confirm(
    monkeypatch, policy_name, confirm
):
    """`local_only` and `private_circle` set `public_egress.mode=deny`
    (and don't list SELF_PUBLIC_EGRESS in `route_order`), so the route
    never runs. The client `confirm_public_egress` value must not be
    able to override that."""
    _seed_empty_indrex()

    def _urlopen(req, timeout=None):
        raise AssertionError(
            f"urlopen must NEVER be called under {policy_name} (mode=deny)"
        )
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _urlopen)

    resp = web_search("xyz unknown topic", policy_name=policy_name,
                      confirm_public_egress=confirm)

    assert resp.public_egress_used_this_request is False
    paths_in_attempts = {a.path for a in resp.attempts}
    assert DeliveryPath.SELF_PUBLIC_EGRESS not in paths_in_attempts


# ─── (d) confirm-mode policy + confirm=False — preserved existing behavior

def test_confirm_mode_blocks_when_confirm_false(monkeypatch):
    """`dev_placeholder_friends` has `public_egress.mode=confirm`. The
    pre-#89 behavior under this policy is preserved: gate fires, no
    urlopen call. Distinct from (a) only in policy mode — this test
    proves we didn't regress the confirm path while fixing allow."""
    from swf.search import lan_friend_direct
    monkeypatch.setattr(lan_friend_direct, "_peer_urls", lambda: [])

    blocked = {"called": False}
    def _urlopen(req, timeout=None):
        blocked["called"] = True
        raise AssertionError("must not reach urlopen without confirmation")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _urlopen)

    resp = web_search("xyz", policy_name="dev_placeholder_friends",
                      confirm_public_egress=False)
    assert resp.status == Status.CONFIRMATION_REQUIRED
    assert resp.debug["proposed_path"] == "SELF_PUBLIC_EGRESS"
    assert blocked["called"] is False


# ─── (e) confirm-mode policy + confirm=True — preserved existing behavior

def test_confirm_mode_proceeds_when_confirm_true(monkeypatch):
    from swf.search import lan_friend_direct
    monkeypatch.setattr(lan_friend_direct, "_peer_urls", lambda: [])

    calls = {"n": 0}
    def _urlopen(req, timeout=None):
        calls["n"] += 1
        return _FakeResp(_ok_payload())
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _urlopen)

    resp = web_search("xyz", policy_name="dev_placeholder_friends",
                      confirm_public_egress=True)
    assert resp.status == Status.OK
    assert resp.delivery_path == DeliveryPath.SELF_PUBLIC_EGRESS
    assert calls["n"] >= 1
