"""Unit tests for `swf.bundles.propagation` (#93 phase 6).

The propagation module reaches into the local `peers` table (via
`peer_scraper.list_peers`) and fans envelopes out to each peer's
`/bundles` endpoint. We exercise the dispatch logic in isolation by:

  * monkey-patching `peer_scraper.list_peers` to return a fixed set
    of `IndrexPeer` rows, and
  * monkey-patching `peer_scraper._resolve_peer_url` to return a
    fixed URL per pubkey, and
  * monkey-patching `_post_bundle_to_peer` to capture POSTs without
    making real network calls.

This keeps the unit tests fast + deterministic; the wire-level POST
path is covered by the live two-peer integration test in
`tests/test_two_peer_bundle_propagation.py`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from swf import peer_scraper
from swf.bundles import propagation
from swf.peer_scraper import IndrexPeer

# ── helpers ────────────────────────────────────────────────────────────


def _peer(pubkey: str, *, trust: str = "known", nickname: str = "") -> IndrexPeer:
    return IndrexPeer(
        pubkey=pubkey,
        nickname=nickname,
        last_seen_at=None,
        last_pull_cursor=0,
        trust_level=trust,
    )


def _envelope(*, author_pubkey: str = "ed25519:author") -> dict:
    """A minimal envelope-shape dict. We never actually verify it in
    these tests — propagation just JSON-encodes and POSTs the bytes —
    so the field set just has to round-trip through `json.dumps`."""
    return {
        "magic": "swf-bundle-v1",
        "kind": "cohort.surface",
        "record_id": "alice",
        "version": 0,
        "author": {"pubkey": author_pubkey, "signed_at": "2026-05-04T12:00:00Z"},
        "encryption": None,
        "payload": "ZGF0YQ==",
        "signature": "ed25519:fake",
    }


@pytest.fixture
def patched_peers(monkeypatch):
    """Yield a callable `setup(peers, urls)` that wires the
    propagation module's view of the local peers table.

    `peers` is a list of IndrexPeer; `urls` is `{pubkey: url}`.
    Pubkeys not in `urls` resolve to `""` (the "no URL" case).
    """
    state: dict = {"peers": [], "urls": {}}

    def _list_peers(_db_path: Path):
        return list(state["peers"])

    def _resolve(peer: IndrexPeer) -> str:
        return state["urls"].get(peer.pubkey, "")

    monkeypatch.setattr(peer_scraper, "list_peers", _list_peers)
    monkeypatch.setattr(peer_scraper, "_resolve_peer_url", _resolve)

    def setup(peers: list[IndrexPeer], urls: dict[str, str]) -> None:
        state["peers"] = list(peers)
        state["urls"] = dict(urls)

    return setup


class _CapturedPosts:
    """Recorder for monkey-patched `_post_bundle_to_peer` calls.

    Behaves like a list of `(peer_url, body)` tuples for assertion
    convenience, with an extra `.set_responses(*items)` method that
    queues up status codes / error tags for the next N calls (the
    last item repeats once the queue is exhausted)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes]] = []
        self._responses: list = [201]

    def __len__(self) -> int:
        return len(self.calls)

    def __getitem__(self, idx):
        return self.calls[idx]

    def __eq__(self, other):
        return self.calls == other

    def __iter__(self):
        return iter(self.calls)

    def append(self, item) -> None:
        self.calls.append(item)

    def set_responses(self, *items) -> None:
        self._responses = list(items)

    def next_response(self):
        if self._responses:
            r = self._responses[0]
            if len(self._responses) > 1:
                self._responses.pop(0)
            return r
        return 201


@pytest.fixture
def captured_posts(monkeypatch):
    """Replace `_post_bundle_to_peer` with a recorder. Returns a
    `_CapturedPosts` that behaves like a list of `(peer_url, body)`
    tuples and exposes a `.set_responses(*items)` method to queue up
    fake responses."""
    cap = _CapturedPosts()

    def _fake_post(peer_url: str, body: bytes, *, timeout_secs: float = 5.0):
        cap.calls.append((peer_url, body))
        return cap.next_response()

    monkeypatch.setattr(propagation, "_post_bundle_to_peer", _fake_post)
    return cap


# ── tests ──────────────────────────────────────────────────────────────


def test_propagate_skips_excluded_pubkey(
    tmp_path, patched_peers, captured_posts,
):
    """A pubkey in `exclude_pubkeys` is recorded as `excluded` and not
    POSTed. This is how we prevent re-broadcasting back to the
    bundle's author (the natural origin-skip)."""
    patched_peers(
        peers=[
            _peer("ed25519:peer-a"),
            _peer("ed25519:peer-author"),
        ],
        urls={
            "ed25519:peer-a": "http://10.0.0.1:7777",
            "ed25519:peer-author": "http://10.0.0.2:7777",
        },
    )
    env = _envelope(author_pubkey="ed25519:peer-author")
    summary = propagation.propagate_bundle(
        env, db_path=tmp_path / "indrex.db",
        exclude_pubkeys={"ed25519:peer-author"},
    )
    assert summary["ed25519:peer-author"] == "excluded"
    assert summary["ed25519:peer-a"] == 201
    # Only the non-excluded peer was POSTed to.
    assert len(captured_posts) == 1
    assert captured_posts[0][0] == "http://10.0.0.1:7777"


def test_propagate_skips_banned_peers(
    tmp_path, patched_peers, captured_posts,
):
    """`trust_level == "banned"` means we won't broadcast to that peer.
    The push side is uniformly conservative regardless of the
    SWF_ENABLE_PEER_TRUST flag (the puller's opt-in)."""
    patched_peers(
        peers=[
            _peer("ed25519:good", trust="known"),
            _peer("ed25519:bad", trust="banned"),
        ],
        urls={
            "ed25519:good": "http://10.0.0.1:7777",
            "ed25519:bad": "http://10.0.0.99:7777",
        },
    )
    summary = propagation.propagate_bundle(
        _envelope(), db_path=tmp_path / "indrex.db",
    )
    assert summary["ed25519:bad"] == "banned"
    assert summary["ed25519:good"] == 201
    assert len(captured_posts) == 1
    assert captured_posts[0][0] == "http://10.0.0.1:7777"


def test_propagate_records_no_url_when_unresolved(
    tmp_path, patched_peers, captured_posts,
):
    """A peer with no resolved URL is recorded as `no_url` and NOT
    POSTed to. The POST path requires a URL to dispatch."""
    patched_peers(
        peers=[
            _peer("ed25519:has-url"),
            _peer("ed25519:no-url-peer"),
        ],
        urls={"ed25519:has-url": "http://10.0.0.1:7777"},
    )
    summary = propagation.propagate_bundle(
        _envelope(), db_path=tmp_path / "indrex.db",
    )
    assert summary["ed25519:no-url-peer"] == "no_url"
    assert summary["ed25519:has-url"] == 201
    assert len(captured_posts) == 1


def test_propagate_records_per_peer_status(
    tmp_path, patched_peers, captured_posts,
):
    """Happy path with three peers — each gets a 201 in the summary
    dict, keyed by pubkey."""
    patched_peers(
        peers=[
            _peer(f"ed25519:peer-{i}") for i in range(3)
        ],
        urls={
            f"ed25519:peer-{i}": f"http://10.0.0.{i}:7777" for i in range(3)
        },
    )
    summary = propagation.propagate_bundle(
        _envelope(), db_path=tmp_path / "indrex.db",
    )
    assert {k: v for k, v in summary.items()} == {
        "ed25519:peer-0": 201,
        "ed25519:peer-1": 201,
        "ed25519:peer-2": 201,
    }
    assert len(captured_posts) == 3


def test_propagate_handles_4xx_responses(
    tmp_path, patched_peers, captured_posts,
):
    """4xx responses (peer rejected the bundle) are recorded as their
    integer status. They are NOT retried."""
    patched_peers(
        peers=[
            _peer("ed25519:peer-bad-shape"),
            _peer("ed25519:peer-not-alch"),
            _peer("ed25519:peer-stale-version"),
            _peer("ed25519:peer-ok"),
        ],
        urls={
            "ed25519:peer-bad-shape": "http://10.0.0.1:7777",
            "ed25519:peer-not-alch": "http://10.0.0.2:7777",
            "ed25519:peer-stale-version": "http://10.0.0.3:7777",
            "ed25519:peer-ok": "http://10.0.0.4:7777",
        },
    )
    captured_posts.set_responses(400, 403, 409, 201)

    summary = propagation.propagate_bundle(
        _envelope(), db_path=tmp_path / "indrex.db",
    )
    # Order of iteration is the order returned by list_peers, which
    # we preserved. Check each tag landed in the right slot.
    assert summary["ed25519:peer-bad-shape"] == 400
    assert summary["ed25519:peer-not-alch"] == 403
    assert summary["ed25519:peer-stale-version"] == 409
    assert summary["ed25519:peer-ok"] == 201


def test_propagate_handles_connection_errors_without_raising(
    tmp_path, patched_peers, captured_posts,
):
    """Network errors land as string tags (`timeout`, `connect_failed`,
    `io_error`). The function must NEVER raise; the caller (a daemon
    thread) discards the summary anyway."""
    patched_peers(
        peers=[
            _peer("ed25519:timeout-peer"),
            _peer("ed25519:refused-peer"),
            _peer("ed25519:io-peer"),
        ],
        urls={
            "ed25519:timeout-peer": "http://10.0.0.1:7777",
            "ed25519:refused-peer": "http://10.0.0.2:7777",
            "ed25519:io-peer": "http://10.0.0.3:7777",
        },
    )
    captured_posts.set_responses("timeout", "connect_failed", "io_error")

    # No exception even if every peer fails.
    summary = propagation.propagate_bundle(
        _envelope(), db_path=tmp_path / "indrex.db",
    )
    assert summary["ed25519:timeout-peer"] == "timeout"
    assert summary["ed25519:refused-peer"] == "connect_failed"
    assert summary["ed25519:io-peer"] == "io_error"


def test_propagate_returns_empty_when_no_peers(
    tmp_path, patched_peers, captured_posts,
):
    """Empty peers table → empty summary, no POSTs. The single-node
    case (no LAN neighbors yet) MUST not raise."""
    patched_peers(peers=[], urls={})
    summary = propagation.propagate_bundle(
        _envelope(), db_path=tmp_path / "indrex.db",
    )
    assert summary == {}
    assert captured_posts == []


def test_propagate_async_runs_in_daemon_thread(
    tmp_path, patched_peers, captured_posts,
):
    """The async wrapper spawns a daemon thread. We can `.join()` to
    wait for completion in tests; production callers ignore the
    returned thread."""
    patched_peers(
        peers=[_peer("ed25519:peer-1")],
        urls={"ed25519:peer-1": "http://10.0.0.1:7777"},
    )
    t = propagation.propagate_bundle_async(
        _envelope(), db_path=tmp_path / "indrex.db",
    )
    assert t.daemon is True
    t.join(timeout=2.0)
    assert not t.is_alive()
    assert len(captured_posts) == 1


def test_post_bundle_to_peer_rejects_non_http_scheme():
    """Direct unit test of the HTTP helper's SSRF guard. Anything
    other than http:// / https:// is refused without trying to
    connect — `file://` would be a particularly bad surprise here."""
    out = propagation._post_bundle_to_peer(
        "file:///etc/passwd", b"{}", timeout_secs=0.5,
    )
    assert out == "scheme_invalid"

    out = propagation._post_bundle_to_peer(
        "ftp://example.com/", b"{}", timeout_secs=0.5,
    )
    assert out == "scheme_invalid"


def test_post_bundle_to_peer_rejects_empty_url():
    """An empty URL (e.g. peer without an mDNS resolution) is
    refused at the helper level — defense in depth: the caller also
    short-circuits but the helper must not crash on `""`."""
    assert propagation._post_bundle_to_peer("", b"{}") == "no_url"


def test_post_bundle_to_peer_caps_body_size():
    """A body over the 4 MiB cap is refused at the helper without
    even attempting the request. (Caller already filters at the
    POST boundary; this is defense-in-depth.)"""
    big = b"a" * (propagation._MAX_BUNDLE_BYTES + 1)
    assert propagation._post_bundle_to_peer(
        "http://10.0.0.1:7777", big,
    ) == "body_too_large"


def test_propagate_skips_peer_with_empty_pubkey(
    tmp_path, patched_peers, captured_posts,
):
    """A peer row with an empty pubkey shouldn't crash propagation —
    skip it silently (defense-in-depth against a malformed peers row;
    real schema CHECKs prevent this but tests should be robust)."""
    patched_peers(
        peers=[
            _peer(""),
            _peer("ed25519:peer-real"),
        ],
        urls={"ed25519:peer-real": "http://10.0.0.1:7777"},
    )
    summary = propagation.propagate_bundle(
        _envelope(), db_path=tmp_path / "indrex.db",
    )
    # The empty-pubkey row is silently skipped (no entry in summary).
    assert "" not in summary
    assert summary["ed25519:peer-real"] == 201


def test_propagate_resolves_peer_url_via_discovery_then_base_url(
    tmp_path, patched_peers, captured_posts, monkeypatch,
):
    """When discovery returns nothing for a peer, we fall back to the
    `IndrexPeer.base_url` field. This is how the test harness can
    inject explicit URLs without seeding the discovery cache (the
    same data flow the scraper uses when populating `base_url` from
    the discovery cache before calling `pull_from_peer`)."""
    patched_peers(peers=[], urls={})
    # Override list_peers to provide a peer with base_url already set.
    peer_with_url = IndrexPeer(
        pubkey="ed25519:fallback",
        nickname="",
        last_seen_at=None,
        last_pull_cursor=0,
        trust_level="known",
        base_url="http://10.0.0.5:7777",
    )
    monkeypatch.setattr(peer_scraper, "list_peers", lambda _p: [peer_with_url])
    summary = propagation.propagate_bundle(
        _envelope(), db_path=tmp_path / "indrex.db",
    )
    assert summary["ed25519:fallback"] == 201
    assert captured_posts[0][0] == "http://10.0.0.5:7777"
