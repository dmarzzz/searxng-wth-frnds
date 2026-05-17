"""Tests for the pull-side bundle replication puller (#93 phase 6 follow-up).

The puller walks every known peer every tick, pulls bundles received
after our per-peer high-water mark, verifies + inserts, and advances
the high-water. These tests cover the unit-level pull machinery
(`pull_from_peer`) and the background-loop wiring (`start_puller`,
`_tick`). The cross-process integration test that proves an offline-
then-rejoin peer catches up via this machinery lives in
`tests/test_two_peer_bundle_propagation.py`.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from swf import bundles, peer_scraper
from swf.bundles import puller as _puller
from swf.bundles.puller import (
    _get_high_water,
    pull_from_peer,
    start_puller,
    stop_puller,
)

# ── fixtures ─────────────────────────────────────────────────────────


@dataclass
class _FakePeer:
    """Minimal stand-in for `swf.peer_scraper.IndrexPeer` — only the
    fields the puller reads."""
    pubkey: str
    nickname: str = ""
    trust_level: str = "known"
    base_url: str = ""
    # Mirrors `IndrexPeer.next_attempt_at`. The puller's `_tick` calls
    # `_peer_in_backoff(peer)` which reads this field; an empty string
    # means "not in backoff" (the safe default).
    next_attempt_at: str = ""


@pytest.fixture(autouse=True)
def _reset_caches(monkeypatch, tmp_path):
    """Wipe the puller's lazy caches between tests so each case loads
    its own alchemists / reservoir fixtures cleanly. Also forces
    SWF_KNOWLEDGE_DIR to a per-test tmp dir so the puller's
    db_path() resolves under tmp."""
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    _puller.reset_alchemists_cache_for_tests()
    _puller.reset_reservoir_cache_for_tests()
    yield
    _puller.reset_alchemists_cache_for_tests()
    _puller.reset_reservoir_cache_for_tests()


@pytest.fixture
def isolated_db(tmp_path):
    """Path to the indrex DB the puller will write to."""
    return tmp_path / "index.db"


@pytest.fixture
def alchemist_list(monkeypatch, alchemist_keypair, tmp_path):
    """Stuff a tmp `.alchemists.yml` containing the test alchemist's
    pubkey, point SWF_ALCHEMISTS_FILE at it, and return the loaded
    AlchemistList. The puller's `_load_alchemists_cached` will pick
    this up on first call."""
    p = tmp_path / "alchemists.yml"
    p.write_text(
        f"schema_version: 1\nalchemists:\n  - id: alc-0\n"
        f'    pubkey: "{alchemist_keypair.pubkey_str}"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(p))
    # Force a fresh load on next access.
    _puller.reset_alchemists_cache_for_tests()
    return p


@pytest.fixture
def fake_http(monkeypatch):
    """Replace the puller's HTTP fetcher with a programmable mock.

    Returns a controller object: assign a list of response dicts to
    `controller.responses`, and each `_http_get_json` call pops the
    next one. If the queue is empty, the mock returns the last
    response forever (useful for testing infinite-pagination caps).
    """
    @dataclass
    class _Controller:
        responses: list[dict | None]
        calls: list[str]

        def push(self, *responses: dict | None) -> None:
            self.responses.extend(responses)

        def pop(self) -> dict | None:
            if not self.responses:
                return None
            if len(self.responses) == 1:
                # Sticky last response — useful for the max_pages cap test.
                return self.responses[0]
            return self.responses.pop(0)

    controller = _Controller(responses=[], calls=[])

    def _fake(url, *, timeout=5.0):
        controller.calls.append(url)
        return controller.pop()

    monkeypatch.setattr(_puller, "_http_get_json", _fake)
    return controller


# ── helpers ──────────────────────────────────────────────────────────


def _serialize_for_wire(env: dict[str, Any]) -> dict[str, Any]:
    """Round-trip an envelope through JSON so the wire shape matches
    what an HTTP peer would return."""
    return json.loads(json.dumps(env))


def _wire_response(envelopes: list[dict], *, next_cursor: int | None) -> dict:
    """Build a `/bundles?received_since=` response body."""
    return {
        "bundles": [_serialize_for_wire(e) for e in envelopes],
        "next_received_since": next_cursor,
    }


# ── tests ────────────────────────────────────────────────────────────


def test_pull_from_peer_happy_path(
    isolated_db, alchemist_list, alchemist_keypair, make_envelope, fake_http,
):
    """Two-bundle response: both ingest, high-water advances to the
    largest rowid, count is 2."""
    e1 = make_envelope(record_id="r1", version=0)
    e2 = make_envelope(record_id="r2", version=0)
    fake_http.push(_wire_response([e1, e2], next_cursor=None))

    peer = _FakePeer(pubkey="ed25519:" + ("a" * 64))
    stored = pull_from_peer(
        isolated_db, peer, base_url="http://peer-a.local:7777",
        page_limit=100, max_pages=10,
    )
    assert stored == 2

    # Both bundles in the DB.
    conn = sqlite3.connect(str(isolated_db))
    try:
        rows = conn.execute(
            "SELECT record_id FROM bundles ORDER BY rowid"
        ).fetchall()
    finally:
        conn.close()
    assert {r[0] for r in rows} == {"r1", "r2"}


def test_pull_from_peer_paginates(
    isolated_db, alchemist_list, alchemist_keypair, make_envelope, fake_http,
):
    """Three pages of bundles: high-water advances to the final
    cursor, all bundles ingested."""
    page1 = [make_envelope(record_id=f"p1-{i}", version=0) for i in range(2)]
    page2 = [make_envelope(record_id=f"p2-{i}", version=0) for i in range(2)]
    page3 = [make_envelope(record_id=f"p3-{i}", version=0) for i in range(2)]

    # The puller decides "this is the final page" when len < page_limit.
    # With page_limit=2, every full page would loop forever; we use
    # the cursor=null signal on page 3 to terminate.
    fake_http.push(
        _wire_response(page1, next_cursor=10),
        _wire_response(page2, next_cursor=20),
        _wire_response(page3, next_cursor=None),
    )

    peer = _FakePeer(pubkey="ed25519:" + ("b" * 64))
    stored = pull_from_peer(
        isolated_db, peer, base_url="http://peer-b.local:7777",
        page_limit=2, max_pages=10,
    )
    assert stored == 6

    # High-water advanced to the largest cursor we received.
    conn = sqlite3.connect(str(isolated_db))
    try:
        assert _get_high_water(conn, peer.pubkey) == 20
    finally:
        conn.close()

    # Three HTTP calls — one per page.
    assert len(fake_http.calls) == 3


def test_pull_from_peer_respects_max_pages(
    isolated_db, alchemist_list, make_envelope, fake_http,
):
    """A peer that ships infinite pages — verify the puller stops at
    `max_pages`."""
    # The mock returns the same response forever (sticky last
    # response when the queue has exactly one entry). This simulates
    # a misbehaving peer that ships `next_received_since` advancing
    # but never null.
    counter = {"i": 0}
    page_limit = 2  # small so each page is "full" and triggers another fetch

    def _runaway(url, *, timeout=5.0):
        counter["i"] += 1
        # Generate full pages of fresh envelopes so the puller
        # doesn't early-exit on a partial page. Without this, the
        # `len(envelopes) < page_limit` short-circuit fires after
        # page 1 and `max_pages` never gets exercised.
        page = [
            make_envelope(
                record_id=f"runaway-{counter['i']}-{j}", version=0,
            )
            for j in range(page_limit)
        ]
        fake_http.calls.append(url)
        return {
            "bundles": [_serialize_for_wire(e) for e in page],
            "next_received_since": counter["i"] * 100,
        }

    import unittest.mock as _mock
    with _mock.patch.object(_puller, "_http_get_json", _runaway):
        peer = _FakePeer(pubkey="ed25519:" + ("c" * 64))
        stored = pull_from_peer(
            isolated_db, peer, base_url="http://peer-c.local:7777",
            page_limit=page_limit, max_pages=5,
        )
    # max_pages=5 caps us at 5 HTTP calls regardless of the runaway
    # cursor signalling more.
    assert counter["i"] == 5
    assert stored == 5 * page_limit


def test_pull_from_peer_skips_invalid_bundles(
    isolated_db, alchemist_list, alchemist_keypair, make_envelope, fake_http,
):
    """A response containing one good bundle and one with a bad
    signature — the good one stores, the bad one is skipped, the
    high-water still advances to the page's cursor."""
    good = make_envelope(record_id="good", version=0)
    bad = make_envelope(record_id="bad", version=0)
    # Tamper the signature so verification fails. Flip the last hex
    # char in a way that's still valid hex.
    sig = bad["signature"]
    bad["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")

    fake_http.push(_wire_response([good, bad], next_cursor=42))

    peer = _FakePeer(pubkey="ed25519:" + ("d" * 64))
    stored = pull_from_peer(
        isolated_db, peer, base_url="http://peer-d.local:7777",
    )
    assert stored == 1

    conn = sqlite3.connect(str(isolated_db))
    try:
        rows = conn.execute(
            "SELECT record_id FROM bundles"
        ).fetchall()
        assert {r[0] for r in rows} == {"good"}
        # High-water still advances despite the bad bundle.
        assert _get_high_water(conn, peer.pubkey) == 42
    finally:
        conn.close()


def test_pull_from_peer_http_error(
    isolated_db, alchemist_list, fake_http,
):
    """Peer returns 500 / unreachable — puller logs + returns 0;
    high-water unchanged."""
    fake_http.push(None)  # `_http_get_json` returns None on any error.

    peer = _FakePeer(pubkey="ed25519:" + ("e" * 64))
    stored = pull_from_peer(
        isolated_db, peer, base_url="http://peer-e.local:7777",
    )
    assert stored == 0

    conn = sqlite3.connect(str(isolated_db))
    try:
        # Never seen this peer → high-water is 0.
        assert _get_high_water(conn, peer.pubkey) == 0
    finally:
        conn.close()


def test_pull_from_peer_high_water_per_peer_isolation(
    isolated_db, alchemist_list, alchemist_keypair, make_envelope, fake_http,
):
    """Pull from peer A advances A's high-water but not B's."""
    e1 = make_envelope(record_id="alice-only", version=0)
    fake_http.push(_wire_response([e1], next_cursor=99))

    peer_a = _FakePeer(pubkey="ed25519:" + ("a" * 64))
    peer_b = _FakePeer(pubkey="ed25519:" + ("b" * 64))

    pull_from_peer(
        isolated_db, peer_a, base_url="http://peer-a.local:7777",
    )

    conn = sqlite3.connect(str(isolated_db))
    try:
        assert _get_high_water(conn, peer_a.pubkey) == 99
        assert _get_high_water(conn, peer_b.pubkey) == 0
    finally:
        conn.close()


def test_tick_skips_banned_peers(
    isolated_db, alchemist_list, monkeypatch, fake_http,
):
    """`_tick` must skip peers whose `trust_level == "banned"`."""
    banned = _FakePeer(
        pubkey="ed25519:" + ("9" * 64), trust_level="banned",
    )
    visible = _FakePeer(pubkey="ed25519:" + ("8" * 64), trust_level="known")

    # Stub peer_scraper.list_peers and _resolve_peer_url so the tick
    # walks our two fakes without touching the real DB.
    from swf import peer_scraper
    monkeypatch.setattr(peer_scraper, "list_peers", lambda _: [banned, visible])
    monkeypatch.setattr(
        peer_scraper, "_resolve_peer_url",
        lambda p: f"http://{p.pubkey[:8]}.local:7777",
    )

    # A response for the visible peer; the banned one should never
    # generate an HTTP call so we never need to enqueue one for it.
    fake_http.push(_wire_response([], next_cursor=None))

    _puller._tick(isolated_db)

    # Exactly one HTTP call, addressed to the visible peer.
    assert len(fake_http.calls) == 1
    assert visible.pubkey[:8] in fake_http.calls[0]


def test_start_puller_is_idempotent(isolated_db):
    """Calling start_puller twice while a thread is alive must not
    spawn a second thread."""
    try:
        # Long interval so the thread parks in `_stop.wait`; we never
        # actually want it to run a tick during this test.
        start_puller(db_path=isolated_db, interval_secs=3600)
        first = _puller._thread
        assert first is not None and first.is_alive()

        start_puller(db_path=isolated_db, interval_secs=3600)
        second = _puller._thread
        assert second is first  # same thread object
    finally:
        stop_puller()
        # The thread is parked in `_stop.wait(3600)`; stop_puller sets
        # the event so the wait returns immediately.
        assert _puller._thread is None


# ── per-peer exponential backoff (mirrors peer_scraper) ──────────────


def _peer_row(db_path, pubkey: str) -> dict[str, Any]:
    """Read one peer row's backoff columns, returning a dict so a test
    can assert on `consecutive_failures` and `next_attempt_at` without
    importing IndrexPeer."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT COALESCE(consecutive_failures, 0) AS cf, "
            "       COALESCE(next_attempt_at, '') AS nat "
            "FROM peers WHERE pubkey=?", (pubkey,),
        ).fetchone()
    finally:
        conn.close()
    return {"consecutive_failures": int(row["cf"]), "next_attempt_at": row["nat"]}


def test_pull_skipped_when_peer_in_backoff(
    isolated_db, alchemist_list, monkeypatch, fake_http,
):
    """A peer whose `next_attempt_at` is in the future MUST NOT have
    `_http_get_json` invoked at all — backoff filtering happens in
    `_tick` before URL resolution + HTTP cost."""
    future = (datetime.now(timezone.utc) + timedelta(minutes=10)
              ).strftime("%Y-%m-%dT%H:%M:%SZ")
    quarantined = _FakePeer(
        pubkey="ed25519:" + ("7" * 64),
        trust_level="known",
        next_attempt_at=future,
    )

    monkeypatch.setattr(peer_scraper, "list_peers", lambda _: [quarantined])
    monkeypatch.setattr(
        peer_scraper, "_resolve_peer_url",
        lambda p: f"http://{p.pubkey[:8]}.local:7777",
    )

    _puller._tick(isolated_db)

    # No HTTP traffic — the backoff filter ate the only peer in the list.
    assert fake_http.calls == []


def test_consecutive_failures_increment_on_http_error(
    isolated_db, alchemist_list, monkeypatch,
):
    """Mock the HTTP transport to fail; assert each pull bumps the
    `peers.consecutive_failures` counter by exactly one and stamps a
    future `next_attempt_at`."""
    pubkey = "ed25519:" + ("f" * 64)
    peer_scraper.upsert_peer(isolated_db, pubkey=pubkey, nickname="flaky")

    # Force every HTTP call to "fail" (the puller's _http_get_json
    # contract is: any error → return None).
    monkeypatch.setattr(_puller, "_http_get_json",
                        lambda url, timeout=5.0: None)

    peer = _FakePeer(pubkey=pubkey)
    last_next_attempt = ""
    for i in range(3):
        pull_from_peer(
            isolated_db, peer, base_url="http://flaky.local:7777",
        )
        row = _peer_row(isolated_db, pubkey)
        assert row["consecutive_failures"] == i + 1
        assert row["next_attempt_at"] != ""
        # Each retry stamps a fresh timestamp; we don't pin the value
        # but the column is non-empty after every recorded failure.
        last_next_attempt = row["next_attempt_at"]
    assert last_next_attempt != ""


def test_record_success_resets_backoff(
    isolated_db, alchemist_list, alchemist_keypair, make_envelope,
    monkeypatch, fake_http,
):
    """Start with `consecutive_failures=3` + a future `next_attempt_at`;
    a successful pull (any 200, even an empty page) clears both."""
    pubkey = "ed25519:" + ("c" * 64)
    peer_scraper.upsert_peer(isolated_db, pubkey=pubkey, nickname="recovering")

    # Manually pre-soil the backoff state.
    conn = sqlite3.connect(str(isolated_db))
    try:
        conn.execute(
            "UPDATE peers SET consecutive_failures=3, "
            "                 next_attempt_at='2099-01-01T00:00:00Z' "
            "WHERE pubkey=?", (pubkey,),
        )
        conn.commit()
    finally:
        conn.close()
    pre = _peer_row(isolated_db, pubkey)
    assert pre["consecutive_failures"] == 3
    assert pre["next_attempt_at"] == "2099-01-01T00:00:00Z"

    # Mock a successful (empty) HTTP response. The pulled-bundles count
    # is irrelevant — just channel reachability matters for backoff.
    fake_http.push(_wire_response([], next_cursor=None))

    peer = _FakePeer(pubkey=pubkey)
    pull_from_peer(
        isolated_db, peer, base_url="http://recovering.local:7777",
    )

    post = _peer_row(isolated_db, pubkey)
    assert post["consecutive_failures"] == 0
    assert post["next_attempt_at"] == ""


def test_per_bundle_verify_rejection_does_not_trip_backoff(
    isolated_db, alchemist_list, alchemist_keypair, make_envelope,
    monkeypatch, fake_http,
):
    """A 200 OK that contains a malformed bundle is a per-envelope
    concern, not a per-peer one. The peer is reachable; we skip the
    bad envelope and the channel-level counter must stay at zero."""
    pubkey = "ed25519:" + ("9" * 64)
    peer_scraper.upsert_peer(isolated_db, pubkey=pubkey, nickname="unlucky")

    # Build an envelope and corrupt its signature so the verifier
    # rejects it. Mirrors `test_pull_from_peer_skips_invalid_bundles`.
    bad = make_envelope(record_id="malformed", version=0)
    sig = bad["signature"]
    bad["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    fake_http.push(_wire_response([bad], next_cursor=None))

    peer = _FakePeer(pubkey=pubkey)
    stored = pull_from_peer(
        isolated_db, peer, base_url="http://unlucky.local:7777",
    )
    assert stored == 0  # the bad bundle was skipped

    # The peer is still reachable — backoff state must NOT be tripped.
    # In fact, `_record_pull_success` should have reset everything to
    # zero (a 200-OK is a 200-OK regardless of payload validity).
    row = _peer_row(isolated_db, pubkey)
    assert row["consecutive_failures"] == 0
    assert row["next_attempt_at"] == ""


def test_backoff_skip_count_in_heartbeat(
    isolated_db, alchemist_list, monkeypatch, capsys, fake_http,
):
    """Two peers, one in backoff and one healthy. After `_tick`, the
    heartbeat line must include `backoff=1`."""
    future = (datetime.now(timezone.utc) + timedelta(minutes=10)
              ).strftime("%Y-%m-%dT%H:%M:%SZ")
    quarantined = _FakePeer(
        pubkey="ed25519:" + ("a" * 64),
        trust_level="known",
        next_attempt_at=future,
    )
    healthy = _FakePeer(
        pubkey="ed25519:" + ("b" * 64),
        trust_level="known",
    )

    monkeypatch.setattr(
        peer_scraper, "list_peers",
        lambda _: [quarantined, healthy],
    )
    monkeypatch.setattr(
        peer_scraper, "_resolve_peer_url",
        lambda p: f"http://{p.pubkey[:8]}.local:7777",
    )
    # The healthy peer needs a row in the peers table so the
    # _record_pull_success after a 200 OK actually has a peer to
    # update — without it, the success path is a no-op (which is
    # fine, but we want full-fidelity).
    peer_scraper.upsert_peer(isolated_db, pubkey=healthy.pubkey, nickname="ok")
    fake_http.push(_wire_response([], next_cursor=None))

    _puller._tick(isolated_db)

    captured = capsys.readouterr()
    assert "[bundle-puller] tick" in captured.err
    assert "backoff=1" in captured.err
    assert "visited=1" in captured.err
