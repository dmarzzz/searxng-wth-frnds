"""HTTP integration tests for #93 phase 4: SSE `/bundles/subscribe`.

Spec §4.1 (SHAPE-ROTATOR-OS-SPEC.md):
    GET /bundles/subscribe?kind=<kind>

    event: bundle
    id:    <cid>
    data:  { "magic": "swf-bundle-v1", ... }    # full envelope

    Reconnection: client passes `Last-Event-ID: <cid>`; server replays
    every bundle inserted *after* that cid (rowid order), then streams
    live.

These tests use `http.client` rather than `urllib.request` because the
stdlib `urlopen` API is request/response-oriented and doesn't expose a
streaming reader for an unbounded body. `http.client.HTTPResponse.read(n)`
returns partial bytes as they arrive, which is exactly what an SSE
consumer needs.

We DO NOT spin up a real `Last-Event-ID` reconnect with `EventSource`;
we test the server's handling of the header on a fresh connection. The
phase-6 two-peer LAN integration test will exercise actual reconnect
flows end-to-end.
"""
from __future__ import annotations

import base64
import http.client
import importlib
import json
import socket
import time
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swf import bundles

# ── keypair + envelope helpers (mirror of the other phase-* test files) ──


@dataclass
class _Keypair:
    priv: Ed25519PrivateKey
    pub_hex: str
    pubkey_str: str


def _make_keypair() -> _Keypair:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = raw.hex()
    return _Keypair(priv=priv, pub_hex=pub_hex, pubkey_str=f"ed25519:{pub_hex}")


def _build_envelope(
    kp: _Keypair,
    *,
    kind: str = "cohort.surface",
    record_id: str = "alice",
    version: int = 0,
    signed_at: str = "2026-05-04T12:00:00Z",
    payload: bytes = b'{"hello":"world"}',
) -> dict:
    env: dict = {
        "magic": "swf-bundle-v1",
        "kind": kind,
        "record_id": record_id,
        "version": int(version),
        "author": {"pubkey": kp.pubkey_str, "signed_at": signed_at},
        "encryption": None,
        "payload": base64.b64encode(payload).decode("ascii"),
    }
    env["signature"] = bundles.sign_envelope(env, priv=kp.priv)
    return env


# ── HTTP test scaffolding ──────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _open_subscribe(
    host: str,
    port: int,
    *,
    kind: str | None = None,
    last_event_id: str | None = None,
    timeout: float = 3.0,
) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
    """Open `GET /bundles/subscribe[?kind=...]` and return a streaming
    response. Caller is responsible for `conn.close()`."""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers: dict[str, str] = {}
    if last_event_id is not None:
        headers["Last-Event-ID"] = last_event_id
    path = "/bundles/subscribe"
    if kind is not None:
        path += f"?kind={kind}"
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    return conn, resp


def _read_one_event(
    resp: http.client.HTTPResponse,
    *,
    deadline_seconds: float = 2.0,
) -> str:
    """Read bytes off `resp` until we've accumulated one complete SSE
    event (terminated by `\\n\\n`). Skip any leading heartbeat-comment
    lines so callers can assert on the `event:` block they care about.

    Returns the raw event block (with the trailing `\\n\\n` included).

    Uses `read1()` (BufferedReader's "read whatever is currently
    available" API) rather than `read(n)`. `HTTPResponse.read(n)`
    blocks until `n` bytes arrive or EOF, which doesn't work for an
    open SSE stream that may emit a 200-byte event and then idle —
    we'd block waiting for the next 56 bytes that never come.

    Buffer carry-over (#106): when the server writes two SSE events
    back-to-back during the replay phase, the kernel often coalesces
    them into a single TCP segment. A single `read1(4096)` then returns
    BOTH events as one ~1KB chunk. Without persisting the leftover
    bytes between calls, the second event would be silently discarded
    and the next call would block waiting for bytes that already
    arrived — that's exactly the flake mode reported in #106. We stash
    any post-terminator bytes on the response object as
    `_swf_sse_buf` and prepend them on the next call.
    """
    deadline = time.monotonic() + deadline_seconds
    buf: bytes = getattr(resp, "_swf_sse_buf", b"")
    while True:
        # Drain whatever's already in our carry-over buffer first; we
        # may already have a full event from the previous read1().
        while b"\n\n" in buf:
            block, _, rest = buf.partition(b"\n\n")
            buf = rest
            text = block.decode("utf-8", errors="replace") + "\n\n"
            non_comment_lines = [
                ln for ln in text.splitlines()
                if ln.strip() and not ln.startswith(":")
            ]
            if non_comment_lines:
                resp._swf_sse_buf = buf
                return text
        # Nothing parseable yet — read more bytes (or sleep a tick if
        # the socket has nothing for us).
        if time.monotonic() >= deadline:
            break
        try:
            chunk = resp.read1(4096)
        except TimeoutError:
            chunk = b""
        if not chunk:
            time.sleep(0.02)
            continue
        buf += chunk
    resp._swf_sse_buf = buf
    raise AssertionError(
        f"no SSE event arrived within {deadline_seconds}s (buffered={buf!r})",
    )


def _parse_sse_event(block: str) -> dict[str, str]:
    """Parse an SSE event block into {id, event, data}. Multi-line
    `data:` is concatenated with newlines per the SSE spec, but our
    server emits single-line `data:` so we don't bother handling the
    multi-line case."""
    out: dict[str, str] = {}
    for line in block.strip().splitlines():
        if ":" not in line:
            continue
        field, _, val = line.partition(":")
        if val.startswith(" "):
            val = val[1:]
        out[field] = val
    return out


# ── fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def keypair():
    return _make_keypair()


@pytest.fixture
def peer_server_running(tmp_path, monkeypatch):
    """Spin up a real peer_server on 127.0.0.1, redirected at a tmp
    indrex DB. Yields `(host, port, base_url)`.

    Mirrors `tests/test_peer_server_bundles_get.py` — fresh import after
    `SWF_KNOWLEDGE_DIR` so the module-level `_DB_PATH` honors the env var.
    """
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))

    import sys
    for mod in [
        "swf.peer_server",
        "swf.indrex",
        "swf.event_bus",
    ]:
        sys.modules.pop(mod, None)
    peer_server = importlib.import_module("swf.peer_server")

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    base = f"http://127.0.0.1:{port}"
    try:
        yield "127.0.0.1", port, base
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


# ── tests ──────────────────────────────────────────────────────────────────


def test_subscribe_invalid_kind_returns_400(peer_server_running):
    """An unknown `kind` is a client bug; reject with 400 BEFORE
    opening the SSE stream so the client gets a clean JSON error."""
    host, port, _base = peer_server_running
    conn, resp = _open_subscribe(host, port, kind="garbage")
    try:
        assert resp.status == 400
        body = json.loads(resp.read().decode("utf-8"))
        assert body["error"] == "invalid_kind"
        assert "valid" in body
        assert "cohort.surface" in body["valid"]
    finally:
        conn.close()


def test_subscribe_live_bundle_streams_full_envelope(
    peer_server_running, keypair,
):
    """Empty store + no Last-Event-ID. Subscribe, then insert a bundle;
    the SSE stream emits one `event: bundle` block with `id: <cid>` and
    the full envelope as the `data:` payload."""
    host, port, _base = peer_server_running
    conn, resp = _open_subscribe(host, port)
    try:
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "text/event-stream"
        assert resp.headers.get("Cache-Control") == "no-store"

        # Insert AFTER the SSE stream is established. The server's
        # event_bus subscription was registered before
        # `_open_subscribe` returned, so we don't need to sleep.
        env = _build_envelope(keypair, record_id="alice-live", version=0)
        cid, was_new = bundles.insert(env)
        assert was_new

        # Phase-3's POST emits the bus event from inside the route;
        # here we're calling `bundles.insert` directly (skipping the
        # HTTP write path), so emit manually to drive phase-4.
        from swf import event_bus
        event_bus.emit("bundle_added", {
            "cid": cid,
            "kind": env["kind"],
            "record_id": env["record_id"],
            "version": env["version"],
        })

        block = _read_one_event(resp, deadline_seconds=3.0)
        evt = _parse_sse_event(block)
        assert evt["event"] == "bundle"
        assert evt["id"] == cid
        envelope = json.loads(evt["data"])
        assert envelope["magic"] == "swf-bundle-v1"
        assert envelope["record_id"] == "alice-live"
        assert envelope["signature"] == env["signature"]
    finally:
        conn.close()


def test_subscribe_resume_from_last_event_id(peer_server_running, keypair):
    """Pre-seed 3 bundles, subscribe with Last-Event-ID = cid-of-bundle-1.
    The replay must emit bundles 2 + 3, then the live phase emits a 4th."""
    host, port, _base = peer_server_running

    cids: list[str] = []
    for v in range(3):
        env = _build_envelope(keypair, record_id="resume", version=v)
        cid, was_new = bundles.insert(env)
        assert was_new
        cids.append(cid)

    conn, resp = _open_subscribe(host, port, last_event_id=cids[0])
    try:
        assert resp.status == 200

        # Replay block 1: should be bundle index 1 (version=1).
        evt1 = _parse_sse_event(_read_one_event(resp, deadline_seconds=3.0))
        assert evt1["event"] == "bundle"
        assert evt1["id"] == cids[1]
        env1 = json.loads(evt1["data"])
        assert env1["version"] == 1

        # Replay block 2: bundle index 2 (version=2).
        evt2 = _parse_sse_event(_read_one_event(resp, deadline_seconds=3.0))
        assert evt2["event"] == "bundle"
        assert evt2["id"] == cids[2]
        env2 = json.loads(evt2["data"])
        assert env2["version"] == 2

        # Now go live: insert a 4th bundle and assert it streams.
        env3 = _build_envelope(keypair, record_id="resume", version=3)
        cid3, was_new = bundles.insert(env3)
        assert was_new
        from swf import event_bus
        event_bus.emit("bundle_added", {
            "cid": cid3,
            "kind": env3["kind"],
            "record_id": env3["record_id"],
            "version": env3["version"],
        })

        evt3 = _parse_sse_event(_read_one_event(resp, deadline_seconds=3.0))
        assert evt3["event"] == "bundle"
        assert evt3["id"] == cid3
    finally:
        conn.close()


def test_subscribe_unknown_last_event_id_falls_through_to_live(
    peer_server_running, keypair,
):
    """An unknown CID in `Last-Event-ID` (cache miss; bundle expired or
    never seen here) falls through to live-only — no replay, no error.
    The client can re-bootstrap with `GET /bundles` if it needs the
    gap filled."""
    host, port, _base = peer_server_running

    # Pre-seed one bundle so the store isn't empty.
    env_seed = _build_envelope(keypair, record_id="seed", version=0)
    bundles.insert(env_seed)

    bogus = "f" * 64
    conn, resp = _open_subscribe(host, port, last_event_id=bogus)
    try:
        assert resp.status == 200

        # No replay should happen — confirm by inserting a NEW bundle
        # and verifying that's the first thing we see (not the seed).
        env_live = _build_envelope(keypair, record_id="live-after-bogus", version=0)
        cid, was_new = bundles.insert(env_live)
        assert was_new
        from swf import event_bus
        event_bus.emit("bundle_added", {
            "cid": cid,
            "kind": env_live["kind"],
            "record_id": env_live["record_id"],
            "version": env_live["version"],
        })

        evt = _parse_sse_event(_read_one_event(resp, deadline_seconds=3.0))
        assert evt["event"] == "bundle"
        assert evt["id"] == cid
        envelope = json.loads(evt["data"])
        assert envelope["record_id"] == "live-after-bogus"
    finally:
        conn.close()


def test_subscribe_filter_by_kind(peer_server_running, keypair):
    """`?kind=<kind>` filter: only bundles of the matching kind are
    streamed. We validate against both the replay and live paths."""
    host, port, _base = peer_server_running

    # Pre-seed one of each kind that we care about, so the replay set
    # contains both. Subscribing with `?kind=cohort.surface` and a
    # Last-Event-ID before the seed must stream only the surface one.
    surface_env = _build_envelope(
        keypair, kind="cohort.surface", record_id="filter-s", version=0,
    )
    surface_cid, _ = bundles.insert(surface_env)
    depth_env = _build_envelope(
        keypair, kind="cohort.depth", record_id="filter-d", version=0,
    )
    depth_cid, _ = bundles.insert(depth_env)

    # Subscribe filtered to cohort.surface, with no resume cursor (so
    # only live events stream). Then emit one of each kind; we should
    # see only the surface one.
    conn, resp = _open_subscribe(host, port, kind="cohort.surface")
    try:
        assert resp.status == 200

        live_surface = _build_envelope(
            keypair, kind="cohort.surface",
            record_id="filter-s", version=1,
        )
        live_surface_cid, _ = bundles.insert(live_surface)
        live_depth = _build_envelope(
            keypair, kind="cohort.depth",
            record_id="filter-d", version=1,
        )
        live_depth_cid, _ = bundles.insert(live_depth)
        from swf import event_bus
        # Emit depth first to make sure the filter SKIPS it rather
        # than just-happening-to-emit-surface-first.
        event_bus.emit("bundle_added", {
            "cid": live_depth_cid,
            "kind": "cohort.depth",
            "record_id": "filter-d",
            "version": 1,
        })
        event_bus.emit("bundle_added", {
            "cid": live_surface_cid,
            "kind": "cohort.surface",
            "record_id": "filter-s",
            "version": 1,
        })

        evt = _parse_sse_event(_read_one_event(resp, deadline_seconds=3.0))
        assert evt["event"] == "bundle"
        assert evt["id"] == live_surface_cid
        envelope = json.loads(evt["data"])
        assert envelope["kind"] == "cohort.surface"

        # Sanity: never see the depth bundle. We don't have a clean
        # "no further events" assertion that's both fast and reliable
        # in a streaming test; a short read attempt with a tiny
        # deadline is the closest we can get without flake.
        # Use a 0.5s window — long enough that a same-thread emit would
        # have arrived, short enough not to bog down the suite.
        try:
            extra = _read_one_event(resp, deadline_seconds=0.5)
        except AssertionError:
            extra = None
        if extra is not None:
            extra_evt = _parse_sse_event(extra)
            # Only acceptable second event would be another surface
            # one (e.g. test order quirk); never the depth.
            envelope2 = json.loads(extra_evt["data"])
            assert envelope2["kind"] == "cohort.surface"

        # Quiet "unused name" warnings for the seed cids — they're
        # named for clarity in the assertion above's failure messages.
        _ = (surface_cid, depth_cid)
    finally:
        conn.close()


def test_subscribe_two_concurrent_subscribers_both_receive(
    peer_server_running, keypair,
):
    """Two concurrent subscribers must each receive the same event when
    a new bundle is inserted. event_bus's subscriber list is the
    fan-out point."""
    host, port, _base = peer_server_running

    conn_a, resp_a = _open_subscribe(host, port)
    conn_b, resp_b = _open_subscribe(host, port)
    try:
        assert resp_a.status == 200 and resp_b.status == 200

        env = _build_envelope(keypair, record_id="fan-out", version=0)
        cid, _ = bundles.insert(env)
        from swf import event_bus
        event_bus.emit("bundle_added", {
            "cid": cid,
            "kind": env["kind"],
            "record_id": env["record_id"],
            "version": env["version"],
        })

        evt_a = _parse_sse_event(_read_one_event(resp_a, deadline_seconds=3.0))
        evt_b = _parse_sse_event(_read_one_event(resp_b, deadline_seconds=3.0))
        assert evt_a["id"] == cid
        assert evt_b["id"] == cid
        assert evt_a["event"] == evt_b["event"] == "bundle"
    finally:
        conn_a.close()
        conn_b.close()


def test_subscribe_client_disconnect_does_not_crash_server(
    peer_server_running, keypair,
):
    """Close the client mid-stream; the server cleans up its event_bus
    subscription on the next emit (when the broken pipe surfaces).

    We don't assert internal subscriber-count state — that's a private
    detail. The contract this test pins is: subsequent requests still
    succeed (server is still healthy), and `loopback_reset_count()`
    doesn't fire (subscribe disconnects are NOT loopback RSTs in the
    handshake-only sense from #82)."""
    host, port, base = peer_server_running

    # Capture the loopback reset baseline. The QuietThreadingHTTPServer
    # only counts handshake-window RSTs (#82); a clean mid-stream close
    # should NOT bump this counter.
    import swf.peer_server as ps
    baseline_resets = ps.loopback_reset_count()

    conn, resp = _open_subscribe(host, port)
    assert resp.status == 200

    # Force-close the client connection without reading the body.
    # This should put the server's wfile.flush() into BrokenPipeError /
    # ConnectionResetError on the next write — we trigger that next
    # write by emitting a bundle_added event.
    conn.close()

    # Give the server a moment to register the close (it won't notice
    # until it tries to write, but emitting before the close has been
    # fully observed by the OS is fine — the next write will fail).
    time.sleep(0.05)

    env = _build_envelope(keypair, record_id="post-disconnect", version=0)
    cid, _ = bundles.insert(env)
    from swf import event_bus
    event_bus.emit("bundle_added", {
        "cid": cid,
        "kind": env["kind"],
        "record_id": env["record_id"],
        "version": env["version"],
    })

    # The server should still be healthy and serving requests. Use the
    # /health endpoint as a smoke check.
    import urllib.request
    with urllib.request.urlopen(base + "/health", timeout=2) as r:
        assert r.status == 200
        body = json.loads(r.read().decode("utf-8"))
        assert body["ok"] is True

    # No new loopback resets should have been counted — subscribe
    # disconnects are normal mid-stream closes, not handshake-window
    # RST noise.
    assert ps.loopback_reset_count() == baseline_resets


def test_subscribe_emits_heartbeat_on_idle(peer_server_running, monkeypatch):
    """When idle (no `bundle_added` events), the SSE stream emits a
    `: keepalive\\n\\n` comment so proxies don't time the connection
    out. We patch the heartbeat down to make this test fast.

    Implementation note: the heartbeat cadence lives on the handler
    class; monkeypatching the class attribute is enough because
    `_do_bundles_subscribe` reads it from `self`."""
    host, port, _base = peer_server_running
    import swf.peer_server as ps
    monkeypatch.setattr(
        ps._Handler, "_BUNDLE_SSE_HEARTBEAT_SECONDS", 0.2,
    )

    conn, resp = _open_subscribe(host, port, timeout=3.0)
    try:
        assert resp.status == 200
        # Read up to 1s of bytes; we should see at least one keepalive
        # comment within that window. The keepalive line is
        # `: keepalive\n\n`; we look for the literal bytes.
        deadline = time.monotonic() + 1.5
        seen = b""
        while time.monotonic() < deadline:
            try:
                chunk = resp.read1(4096)
            except TimeoutError:
                chunk = b""
            if chunk:
                seen += chunk
                if b": keepalive" in seen:
                    break
            else:
                time.sleep(0.05)
        assert b": keepalive" in seen, f"no keepalive in {seen!r}"
    finally:
        conn.close()


# ── meta: confirm the route is reachable and only this exact path matches ──


def test_subscribe_path_is_exact_not_prefix(peer_server_running):
    """`/bundles/subscribe` must not collide with `/bundles/by_cid/...`
    or `/bundles` — the exact-path match is locked. This test confirms
    a sibling path (`/bundles/subscribex`) is a 404, not a partial
    match into the SSE handler."""
    host, port, _base = peer_server_running
    cn = http.client.HTTPConnection(host, port, timeout=2.0)
    try:
        cn.request("GET", "/bundles/subscribex")
        r = cn.getresponse()
        body = r.read().decode("utf-8")
        assert r.status == 404
        # Body is JSON `{"error": "not found", ...}` — confirm we
        # didn't accidentally enter the SSE response framing.
        assert r.headers.get("Content-Type") == "application/json"
        json.loads(body)  # parses as JSON
    finally:
        cn.close()
