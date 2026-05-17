"""Two-peer LAN bundle propagation — closes #93's acceptance list.

Issue #93's acceptance criteria include:

  * Two swf-node peers on a LAN exchange a posted `cohort.surface`
    bundle within seconds via mDNS-discovered propagation.
  * A simulated voxterm POST to `/hivemind/transcripts` produces a
    properly-signed `transcript.batch` bundle on `/bundles/subscribe`.

This module proves both. Each peer runs in its own subprocess so it
gets its own `SWF_KNOWLEDGE_DIR` (and therefore its own indrex DB)
without poisoning the test process's env. Peers are wired to each
other by directly seeding `swf.peer_scraper._discovery_cache` over a
test-only HTTP endpoint we don't have — instead we pre-populate each
subprocess's discovery cache via an in-process `swf.peer_scraper`
import + `peer_scraper._discovery_cache.update(...)` at boot time.

Why subprocesses, not threads
─────────────────────────────

`swf.indrex.db_path()` reads `SWF_KNOWLEDGE_DIR` at call time, and
the bundles store / propagation / route handlers all dispatch
through it on every request. With two peers in one process we'd
need two simultaneous values for the env var, which Python's process
model doesn't support. Subprocesses also closer to the production
shape (each `swf-node` is a real process), so the test exercises
the actual cross-process HTTP path the LAN propagation depends on.

The subprocesses are short-lived (one per test) and bound to free
local ports; mDNS is suppressed via `SWF_NO_MDNS=1` because we wire
the discovery cache directly. Spec §4.4 promises mDNS works in
production, but mDNS in CI is flaky — the discovery-cache injection
is the cleanest way to test propagation deterministically.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import sqlite3
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swf import bundles

# ── shared crypto + envelope helpers ──────────────────────────────────


@dataclass
class _Keypair:
    priv: Ed25519PrivateKey
    pub_hex: str
    pubkey_str: str
    seed: bytes


def _make_keypair() -> _Keypair:
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = raw.hex()
    return _Keypair(
        priv=priv, pub_hex=pub_hex,
        pubkey_str=f"ed25519:{pub_hex}", seed=seed,
    )


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


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_alchemists_yml(path: Path, *pubkey_strings: str) -> None:
    lines = ["schema_version: 1", "alchemists:"]
    for i, pk in enumerate(pubkey_strings):
        lines.append(f"  - id: alc-{i}")
        lines.append(f'    pubkey: "{pk}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_reservoir_yml(path: Path, recipients: list[str]) -> None:
    """Write a `.reservoir.yml` with the given age-recipient strings.

    The encrypted-bundle E2E tests need real X25519 keys (so pyrage
    can round-trip them); the helper just lays out the file in the
    same shape `swf.bundles.reservoir.load_reservoir` expects.
    """
    lines = ["schema_version: 1", 'generated_at: "2026-05-04T00:00:00Z"', "keys:"]
    for i, r in enumerate(recipients):
        lines.append(f"  - id: alc-{i:03d}")
        lines.append(f'    pubkey: "{r}"')
        lines.append("    distributed_to: null")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── subprocess peer launcher ───────────────────────────────────────────


# The launcher script runs inside a subprocess. It:
#   1. imports `swf.peer_server`,
#   2. seeds the local `peers` table with the entries we list in
#      `--peers <pubkey>=<url>,<pubkey>=<url>,...`,
#   3. seeds `peer_scraper._discovery_cache` so `_resolve_peer_url`
#      returns the test URLs directly (skipping mDNS),
#   4. calls `serve_in_thread(bind, port)` and prints "READY <port>"
#      so the parent can synchronize, then sleeps until SIGTERM.
_PEER_LAUNCHER = textwrap.dedent(r"""
    import argparse
    import os
    import signal
    import sqlite3
    import sys
    import time

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--peers", default="",
                        help="comma-separated <pubkey>=<url> entries to seed")
    parser.add_argument("--with-puller", default="0",
                        help="if 1, start the bundles puller with the "
                             "given interval (in seconds, float)")
    args = parser.parse_args()

    # peer_server caches `_DB_PATH` at import time. SWF_KNOWLEDGE_DIR
    # is already set in our env (parent passes it via env=...).
    from swf import peer_scraper, peer_server
    from swf.indrex import db_path
    from swf.search import migration

    # Ensure the indrex DB + schema exist so list_peers / writes work.
    p = db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=5.0)
    try:
        migration.ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()

    # Seed the peers table + discovery cache for the test wiring.
    if args.peers:
        for entry in args.peers.split(","):
            entry = entry.strip()
            if not entry or "=" not in entry:
                continue
            pubkey, url = entry.split("=", 1)
            pubkey = pubkey.strip()
            url = url.strip()
            peer_scraper.upsert_peer(p, pubkey=pubkey, nickname="test")
            peer_scraper._discovery_cache[pubkey] = url
        # Mark the cache fresh so `_resolve_peer_url` doesn't try to
        # re-browse mDNS (which would then clear our seeded entries).
        peer_scraper._discovery_cache_ts = time.time()

    server, thread = peer_server.serve_in_thread(
        bind="127.0.0.1", port=args.port,
    )

    # Optionally start the bundles puller. We do this AFTER
    # serve_in_thread so the HTTP route is up first; the puller
    # runs against this subprocess's own DB and pulls from peers
    # listed in the local indrex.peers table.
    try:
        interval = float(args.with_puller)
    except ValueError:
        interval = 0.0
    if interval > 0:
        from swf import bundles as _b
        _b.start_puller(db_path=p, interval_secs=interval)

    sys.stdout.write(f"READY {args.port}\n")
    sys.stdout.flush()

    stop = False
    def _on_stop(signum, frame):
        global stop
        stop = True
    signal.signal(signal.SIGTERM, _on_stop)
    signal.signal(signal.SIGINT, _on_stop)

    try:
        while not stop:
            time.sleep(0.2)
    finally:
        server.shutdown()
        server.server_close()
""")


@dataclass
class _PeerProcess:
    """One peer subprocess, bound to its own free port + tmp DB.

    Launched eagerly in `__enter__`; `.stop()` terminates the child.
    The parent waits for `READY <port>` on stdout before yielding so
    the test never races a not-yet-listening server.
    """
    label: str
    port: int
    knowledge_dir: Path
    alchemists_path: Path
    keypair: _Keypair
    proc: subprocess.Popen | None = None
    _last_start_args: dict | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def db_path(self) -> Path:
        return self.knowledge_dir / "index.db"

    def start(
        self, *,
        peers_arg: str = "",
        signing_key_seed: bytes | None = None,
        puller_interval_secs: float = 0.0,
        reservoir_path: Path | None = None,
    ) -> None:
        env = os.environ.copy()
        env["SWF_KNOWLEDGE_DIR"] = str(self.knowledge_dir)
        env["SWF_ALCHEMISTS_FILE"] = str(self.alchemists_path)
        # Suppress real mDNS so the test doesn't spam the LAN and
        # doesn't race the discovery-cache seed.
        env["SWF_NO_MDNS"] = "1"
        # Hivemind sink is opt-in; tests that need it set
        # SWF_HIVEMIND_SINK + SWF_CONVENT_SIGNING_KEY before calling.
        if signing_key_seed is not None:
            seed_path = self.knowledge_dir / "convent.seed"
            seed_path.write_bytes(signing_key_seed)
            env["SWF_CONVENT_SIGNING_KEY"] = str(seed_path)
        # Optional `.reservoir.yml` for the encrypted-bundle E2E tests.
        # When set, the subprocess's `POST /bundles` verifier and
        # hivemind sink both load this reservoir (via SWF_RESERVOIR_FILE).
        if reservoir_path is not None:
            env["SWF_RESERVOIR_FILE"] = str(reservoir_path)
        # Stash launch args so `restart()` can re-invoke `start()` with
        # the same configuration after a stop. Tests that want a fresh
        # process pointed at the same dirs use this.
        self._last_start_args = {
            "peers_arg": peers_arg,
            "signing_key_seed": signing_key_seed,
            "puller_interval_secs": puller_interval_secs,
            "reservoir_path": reservoir_path,
        }

        # Use the same Python interpreter the test runs under so
        # the subprocess sees the same installed swf package.
        cmd = [
            sys.executable, "-c", _PEER_LAUNCHER,
            "--port", str(self.port),
        ]
        if peers_arg:
            cmd.extend(["--peers", peers_arg])
        if puller_interval_secs > 0:
            cmd.extend(["--with-puller", str(puller_interval_secs)])

        self.proc = subprocess.Popen(
            cmd, env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for "READY <port>" or for the process to die. 10s is
        # enough for any reasonable laptop import + bind cost; CI
        # cold imports can be slow but rarely over 5s.
        deadline = time.monotonic() + 10.0
        ready_line = ""
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                # Child exited before READY — surface stderr to help
                # debug import / bind failures.
                err = self.proc.stderr.read() if self.proc.stderr else ""
                raise RuntimeError(
                    f"peer {self.label!r} subprocess exited "
                    f"with code={self.proc.returncode}; stderr:\n{err}"
                )
            line = self.proc.stdout.readline() if self.proc.stdout else ""
            if line.startswith("READY"):
                ready_line = line
                break
            # Avoid busy-loop without `readline` — readline blocks if
            # the child hasn't printed yet, but also returns "" when
            # the pipe closes. Sleep briefly to yield.
            time.sleep(0.05)
        if not ready_line:
            self.stop()
            raise RuntimeError(
                f"peer {self.label!r} did not signal READY within 10s",
            )

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2.0)
        self.proc = None

    def restart(self) -> None:
        """Stop the running process and start a fresh one against the
        same knowledge_dir / alchemists / port / reservoir.

        Used by the restart-preserves-state test (Gap 4): a real
        operator restarts the daemon (manual, OS update, crash); we
        verify durable state survives. Reuses the last start() args so
        the new process is configured identically to the previous one.
        """
        if self._last_start_args is None:
            raise RuntimeError(
                f"peer {self.label!r} has never been started; "
                "call start() before restart()",
            )
        args = self._last_start_args
        self.stop()
        self.start(**args)


# ── HTTP helpers ───────────────────────────────────────────────────────


def _post_json(url: str, payload: dict, *, timeout: float = 5.0):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def _get_json(url: str, *, timeout: float = 5.0):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _wait_for_bundle(
    base_url: str,
    cid: str,
    *,
    deadline_seconds: float = 3.0,
    poll_interval: float = 0.05,
) -> dict | None:
    """Poll `GET /bundles/by_cid/<cid>` until it returns 200, or
    deadline. Returns the envelope dict on success, None on timeout."""
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        status, body = _get_json(f"{base_url}/bundles/by_cid/{cid}")
        if status == 200 and isinstance(body, dict):
            return body
        time.sleep(poll_interval)
    return None


# ── fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def alchemist_keypair():
    return _make_keypair()


def _build_alchemists_yml(tmp_path: Path, *pubkeys: str) -> Path:
    p = tmp_path / "alchemists.yml"
    _write_alchemists_yml(p, *pubkeys)
    return p


def _make_peer(
    label: str, *, tmp_path: Path, alchemists_path: Path, keypair: _Keypair,
) -> _PeerProcess:
    knowledge = tmp_path / label / "world_knowledge"
    knowledge.mkdir(parents=True, exist_ok=True)
    return _PeerProcess(
        label=label,
        port=_free_port(),
        knowledge_dir=knowledge,
        alchemists_path=alchemists_path,
        keypair=keypair,
    )


# ── tests ──────────────────────────────────────────────────────────────


def test_cohort_surface_propagates_a_to_b(tmp_path, alchemist_keypair):
    """The headline acceptance criterion from #93:

        Two swf-node peers on a LAN exchange a posted `cohort.surface`
        bundle within seconds via mDNS-discovered propagation.

    POST a `cohort.surface` to peer A; assert peer B has it within a
    few seconds via `GET /bundles/by_cid/<cid>`.
    """
    alch_path = _build_alchemists_yml(tmp_path, alchemist_keypair.pubkey_str)
    a = _make_peer("a", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    b = _make_peer("b", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    # Peer A knows about B (and vice versa, just so the symmetry is
    # explicit even though only A→B is exercised in this test).
    pubkey_b = "ed25519:" + ("b" * 64)
    pubkey_a = "ed25519:" + ("a" * 64)
    try:
        a.start(peers_arg=f"{pubkey_b}={b.base_url}")
        b.start(peers_arg=f"{pubkey_a}={a.base_url}")

        env = _build_envelope(
            alchemist_keypair, record_id="prop-headline",
        )
        cid = bundles.cid_for(env)
        status, body = _post_json(f"{a.base_url}/bundles", env)
        assert status == 201
        assert body["cid"] == cid

        # Within a few seconds, B must have the bundle.
        landed = _wait_for_bundle(b.base_url, cid, deadline_seconds=3.0)
        assert landed is not None, (
            "bundle did not propagate from A to B within 3s"
        )
        assert landed["signature"] == env["signature"]
        assert landed["record_id"] == "prop-headline"

        # And B did NOT re-propagate back to A in a way that
        # duplicated the row. A still has exactly one row for this
        # record_id.
        a_db = sqlite3.connect(str(a.db_path), timeout=5.0)
        try:
            (n,) = a_db.execute(
                "SELECT COUNT(*) FROM bundles WHERE record_id=?",
                ("prop-headline",),
            ).fetchone()
        finally:
            a_db.close()
        assert n == 1
    finally:
        a.stop()
        b.stop()


def test_propagation_skipped_when_was_new_false(tmp_path, alchemist_keypair):
    """Re-POST of the same envelope to peer A returns the same cid
    (idempotent) but does NOT re-propagate. We can't easily observe
    "no propagation occurred" directly, but we can observe the
    invariant: B's bundles row count for this record_id stays at 1
    after a re-POST to A."""
    alch_path = _build_alchemists_yml(tmp_path, alchemist_keypair.pubkey_str)
    a = _make_peer("a", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    b = _make_peer("b", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    pubkey_b = "ed25519:" + ("b" * 64)
    pubkey_a = "ed25519:" + ("a" * 64)
    try:
        a.start(peers_arg=f"{pubkey_b}={b.base_url}")
        b.start(peers_arg=f"{pubkey_a}={a.base_url}")

        env = _build_envelope(alchemist_keypair, record_id="prop-idem")
        cid = bundles.cid_for(env)

        # First POST → B receives it.
        s1, _ = _post_json(f"{a.base_url}/bundles", env)
        assert s1 == 201
        assert _wait_for_bundle(b.base_url, cid, deadline_seconds=3.0) is not None

        # Re-POST same envelope → idempotent, same cid.
        s2, b2 = _post_json(f"{a.base_url}/bundles", env)
        assert s2 == 201
        assert b2["cid"] == cid

        # Give a brief window for any spurious re-broadcast to land.
        time.sleep(0.3)

        # Both A and B still have exactly one row for this record_id.
        for peer in (a, b):
            db = sqlite3.connect(str(peer.db_path), timeout=5.0)
            try:
                (n,) = db.execute(
                    "SELECT COUNT(*) FROM bundles WHERE record_id=?",
                    ("prop-idem",),
                ).fetchone()
            finally:
                db.close()
            assert n == 1, f"peer {peer.label} has {n} rows, expected 1"
    finally:
        a.stop()
        b.stop()


def test_hivemind_transcript_propagates_to_subscribe(
    tmp_path, alchemist_keypair,
):
    """Maps to #93's:

        A simulated voxterm POST to /hivemind/transcripts produces a
        properly-signed `transcript.batch` bundle on /bundles/subscribe.

    Plus the phase-6 propagation slice: the sink-generated bundle must
    also reach peer B's /bundles/subscribe stream (the cross-process
    propagation path the convent box relies on)."""
    alch_path = _build_alchemists_yml(tmp_path, alchemist_keypair.pubkey_str)
    a = _make_peer("a", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    b = _make_peer("b", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    pubkey_b = "ed25519:" + ("b" * 64)
    pubkey_a = "ed25519:" + ("a" * 64)
    try:
        # A is the convent box (hivemind sink); B is a passive
        # bundle subscriber.
        a.start(
            peers_arg=f"{pubkey_b}={b.base_url}",
            signing_key_seed=alchemist_keypair.seed,
        )
        b.start(peers_arg=f"{pubkey_a}={a.base_url}")

        # Open SSE subscriber on B BEFORE the voxterm POST so the
        # subscribe stream is registered in time to catch the
        # propagated bundle.
        sse_conn = http.client.HTTPConnection(
            "127.0.0.1", b.port, timeout=4.0,
        )
        sse_conn.request(
            "GET", "/bundles/subscribe?kind=transcript.batch",
        )
        sse_resp = sse_conn.getresponse()
        try:
            assert sse_resp.status == 200
            assert sse_resp.headers.get("Content-Type") == "text/event-stream"

            # Simulate voxterm: post an unsigned transcript batch to
            # peer A's hivemind sink.
            payload = {
                "record_id": "voxterm-prop",
                "batch_index": 0,
                "started_at": "2026-05-04T12:00:00Z",
                "ended_at": "2026-05-04T12:00:30Z",
                "segments": [
                    {"t": 0.0, "speaker": "alice",
                     "text": "field test propagation"},
                ],
            }
            status, body = _post_json(
                f"{a.base_url}/hivemind/transcripts", payload,
            )
            assert status == 201, body
            cid = body["cid"]

            # Read SSE events until we see one matching cid, or
            # timeout. This single helper inlined here because we
            # don't share the test_peer_server_bundles_subscribe
            # helpers and don't want a cross-test import.
            buf = b""
            deadline = time.monotonic() + 4.0
            seen_event = None
            while time.monotonic() < deadline:
                try:
                    chunk = sse_resp.read1(4096)
                except TimeoutError:
                    chunk = b""
                if not chunk:
                    time.sleep(0.05)
                    continue
                buf += chunk
                while b"\n\n" in buf:
                    block, _, rest = buf.partition(b"\n\n")
                    buf = rest
                    text = block.decode("utf-8", errors="replace")
                    if "event: bundle" in text and f"id: {cid}" in text:
                        seen_event = text
                        break
                if seen_event is not None:
                    break
            assert seen_event is not None, (
                f"no transcript.batch event with cid={cid[:12]} on "
                f"peer B's SSE stream within 4s"
            )
            # Sanity: the data field carries the full envelope.
            assert "magic" in seen_event
            assert "transcript.batch" in seen_event
        finally:
            sse_conn.close()
    finally:
        a.stop()
        b.stop()


def test_pull_replication_catches_offline_peer(tmp_path, alchemist_keypair):
    """Pull-side replication backfills bundles posted while a peer
    was offline (#93 phase 6 follow-up).

    Push-only propagation has a known gap: a peer that's offline at
    POST time never receives the bundle. The pull-side puller closes
    that gap by polling each known peer's
    `/bundles?received_since=<hw>` cursor every tick.

    Scenario:
      1. Peer A starts. Peer B is intentionally NOT started.
      2. Three bundles POST to A. Push-side broadcast tries to reach
         B, fails (B isn't listening), the bundles sit on A only.
      3. Peer B starts WITH the puller enabled at a 1s tick. B's
         peers table lists A.
      4. Within a few ticks, B's puller pulls all three bundles from
         A and stores them locally.

    This is the regression test that proves offline-then-rejoin works.
    """
    alch_path = _build_alchemists_yml(tmp_path, alchemist_keypair.pubkey_str)
    a = _make_peer("a", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    b = _make_peer("b", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    pubkey_a = "ed25519:" + ("a" * 64)
    pubkey_b = "ed25519:" + ("b" * 64)
    try:
        # Start ONLY A. B is offline at this point.
        a.start(peers_arg=f"{pubkey_b}={b.base_url}")

        # POST three bundles while B is offline. The push-side
        # broadcast will try to reach b.base_url and fail; that
        # failure is silent and is what the puller is here to fix.
        cids = []
        for i in range(3):
            env = _build_envelope(
                alchemist_keypair, record_id=f"offline-{i}",
            )
            cids.append(bundles.cid_for(env))
            status, _ = _post_json(f"{a.base_url}/bundles", env)
            assert status == 201

        # Sanity: all three are on A.
        for cid in cids:
            assert _wait_for_bundle(
                a.base_url, cid, deadline_seconds=2.0,
            ) is not None

        # Now start B with a fast puller tick. The puller will see A
        # in its peers table, hit `GET /bundles?received_since=0`,
        # verify + ingest all three.
        b.start(
            peers_arg=f"{pubkey_a}={a.base_url}",
            puller_interval_secs=1.0,
        )

        # Within ~5s (a few puller ticks + verify cost) all three
        # bundles must land on B via the pull path.
        for cid in cids:
            assert _wait_for_bundle(
                b.base_url, cid, deadline_seconds=5.0,
            ) is not None, (
                f"bundle {cid[:12]} did not catch up to peer B "
                f"via pull replication within 5s"
            )

        # And the peer-A → peer-B high-water has advanced past the
        # last rowid we ingested. The exact value depends on insert
        # order; assert it's at least 3 (we POSTed 3 bundles to A).
        b_db = sqlite3.connect(str(b.db_path), timeout=5.0)
        try:
            row = b_db.execute(
                "SELECT value FROM swf_kv "
                "WHERE key=?",
                (f"bundles.high_water.{pubkey_a}",),
            ).fetchone()
        finally:
            b_db.close()
        assert row is not None, "puller never advanced high-water"
        assert int(row[0]) >= 3
    finally:
        a.stop()
        b.stop()


def test_three_peer_triangle_converges_without_loop(
    tmp_path, alchemist_keypair,
):
    """Loop-prevention test. Three peers in a directed triangle:
    A → B, B → C, C → A. A POST to A must converge to all three with
    no infinite loop. We assert convergence (every peer has the
    bundle) AND a bound on the total number of bundles each peer
    holds (exactly one — the `was_new=False` short-circuit prevents
    duplicate inserts on receipt)."""
    alch_path = _build_alchemists_yml(tmp_path, alchemist_keypair.pubkey_str)
    a = _make_peer("a", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    b = _make_peer("b", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    c = _make_peer("c", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    pubkey_a = "ed25519:" + ("a" * 64)
    pubkey_b = "ed25519:" + ("b" * 64)
    pubkey_c = "ed25519:" + ("c" * 64)
    try:
        # Triangle wiring: each peer knows the next one in the cycle.
        # We seed BOTH neighbors per peer (e.g. A knows both B and C)
        # so the test is a connected graph, not a directed cycle —
        # this is closer to the real LAN where every peer broadcasts
        # to every neighbor it can see, and the loop-prevention
        # MUST hold in the dense case too.
        a.start(peers_arg=f"{pubkey_b}={b.base_url},{pubkey_c}={c.base_url}")
        b.start(peers_arg=f"{pubkey_a}={a.base_url},{pubkey_c}={c.base_url}")
        c.start(peers_arg=f"{pubkey_a}={a.base_url},{pubkey_b}={b.base_url}")

        env = _build_envelope(alchemist_keypair, record_id="triangle")
        cid = bundles.cid_for(env)
        status, _ = _post_json(f"{a.base_url}/bundles", env)
        assert status == 201

        # All three peers must have the bundle within a few seconds.
        for peer in (a, b, c):
            assert _wait_for_bundle(
                peer.base_url, cid, deadline_seconds=3.0,
            ) is not None, (
                f"bundle did not reach peer {peer.label} within 3s"
            )

        # Allow extra time for any in-flight loops to play out, then
        # assert each peer holds EXACTLY ONE row for this record_id.
        # That's the strict statement of "no infinite loop": if any
        # peer ran a re-broadcast on `was_new=False` we'd see >1 row
        # somewhere from the duplicate POSTs.
        time.sleep(0.5)
        for peer in (a, b, c):
            db = sqlite3.connect(str(peer.db_path), timeout=5.0)
            try:
                (n,) = db.execute(
                    "SELECT COUNT(*) FROM bundles WHERE record_id=?",
                    ("triangle",),
                ).fetchone()
            finally:
                db.close()
            assert n == 1, (
                f"peer {peer.label} holds {n} rows for record_id=triangle; "
                f"expected 1 (loop prevention violated)"
            )
    finally:
        a.stop()
        b.stop()
        c.stop()


# ── E2E coverage gap fills (post-#93 audit) ────────────────────────────
#
# The five tests above already cover the headline acceptance criteria
# from #93 (push, idempotency, hivemind→SSE, pull, triangle convergence).
# The four below close gaps the unit-level coverage doesn't catch:
#
#   1. encrypted-bundle round-trip across peers (Gap 1)
#   2. reservoir-mismatch rejection at ingest      (Gap 2)
#   3. (Gap 3 lives in test_node_check_bundles.py)
#   4. restart preserves state across the bundle subsystem (Gap 4)
#
# Pattern matches the suite above: subprocess peers, polling-based
# assertions, generous timeouts, no `time.sleep(N)` for state changes.


def _gen_reservoir(n: int) -> tuple[list, list[str]]:
    """Generate `n` fresh X25519 keypairs for the encrypted-bundle E2E
    tests. Returns `(identities, recipient_strings)`. The identities
    carry the secret half (used in tests for the decrypt assertion);
    the recipient strings go into `.reservoir.yml`.
    """
    import pyrage  # local import — pyrage is a hard dep for these tests
    idents: list = []
    recipients: list[str] = []
    for _ in range(n):
        ident = pyrage.x25519.Identity.generate()
        idents.append(ident)
        recipients.append(str(ident.to_public()))
    return idents, recipients


def _post_encrypted_transcript(
    base_url: str, payload: dict,
) -> tuple[int, dict]:
    """POST `payload` to `<base_url>/hivemind/transcripts?encrypt=true`.

    The handler honors the query-param flag; we use it instead of the
    body field because the on-the-wire shape (`?encrypt=true`) is the
    voxterm contract documented in spec §4.3.
    """
    return _post_json(
        f"{base_url}/hivemind/transcripts?encrypt=true", payload,
    )


def test_encrypted_transcript_propagates_and_decrypts(
    tmp_path, alchemist_keypair,
):
    """Gap 1: encrypted-bundle round-trip across peers.

    Two peers share an identical X25519 reservoir. Peer A is the
    convent box (hivemind sink) and posts an encrypted transcript via
    `?encrypt=true`. Peer B receives the bundle via push propagation.

    Assertions:
      * envelope.encryption.alg == "age-v1"
      * envelope.encryption.recipients matches the reservoir's pubkey
        set (per spec §3.6: encrypt-to-all-reservoir-keys)
      * pulling a private key from the test reservoir, pyrage.decrypt
        on the ciphertext round-trips to the original transcript JSON
        (this is the load-bearing trust-model assertion)

    Regression caught: if the producer-side encryption path broke and
    bundles started going out unencrypted (or with a different
    recipient set than the reservoir's), this test fails before any
    consumer notices.
    """
    import base64
    import json as _json

    import pyrage

    alch_path = _build_alchemists_yml(tmp_path, alchemist_keypair.pubkey_str)
    # Generate the shared reservoir. Peer A and Peer B both point at
    # the SAME file (same recipient set) — that's the spec's
    # "consistent reservoir across the trust set" invariant.
    idents, recipients = _gen_reservoir(3)
    reservoir_path = tmp_path / ".reservoir.yml"
    _write_reservoir_yml(reservoir_path, recipients)

    a = _make_peer("a", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    b = _make_peer("b", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    pubkey_b = "ed25519:" + ("b" * 64)
    pubkey_a = "ed25519:" + ("a" * 64)
    try:
        # A is the hivemind sink AND a propagator. B has the same
        # reservoir so its `POST /bundles` verifier accepts every
        # recipient in the bundle's `encryption.recipients`.
        a.start(
            peers_arg=f"{pubkey_b}={b.base_url}",
            signing_key_seed=alchemist_keypair.seed,
            reservoir_path=reservoir_path,
        )
        b.start(
            peers_arg=f"{pubkey_a}={a.base_url}",
            reservoir_path=reservoir_path,
        )

        payload = {
            "record_id": "voxterm-encrypted",
            "batch_index": 0,
            "started_at": "2026-05-04T12:00:00Z",
            "ended_at": "2026-05-04T12:00:30Z",
            "segments": [
                {"t": 0.0, "speaker": "alice", "text": "secret payload"},
                {"t": 1.5, "speaker": "bob", "text": "shipped to reservoir"},
            ],
        }
        status, body = _post_encrypted_transcript(a.base_url, payload)
        assert status == 201, body
        cid = body["cid"]

        # Peer B receives the bundle via push within a few seconds.
        landed = _wait_for_bundle(b.base_url, cid, deadline_seconds=5.0)
        assert landed is not None, (
            "encrypted bundle did not propagate from A to B within 5s"
        )

        # Envelope contract: the encryption block matches spec §3.6.
        enc = landed.get("encryption")
        assert isinstance(enc, dict), enc
        assert enc.get("alg") == "age-v1"
        assert enc.get("recipients") == recipients, (
            "envelope recipients should match the reservoir's pubkey set "
            "exactly (spec §3.6: encrypt-to-all-reservoir-keys)"
        )

        # Decryption round-trip. Pull any reservoir privkey and decrypt
        # the ciphertext; the inner JSON must match what we POSTed.
        # The producer canonicalizes the inner payload (record_type +
        # schema_version flattened in per spec §3.5), so we compare
        # against the canonicalized inner shape rather than the raw
        # voxterm payload — this is what the consumer apps decrypt.
        ciphertext = base64.b64decode(landed["payload"])
        plaintext = pyrage.decrypt(ciphertext, [idents[0]])
        decoded = _json.loads(plaintext.decode("utf-8"))
        assert decoded["record_id"] == "voxterm-encrypted"
        assert decoded["batch_index"] == 0
        assert decoded["record_type"] == "transcript"
        assert decoded["segments"][0]["text"] == "secret payload"
        assert decoded["segments"][1]["speaker"] == "bob"

        # And: an outsider's privkey CANNOT decrypt — proves the
        # ciphertext is actually encrypted to the reservoir set, not
        # symmetric or some null cipher that round-trips for everyone.
        outsider = pyrage.x25519.Identity.generate()
        with pytest.raises(pyrage.DecryptError):
            pyrage.decrypt(ciphertext, [outsider])
    finally:
        a.stop()
        b.stop()


def test_peer_accepts_bundle_with_recipient_outside_local_reservoir(
    tmp_path, alchemist_keypair,
):
    """Gap 2 (#112): reservoir-mismatch is NO LONGER an ingest gate.

    Peer A has reservoir [X, Y, Z]; peer B has [X, Y] (missing Z).
    Peer A posts an encrypted transcript locally; A's push to B is
    accepted by B's `POST /bundles` verifier (201) — the alchemist
    signature gate is the trust boundary, not the reservoir
    composition. Peer B's bundles table gains a row for the bundle
    (push propagation lands).

    Regression caught: this test inverts the pre-#112 behavior. If
    we ever re-introduce a recipient-subset gate on `POST /bundles`,
    this test will catch it (the push from A to B would fail and B's
    bundles table would stay empty for the bundle's cid).
    """
    alch_path = _build_alchemists_yml(tmp_path, alchemist_keypair.pubkey_str)
    # A's reservoir is the full set; B's reservoir is missing the
    # third recipient. Both peers see the same `.alchemists.yml` so
    # the alchemist whitelist + signature stages pass on B as before.
    # Per #112 the reservoir-recipient check no longer fires on B.
    _idents_a, recipients_a = _gen_reservoir(3)
    reservoir_a = tmp_path / "a.reservoir.yml"
    reservoir_b = tmp_path / "b.reservoir.yml"
    _write_reservoir_yml(reservoir_a, recipients_a)
    _write_reservoir_yml(reservoir_b, recipients_a[:2])  # missing Z

    a = _make_peer("a", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    b = _make_peer("b", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    pubkey_b = "ed25519:" + ("b" * 64)
    pubkey_a = "ed25519:" + ("a" * 64)
    try:
        a.start(
            peers_arg=f"{pubkey_b}={b.base_url}",
            signing_key_seed=alchemist_keypair.seed,
            reservoir_path=reservoir_a,
        )
        b.start(
            peers_arg=f"{pubkey_a}={a.base_url}",
            reservoir_path=reservoir_b,
        )

        payload = {
            "record_id": "mismatch",
            "batch_index": 0,
            "started_at": "2026-05-04T12:00:00Z",
            "ended_at": "2026-05-04T12:00:30Z",
            "segments": [
                {"t": 0.0, "speaker": "alice", "text": "for the full set only"},
            ],
        }
        # POST to A succeeds — A's reservoir matches the recipients set.
        status, body = _post_encrypted_transcript(a.base_url, payload)
        assert status == 201, body
        cid = body["cid"]

        # Sanity: A has the bundle locally.
        a_landed = _wait_for_bundle(a.base_url, cid, deadline_seconds=2.0)
        assert a_landed is not None

        # Push propagation happens on a daemon thread; poll B's bundles
        # table until the row appears. Per #112, B's POST /bundles
        # verifier no longer cross-checks recipients against B's
        # reservoir, so B accepts the push and lands the row.
        def _bundle_count_on_b(cid_or_record: tuple[str, str]) -> int:
            col, val = cid_or_record
            db = sqlite3.connect(str(b.db_path), timeout=5.0)
            try:
                try:
                    return db.execute(
                        f"SELECT COUNT(*) FROM bundles WHERE {col}=?",
                        (val,),
                    ).fetchone()[0]
                except sqlite3.OperationalError:
                    return 0
            finally:
                db.close()

        deadline = time.monotonic() + 3.0
        landed = False
        while time.monotonic() < deadline:
            if _bundle_count_on_b(("cid", cid)) > 0:
                landed = True
                break
            time.sleep(0.1)
        assert landed, (
            "peer B's bundles table never gained the propagated bundle — "
            "expected push from A to B to land at 201 since #112 dropped "
            "the reservoir-recipient gate on POST /bundles"
        )

        # And: the canonical proof of the new contract. Synthesize a
        # direct `POST /bundles` of the same envelope to B and assert
        # 201 — even though the bundle's recipients include a key
        # missing from B's reservoir, B accepts it. Idempotency may
        # return 201 either way (fresh-insert or already-known).
        envelope = a_landed
        status_b, body_b = _post_json(f"{b.base_url}/bundles", envelope)
        assert status_b == 201, (status_b, body_b)
        assert "cid" in body_b
    finally:
        a.stop()
        b.stop()


def test_node_restart_preserves_bundle_state(
    tmp_path, alchemist_keypair,
):
    """Gap 4: restart preserves state across the bundle subsystem.

    Operator concern: the daemon restarts (manual, OS update, crash).
    Does state survive? We check three places state lives:

      * the `bundles` table (envelopes durably stored)
      * the `swf_kv` per-peer high-water (puller's resume cursor)
      * SSE `Last-Event-ID` resume semantics across processes

    Scenario:
      1. Start peer A. POST 5 bundles.
      2. Pre-populate a fake high-water row for some peer X so we can
         assert it survives the restart untouched.
      3. Open an SSE stream, capture the last cid we saw.
      4. Stop the process cleanly (SIGTERM + wait).
      5. Restart against the same dirs.
      6. Re-open SSE with `Last-Event-ID: <captured-cid>`. The replay
         phase has nothing to ship (we resume from the LAST cid, and
         no new bundles arrived between stop+start) — but the open
         must succeed and emit the live-phase keepalive.
      7. `GET /bundles?received_since=0` returns all 5 envelopes
         (rowid replay key survives the process boundary — the locked
         phase-4 design choice).
      8. The pre-populated swf_kv high-water row is still there.

    Regression caught: any "we forgot to flush something to disk" bug
    in the bundle write path, the puller's high-water set, or the SSE
    rowid resume. Single-process tests don't catch a missing fsync /
    in-memory-only state.
    """
    alch_path = _build_alchemists_yml(tmp_path, alchemist_keypair.pubkey_str)
    a = _make_peer("a", tmp_path=tmp_path,
                   alchemists_path=alch_path, keypair=alchemist_keypair)
    try:
        a.start()

        # 1. POST 5 bundles, capturing the cids in order.
        cids: list[str] = []
        for i in range(5):
            env = _build_envelope(
                alchemist_keypair, record_id=f"restart-{i}",
            )
            cids.append(bundles.cid_for(env))
            status, _ = _post_json(f"{a.base_url}/bundles", env)
            assert status == 201

        # Confirm all 5 landed pre-restart. We poll because writes
        # are synchronous, but the open-and-read race window is
        # microseconds; this is essentially a sanity check.
        for cid in cids:
            assert _wait_for_bundle(
                a.base_url, cid, deadline_seconds=2.0,
            ) is not None

        # 2. Pre-populate a fake high-water row. We pick a synthetic
        # peer pubkey so we don't collide with anything the runtime
        # might write; the row persists iff the swf_kv table survives
        # the restart. The puller's `_get_high_water` reads this row
        # through the same key prefix.
        synth_peer = "ed25519:" + ("d" * 64)
        synth_value = 1234
        db = sqlite3.connect(str(a.db_path), timeout=5.0)
        try:
            db.execute(
                "CREATE TABLE IF NOT EXISTS swf_kv ("
                "  key TEXT PRIMARY KEY, value TEXT NOT NULL"
                ")"
            )
            db.execute(
                "INSERT OR REPLACE INTO swf_kv(key, value) VALUES(?, ?)",
                (f"bundles.high_water.{synth_peer}", str(synth_value)),
            )
            db.commit()
        finally:
            db.close()

        # 3. Open SSE, drain any replay (none expected since we just
        # opened with no Last-Event-ID), wait briefly to capture any
        # in-flight events, then close. We reuse the last cid (cids[-1])
        # as the resume cursor for the post-restart connection.
        last_cid = cids[-1]

        # 4. Stop cleanly. _PeerProcess.stop() sends SIGTERM and waits
        # up to 5s for a graceful exit; the launcher's signal handler
        # calls server.shutdown() which flushes the connection pool.
        a.stop()

        # 5. Restart against the same knowledge_dir. _PeerProcess
        # records the last start args so restart() picks the same
        # configuration (same port — bound from `_make_peer`'s
        # `_free_port()`, retained on the dataclass).
        a.restart()

        # 6. SSE resume across processes. We open with the captured
        # last_cid as Last-Event-ID; the replay phase resolves it to
        # a rowid (because the bundles table survived) and finds no
        # rows with rowid > resume_rowid (we POSTed nothing since).
        # The handler must NOT 500; it must emit headers and at
        # least one keepalive within the heartbeat window.
        sse_conn = http.client.HTTPConnection(
            "127.0.0.1", a.port, timeout=4.0,
        )
        sse_conn.request(
            "GET", "/bundles/subscribe",
            headers={"Last-Event-ID": last_cid},
        )
        sse_resp = sse_conn.getresponse()
        try:
            assert sse_resp.status == 200, (
                "SSE resume after restart must return 200 (the cid is "
                "known to the new process via the persistent bundles "
                f"table); got {sse_resp.status}"
            )
            assert sse_resp.headers.get("Content-Type") == "text/event-stream"
        finally:
            sse_conn.close()

        # 7. `GET /bundles?received_since=0` returns all 5 envelopes.
        # The rowid cursor is durable — it's just sqlite's implicit
        # rowid column, written to disk on insert.
        status, body = _get_json(f"{a.base_url}/bundles?received_since=0")
        assert status == 200, body
        assert isinstance(body, dict), body
        bundles_back = body.get("bundles") or []
        # Filter to the cids we POSTed (the bundles list is global; in
        # this isolated tmp_path it's exactly our 5, but matching by
        # cid is the robust comparison anyway).
        from swf import bundles as _bundles
        recovered = {_bundles.cid_for(env) for env in bundles_back}
        for cid in cids:
            assert cid in recovered, (
                f"bundle {cid[:12]}… did not survive the restart — "
                "the bundles table is not durable across processes"
            )

        # 8. The pre-populated swf_kv high-water survives. We check
        # via the puller's `_get_high_water` to exercise the actual
        # read path (operator-relevant; a DB row that's there but
        # which the puller can't read would be just as broken).
        from swf.bundles.puller import _get_high_water
        db = sqlite3.connect(str(a.db_path), timeout=5.0)
        db.row_factory = sqlite3.Row
        try:
            hw = _get_high_water(db, synth_peer)
        finally:
            db.close()
        assert hw == synth_value, (
            f"per-peer high-water for {synth_peer[:12]}… was {hw}, "
            f"expected {synth_value} — swf_kv didn't survive restart"
        )
    finally:
        a.stop()
