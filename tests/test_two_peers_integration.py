"""Two real peers on localhost, each with a different world_knowledge/.

Spins up two `ThreadingHTTPServer` peer instances via `swf.peer_server`,
seeds each with distinctive content, then queries each peer from the
other side to prove p2p flow end-to-end. No crypto, no discovery, no
searxng; just the HTTP transport that the `local_friends` searxng
engine uses.

Each peer gets its own sqlite DB (pointed at a temporary
world_knowledge dir). They run on different localhost ports.

Run with: `.venv/bin/pytest tests/test_two_peers_integration.py -q`
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

# Marker so CI's default `-m 'not integration'` skips this whole module.
# Run explicitly with `pytest -m integration` or in the dedicated
# integration job.
pytestmark = pytest.mark.integration


# ── Test harness ───────────────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PeerFixture:
    """One peer: its own world_knowledge dir, its own sqlite DB, its
    own HTTP server on a free port. Tears down cleanly.
    """

    def __init__(self, label: str):
        self.label = label
        self.tmpdir = Path(tempfile.mkdtemp(prefix=f"swf-test-{label}-"))
        self.knowledge_dir = self.tmpdir / "world_knowledge"
        (self.knowledge_dir / "web").mkdir(parents=True)
        self.port = _free_port()
        self._server = None
        self._thread = None

    def seed(self, url: str, title: str, content: str) -> None:
        """Write a page through the swf.web knowledge/index pipeline
        under this peer's isolated world_knowledge dir.
        """
        os.environ["RA_WORLD_KNOWLEDGE_DIR"] = str(self.knowledge_dir)
        os.environ["RA_WORLD_KNOWLEDGE"] = "1"
        # Reset the world_knowledge module's cached root (if any) by re-
        # importing — but the helpers compute knowledge_root() each call,
        # so just setting env is enough.
        from swf.web.knowledge import world_write

        world_write(url, content, extractor="test", title=title)

    def start(self) -> None:
        """Start the HTTP server in a background thread, pointed at this
        peer's DB. We set RA_WORLD_KNOWLEDGE_DIR in env so peer_server's
        import-time DB path resolution uses our isolated dir.
        """
        os.environ["RA_WORLD_KNOWLEDGE_DIR"] = str(self.knowledge_dir)
        # peer_server captures _DB_PATH at import time; force fresh import
        # by invalidating sys.modules.
        import importlib
        import sys

        for modname in list(sys.modules):
            if modname in (
                "swf.peer_server",
                "swf.web.knowledge",
            ):
                del sys.modules[modname]
        peer_server = importlib.import_module("swf.peer_server")
        # Sanity: make sure peer_server picked up our isolated dir.
        assert str(self.knowledge_dir) in str(peer_server._DB_PATH), (
            f"peer_server._DB_PATH = {peer_server._DB_PATH} "
            f"did not pick up {self.knowledge_dir}"
        )
        self._server, self._thread = peer_server.serve_in_thread(
            bind="127.0.0.1", port=self.port
        )

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def http_get(self, path: str, **params) -> dict:
        url = self.url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        with urllib.request.urlopen(url, timeout=5.0) as resp:
            return json.loads(resp.read())


# ── The test ───────────────────────────────────────────────────────────────


SIGIL_ALICE = "WTHFRND-ALICE-ATTESTATION-9f3c1a"
SIGIL_BOB = "WTHFRND-BOB-ATTESTATION-4e8b27"


@pytest.fixture
def alice_and_bob():
    """Two peers with distinct content. Each one's content contains a
    SIGIL string that only appears in their own archive, so we can prove
    cross-peer queries actually crossed."""
    alice = PeerFixture("alice")
    bob = PeerFixture("bob")

    alice.seed(
        url="https://alice.example.com/my-paper",
        title="Alice's Paper on Privacy-Preserving Meta-Search",
        content=(
            "This is Alice's local note. It uniquely contains the sigil "
            f"{SIGIL_ALICE}. It also discusses mixnets and the role of "
            "anonymity in friend-to-friend networks."
        ),
    )
    bob.seed(
        url="https://bob.example.com/my-post",
        title="Bob on Onion Routing Benchmarks",
        content=(
            "This is Bob's local note. It uniquely contains the sigil "
            f"{SIGIL_BOB}. It also contains benchmarks of onion routing "
            "versus mixnets under realistic load."
        ),
    )

    alice.start()
    bob.start()

    try:
        yield alice, bob
    finally:
        alice.stop()
        bob.stop()


class TestPeerEndpoints:
    def test_health(self, alice_and_bob):
        alice, _ = alice_and_bob
        r = alice.http_get("/health")
        assert r["ok"] is True
        assert r["version"]

    def test_well_known_indrex(self, alice_and_bob):
        alice, _ = alice_and_bob
        r = alice.http_get("/.well-known/indrex")
        assert r["protocol"].startswith("searxng-wth-frnds")
        assert "search" in r["capabilities"]
        # Alice should report at least one page
        assert r["stats"]["pages"] >= 1

    def test_search_finds_own_content(self, alice_and_bob):
        alice, _ = alice_and_bob
        r = alice.http_get("/search", q=SIGIL_ALICE)
        assert r["query"] == SIGIL_ALICE
        assert len(r["results"]) >= 1
        assert any(SIGIL_ALICE in hit["snippet"] for hit in r["results"])

    def test_search_does_not_find_others_content(self, alice_and_bob):
        """Alice must NOT return Bob's sigil; isolation confirmed."""
        alice, _ = alice_and_bob
        r = alice.http_get("/search", q=SIGIL_BOB)
        # Alice's DB has nothing matching Bob's sigil
        assert all(SIGIL_BOB not in (hit["snippet"] + hit["title"]) for hit in r["results"])


class TestP2PFlow:
    """Bob's swarm queries Alice's peer_server and gets Alice's content.

    This is the "friend's indrex via p2p" story the user cares about.
    """

    def test_bob_retrieves_alice_content_via_http(self, alice_and_bob):
        alice, bob = alice_and_bob
        # From Bob's side: configure Alice as the only peer and issue a
        # query containing Alice's sigil. The local_friends engine would
        # do this behind the scenes inside searxng; we simulate the HTTP
        # call directly here since we're not running the searxng container.
        req = urllib.request.Request(
            alice.url + "/search?" + urllib.parse.urlencode({"q": SIGIL_ALICE}),
            headers={"User-Agent": "test-bob"},
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            payload = json.loads(resp.read())

        assert len(payload["results"]) >= 1
        hit = payload["results"][0]
        assert hit["url"].startswith("https://alice.example.com")
        assert SIGIL_ALICE in hit["snippet"]
        # And the peer header identifies who served it.
        assert payload["peer"]  # hostname or SWF_NODE_NAME

    def test_alice_retrieves_bob_content_via_http(self, alice_and_bob):
        alice, bob = alice_and_bob
        req = urllib.request.Request(
            bob.url + "/search?" + urllib.parse.urlencode({"q": SIGIL_BOB}),
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            payload = json.loads(resp.read())
        assert len(payload["results"]) >= 1
        assert SIGIL_BOB in payload["results"][0]["snippet"]

    def test_query_with_no_matches_returns_empty(self, alice_and_bob):
        alice, _ = alice_and_bob
        req = urllib.request.Request(
            alice.url + "/search?" + urllib.parse.urlencode(
                {"q": "unrelated-term-that-should-not-match-anywhere"}
            ),
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            payload = json.loads(resp.read())
        assert payload["results"] == []


class TestPeersYamlRoundtrip:
    """`swf-peer add/list/remove` round-trips correctly."""

    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.peers import Peer, PeerConfig, load_peers, save_peers

        cfg = PeerConfig(
            peers=[
                Peer(name="alice", url="http://127.0.0.1:7777"),
                Peer(name="bob", url="http://127.0.0.1:7778", pubkey="abc123"),
            ]
        )
        save_peers(cfg)
        loaded = load_peers()
        assert len(loaded.peers) == 2
        assert loaded.peers[0].name == "alice"
        assert loaded.peers[1].pubkey == "abc123"

    def test_load_absent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.peers import load_peers

        cfg = load_peers()
        assert cfg.peers == []
