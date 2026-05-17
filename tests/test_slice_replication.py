"""End-to-end slice replication: Alice publishes, Bob pulls, Bob searches.

Proves the architectural promise of 0.8: queries stay local, content
flows peer-to-peer via signed slices. No query-time HTTP fan-out in
the normal path.
"""

from __future__ import annotations

import importlib
import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest

SIGIL_URL = "https://slice-test.example.com/target-post"
SIGIL_TEXT = "SIGIL-WTHFRND-SLICE-9f3c1a-UNIQUE-PHRASE"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _reset_swf_modules():
    """Force-reimport swf.* + swf.web.* so env vars take."""
    for m in list(sys.modules):
        if m.startswith("swf.") or m.startswith("swf.web."):
            del sys.modules[m]


@pytest.fixture
def alice_peer(tmp_path, monkeypatch):
    """A running peer_server with Alice's identity, world_knowledge, and
    slices directory isolated under tmp_path."""
    alice_root = tmp_path / "alice"
    (alice_root / "wk" / "web").mkdir(parents=True)
    (alice_root / "cfg").mkdir(parents=True)

    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(alice_root / "wk"))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(alice_root / "cfg"))
    _reset_swf_modules()

    # Seed Alice's indrex with the sigil URL inside search_results.
    # Use record_search_results directly so it lands in the table the
    # publisher reads.
    from swf.web.index import record_search_results

    n = record_search_results(
        query="alice-seed-query",
        results=[
            {
                "url": SIGIL_URL,
                "title": "Alice's Unique Post on Mixnets",
                "snippet": SIGIL_TEXT + " discussing p2p search.",
            }
        ],
        engines="alice-local",
    )
    assert n == 1

    # Publish a slice containing it
    from swf.slice_publish import publish

    outcome = publish()
    assert not outcome.skipped, outcome.reason
    assert outcome.entries == 1

    # Start peer_server on a free port
    peer_server = importlib.import_module("swf.peer_server")
    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)

    yield {
        "port": port,
        "url": f"http://127.0.0.1:{port}",
        "root": alice_root,
        "pubkey": _read_identity_pubkey(alice_root / "cfg"),
    }

    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def _read_identity_pubkey(cfg_dir: Path) -> str:
    pub_file = cfg_dir / "identity.pub"
    return pub_file.read_text().strip() if pub_file.exists() else ""


class TestSliceEndpoints:
    def test_head_returns_alice_seq(self, alice_peer):
        import urllib.request

        with urllib.request.urlopen(alice_peer["url"] + "/slices/head", timeout=3) as resp:
            data = json.loads(resp.read())
        assert data["seq"] == 0
        assert data["hash"]

    def test_slice_returns_entries(self, alice_peer):
        import urllib.request

        with urllib.request.urlopen(alice_peer["url"] + "/slices/0", timeout=3) as resp:
            slice_data = json.loads(resp.read())
        assert slice_data["seq"] == 0
        assert slice_data["author"] == alice_peer["pubkey"]
        assert slice_data["sig"]
        assert slice_data["merkle_root"]
        assert len(slice_data["entries"]) == 1
        assert slice_data["entries"][0]["url"] == SIGIL_URL

    def test_slice_not_found(self, alice_peer):
        import urllib.error
        import urllib.request

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(alice_peer["url"] + "/slices/999", timeout=3)
        assert exc_info.value.code == 404


class TestE2EReplication:
    def test_bob_pulls_and_finds(self, alice_peer, tmp_path, monkeypatch):
        """The big one: Bob has an empty indrex, adds Alice as a peer,
        syncs, and his local_search now finds Alice's sigil."""
        # Switch to Bob's isolated config
        bob_root = tmp_path / "bob"
        (bob_root / "wk" / "web").mkdir(parents=True)
        (bob_root / "cfg").mkdir(parents=True)

        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(bob_root / "wk"))
        monkeypatch.setenv("SWF_CONFIG_DIR", str(bob_root / "cfg"))
        _reset_swf_modules()

        # Add Alice as Bob's peer
        from swf.peers import Peer, PeerConfig, save_peers
        save_peers(PeerConfig(peers=[
            Peer(name="alice", url=alice_peer["url"], pubkey=alice_peer["pubkey"]),
        ]))

        # Baseline: Bob has no content
        from swf.indrex import query as indrex_query
        pre = indrex_query(SIGIL_TEXT)
        assert pre == [], "Bob should start with an empty indrex"

        # Run the sync
        from swf.peers import load_peers
        from swf.slice_consume import sync_from_peer
        alice = next(p for p in load_peers().peers if p.name == "alice")
        outcome = sync_from_peer(alice)
        assert outcome.error is None, outcome.error
        assert outcome.pulled == 1
        assert outcome.verified == 1
        assert outcome.merged == 1

        # Verify: Bob's local indrex now surfaces Alice's content
        post = indrex_query(SIGIL_TEXT)
        assert len(post) >= 1
        found_urls = [r.url for r in post]
        assert SIGIL_URL in found_urls

    def test_bob_second_sync_is_noop(self, alice_peer, tmp_path, monkeypatch):
        """Running sync twice should not pull anything the second time
        (state file tracks last_seq)."""
        bob_root = tmp_path / "bob2"
        (bob_root / "wk" / "web").mkdir(parents=True)
        (bob_root / "cfg").mkdir(parents=True)

        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(bob_root / "wk"))
        monkeypatch.setenv("SWF_CONFIG_DIR", str(bob_root / "cfg"))
        _reset_swf_modules()

        from swf.peers import Peer, PeerConfig, save_peers
        save_peers(PeerConfig(peers=[
            Peer(name="alice", url=alice_peer["url"], pubkey=alice_peer["pubkey"]),
        ]))

        from swf.peers import load_peers
        from swf.slice_consume import sync_from_peer
        alice = next(p for p in load_peers().peers if p.name == "alice")

        first = sync_from_peer(alice)
        assert first.pulled == 1

        second = sync_from_peer(alice)
        assert second.pulled == 0
        assert second.head_seq == first.head_seq

    def test_bob_rejects_tampered_slice(self, tmp_path, monkeypatch):
        """If we mess with the slice JSON after Alice signed it, Bob's
        verify step rejects it and doesn't merge."""
        # Set up Alice's slice
        alice_root = tmp_path / "alice_tamper"
        (alice_root / "wk" / "web").mkdir(parents=True)
        (alice_root / "cfg").mkdir(parents=True)
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(alice_root / "wk"))
        monkeypatch.setenv("SWF_CONFIG_DIR", str(alice_root / "cfg"))
        _reset_swf_modules()

        from swf.slice_publish import publish, slices_dir
        from swf.web.index import record_search_results

        record_search_results(
            query="seed", results=[{"url": SIGIL_URL, "title": "t", "snippet": "s"}],
            engines="alice",
        )
        publish()
        import swf.identity as ident_mod
        alice_pub = ident_mod.get_or_create_identity().pub_b64

        # Tamper with the slice on disk
        slice_file = next(slices_dir().glob("000000-*.json"))
        data = json.loads(slice_file.read_text())
        data["entries"][0]["url"] = "https://attacker.example.com/rewritten"
        slice_file.write_text(json.dumps(data, indent=2))

        # Start Alice's peer
        peer_server = importlib.import_module("swf.peer_server")
        port = _free_port()
        server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)

        try:
            # Switch to Bob
            bob_root = tmp_path / "bob_tamper"
            (bob_root / "wk" / "web").mkdir(parents=True)
            (bob_root / "cfg").mkdir(parents=True)
            monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(bob_root / "wk"))
            monkeypatch.setenv("SWF_CONFIG_DIR", str(bob_root / "cfg"))
            _reset_swf_modules()

            from swf.peers import Peer, PeerConfig, save_peers
            save_peers(PeerConfig(peers=[
                Peer(name="alice", url=f"http://127.0.0.1:{port}", pubkey=alice_pub),
            ]))

            from swf.peers import load_peers
            from swf.slice_consume import sync_from_peer
            alice = next(p for p in load_peers().peers if p.name == "alice")
            outcome = sync_from_peer(alice)
            assert outcome.error is not None
            assert "verify" in outcome.error.lower() or "merkle" in outcome.error.lower()
            assert outcome.merged == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
