"""Tests for swf.discovery and the `swf-peer discover/sync` CLI paths.

We do NOT rely on a real mDNS responder being on the test host; instead
we monkeypatch the internals to return known fixtures. A full LAN-mDNS
round-trip test is too flaky for CI (firewalls, client isolation, etc).
"""

from __future__ import annotations

import pytest

from swf.discovery import DiscoveredPeer, discover_all_peers


class TestDiscoveredPeer:
    def test_to_peer_preserves_fields(self):
        dp = DiscoveredPeer(
            name="alice",
            url="http://127.0.0.1:7777",
            source="mdns",
            pubkey="abc123",
        )
        p = dp.to_peer()
        assert p.name == "alice"
        assert p.url == "http://127.0.0.1:7777"
        assert p.pubkey == "abc123"


class TestUnionPrecedence:
    """config > mDNS > Tailscale on URL collision."""

    def test_config_wins_over_mdns(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.peers import Peer, PeerConfig, save_peers

        save_peers(PeerConfig(peers=[
            Peer(name="alice-hand", url="http://192.168.1.5:7777", pubkey="pinned-pk"),
        ]))

        import swf.discovery as d
        monkeypatch.setattr(
            d, "browse_mdns",
            lambda timeout=1.5: [
                DiscoveredPeer(name="mdns-name", url="http://192.168.1.5:7777", source="mdns")
            ],
        )
        monkeypatch.setattr(d, "detect_tailscale_peers", lambda timeout=2.0: [])

        out = d.discover_all_peers(mdns_timeout=0.0)
        # Only one entry for that URL; config wins (pinned pubkey preserved).
        matching = [p for p in out if p.url == "http://192.168.1.5:7777"]
        assert len(matching) == 1
        assert matching[0].source == "config"
        assert matching[0].pubkey == "pinned-pk"

    def test_mdns_plus_new_tailscale(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.peers import PeerConfig, save_peers

        save_peers(PeerConfig(peers=[]))

        import swf.discovery as d
        monkeypatch.setattr(
            d, "browse_mdns",
            lambda timeout=1.5: [
                DiscoveredPeer(name="bob-laptop", url="http://192.168.1.7:7777", source="mdns"),
            ],
        )
        monkeypatch.setattr(
            d, "detect_tailscale_peers",
            lambda timeout=2.0: [
                DiscoveredPeer(name="carol-desktop", url="http://100.64.0.3:7777", source="tailscale"),
            ],
        )

        out = d.discover_all_peers(mdns_timeout=0.0)
        names = [p.name for p in out]
        assert "bob-laptop" in names
        assert "carol-desktop" in names


class TestSyncCommand:
    """`swf-peer sync` appends new discoveries without clobbering pins."""

    def test_sync_adds_new_preserves_existing(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.peers import Peer, PeerConfig, load_peers, save_peers

        # Existing hand-pinned peer
        save_peers(PeerConfig(peers=[
            Peer(name="alice", url="http://192.168.1.5:7777", pubkey="pinned-pk"),
        ]))

        # Monkeypatch discovery to return one known (alice) and one new (bob)
        import swf.discovery as d
        monkeypatch.setattr(
            d, "browse_mdns",
            lambda timeout=1.5: [
                DiscoveredPeer(name="alice", url="http://192.168.1.5:7777", source="mdns"),
                DiscoveredPeer(name="bob-laptop", url="http://192.168.1.7:7777", source="mdns"),
            ],
        )
        monkeypatch.setattr(d, "detect_tailscale_peers", lambda timeout=2.0: [])

        # Run the sync command
        from swf.peer_cli import _cmd_sync

        class Args:
            pass
        rc = _cmd_sync(Args())
        assert rc == 0

        # Alice is untouched (still has pinned pubkey), bob-laptop added
        # with auto-mdns-* prefix.
        loaded = load_peers()
        alice = next(p for p in loaded.peers if p.name == "alice")
        assert alice.pubkey == "pinned-pk"
        assert any(p.url == "http://192.168.1.7:7777" for p in loaded.peers)
        auto_bob = next(p for p in loaded.peers if p.url == "http://192.168.1.7:7777")
        assert auto_bob.name.startswith("auto-mdns-")
