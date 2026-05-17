"""Tests for swf.identity and the signed /.well-known/indrex handshake."""

from __future__ import annotations

import json
import os
import shutil
import socket
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

# ── Unit: keypair roundtrip, sign/verify, fingerprints ──────────────────────


class TestKeypair:
    def test_generate_and_persist(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.identity import get_or_create_identity

        ident = get_or_create_identity()
        assert ident.pub_b64
        assert len(ident.pub_b64) >= 40  # b64url of 32 bytes
        # Private key file should be exactly 32 bytes, mode 0600 on posix
        priv_path = tmp_path / "identity.key"
        pub_path = tmp_path / "identity.pub"
        assert priv_path.exists()
        assert pub_path.exists()
        assert len(priv_path.read_bytes()) == 32
        if os.name == "posix":
            mode = priv_path.stat().st_mode & 0o777
            assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_persisted_identity_stable_across_loads(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.identity import get_or_create_identity

        a = get_or_create_identity()
        b = get_or_create_identity()
        assert a.pub_b64 == b.pub_b64


class TestSignVerify:
    def test_sign_verifies_with_pubkey(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.identity import get_or_create_identity, verify

        ident = get_or_create_identity()
        data = b"hello searxng-wth-frnds"
        sig = ident.sign(data)
        assert verify(ident.pub_b64, data, sig)

    def test_tampered_data_fails(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.identity import get_or_create_identity, verify

        ident = get_or_create_identity()
        sig = ident.sign(b"original")
        assert not verify(ident.pub_b64, b"tampered", sig)

    def test_wrong_pubkey_fails(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from swf.identity import get_or_create_identity, pubkey_to_b64, verify

        ident = get_or_create_identity()
        sig = ident.sign(b"data")

        other = Ed25519PrivateKey.generate().public_key()
        assert not verify(pubkey_to_b64(other), b"data", sig)

    def test_verify_b64_sig(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.identity import get_or_create_identity, verify

        ident = get_or_create_identity()
        sig_b64 = ident.sign_b64(b"hi")
        assert verify(ident.pub_b64, b"hi", sig_b64)


class TestFingerprint:
    def test_fingerprint_stable(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from swf.identity import get_or_create_identity, pubkey_fingerprint

        ident = get_or_create_identity()
        fp1 = pubkey_fingerprint(ident.pub_b64)
        fp2 = pubkey_fingerprint(ident.pub_b64)
        assert fp1 == fp2
        assert len(fp1) == 16  # 8 bytes hex

    def test_different_keys_different_fingerprints(self, tmp_path, monkeypatch):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from swf.identity import pubkey_fingerprint, pubkey_to_b64

        a = pubkey_to_b64(Ed25519PrivateKey.generate().public_key())
        b = pubkey_to_b64(Ed25519PrivateKey.generate().public_key())
        assert pubkey_fingerprint(a) != pubkey_fingerprint(b)


# ── Integration: live peer_server signs /.well-known/indrex, TOFU captures ─


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def peer_with_identity(tmp_path, monkeypatch):
    """Start a peer_server backed by an isolated SWF_CONFIG_DIR (so its
    identity is deterministic and we don't interfere with the user's)."""
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "config"))
    kdir = tmp_path / "wk"
    (kdir / "web").mkdir(parents=True)
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(kdir))

    # Re-import peer_server fresh so its module-level DB path picks up our dir.
    import importlib
    import sys

    for mod in list(sys.modules):
        if mod in ("swf.peer_server", "swf.identity", "swf.web.knowledge"):
            del sys.modules[mod]
    peer_server = importlib.import_module("swf.peer_server")

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    try:
        yield {"port": port, "url": f"http://127.0.0.1:{port}", "config_dir": tmp_path / "config"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class TestSignedHandshake:
    def _fetch(self, url: str) -> dict:
        with urllib.request.urlopen(url + "/.well-known/indrex", timeout=3) as resp:
            return json.loads(resp.read())

    def test_indrex_response_has_pubkey_and_sig(self, peer_with_identity):
        p = peer_with_identity
        data = self._fetch(p["url"])
        assert data.get("pubkey"), data
        assert data.get("sig"), data
        assert data.get("ts"), data
        assert data.get("body_hash"), data
        assert data.get("fingerprint")

    def test_signature_verifies(self, peer_with_identity):
        p = peer_with_identity
        data = self._fetch(p["url"])

        from swf.identity import canonical_indrex_response, verify

        canonical = canonical_indrex_response(
            pubkey_b64=data["pubkey"],
            node=data["name"],
            ts=data["ts"],
            body_hash=data["body_hash"],
        )
        assert verify(data["pubkey"], canonical, data["sig"])


class TestTofuPin:
    """`swf-peer add` captures the peer's pubkey and refuses to pin if
    the signature is missing/bad."""

    def test_add_captures_pubkey(self, peer_with_identity, monkeypatch, capsys, tmp_path):
        p = peer_with_identity
        # peers.yaml lives in the same isolated dir as the identity
        monkeypatch.setenv("SWF_CONFIG_DIR", str(p["config_dir"]))

        from argparse import Namespace

        from swf.peer_cli import _cmd_add
        from swf.peers import load_peers

        rc = _cmd_add(Namespace(name="self", url=p["url"]))
        assert rc == 0
        loaded = load_peers()
        assert len(loaded.peers) == 1
        assert loaded.peers[0].url == p["url"]
        # The pubkey should be the one the server reports
        data = json.loads(
            urllib.request.urlopen(
                p["url"] + "/.well-known/indrex", timeout=3
            ).read()
        )
        assert loaded.peers[0].pubkey == data["pubkey"]

    def test_add_without_server_leaves_pubkey_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        from argparse import Namespace

        from swf.peer_cli import _cmd_add
        from swf.peers import load_peers

        # Use a guaranteed-unreachable port; probe fails silently.
        rc = _cmd_add(Namespace(name="ghost", url="http://127.0.0.1:1"))
        assert rc == 0
        loaded = load_peers()
        assert loaded.peers[0].pubkey is None
