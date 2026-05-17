"""Tests for swf.digest — bloom filter with per-recipient salting."""

from __future__ import annotations

import os

import pytest

from swf.digest import (
    build_filter,
    contains,
    filter_stats,
    generate_circle_secret,
    load_circle_secret,
)

KNOWN_URLS = [
    "https://alice.example.com/paper-on-mixnets",
    "https://bob.example.com/onion-routing-post",
    "https://carol.example.com/post-quantum-survey",
    "https://vitalik.eth.limo/general/2026/04/02/secure_llms.html",
    "https://en.wikipedia.org/wiki/Mix_network",
]


ALICE_PK = "alice_fake_pubkey_" + "a" * 20
BOB_PK = "bob_fake_pubkey_" + "b" * 22


class TestMembership:
    def test_all_inserted_urls_are_present(self):
        blob = build_filter(KNOWN_URLS, recipient_pubkey_b64=ALICE_PK)
        for u in KNOWN_URLS:
            assert contains(blob, u, ALICE_PK), f"false negative for {u}"

    def test_random_urls_mostly_absent(self):
        blob = build_filter(KNOWN_URLS, recipient_pubkey_b64=ALICE_PK, target_fp=0.01)
        not_in_set = [
            "https://example.com/totally-different-topic-" + str(i)
            for i in range(100)
        ]
        fp_count = sum(1 for u in not_in_set if contains(blob, u, ALICE_PK))
        # With target_fp=0.01, we expect ~1 hit per 100. Allow up to 5.
        assert fp_count <= 5, f"too many false positives: {fp_count}/100"


class TestPerRecipientSalting:
    def test_alice_filter_does_not_work_for_bob(self):
        alice_blob = build_filter(KNOWN_URLS, recipient_pubkey_b64=ALICE_PK)
        # Testing Alice's filter with Bob's pubkey should raise (wrong salt).
        with pytest.raises(ValueError, match="salt mismatch"):
            contains(alice_blob, KNOWN_URLS[0], BOB_PK)

    def test_circle_secret_changes_salt(self):
        blob_no_secret = build_filter(KNOWN_URLS, recipient_pubkey_b64=ALICE_PK)
        blob_secret = build_filter(
            KNOWN_URLS, recipient_pubkey_b64=ALICE_PK, circle_secret=b"\x01" * 32
        )
        # Different filters because salt differs
        assert blob_no_secret != blob_secret
        # Each works with its own secret
        assert contains(blob_no_secret, KNOWN_URLS[0], ALICE_PK)
        assert contains(blob_secret, KNOWN_URLS[0], ALICE_PK, circle_secret=b"\x01" * 32)
        # Cross-use fails
        with pytest.raises(ValueError):
            contains(blob_secret, KNOWN_URLS[0], ALICE_PK)


class TestSizeAndStats:
    def test_reasonable_size_at_scale(self):
        """180k URLs at 1% FP should land near the theoretical ~216 KB."""
        urls = [f"https://example.com/page-{i}" for i in range(180_000)]
        blob = build_filter(urls, recipient_pubkey_b64=ALICE_PK, target_fp=0.01)
        # m ≈ -n*ln(0.01)/(ln2)^2 ≈ 9.585 bits/key * 180k = 1.725M bits ≈ 215KB
        # plus header (~46 bytes). Allow slack for rounding.
        assert 215_000 <= len(blob) <= 230_000, f"size {len(blob)} outside expected range"

    def test_stats_are_sensible(self):
        blob = build_filter(KNOWN_URLS, recipient_pubkey_b64=ALICE_PK, target_fp=0.01)
        stats = filter_stats(blob)
        assert stats["version"] == 1
        assert stats["n_items"] == len(KNOWN_URLS)
        assert stats["k"] >= 1
        assert 0.0 <= stats["fill_ratio"] <= 1.0


class TestEmpty:
    def test_empty_urls_builds_header_only(self):
        blob = build_filter([], recipient_pubkey_b64=ALICE_PK)
        stats = filter_stats(blob)
        assert stats["n_items"] == 0
        # Never a false positive in an empty filter (unless hash collides,
        # but m=64 bits empty is truly empty).
        assert not contains(blob, KNOWN_URLS[0], ALICE_PK)


class TestHeaderValidation:
    def test_bad_magic(self):
        with pytest.raises(ValueError, match="bad magic"):
            contains(b"XXXX" + b"\x00" * 50, "url", ALICE_PK)

    def test_truncated(self):
        with pytest.raises(ValueError):
            contains(b"SWF1" + b"\x00" * 5, "url", ALICE_PK)


class TestCircleSecretStorage:
    def test_generate_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        secret = generate_circle_secret()
        assert len(secret) == 32
        loaded = load_circle_secret()
        assert loaded == secret

    def test_load_absent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
        assert load_circle_secret() is None


# ── Integration: a peer's /digest/urls returns a filter that recognizes
#   its own URLs and rejects stranger URLs. ──────────────────────────────


class TestPeerDigestEndpoint:
    def test_digest_endpoint_returns_working_filter(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
        kdir = tmp_path / "wk"
        (kdir / "web").mkdir(parents=True)
        monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(kdir))

        # Seed with known URLs
        import importlib
        import sys

        for mod in list(sys.modules):
            if mod in (
                "swf.peer_server",
                "swf.web.knowledge",
                "swf.web.index",
                "swf.identity",
            ):
                del sys.modules[mod]

        from swf.web.knowledge import world_write

        sigil_url = "https://sigil.example.com/target-page"
        other_url = "https://other.example.com/unrelated"

        world_write(
            sigil_url, "content with sigil-ABC", extractor="test", title="Target"
        )
        world_write(
            other_url, "content with other-XYZ", extractor="test", title="Other"
        )

        # Start the peer server
        peer_server = importlib.import_module("swf.peer_server")
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)

        try:
            import urllib.parse
            import urllib.request

            recipient_pk = "recipient_test_pk_" + "x" * 25
            url = (
                f"http://127.0.0.1:{port}/digest/urls"
                f"?recipient_pk={urllib.parse.quote(recipient_pk)}&target_fp=0.01"
            )
            with urllib.request.urlopen(url, timeout=5) as resp:
                blob = resp.read()

            # The seeded URLs are present
            assert contains(blob, sigil_url, recipient_pk)
            assert contains(blob, other_url, recipient_pk)

            # URLs never seeded should mostly be absent (with <5% FP at
            # this scale — the seeded set is tiny so fill-ratio is low)
            missing_hits = sum(
                1
                for u in (
                    f"https://nope.example.com/page-{i}" for i in range(100)
                )
                if contains(blob, u, recipient_pk)
            )
            assert missing_hits <= 5
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
