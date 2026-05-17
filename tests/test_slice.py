"""Tests for swf.slice — signed slices + RFC 6962 merkle root."""

from __future__ import annotations

import hashlib
import json

import pytest

from swf.slice import (
    Slice,
    _leaf_hash,
    _node_hash,
    build_slice,
    canonical_json,
    entry_leaf_bytes,
    inclusion_proof,
    merkle_root,
    verify_inclusion,
    verify_slice,
)

# ── Test fixtures ─────────────────────────────────────────────────────────


def _mk_entry(i: int) -> dict:
    return {
        "url": f"https://example.com/p{i}",
        "content_hash": f"sha256:{'a' * 63}{i}",
        "extractor": "trafilatura-2.0.0",
        "fetched_at": f"2026-04-{(i % 28) + 1:02d}T00:00:00Z",
        "final_url": f"https://example.com/p{i}",
    }


@pytest.fixture
def identity(tmp_path, monkeypatch):
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
    # Reset in case another test loaded already
    import sys

    for m in list(sys.modules):
        if m == "swf.identity":
            del sys.modules[m]
    from swf.identity import get_or_create_identity

    return get_or_create_identity()


# ── RFC 6962 merkle correctness ───────────────────────────────────────────


class TestMerkleBasics:
    def test_empty_root(self):
        assert merkle_root([]) == hashlib.sha256(b"").digest()

    def test_single_leaf(self):
        leaf = _leaf_hash(b"alpha")
        assert merkle_root([leaf]) == leaf

    def test_two_leaves(self):
        l1 = _leaf_hash(b"alpha")
        l2 = _leaf_hash(b"beta")
        assert merkle_root([l1, l2]) == _node_hash(l1, l2)

    def test_three_leaves_odd_promotion(self):
        """RFC 6962: odd final leaf promoted as-is at its level."""
        l1 = _leaf_hash(b"a")
        l2 = _leaf_hash(b"b")
        l3 = _leaf_hash(b"c")
        # Level 1: [node(l1,l2), l3]
        # Level 2: node(node(l1,l2), l3)
        expected = _node_hash(_node_hash(l1, l2), l3)
        assert merkle_root([l1, l2, l3]) == expected


class TestInclusionProof:
    @pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 15, 16, 31])
    def test_every_leaf_verifies(self, n):
        leaves = [_leaf_hash(f"leaf-{i}".encode()) for i in range(n)]
        root = merkle_root(leaves)
        for i in range(n):
            proof = inclusion_proof(leaves, i)
            assert verify_inclusion(leaves[i], i, n, proof, root), (
                f"leaf {i} of {n} failed inclusion proof"
            )

    def test_wrong_leaf_fails(self):
        leaves = [_leaf_hash(f"leaf-{i}".encode()) for i in range(8)]
        root = merkle_root(leaves)
        proof = inclusion_proof(leaves, 3)
        tampered = _leaf_hash(b"nope")
        assert not verify_inclusion(tampered, 3, 8, proof, root)

    def test_wrong_root_fails(self):
        leaves = [_leaf_hash(f"leaf-{i}".encode()) for i in range(8)]
        proof = inclusion_proof(leaves, 3)
        bad_root = hashlib.sha256(b"bad").digest()
        assert not verify_inclusion(leaves[3], 3, 8, proof, bad_root)


# ── Entry canonicalization ────────────────────────────────────────────────


class TestEntryCanonicalization:
    def test_key_order_irrelevant(self):
        a = {"url": "x", "content_hash": "h", "extractor": "e", "fetched_at": "t", "final_url": "x"}
        b = {"final_url": "x", "fetched_at": "t", "extractor": "e", "content_hash": "h", "url": "x"}
        assert entry_leaf_bytes(a) == entry_leaf_bytes(b)

    def test_extra_keys_ignored(self):
        base = {"url": "x", "content_hash": "h", "extractor": "e", "fetched_at": "t", "final_url": "x"}
        with_extras = {**base, "extra_key": "anything"}
        assert entry_leaf_bytes(base) == entry_leaf_bytes(with_extras)


# ── Slice build + verify ──────────────────────────────────────────────────


class TestSliceRoundtrip:
    def test_build_and_verify(self, identity):
        entries = [_mk_entry(i) for i in range(5)]
        s = build_slice(
            author_pubkey_b64=identity.pub_b64,
            seq=0,
            prev_hash="",
            entries=entries,
            identity=identity,
        )
        ok, reason = verify_slice(s, expected_author_pubkey=identity.pub_b64)
        assert ok, reason

    def test_dict_roundtrip_via_json(self, identity):
        entries = [_mk_entry(i) for i in range(3)]
        s = build_slice(
            author_pubkey_b64=identity.pub_b64,
            seq=0,
            prev_hash="",
            entries=entries,
            identity=identity,
        )
        # Simulate wire: serialize to dict, JSON-encode, decode, verify.
        wire = s.to_dict(include_sig=True)
        reparsed = json.loads(json.dumps(wire))
        ok, reason = verify_slice(reparsed, expected_author_pubkey=identity.pub_b64)
        assert ok, reason

    def test_tampered_entries_fail(self, identity):
        entries = [_mk_entry(i) for i in range(3)]
        s = build_slice(
            author_pubkey_b64=identity.pub_b64,
            seq=0,
            prev_hash="",
            entries=entries,
            identity=identity,
        )
        # Tamper: flip a content hash after signing
        tampered = s.to_dict(include_sig=True)
        tampered["entries"][1]["content_hash"] = "sha256:" + "f" * 64
        ok, reason = verify_slice(tampered)
        assert not ok
        # The merkle root mismatch is caught before the signature since
        # the root is easier to compute.
        assert "merkle root mismatch" in reason or "signature" in reason

    def test_tampered_signature_fails(self, identity):
        entries = [_mk_entry(i) for i in range(3)]
        s = build_slice(
            author_pubkey_b64=identity.pub_b64,
            seq=0,
            prev_hash="",
            entries=entries,
            identity=identity,
        )
        bad = s.to_dict(include_sig=True)
        # Flip a bit in the sig (b64url modification)
        bad_sig = list(bad["sig"])
        bad_sig[5] = "A" if bad_sig[5] != "A" else "B"
        bad["sig"] = "".join(bad_sig)
        ok, reason = verify_slice(bad)
        assert not ok
        assert "signature" in reason.lower()

    def test_wrong_author_fails(self, identity):
        entries = [_mk_entry(i) for i in range(3)]
        s = build_slice(
            author_pubkey_b64=identity.pub_b64,
            seq=0,
            prev_hash="",
            entries=entries,
            identity=identity,
        )
        ok, reason = verify_slice(s, expected_author_pubkey="someone-else-pubkey")
        assert not ok
        assert "author mismatch" in reason


class TestSliceChain:
    def test_chain_linked_correctly(self, identity):
        entries1 = [_mk_entry(i) for i in range(3)]
        s1 = build_slice(
            author_pubkey_b64=identity.pub_b64,
            seq=0,
            prev_hash="",
            entries=entries1,
            identity=identity,
        )
        ch1 = s1.content_hash()
        entries2 = [_mk_entry(i + 3) for i in range(3)]
        s2 = build_slice(
            author_pubkey_b64=identity.pub_b64,
            seq=1,
            prev_hash=ch1,
            entries=entries2,
            identity=identity,
        )
        ok, _ = verify_slice(s2, expected_prev_hash=ch1)
        assert ok

    def test_chain_break_detected(self, identity):
        entries1 = [_mk_entry(i) for i in range(3)]
        s1 = build_slice(
            author_pubkey_b64=identity.pub_b64,
            seq=0,
            prev_hash="",
            entries=entries1,
            identity=identity,
        )
        entries2 = [_mk_entry(i + 3) for i in range(3)]
        # Attacker sets prev_hash wrong
        s2 = build_slice(
            author_pubkey_b64=identity.pub_b64,
            seq=1,
            prev_hash="attackers-fake-prev-hash",
            entries=entries2,
            identity=identity,
        )
        ok, reason = verify_slice(s2, expected_prev_hash=s1.content_hash())
        assert not ok
        assert "prev_hash mismatch" in reason
