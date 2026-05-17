"""Shared fixtures for bundle tests.

Provides:
  - `alchemist_keypair` — a fresh Ed25519 keypair with the canonical
    `ed25519:<hex>` pubkey string the verifier expects.
  - `make_envelope` — a factory that builds a fully-signed envelope
    around any payload + alchemist key.
  - `alchemists_with` — turn a list of pubkey strings into an
    `AlchemistList` without writing a file.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swf.bundles import sign_envelope
from swf.bundles.alchemists import AlchemistList


@dataclass
class _Keypair:
    priv: Ed25519PrivateKey
    pub_hex: str           # raw 64-char hex
    pubkey_str: str        # ed25519:<hex>


def _make_keypair() -> _Keypair:
    priv = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = raw.hex()
    return _Keypair(priv=priv, pub_hex=pub_hex, pubkey_str=f"ed25519:{pub_hex}")


@pytest.fixture
def alchemist_keypair() -> _Keypair:
    return _make_keypair()


@pytest.fixture
def make_keypair():
    """Factory in case a test needs more than one alchemist."""
    return _make_keypair


@pytest.fixture
def make_envelope(alchemist_keypair):
    """Factory for fully-signed bundle envelopes.

    Defaults to a `cohort.surface` bundle with a small JSON payload.
    Pass overrides as kwargs (e.g. `kind="cohort.depth"`,
    `version=2`, `record_id="alice"`).
    """

    def _build(
        *,
        kind: str = "cohort.surface",
        record_id: str = "alice",
        version: int = 0,
        signed_at: str = "2026-05-04T12:00:00Z",
        payload: bytes = b'{"hello":"world"}',
        encryption: dict[str, Any] | None = None,
        prev_cid: str | None = None,
        priv: Ed25519PrivateKey | None = None,
        pubkey_str: str | None = None,
    ) -> dict[str, Any]:
        env: dict[str, Any] = {
            "magic": "swf-bundle-v1",
            "kind": kind,
            "record_id": record_id,
            "version": int(version),
            "author": {
                "pubkey": pubkey_str or alchemist_keypair.pubkey_str,
                "signed_at": signed_at,
            },
            "encryption": encryption,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        if prev_cid is not None:
            env["prev_cid"] = prev_cid
        env["signature"] = sign_envelope(
            env, priv=priv or alchemist_keypair.priv,
        )
        return env

    return _build


@pytest.fixture
def alchemists_with():
    """Factory for an in-memory AlchemistList (no YAML on disk)."""

    def _build(*pubkey_strings: str, ids: list[str] | None = None) -> AlchemistList:
        members: dict[str, str] = {}
        for i, pk in enumerate(pubkey_strings):
            ident = ids[i] if ids and i < len(ids) else f"alc-{i}"
            members[pk] = ident
        return AlchemistList(members=members, path=None)

    return _build
