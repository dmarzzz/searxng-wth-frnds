"""Shared fixtures for the sync substrate tests.

Provides:
  - `sync_keypair` — a fresh Ed25519 keypair with the canonical
    `ed25519:<hex>` pubkey string the verifier expects.
  - `make_keypair` — factory for multi-keypair tests.
  - `make_envelope` — factory that builds a fully-signed sync envelope
    around any content + keypair.
  - `cohort_keys_with` — turn a `{handle: pubkey}` mapping into an
    in-memory `CohortKeys` (no file on disk).
  - `sync_conn` — an open sqlite3 connection to a tmp DB with the
    sync schema applied.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swf.sync import (
    SYNC_MAGIC,
    CohortKeys,
    content_hash,
    ensure_schema,
    sign_envelope,
)


@dataclass
class _SyncKeypair:
    priv: Ed25519PrivateKey
    pub_hex: str
    pubkey_str: str  # ed25519:<hex>


def _make_keypair() -> _SyncKeypair:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = raw.hex()
    return _SyncKeypair(priv=priv, pub_hex=pub_hex, pubkey_str=f"ed25519:{pub_hex}")


@pytest.fixture
def sync_keypair() -> _SyncKeypair:
    return _make_keypair()


@pytest.fixture
def make_keypair():
    return _make_keypair


@pytest.fixture
def make_envelope(sync_keypair):
    """Factory for fully-signed sync envelopes.

    Defaults to a `kind=person` envelope with a small JSON content.
    Pass overrides as kwargs.
    """

    def _build(
        *,
        kind: str = "person",
        record_id: str = "amiller",
        wall_ts_ms: int | None = None,
        prev_hash: str | None = None,
        content: dict[str, Any] | None = None,
        priv: Ed25519PrivateKey | None = None,
        pubkey_str: str | None = None,
    ) -> dict[str, Any]:
        if wall_ts_ms is None:
            wall_ts_ms = int(time.time() * 1000)
        if content is None:
            content = {"name": "Andrew", "geo": "NYC"}
        env: dict[str, Any] = {
            "magic": SYNC_MAGIC,
            "kind": kind,
            "record_id": record_id,
            "author_pubkey": pubkey_str or sync_keypair.pubkey_str,
            "wall_ts_ms": int(wall_ts_ms),
            "prev_hash": prev_hash,
            "content": content,
            "content_hash": content_hash(content),
        }
        env["signature"] = sign_envelope(
            env, priv=priv or sync_keypair.priv,
        )
        return env

    return _build


@pytest.fixture
def cohort_keys_with():
    def _build(**handle_to_pubkey: str) -> CohortKeys:
        return CohortKeys(
            members=dict(handle_to_pubkey),
            cohort_id="test-cohort",
            path=Path("/tmp/sync-tests/cohort-keys.json"),
            mtime_ns=0,
        )

    return _build


@pytest.fixture
def sync_conn(tmp_path):
    """An open sqlite3 connection to a tmp DB with the sync schema."""
    db_path = tmp_path / "sync.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    yield conn
    conn.close()
