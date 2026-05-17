"""Shared fixtures for hivemind sink tests (#93 phase 5).

Provides:
  - `convent_keypair` — fresh Ed25519 keypair the sink will use to
    sign envelopes. The seed bytes are also written to a tmp file
    pointed at via `SWF_CONVENT_SIGNING_KEY` so the sink's
    `load_signing_key()` finds them.
  - `sink_environment` — sets up the convent signing key + the
    `.alchemists.yml` whitelist + a fresh tmp indrex DB. Returns a
    `SinkEnvironment` with the loaded SinkConfig and the keypair so
    tests can assert on the wrapped envelope.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swf.bundles.alchemists import AlchemistList
from swf.hivemind.sink import SinkConfig


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
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = pub_raw.hex()
    return _Keypair(
        priv=priv, pub_hex=pub_hex,
        pubkey_str=f"ed25519:{pub_hex}", seed=seed,
    )


@pytest.fixture
def convent_keypair() -> _Keypair:
    return _make_keypair()


@dataclass
class SinkEnvironment:
    """Bundle of everything a hivemind sink test needs."""
    keypair: _Keypair
    seed_path: Path
    alchemists_path: Path
    sink_cfg: SinkConfig
    indrex_dir: Path


@pytest.fixture
def sink_environment(tmp_path, monkeypatch, convent_keypair) -> SinkEnvironment:
    """Set up a complete sink environment with all the env vars wired.

    Touches:
      - `SWF_KNOWLEDGE_DIR` → fresh tmp indrex dir
      - `SWF_CONVENT_SIGNING_KEY` → tmp 32-byte seed file
      - `SWF_ALCHEMISTS_FILE` → tmp YAML containing the convent pubkey

    Returns a `SinkEnvironment` whose `sink_cfg` is ready to drive
    `persist_transcript_batch` directly. The sink's signing-key cache
    is reset between tests via `autouse` `_reset_caches` (see below).
    """
    knowledge = tmp_path / "wk"
    knowledge.mkdir()
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(knowledge))

    seed_path = tmp_path / "convent.seed"
    seed_path.write_bytes(convent_keypair.seed)
    monkeypatch.setenv("SWF_CONVENT_SIGNING_KEY", str(seed_path))

    alchemists_path = tmp_path / ".alchemists.yml"
    alchemists_path.write_text(
        "schema_version: 1\n"
        "alchemists:\n"
        f'  - id: convent\n    pubkey: "{convent_keypair.pubkey_str}"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(alchemists_path))

    # The indrex db_path() reads the env at call time, so we don't
    # need to reload `swf.indrex`. We DO need to reset the hivemind
    # signing-key cache so each test loads its own seed file.
    from swf.hivemind import sink as _sink_mod
    _sink_mod.reset_signing_key_cache_for_tests()

    priv = _sink_mod.load_signing_key()
    alchemists = AlchemistList(
        members={convent_keypair.pubkey_str: "convent"},
        path=alchemists_path,
    )
    sink_cfg = SinkConfig(signing_key=priv, alchemists=alchemists)

    return SinkEnvironment(
        keypair=convent_keypair,
        seed_path=seed_path,
        alchemists_path=alchemists_path,
        sink_cfg=sink_cfg,
        indrex_dir=knowledge,
    )


@pytest.fixture(autouse=True)
def _reset_caches():
    """Drop sink-side caches between tests so monkeypatched env vars
    don't leak across cases."""
    from swf.hivemind import sink as _sink_mod
    _sink_mod.reset_signing_key_cache_for_tests()
    _sink_mod.reset_reservoir_cache_for_tests()
    yield
    _sink_mod.reset_signing_key_cache_for_tests()
    _sink_mod.reset_reservoir_cache_for_tests()


def make_payload(
    *,
    record_id: str = "transcript-2026-05-07-1430-room-a",
    batch_index: int | str = 0,
    started_at: str = "2026-05-07T14:30:00Z",
    ended_at: str = "2026-05-07T14:31:08Z",
    location: str | None = "convent-room-a",
    origin_device: str | None = "voxterm-uuid-abc",
    segments: list | None = None,
) -> dict:
    """Factory for a well-formed voxterm payload."""
    out: dict = {
        "record_id": record_id,
        "batch_index": batch_index,
        "started_at": started_at,
        "ended_at": ended_at,
        "segments": segments if segments is not None else [
            {"t": 0.0, "speaker": "Tina", "text": "hello"},
            {"t": 4.7, "speaker": "Andrew", "text": "world"},
        ],
    }
    if location is not None:
        out["location"] = location
    if origin_device is not None:
        out["origin_device"] = origin_device
    return out
