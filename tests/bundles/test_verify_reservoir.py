"""Verifier reservoir-recipients cross-check tests (#93 phase 7).

Covers the optional `reservoir=` kwarg added to `verify_bundle` so the
phase-2-deferred recipients-subset-of-reservoir invariant fires when
the caller has a reservoir handy. Existing call sites that pass
`reservoir=None` (the default) keep their phase-1/2 behavior — those
back-compat assertions live here too so a future refactor can't break
them silently.
"""
from __future__ import annotations

import sqlite3

import pytest

from swf.bundles import (
    Reservoir,
    ReservoirEntry,
    VerifyReason,
    ensure_schema,
    verify_bundle,
)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    c = sqlite3.connect(str(tmp_path / "index.db"))
    c.row_factory = sqlite3.Row
    ensure_schema(c)
    yield c
    c.close()


# Stand-in pubkey strings — the verifier only does string membership;
# real bech32 isn't required for this layer.
_R1 = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0001"
_R2 = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0002"
_R3 = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0003"
_OUTSIDER = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxoutsider"


def _reservoir(*pubkeys: str) -> Reservoir:
    return Reservoir(
        keys=[
            ReservoirEntry(id=f"alc-{i}", pubkey=pk, distributed_to=None)
            for i, pk in enumerate(pubkeys)
        ],
    )


def _enc_block(*recipients: str) -> dict:
    return {"alg": "age-v1", "recipients": list(recipients)}


# ── happy path: every recipient is in the reservoir ────────────────────


def test_recipients_all_in_reservoir_passes(
    conn, make_envelope, alchemists_with, alchemist_keypair,
):
    env = make_envelope(encryption=_enc_block(_R1, _R2, _R3))
    al = alchemists_with(alchemist_keypair.pubkey_str)
    res = _reservoir(_R1, _R2, _R3)
    result = verify_bundle(env, alchemists=al, conn=conn, reservoir=res)
    assert result.ok, result.reason


def test_recipient_outside_reservoir_rejected(
    conn, make_envelope, alchemists_with, alchemist_keypair,
):
    """One recipient that's not in the reservoir means the bundle is
    addressed to someone the consumer set can't decrypt for. Reject."""
    env = make_envelope(encryption=_enc_block(_R1, _OUTSIDER, _R2))
    al = alchemists_with(alchemist_keypair.pubkey_str)
    res = _reservoir(_R1, _R2, _R3)
    result = verify_bundle(env, alchemists=al, conn=conn, reservoir=res)
    assert not result.ok
    assert result.reason == VerifyReason.ENCRYPTION_RECIPIENT_NOT_IN_RESERVOIR
    assert len(result.cid) == 64


def test_all_recipients_outside_reservoir_rejected(
    conn, make_envelope, alchemists_with, alchemist_keypair,
):
    env = make_envelope(encryption=_enc_block(_OUTSIDER))
    al = alchemists_with(alchemist_keypair.pubkey_str)
    res = _reservoir(_R1, _R2)
    result = verify_bundle(env, alchemists=al, conn=conn, reservoir=res)
    assert not result.ok
    assert result.reason == VerifyReason.ENCRYPTION_RECIPIENT_NOT_IN_RESERVOIR


# ── reservoir not passed: no recipient check fires (back-compat) ──────


def test_no_reservoir_kwarg_skips_recipient_check(
    conn, make_envelope, alchemists_with, alchemist_keypair,
):
    """Existing phase-1/2/5 call sites pass no reservoir; they get the
    pre-phase-7 behavior. A bundle with a recipient that would be
    rejected with a reservoir verifies fine without one."""
    env = make_envelope(encryption=_enc_block(_OUTSIDER))
    al = alchemists_with(alchemist_keypair.pubkey_str)
    result = verify_bundle(env, alchemists=al, conn=conn)
    assert result.ok, result.reason


def test_explicit_reservoir_none_skips_recipient_check(
    conn, make_envelope, alchemists_with, alchemist_keypair,
):
    """Same back-compat property when callers pass `reservoir=None`
    explicitly."""
    env = make_envelope(encryption=_enc_block(_OUTSIDER))
    al = alchemists_with(alchemist_keypair.pubkey_str)
    result = verify_bundle(env, alchemists=al, conn=conn, reservoir=None)
    assert result.ok, result.reason


# ── unencrypted bundle: reservoir kwarg is a no-op ────────────────────


def test_no_encryption_block_skips_recipient_check_with_reservoir(
    conn, make_envelope, alchemists_with, alchemist_keypair,
):
    """Cohort.surface bundles aren't encrypted — passing a reservoir
    should not change anything."""
    env = make_envelope(encryption=None)
    al = alchemists_with(alchemist_keypair.pubkey_str)
    res = _reservoir(_R1, _R2, _R3)
    result = verify_bundle(env, alchemists=al, conn=conn, reservoir=res)
    assert result.ok, result.reason


# ── empty reservoir + encrypted bundle: every recipient is "outside" ──


def test_empty_reservoir_rejects_any_encrypted_bundle(
    conn, make_envelope, alchemists_with, alchemist_keypair,
):
    """If the operator hasn't staged the reservoir but the verifier
    is invoked with one anyway (a misconfigured boot sequence), every
    encrypted bundle should be rejected — not silently accepted."""
    env = make_envelope(encryption=_enc_block(_R1))
    al = alchemists_with(alchemist_keypair.pubkey_str)
    res = _reservoir()  # empty
    result = verify_bundle(env, alchemists=al, conn=conn, reservoir=res)
    assert not result.ok
    assert result.reason == VerifyReason.ENCRYPTION_RECIPIENT_NOT_IN_RESERVOIR
