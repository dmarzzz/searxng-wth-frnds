"""Unit tests for `swf.sync.cohort_keys` (spec §8.2 + §9.6)."""
from __future__ import annotations

import json
import os
import time

import pytest

from swf.sync import (
    load_cohort_keys,
    load_cohort_keys_cached,
    reset_cohort_keys_cache_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_cache_between_cases():
    reset_cohort_keys_cache_for_tests()
    yield
    reset_cohort_keys_cache_for_tests()


@pytest.fixture
def _isolated_env(monkeypatch, tmp_path):
    """Point cohort-keys lookups at a tmp config dir, away from any
    real ~/.config/swf file."""
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("SWF_COHORT_KEYS_FILE", raising=False)
    return tmp_path


def _write_keys_file(path, members, *, cohort_id: str = "c1"):
    path.write_text(json.dumps({
        "schema": "swf.cohort_keys.v1",
        "cohort_id": cohort_id,
        "members": members,
    }))


def test_missing_file_returns_empty(_isolated_env):
    keys = load_cohort_keys()
    assert not keys
    assert keys.pubkeys == frozenset()
    assert keys.path is None


def test_loads_valid_file(_isolated_env):
    cohort_keys_path = _isolated_env / "cohort-keys.json"
    _write_keys_file(cohort_keys_path, [
        {"handle": "amiller", "pubkey": "ed25519:" + "ab" * 32, "added_at_ms": 1},
        {"handle": "halcyon", "pubkey": "ed25519:" + "cd" * 32, "added_at_ms": 2},
    ])
    keys = load_cohort_keys()
    assert len(keys) == 2
    assert keys.is_known_pubkey("ed25519:" + "ab" * 32)
    assert keys.pubkey_for_handle("amiller") == "ed25519:" + "ab" * 32
    assert keys.handle_for_pubkey("ed25519:" + "cd" * 32) == "halcyon"


def test_rejects_duplicate_handle(_isolated_env, capsys):
    """Spec §9.6: duplicate handles must be rejected at parse time."""
    cohort_keys_path = _isolated_env / "cohort-keys.json"
    _write_keys_file(cohort_keys_path, [
        {"handle": "amiller", "pubkey": "ed25519:" + "ab" * 32, "added_at_ms": 1},
        # Duplicate handle, different pubkey
        {"handle": "amiller", "pubkey": "ed25519:" + "cd" * 32, "added_at_ms": 2},
    ])
    keys = load_cohort_keys()
    assert len(keys) == 1
    # The first entry wins.
    assert keys.pubkey_for_handle("amiller") == "ed25519:" + "ab" * 32
    err = capsys.readouterr().err
    assert "duplicate handle" in err


def test_rejects_duplicate_pubkey(_isolated_env, capsys):
    cohort_keys_path = _isolated_env / "cohort-keys.json"
    _write_keys_file(cohort_keys_path, [
        {"handle": "amiller", "pubkey": "ed25519:" + "ab" * 32, "added_at_ms": 1},
        {"handle": "halcyon", "pubkey": "ed25519:" + "ab" * 32, "added_at_ms": 2},
    ])
    keys = load_cohort_keys()
    assert len(keys) == 1
    err = capsys.readouterr().err
    assert "duplicate pubkey" in err


def test_skips_malformed_pubkey(_isolated_env, capsys):
    cohort_keys_path = _isolated_env / "cohort-keys.json"
    _write_keys_file(cohort_keys_path, [
        {"handle": "amiller", "pubkey": "not-hex"},
        {"handle": "halcyon", "pubkey": "ed25519:" + "cd" * 32, "added_at_ms": 2},
    ])
    keys = load_cohort_keys()
    assert len(keys) == 1
    assert keys.pubkey_for_handle("halcyon")


def test_env_override_wins(monkeypatch, tmp_path):
    explicit = tmp_path / "explicit.json"
    _write_keys_file(explicit, [
        {"handle": "x", "pubkey": "ed25519:" + "11" * 32},
    ])
    # Also seed the default location with different content; the env
    # override should win.
    monkeypatch.setenv("SWF_COHORT_KEYS_FILE", str(explicit))
    keys = load_cohort_keys()
    assert keys.pubkey_for_handle("x") == "ed25519:" + "11" * 32


def test_cached_hot_reload(_isolated_env):
    cohort_keys_path = _isolated_env / "cohort-keys.json"
    _write_keys_file(cohort_keys_path, [
        {"handle": "a", "pubkey": "ed25519:" + "ab" * 32},
    ])
    first = load_cohort_keys_cached()
    assert len(first) == 1

    # Edit the file: add an entry. Forward mtime explicitly so the
    # cache detects the change without sleeping in the test.
    _write_keys_file(cohort_keys_path, [
        {"handle": "a", "pubkey": "ed25519:" + "ab" * 32},
        {"handle": "b", "pubkey": "ed25519:" + "cd" * 32},
    ])
    new_mtime = first.mtime_ns + 1_000_000_000
    os.utime(cohort_keys_path, ns=(new_mtime, new_mtime))

    second = load_cohort_keys_cached()
    assert len(second) == 2
