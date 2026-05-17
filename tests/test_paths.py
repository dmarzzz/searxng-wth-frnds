"""Tests for `swf.paths` — the centralized state-dir helper.

Pins:
  - new dirs are created with mode 0700 (owner-only)
  - existing dirs with looser modes are repaired on access
  - SWF_CONFIG_DIR / SWF_STATE_DIR env overrides honored
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
    monkeypatch.delenv("SWF_STATE_DIR", raising=False)
    # Force a fresh module so cached defaults pick up new HOME.
    import sys
    sys.modules.pop("swf.paths", None)
    yield


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


# ─── fresh dir creation ──────────────────────────────────────────

def test_config_dir_created_with_0700():
    from swf.paths import config_dir
    p = config_dir()
    assert p.exists()
    assert p.is_dir()
    assert _mode(p) == 0o700


def test_state_dir_created_with_0700():
    from swf.paths import state_dir
    p = state_dir()
    assert p.exists()
    assert _mode(p) == 0o700


# ─── existing-dir repair ─────────────────────────────────────────

def test_existing_world_readable_dir_is_repaired(tmp_path):
    """A directory created earlier with mode 0755 must be re-chmodded
    to 0700 on next access. This is the upgrade path for users whose
    state dirs were created by an older release."""
    from swf.paths import ensure_dir
    p = tmp_path / "loose"
    p.mkdir(mode=0o755)
    assert _mode(p) == 0o755  # baseline confirms the loose mode
    ensure_dir(p)
    assert _mode(p) == 0o700


def test_existing_dir_already_0700_is_no_op(tmp_path):
    from swf.paths import ensure_dir
    p = tmp_path / "tight"
    p.mkdir(mode=0o700)
    ensure_dir(p)
    assert _mode(p) == 0o700


# ─── env overrides ───────────────────────────────────────────────

def test_swf_config_dir_env_honored(tmp_path, monkeypatch):
    import sys
    custom = tmp_path / "custom-config"
    monkeypatch.setenv("SWF_CONFIG_DIR", str(custom))
    sys.modules.pop("swf.paths", None)
    from swf.paths import config_dir
    p = config_dir()
    assert p == custom
    assert _mode(p) == 0o700


def test_swf_state_dir_env_honored(tmp_path, monkeypatch):
    import sys
    custom = tmp_path / "custom-state"
    monkeypatch.setenv("SWF_STATE_DIR", str(custom))
    sys.modules.pop("swf.paths", None)
    from swf.paths import state_dir
    p = state_dir()
    assert p == custom
    assert _mode(p) == 0o700


# ─── per-module wiring ───────────────────────────────────────────

def test_local_cache_secret_dir_is_0700(tmp_path, monkeypatch):
    """Module-level `secret_path()` writes through ensure_dir."""
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    import sys
    for m in ("swf.paths", "swf.search.local_cache"):
        sys.modules.pop(m, None)
    from swf.search.local_cache import secret_path
    p = secret_path()
    assert _mode(p.parent) == 0o700


def test_reputation_db_dir_is_0700(tmp_path, monkeypatch):
    monkeypatch.setenv("SWF_STATE_DIR", str(tmp_path / "state"))
    import sys
    for m in ("swf.paths", "swf.search.reputation"):
        sys.modules.pop(m, None)
    from swf.search.reputation import db_path
    p = db_path()
    assert _mode(p.parent) == 0o700


def test_tickets_db_dir_is_0700(tmp_path, monkeypatch):
    monkeypatch.setenv("SWF_STATE_DIR", str(tmp_path / "state"))
    import sys
    for m in ("swf.paths", "swf.search.tickets"):
        sys.modules.pop(m, None)
    from swf.search.tickets import db_path
    p = db_path()
    assert _mode(p.parent) == 0o700


def test_identity_dir_is_0700(tmp_path, monkeypatch):
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    import sys
    for m in ("swf.paths", "swf.identity"):
        sys.modules.pop(m, None)
    from swf.identity import _identity_dir
    d = _identity_dir()
    assert _mode(d) == 0o700
