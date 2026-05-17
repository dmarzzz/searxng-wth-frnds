"""Tests for `swf-node init / doctor / migrate / version` subcommands.

The CLI dispatch table in `swf.peer_server.main` routes
`sys.argv[1]` ∈ {init, doctor, migrate, version} to a subcommand
handler; everything else falls through to the existing serve flow
(`_serve(argv)`). Zero-arg behavior preserved.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Force every subcommand to land in a tmpdir, never the user's
    real ~/.config/swf or ~/world_knowledge. We set HOME *and* every
    swf-specific override so a stale env var on the dev box doesn't
    bleed through."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / ".config" / "swf"))
    monkeypatch.setenv("SWF_STATE_DIR", str(tmp_path / ".local" / "share" / "swf"))
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path / "world_knowledge"))
    # Belt-and-braces: also clear the legacy var so it can't override.
    monkeypatch.delenv("RA_WORLD_KNOWLEDGE_DIR", raising=False)
    monkeypatch.setenv("SWF_NO_MDNS", "1")
    yield tmp_path


def _swf_node_invocation() -> list[str]:
    """Return the command prefix to run the swf-node CLI, preferring
    the installed console script and falling back to `python -m swf`
    so the tests work whether or not `.venv/bin` is on PATH."""
    bin_path = shutil.which("swf-node")
    if bin_path:
        return [bin_path]
    return [sys.executable, "-m", "swf"]


def _run(*args, env: dict | None = None) -> tuple[int, str, str]:
    e = os.environ.copy()
    if env:
        e.update(env)
    cmd = [*_swf_node_invocation(), *args]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=15, env=e,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_version_prints_canonical_version(isolated_home):
    rc, out, _ = _run("version")
    assert rc == 0
    assert out.startswith("swf-node ")
    # Pulled from importlib.metadata — should be a semver-shaped string.
    parts = out.strip().split()
    assert len(parts) == 2 and parts[0] == "swf-node"
    assert parts[1] not in ("", "0.0.0+unknown"), \
        f"unexpected version {parts[1]!r}"


def test_python_dash_m_swf_works(isolated_home):
    """`python -m swf` must dispatch to the same main as the console
    script. Used by the Dockerfile ENTRYPOINT in PR #70."""
    proc = subprocess.run(
        [sys.executable, "-m", "swf", "version"],
        capture_output=True, text=True, timeout=15,
    )
    assert proc.returncode == 0
    assert proc.stdout.startswith("swf-node ")


def test_init_creates_identity_and_config(isolated_home):
    rc, out, _ = _run("init")
    assert rc == 0
    assert "identity created" in out
    assert "config written" in out

    config_dir = Path(os.environ["SWF_CONFIG_DIR"])
    assert (config_dir / "identity.key").exists()
    assert (config_dir / "config.toml").exists()

    # Identity file must be 0600 — TOFU trust hinges on the private
    # key being unreadable by other users.
    mode = (config_dir / "identity.key").stat().st_mode & 0o777
    assert mode == 0o600, f"identity.key mode {oct(mode)}; expected 0o600"


def test_init_is_idempotent(isolated_home):
    """Running init twice must not rotate the identity. Peers TOFU
    pubkeys; an unintentional rotation breaks every prior trust
    relationship."""
    rc1, _, _ = _run("init")
    assert rc1 == 0
    config_dir = Path(os.environ["SWF_CONFIG_DIR"])
    key_before = (config_dir / "identity.key").read_bytes()

    rc2, out2, _ = _run("init")
    assert rc2 == 0
    assert "identity present" in out2  # not "identity created"

    key_after = (config_dir / "identity.key").read_bytes()
    assert key_before == key_after, "init rotated the identity unexpectedly"


def test_migrate_handles_missing_db_gracefully(isolated_home):
    """Fresh install: no indrex DB yet. `migrate` should report it
    politely, not crash."""
    rc, out, _ = _run("migrate")
    assert rc == 0
    assert "nothing to migrate" in out


def test_migrate_reports_schema_state(isolated_home):
    """After the daemon (or the test fixture below) creates the DB,
    `migrate` reports the column count instead of skipping."""
    # Seed the DB by calling ensure_schema directly; same code path
    # the daemon runs on first write.
    import sqlite3

    from swf.indrex import db_path
    from swf.search.migration import ensure_schema
    db = db_path()
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db))
    try:
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()

    rc, out, _ = _run("migrate")
    assert rc == 0
    assert "schema OK" in out
    assert "pages_meta has" in out


def test_doctor_runs_without_peers_or_searxng(isolated_home):
    """No peers configured, no SearXNG running, no mDNS probe — doctor
    should still complete and print a structured report."""
    rc, out, _ = _run("doctor")
    # Exit 0 because all the real checks pass on fresh state (skips
    # don't count as failures).
    assert rc == 0
    assert "swf-node doctor" in out
    assert "core checks" in out
    assert "SearXNG" in out
    assert "configured peers" in out


def test_doctor_searxng_unreachable_marks_failure(isolated_home):
    """If SEARXNG_URL is set but unreachable, doctor exits non-zero."""
    rc, out, _ = _run("doctor", env={"SEARXNG_URL": "http://127.0.0.1:1"})
    assert rc != 0
    assert "unreachable" in out


def test_zero_arg_falls_through_to_serve(isolated_home):
    """Bare `swf-node` (no subcommand) must still try to start the
    daemon. We don't want it actually serving in the test process,
    so use --check which is the closest no-op flag."""
    rc, out, _ = _run("--check")
    assert rc == 0
    assert "[ok]" in out or "checks passed" in out


def test_unknown_subcommand_falls_through_to_argparse(isolated_home):
    """Anything not in the subcommand allowlist goes to the serve-flow
    argparser, which will error on unknown args (exit 2) rather than
    silently ignore them."""
    rc, _, err = _run("--definitely-not-a-real-flag")
    assert rc != 0
    assert "unrecognized" in err.lower() or "error" in err.lower()


def test_swf_knowledge_dir_alias_works(tmp_path, monkeypatch):
    """The new SWF_KNOWLEDGE_DIR env var should win over (and not
    require) the legacy RA_WORLD_KNOWLEDGE_DIR."""
    monkeypatch.delenv("RA_WORLD_KNOWLEDGE_DIR", raising=False)
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path / "kn"))

    # Reload swf.indrex so it re-reads the env.
    import importlib

    import swf.indrex
    importlib.reload(swf.indrex)
    import swf.web.knowledge
    importlib.reload(swf.web.knowledge)

    expected_root = tmp_path / "kn"
    assert swf.indrex.db_path() == expected_root / "index.db"
    assert swf.web.knowledge.knowledge_root() == expected_root


def test_swf_knowledge_dir_overrides_legacy(tmp_path, monkeypatch):
    """If both SWF_KNOWLEDGE_DIR and RA_WORLD_KNOWLEDGE_DIR are set,
    the new var wins."""
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "legacy"))
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path / "new"))

    import importlib

    import swf.indrex
    importlib.reload(swf.indrex)
    assert swf.indrex.db_path() == tmp_path / "new" / "index.db"
