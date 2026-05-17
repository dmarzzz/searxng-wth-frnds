"""TODO-12: tests for `swf-node --check` self-test.

Spawns the CLI in a subprocess against a fresh temp HOME so we don't
clobber the developer's real ~/.config/swf or ~/world_knowledge. Each
test sets up exactly the state it wants to assert against.

Three scenarios:
1. Empty HOME — every DB is missing; check reports each as `[skip]`
   and the exit code equals the number of missing artifacts.
2. All DBs present + correctly-shaped → exit 0.
3. Reputation DB has the wrong table → exit non-zero with a [FAIL] line
   pointing at provider_scores.

The check is read-only (§ TODO-12 strict scope), so we manually create
each DB by running its module's CREATE script. For indrex we
hand-write the schema because (a) `pages` is FTS5 owned by
swf.web and (b) `pages_meta` post-TODO-8 has six metadata
columns the live migration doesn't yet emit.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"


# pages_meta as TODO-8 will eventually ship it. The check only verifies
# the six metadata columns are present (not their exact CHECK
# constraints), so this stub is forward-compatible with the migration.
_INDREX_SCHEMA_SQL = """
CREATE VIRTUAL TABLE pages USING fts5(url, title, content, fetched_at);
CREATE TABLE pages_meta (
    url               TEXT PRIMARY KEY,
    share_scope       TEXT NOT NULL DEFAULT 'private',
    sensitivity_label TEXT NOT NULL DEFAULT 'unknown',
    source_type       TEXT NOT NULL DEFAULT 'user_fetched',
    content_hash      TEXT,
    fetched_at_ms     INTEGER,
    deleted_at_ms     INTEGER,
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
"""


def _run_check(home: Path, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(SRC)
    # Strip any leftover overrides from the parent shell that would
    # redirect DB paths outside `home`.
    for k in (
        "SWF_CONFIG_DIR", "SWF_CACHE_DB", "SWF_CACHE_SECRET_FILE",
        "SWF_REPUTATION_DB", "SWF_TICKETS_DB",
        "RA_WORLD_KNOWLEDGE_DIR",
    ):
        env.pop(k, None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "swf.peer_server", "--check"],
        capture_output=True, text=True, env=env, timeout=60,
    )


# Without the package being installed in this environment, `python -m
# swf.peer_server` is the cleanest invocation — it does not require
# `swf-node` on PATH but still exercises the same `main()`.


def _bootstrap_runtime_dbs(home: Path) -> None:
    """Create the four runtime DBs at the locations check expects.
    For cache/rep/tickets we just run their module's `_connect()` to
    materialize the CREATE TABLE statements. For indrex we write our
    own schema (see _INDREX_SCHEMA_SQL)."""
    # World-knowledge indrex (read-only check).
    knowledge_db = home / "world_knowledge" / "index.db"
    knowledge_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(knowledge_db))
    try:
        conn.executescript(_INDREX_SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()

    # Cache + reputation + tickets DBs are bootstrapped by their own
    # `_connect()` helpers. Run each one in a subprocess so HOME is
    # honored at module-import time (db_path() reads it lazily, so a
    # fresh subprocess works just as well).
    # `_connect()` materializes the schema; `_load_or_create_secret()`
    # writes the 32-byte HMAC key with mode 0600 (matching what the
    # check verifies on the read path).
    bootstrap = textwrap.dedent("""
        from swf.search.local_cache import _connect as cc, _load_or_create_secret
        from swf.search.reputation import _connect as rc
        from swf.search.tickets import _connect as tc
        cc().close(); rc().close(); tc().close()
        _load_or_create_secret()
    """).strip()
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(SRC)
    for k in (
        "SWF_CONFIG_DIR", "SWF_CACHE_DB", "SWF_CACHE_SECRET_FILE",
        "SWF_REPUTATION_DB", "SWF_TICKETS_DB", "RA_WORLD_KNOWLEDGE_DIR",
    ):
        env.pop(k, None)
    out = subprocess.run(
        [sys.executable, "-c", bootstrap],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, (
        f"bootstrap failed: stdout={out.stdout!r} stderr={out.stderr!r}"
    )


# ─── tests ────────────────────────────────────────────────────────────

def test_check_on_fresh_home_reports_missing_dbs(tmp_path):
    """Fresh HOME with nothing seeded: identity is auto-created (the
    check loads it lazily, which materializes the keypair), routes are
    wired in code, invariants are pure-Python — those three pass.
    Every disk-backed artifact is reported as [skip].

    The bundle-config checks (alchemists.yml / reservoir.yml / convent
    signing key) are also unconfigured on a fresh HOME, so they SKIP
    too — they bring the skip count from 5 to 8.
    """
    res = _run_check(tmp_path)
    out = res.stdout
    # Diagnostics if it crashes.
    assert "checks passed" in out, (
        f"missing summary line. stdout={out!r} stderr={res.stderr!r}"
    )
    # Eight skip lines:
    #   - indrex / cache / reputation / tickets DBs + cache HMAC secret
    #     (5; identity is allowed to materialize as [ok])
    #   - alchemists.yml + reservoir.yml + convent signing key
    #     (3; the bundle-config checks added in the operator-UX pass)
    assert out.count("[skip]") == 8, out
    assert out.count("[FAIL]") == 0, out
    # Pass-4 finding #6: skip is reported but does NOT count as a
    # failure (the module docstring promises "missing DB is `[skip]`,
    # not a hard failure"). Exit code is 0 on a fresh install so init
    # scripts that treat non-zero as fatal don't misfire.
    assert res.returncode == 0, (res.returncode, out)
    # Summary surfaces the skip count alongside the pass count.
    assert "3/11 checks passed" in out, out
    assert "8 skipped" in out, out


def test_check_passes_when_all_dbs_present(tmp_path):
    _bootstrap_runtime_dbs(tmp_path)
    res = _run_check(tmp_path)
    out = res.stdout
    assert res.returncode == 0, (
        f"expected 0, got {res.returncode}\n"
        f"stdout={out}\nstderr={res.stderr}"
    )
    assert "[FAIL]" not in out
    # The three bundle-config checks SKIP without configuration; this
    # test bootstraps only the legacy runtime DBs, so the skips remain.
    # Confirm exactly the bundle-config skips, no more.
    assert out.count("[skip]") == 3, out
    assert "8/11 checks passed" in out
    # Bundle-config checks are individually present + skipped.
    assert "[skip] alchemists.yml" in out
    assert "[skip] reservoir.yml" in out
    assert "[skip] convent signing key" in out


def test_check_fails_on_corrupt_reputation_db(tmp_path):
    """Corrupt the reputation DB by giving it a totally wrong table
    layout. The check must report [FAIL] with a missing-tables reason
    and exit non-zero."""
    _bootstrap_runtime_dbs(tmp_path)
    rep_db = tmp_path / ".local" / "share" / "swf" / "reputation.db"
    rep_db.unlink()  # drop the good one
    conn = sqlite3.connect(str(rep_db))
    try:
        conn.execute("CREATE TABLE wrong_table_name (x INTEGER)")
        conn.commit()
    finally:
        conn.close()
    res = _run_check(tmp_path)
    out = res.stdout
    assert "[FAIL] reputation schema" in out, out
    assert "provider_scores" in out, out
    assert res.returncode >= 1, (res.returncode, out)
