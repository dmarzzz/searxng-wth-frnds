"""Tests for `swf-node backup` + `swf-node restore`.

Two layers of coverage:

  1. Direct calls into `swf.backup.{backup_to_tarball,
     restore_from_tarball, verify_backup}` — fast, in-process, exercises
     the manifest schema, sha256 verification, force-flag semantics,
     and the sqlite online-backup API.
  2. CLI subprocess round-trip — invokes `swf-node backup ...` and
     `swf-node restore ...` via `python -m swf` to confirm the
     dispatcher is wired correctly. Mirrors the pattern in
     `tests/test_subcommands.py` and `tests/test_node_check.py`.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

import pytest

from swf.backup import (
    SCHEMA_VERSION,
    BackupError,
    backup_to_tarball,
    restore_from_tarball,
    verify_backup,
)

# ── Helpers ────────────────────────────────────────────────────────


def _seed_indrex(db_path: Path, n_rows: int = 25) -> None:
    """Create a tiny `pages_meta` and write rows so we have something
    to round-trip and so `ensure_schema` will work on the restored
    copy."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        from swf.search.migration import ensure_schema
        ensure_schema(conn)
        for i in range(n_rows):
            conn.execute(
                "INSERT INTO pages_meta(url, content_hash) "
                "VALUES (?, ?) ON CONFLICT(url) DO NOTHING",
                (f"https://example.test/{i}", f"hash-{i}"),
            )
        conn.commit()
    finally:
        conn.close()


def _seed_config(config_dir: Path, *, with_optional: bool = True) -> None:
    """Lay down identity.key and (optionally) the .alchemists.yml,
    .reservoir.yml, peers.yaml, and convent-signing.key."""
    config_dir.mkdir(parents=True, exist_ok=True)
    # 32-byte Ed25519 seed — matches the on-disk format the real
    # identity helper writes.
    (config_dir / "identity.key").write_bytes(b"\x42" * 32)
    os.chmod(config_dir / "identity.key", 0o600)
    if with_optional:
        (config_dir / "peers.yaml").write_text(
            "schema_version: 1\npeers: []\n",
        )
        (config_dir / ".alchemists.yml").write_text(
            "schema_version: 1\nalchemists: []\n",
        )
        (config_dir / ".reservoir.yml").write_text(
            "schema_version: 1\nkeys: []\n",
        )
        (config_dir / "convent-signing.key").write_bytes(b"\x37" * 32)
        os.chmod(config_dir / "convent-signing.key", 0o600)


@pytest.fixture
def populated_state(tmp_path: Path):
    """A tmp pair of (knowledge_dir, config_dir) populated with the
    same shape as a live convent box: indrex DB with a few rows, all
    optional config files present."""
    knowledge_dir = tmp_path / "world_knowledge"
    config_dir = tmp_path / "config"
    knowledge_dir.mkdir(parents=True)
    _seed_indrex(knowledge_dir / "index.db", n_rows=25)
    _seed_config(config_dir, with_optional=True)
    return knowledge_dir, config_dir


# ── 1. backup writes a tarball with a valid manifest ──────────────


def test_backup_writes_tarball_with_manifest(populated_state, tmp_path: Path):
    knowledge_dir, config_dir = populated_state
    out = tmp_path / "snap.tar.gz"

    manifest = backup_to_tarball(
        output_path=out,
        knowledge_dir=knowledge_dir,
        config_dir=config_dir,
    )

    assert out.exists()
    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["swf_node_version"]  # non-empty
    captured = {f["path"]: f for f in manifest["files"]}
    assert "world_knowledge/index.db" in captured
    assert "config/identity.key" in captured
    assert "config/peers.yaml" in captured
    assert "config/.alchemists.yml" in captured
    assert "config/.reservoir.yml" in captured
    assert "config/convent-signing.key" in captured

    # The manifest's sha256s must match what's actually inside the
    # archive — this is the load-bearing invariant.
    with tarfile.open(out, "r:gz") as tf:
        names = tf.getnames()
        # Single archive root.
        roots = {n.split("/", 1)[0] for n in names}
        assert len(roots) == 1
        root = next(iter(roots))
        for entry in manifest["files"]:
            arc_path = f"{root}/{entry['path']}"
            assert arc_path in names, arc_path
            f = tf.extractfile(arc_path)
            data = f.read()
            import hashlib
            assert hashlib.sha256(data).hexdigest() == entry["sha256"]
            assert len(data) == entry["size"]

    # The tarball should be 0600 — sensitive (contains identity seed).
    mode = out.stat().st_mode & 0o777
    assert mode == 0o600, f"backup tarball mode {oct(mode)}; expected 0o600"


# ── 2. optional files absent → backup still succeeds ─────────────


def test_backup_handles_missing_optional_files(tmp_path: Path):
    """A freshly-init'd box has identity.key + the indrex DB but no
    peers.yaml / convent-signing.key. The backup should not fail and
    the manifest should only mention what was actually present."""
    knowledge_dir = tmp_path / "world_knowledge"
    config_dir = tmp_path / "config"
    knowledge_dir.mkdir(parents=True)
    _seed_indrex(knowledge_dir / "index.db", n_rows=3)
    config_dir.mkdir(parents=True)
    (config_dir / "identity.key").write_bytes(b"\x11" * 32)
    os.chmod(config_dir / "identity.key", 0o600)

    out = tmp_path / "fresh.tar.gz"
    manifest = backup_to_tarball(
        output_path=out,
        knowledge_dir=knowledge_dir,
        config_dir=config_dir,
    )

    captured = {f["path"] for f in manifest["files"]}
    assert "world_knowledge/index.db" in captured
    assert "config/identity.key" in captured
    # These must NOT be in the manifest because they didn't exist.
    assert "config/peers.yaml" not in captured
    assert "config/.alchemists.yml" not in captured
    assert "config/.reservoir.yml" not in captured
    assert "config/convent-signing.key" not in captured


# ── 3. sqlite online-backup API works under concurrent writes ─────


def test_backup_uses_sqlite_online_backup_api(tmp_path: Path):
    """Spin up a writer thread inserting into index.db concurrently
    with the backup. The backup must complete cleanly and the resulting
    copy must be a valid sqlite DB on which `ensure_schema` runs."""
    knowledge_dir = tmp_path / "world_knowledge"
    config_dir = tmp_path / "config"
    knowledge_dir.mkdir(parents=True)
    _seed_indrex(knowledge_dir / "index.db", n_rows=10)
    _seed_config(config_dir, with_optional=False)
    db = knowledge_dir / "index.db"

    stop = threading.Event()

    def _writer():
        # Use a fresh connection in this thread; SQLite connections
        # are not thread-safe for sharing.
        conn = sqlite3.connect(str(db))
        try:
            i = 1000
            while not stop.is_set():
                try:
                    conn.execute(
                        "INSERT INTO pages_meta(url, content_hash) "
                        "VALUES (?, ?) ON CONFLICT(url) DO NOTHING",
                        (f"https://writer.test/{i}", f"hash-{i}"),
                    )
                    conn.commit()
                except sqlite3.OperationalError:
                    # Backup is holding a lock; retry.
                    pass
                i += 1
                # Tight loop is fine — we want pressure during the backup.
        finally:
            conn.close()

    t = threading.Thread(target=_writer, daemon=True)
    t.start()
    try:
        # Give the writer a beat to actually write some rows.
        time.sleep(0.05)
        out = tmp_path / "live.tar.gz"
        backup_to_tarball(
            output_path=out,
            knowledge_dir=knowledge_dir,
            config_dir=config_dir,
        )
    finally:
        stop.set()
        t.join(timeout=5)

    # Restore the captured DB and confirm we can open it AND that
    # ensure_schema works on it (i.e. it's a valid, usable copy).
    restore_target_kn = tmp_path / "restored_kn"
    restore_target_cfg = tmp_path / "restored_cfg"
    restore_from_tarball(
        tarball=out,
        target_knowledge_dir=restore_target_kn,
        target_config_dir=restore_target_cfg,
        force=True,
    )
    restored_db = restore_target_kn / "index.db"
    assert restored_db.exists()
    conn = sqlite3.connect(str(restored_db))
    try:
        from swf.search.migration import ensure_schema
        ensure_schema(conn)
        conn.commit()
        # The DB must contain at least the 10 seeded rows. (The writer
        # may or may not have committed any of its rows before the
        # online-backup snapshot — that's fine; we just care the
        # snapshot is consistent.)
        n = conn.execute(
            "SELECT COUNT(*) FROM pages_meta"
        ).fetchone()[0]
        assert n >= 10
    finally:
        conn.close()


# ── 4. restore round-trips ────────────────────────────────────────


def test_restore_round_trips(populated_state, tmp_path: Path):
    knowledge_dir, config_dir = populated_state
    out = tmp_path / "rt.tar.gz"

    manifest = backup_to_tarball(
        output_path=out,
        knowledge_dir=knowledge_dir,
        config_dir=config_dir,
    )

    target_kn = tmp_path / "target_kn"
    target_cfg = tmp_path / "target_cfg"
    result = restore_from_tarball(
        tarball=out,
        target_knowledge_dir=target_kn,
        target_config_dir=target_cfg,
        force=False,  # fresh dirs — no clobber
    )
    assert sorted(result["restored"]) == sorted(
        f["path"] for f in manifest["files"]
    )
    assert result["skipped"] == []

    # Per-file sha256 round-trip.
    import hashlib
    for entry in manifest["files"]:
        if entry["path"].startswith("world_knowledge/"):
            dest = target_kn / entry["path"][len("world_knowledge/"):]
        else:
            dest = target_cfg / entry["path"][len("config/"):]
        assert dest.exists(), entry["path"]
        assert (
            hashlib.sha256(dest.read_bytes()).hexdigest() == entry["sha256"]
        )
        assert dest.stat().st_size == entry["size"]

    # The restored DB must be usable.
    conn = sqlite3.connect(str(target_kn / "index.db"))
    try:
        from swf.search.migration import ensure_schema
        ensure_schema(conn)
        conn.commit()
        n = conn.execute(
            "SELECT COUNT(*) FROM pages_meta"
        ).fetchone()[0]
        assert n == 25
    finally:
        conn.close()

    # Sensitive keys must end up 0600.
    for sensitive in ("identity.key", "convent-signing.key"):
        mode = (target_cfg / sensitive).stat().st_mode & 0o777
        assert mode == 0o600, (
            f"{sensitive} mode {oct(mode)}; expected 0o600"
        )


# ── 5. restore refuses clobber without --force ────────────────────


def test_restore_refuses_when_target_exists_without_force(
    populated_state, tmp_path: Path,
):
    knowledge_dir, config_dir = populated_state
    out = tmp_path / "guard.tar.gz"
    backup_to_tarball(
        output_path=out,
        knowledge_dir=knowledge_dir,
        config_dir=config_dir,
    )

    target_kn = tmp_path / "live_kn"
    target_cfg = tmp_path / "live_cfg"
    # Pre-populate the target indrex DB so the safety check fires.
    _seed_indrex(target_kn / "index.db", n_rows=2)

    with pytest.raises(BackupError) as excinfo:
        restore_from_tarball(
            tarball=out,
            target_knowledge_dir=target_kn,
            target_config_dir=target_cfg,
            force=False,
        )
    msg = str(excinfo.value).lower()
    assert "force" in msg

    # With --force, it succeeds.
    result = restore_from_tarball(
        tarball=out,
        target_knowledge_dir=target_kn,
        target_config_dir=target_cfg,
        force=True,
    )
    assert result["restored"]


# ── 6. tampered tarball is rejected on sha256 mismatch ────────────


def test_restore_rejects_tampered_tarball(populated_state, tmp_path: Path):
    knowledge_dir, config_dir = populated_state
    out = tmp_path / "tamper.tar.gz"
    backup_to_tarball(
        output_path=out,
        knowledge_dir=knowledge_dir,
        config_dir=config_dir,
    )

    # Re-pack the tarball with one file's content flipped. Easiest way
    # without rewriting tarfile internals: extract everything to a
    # tmpdir, twiddle a byte in identity.key, re-tar.
    extract_to = tmp_path / "extracted"
    extract_to.mkdir()
    with tarfile.open(out, "r:gz") as tf:
        tf.extractall(extract_to)
    # There should be exactly one root dir.
    roots = [p for p in extract_to.iterdir() if p.is_dir()]
    assert len(roots) == 1
    root = roots[0]
    target = root / "config" / "identity.key"
    assert target.exists()
    raw = bytearray(target.read_bytes())
    raw[0] ^= 0xFF  # flip a byte
    target.write_bytes(bytes(raw))

    tampered = tmp_path / "tampered.tar.gz"
    with tarfile.open(tampered, "w:gz") as tf:
        tf.add(root, arcname=root.name)

    target_kn = tmp_path / "tk2"
    target_cfg = tmp_path / "tc2"
    with pytest.raises(BackupError) as excinfo:
        restore_from_tarball(
            tarball=tampered,
            target_knowledge_dir=target_kn,
            target_config_dir=target_cfg,
            force=False,
        )
    msg = str(excinfo.value).lower()
    assert "sha256" in msg or "integrity" in msg


# ── 7. unknown schema_version is rejected ─────────────────────────


def test_restore_rejects_unknown_schema_version(tmp_path: Path):
    """Hand-roll a tarball whose manifest claims schema_version: 99
    so future-version backups don't silently succeed against today's
    binary."""
    root_name = "swf-node-backup-future"
    root = tmp_path / root_name
    (root / "config").mkdir(parents=True)
    fake_key = root / "config" / "identity.key"
    fake_key.write_bytes(b"\x00" * 32)

    import hashlib
    manifest = {
        "schema_version": 99,
        "swf_node_version": "999.0.0",
        "created_at": "2099-01-01T00:00:00Z",
        "files": [{
            "path": "config/identity.key",
            "size": 32,
            "sha256": hashlib.sha256(b"\x00" * 32).hexdigest(),
        }],
    }
    (root / "manifest.json").write_text(json.dumps(manifest))

    archive = tmp_path / "future.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root, arcname=root_name)

    target_kn = tmp_path / "tk_fu"
    target_cfg = tmp_path / "tc_fu"
    with pytest.raises(BackupError) as excinfo:
        restore_from_tarball(
            tarball=archive,
            target_knowledge_dir=target_kn,
            target_config_dir=target_cfg,
            force=False,
        )
    msg = str(excinfo.value).lower()
    assert "schema_version" in msg or "unsupported" in msg


# ── 8. CLI round-trip via subprocess ──────────────────────────────


def _swf_node_invocation() -> list[str]:
    """Always use `python -m swf` so the subprocess imports from the
    same `swf` package that the in-process test resolved (pytest's
    `pythonpath = ["src"]` puts THIS checkout first; the console
    script `swf-node` may resolve to a different editable install
    further up the directory tree, e.g. when this is a worktree of a
    parent repo)."""
    return [sys.executable, "-m", "swf"]


def _run(*args, env: dict | None = None) -> tuple[int, str, str]:
    e = os.environ.copy()
    # Mirror pytest's pythonpath setting so the subprocess resolves
    # `swf` to the same checkout as the in-process tests.
    repo_src = str(Path(__file__).resolve().parent.parent / "src")
    existing = e.get("PYTHONPATH", "")
    e["PYTHONPATH"] = (
        f"{repo_src}:{existing}" if existing else repo_src
    )
    if env:
        e.update(env)
        # Don't let caller-supplied env clobber our PYTHONPATH unless
        # they explicitly set one.
        if "PYTHONPATH" not in env:
            e["PYTHONPATH"] = (
                f"{repo_src}:{existing}" if existing else repo_src
            )
    cmd = [*_swf_node_invocation(), *args]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, env=e,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_cli_backup_and_restore_roundtrip(tmp_path: Path):
    """Spawn `swf-node backup` and `swf-node restore` as subprocesses,
    asserting non-zero behavior + stdout messaging."""
    src_kn = tmp_path / "src_kn"
    src_cfg = tmp_path / "src_cfg"
    src_kn.mkdir()
    _seed_indrex(src_kn / "index.db", n_rows=5)
    _seed_config(src_cfg, with_optional=True)

    # Backup: point env at the source dirs so the CLI's defaults
    # resolve there. HOME redirect protects against accidental real-
    # home writes if anything misbehaves.
    out = tmp_path / "cli.tar.gz"
    backup_env = {
        "HOME": str(tmp_path),
        "SWF_KNOWLEDGE_DIR": str(src_kn),
        "SWF_CONFIG_DIR": str(src_cfg),
        "SWF_STATE_DIR": str(tmp_path / "state"),
        "SWF_NO_MDNS": "1",
    }
    rc, stdout, stderr = _run("backup", "--output", str(out), env=backup_env)
    assert rc == 0, f"backup failed: stderr={stderr!r}"
    assert "backup written" in stdout
    assert out.exists()

    # Restore to fresh tmp dirs via the CLI flags (don't rely on env).
    target_kn = tmp_path / "tgt_kn"
    target_cfg = tmp_path / "tgt_cfg"
    rc, stdout, stderr = _run(
        "restore",
        str(out),
        "--target-knowledge-dir", str(target_kn),
        "--target-config-dir", str(target_cfg),
        env={
            "HOME": str(tmp_path),
            "SWF_NO_MDNS": "1",
        },
    )
    assert rc == 0, f"restore failed: stderr={stderr!r}"
    assert "restore complete" in stdout
    assert (target_kn / "index.db").exists()
    assert (target_cfg / "identity.key").exists()
    assert (target_cfg / "peers.yaml").exists()


# ── verify_backup ──────────────────────────────────────────────────


def test_verify_backup_reports_clean(populated_state, tmp_path: Path):
    knowledge_dir, config_dir = populated_state
    out = tmp_path / "verify.tar.gz"
    backup_to_tarball(
        output_path=out,
        knowledge_dir=knowledge_dir,
        config_dir=config_dir,
    )
    rep = verify_backup(out)
    assert rep["ok"] is True
    assert rep["mismatches"] == []
    assert rep["manifest"]["schema_version"] == SCHEMA_VERSION
