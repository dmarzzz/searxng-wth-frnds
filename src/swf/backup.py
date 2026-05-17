"""Convent-box snapshot + restore.

Operator workflow:

    swf-node backup --output ~/backups/convent-$(date +%Y%m%d).tar.gz
    swf-node restore ~/backups/convent-20260509.tar.gz

The backup captures everything an operator needs to recover a node:

    * `world_knowledge/index.db` (the indrex + bundles store)
    * `~/.config/swf/identity.key` (the peer Ed25519 identity)
    * `~/.config/swf/peers.yaml` (if present)
    * `~/.config/swf/.alchemists.yml` and `.reservoir.yml` (if present)
    * `~/.config/swf/convent-signing.key` (if present)

Stdlib-only on purpose. The module exports three entrypoints that the
CLI dispatcher in `swf.peer_server` thin-wraps:

    backup_to_tarball(...)   -> dict        write a tarball, return manifest
    restore_from_tarball(...) -> dict       restore files from a tarball
    verify_backup(tarball)    -> dict       read-only sha256 check

Why `sqlite3.connect(...).backup(...)` for the indrex DB and not `cp`:
the indrex runs in WAL mode, so a raw byte-copy mid-checkpoint can
yield a torn read where the journal and the main file disagree. The
online-backup API holds the right locks for the duration of the page
copy and produces a self-consistent snapshot even while the daemon is
serving requests.

Why a single tarball: ops people want to scp one artifact, not a
directory tree. Setting it 0600 because it contains the identity.key
and (when present) the convent-signing.key — both are sensitive.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import os
import sqlite3
import tarfile
import tempfile
from pathlib import Path

from swf import __version__ as SWF_VERSION

SCHEMA_VERSION = 1

# Files relative to the config_dir. `peers.yaml` and the alchemists /
# reservoir / convent-signing files are optional — present on a fully
# wired convent box, absent on a freshly-init'd one. The backup must
# tolerate either.
_CONFIG_FILES: tuple[str, ...] = (
    "identity.key",
    "peers.yaml",
    ".alchemists.yml",
    ".reservoir.yml",
    "convent-signing.key",
)

# Files relative to the knowledge_dir. `index.db` is captured via the
# sqlite3 online-backup API to stay safe against a concurrently-running
# daemon's WAL checkpoint.
_KNOWLEDGE_DB = "index.db"


class BackupError(RuntimeError):
    """Raised when a backup or restore operation cannot proceed safely."""


def _sha256_file(path: Path, chunk: int = 1 << 16) -> str:
    """Stream-hash a file. We never load the full DB into memory."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def _online_backup_sqlite(src: Path, dest: Path) -> None:
    """Copy `src` (a SQLite DB, possibly being written by another
    process) into `dest` using the online-backup API.

    The API copies pages under the right locks and is the canonical
    way to snapshot a live SQLite DB without halting writers.
    """
    src_conn = sqlite3.connect(str(src))
    try:
        # `dest` shouldn't exist yet — the destination is a fresh
        # file inside the staging dir.
        dest_conn = sqlite3.connect(str(dest))
        try:
            src_conn.backup(dest_conn)
            dest_conn.commit()
        finally:
            dest_conn.close()
    finally:
        src_conn.close()


def _iso_timestamp() -> str:
    """UTC, second precision, filesystem-safe (no colons)."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _default_output_path() -> Path:
    return Path.cwd() / f"swf-node-backup-{_iso_timestamp()}.tar.gz"


def backup_to_tarball(
    *,
    output_path: Path | None = None,
    knowledge_dir: Path,
    config_dir: Path,
) -> dict:
    """Snapshot the node's state into a single tarball.

    Returns the manifest dict (also written verbatim to
    ``manifest.json`` inside the tarball). Writes the tarball at
    ``output_path`` with mode 0600.

    Optional files (peers.yaml, .alchemists.yml, .reservoir.yml,
    convent-signing.key) are skipped silently if absent — the manifest
    only lists what was captured.
    """
    if output_path is None:
        output_path = _default_output_path()
    output_path = Path(output_path)
    knowledge_dir = Path(knowledge_dir)
    config_dir = Path(config_dir)

    # Stage everything under a tmpdir, then build the tarball atomically.
    # The staging dir is removed when the with-block exits.
    with tempfile.TemporaryDirectory(prefix="swf-backup-") as staging_str:
        staging = Path(staging_str)
        root_name = output_path.name.removesuffix(".tar.gz")
        if root_name.endswith(".tar"):
            root_name = root_name[: -len(".tar")]
        if not root_name:
            root_name = f"swf-node-backup-{_iso_timestamp()}"
        root = staging / root_name
        (root / "world_knowledge").mkdir(parents=True)
        (root / "config").mkdir(parents=True)

        files: list[dict] = []

        # 1. indrex DB via online-backup API. `world_knowledge/index.db`
        #    might be absent on a freshly-init'd box; that's fine — we
        #    just don't include it in the manifest.
        src_db = knowledge_dir / _KNOWLEDGE_DB
        if src_db.exists():
            dest_db = root / "world_knowledge" / _KNOWLEDGE_DB
            _online_backup_sqlite(src_db, dest_db)
            files.append({
                "path": f"world_knowledge/{_KNOWLEDGE_DB}",
                "size": dest_db.stat().st_size,
                "sha256": _sha256_file(dest_db),
            })

        # 2. Config files. The identity.key is the only one that's
        #    semi-required (a node without it can't sign anything),
        #    but we still don't HARD fail — let the operator decide.
        for name in _CONFIG_FILES:
            src = config_dir / name
            if not src.exists():
                continue
            dest = root / "config" / name
            dest.write_bytes(src.read_bytes())
            # Preserve the 0600 perms on identity.key / convent-signing.key
            # in the staging area too, so a `tar -xf` ends up with the
            # right perms by default.
            with contextlib.suppress(OSError):
                os.chmod(dest, src.stat().st_mode & 0o777)
            files.append({
                "path": f"config/{name}",
                "size": dest.stat().st_size,
                "sha256": _sha256_file(dest),
            })

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "swf_node_version": SWF_VERSION,
            "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(
                timespec="seconds",
            ).replace("+00:00", "Z"),
            "files": files,
        }
        manifest_path = root / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        )

        # Build the tarball. We open with mode 'w:gz' and add the staging
        # root with arcname=root_name so paths inside the archive are
        # `<root_name>/manifest.json`, etc.
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output_path, "w:gz") as tf:
            tf.add(root, arcname=root_name)

    # Restrictive perms: the tarball contains the identity seed.
    with contextlib.suppress(OSError):
        os.chmod(output_path, 0o600)

    return manifest


# ── Restore ────────────────────────────────────────────────────────


def _safe_extract_one(
    tf: tarfile.TarFile, member: tarfile.TarInfo, dest_dir: Path,
) -> Path:
    """Extract `member` to `dest_dir`, refusing absolute paths and
    ``..`` traversal. Returns the resolved on-disk path.

    PEP 706 (Python 3.12+) ships a `data` filter that does similar
    rejection, but we support 3.10+ so we open-code it.
    """
    name = member.name
    # Strip the top-level archive root (`<root_name>/...`); the caller
    # passed us the member straight from the archive.
    if name.startswith("/") or ".." in Path(name).parts:
        raise BackupError(f"refusing unsafe archive member {name!r}")
    target = (dest_dir / name).resolve()
    if not str(target).startswith(str(dest_dir.resolve())):
        raise BackupError(f"archive member {name!r} escapes destination")
    return target


def _read_manifest(tf: tarfile.TarFile, archive_root: str) -> dict:
    """Locate and parse manifest.json inside the open tarball."""
    member_name = f"{archive_root}/manifest.json"
    try:
        member = tf.getmember(member_name)
    except KeyError as exc:
        raise BackupError(
            f"backup archive missing {member_name} — not a swf-node backup",
        ) from exc
    f = tf.extractfile(member)
    if f is None:
        raise BackupError(f"could not read {member_name} from archive")
    try:
        return json.loads(f.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError(f"manifest.json is not valid JSON: {exc}") from exc


def _detect_archive_root(tf: tarfile.TarFile) -> str:
    """Find the top-level directory inside the archive. We accept any
    single-rooted layout (`<root>/manifest.json`, `<root>/config/...`,
    `<root>/world_knowledge/...`)."""
    roots = set()
    for name in tf.getnames():
        head = name.split("/", 1)[0]
        if head:
            roots.add(head)
    if len(roots) != 1:
        raise BackupError(
            f"archive has {len(roots)} top-level entries; "
            "expected exactly one root directory",
        )
    return next(iter(roots))


def _validate_schema(manifest: dict) -> None:
    sv = manifest.get("schema_version")
    if sv != SCHEMA_VERSION:
        raise BackupError(
            f"unsupported manifest schema_version {sv!r}; "
            f"this swf-node only understands {SCHEMA_VERSION}",
        )


def verify_backup(tarball: Path) -> dict:
    """Read-only: parse manifest, recompute sha256 for each captured
    file inside the archive, and report any drift.

    Returns ``{"manifest": {...}, "ok": bool, "mismatches": [...]}``.
    Raises BackupError only on structural problems (no manifest,
    unknown schema, malformed archive).
    """
    tarball = Path(tarball)
    if not tarball.exists():
        raise BackupError(f"no such file: {tarball}")

    with tarfile.open(tarball, "r:gz") as tf:
        root = _detect_archive_root(tf)
        manifest = _read_manifest(tf, root)
        _validate_schema(manifest)

        mismatches: list[dict] = []
        for entry in manifest.get("files", []):
            arc_path = f"{root}/{entry['path']}"
            try:
                member = tf.getmember(arc_path)
            except KeyError:
                mismatches.append({
                    "path": entry["path"], "reason": "missing in archive",
                })
                continue
            f = tf.extractfile(member)
            if f is None:
                mismatches.append({
                    "path": entry["path"], "reason": "not extractable",
                })
                continue
            h = hashlib.sha256()
            while True:
                buf = f.read(1 << 16)
                if not buf:
                    break
                h.update(buf)
            got = h.hexdigest()
            if got != entry.get("sha256"):
                mismatches.append({
                    "path": entry["path"],
                    "reason": "sha256 mismatch",
                    "expected": entry.get("sha256"),
                    "actual": got,
                })

    return {
        "manifest": manifest,
        "ok": not mismatches,
        "mismatches": mismatches,
    }


def _target_paths(
    target_knowledge_dir: Path, target_config_dir: Path, manifest_path: str,
) -> Path:
    """Resolve the on-disk destination for a manifest entry."""
    if manifest_path.startswith("world_knowledge/"):
        rel = manifest_path[len("world_knowledge/"):]
        return target_knowledge_dir / rel
    if manifest_path.startswith("config/"):
        rel = manifest_path[len("config/"):]
        return target_config_dir / rel
    raise BackupError(
        f"unrecognized manifest path {manifest_path!r} — "
        "expected world_knowledge/* or config/*",
    )


def restore_from_tarball(
    *,
    tarball: Path,
    target_knowledge_dir: Path,
    target_config_dir: Path,
    force: bool = False,
) -> dict:
    """Inverse of `backup_to_tarball`. Verify sha256s, then write the
    captured files into the target dirs.

    Safety rails:

      * Refuse if the target ``index.db`` exists and is non-empty
        unless ``force=True``. We don't clobber operator data on a
        typo.
      * Refuse if any individual target file exists unless ``force``.
      * Verify each file's sha256 matches the manifest BEFORE writing
        anything to the target dirs. A tampered tarball aborts before
        we touch the live state.
      * Reject unknown ``schema_version`` outright.

    Returns ``{"restored": [...], "skipped": [...], "manifest": {...}}``.
    """
    tarball = Path(tarball)
    if not tarball.exists():
        raise BackupError(f"no such file: {tarball}")
    target_knowledge_dir = Path(target_knowledge_dir)
    target_config_dir = Path(target_config_dir)

    # Round 1: verify integrity end-to-end. Do this before any mkdir
    # on the target side; if the tarball is busted, leave the target
    # untouched.
    verification = verify_backup(tarball)
    if not verification["ok"]:
        details = ", ".join(
            f"{m['path']} ({m['reason']})" for m in verification["mismatches"]
        )
        raise BackupError(
            f"backup integrity check failed: {details}",
        )
    manifest = verification["manifest"]

    # Round 2: pre-flight clobber check. Before writing anything,
    # confirm every destination is either absent OR force=True.
    target_db = target_knowledge_dir / _KNOWLEDGE_DB
    if target_db.exists() and target_db.stat().st_size > 0 and not force:
        raise BackupError(
            f"target indrex DB already exists and is non-empty: {target_db} "
            "(pass --force to overwrite)",
        )
    if not force:
        for entry in manifest.get("files", []):
            dest = _target_paths(
                target_knowledge_dir, target_config_dir, entry["path"],
            )
            if dest.exists():
                raise BackupError(
                    f"target file exists: {dest} (pass --force to overwrite)",
                )

    # Round 3: actually extract. We can't use TarFile.extract directly
    # because we want to write to two distinct target roots (config_dir
    # vs knowledge_dir), with mode preservation on sensitive keys.
    target_knowledge_dir.mkdir(parents=True, exist_ok=True)
    target_config_dir.mkdir(parents=True, exist_ok=True)

    restored: list[str] = []
    skipped: list[str] = []

    with tarfile.open(tarball, "r:gz") as tf:
        archive_root = _detect_archive_root(tf)
        for entry in manifest.get("files", []):
            arc_path = f"{archive_root}/{entry['path']}"
            try:
                member = tf.getmember(arc_path)
            except KeyError:
                # Already caught by verify_backup, but defensive in case
                # the archive was modified between the verify and the
                # restore.
                skipped.append(entry["path"])
                continue
            _safe_extract_one(tf, member, Path(tempfile.gettempdir()))
            f = tf.extractfile(member)
            if f is None:
                skipped.append(entry["path"])
                continue
            data = f.read()
            dest = _target_paths(
                target_knowledge_dir, target_config_dir, entry["path"],
            )
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            # Sensitive keys (identity.key, convent-signing.key) need
            # 0600; tarfile preserves perms but we re-apply explicitly
            # because the staging-side chmod was best-effort.
            if entry["path"] in (
                "config/identity.key", "config/convent-signing.key",
            ):
                with contextlib.suppress(OSError):
                    os.chmod(dest, 0o600)
            restored.append(entry["path"])

    return {"restored": restored, "skipped": skipped, "manifest": manifest}
