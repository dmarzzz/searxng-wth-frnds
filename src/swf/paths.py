"""SWF state-directory helpers.

Centralized, single source of truth for `~/.config/swf/` and
`~/.local/share/swf/`. Every module that reads or writes state should
use these helpers so that:

  1. Directories are created with mode **0700** (owner-only).
  2. Existing directories with looser modes are silently repaired on
     first access.
  3. Future relocations (e.g. XDG_DATA_HOME) only need to change one
     module.

Hardening checklist §12 row "Mode-0600 enforcement on `~/.config/swf/`
and `~/.local/share/swf/`" is satisfied by `ensure_dir(0o700)`.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path

_DIR_MODE = 0o700  # rwx------


def config_dir() -> Path:
    """`~/.config/swf/` (or `SWF_CONFIG_DIR`). Owner-only."""
    p = Path(os.environ.get("SWF_CONFIG_DIR")
             or (Path.home() / ".config" / "swf"))
    return ensure_dir(p)


def state_dir() -> Path:
    """`~/.local/share/swf/` (or `SWF_STATE_DIR`). Owner-only."""
    p = Path(os.environ.get("SWF_STATE_DIR")
             or (Path.home() / ".local" / "share" / "swf"))
    return ensure_dir(p)


def ensure_dir(p: Path, mode: int = _DIR_MODE) -> Path:
    """Create `p` if missing, then chmod to `mode` (default 0700).
    Idempotent. The chmod runs even when the dir already exists, so
    a directory that ended up world-readable from an earlier release
    gets repaired on next access.

    Best-effort on read-only filesystems / unprivileged contexts —
    chmod failure is swallowed (the caller's `db_path()` would still
    succeed; the warning would just not get applied)."""
    with contextlib.suppress(FileExistsError):
        p.mkdir(parents=True, exist_ok=True, mode=mode)
    try:
        current = p.stat().st_mode & 0o777
        if current != mode:
            os.chmod(p, mode)
    except OSError:
        pass
    return p
