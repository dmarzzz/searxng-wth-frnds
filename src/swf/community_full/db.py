"""metrics.db helpers.

Issue #43 PR C trimmed this module down to what the self-contained
metrics collector needs. The legacy community-graph machinery
(contributions, pages, peers, etc) has moved to indrex.db's
single-graph model — see `swf.indrex_graph` and `swf.event_bus`.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
DEFAULT_DB = Path(os.environ.get(
    "SWF_COMMUNITY_DB",
    Path.home() / ".local" / "share" / "swf" / "community.db",
))

_lock = threading.Lock()


def db_path() -> Path:
    return DEFAULT_DB


def init(path: Path | None = None) -> Path:
    p = Path(path) if path else db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    sql = SCHEMA_PATH.read_text()
    with sqlite3.connect(p) as conn:
        conn.executescript(sql)
    return p


@contextmanager
def writer():
    conn = sqlite3.connect(db_path(), isolation_level=None, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        with _lock:
            yield conn
    finally:
        conn.close()


@contextmanager
def reader():
    conn = sqlite3.connect(f"file:{db_path()}?mode=ro", uri=True, timeout=2.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


## peer signature derivation has moved to `swf.peer_signature`
## (P2P-review #6). Re-exported here for back-compat with callers
## that imported it from `community_full.db`.
from swf.peer_signature import signature_for  # noqa: E402,F401
