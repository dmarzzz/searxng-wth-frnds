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

# Embedded copy of schema.sql. PyInstaller onefile builds ship the .sql
# via `--collect-data swf`, but the bootloader's _MEI extraction is
# occasionally incomplete (stale/contended temp dirs), and a missing
# schema.sql here was crash-looping the whole daemon at startup
# (_start_full_subsystems → init() → FileNotFoundError). The file stays
# the source of truth; this string is a byte-for-byte fallback so the
# daemon still boots when extraction drops the file. Keep them in sync —
# tests/community_full/test_schema_embed.py asserts equality.
_EMBEDDED_SCHEMA = """\
-- metrics.db schema (post-#43 PR C). The legacy community-graph
-- tables (peers, pages, page_contributors, search_results, visits,
-- contributions, pending_contributions, events, embeddings) are
-- gone — that data lives in indrex.db now via the single-graph model.
-- What remains is the self-contained metrics collector's storage.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- arbitrary server state for the metrics collector.
CREATE TABLE IF NOT EXISTS kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Self-contained Prometheus-lite. The `metrics` background thread
-- inserts rows on a fixed cadence (default 10s) and a maintenance pass
-- deletes rows older than 7 days. The viz polls `/metrics/series` and
-- `/metrics/snapshot` against this table — no separate Prometheus.
CREATE TABLE IF NOT EXISTS metrics_samples (
  ts_ms       INTEGER NOT NULL,
  name        TEXT NOT NULL,
  value       REAL NOT NULL,
  labels_json TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (ts_ms, name, labels_json)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_metrics_name_ts ON metrics_samples(name, ts_ms);
"""

_lock = threading.Lock()


def db_path() -> Path:
    return DEFAULT_DB


def _load_schema_sql() -> str:
    """Metrics-db DDL. Prefer the bundled file (source of truth); fall
    back to the embedded copy if the file is missing/unreadable — which
    happens when a PyInstaller onefile _MEI extraction comes up short and
    drops the --collect-data .sql. Without this the daemon FileNotFound-
    crashed at startup and the supervisor crash-looped it."""
    try:
        text = SCHEMA_PATH.read_text()
        if text.strip():
            return text
    except Exception:
        pass
    return _EMBEDDED_SCHEMA


def init(path: Path | None = None) -> Path:
    p = Path(path) if path else db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    sql = _load_schema_sql()
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
