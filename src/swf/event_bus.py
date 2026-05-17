"""Issue #43 PR B — indrex-backed event bus.

Replaces the legacy `community_full.events` bus. Events live in
`indrex.db`'s `events` table (created by `swf.search.migration`), so
the wall can subscribe via SSE without depending on community.db at all.

Public surface:
    emit(kind, payload)              — append + fan out to live subs
    subscribe(replay_since_id=None)  — generator yielding event dicts
                                        (or None heartbeats every 15s)
    recent(kind=None, limit=50)      — DB-only history snapshot

Wire format (matches the legacy bus so the wall doesn't need changes
beyond the new event kinds):
    { "id": int, "ts": "...Z", "kind": "...", "payload": {...} }

Concurrency:
    - DB writes go through a short-held connection per emit; relies on
      WAL mode set by `swf.indrex.db_path()` consumers.
    - Live fan-out is via a per-subscriber bounded queue. Slow
      subscribers drop messages (`queue.Full` is silent) — they catch up
      via the next `since=<id>` replay.
"""
from __future__ import annotations

import contextlib
import json
import logging
import queue
import sqlite3
import threading
from collections import deque
from collections.abc import Iterator

from . import indrex
from .search import migration

logger = logging.getLogger(__name__)

_subscribers_lock = threading.Lock()
_subscribers: list[queue.Queue] = []
_recent: deque = deque(maxlen=512)


# P2P-review #4: bound the events table. Without a vacuum, ~50k
# events/hour from the scraper grow unbounded and the WAL file with
# them. Strategy: opportunistic vacuum every N emits, retaining the
# most-recent EVENT_RETAIN rows + last 7 days. Mirrors the
# spent-nullifier vacuum cadence in tickets.py.
_VACUUM_EVERY = 1024
_EVENT_RETAIN_COUNT = 100_000
_EVENT_RETAIN_DAYS = 7
_emit_count_lock = threading.Lock()
_emit_count = 0


def _connect():
    """Open indrex.db read/write. WAL mode is enabled once-per-DB by
    `migration.ensure_schema` (pass-5 #5); re-issuing it on every
    connect was a non-trivial transaction that collided with
    concurrent writers and dropped events as `database is locked`.
    Connect timeout bumped to 5s so a brief contention spike during
    heavy emit traffic doesn't lose entries."""
    p = indrex.db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=5.0)
    migration.ensure_schema(conn)
    return conn


def emit(kind: str, payload: dict) -> None:
    """Append `(kind, payload)` to indrex.events and fan out to live
    subscribers. Best-effort: a DB error is logged but never raised —
    the caller (peer scraper, mdns probe, etc) shouldn't crash because
    of an event log failure.

    Opportunistic vacuum every _VACUUM_EVERY emits keeps the events
    table bounded (P2P-review #4)."""
    body = json.dumps(payload, separators=(",", ":"))
    eid: int | None = None
    ts: str | None = None
    try:
        conn = _connect()
        try:
            cur = conn.execute(
                "INSERT INTO events(kind, payload_json) VALUES(?, ?)",
                (kind, body),
            )
            eid = cur.lastrowid
            row = conn.execute(
                "SELECT ts FROM events WHERE id=?", (eid,),
            ).fetchone()
            ts = row[0] if row else None
            conn.commit()
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        logger.error("db emit failed: %s", e)
    if eid is None:
        return
    msg = {"id": int(eid), "ts": ts, "kind": kind, "payload": payload}
    _recent.append(msg)
    with _subscribers_lock:
        live = list(_subscribers)
    for q in live:
        with contextlib.suppress(queue.Full):
            q.put_nowait(msg)
    # Opportunistic vacuum.
    global _emit_count
    with _emit_count_lock:
        _emit_count += 1
        do_vacuum = (_emit_count % _VACUUM_EVERY) == 0
    if do_vacuum:
        with contextlib.suppress(Exception):
            vacuum_events()


def vacuum_events(
    *,
    retain_count: int = _EVENT_RETAIN_COUNT,
    retain_days: int = _EVENT_RETAIN_DAYS,
) -> int:
    """Trim the events table: keep the most-recent `retain_count` rows
    AND any row newer than `retain_days`. Returns the number of rows
    deleted. Also runs `PRAGMA wal_checkpoint(TRUNCATE)` so the WAL
    file shrinks after the DELETE.

    Cron-friendly. Called opportunistically from `emit` every
    _VACUUM_EVERY writes; can also be invoked directly."""
    try:
        conn = _connect()
    except sqlite3.DatabaseError:
        return 0
    try:
        # We keep any row that's in the top-N by id OR (if age rule
        # enabled) newer than the cutoff. The "delete floor" is the
        # LOWER (older) of the two per-rule minimums, since
        # OR-semantics means we keep everything at-or-above either
        # threshold. Set retain_days <= 0 to disable the age rule.
        recent_row = conn.execute(
            "SELECT MIN(id) FROM "
            "(SELECT id FROM events ORDER BY id DESC LIMIT ?)",
            (int(retain_count),),
        ).fetchone()
        candidates = []
        if recent_row is not None and recent_row[0] is not None:
            candidates.append(recent_row[0])
        if retain_days > 0:
            from datetime import datetime, timedelta, timezone
            cutoff_ts = (
                datetime.now(timezone.utc) - timedelta(days=retain_days)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            age_row = conn.execute(
                "SELECT MIN(id) FROM events WHERE ts >= ?",
                (cutoff_ts,),
            ).fetchone()
            if age_row is not None and age_row[0] is not None:
                candidates.append(age_row[0])
        keep_floor = min(candidates) if candidates else None
        if keep_floor is None:
            deleted = 0
        else:
            cur = conn.execute(
                "DELETE FROM events WHERE id < ?", (int(keep_floor),),
            )
            conn.commit()
            deleted = int(cur.rowcount or 0)
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return deleted
    finally:
        conn.close()


def subscribe(
    replay_since_id: int | None = None,
    heartbeat_seconds: float = 15.0,
) -> Iterator[dict | None]:
    """Synchronous generator. Replays history (id > replay_since_id)
    then yields live events. Yields `None` once per `heartbeat_seconds`
    when idle so the SSE handler can flush a keepalive."""
    q: queue.Queue = queue.Queue(maxsize=512)
    with _subscribers_lock:
        _subscribers.append(q)
    try:
        if replay_since_id is not None:
            try:
                conn = _connect()
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, ts, kind, payload_json FROM events "
                    "WHERE id > ? ORDER BY id",
                    (int(replay_since_id),),
                ).fetchall()
                conn.close()
            except sqlite3.DatabaseError:
                rows = []
            for r in rows:
                try:
                    payload = json.loads(r["payload_json"])
                except Exception:
                    payload = {}
                yield {
                    "id": int(r["id"]),
                    "ts": r["ts"],
                    "kind": r["kind"],
                    "payload": payload,
                }
        while True:
            try:
                msg = q.get(timeout=heartbeat_seconds)
                yield msg
            except queue.Empty:
                yield None
    finally:
        with _subscribers_lock, contextlib.suppress(ValueError):
            _subscribers.remove(q)


def recent(kind: str | None = None, limit: int = 50) -> list[dict]:
    """Most-recent events (DB-only — useful for tests, /admin pages,
    diagnostics). Optionally filtered by `kind`."""
    limit = max(1, min(int(limit), 1000))
    try:
        conn = _connect()
        conn.row_factory = sqlite3.Row
        if kind is None:
            rows = conn.execute(
                "SELECT id, ts, kind, payload_json FROM events "
                "ORDER BY id DESC LIMIT ?", (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, ts, kind, payload_json FROM events "
                "WHERE kind=? ORDER BY id DESC LIMIT ?", (kind, limit),
            ).fetchall()
        conn.close()
    except sqlite3.DatabaseError:
        return []
    out: list[dict] = []
    for r in rows:
        try:
            payload = json.loads(r["payload_json"])
        except Exception:
            payload = {}
        out.append({
            "id": int(r["id"]), "ts": r["ts"],
            "kind": r["kind"], "payload": payload,
        })
    return out


__all__ = ["emit", "subscribe", "recent", "vacuum_events"]
