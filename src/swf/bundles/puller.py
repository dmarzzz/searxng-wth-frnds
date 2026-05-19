"""Pull-side bundle replication (#93 phase 6 follow-up).

Push-side propagation (`swf.bundles.propagation`) fans a freshly-posted
bundle out to every known peer's `/bundles` endpoint. **A peer that's
offline at broadcast time never receives that bundle** — the push-side
daemon thread doesn't retry, and there's no per-peer queue. Without a
pull-side catch-up, an offline-then-rejoin peer stays permanently behind.

This module is the catch-up. Every `DEFAULT_PULL_INTERVAL_SECS` (60s
default), for every known peer:

  1. Look up the highest `rowid` we've ingested from that peer (a
     per-peer high-water in `swf_kv` keyed by `bundles.high_water.<pubkey>`).
  2. `GET <peer>/bundles?received_since=<hw>&limit=100` to fetch any
     bundles inserted on the peer after that rowid, in rowid ASC order.
  3. For each returned envelope, run `bundles.verify_bundle` (same
     alchemist whitelist + signature + monotonicity check that
     `POST /bundles` runs) and, on success, `bundles.insert(envelope)`.
  4. Advance the per-peer high-water to the response's
     `next_received_since`. Loop until the peer signals "no more"
     (`next_received_since=null`) or `max_pages` is exhausted.

This is parallel to `swf.peer_scraper`, which pulls *search* result
pages — same shape, different transport (a search-page scraper that
rolls its own merkle-rooted bundle vs. a bundle puller that piggybacks
on the canonical `swf-bundle-v1` envelope). The two share NO code by
design — they're independent concerns over a shared `peers` table
(see `bundles.propagation` for the same rule on the push side).

Loop prevention
───────────────

`bundles.insert` is idempotent on `cid`. If peer B already pushed us a
bundle (via phase 6 push), the next pull from peer C will receive the
same bundle but `bundles.insert` returns `was_new=False` and we just
move on. Pull and push converge cleanly.

Crucially, the puller does **NOT** propagate after a successful pull
(that would create amplification — every pull would fan out to every
other peer, multiplying the storm by N each round). Push-side handles
propagation when WE locally accept a `POST /bundles`; pull is purely
catch-up.

Verify
──────

The puller passes the loaded alchemist list into `verify_bundle` so
the pull path enforces the same alchemist-signature gate as the local
`POST /bundles` write side. Per #112, the puller does NOT pass a
`reservoir=` (and POST doesn't either): swf-node is a relay over
opaque ciphertext, so screening recipient strings adds no security
boundary the alchemist signature gate doesn't already provide. The
reservoir cache helpers (`reset_reservoir_cache_for_tests`,
`_load_reservoir_cached`) stay in this module's surface for back-compat
with tests and external callers — they're just no longer consulted on
the verify path.
"""
from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .alchemists import (
    AlchemistList,
)
from .alchemists import (
    load_alchemists_cached as _shared_load_alchemists_cached,
)
from .alchemists import (
    reset_alchemists_cache_for_tests as _shared_reset_alchemists_cache,
)
from .reservoir import (
    load_reservoir_cached,
)
from .reservoir import (
    reset_reservoir_cache_for_tests as _shared_reset_reservoir_cache,
)
from .store import ensure_schema, insert
from .verify import verify_bundle

logger = logging.getLogger(__name__)

# Background tick interval. Mirrors `peer_scraper.DEFAULT_INTERVAL_SECS`
# at 60s — same cadence so an operator who tunes the LAN can reason
# about both pullers as one unit. Set the env var
# `SWF_BUNDLE_PULL_INTERVAL_SECS=0` to disable the background loop
# entirely (test convenience; production should leave it on).
DEFAULT_PULL_INTERVAL_SECS = 60

# Per-peer HTTP timeout. LAN round-trips should be sub-second; 5s lets
# us absorb a single retransmit without making the puller thread block
# on a flaky peer for the full default 10s.
_DEFAULT_HTTP_TIMEOUT_SECS = 5.0

# Body size cap. Mirror's `peer_scraper`'s 32 MiB cap — a single page
# of 100 bundles can comfortably fit (each bundle is at most a few KB,
# at most low-MB if it carries a transcript.batch payload), but a
# malicious peer that ships a 1 GB response cannot OOM the puller.
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024

# Default page size. The HTTP layer caps at 1000; we ask for 100 so
# the catch-up scans cleanly across many records without burning a
# gigantic single response.
_DEFAULT_PAGE_LIMIT = 100

# Hard cap on pages-per-pull. Defense against a misbehaving peer that
# returns `next_received_since != null` forever (a runaway-cursor
# attack). Ten pages × 100 bundles per page = 1000 bundles per peer
# per tick, comfortably more than any reasonable backlog the offline-
# then-rejoin scenario produces and orders of magnitude under the
# memory ceiling.
_DEFAULT_MAX_PAGES = 10


# ── alchemist + reservoir caches (both shared) ────────────────────────
#
# Both caches now live in their respective `swf.bundles` modules
# (`alchemists.py`, `reservoir.py`) so a single process-wide cache is
# shared across all bundle ingest channels (puller, hivemind route,
# `POST /bundles` verifier). The wrappers below preserve the puller's
# existing import surface (`_load_alchemists_cached`,
# `reset_alchemists_cache_for_tests`, `reset_reservoir_cache_for_tests`)
# so tests that reset the puller's cache continue to work after the
# lift.


def _load_alchemists_cached() -> AlchemistList:
    """Delegate to the shared `swf.bundles.alchemists` cache so all
    bundle ingest paths read the same file at most once per process."""
    return _shared_load_alchemists_cached()


def _load_reservoir_cached():
    """Delegate to the shared `swf.bundles.reservoir` cache so all
    bundle ingest paths read the same file at most once per process."""
    return load_reservoir_cached()


def reset_alchemists_cache_for_tests() -> None:
    """Drop the shared `AlchemistList` cache. Tests call this between
    cases that point at different tmp `.alchemists.yml` files. This is
    a thin wrapper over `swf.bundles.alchemists.reset_alchemists_cache_for_tests`
    so the puller's existing test surface continues to work after the
    cache was lifted to the alchemists module."""
    _shared_reset_alchemists_cache()


def reset_reservoir_cache_for_tests() -> None:
    """Drop the shared `Reservoir` cache. Tests call this between
    cases that point at different tmp `.reservoir.yml` files. This is
    a thin wrapper over `swf.bundles.reservoir.reset_reservoir_cache_for_tests`
    so the puller's existing test surface continues to work after the
    cache was lifted to the reservoir module."""
    _shared_reset_reservoir_cache()


# ── per-peer high-water ────────────────────────────────────────────────


_HIGH_WATER_KEY_PREFIX = "bundles.high_water."


def _kv_key(peer_pubkey: str) -> str:
    """Return the `swf_kv` row key for `peer_pubkey`'s high-water."""
    return _HIGH_WATER_KEY_PREFIX + peer_pubkey


def _ensure_kv_table(conn: sqlite3.Connection) -> None:
    """Create the `swf_kv` table if missing.

    The search migration owns this table in production (it's mostly
    used for `node_epoch_id`), but a process that has only imported
    the bundles substrate may open a fresh DB before the migration
    fires. Belt-and-suspenders.
    """
    with contextlib.suppress(sqlite3.DatabaseError):
        conn.execute(
            "CREATE TABLE IF NOT EXISTS swf_kv ("
            "  key   TEXT PRIMARY KEY,"
            "  value TEXT NOT NULL"
            ")"
        )


def _get_high_water(conn: sqlite3.Connection, peer_pubkey: str) -> int:
    """Return the highest rowid we've consumed from `peer_pubkey`,
    or 0 if we've never pulled from this peer.

    Defensive: a missing `swf_kv` table or a malformed value yields
    `0` (start from the beginning) — never raises.
    """
    if not peer_pubkey:
        return 0
    _ensure_kv_table(conn)
    try:
        row = conn.execute(
            "SELECT value FROM swf_kv WHERE key=?",
            (_kv_key(peer_pubkey),),
        ).fetchone()
    except sqlite3.OperationalError:
        return 0
    if row is None:
        return 0
    try:
        v = row["value"]
    except (TypeError, IndexError):
        v = row[0]
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _set_high_water(
    conn: sqlite3.Connection,
    peer_pubkey: str,
    rowid: int,
) -> None:
    """Persist `rowid` as the new high-water for `peer_pubkey`.

    Strict-greater monotonic: an older value is never written back
    over a newer one. The caller's transaction owns the commit.
    """
    if not peer_pubkey:
        return
    _ensure_kv_table(conn)
    try:
        conn.execute(
            "INSERT INTO swf_kv(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value "
            "WHERE CAST(excluded.value AS INTEGER) "
            "     > CAST(swf_kv.value AS INTEGER)",
            (_kv_key(peer_pubkey), str(int(rowid))),
        )
    except sqlite3.OperationalError as exc:
        logger.error(
            "high_water set failed for %s: %s",
            peer_pubkey[:12], exc,
        )


# ── HTTP fetch ────────────────────────────────────────────────────────


def _http_get_json(
    url: str,
    *,
    timeout: float = _DEFAULT_HTTP_TIMEOUT_SECS,
) -> dict | None:
    """GET `url` and parse the body as JSON.

    Hardening (mirrors `peer_scraper._http_get_json`):
      * scheme MUST be http or https — file:// / ftp:// rejected
      * Content-Length > _MAX_RESPONSE_BYTES rejected before reading
      * body capped at _MAX_RESPONSE_BYTES
      * any error returns None; never raises (the puller logs at the
        call site so an operator can see which peer is misbehaving)
    """
    try:
        from urllib.parse import urlparse
        if urlparse(url).scheme not in ("http", "https"):
            return None
    except Exception:
        return None
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            try:
                declared = int(resp.headers.get("Content-Length") or "0")
            except ValueError:
                declared = 0
            if declared > _MAX_RESPONSE_BYTES:
                return None
            raw = resp.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                return None
            return json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            json.JSONDecodeError, UnicodeDecodeError):
        return None


# ── per-peer pull ─────────────────────────────────────────────────────


def pull_from_peer(
    db_path: Path,
    peer: Any,
    *,
    base_url: str,
    page_limit: int = _DEFAULT_PAGE_LIMIT,
    max_pages: int = _DEFAULT_MAX_PAGES,
    timeout_secs: float = _DEFAULT_HTTP_TIMEOUT_SECS,
) -> int:
    """Pull every bundle from `peer` that we haven't seen yet.

    Walks the peer's `/bundles?received_since=<hw>&limit=<page_limit>`
    cursor across up to `max_pages` pages, verifying + inserting each
    bundle and advancing the per-peer high-water as we go.

    Returns the count of new bundles stored. Zero on any of:
      * empty response
      * peer offline / 5xx / malformed JSON
      * bundles all already-known (cid collisions → was_new=False)

    Never raises. Per-bundle verify failures are logged + skipped
    (we don't want one bad envelope to abort the catch-up); HTTP
    failures abort just this peer's pull and return whatever was
    successfully ingested before the failure.

    Per-peer exponential backoff (mirrors `peer_scraper`). The shared
    `peers.consecutive_failures` + `peers.next_attempt_at` columns
    are bumped on any HTTP-channel failure (timeout, refused, 5xx,
    malformed JSON) and reset on the first successful fetch. The
    state is shared with `peer_scraper`: a peer that fails the
    search-side pull is also deferred bundle-side, by design (one
    unreachable peer is unreachable for both pullers). Per-bundle
    verifier rejections do NOT trip the channel-level backoff — a
    reachable peer shipping one malformed envelope is its own
    concern, handled by the per-envelope skip-and-log path below.

    `base_url` is passed in (rather than read off `peer`) because
    `swf.peer_scraper.IndrexPeer` doesn't store it — the discovery
    cache is consulted by the caller (`_tick`). This mirrors how
    `peer_scraper.pull_from_peer` consumes a pre-resolved URL.
    """
    # Lazy import to avoid the circular dependency (peer_scraper
    # imports the bundles substrate in its push path).
    from swf import peer_scraper as _peer_scraper

    if not peer.pubkey or not base_url:
        return 0
    base = base_url.rstrip("/")

    alchemists = _load_alchemists_cached()

    stored_total = 0
    # Approximate bytes of new bundles ingested this pull — surfaced
    # to the node event ring on success (docs/SYNC.md §13). Counted
    # at insert time via `len(json.dumps(env))` so a verifier
    # rejection or pre-existing cid (was_new=False) doesn't inflate
    # the figure. Cheap relative to the verify+insert pipeline.
    stored_bytes = 0
    # Channel-level reachability flags. Recorded once after the loop:
    # the first HTTP failure trips backoff; otherwise the first
    # successful fetch resets the counter. Per-bundle verify
    # rejections deliberately do NOT toggle these — see the
    # backoff note in the docstring.
    saw_http_success = False
    saw_http_failure = False

    # Open one writer connection for the whole pull. SQLite WAL means
    # readers don't block; we share the connection across pages so
    # `_get_high_water` and `insert` see the same state.
    try:
        conn = sqlite3.connect(str(db_path), timeout=5.0)
    except sqlite3.OperationalError as exc:
        logger.error(
            "open db for %s failed: %s", peer.pubkey[:12], exc,
        )
        return 0
    conn.row_factory = sqlite3.Row
    try:
        ensure_schema(conn)
        high_water = _get_high_water(conn, peer.pubkey)

        for _ in range(max_pages):
            url = (
                f"{base}/bundles?received_since={int(high_water)}"
                f"&limit={int(page_limit)}"
            )
            doc = _http_get_json(url, timeout=timeout_secs)
            if not isinstance(doc, dict):
                # `_http_get_json` returns None on timeout / connect
                # error / non-200 / malformed JSON. The channel itself
                # is unhealthy — flag for backoff and stop.
                saw_http_failure = True
                break
            saw_http_success = True

            envelopes = doc.get("bundles") or []
            if not isinstance(envelopes, list):
                break

            for env in envelopes:
                if not isinstance(env, dict):
                    continue
                try:
                    result = verify_bundle(
                        env,
                        alchemists=alchemists,
                        conn=conn,
                    )
                except Exception as exc:
                    logger.error(
                        "verify crashed for %s: %s",
                        peer.pubkey[:12], exc,
                    )
                    continue
                if not result.ok:
                    logger.info(
                        "%s verify=%s cid=%s (skipped)",
                        peer.pubkey[:12], result.reason,
                        result.cid[:12] or "-",
                    )
                    continue
                try:
                    _, was_new = insert(env, conn=conn)
                except Exception as exc:
                    logger.error(
                        "insert crashed for %s: %s",
                        peer.pubkey[:12], exc,
                    )
                    continue
                if was_new:
                    stored_total += 1
                    # Defensive: the envelope round-tripped through
                    # `verify_bundle`, so it's JSON-serializable in
                    # practice. If it isn't, drop the byte count
                    # rather than crashing the puller.
                    with contextlib.suppress(TypeError, ValueError):
                        stored_bytes += len(json.dumps(env).encode("utf-8"))

            # Advance high-water using the response's
            # `next_received_since`. Contract (server side, in
            # `peer_server._do_bundles_list`):
            #   * non-empty page → `next_received_since` is the
            #     highest rowid in this page. The next request uses
            #     it as `received_since` to skip past these bundles.
            #   * empty page (peer has nothing newer) →
            #     `next_received_since` is null. The puller stops
            #     looping on this peer this tick.
            next_cursor = doc.get("next_received_since")
            if next_cursor is None:
                # Empty page or peer signalled exhaustion. Stop
                # looping on this peer; the next tick will re-probe.
                break

            try:
                next_int = int(next_cursor)
            except (TypeError, ValueError):
                break
            if next_int <= high_water:
                # Defensive: a malicious / buggy peer that ships a
                # cursor that doesn't advance must not stall us in an
                # infinite loop.
                break
            _set_high_water(conn, peer.pubkey, next_int)
            high_water = next_int
            conn.commit()

            # If the page came back smaller than `page_limit`, the
            # peer has exhausted the stream — stop looping early
            # rather than burning a final HTTP just to receive the
            # empty page.
            if len(envelopes) < page_limit:
                break

        conn.commit()
    finally:
        conn.close()

    # Channel-level backoff bookkeeping. `saw_http_failure` wins over
    # `saw_http_success` to be conservative — a peer that succeeded on
    # page 1 but failed on page 2 had a real connectivity issue, and
    # we'd rather over-defer than hammer. In practice the puller breaks
    # on the first failure so they're mutually exclusive in any realistic
    # tick.
    if saw_http_failure:
        try:
            _peer_scraper._record_pull_failure(db_path, pubkey=peer.pubkey)
        except Exception as exc:
            logger.error(
                "record_pull_failure crashed for %s: %s",
                peer.pubkey[:12], exc,
            )
    elif saw_http_success:
        try:
            _peer_scraper._record_pull_success(db_path, pubkey=peer.pubkey)
        except Exception as exc:
            logger.error(
                "record_pull_success crashed for %s: %s",
                peer.pubkey[:12], exc,
            )

    # Surface successful bundle pulls on the unified node event ring
    # (docs/SYNC.md §13). Emit only when at least one new bundle was
    # ingested — `stored_total=0` is the steady state.
    if stored_total > 0:
        try:
            from swf.sync.event_log import emit_node_event
            emit_node_event(
                "bundle_pulled",
                category="ingest",
                peer_pubkey=peer.pubkey,
                peer_url=base,
                bundle_count=stored_total,
                bytes=stored_bytes,
            )
        except Exception:
            # Event emission must never break the puller's
            # accounting; the return value is the source of truth.
            pass

    return stored_total


# ── background loop ───────────────────────────────────────────────────


_thread: threading.Thread | None = None
_stop = threading.Event()
_thread_lock = threading.Lock()

# Last-tick stats. The metrics collector reads these via `puller_stats()`
# on every `/metrics/snapshot` tick so an operator can see at-a-glance
# whether the puller is making progress, stuck on offline peers, or
# raising per-peer exceptions. Set inside `_tick` after each pass; zero
# until the puller has run for the first time.
_last_tick_lock = threading.Lock()
_last_tick_visited = 0
_last_tick_pulled = 0
_last_tick_failed = 0


def puller_stats() -> tuple[int, int, int]:
    """Return `(visited, pulled, failed)` from the most recent `_tick`.

    Used by the metrics collector (`bundles.puller_*` gauges in
    `/metrics/snapshot`) to surface per-tick health without forcing the
    metrics module to reach into private state. All three counters
    start at zero; they're updated atomically at the end of each tick.
    """
    with _last_tick_lock:
        return _last_tick_visited, _last_tick_pulled, _last_tick_failed


def is_thread_alive() -> bool:
    """True iff the puller daemon thread is currently running.

    Used by the metrics collector (`bundles.puller_thread_alive` gauge)
    to surface daemon liveness. Returns False when the puller has not
    been started, has been stopped, or its thread crashed.
    """
    with _thread_lock:
        t = _thread
    return t is not None and t.is_alive()


def _tick(db_path: Path) -> None:
    """One pull round: walk every known peer and pull bundles since
    our per-peer high-water mark.

    Mirrors `peer_scraper._tick`'s convention: skip banned peers,
    resolve URL via the same discovery cache, never raise — log
    per-peer failures and keep going so one chronically-broken peer
    can't prevent the puller from catching up the rest of the LAN.
    """
    # Lazy import to keep this module's startup cheap and to avoid a
    # circular dependency (peer_scraper imports bundles in its push
    # path; bundles importing peer_scraper at top level would loop).
    from swf import peer_scraper

    global _last_tick_visited, _last_tick_pulled, _last_tick_failed

    visited = 0
    pulled_total = 0
    failed = 0
    skipped_backoff = 0
    try:
        peers = peer_scraper.list_peers(db_path)
    except Exception as exc:
        logger.error("list_peers failed: %s", exc)
        with _last_tick_lock:
            _last_tick_visited = 0
            _last_tick_pulled = 0
            _last_tick_failed = 0
        return

    for peer in peers:
        if (peer.trust_level or "known") == "banned":
            continue
        # Mirror `peer_scraper._tick`: skip peers in their exponential-
        # backoff window before paying the URL-resolution + HTTP cost.
        # The backoff state is shared with the search-side scraper, so a
        # peer that's unreachable for the page-puller is also deferred
        # here (and vice versa) — see `pull_from_peer`'s docstring for
        # why that's the right default.
        if peer_scraper._peer_in_backoff(peer):
            skipped_backoff += 1
            continue
        try:
            peer_url = peer_scraper._resolve_peer_url(peer)
        except Exception:
            peer_url = ""
        if not peer_url:
            continue
        visited += 1
        try:
            stored = pull_from_peer(db_path, peer, base_url=peer_url)
            pulled_total += stored
        except Exception as exc:
            failed += 1
            logger.error(
                "pull from %s failed: %s", peer.pubkey[:12], exc,
            )

    with _last_tick_lock:
        _last_tick_visited = visited
        _last_tick_pulled = pulled_total
        _last_tick_failed = failed

    # Heartbeat: emit the line whenever something happened — including
    # ticks where every visit-eligible peer was deferred by backoff.
    # Without the backoff branch, a tick where every known peer is in
    # quarantine would be silent and operators couldn't tell the loop
    # was alive vs. wedged.
    if visited or pulled_total or skipped_backoff:
        parts = [f"visited={visited}", f"pulled={pulled_total}"]
        if failed:
            parts.append(f"failed={failed}")
        if skipped_backoff:
            parts.append(f"backoff={skipped_backoff}")
        logger.info("tick %s", " ".join(parts))


def _loop(db_path: Path, interval_secs: float) -> None:
    """Background loop body. Runs `_tick` every `interval_secs` until
    `stop_puller()` sets the stop event."""
    while not _stop.is_set():
        try:
            _tick(db_path)
        except Exception as exc:
            logger.error("loop error: %s", exc)
        _stop.wait(timeout=interval_secs)


def start_puller(
    *,
    db_path: Path | None = None,
    interval_secs: float = DEFAULT_PULL_INTERVAL_SECS,
) -> None:
    """Start the background bundle-puller daemon thread.

    Idempotent — calling twice while a thread is alive is a no-op.
    Production wiring is in `peer_server._start_full_subsystems`,
    parallel to `peer_scraper.start()`. Tests call this directly with
    a small `interval_secs` to drive the offline-then-rejoin scenario
    deterministically.
    """
    global _thread
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return
        if db_path is None:
            from swf import indrex
            db_path = indrex.db_path()
        _stop.clear()
        _thread = threading.Thread(
            target=_loop,
            args=(db_path, float(interval_secs)),
            daemon=True,
            name="swf-bundle-puller",
        )
        _thread.start()


def stop_puller() -> None:
    """Signal the background loop to exit and wait briefly for the
    thread to die. For tests."""
    global _thread
    _stop.set()
    with _thread_lock:
        t = _thread
        _thread = None
    if t is not None and t.is_alive():
        t.join(timeout=2.0)


__all__ = [
    "DEFAULT_PULL_INTERVAL_SECS",
    "pull_from_peer",
    "start_puller",
    "stop_puller",
    "puller_stats",
    "is_thread_alive",
    "reset_alchemists_cache_for_tests",
    "reset_reservoir_cache_for_tests",
]
