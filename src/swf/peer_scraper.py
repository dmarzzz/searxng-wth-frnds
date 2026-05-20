"""Issue #43 PR A — peer indrex scraper.

The single-graph model: there is no separate community.db. Each node's
indrex grows from (a) its own searches and (b) a slow background pull
from peers' indexes. This module is (b).

================================================================
Cursor vocabulary (P2P-review #10).
================================================================

Multiple integers track "how far through the indrex have we gotten",
each in a slightly different role. Pin the names:

  producer_high_water_mark  — `MAX(rowid in pages)` on the producer.
                              Returned by `GET /index/cursor` so a
                              consumer can compute "how far am I behind".
                              Same DB also returns `epoch_id`.
  consumer_pull_cursor      — `peers.last_pull_cursor` on the consumer.
                              The largest producer-side rowid we have
                              ingested-or-considered from a given
                              peer. Advances on every successful pull,
                              including bundles that ship 0 shareable
                              rows in the considered window.
  bundle_since / bundle_until — the half-open window the *bundle*
                              describes. Producer's build_bundle uses
                              `bundle_since = consumer_pull_cursor` and
                              `bundle_until = max(rowid considered in
                              this window)`. Consumer's verify_bundle
                              checks `until >= since` and the cursor
                              jump is bounded.

In the SQLite schema the legacy column name `last_pull_cursor` stays
(renaming a persisted column would force a migration; the operator
contract is the same anyway). In Python we say
`consumer_pull_cursor` when we want to be clear about role.

What the scraper does, every ~60s in `--full` mode:

  1. Walk the local `peers` table.
  2. For each peer with `trust_level != 'banned'`, ask
     `GET /index/cursor` and `GET /index/pages?since=<consumer_pull_cursor>`.
  3. Verify the bundle: recompute the RFC-6962 merkle root over the
     canonical encoding of each page row; check the ed25519 signature
     covers `merkle_root || since || until || pubkey || page_count
     || epoch_id`.
  4. INSERT OR IGNORE each page into local indrex. Tag it with
     `source_pubkey` / `source_label` / `bundle_root` / `bundle_sig` so
     the wall can color by origin and a future audit can re-prove
     provenance without refetching.
  5. Advance `peers.last_pull_cursor` to the bundle's `until`.

Failure modes (all silently logged, never raise):
  - merkle mismatch  → skip the bundle, leave cursor unchanged
  - signature mismatch → skip the bundle
  - HTTP error / timeout → skip this peer this round (with backoff)
  - empty bundle → advance cursor past the empty range

This is the **client** side of the contract; `peer_server.py` serves
the matching `/index/pages` + `/index/cursor` endpoints.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from . import identity

logger = logging.getLogger(__name__)


def _emit_node(
    kind: str,
    *,
    category: str,
    payload: dict | None = None,
    **kwargs,
) -> None:
    """Fire an event onto the unified node event ring (docs/SYNC.md
    §13). Best-effort: ring failures must never crash the scraper's
    actual work.

    Forwards `payload=` + `**kwargs` to `emit_node_event` with the
    same semantics — use `payload=` when a field name collides with
    the function signature (e.g. `kind`).
    """
    try:
        from .sync.event_log import emit_node_event
        emit_node_event(kind, category=category, payload=payload, **kwargs)
    except Exception:
        pass


def _emit(kind: str, payload: dict) -> None:
    """Fire an event onto the indrex bus. Best-effort: a circular-import
    or a missing schema must never crash the scraper."""
    try:
        from . import event_bus
        event_bus.emit(kind, payload)
    except Exception:
        pass


BUNDLE_SCHEMA = "swf.index_pages.v1"
DEFAULT_LIMIT = 500
DEFAULT_TIMEOUT_SECS = 10
DEFAULT_INTERVAL_SECS = 60

# Red-team pass-5 finding #1: bound the per-bundle cursor advance so a
# malicious peer can't return `pages=[]` with `until=2**62` and
# permanently lock the puller past any future ingest. 100k allows a
# legit peer with millions of pages to catch up in a few hundred
# round-trips while denying the indefinite-jump attack.
MAX_BUNDLE_CURSOR_ADVANCE = 100_000

# Red-team pass-5 findings #3 + #6: cap `len(pages)` so a peer can't
# ship 5MB of duplicates and burn verifier CPU. The server-side
# build_bundle already caps at 5000; the verifier enforces the same
# bound.
MAX_BUNDLE_PAGES = 5_000

# Red-team pass-5 finding #4: bound user-controlled string fields that
# flow into the wall (signature_color, nickname, source_label).
MAX_NICKNAME_LEN = 64
MAX_SOURCE_LABEL_LEN = 64
_HEX_COLOR_RE = __import__("re").compile(r"^#[0-9A-Fa-f]{6}$")


# P2P-review #8: exponential backoff for chronically-failing peers.
# After every failed pull, `next_attempt_at` is set to
# now + min(BACKOFF_BASE_S * 2**min(failures, 6), BACKOFF_MAX_S).
# 60s, 120s, 240s, 480s, 960s, 1920s, 3600s (cap). On success, the
# columns reset and the peer is pulled on the next tick.
BACKOFF_BASE_S = 60
BACKOFF_MAX_S = 3600


# ── geth/reth-style peer-table management ─────────────────────────
#
# devp2p / discv5 maintain a Kademlia routing table with k-buckets,
# eviction policies, proof-of-liveness pings, and dial-quality
# scoring. We're at LAN-friend scale (target ~10 peers, hard cap 64),
# so we adopt the patterns that matter at that scale:
#
#   * `MAX_PEERS`              — hard cap on indrex.peers row count
#   * `PEER_STALE_DAYS`        — evict peers we haven't seen in N days
#   * `EVICT_AFTER_FAILURES`   — evict peers that never worked + are
#                                still failing (bad bootnode pattern)
#   * `LIVENESS_TIMEOUT_S`     — cheap /health probe before full pull
#                                (geth's PING/PONG: distinguish dead
#                                from "alive but nothing new")
#   * `PRUNE_EVERY_TICKS`      — periodic table cleanup, like geth's
#                                cleanupInterval
#
# Self-loop guard mirrors geth's nodeID check: never seed our own
# pubkey as a peer (would deadlock the scraper trying to pull from
# ourselves and double-count our own pages).

MAX_PEERS = 64
PEER_STALE_DAYS = 7
EVICT_AFTER_FAILURES = 20
LIVENESS_TIMEOUT_S = 2.0
PRUNE_EVERY_TICKS = 10


def _self_pubkey() -> str:
    """Cached lookup of our own pubkey. Used by the self-loop guard
    in `_seed_peers_from_discovery` and `_bootstrap_from_peers_yaml`."""
    try:
        from . import identity
        return identity.get_or_create_identity().pub_b64
    except Exception:
        return ""


def _backoff_seconds(failures: int) -> int:
    if failures <= 0:
        return 0
    return min(BACKOFF_BASE_S * (2 ** min(failures - 1, 6)),
               BACKOFF_MAX_S)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _trust_enabled() -> bool:
    """`SWF_ENABLE_PEER_TRUST=1` opts into tiered peer trust. Default
    OFF — every peer is treated uniformly (the trust_level column is
    stored but ignored). Operators who want a real
    known/trusted/banned distinction set the flag and use the
    `swf-peer trust` CLI to label individual peers.

    Why default-off: tiered trust adds operator burden (someone has
    to label peers; banned-by-default would block real peers
    silently) without proportional security value at LAN scale,
    where pubkey verification + signed bundles already authenticate
    every byte. The flag is the on-ramp for deployments that grow
    past trust-everything-on-LAN."""
    return (os.environ.get("SWF_ENABLE_PEER_TRUST") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


# ── canonical bundle encoding ──────────────────────────────────────

def _canonical_page_bytes(page: dict) -> bytes:
    """Canonical bytes for a single page row in a bundle. Deterministic
    JSON with sorted keys + no extra whitespace, so the merkle leaf is
    stable across machines. Only the spec'd fields are included; any
    extras are ignored (forward-compat: a future field doesn't break
    older verifiers)."""
    canon = {
        "url": page.get("url") or "",
        "title": page.get("title") or "",
        "host": page.get("host") or "",
        "topic": page.get("topic") or "",
        "fetched_at": page.get("fetched_at") or "",
        "content_cid": page.get("content_cid") or "",
    }
    return json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _leaf_hash(page_bytes: bytes) -> bytes:
    """RFC-6962 leaf hash: 0x00 || data."""
    return hashlib.sha256(b"\x00" + page_bytes).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """RFC-6962 internal node: 0x01 || left || right."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(pages: Iterable[dict]) -> str:
    """Compute the RFC-6962 merkle root over an ordered list of pages.
    Empty input → "" (the bundle's signature still covers the
    `since||until||pubkey` tail so empty bundles are still authentic)."""
    leaves = [_leaf_hash(_canonical_page_bytes(p)) for p in pages]
    if not leaves:
        return ""
    # Standard RFC-6962 binary tree. Odd levels promote the last node.
    level = leaves
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0].hex()


def signing_payload(*, merkle_root_hex: str, since: int, until: int,
                    pubkey_b64: str, page_count: int = 0,
                    epoch_id: str = "") -> bytes:
    """Bytes ed25519-signed by the producer over the bundle. Domain-
    separated so a bundle sig can't be replayed as some other
    protocol artifact.

    Fields bound into the signature:
      - schema tag (`swf.index_pages.v1`)
      - merkle root over canonical pages
      - (since, until) cursor window
      - producer pubkey (anti-impersonation)
      - page_count  (P2P-review #11: anti-equivocation about how
        many pages fit a window)
      - epoch_id    (P2P-review #2: ties the bundle to this DB
        generation; a rebuilt DB mints a new epoch, which makes the
        consumer reset its per-peer cursor)

    `page_count` and `epoch_id` default to 0/"" for back-compat with
    older test fixtures; production callers (build_bundle,
    verify_bundle) always pass the real values."""
    return (
        b"swf.index_pages.v1\n"
        + merkle_root_hex.encode("ascii") + b"\n"
        + str(int(since)).encode("ascii") + b"\n"
        + str(int(until)).encode("ascii") + b"\n"
        + pubkey_b64.encode("ascii") + b"\n"
        + str(int(page_count)).encode("ascii") + b"\n"
        + epoch_id.encode("ascii")
    )


# ── bundle build (server side) ─────────────────────────────────────

def build_bundle(
    *,
    db_path: Path,
    since: int,
    limit: int = DEFAULT_LIMIT,
    ident: identity.Identity | None = None,
) -> dict:
    """Read up to `limit` rows from the local indrex `pages` table whose
    `rowid > since`, compute the merkle root, sign with our identity,
    return the JSON-ready bundle. Caller serializes this into the HTTP
    response body."""
    if ident is None:
        ident = identity.get_or_create_identity()
    pages: list[dict] = []
    until = int(since)
    epoch_id = ""
    if db_path.exists():
        try:
            uri = f"file:{db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=0.5)
        except sqlite3.OperationalError:
            conn = None
        if conn is not None:
            conn.row_factory = sqlite3.Row
            try:
                # FTS5 virtual tables expose a `rowid` column that
                # auto-increments. We use it as the cursor — stable,
                # monotonic, cheap to index.
                #
                # Red-team pass-5 finding #7 (CRITICAL): join pages_meta
                # to enforce §13.1 privacy. The default share_scope is
                # 'private'; without this filter every locally-fetched
                # page leaked to any LAN caller of /index/pages with
                # zero auth. Now: serve only rows the user has
                # explicitly opted in to share ('friends' or 'public'),
                # never tombstoned (deleted_at_ms NOT NULL), and never
                # already-peer-ingested rows (chained-provenance
                # protection — same rule the friend-responder uses).
                lim = max(1, min(limit, 5000))
                rows = conn.execute(
                    "SELECT p.rowid, p.url, p.title, p.fetched_at "
                    "FROM pages p "
                    "LEFT JOIN pages_meta m ON m.url = p.url "
                    "WHERE p.rowid > ? "
                    "  AND m.deleted_at_ms IS NULL "
                    "  AND COALESCE(m.share_scope, 'private') "
                    "      IN ('friends','public') "
                    "  AND COALESCE(m.source_type, 'user_fetched') "
                    "      != 'peer_ingest' "
                    "ORDER BY p.rowid ASC LIMIT ?",
                    (int(since), lim),
                ).fetchall()
                # Advance the cursor to the largest rowid in the
                # (since, since+lim] window REGARDLESS of whether the
                # row was shareable. Without this, a block of private
                # rows would make the puller re-pull the same window
                # forever (the bundle's `until` would never move past
                # the first private row). We never disclose those
                # rows; the cursor just reflects "we've considered
                # everything up to here".
                window_max_row = conn.execute(
                    "SELECT MAX(rid) AS m FROM "
                    "(SELECT rowid AS rid FROM pages "
                    " WHERE rowid > ? ORDER BY rowid ASC LIMIT ?)",
                    (int(since), lim),
                ).fetchone()
                if window_max_row is not None and window_max_row["m"]:
                    until = max(until, int(window_max_row["m"]))
                # CIDs from the page_cids sidecar (best-effort).
                cid_map: dict[str, str] = {}
                try:
                    for cr in conn.execute(
                        "SELECT url, content_cid FROM page_cids"
                    ).fetchall():
                        if cr["url"] and cr["content_cid"]:
                            cid_map[cr["url"]] = cr["content_cid"]
                except sqlite3.OperationalError:
                    pass
                # Read this DB's stable node_epoch_id so we can sign
                # it into the bundle. P2P-review #2.
                try:
                    row = conn.execute(
                        "SELECT value FROM swf_kv "
                        "WHERE key='node_epoch_id'"
                    ).fetchone()
                    if row is not None:
                        try:
                            epoch_id = row["value"] or ""
                        except (TypeError, IndexError):
                            epoch_id = row[0] or ""
                except sqlite3.OperationalError:
                    pass
            except sqlite3.OperationalError:
                rows = []
                cid_map = {}
            finally:
                conn.close()
            for r in rows:
                u = r["url"] or ""
                if not u:
                    continue
                pages.append({
                    "url": u,
                    "title": r["title"] or "",
                    "host": _host_of(u),
                    "topic": "",   # PR B fills this in once topic-coloring lands
                    "fetched_at": r["fetched_at"] or "",
                    "content_cid": cid_map.get(u, ""),
                })
                until = max(until, int(r["rowid"]))
    # If we couldn't read the kv (DB missing / read-only error / row
    # not yet inserted), bootstrap one in a writable connection. The
    # producer MUST have a stable epoch — without it consumers can't
    # detect a DB rebuild.
    if not epoch_id and db_path.exists():
        try:
            wconn = sqlite3.connect(str(db_path), timeout=2.0)
            try:
                from .search import migration as _mig
                _mig.ensure_schema(wconn)
                epoch_id = _mig.get_node_epoch_id(wconn)
            finally:
                wconn.close()
        except Exception:
            epoch_id = ""
    root = merkle_root(pages)
    sig_bytes = ident.sign(signing_payload(
        merkle_root_hex=root, since=since, until=until,
        pubkey_b64=ident.pub_b64, page_count=len(pages),
        epoch_id=epoch_id,
    ))
    return {
        "schema": BUNDLE_SCHEMA,
        "pubkey": ident.pub_b64,
        "since": int(since),
        "until": until,
        "epoch_id": epoch_id,
        "pages": pages,
        "merkle_root": root,
        "sig": base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii"),
    }


def producer_high_water_mark(db_path: Path) -> int:
    """Largest rowid currently in `pages`. 0 when the DB or table is
    missing — callers never see an exception here.

    Cursor vocabulary (P2P-review #10): this is what
    `GET /index/cursor` returns to a consumer. Compare against the
    consumer's `peers.last_pull_cursor` to compute how far behind a
    given consumer is."""
    if not db_path.exists():
        return 0
    try:
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    except sqlite3.OperationalError:
        return 0
    try:
        try:
            row = conn.execute("SELECT MAX(rowid) FROM pages").fetchone()
            return int(row[0] or 0)
        except sqlite3.OperationalError:
            return 0
    finally:
        conn.close()


def producer_high_water_with_epoch(db_path: Path) -> tuple[int, str]:
    """Same as `producer_high_water_mark` plus the producer's
    `node_epoch_id`. Used by `GET /index/cursor` so consumers can
    detect a DB rebuild (P2P-review #2) without fetching a full
    bundle."""
    cursor = producer_high_water_mark(db_path)
    epoch = ""
    if not db_path.exists():
        return (cursor, epoch)
    try:
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    except sqlite3.OperationalError:
        return (cursor, epoch)
    try:
        try:
            row = conn.execute(
                "SELECT value FROM swf_kv WHERE key='node_epoch_id'",
            ).fetchone()
            if row is not None:
                epoch = row[0] or ""
        except sqlite3.OperationalError:
            pass
    finally:
        conn.close()
    if not epoch:
        # Bootstrap if missing.
        try:
            wconn = sqlite3.connect(str(db_path), timeout=2.0)
            try:
                from .search import migration as _mig
                _mig.ensure_schema(wconn)
                epoch = _mig.get_node_epoch_id(wconn)
            finally:
                wconn.close()
        except Exception:
            epoch = ""
    return (cursor, epoch)


# Back-compat aliases for callers that imported the old names before
# P2P-review #10. New code uses `producer_high_water_mark` /
# `producer_high_water_with_epoch`.
latest_cursor = producer_high_water_mark
latest_cursor_with_epoch = producer_high_water_with_epoch


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


# ── bundle verify (client side) ────────────────────────────────────

@dataclass(frozen=True)
class VerifyResult:
    """Why a bundle was accepted or rejected. The scraper logs the
    reason and (on rejection) leaves `last_pull_cursor` unchanged so a
    later round retries.

    P2P-review #9: also carry the diagnostic context an operator
    needs to understand WHICH bundle failed — `since`/`until` define
    the window, `page_count` says how many pages were in flight,
    and the truncated merkle roots let an offline diff find the
    tampered leaf."""
    ok: bool
    reason: str = ""
    since: int = 0
    until: int = 0
    page_count: int = 0
    declared_root: str = ""
    computed_root: str = ""


def verify_bundle(bundle: dict, *, expected_pubkey: str) -> VerifyResult:
    """Re-derive the merkle root and verify the ed25519 signature.
    Returns VerifyResult(ok, reason, ...). `expected_pubkey` is what
    the scraper *thinks* the peer is; if the bundle's `pubkey` field
    disagrees, it's a `pubkey_mismatch` rejection (a peer can't
    impersonate another from the puller's POV).

    P2P-review #9: every rejection carries diagnostic context
    (since/until/page_count/declared_root[:12]/computed_root[:12])
    so an operator looking at `peer_pull_failed` events can tell
    WHICH window failed without crawling logs."""

    def _ctx(reason: str, *, declared_root: str = "",
             computed_root: str = "") -> VerifyResult:
        # Pull whatever fields are safely accessible.
        try:
            s = int(bundle.get("since")) if isinstance(bundle, dict) else 0
        except (TypeError, ValueError):
            s = 0
        try:
            u = int(bundle.get("until")) if isinstance(bundle, dict) else 0
        except (TypeError, ValueError):
            u = 0
        pc = 0
        if isinstance(bundle, dict):
            pl = bundle.get("pages")
            if isinstance(pl, list):
                pc = len(pl)
        return VerifyResult(
            ok=False, reason=reason, since=s, until=u,
            page_count=pc,
            declared_root=declared_root[:12] if declared_root else "",
            computed_root=computed_root[:12] if computed_root else "",
        )

    if not isinstance(bundle, dict):
        return _ctx("not_a_dict")
    if bundle.get("schema") != BUNDLE_SCHEMA:
        return _ctx("wrong_schema")
    pubkey = (bundle.get("pubkey") or "").strip()
    if not pubkey:
        return _ctx("missing_pubkey")
    if pubkey != expected_pubkey:
        return _ctx("pubkey_mismatch")
    pages = bundle.get("pages") or []
    if not isinstance(pages, list):
        return _ctx("pages_not_a_list")
    if len(pages) > MAX_BUNDLE_PAGES:
        return _ctx("too_many_pages")
    seen_urls: set[str] = set()
    for p in pages:
        if not isinstance(p, dict):
            return _ctx("page_not_a_dict")
        u = p.get("url") or ""
        if u in seen_urls:
            return _ctx("duplicate_url")
        seen_urls.add(u)
    try:
        since = int(bundle.get("since"))
        until = int(bundle.get("until"))
    except (TypeError, ValueError):
        return _ctx("bad_cursor")
    if until < since:
        return _ctx("cursor_inverted")
    if until - since > MAX_BUNDLE_CURSOR_ADVANCE:
        return _ctx("cursor_jump_too_large")
    declared_root = (bundle.get("merkle_root") or "").strip()
    computed_root = merkle_root(pages)
    if declared_root != computed_root:
        return _ctx("merkle_mismatch",
                    declared_root=declared_root,
                    computed_root=computed_root)
    sig_b64 = bundle.get("sig") or ""
    if not sig_b64:
        return _ctx("missing_sig", declared_root=declared_root,
                    computed_root=computed_root)
    epoch_id = bundle.get("epoch_id") or ""
    if not isinstance(epoch_id, str):
        return _ctx("bad_epoch_id")
    if len(epoch_id) > 64:
        return _ctx("bad_epoch_id")
    payload = signing_payload(
        merkle_root_hex=computed_root, since=since, until=until,
        pubkey_b64=pubkey, page_count=len(pages),
        epoch_id=epoch_id,
    )
    if not identity.verify(pubkey, payload, sig_b64):
        return _ctx("sig_mismatch", declared_root=declared_root,
                    computed_root=computed_root)
    return VerifyResult(
        ok=True, reason="ok", since=since, until=until,
        page_count=len(pages),
        declared_root=declared_root[:12],
        computed_root=computed_root[:12],
    )


# ── peers table accessors ──────────────────────────────────────────

@dataclass
class IndrexPeer:
    """Per-peer state stored in indrex.peers — the puller's view of
    a remote producer.

    P2P-review #5: distinct from `swf.peers.Peer` (peers.yaml-backed,
    `name`+`url`+`pubkey`-only) which is the *config* model. The
    scraper's runtime state lives here because it grows and changes
    (cursor advance, epoch rotation, trust level edits) — config
    files don't fit. A first-tick bootstrap migrates yaml entries
    into this table; over time `swf.peers.Peer` becomes vestigial."""
    pubkey: str
    nickname: str
    last_seen_at: str | None
    last_pull_cursor: int
    trust_level: str
    base_url: str = ""   # populated by the scraper from mDNS / config
    # P2P-review #2: epoch from the last verified bundle. When we
    # receive a bundle whose `epoch_id` differs, we know the producer
    # rebuilt their indrex (or rotated identity-and-DB) and we reset
    # `last_pull_cursor` to 0 to re-ingest from scratch.
    last_seen_epoch: str = ""
    # P2P-review #8: exponential-backoff scheduling.
    consecutive_failures: int = 0
    next_attempt_at: str = ""
    # geth/reth-style positive score: clean-pull counter.
    successful_pulls: int = 0


# Back-compat alias for callers that imported `peer_scraper.Peer`
# before P2P-review #5. New code should use `IndrexPeer`.
Peer = IndrexPeer


def list_peers(db_path: Path) -> list[Peer]:
    """Return every peer the local indrex knows about. Banned peers are
    included but the scraper filters them out."""
    if not db_path.exists():
        return []
    try:
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    except sqlite3.OperationalError:
        return []
    conn.row_factory = sqlite3.Row
    try:
        try:
            rows = conn.execute(
                "SELECT pubkey, nickname, last_seen_at, "
                "       last_pull_cursor, trust_level, "
                "       COALESCE(last_seen_epoch, '') AS last_seen_epoch, "
                "       COALESCE(consecutive_failures, 0) "
                "         AS consecutive_failures, "
                "       COALESCE(next_attempt_at, '') AS next_attempt_at, "
                "       COALESCE(successful_pulls, 0) AS successful_pulls "
                "FROM peers"
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        return [
            IndrexPeer(
                pubkey=r["pubkey"],
                nickname=r["nickname"] or "",
                last_seen_at=r["last_seen_at"],
                last_pull_cursor=int(r["last_pull_cursor"] or 0),
                trust_level=r["trust_level"] or "known",
                last_seen_epoch=r["last_seen_epoch"] or "",
                consecutive_failures=int(r["consecutive_failures"] or 0),
                next_attempt_at=r["next_attempt_at"] or "",
                successful_pulls=int(r["successful_pulls"] or 0),
            )
            for r in rows
        ]
    finally:
        conn.close()


def upsert_peer(
    db_path: Path,
    *,
    pubkey: str,
    nickname: str = "",
    signature_color: str = "",
    signature_freq: float = 0.0,
    trust_level: str = "known",
    last_seen_at: str | None = None,
) -> None:
    """Add or update a peer row. Idempotent on `pubkey`. Defaults are
    chosen so a `swf-peer add <pk>` flow can call this with just a key
    and have the scraper start pulling at the next tick.

    Pass-5 finding #4: validate the user-controlled fields that flow
    into the wall. `signature_color` must look like `#RRGGBB`;
    `nickname` is capped at MAX_NICKNAME_LEN. Anything else gets
    silently coerced to a safe default — we don't want a malformed
    peers.yaml row to crash the import.

    `last_seen_at`: when provided, the column is stamped (both on
    insert and on update). The default `None` preserves the legacy
    behavior — the column stays NULL on insert and is left untouched
    on update. Bug #100: bootstrap/discovery callers that have just
    learned about a peer pass `last_seen_at=_now_iso()` so the very
    first `prune_stale_peers` tick (which evicts NULL `last_seen_at`)
    doesn't immediately delete what we just inserted."""
    if trust_level not in ("known", "trusted", "banned"):
        raise ValueError(f"bad trust_level: {trust_level!r}")
    if signature_color and not _HEX_COLOR_RE.match(signature_color):
        signature_color = ""
    nickname = (nickname or "")[:MAX_NICKNAME_LEN]
    conn = sqlite3.connect(str(db_path), timeout=2.0)
    try:
        with contextlib.suppress(sqlite3.DatabaseError):
            conn.execute("PRAGMA journal_mode=WAL")
        # Ensure the schema exists in case the caller forgot.
        from .search import migration
        migration.ensure_schema(conn)
        if last_seen_at is None:
            conn.execute(
                "INSERT INTO peers(pubkey, nickname, signature_color, "
                "                  signature_freq, trust_level) "
                "VALUES(?, ?, ?, ?, ?) "
                "ON CONFLICT(pubkey) DO UPDATE SET "
                "  nickname = excluded.nickname, "
                "  signature_color = excluded.signature_color, "
                "  signature_freq = excluded.signature_freq, "
                "  trust_level = excluded.trust_level",
                (pubkey, nickname, signature_color, signature_freq,
                 trust_level),
            )
        else:
            conn.execute(
                "INSERT INTO peers(pubkey, nickname, signature_color, "
                "                  signature_freq, trust_level, "
                "                  last_seen_at) "
                "VALUES(?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(pubkey) DO UPDATE SET "
                "  nickname = excluded.nickname, "
                "  signature_color = excluded.signature_color, "
                "  signature_freq = excluded.signature_freq, "
                "  trust_level = excluded.trust_level, "
                "  last_seen_at = excluded.last_seen_at",
                (pubkey, nickname, signature_color, signature_freq,
                 trust_level, last_seen_at),
            )
        conn.commit()
    finally:
        conn.close()


def reset_all_backoff(db_path: Path) -> int:
    """Reset every peer's `consecutive_failures` and `next_attempt_at`
    so the next scraper tick re-probes immediately. Returns the
    number of rows affected.

    Called by the network-change hook (joining a new Wi-Fi network
    invalidates every previous failure — those were against the
    OLD network's reachability, not this peer's actual liveness)."""
    if not db_path.exists():
        return 0
    try:
        conn = sqlite3.connect(str(db_path), timeout=2.0)
    except sqlite3.OperationalError:
        return 0
    try:
        try:
            cur = conn.execute(
                "UPDATE peers SET consecutive_failures=0, "
                "                 next_attempt_at='' "
                "WHERE consecutive_failures > 0 OR next_attempt_at != ''"
            )
            conn.commit()
            return int(cur.rowcount or 0)
        except sqlite3.OperationalError:
            return 0
    finally:
        conn.close()


def _record_pull_failure(db_path: Path, *, pubkey: str) -> int:
    """Bump `consecutive_failures` and set `next_attempt_at` to the
    backoff window. Returns the new failure count. Best-effort: if
    the DB isn't openable (tests with Path('/dev/null'), missing
    DB on first contact, etc), return 0 without raising — the
    scraper must keep running."""
    try:
        conn = sqlite3.connect(str(db_path), timeout=2.0)
    except sqlite3.OperationalError:
        return 0
    try:
        try:
            row = conn.execute(
                "SELECT COALESCE(consecutive_failures, 0) FROM peers "
                "WHERE pubkey=?", (pubkey,),
            ).fetchone()
        except sqlite3.OperationalError:
            return 0
        if row is None:
            return 0
        new_count = int(row[0] or 0) + 1
        backoff = _backoff_seconds(new_count)
        next_at = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + backoff),
        )
        try:
            conn.execute(
                "UPDATE peers SET consecutive_failures=?, next_attempt_at=? "
                "WHERE pubkey=?",
                (new_count, next_at, pubkey),
            )
            conn.commit()
        except sqlite3.OperationalError:
            return 0
        return new_count
    finally:
        conn.close()


def _record_pull_success(db_path: Path, *, pubkey: str) -> None:
    """Reset failure counters and bump `successful_pulls` (positive
    score) after a successful pull. Best-effort."""
    try:
        conn = sqlite3.connect(str(db_path), timeout=2.0)
    except sqlite3.OperationalError:
        return
    try:
        try:
            conn.execute(
                "UPDATE peers SET consecutive_failures=0, "
                "                 next_attempt_at='', "
                "                 successful_pulls=successful_pulls+1 "
                "WHERE pubkey=?", (pubkey,),
            )
            conn.commit()
        except sqlite3.OperationalError:
            return
    finally:
        conn.close()


# ── geth-style table cleanup: prune stale + repeatedly-broken ────

def prune_stale_peers(
    db_path: Path,
    *,
    stale_days: int = PEER_STALE_DAYS,
    evict_after_failures: int = EVICT_AFTER_FAILURES,
) -> dict:
    """Evict peers under either rule:

      A. Time-based:  `last_seen_at` is NULL or older than
         `stale_days`. The peer hasn't given us a successful pull in
         too long; it's safe to forget. (geth's tableCleanup)

      B. Quality-based: `successful_pulls == 0` AND
         `consecutive_failures >= evict_after_failures`. The peer
         has NEVER worked and is still failing — almost certainly a
         stale entry from a peer that rotated identity, changed
         networks, or was added in error. (geth's invalid-bootnode
         eviction.)

    Returns `{"stale": N, "broken": M, "kept": K}`.

    The two rules are independent: a peer that's both stale AND
    broken counts in `stale` (the more conservative bucket — it
    might've worked once a year ago)."""
    if not db_path.exists():
        return {"stale": 0, "broken": 0, "kept": 0}
    try:
        conn = sqlite3.connect(str(db_path), timeout=2.0)
    except sqlite3.OperationalError:
        return {"stale": 0, "broken": 0, "kept": 0}
    try:
        from datetime import datetime, timedelta, timezone
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=int(stale_days))
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            stale_cur = conn.execute(
                "DELETE FROM peers "
                "WHERE last_seen_at IS NULL OR last_seen_at < ?",
                (cutoff,),
            )
            conn.commit()
            stale_n = int(stale_cur.rowcount or 0)
        except sqlite3.OperationalError:
            stale_n = 0
        try:
            broken_cur = conn.execute(
                "DELETE FROM peers "
                "WHERE COALESCE(successful_pulls, 0) = 0 "
                "  AND COALESCE(consecutive_failures, 0) >= ?",
                (int(evict_after_failures),),
            )
            conn.commit()
            broken_n = int(broken_cur.rowcount or 0)
        except sqlite3.OperationalError:
            broken_n = 0
        try:
            kept = int(conn.execute(
                "SELECT COUNT(*) FROM peers"
            ).fetchone()[0])
        except sqlite3.OperationalError:
            kept = 0
        return {"stale": stale_n, "broken": broken_n, "kept": kept}
    finally:
        conn.close()


# ── geth-style PING/PONG: cheap liveness probe ───────────────────

def liveness_check(
    base_url: str, *, timeout_s: float = LIVENESS_TIMEOUT_S,
) -> bool:
    """Cheap GET /health probe. True iff the peer responds 200 with
    a JSON body that contains `ok: true`. Used by `pull_from_peer`
    to fail-fast on dead peers without paying the bundle round-trip.

    Decouples liveness from "had something to ship" — a quiet but
    healthy peer should stay in the pull rotation."""
    if not base_url:
        return False
    base = base_url.rstrip("/")
    try:
        from urllib.parse import urlparse
        if urlparse(base).scheme not in ("http", "https"):
            return False
    except Exception:
        return False
    try:
        with _no_redirect_opener.open(
            urllib.request.Request(
                f"{base}/health",
                headers={"Accept": "application/json"},
            ),
            timeout=timeout_s,
        ) as resp:
            if resp.status != 200:
                return False
            raw = resp.read(4096)  # /health is tiny
            doc = json.loads(raw.decode("utf-8"))
            return bool(doc.get("ok"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            json.JSONDecodeError, UnicodeDecodeError):
        return False


def _peer_in_backoff(peer: IndrexPeer) -> bool:
    """True iff `now < peer.next_attempt_at`. Empty/malformed values
    treated as 'not in backoff' (safe default — pull anyway)."""
    if not peer.next_attempt_at:
        return False
    try:
        from datetime import datetime, timezone
        ts = peer.next_attempt_at
        if ts.endswith("Z"):
            ts = ts[:-1]
        scheduled = datetime.strptime(
            ts, "%Y-%m-%dT%H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < scheduled
    except Exception:
        return False


def update_pull_cursor(db_path: Path, *, pubkey: str, cursor: int,
                       last_seen_at: str | None = None,
                       last_seen_epoch: str | None = None) -> None:
    """Advance a peer's `last_pull_cursor` after a successful bundle.
    `last_seen_at` updates every successful pull so dead peers can be
    evicted later. `last_seen_epoch` records the producer's epoch so
    a future change triggers a cursor reset (P2P-review #2)."""
    conn = sqlite3.connect(str(db_path), timeout=2.0)
    try:
        if last_seen_at is None:
            last_seen_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if last_seen_epoch is None:
            conn.execute(
                "UPDATE peers SET last_pull_cursor=?, last_seen_at=? "
                "WHERE pubkey=?",
                (int(cursor), last_seen_at, pubkey),
            )
        else:
            conn.execute(
                "UPDATE peers SET last_pull_cursor=?, last_seen_at=?, "
                "                 last_seen_epoch=? "
                "WHERE pubkey=?",
                (int(cursor), last_seen_at, last_seen_epoch, pubkey),
            )
        conn.commit()
    finally:
        conn.close()


# ── ingest verified pages into local indrex ────────────────────────

def ingest_bundle(
    db_path: Path,
    bundle: dict,
    *,
    source_label: str = "",
) -> int:
    """Write each page in a verified bundle to the local indrex. Returns
    the count of newly-stored rows. Existing URLs are skipped (first
    write wins via INSERT OR IGNORE pattern — we check for `url`
    existence in `pages` since FTS5 doesn't enforce UNIQUE).

    The bundle MUST have been verified by `verify_bundle` first; this
    function does not re-verify (separation of concerns)."""
    pages = bundle.get("pages") or []
    if not pages:
        return 0
    pubkey = bundle.get("pubkey") or ""
    bundle_root = bundle.get("merkle_root") or ""
    bundle_sig = bundle.get("sig") or ""
    scraped_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # Pass-5 #4: bound the peer-supplied label that flows into
    # pages_meta.source_label and back out to the wall.
    source_label = (source_label or "")[:MAX_SOURCE_LABEL_LEN]

    # Collect (url, title) of newly-stored rows so we can fire
    # page_added events AFTER closing the write connection — emitting
    # mid-transaction would deadlock against event_bus's own writer.
    newly_stored: list[tuple[str, str]] = []

    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.DatabaseError:
            pass
        # Make sure the destination schema is there. ensure_schema
        # owns the sidecar tables; the FTS5 `pages` table itself is
        # owned by swf.web.index. On a fresh node where
        # the agent hasn't run yet (or a peer-only deployment),
        # pages won't exist — bootstrap it here so the scraper can
        # ingest. Idempotent: IF NOT EXISTS.
        conn.executescript(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS pages USING fts5(
                url UNINDEXED, title, content, fetched_at UNINDEXED,
                tokenize='porter unicode61'
            );
            CREATE TABLE IF NOT EXISTS page_cids(
                url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
                computed_at TEXT NOT NULL
            );
            """
        )
        from .search import migration
        migration.ensure_schema(conn)

        # #84: junk-title filter. Imported once per ingest_bundle, not
        # once per page, since the function is small but the call
        # surface is hot.
        from swf.search.junk_titles import is_junk_title
        for p in pages:
            url = p.get("url") or ""
            if not url:
                continue
            # #84: drop junk-title pages at ingest. A peer running old
            # code could still ship `404 Not Found` / `Publications`
            # titles in its bundle; we silently skip them on the
            # consumer side so our own corpus doesn't inherit the
            # noise. Producer-side filter (swf.web.index_page) handles
            # outbound; this is the symmetric inbound path.
            if is_junk_title(p.get("title") or ""):
                continue
            # P2P-review #3: respect local tombstones. If the user
            # tombstoned this URL (pages_meta.deleted_at_ms set), a
            # peer's bundle MUST NOT resurrect it — the FTS row may
            # or may not still exist, but the user's intent stands.
            try:
                tomb = conn.execute(
                    "SELECT deleted_at_ms FROM pages_meta "
                    "WHERE url=? AND deleted_at_ms IS NOT NULL "
                    "LIMIT 1", (url,),
                ).fetchone()
            except sqlite3.OperationalError:
                tomb = None
            if tomb is not None:
                continue
            # Issue #65: every URL in a verified bundle is a peer
            # contribution, regardless of whether the local node
            # already has the FTS row. Record it before the dedup
            # check so attribution is preserved even when the page
            # already exists. `pages_meta.source_pubkey` keeps its
            # primary-attribution semantics; the join table stores
            # the long tail.
            if pubkey:
                # Legacy DB without page_contributors — ensure_schema
                # adds it on the next migrate, no need to fail here.
                with contextlib.suppress(sqlite3.OperationalError):
                    migration.add_contributor(
                        conn, url,
                        source_pubkey=pubkey,
                        source_label=source_label,
                        scraped_at=scraped_at,
                        bundle_root=bundle_root,
                        bundle_sig=bundle_sig,
                    )
            # First-write-wins dedup. FTS5 has no UNIQUE — we check.
            try:
                row = conn.execute(
                    "SELECT 1 FROM pages WHERE url=? LIMIT 1", (url,),
                ).fetchone()
            except sqlite3.OperationalError:
                row = None
            if row is not None:
                continue
            # P2P-review #12: write the sidecar FIRST. If meta fails
            # (e.g. CHECK constraint violation, malformed input), we
            # never insert the FTS row — without that ordering, a meta
            # failure leaves an orphan FTS row that indrex_graph
            # mis-attributes to `is_self=True` because `source_pubkey`
            # is NULL. The combined effect: a malformed peer ingest
            # could silently transfer "ownership" of a URL to the
            # local user.
            try:
                migration.set_meta(
                    conn, url,
                    source_type="peer_ingest",
                    content_hash=None,
                    source_pubkey=pubkey,
                    source_label=source_label,
                    scraped_at=scraped_at,
                    bundle_root=bundle_root,
                    bundle_sig=bundle_sig,
                )
            except Exception:
                # Don't write the FTS row if attribution is missing.
                # Better to skip the page than to mis-attribute it.
                continue
            try:
                conn.execute(
                    "INSERT INTO pages(url, title, content, fetched_at) "
                    "VALUES(?, ?, ?, ?)",
                    (url, p.get("title") or "", "",
                     p.get("fetched_at") or ""),
                )
            except sqlite3.OperationalError:
                continue
            # CID sidecar, if the producer included one.
            cid = p.get("content_cid") or ""
            if cid:
                with contextlib.suppress(sqlite3.OperationalError):
                    conn.execute(
                        "INSERT OR IGNORE INTO page_cids(url, content_cid, computed_at) "
                        "VALUES(?, ?, ?)",
                        (url, cid, scraped_at),
                    )
            newly_stored.append((url, p.get("title") or ""))
        conn.commit()
    finally:
        conn.close()

    # Fire one page_added per ingested row, now that the write
    # connection is closed. Self-fetched pages don't go through this
    # path; the agent's index_page writes directly to FTS5.
    for url, title in newly_stored:
        _emit("page_added", {
            "url": url, "title": title,
            "host": _host_of(url),
            "source_pubkey": pubkey,
            "source_label": source_label,
        })
    return len(newly_stored)


# ── HTTP fetch (client-side) ───────────────────────────────────────

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Pass-5 finding #2: refuse to follow redirects. A peer that
    302-redirects us to 169.254.169.254 (cloud metadata),
    127.0.0.1:5984 (CouchDB), or any internal-only host would otherwise
    trigger SSRF — `urlopen` follows redirects by default. We require
    the peer's `base_url` to point at the response directly."""

    def http_error_301(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirects refused", headers, fp,
        )

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


_no_redirect_opener = urllib.request.build_opener(_NoRedirectHandler())


_BUNDLE_BODY_CAP = 32 * 1024 * 1024


def _http_get_json(url: str, *, timeout: float = DEFAULT_TIMEOUT_SECS) -> dict | None:
    """Fetch a JSON bundle from a peer. Hard guarantees:
      * scheme MUST be http or https — file:// / ftp:// rejected
      * redirects refused (SSRF guard, pass-5 #2)
      * Content-Length > 32 MiB rejected before reading
      * body capped at 32 MiB; oversize bodies are rejected, not
        silently truncated (pass-5 #3)
    Returns None on any error; never raises."""
    try:
        from urllib.parse import urlparse
        if urlparse(url).scheme not in ("http", "https"):
            return None
    except Exception:
        return None
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with _no_redirect_opener.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            try:
                declared = int(resp.headers.get("Content-Length") or "0")
            except ValueError:
                declared = 0
            if declared > _BUNDLE_BODY_CAP:
                return None
            # Read at most cap+1 bytes so we can detect overage rather
            # than silently truncate.
            raw = resp.read(_BUNDLE_BODY_CAP + 1)
            if len(raw) > _BUNDLE_BODY_CAP:
                return None
            return json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            json.JSONDecodeError, UnicodeDecodeError):
        return None


def pull_from_peer(
    db_path: Path,
    peer: Peer,
    *,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
    limit: int = DEFAULT_LIMIT,
) -> tuple[int, str]:
    """Pull a single bundle from `peer.base_url`, verify it, ingest it,
    advance the cursor. Returns `(stored_count, status)` where status
    is one of:
      "ok"               — bundle accepted (possibly empty)
      "no_url"           — peer has no base_url
      "banned"           — trust_level=banned
      "http_error"       — peer didn't respond / wrong status
      "verify:<reason>"  — bundle failed verification
    Never raises."""
    # Trust gating is opt-in via SWF_ENABLE_PEER_TRUST. Default off
    # means every peer pulls regardless of trust_level — uniform
    # peerhood, no operator burden. With the flag set, banned peers
    # are skipped at the pull boundary AND list_peers/_tick filters
    # them upstream so they never even hit this point.
    if _trust_enabled() and peer.trust_level == "banned":
        return (0, "banned")
    if not peer.base_url:
        return (0, "no_url")
    base = peer.base_url.rstrip("/")
    # geth-style PING/PONG: cheap liveness probe before paying the
    # full bundle round-trip. A dead peer fails the probe in
    # LIVENESS_TIMEOUT_S (2s default) instead of waiting for the
    # default 10s timeout on /index/pages.
    if not liveness_check(base):
        _record_pull_failure(db_path, pubkey=peer.pubkey)
        _emit("peer_pull_failed", {
            "pubkey": peer.pubkey, "reason": "liveness_check_failed",
            "since": peer.last_pull_cursor,
            "until": peer.last_pull_cursor,
            "page_count": 0,
            "declared_root": "", "computed_root": "",
        })
        _emit_node(
            "scraper_error", category="error",
            peer_pubkey=peer.pubkey, peer_url=base,
            error="liveness_check_failed",
        )
        return (0, "liveness_check_failed")
    # P2P-review #2: detect epoch change via /index/cursor BEFORE
    # asking for the bundle. If the producer's epoch has rotated
    # (DB rebuild / identity-and-DB rotation), reset our cursor so
    # the next /index/pages call returns from the start. Best-effort:
    # if the cursor probe fails, fall through to /index/pages and
    # rely on verify_bundle's epoch_id check to catch the rotation.
    cursor_doc = _http_get_json(
        f"{base}/index/cursor", timeout=timeout_secs,
    )
    effective_since = peer.last_pull_cursor
    if isinstance(cursor_doc, dict):
        producer_epoch = cursor_doc.get("epoch_id") or ""
        if (peer.last_seen_epoch and producer_epoch
                and producer_epoch != peer.last_seen_epoch):
            effective_since = 0
            _emit("peer_epoch_rotated", {
                "pubkey": peer.pubkey,
                "old_epoch": peer.last_seen_epoch[:12],
                "new_epoch": producer_epoch[:12],
            })
    _emit("peer_pull_started", {
        "pubkey": peer.pubkey, "nickname": peer.nickname,
        "since": effective_since,
    })
    bundle = _http_get_json(
        f"{base}/index/pages?since={effective_since}&limit={int(limit)}",
        timeout=timeout_secs,
    )
    if bundle is None:
        _record_pull_failure(db_path, pubkey=peer.pubkey)
        _emit("peer_pull_failed", {
            "pubkey": peer.pubkey, "reason": "http_error",
            "since": effective_since, "until": effective_since,
            "page_count": 0,
            "declared_root": "", "computed_root": "",
        })
        _emit_node(
            "scraper_error", category="error",
            peer_pubkey=peer.pubkey, peer_url=base,
            error="http_error",
        )
        return (0, "http_error")
    v = verify_bundle(bundle, expected_pubkey=peer.pubkey)
    if not v.ok:
        _record_pull_failure(db_path, pubkey=peer.pubkey)
        # P2P-review #9: ship full diagnostic context so an operator
        # can pin down which window broke without crawling logs.
        _emit("peer_pull_failed", {
            "pubkey": peer.pubkey, "reason": v.reason,
            "since": v.since, "until": v.until,
            "page_count": v.page_count,
            "declared_root": v.declared_root,
            "computed_root": v.computed_root,
        })
        logger.info(
            "%s verify=%s since=%s until=%s pages=%s "
            "declared=%s computed=%s",
            peer.pubkey[:12], v.reason, v.since, v.until,
            v.page_count,
            v.declared_root or "-",
            v.computed_root or "-",
        )
        _emit_node(
            "scraper_error", category="error",
            peer_pubkey=peer.pubkey, peer_url=base,
            error=f"verify:{v.reason}",
        )
        return (0, f"verify:{v.reason}")
    bundle_epoch = bundle.get("epoch_id") or ""
    # Defense-in-depth: if the bundle's epoch differs from our last
    # seen AND we didn't catch it in the /index/cursor probe (e.g.
    # the probe failed), reset the cursor and retry on next tick.
    # Don't ingest stale-cursor bundles whose contents we may
    # already partially have under a different epoch.
    if (peer.last_seen_epoch and bundle_epoch
            and bundle_epoch != peer.last_seen_epoch
            and effective_since != 0):
        update_pull_cursor(
            db_path, pubkey=peer.pubkey, cursor=0,
            last_seen_epoch=bundle_epoch,
        )
        _emit("peer_epoch_rotated", {
            "pubkey": peer.pubkey,
            "old_epoch": peer.last_seen_epoch[:12],
            "new_epoch": bundle_epoch[:12],
        })
        return (0, "epoch_rotated_resetting")
    stored = ingest_bundle(db_path, bundle, source_label=peer.nickname)
    until = int(bundle.get("until") or effective_since)
    update_pull_cursor(
        db_path, pubkey=peer.pubkey, cursor=until,
        last_seen_epoch=bundle_epoch or peer.last_seen_epoch,
    )
    _record_pull_success(db_path, pubkey=peer.pubkey)
    _emit("peer_pull_completed", {
        "pubkey": peer.pubkey, "nickname": peer.nickname,
        "stored": stored, "until": until,
    })
    # Surface successful scraper pulls on the unified node event ring
    # (docs/SYNC.md §13). Only emit when we actually ingested fresh
    # rows — a `stored=0` tick is the steady state (peer is caught
    # up) and would spam the feed.
    #
    # The `kind` field collides with `emit_node_event`'s positional
    # parameter, so we route the payload through `payload=` — see
    # event_log.emit_node_event docstring.
    if stored > 0:
        # Use `kind_pulled` not `kind` — the latter is a reserved field
        # in emit_node_event (the OUTER `kind` is the event-type name,
        # e.g. "scraper_pulled" itself). Payload `kind` was silently
        # dropped, so the SROS renderer's "scraper · N <kind_pulled>"
        # row was falling back to the literal "records" instead of
        # showing "pages". Same goes for any future kinds (e.g.
        # "bundles") emitted from this site.
        _emit_node(
            "scraper_pulled", category="ingest",
            payload={
                "peer_pubkey": peer.pubkey,
                "peer_url": base,
                "count": stored,
                "kind_pulled": "pages",
            },
        )
    return (stored, "ok")


# ── background loop ────────────────────────────────────────────────

_thread: threading.Thread | None = None
_stop = threading.Event()


_discovery_cache: dict[str, str] = {}
_discovery_cache_ts: float = 0.0
_discovery_cache_lock = threading.Lock()
_DISCOVERY_TTL_SECS = 30.0


def _seed_peers_from_discovery(db_path: Path) -> int:
    """P2P review #1: a fresh node started with `--full` has an empty
    `peers` table; the scraper iterates `[]` and silently does
    nothing forever. We auto-`upsert_peer` every DiscoveredPeer that
    carries a pubkey (mDNS advertisement, peers.yaml entry,
    Tailscale-detected peer) so the scraper has work on first tick.

    Returns the number of new rows inserted. Idempotent — existing
    rows are updated, not duplicated. The signature_color/freq is
    derived deterministically from the pubkey via signature_for.

    Bug #100: stamp `last_seen_at` to "now" on insert. A discovered
    peer is by definition seen-now (we just learned about it on the
    wire); without the stamp, the very first `prune_stale_peers` tick
    treats `last_seen_at IS NULL` as ancient and evicts the row we
    just created. The same first tick runs both the seed and the
    prune (`_tick_count % PRUNE_EVERY_TICKS == 1`), so the two race."""
    try:
        from . import discovery
        from .peer_signature import signature_for
    except Exception:
        return 0
    seeded = 0
    own_pk = _self_pubkey()
    now = _now_iso()
    try:
        existing = {p.pubkey for p in list_peers(db_path)}
        for dp in discovery.discover_all_peers():
            if not dp.pubkey or dp.pubkey in existing:
                continue
            # Self-loop guard (geth nodeID check). Without this, our
            # own mDNS broadcast would seed ourselves as a peer and
            # the scraper would pull from itself.
            if own_pk and dp.pubkey == own_pk:
                continue
            color, freq = signature_for(dp.pubkey)
            try:
                upsert_peer(
                    db_path, pubkey=dp.pubkey,
                    nickname=(dp.name or "")[:MAX_NICKNAME_LEN],
                    signature_color=color,
                    signature_freq=freq,
                    last_seen_at=now,
                )
                logger.info(
                    "seeded %s from discovery (last_seen_at=%s)",
                    dp.pubkey[:12], now,
                )
                seeded += 1
            except Exception:
                continue
    except Exception:
        pass
    return seeded


def _bootstrap_from_peers_yaml(db_path: Path) -> int:
    """P2P-review #5: one-shot migration of peers.yaml into the
    indrex.peers table. Runs once per process start (the
    `_yaml_bootstrap_done` flag). Yaml entries with no pubkey are
    skipped — peer state must key on a stable identifier, and the
    yaml's optional `pubkey` field is exactly that.

    Returns the number of rows inserted. Idempotent across runs; a
    yaml entry that's already in `indrex.peers` is left alone.

    Bug #100: stamp `last_seen_at` to "now" on insert. A yaml entry
    is a "trust this peer at startup" assertion from the operator;
    without the stamp, the first `prune_stale_peers` tick (which
    evicts rows where `last_seen_at IS NULL`) immediately deletes
    the row this function just inserted. The bootstrap and the
    prune run in the same `_tick()` (the prune fires when
    `_tick_count % PRUNE_EVERY_TICKS == 1`, which is true on tick
    one), so without this stamp the yaml fallback is silently
    broken on every fresh-start node."""
    try:
        from .peer_signature import signature_for
        from .peers import load_peers
    except Exception:
        return 0
    seeded = 0
    own_pk = _self_pubkey()
    now = _now_iso()
    try:
        existing = {p.pubkey for p in list_peers(db_path)}
        cfg = load_peers()
        for p in cfg.enabled_peers:
            if not p.pubkey or p.pubkey in existing:
                continue
            # Self-loop guard (see _seed_peers_from_discovery).
            if own_pk and p.pubkey == own_pk:
                continue
            color, freq = signature_for(p.pubkey)
            try:
                upsert_peer(
                    db_path, pubkey=p.pubkey,
                    nickname=(p.name or "")[:MAX_NICKNAME_LEN],
                    signature_color=color,
                    signature_freq=freq,
                    last_seen_at=now,
                )
                logger.info(
                    "bootstrapped %s from peers.yaml (last_seen_at=%s)",
                    p.pubkey[:12], now,
                )
                seeded += 1
            except Exception:
                continue
    except Exception:
        pass
    return seeded


_yaml_bootstrap_done = False
_yaml_bootstrap_lock = threading.Lock()


def _bootstrap_once_from_yaml(db_path: Path) -> int:
    global _yaml_bootstrap_done
    with _yaml_bootstrap_lock:
        if _yaml_bootstrap_done:
            return 0
        n = _bootstrap_from_peers_yaml(db_path)
        _yaml_bootstrap_done = True
    return n


_orphan_reset_done = False
_orphan_reset_lock = threading.Lock()


def reset_orphan_cursors(db_path: Path) -> int:
    """Recovery for stuck cursors. A peer row with `last_pull_cursor > 0`
    but no `pages_meta` rows attributed to its pubkey is the residue of
    a previous run that advanced the cursor without persisting pages
    (db wipe, schema reset, or older ingest path). Every subsequent
    tick reads "cursor == producer HWM" and silently no-ops, so the
    wall stays empty even though discovery + verify are healthy.

    For each such peer, reset `last_pull_cursor=0` and clear
    `last_seen_epoch` so the next tick re-pulls from the start.
    Returns the number of peers reset. Idempotent; healthy peers
    (cursor=0 OR matching pages_meta rows) are left alone."""
    reset = 0
    try:
        conn = sqlite3.connect(str(db_path), timeout=5.0)
        try:
            try:
                rows = conn.execute(
                    "SELECT pubkey, nickname, last_pull_cursor "
                    "FROM peers WHERE last_pull_cursor > 0"
                ).fetchall()
            except sqlite3.OperationalError:
                return 0
            for pubkey, nickname, cursor in rows:
                try:
                    has_pages = conn.execute(
                        "SELECT 1 FROM pages_meta "
                        "WHERE source_type='peer_ingest' "
                        "AND source_pubkey=? LIMIT 1",
                        (pubkey,),
                    ).fetchone()
                except sqlite3.OperationalError:
                    # pages_meta not yet provisioned — skip silently;
                    # the next ingest will create it.
                    return 0
                if has_pages is not None:
                    continue
                conn.execute(
                    "UPDATE peers SET last_pull_cursor=0, "
                    "last_seen_epoch='' WHERE pubkey=?",
                    (pubkey,),
                )
                reset += 1
                logger.info(
                    "orphan cursor reset for %s: cursor was %s "
                    "but no peer_ingest pages exist — re-pulling from 0",
                    nickname or pubkey[:12], cursor,
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.error("orphan cursor scan failed: %s", e)
    return reset


def _orphan_reset_once(db_path: Path) -> int:
    global _orphan_reset_done
    with _orphan_reset_lock:
        if _orphan_reset_done:
            return 0
        n = reset_orphan_cursors(db_path)
        _orphan_reset_done = True
    return n


_self_purge_done = False
_self_purge_lock = threading.Lock()


def purge_self_peer_row(db_path: Path) -> int:
    """One-shot cleanup of a legacy self-row in `peers`. The auto-seed
    paths (`_seed_peers_from_discovery`, `_bootstrap_from_peers_yaml`)
    already block our own pubkey from being inserted, but a node that
    was running before that guard landed (or one whose self-row was
    added manually via `swf-peer add`) still has a stale row that
    causes an http_error pull every tick. Deletes the self-row if
    present; returns 1 if a row was removed, else 0."""
    own_pk = _self_pubkey()
    if not own_pk:
        return 0
    try:
        conn = sqlite3.connect(str(db_path), timeout=5.0)
        try:
            cur = conn.execute(
                "DELETE FROM peers WHERE pubkey=?", (own_pk,),
            )
            removed = cur.rowcount or 0
            conn.commit()
            if removed:
                logger.info(
                    "purged legacy self-row from peers (pubkey=%s…)",
                    own_pk[:12],
                )
            return int(removed)
        finally:
            conn.close()
    except Exception as e:
        logger.error("self-row purge failed: %s", e)
        return 0


def _self_purge_once(db_path: Path) -> int:
    global _self_purge_done
    with _self_purge_lock:
        if _self_purge_done:
            return 0
        n = purge_self_peer_row(db_path)
        _self_purge_done = True
    return n


def _resolve_peer_url(peer: Peer) -> str:
    """Best-effort: ask the discovery layer where this peer lives.
    Caches the discovery result for `_DISCOVERY_TTL_SECS` so a tick
    walking N peers doesn't re-browse mDNS N times.

    Pass-5 #10: serialize cache reads/writes through a lock. Today the
    only writer is the scraper thread, but a future signal (e.g. a
    "refresh peers" admin route) would race with `dict.clear()` and
    expose a partially-rebuilt cache to readers."""
    global _discovery_cache_ts
    now = time.time()
    with _discovery_cache_lock:
        stale = (now - _discovery_cache_ts > _DISCOVERY_TTL_SECS
                 or not _discovery_cache)
    if stale:
        try:
            from . import discovery
            fresh: dict[str, str] = {}
            for dp in discovery.discover_all_peers():
                if dp.pubkey and dp.url:
                    fresh[dp.pubkey] = dp.url
            with _discovery_cache_lock:
                _discovery_cache.clear()
                _discovery_cache.update(fresh)
                _discovery_cache_ts = now
        except Exception:
            pass
    with _discovery_cache_lock:
        return _discovery_cache.get(peer.pubkey, "")


_tick_count_lock = threading.Lock()
_tick_count = 0


def _tick(db_path: Path) -> None:
    """One scraper round. Pulls every peer in sequence (LAN is small;
    serial is fine and keeps the load predictable). When
    SWF_ENABLE_PEER_TRUST is set, banned peers are skipped here too
    so we don't even waste a discovery lookup on them.

    Auto-seeds the peers table from discovery before iterating so a
    fresh node with no manual `swf-peer add` calls still works
    (P2P-review finding #1). Also bootstraps once from peers.yaml
    on the first tick of the process (P2P-review #5) so existing
    yaml-managed deployments get a smooth migration.

    Every PRUNE_EVERY_TICKS rounds runs `prune_stale_peers` so dead
    rows from rotated identities / abandoned peers don't accumulate
    forever (geth-style table cleanup)."""
    yaml_seeded = _bootstrap_once_from_yaml(db_path)
    if yaml_seeded:
        logger.info(
            "bootstrapped %s peer(s) from peers.yaml", yaml_seeded,
        )
    # Once-per-process recovery for cursors stuck past producer HWM
    # with no peer_ingest pages on disk (see reset_orphan_cursors).
    _orphan_reset_once(db_path)
    # Once-per-process cleanup of legacy self-rows (#64). The seed
    # paths now block self-insertion, but pre-fix data may still
    # have a self-row that the runtime guard below would re-skip
    # forever — delete it once so the row count reflects reality.
    _self_purge_once(db_path)
    seeded = _seed_peers_from_discovery(db_path)
    if seeded:
        logger.info(
            "auto-seeded %s new peer(s) from discovery", seeded,
        )
    # Periodic table cleanup. Cheap (two indexed DELETEs); even at
    # 10× cadence overhead is negligible.
    global _tick_count
    with _tick_count_lock:
        _tick_count += 1
        do_prune = (_tick_count % PRUNE_EVERY_TICKS) == 1
    if do_prune:
        try:
            stats = prune_stale_peers(db_path)
            evicted = stats["stale"] + stats["broken"]
            if evicted:
                logger.info(
                    "pruned %s peer row(s) (stale=%s broken=%s kept=%s)",
                    evicted, stats["stale"], stats["broken"],
                    stats["kept"],
                )
                _emit("peer_pruned", stats)
        except Exception as e:
            logger.error("prune failed: %s", e)
    trust_on = _trust_enabled()
    # Per-tick aggregates for the heartbeat line. Without this, a tick
    # where every peer returns `status=ok stored=0` (caught up to HWM,
    # or silently skipped) emits zero log output — the exact failure
    # mode that hid the orphan-cursor bug for so long.
    visited = 0
    skipped_backoff = 0
    skipped_no_url = 0
    skipped_banned = 0
    skipped_self = 0
    total_stored = 0
    status_counts: dict[str, int] = {}
    own_pk = _self_pubkey()
    for peer in list_peers(db_path):
        if trust_on and peer.trust_level == "banned":
            skipped_banned += 1
            continue
        # Defensive belt-and-suspenders for the self-loop guard (#64).
        # The seed paths already filter self, and `_self_purge_once`
        # removes any legacy self-row at startup, but a runtime check
        # at the tick boundary protects against future regressions
        # (e.g. `swf-peer add` that omits the guard) without paying
        # for the extra HTTP round-trip.
        if own_pk and peer.pubkey == own_pk:
            skipped_self += 1
            continue
        # P2P-review #8: skip peers in exponential-backoff window.
        # The pull_from_peer call would still work, but a chronically-
        # failing peer (verify:merkle_mismatch on every round) was
        # burning network + log noise once a minute forever.
        if _peer_in_backoff(peer):
            skipped_backoff += 1
            continue
        peer.base_url = _resolve_peer_url(peer)
        if not peer.base_url:
            skipped_no_url += 1
            continue
        visited += 1
        try:
            stored, status = pull_from_peer(db_path, peer)
            total_stored += stored
            status_counts[status] = status_counts.get(status, 0) + 1
            if stored:
                logger.info(
                    "pulled %s pages from %s: %s",
                    stored,
                    peer.nickname or peer.pubkey[:12],
                    status,
                )
            elif status not in ("ok", "http_error"):
                logger.info(
                    "%s status=%s", peer.pubkey[:12], status,
                )
        except Exception as e:
            # Scraper errors must never bring down the host process.
            logger.error("tick error: %s", e)
            status_counts["exception"] = status_counts.get("exception", 0) + 1
    # Heartbeat: one line per tick summarising what happened. Emitted
    # even when nothing was stored so an operator can tell the loop
    # is alive and observe per-peer status distribution at a glance.
    if visited or skipped_backoff or skipped_no_url or skipped_banned:
        parts = [
            f"visited={visited}",
            f"stored={total_stored}",
        ]
        if skipped_backoff:
            parts.append(f"backoff={skipped_backoff}")
        if skipped_no_url:
            parts.append(f"no_url={skipped_no_url}")
        if skipped_banned:
            parts.append(f"banned={skipped_banned}")
        if skipped_self:
            parts.append(f"self={skipped_self}")
        if status_counts:
            statuses = " ".join(
                f"{k}={v}" for k, v in sorted(status_counts.items())
            )
            parts.append(f"[{statuses}]")
        logger.info("tick %s", " ".join(parts))


def _loop(db_path: Path, interval_secs: float) -> None:
    while not _stop.is_set():
        try:
            _tick(db_path)
        except Exception as e:
            logger.error("loop error: %s", e)
        # Wait — but wake immediately on stop().
        _stop.wait(timeout=interval_secs)


def start(*, db_path: Path | None = None,
          interval_secs: float = DEFAULT_INTERVAL_SECS) -> None:
    """Start the background scraper thread. Idempotent — calling twice
    is a no-op. Caller should be `swf-peer-server --full`."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    if db_path is None:
        from . import indrex
        db_path = indrex.db_path()
    # Register the network-change hook so a Wi-Fi switch / VPN flip
    # clears the discovery URL cache + resets every peer's backoff.
    # The discovery watchdog is started by peer_server.main; we just
    # subscribe to the event here. Captured `db_path` keeps the hook
    # bound to the right DB even if the scraper later runs against
    # a different one.
    captured = db_path
    def _on_network_change(old_ip: str, new_ip: str) -> None:
        # 1. drop the discovery URL cache so the next tick re-browses.
        with _discovery_cache_lock:
            _discovery_cache.clear()
        # 2. reset every peer's backoff — old failures were against
        #    the previous network's reachability.
        n = reset_all_backoff(captured)
        logger.info(
            "network change %s→%s: cleared discovery cache, "
            "reset backoff on %s peer(s)",
            old_ip, new_ip, n,
        )
        _emit("network_changed", {
            "old_ip": old_ip, "new_ip": new_ip,
            "peers_unblocked": n,
        })
    try:
        from . import discovery
        discovery.register_ip_change_hook(_on_network_change)
    except Exception:
        pass
    _stop.clear()
    _thread = threading.Thread(
        target=_loop, args=(db_path, float(interval_secs)),
        daemon=True, name="swf-peer-scraper",
    )
    _thread.start()


def stop() -> None:
    """Signal the loop to exit and wait briefly. For tests."""
    global _thread
    _stop.set()
    t = _thread
    if t is not None and t.is_alive():
        t.join(timeout=2.0)
    _thread = None


__all__ = [
    "BUNDLE_SCHEMA", "DEFAULT_LIMIT", "DEFAULT_INTERVAL_SECS",
    "MAX_BUNDLE_CURSOR_ADVANCE", "MAX_BUNDLE_PAGES",
    "MAX_NICKNAME_LEN", "MAX_SOURCE_LABEL_LEN",
    "BACKOFF_BASE_S", "BACKOFF_MAX_S",
    # Peer dataclass + alias
    "IndrexPeer", "Peer",
    "VerifyResult",
    # bundle build / verify
    "build_bundle", "verify_bundle",
    "merkle_root", "signing_payload",
    # producer-side cursor view (P2P-review #10 names + back-compat aliases)
    "producer_high_water_mark", "producer_high_water_with_epoch",
    "latest_cursor", "latest_cursor_with_epoch",
    # peers table CRUD
    "list_peers", "upsert_peer", "update_pull_cursor",
    "reset_orphan_cursors", "purge_self_peer_row",
    # ingest path
    "ingest_bundle", "pull_from_peer",
    # background loop
    "start", "stop",
]
