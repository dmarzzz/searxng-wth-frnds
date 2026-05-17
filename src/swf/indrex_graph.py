"""Issue #43 PR B — graph snapshot built from indrex.db.

The single-graph model: `/graph` reads directly from indrex's `pages`
table (joined with `pages_meta` for attribution) plus the `peers` table
that PR A introduced. Nodes are colored by `source_pubkey` so the wall
can show who contributed what.

Wire format (matches the legacy community_full.graph snapshot so the
wall doesn't break — same shape, new origin + filter tools):

    {
      "nodes": [{ id, title, host, topic, fetched_at,
                  source_pubkey, source_label, source_color,
                  is_self, degree }, ...],
      "edges": [{ source, target, weight }, ...],
      "peers": [{ pubkey, nickname, signature_color, signature_freq,
                  page_count, trust_level, last_seen_at, is_self }, ...],
      "topics": [],
      "stats": { nodes, edges, peers, lens, generated_at },
      "lens": <id>,
      "lens_options": [...],
      "shape_options": [...],
    }

The wall is responsible for layout. The server only ships data.
"""
from __future__ import annotations

import collections
import hashlib
import sqlite3
import threading
import time
import time as _time
from typing import Any

from . import indrex
from .peer_signature import signature_for

# ── snapshot cache ─────────────────────────────────────────────────
#
# P2P-review #7: `snapshot()` rebuilds the entire graph on every
# /graph hit (page_rows + sr_rows scans + O(N²) co-occurrence edge
# build). At 50k pages the search_results cross-product is several
# seconds blocking the HTTP thread. Cache by (max(rowid in pages),
# max(rowid in search_results), lens, own_pubkey) so duplicate
# /graph hits within `_CACHE_TTL_S` reuse the result. The keys are
# monotonic; any write invalidates the cache instantly.

_CACHE_TTL_S = 5.0
_cache_lock = threading.Lock()
_cache: dict[tuple, tuple[float, dict]] = {}


def _cache_key(
    p, lens: str, own_pubkey: str | None,
) -> tuple | None:
    """Return a cache key keyed on the high-water marks of the two
    source tables. None on any read error (skip cache, fall through
    to a fresh build)."""
    try:
        conn = indrex.open_read(p)
    except sqlite3.OperationalError:
        return None
    try:
        try:
            row = conn.execute("SELECT MAX(rowid) FROM pages").fetchone()
            page_hw = int(row[0] or 0)
        except sqlite3.OperationalError:
            page_hw = 0
        try:
            row = conn.execute(
                "SELECT MAX(rowid) FROM search_results"
            ).fetchone()
            sr_hw = int(row[0] or 0)
        except sqlite3.OperationalError:
            sr_hw = 0
    finally:
        conn.close()
    return (str(p), page_hw, sr_hw, lens, own_pubkey or "")


def _cache_get(key: tuple) -> dict | None:
    now = _time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
    if hit is None:
        return None
    ts, snap = hit
    if now - ts > _CACHE_TTL_S:
        return None
    return snap


def _cache_put(key: tuple, snap: dict) -> None:
    with _cache_lock:
        _cache[key] = (_time.monotonic(), snap)
        # Bound the cache so a `lens=` flood doesn't blow it up.
        if len(_cache) > 32:
            # Drop the oldest entries.
            stale = sorted(_cache.items(), key=lambda kv: kv[1][0])[:8]
            for k, _ in stale:
                _cache.pop(k, None)


def invalidate_cache() -> None:
    """Drop every cached snapshot. Tests + future explicit refresh
    triggers call this; the natural high-water-mark keying makes
    explicit invalidation unnecessary in normal operation."""
    with _cache_lock:
        _cache.clear()


# ── color helpers ───────────────────────────────────────────────────

def stable_hue(s: str) -> str:
    """Generic per-string hue. Used for hosts, fallback URLs, etc.
    For per-pubkey peer colors, prefer `peer_signature.signature_for`
    (P2P-review #6) — its 12-color palette guarantees distinctness
    where pure hash-to-hue produces near-collisions."""
    h = hashlib.blake2b(s.encode("utf-8"), digest_size=4).digest()
    hue = int.from_bytes(h, "big") / 0xFFFFFFFF
    return _hsl_hex(hue, 0.78, 0.62)


def _hsl_hex(h: float, s: float, lightness: float) -> str:
    if s == 0:
        v = round(lightness * 255)
        return f"#{v:02X}{v:02X}{v:02X}"
    q = lightness * (1 + s) if lightness < 0.5 else lightness + s - lightness * s
    p = 2 * lightness - q
    def t(x: float) -> int:
        if x < 0:
            x += 1
        if x > 1:
            x -= 1
        if x < 1 / 6:
            return round((p + (q - p) * 6 * x) * 255)
        if x < 1 / 2:
            return round(q * 255)
        if x < 2 / 3:
            return round((p + (q - p) * (2 / 3 - x) * 6) * 255)
        return round(p * 255)
    r, g, b = t(h + 1 / 3), t(h), t(h - 1 / 3)
    return f"#{r:02X}{g:02X}{b:02X}"


# Self-attributed nodes get a neutral cyan; peer nodes get the peer's
# signature_color from the peers table (or a stable_hue fallback).
SELF_COLOR = "#5AE6E6"


# ── snapshot ───────────────────────────────────────────────────────

def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def snapshot(
    *,
    lens: str = "topic",
    own_pubkey: str | None = None,
    db_path = None,
) -> dict[str, Any]:
    """Build the graph snapshot. Cached for `_CACHE_TTL_S` (P2P-#7);
    keyed on the (max-rowid-pages, max-rowid-search_results, lens,
    own_pubkey) tuple so any write to either source table evicts
    the entry instantly. Caller can force a rebuild by calling
    `invalidate_cache()` first."""
    p = indrex.db_path(db_path) if db_path is not None else indrex.db_path()
    if not p.exists():
        return _empty_snapshot(lens)

    key = _cache_key(p, lens, own_pubkey)
    if key is not None:
        cached = _cache_get(key)
        if cached is not None:
            return cached

    try:
        conn = indrex.open_read(p)
    except sqlite3.OperationalError:
        return _empty_snapshot(lens)

    try:
        page_rows = conn.execute(
            """SELECT p.url, p.title, p.fetched_at,
                      m.source_pubkey, m.source_label, m.source_type,
                      m.scraped_at, m.deleted_at_ms
               FROM pages p
               LEFT JOIN pages_meta m ON m.url = p.url
               ORDER BY p.rowid DESC"""
        ).fetchall()

        # Cached search-result associations build edges. The
        # swf.web's `search_results` FTS5 cache stores
        # (query_hash, url) tuples so URLs co-occurring under the same
        # query get a weighted edge.
        try:
            sr_rows = conn.execute(
                "SELECT query_hash, url FROM search_results"
            ).fetchall()
        except sqlite3.OperationalError:
            sr_rows = []

        # Peers known to the local indrex (post-PR-A). Includes
        # signature color/freq for the wall's sigchain rendering.
        try:
            peer_rows = conn.execute(
                "SELECT pubkey, nickname, signature_color, "
                "       signature_freq, last_seen_at, last_pull_cursor, "
                "       trust_level FROM peers"
            ).fetchall()
        except sqlite3.OperationalError:
            peer_rows = []

        # Issue #65: secondary attributions per URL. `pages_meta.source_pubkey`
        # is the *primary* contributor (first writer); `page_contributors`
        # holds every peer who has vouched for the same URL. We hydrate the
        # full set into a dict so `contributors[]` on each node reflects
        # multi-peer attribution. Best-effort: a legacy DB without the
        # table just yields an empty mapping.
        contrib_by_url: dict[str, list[str]] = collections.defaultdict(list)
        try:
            for r in conn.execute(
                "SELECT url, source_pubkey FROM page_contributors "
                "ORDER BY scraped_at DESC"
            ):
                try:
                    u, pk = r["url"], r["source_pubkey"]
                except (TypeError, IndexError):
                    u, pk = r[0], r[1]
                if u and pk:
                    contrib_by_url[u].append(pk)
        except sqlite3.OperationalError:
            pass
    finally:
        conn.close()

    # Drop tombstoned rows.
    page_rows = [r for r in page_rows if r["deleted_at_ms"] is None]

    # Index peer signature_color by pubkey for fast node-coloring.
    peer_color: dict[str, str] = {}
    peer_label: dict[str, str] = {}
    for r in peer_rows:
        pk = r["pubkey"]
        # Prefer the stored color; fall back to the deterministic
        # palette so a yet-uncolored peer still renders distinctly.
        peer_color[pk] = r["signature_color"] or signature_for(pk)[0]
        peer_label[pk] = r["nickname"] or pk[:12]

    # Edges from search-result co-occurrence.
    page_urls = {r["url"] for r in page_rows}
    by_query: dict[str, list[str]] = collections.defaultdict(list)
    for r in sr_rows:
        if r["url"] in page_urls:
            by_query[r["query_hash"]].append(r["url"])
    edge_w: collections.Counter = collections.Counter()
    for urls in by_query.values():
        urls = sorted(set(urls))
        for i, a in enumerate(urls):
            for b in urls[i + 1:]:
                edge_w[(a, b)] += 1

    degrees: collections.Counter = collections.Counter()
    for (a, b) in edge_w:
        degrees[a] += 1
        degrees[b] += 1

    nodes: list[dict[str, Any]] = []
    for r in page_rows:
        url = r["url"] or ""
        if not url:
            continue
        spk = r["source_pubkey"]
        # `is_self` lets the wall's mine/all toggle filter without
        # re-walking the peers table. A row counts as self if either
        # source_type='user_fetched' (default) or source_pubkey is
        # missing (legacy rows pre-#43).
        is_self = (spk is None) or (r["source_type"] == "user_fetched") \
            or (own_pubkey is not None and spk == own_pubkey)
        if is_self:
            color = SELF_COLOR
            label = "self"
            spk_out = own_pubkey or "self"
        else:
            color = peer_color.get(spk) or signature_for(spk or url)[0]
            label = r["source_label"] or peer_label.get(spk, "")
            spk_out = spk or ""
        host = _host_of(url)
        # Merge primary attribution with the page_contributors join
        # table so URLs vouched for by multiple peers expose all of
        # them. Order: primary first (preserving wall coloring), then
        # secondary contributors in scraped_at DESC order, deduped.
        contributors: list[str] = []
        if spk_out:
            contributors.append(spk_out)
        for pk in contrib_by_url.get(url, ()):
            if pk and pk not in contributors:
                contributors.append(pk)
        nodes.append({
            "id": url,
            "title": r["title"] or url,
            "host": host,
            "topic": "",   # PR D adds topic-coloring; today empty string
            "fetched_at": r["fetched_at"] or "",
            "source_pubkey": spk_out,
            "source_label": label,
            "source_color": color,
            "is_self": bool(is_self),
            "host_color": stable_hue(host or url),
            "degree": int(degrees.get(url, 0)),
            "scraped_at": r["scraped_at"] or "",
            # Back-compat aliases for the legacy wall (pre-#43 D). The
            # wall colors and groups by `primary_contributor`; we mirror
            # `source_pubkey` here so existing UI keeps working without
            # a coordinated rename.
            "primary_contributor": spk_out,
            "contributors": contributors,
        })

    edges = [
        {"source": a, "target": b, "weight": int(w)}
        for (a, b), w in edge_w.items() if w >= 2
    ]

    # Per-peer page counts for the peers panel.
    page_count_by_pk: collections.Counter = collections.Counter()
    for n in nodes:
        page_count_by_pk[n["source_pubkey"]] += 1

    peers_out: list[dict[str, Any]] = []
    if own_pubkey is not None:
        peers_out.append({
            "pubkey": own_pubkey,
            "nickname": "self",
            "signature_color": SELF_COLOR,
            "signature_freq": 0.0,
            "page_count": int(page_count_by_pk.get(own_pubkey, 0)
                              + page_count_by_pk.get("self", 0)),
            "last_seen_at": "",
            "trust_level": "self",
            "is_self": True,
        })
    for r in peer_rows:
        pk = r["pubkey"]
        peers_out.append({
            "pubkey": pk,
            "nickname": r["nickname"] or pk[:12],
            "signature_color": r["signature_color"] or signature_for(pk)[0],
            "signature_freq": float(r["signature_freq"] or 0.0),
            "page_count": int(page_count_by_pk.get(pk, 0)),
            "last_seen_at": r["last_seen_at"] or "",
            "trust_level": r["trust_level"] or "known",
            "is_self": False,
        })

    snap = {
        "nodes": nodes,
        "edges": edges,
        "peers": peers_out,
        "topics": [],
        "clusters": [],
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "peers": len(peers_out),
            "lens": lens,
            "generated_at": int(time.time() * 1000),
        },
        "lens": lens,
        "lens_options": LENS_OPTIONS,
        "shape_options": SHAPE_OPTIONS,
    }
    if key is not None:
        _cache_put(key, snap)
    return snap


def _empty_snapshot(lens: str) -> dict[str, Any]:
    return {
        "nodes": [], "edges": [], "peers": [], "topics": [],
        "clusters": [],
        "stats": {"nodes": 0, "edges": 0, "peers": 0, "lens": lens,
                  "generated_at": int(time.time() * 1000)},
        "lens": lens,
        "lens_options": LENS_OPTIONS,
        "shape_options": SHAPE_OPTIONS,
    }


LENS_OPTIONS = [
    {"id": "topic",       "label": "Topic",       "desc": "Group by topic-cluster."},
    {"id": "domain",      "label": "Domain",      "desc": "Group by host."},
    {"id": "contributor", "label": "Contributor", "desc": "Group by who contributed."},
    {"id": "time",        "label": "Time",        "desc": "Sort along the contribution timeline."},
    {"id": "recency",     "label": "Recency",     "desc": "Distance = time since last touched."},
    {"id": "chaos",       "label": "Chaos",       "desc": "🌀"},
]
SHAPE_OPTIONS = [
    {"id": "cluster", "label": "Cluster", "desc": "Force-directed."},
    {"id": "sphere",  "label": "Sphere",  "desc": "Fibonacci sphere."},
    {"id": "matrix",  "label": "Matrix",  "desc": "3D grid."},
    {"id": "spiral",  "label": "Spiral",  "desc": "Golden-ratio spiral."},
    {"id": "stream",  "label": "Stream",  "desc": "Horizontal flow."},
    {"id": "grid",    "label": "Grid",    "desc": "Uniform lattice."},
]


__all__ = ["snapshot", "stable_hue", "SELF_COLOR",
           "LENS_OPTIONS", "SHAPE_OPTIONS"]
