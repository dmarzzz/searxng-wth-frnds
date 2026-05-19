"""Peer HTTP server. Exposes the local indrex to other peers in the trust circle.

Endpoints:
  GET /health                            → {"ok": true, "version": "0.5.0"}
  GET /.well-known/indrex                → self-description JSON
  GET /search?q=...&limit=8              → JSON list of hits from local pages+cache
  GET /slices/head                       → Ship 0.8 sigchain head
  GET /slices/<seq>                      → Ship 0.8 sigchain slice
  GET /community/slice?since_p=&since_s= → community-graph slice (Ed25519 signed
                                            envelope of new pages + search_results,
                                            with IPFS CIDs). Pulled by full nodes.
  GET /digest/urls                       → URL membership digest
  GET /bundles?kind=&since=&record_id=   → list signed bundles (#93 phase 2)
  GET /bundles/by_cid/<cid>              → fetch one bundle by content hash
  POST /bundles                          → submit signed bundle (#93 phase 3)
  GET /bundles/subscribe?kind=<kind>     → SSE stream of new bundles (#93 phase 4)
  GET /alchemists                        → active alchemist roster (#108 ask 2)
  POST /hivemind/transcripts             → voxterm sink: wrap+sign batch
                                           (#93 phase 5; only registered
                                            when --hivemind-sink is set)

`--full` also boots an aggregator on a sibling port (default 7790) that
scrapes `/community/slice` from every LAN peer it discovers via mDNS and
builds the union community indrex. See `swf.community_full`.

v0.2 posture: plain HTTP, no auth, LAN-trust. Bind is `127.0.0.1` by
default so nothing is exposed until the user opts in with
`SWF_BIND=0.0.0.0` (or a specific LAN IP). See INDREX.md section D.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import re
import sqlite3
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from swf import __version__ as SWF_VERSION
from swf.web.knowledge import knowledge_root

logger = logging.getLogger(__name__)

_DB_PATH = knowledge_root() / "index.db"
_CFG_DIR = os.environ.get("SWF_CONFIG_DIR") or str(
    os.path.expanduser("~/.config/swf")
)
_DEFAULT_LIMIT = 10
_MAX_LIMIT = 50


def _open_db() -> sqlite3.Connection:
    """Legacy shim kept for the /digest endpoint which still reads the DB
    directly. New code paths use `swf.indrex` helpers."""
    uri = f"file:{_DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    conn.row_factory = sqlite3.Row
    return conn


def _do_search(q: str, limit: int) -> list[dict]:
    """Thin wrapper over `swf.indrex.query`. Passes this server's own
    `_DB_PATH` so multi-peer-in-one-process test harnesses stay isolated
    from each other."""
    from swf.indrex import query as indrex_query

    lim = max(1, min(limit, _MAX_LIMIT))
    results = indrex_query(q, limit=lim, db=_DB_PATH)
    return [
        {
            "url": r.url,
            "title": r.title,
            "snippet": r.snippet,
            "seen_at": r.when,
            "source": r.source,
        }
        for r in results
    ]


def _hostname() -> str:
    # Prefer a stable node name if the user set one; otherwise socket.gethostname().
    import socket

    return os.environ.get("SWF_NODE_NAME") or socket.gethostname()


def _all_urls_in_indrex() -> list[str]:
    """Return all canonical URLs this peer holds (pages + cached search
    results, unioned). Used to build a URL-membership digest."""
    if not _DB_PATH.exists():
        return []
    urls: set[str] = set()
    try:
        conn = _open_db()
    except sqlite3.OperationalError:
        return []
    try:
        try:
            for row in conn.execute("SELECT url FROM pages"):
                u = row[0]
                if u:
                    urls.add(u)
        except sqlite3.OperationalError:
            pass
        try:
            for row in conn.execute("SELECT url FROM search_results"):
                u = row[0]
                if u:
                    urls.add(u)
        except sqlite3.OperationalError:
            pass
    finally:
        conn.close()
    return sorted(urls)


def _build_urls_digest(recipient_pubkey_b64: str, target_fp: float = 0.01) -> bytes:
    """Build a per-recipient-salted URL-membership bloom filter over
    this peer's entire indrex. Circle secret (if configured) is folded
    into the salt too."""
    from swf.digest import build_filter, load_circle_secret

    urls = _all_urls_in_indrex()
    return build_filter(
        urls,
        recipient_pubkey_b64=recipient_pubkey_b64,
        circle_secret=load_circle_secret(),
        target_fp=target_fp,
    )


def _identity_cached():
    """Lazy-load the Ed25519 identity; cache on first use.

    Kept as a function (not module-level) so unit tests can set
    `SWF_CONFIG_DIR` before the first import and get isolated keypairs.
    """
    from swf.identity import get_or_create_identity

    global _IDENTITY
    try:
        if _IDENTITY is None:
            _IDENTITY = get_or_create_identity()
    except Exception as exc:
        logger.error("identity unavailable: %s", exc)
        _IDENTITY = None
    return _IDENTITY


_IDENTITY = None


# ── #93 phase 3: alchemist list cache (shared) ─────────────────────────────
# `swf.bundles.load_alchemists` reads YAML from env / config dir / HOME.
# We cache the result on first POST instead of reloading per request: the
# file is conceptually static across a process lifetime, and reloading on
# every request both burns disk reads and races against an operator's
# mid-write `.alchemists.yml` edit. Reload semantics are deferred (the spec
# is silent on hot-reload).
#
# The cache itself now lives in `swf.bundles.alchemists` so a single
# process-wide cache is shared by every bundle ingest channel
# (peer_server's `POST /bundles` verifier, the pull puller, the
# hivemind route). The wrappers below preserve this module's import
# surface — `_load_alchemists_cached` and `_reset_alchemists_cache_for_tests`
# are used by tests and by `swf.hivemind.route` — so the lift is
# transparent. This mirrors the reservoir cache lift in #105.


def _load_alchemists_cached():
    """Return the AlchemistList, loading from disk on the first call.

    Delegates to the shared cache in `swf.bundles.alchemists` so the
    `POST /bundles` verifier, the pull puller, and the hivemind route
    all read the same parse result. The first POST after process start
    pays the YAML parse cost; subsequent POSTs are dict lookups.
    """
    from swf.bundles import load_alchemists_cached as _shared
    return _shared()


def _reset_alchemists_cache_for_tests() -> None:
    """Drop the shared AlchemistList cache. Tests call this in setup so
    each case loads its own tmp `.alchemists.yml` instead of leaking
    the previous test's pubkey set. Thin wrapper over
    `swf.bundles.alchemists.reset_alchemists_cache_for_tests` so the
    existing peer_server-level test surface (used by
    `tests/test_peer_server_bundles_post.py` and friends) keeps working
    after the cache was lifted."""
    from swf.bundles import reset_alchemists_cache_for_tests as _shared
    _shared()


def _well_known_indrex() -> dict:
    try:
        conn = _open_db()
        try:
            n_pages = conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]
            try:
                n_cache = conn.execute(
                    "SELECT COUNT(*) FROM search_results"
                ).fetchone()[0]
            except sqlite3.OperationalError:
                n_cache = 0
        finally:
            conn.close()
    except Exception:
        n_pages = 0
        n_cache = 0
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    ts = _dt.now(_tz.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    ident = _identity_cached()
    pubkey = ident.pub_b64 if ident is not None else None
    body = {
        "name": _hostname(),
        "version": SWF_VERSION,
        "protocol": "searxng-wth-frnds/v0.4",
        "capabilities": ["search", "signed-handshake"],
        "stats": {
            "pages": n_pages,
            "cached_urls": n_cache,
        },
        "pubkey": pubkey,
        "fingerprint": ident.fingerprint() if ident is not None else None,
        "ts": ts,
    }

    # Sign the body so a pinning peer can verify identity continuity.
    # The signature covers the canonical form (pubkey, node, ts, body_hash)
    # so flipping any of those invalidates the sig.
    if ident is not None:
        from swf.identity import body_hash_b64, canonical_indrex_response

        body_for_hash = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload = canonical_indrex_response(
            pubkey_b64=ident.pub_b64,
            node=_hostname(),
            ts=ts,
            body_hash=body_hash_b64(body_for_hash),
        )
        body["sig"] = ident.sign_b64(payload)
        body["body_hash"] = body_hash_b64(body_for_hash)
    return body


class _Handler(BaseHTTPRequestHandler):
    server_version = f"swf-peer/{SWF_VERSION}"

    def _respond(self, status: int, body: dict | str, content_type: str = "application/json"):
        if isinstance(body, (dict, list)):
            payload = json.dumps(body).encode("utf-8")
            content_type = "application/json"
        else:
            payload = str(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        # Conservative: no CORS, no caching. Clients are our own peer_client.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802  (stdlib API)
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            return self._respond(200, {"ok": True, "version": SWF_VERSION})

        if path == "/.well-known/indrex":
            return self._respond(200, _well_known_indrex())

        if path == "/search":
            qs = parse_qs(parsed.query)
            q = (qs.get("q") or [""])[0]
            try:
                limit = int((qs.get("limit") or [str(_DEFAULT_LIMIT)])[0])
            except ValueError:
                limit = _DEFAULT_LIMIT
            results = _do_search(q, limit)
            return self._respond(
                200,
                {
                    "query": q,
                    "peer": _hostname(),
                    "version": SWF_VERSION,
                    "results": results,
                },
            )

        if path == "/slices/head":
            from swf.slice_publish import latest_head

            head = latest_head(cfg_dir=_CFG_DIR)
            if head is None:
                return self._respond(404, {"error": "no slices published yet"})
            return self._respond(
                200,
                {
                    "seq": head["seq"],
                    "hash": head["hash"],
                    "cursor": head["cursor"],
                },
            )

        if path.startswith("/slices/"):
            tail = path[len("/slices/"):]
            if tail and tail.lstrip("-").isdigit():
                from swf.slice_publish import slice_path_for

                seq = int(tail)
                fp = slice_path_for(seq, cfg_dir=_CFG_DIR)
                if fp is None or not fp.exists():
                    return self._respond(404, {"error": f"slice {seq} not found"})
                try:
                    body = fp.read_text()
                except Exception as exc:
                    return self._respond(500, {"error": f"read failed: {exc}"})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "public, max-age=3600")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))
                return

        if path == "/graph":
            # Issue #43 PR B: graph reads from indrex.db now (joined
            # with pages_meta for attribution and peers for color).
            # No longer requires --full mode — every node has the
            # data; aggregator-only state is gone.
            qs = parse_qs(parsed.query)
            lens = (qs.get("lens") or ["topic"])[0]
            try:
                from swf import indrex_graph
                from swf.identity import get_or_create_identity
                own_pubkey = get_or_create_identity().pub_b64
                body = indrex_graph.snapshot(
                    lens=lens, own_pubkey=own_pubkey,
                )
            except Exception as exc:
                return self._respond(500, {"error": f"graph build failed: {exc}"})
            return self._respond(200, body)

        if path == "/events":
            # Issue #43 PR B: subscribes to swf.event_bus (indrex-backed).
            # The bus replays history from indrex.events on `since=`
            # and streams live events from any emitter (peer scraper,
            # mDNS probe, etc).
            qs = parse_qs(parsed.query)
            since: int | None = None
            try:
                if qs.get("since"):
                    since = int(qs["since"][0])
            except ValueError:
                since = None
            try:
                from swf import event_bus
            except Exception as exc:
                return self._respond(500, {"error": f"event bus unavailable: {exc}"})
            return self._serve_sse(event_bus, since)

        if path == "/admin/pending" or path == "/admin/peers":
            # Removed in #43 PR C alongside the rest of the
            # community-graph machinery. The 410 stays so old clients
            # stop polling instead of getting a confusing 404.
            return self._respond(410, {"error": f"{path} removed in #43 PR C"})

        # ── /metrics/snapshot + /metrics/series ─────────────────────────
        # Self-contained metrics endpoints. Read-only; live behind no auth
        # for parity with /graph and /events. Backed by metrics.db's
        # `metrics_samples` table populated by the metrics collector
        # background thread (see community_full/metrics.py).
        if path == "/metrics/snapshot":
            try:
                from swf.community_full import metrics as cmetrics
            except ImportError:
                return self._respond(404, {"error": "/metrics requires --full mode"})
            return self._respond(200, cmetrics.snapshot())

        if path == "/metrics/series":
            try:
                from swf.community_full import metrics as cmetrics
            except ImportError:
                return self._respond(404, {"error": "/metrics requires --full mode"})
            qs = parse_qs(parsed.query)
            names_raw = (qs.get("names") or [""])[0]
            names = [n.strip() for n in names_raw.split(",") if n.strip()]
            now_ms = int(__import__("time").time() * 1000)
            try:
                from_ms = int((qs.get("from") or [str(now_ms - 3600_000)])[0])
                until_ms = int((qs.get("until") or [str(now_ms)])[0])
                step_ms = int((qs.get("step") or ["60000"])[0])
            except ValueError:
                return self._respond(400, {"error": "from/until/step must be integers"})
            if not names:
                return self._respond(400, {"error": "names is required (comma-separated)"})
            # Cap the query span so a malicious caller can't ask us to
            # bucket months of data into 1ms steps.
            step_ms = max(1_000, min(step_ms, 6 * 3600_000))
            until_ms = max(until_ms, from_ms + step_ms)
            return self._respond(200, cmetrics.series(
                names, from_ms=from_ms, until_ms=until_ms, step_ms=step_ms,
            ))

        # ── Issue #43 PR A: single-graph indrex pull endpoints ───────────
        # `/index/cursor` → max(rowid in pages). Caller pages with
        # `/index/pages?since=&limit=`. Each response is one signed
        # bundle the puller can verify offline.
        if path == "/index/cursor":
            # P2P-review #2: include `epoch_id` so consumers can
            # detect a DB rebuild without fetching a full bundle.
            try:
                from swf.indrex import db_path as _idx_db
                from swf.peer_scraper import producer_high_water_with_epoch
                cur, epoch = producer_high_water_with_epoch(_idx_db())
            except Exception as exc:
                return self._respond(500, {"error": f"cursor failed: {exc}"})
            return self._respond(200, {
                "cursor": int(cur), "epoch_id": epoch,
            })

        if path == "/index/pages":
            qs = parse_qs(parsed.query)
            try:
                since = int((qs.get("since") or ["0"])[0])
                limit = int((qs.get("limit") or ["500"])[0])
            except ValueError:
                return self._respond(400, {"error": "since/limit must be integers"})
            # Cap limit to keep p50 verify under 10ms even on a slow client.
            limit = max(1, min(limit, 5000))
            try:
                from swf.indrex import db_path as _idx_db
                from swf.peer_scraper import build_bundle
                bundle = build_bundle(
                    db_path=_idx_db(), since=since, limit=limit,
                )
            except Exception as exc:
                return self._respond(500, {"error": f"bundle failed: {exc}"})
            return self._respond(200, bundle)

        # ── #93 phase 2: bundle read API (§4.1 of SHAPE-ROTATOR-OS-SPEC.md) ──
        # Read-only routes over the swf.bundles SQLite store. POST is
        # phase 3; SSE subscribe is phase 4. Order matters: the exact
        # `/bundles/subscribe` match must come BEFORE `/bundles` so
        # the SSE handler wins over the JSON-list handler.
        if path == "/bundles/subscribe":
            return self._do_bundles_subscribe(parse_qs(parsed.query))
        if path == "/bundles":
            return self._do_bundles_list(parse_qs(parsed.query))
        if path.startswith("/bundles/by_cid/"):
            cid = path[len("/bundles/by_cid/"):]
            return self._do_bundles_by_cid(cid)

        # ── Phase 2 sync: cohort-profile sync protocol (docs/SYNC.md) ────
        # Three read endpoints + one write endpoint (in do_POST below).
        # All routes load a fresh sqlite connection per request and run
        # `swf.sync.schema.ensure_schema` defensively. The handlers
        # themselves live below as `_do_sync_*` methods.
        if path == "/sync/manifest":
            return self._do_sync_manifest()
        if path.startswith("/sync/record/"):
            tail = path[len("/sync/record/"):]
            # `/sync/record/<id>` (current page) and
            # `/sync/record/<id>/history` (full append-only log) split
            # on the suffix. Order: history match wins.
            if tail.endswith("/history"):
                rec = tail[: -len("/history")]
                return self._do_sync_record_history(rec, parse_qs(parsed.query))
            return self._do_sync_record(tail, parse_qs(parsed.query))

        # ── #108 ask 2: discoverable alchemist roster ────────────────────
        # `GET /alchemists` lets the alchemist Electron app + the
        # cohort viz check whether their loaded Ed25519 key is in the
        # active roster BEFORE attempting a POST (which would 403 with
        # `author_not_alchemist` and waste a round trip on the user).
        # Also surfaces the file path + a `loaded_at` timestamp so a
        # parallel-worktree workflow (#109) can confirm the in-memory
        # roster reflects the latest YAML edit.
        #
        # NEW PUBLIC ROUTE. No auth — the alchemist pubkey list is
        # the trust set; consumers verifying signatures need it. So
        # there is no 403 path here.
        if path == "/alchemists":
            return self._do_alchemists_get()

        if path == "/digest/urls":
            qs = parse_qs(parsed.query)
            recipient_pk = (qs.get("recipient_pk") or [""])[0].strip()
            try:
                fp = float((qs.get("target_fp") or ["0.01"])[0])
            except ValueError:
                fp = 0.01
            if not recipient_pk:
                return self._respond(
                    400,
                    {"error": "recipient_pk required (base64url Ed25519 pubkey)"},
                )
            try:
                blob = _build_urls_digest(recipient_pk, target_fp=fp)
            except Exception as exc:
                return self._respond(500, {"error": f"digest build failed: {exc}"})
            # Return as application/octet-stream with stats in headers.
            from swf.digest import filter_stats

            stats = filter_stats(blob)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob)))
            self.send_header("X-Swf-Digest-K", str(stats["k"]))
            self.send_header("X-Swf-Digest-MBits", str(stats["m_bits"]))
            self.send_header("X-Swf-Digest-N", str(stats["n_items"]))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(blob)
            return

        return self._respond(404, {"error": "not found", "path": path})

    # TODO-5: SPEC v0.3 search routes never need more than a few KiB.
    # The legacy slice/contribute paths can carry larger payloads, so
    # we keep a 10 MB outer ceiling but the SPEC-v0.3 routes pass a
    # tighter `max_bytes` override at their call site. Slow-loris is
    # mitigated by the per-request socket timeout (leak audit F1).
    _MAX_DEFAULT_BODY_BYTES = 10_000_000
    _MAX_SEARCH_BODY_BYTES = 65_536  # 64 KiB; enough for any /web_search,
                                      # /friend_search, /search_feedback body

    def _read_json_body(self, *, max_bytes: int | None = None) -> dict | None:
        try:
            n = int(self.headers.get("Content-Length") or "0")
            limit = max_bytes if max_bytes is not None else self._MAX_DEFAULT_BODY_BYTES
            if n <= 0 or n > limit:
                return None
            with contextlib.suppress(OSError):
                self.connection.settimeout(15)
            raw = self.rfile.read(n)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def _content_length_over(self, max_bytes: int) -> bool:
        """True if `Content-Length` declares a body larger than
        `max_bytes`. Used by SPEC-v0.3 search routes to return a
        structured 413 BEFORE reading, so a malformed-but-tiny body
        doesn't get conflated with an oversize-but-rejected one."""
        try:
            n = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return False
        return n > max_bytes

    def _check_token(self) -> bool:
        """True if the caller is authorized for privileged sources.
        - When SWF_AGENT_TOKEN is unset, we accept iff bound to loopback
          (the agent is local; LAN can't reach us anyway).
        - When set, require Authorization: Bearer <token>.
        """
        expected = os.environ.get("SWF_AGENT_TOKEN")
        if not expected:
            bind = (self.server.server_address[0] or "")
            return bind.startswith("127.") or bind in ("localhost", "::1")
        h = self.headers.get("Authorization") or ""
        return h.strip() == f"Bearer {expected}"

    def _serve_sse(self, cevents, since):
        """SSE handler — keeps the connection open and writes events as
        they arrive. Heartbeats every 15s as `: keepalive\\n\\n` so proxies
        and the renderer's EventSource know we're alive."""
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
        except Exception:
            return
        try:
            for ev in cevents.subscribe(replay_since_id=since):
                if ev is None:
                    # heartbeat
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                msg = (
                    f"id: {ev['id']}\n"
                    f"event: {ev['kind']}\n"
                    f"data: {json.dumps(ev['payload'], separators=(',',':'))}\n\n"
                ).encode()
                self.wfile.write(msg)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:
            logger.error("SSE error: %s", e)
            return

    # ── #93 phase 2: bundle read API helpers (§4.1 of SHAPE-ROTATOR-OS-SPEC.md) ──
    # Read-only. Both routes open a fresh connection to the indrex DB,
    # run `ensure_schema` defensively (so a node that's never written a
    # bundle still responds with an empty list rather than 500), and
    # then delegate to `swf.bundles.list_` / `get_by_cid`.

    _BUNDLES_DEFAULT_LIMIT = 100
    _BUNDLES_MAX_LIMIT = 1000
    _CID_RE = re.compile(r"^[0-9a-f]{64}$")

    def _open_bundles_conn(self) -> sqlite3.Connection:
        """Open the indrex DB for bundle reads.

        We deliberately use a writable connection (not `indrex.open_read`)
        because `ensure_schema` may need to CREATE TABLE on a node that's
        never had a bundle written. WAL mode means readers don't block,
        and the swf.bundles helpers commit on their own (insert path);
        the read paths used here issue no writes beyond the idempotent
        DDL in `ensure_schema`.
        """
        from swf.indrex import db_path as _idx_db
        conn = sqlite3.connect(str(_idx_db()), timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _do_bundles_list(self, qs: dict) -> None:
        """Handle `GET /bundles?kind=&since=&record_id=&received_since=&limit=`.

        Two cursor modes, mutually exclusive:

          * **Per-record version cursor** (legacy, phase 2): pass
            `record_id=<r>&since=<v>` to paginate the single-record
            version stream (strict-greater than `since`). When
            `record_id` is absent, `since` is ignored and the response
            is the first page only (newest-first by `signed_at`,
            capped at `limit`). Used by clients that follow one
            record's evolution.
          * **Cross-record rowid cursor** (#93 phase 6 follow-up):
            pass `received_since=<rowid>` (no `record_id`, no `since`)
            to paginate every bundle in insertion order with
            `rowid > received_since`, ordered ASC. Used by the
            pull-side replication puller (`swf.bundles.puller`) to
            catch up an offline-then-rejoin peer past everything we've
            already received.

        Mixing modes (`received_since=` together with `record_id=` or
        `since=`) returns 400 — the cursor types address different
        data shapes (per-record version vs. cross-record rowid) and
        have no coherent merged semantic.

        Response shape:
          - per-record mode → `{ bundles, next_since }`
          - rowid mode      → `{ bundles, next_received_since }`
            * `next_received_since` is the largest rowid in the page
              (the next call should use it as `received_since` to skip
              past these bundles), OR null when the page is empty
              (puller stops looping on this peer).

        Privacy note: `payload` for `cohort.depth` (and any future
        encrypted kinds) is opaque ciphertext. swf-node has no
        decryption capability — we return the envelope verbatim, exactly
        as it was signed and stored.
        """
        from swf import bundles as _bundles

        kind_raw = (qs.get("kind") or [None])[0]
        record_id = (qs.get("record_id") or [None])[0]
        since_raw = (qs.get("since") or [None])[0]
        received_since_raw = (qs.get("received_since") or [None])[0]
        limit_raw = (qs.get("limit") or [None])[0]

        # Validate `kind` early — an unknown kind is a client bug, not
        # an empty-result, so we 400 with the valid list.
        if kind_raw is not None and kind_raw not in _bundles.BUNDLE_KINDS:
            return self._respond(400, {
                "error": "invalid_kind",
                "valid": sorted(_bundles.BUNDLE_KINDS),
            })

        # Mode-mixing guard. The two cursor modes (per-record version
        # vs. cross-record rowid) address different shapes and merging
        # them has no coherent semantic; reject early so a client bug
        # surfaces as a 400 rather than silently mis-paginating.
        if received_since_raw is not None and (
            record_id is not None or since_raw is not None
        ):
            return self._respond(400, {
                "error": "received_since_mutually_exclusive",
                "detail": (
                    "received_since cannot be combined with record_id "
                    "or since; use received_since for cross-record "
                    "rowid pagination, record_id+since for per-record "
                    "version pagination."
                ),
            })

        # Parse `since`. Only honored when `record_id` is also set; see
        # the docstring above for the rationale.
        since_version: int | None = None
        if since_raw is not None and record_id is not None:
            try:
                since_version = int(since_raw)
            except ValueError:
                return self._respond(400, {"error": "invalid_since"})

        # Parse `received_since`. Must be a non-negative integer.
        received_since: int | None = None
        if received_since_raw is not None:
            try:
                received_since = int(received_since_raw)
            except ValueError:
                return self._respond(400, {"error": "invalid_received_since"})
            if received_since < 0:
                return self._respond(400, {"error": "invalid_received_since"})

        # Parse `limit`. Default 100; cap at 1000 to prevent a single
        # request from exfiltrating the entire bundle store at once.
        try:
            limit = int(limit_raw) if limit_raw is not None else self._BUNDLES_DEFAULT_LIMIT
        except ValueError:
            return self._respond(400, {"error": "invalid_limit"})
        if limit < 1:
            limit = 1
        if limit > self._BUNDLES_MAX_LIMIT:
            return self._respond(400, {
                "error": "limit_too_large",
                "max": self._BUNDLES_MAX_LIMIT,
            })

        try:
            conn = self._open_bundles_conn()
        except sqlite3.OperationalError as exc:
            return self._respond(500, {"error": f"bundles store unavailable: {exc}"})
        try:
            _bundles.ensure_schema(conn)
            if received_since is not None:
                # Rowid-mode cursor — `list_with_rowid` returns
                # (envelope, rowid) tuples in rowid ASC. The puller
                # uses `next_received_since` to advance its
                # per-peer high-water across ticks.
                pairs = _bundles.list_with_rowid(
                    conn,
                    kind=kind_raw,
                    received_since=received_since,
                    limit=limit,
                )
                page = [env for env, _rid in pairs]
                next_received_since: int | None = (
                    int(pairs[-1][1]) if pairs else None
                )
                return self._respond(200, {
                    "bundles": page,
                    "next_received_since": next_received_since,
                })

            # Legacy per-record version cursor. We over-fetch by 1
            # row so we can detect "more pages exist" without a
            # second query.
            rows = _bundles.list_(
                conn,
                kind=kind_raw,
                record_id=record_id,
                since_version=since_version,
                limit=limit + 1,
            )
        finally:
            conn.close()

        # `swf.bundles.list_` orders by version DESC when record_id is
        # set; the spec wants ascending. Re-sort here without mutating
        # the phase-1 contract (its existing test
        # `test_record_id_results_are_version_desc` is locked).
        if record_id is not None:
            rows.sort(key=lambda env: int(env.get("version", 0)))

        has_more = len(rows) > limit
        page = rows[:limit]

        next_since: int | None
        if has_more and record_id is not None:
            # Cursor is the largest version we just returned; the next
            # request will use `since=<this>` to get strictly newer
            # versions. (`list_` uses strict-greater filtering.)
            next_since = int(page[-1]["version"])
        else:
            # No `record_id` filter (phase-2 doesn't support cross-record
            # pagination) or no further pages: terminate the cursor.
            next_since = None

        return self._respond(200, {
            "bundles": page,
            "next_since": next_since,
        })

    def _do_bundles_by_cid(self, cid: str) -> None:
        """Handle `GET /bundles/by_cid/<cid>`.

        Returns the full envelope JSON, or 404 if no bundle with that
        CID is in the local store. Validates the CID format (64-char
        lowercase hex) before hitting SQLite — a malformed CID is a
        client bug worth distinguishing from a not-found.
        """
        from swf import bundles as _bundles

        if not self._CID_RE.match(cid or ""):
            return self._respond(400, {"error": "invalid_cid"})

        try:
            conn = self._open_bundles_conn()
        except sqlite3.OperationalError as exc:
            return self._respond(500, {"error": f"bundles store unavailable: {exc}"})
        try:
            _bundles.ensure_schema(conn)
            envelope = _bundles.get_by_cid(conn, cid)
        finally:
            conn.close()

        if envelope is None:
            return self._respond(404, {"error": "not_found", "cid": cid})
        return self._respond(200, envelope)

    # ── #93 phase 4: bundle SSE subscribe (§4.1 of SHAPE-ROTATOR-OS-SPEC.md) ──
    # Heartbeat cadence for `/bundles/subscribe`. The renderer-facing
    # `/events` route uses the same 15s default (see `event_bus.subscribe`
    # heartbeat), so we mirror it here — consistent timeouts let a single
    # operator-facing keep-alive setting (proxy idle timeout > 15s) cover
    # both surfaces.
    _BUNDLE_SSE_HEARTBEAT_SECONDS = 15.0

    def _do_bundles_subscribe(self, qs: dict) -> None:
        """Handle `GET /bundles/subscribe[?kind=<kind>]` (SSE).

        Spec §4.1:
            event: bundle
            id: <cid>
            data: {"magic": "swf-bundle-v1", ...}    # full envelope JSON

        Streams bundles in insertion order (resumable) and continues
        live as new bundles land via `event_bus`'s `bundle_added` topic.

        Replay-key choice (locked for v1):
            We use sqlite's implicit `rowid` as the monotonic insertion
            cursor. The cursor exposed to the wire is the bundle's
            `cid` (sha256-hex of the canonical bytes); we map cid →
            rowid internally on each subscribe. Pros: zero migration —
            sqlite gives us a stable, monotonically-increasing id for
            every row in a non-WITHOUT-ROWID table for free. Cons: not
            portable if/when we move to Postgres, but the substrate is
            sqlite-only today (`swf.indrex.db_path()`).

        `Last-Event-ID` semantics:
            - Header empty / absent  → no replay; emit only events that
              arrive *after* the subscription begins.
            - Header is a known cid → replay every bundle inserted
              after that cid (rowid > resolved), in rowid order, then
              stream live.
            - Header is an unknown cid (cache miss; bundle expired or
              never seen here) → fall through to live-only (no error,
              no replay). The client can re-bootstrap with `GET
              /bundles` if it needs the gap filled.

        Filter semantics:
            - `kind` is optional. If provided, validated against
              `bundles.BUNDLE_KINDS` and 400'd on unknown kind.
            - Without `kind`, all kinds stream.

        Disconnect handling:
            BrokenPipeError / ConnectionResetError on `wfile.flush()`
            unwinds quietly — no traceback. The QuietThreadingHTTPServer
            from #82 separately swallows loopback RSTs at the server
            level so `loopback_reset_count()` stays clean for legitimate
            subscribe disconnects.

        Heartbeat: SSE comments (`: keepalive\\n\\n`) every
        `_BUNDLE_SSE_HEARTBEAT_SECONDS` so proxies don't time out the
        connection during quiet windows.
        """
        from swf import bundles as _bundles

        kind = (qs.get("kind") or [None])[0]
        if kind is not None and kind not in _bundles.BUNDLE_KINDS:
            return self._respond(400, {
                "error": "invalid_kind",
                "valid": sorted(_bundles.BUNDLE_KINDS),
            })

        last_event_id = (self.headers.get("Last-Event-ID") or "").strip()

        # Resolve the resume cursor (cid → rowid). Unknown cid → no
        # replay; we still serve a live-only stream. Malformed cid →
        # same: cheap to be lenient here since the client may have a
        # stale cache that we can't repair anyway.
        resume_rowid: int | None = None
        try:
            conn = self._open_bundles_conn()
        except sqlite3.OperationalError as exc:
            return self._respond(500, {"error": f"bundles store unavailable: {exc}"})
        try:
            _bundles.ensure_schema(conn)
            if last_event_id and self._CID_RE.match(last_event_id):
                row = conn.execute(
                    "SELECT rowid FROM bundles WHERE cid=?", (last_event_id,),
                ).fetchone()
                if row is not None:
                    resume_rowid = int(row[0])
        finally:
            conn.close()

        # Open the live subscription BEFORE the replay query — there's
        # an inherent race window between "I queried up to rowid R" and
        # "I started listening for new events", and a bundle inserted
        # in that window would otherwise be lost. Subscribing first
        # means the worst case is a duplicate (same cid emitted twice);
        # SSE clients dedupe on `id:` so duplicates are harmless,
        # whereas drops are silent and unrecoverable.
        try:
            from swf import event_bus
        except Exception as exc:
            return self._respond(500, {"error": f"event bus unavailable: {exc}"})

        # Send SSE response headers.
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            # X-Accel-Buffering disables nginx response buffering so
            # subscribers see events at write time, not flush-block time.
            # Mirrored from `_serve_sse` in this same module.
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
        except Exception:
            return

        # We track replay-emitted CIDs so a `bundle_added` event that
        # races with the replay query doesn't emit twice on the same
        # SSE stream. (Same-stream dedupe; cross-stream dedupe is the
        # client's responsibility via `Last-Event-ID`.)
        emitted_cids: set[str] = set()

        def _write_event(cid: str, envelope: dict) -> bool:
            """Write a single SSE `event: bundle` block. Returns True
            on success, False on disconnect (caller should exit)."""
            data = json.dumps(envelope, separators=(",", ":"))
            chunk = (
                f"id: {cid}\n"
                f"event: bundle\n"
                f"data: {data}\n\n"
            ).encode()
            try:
                self.wfile.write(chunk)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return False
            return True

        # --- replay phase --------------------------------------------------
        # If the client provided a resume cursor that resolved to a
        # rowid, walk every bundle with rowid > that, in insertion
        # order. We optionally narrow by `kind`. We open a fresh
        # connection (the one above was closed) so the replay sees a
        # consistent snapshot at the moment of subscribe.
        replay_rows: list[tuple[int, str, str]] = []
        if resume_rowid is not None:
            try:
                conn = self._open_bundles_conn()
            except sqlite3.OperationalError as exc:
                logger.error(
                    "bundles subscribe replay open failed: %s", exc,
                )
                conn = None
            if conn is not None:
                try:
                    if kind is None:
                        cur = conn.execute(
                            "SELECT rowid, cid, envelope_json FROM bundles "
                            "WHERE rowid > ? ORDER BY rowid",
                            (resume_rowid,),
                        )
                    else:
                        cur = conn.execute(
                            "SELECT rowid, cid, envelope_json FROM bundles "
                            "WHERE rowid > ? AND kind = ? ORDER BY rowid",
                            (resume_rowid, kind),
                        )
                    replay_rows = list(cur.fetchall())
                except sqlite3.OperationalError:
                    replay_rows = []
                finally:
                    conn.close()

        for _rowid, cid, envelope_json in replay_rows:
            try:
                envelope = json.loads(envelope_json)
            except (TypeError, ValueError):
                continue
            if not _write_event(cid, envelope):
                return
            emitted_cids.add(cid)

        # --- live phase ----------------------------------------------------
        # `event_bus.subscribe()` is a generator that yields:
        #   - dict events (with `kind`, `payload`, `id`, ...)
        #   - None on heartbeat tick
        # We only forward `bundle_added` events; everything else
        # (page_added, peer_*) is filtered out. The bus replay
        # mechanism is bypassed (we already replayed from the bundles
        # table directly above; the events table is unrelated).
        try:
            for ev in event_bus.subscribe(
                replay_since_id=None,
                heartbeat_seconds=self._BUNDLE_SSE_HEARTBEAT_SECONDS,
            ):
                if ev is None:
                    # Heartbeat: SSE comment line keeps the connection
                    # alive across NAT/proxy idle timeouts.
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    continue

                if ev.get("kind") != "bundle_added":
                    continue
                payload = ev.get("payload") or {}
                cid = payload.get("cid")
                if not cid or not isinstance(cid, str):
                    continue
                if cid in emitted_cids:
                    # Already shipped during the replay phase — the
                    # event_bus emit raced our replay query. Skip.
                    continue
                ev_kind = payload.get("kind")
                if kind is not None and ev_kind != kind:
                    continue

                # Fetch the full envelope from the store. The event
                # payload only carries the index summary by design (see
                # phase-3's `_do_bundles_post`); the SSE wire format
                # ships the full envelope per spec §4.1.
                try:
                    conn = self._open_bundles_conn()
                except sqlite3.OperationalError:
                    continue
                try:
                    envelope = _bundles.get_by_cid(conn, cid)
                finally:
                    conn.close()
                if envelope is None:
                    # Bundle vanished between emit and fetch (vacuum,
                    # manual delete, etc). Skip — we have no envelope
                    # to ship.
                    continue
                if not _write_event(cid, envelope):
                    return
                emitted_cids.add(cid)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:  # noqa: BLE001  (defensive top-level)
            logger.error("/bundles/subscribe error: %s", e)
            return

    # ── #108 ask 2: GET /alchemists ─────────────────────────────────
    # Discoverable roster endpoint. Returns the active alchemist set
    # so the alchemist Electron app, the cohort viz, and operator
    # tooling can confirm the in-memory roster matches expectations
    # without parsing `.alchemists.yml` from the filesystem.
    #
    # Privacy: pubkeys are part of the trust set (consumers verifying
    # signatures need them) and are intentionally public. The file
    # PATH, however, is filesystem-local information — leak-prevention
    # principle says don't expose it on a non-loopback bind. So
    # `loaded_from` is omitted (null) when bind != 127.0.0.1; loopback
    # ops still see the path, which is operationally useful.
    def _do_alchemists_get(self) -> None:
        """Handle `GET /alchemists` — return the active alchemist roster.

        Response shape (#108 ask 2):
            {
              "alchemists": [
                {"id": "alchemist-01", "pubkey": "ed25519:..."}, ...
              ],
              "loaded_from": "<absolute path or null>",
              "loaded_at": "<ISO 8601 UTC timestamp>"
            }

        - `alchemists[]` is sorted by `id` for deterministic output
          (the underlying dict's insertion order matches YAML order,
          but operators expect a stable response on subsequent calls
          regardless of YAML rewrite order).
        - `loaded_from` is the absolute path the loader picked, or
          `null` when the file was missing OR when this peer is
          bound on a non-loopback interface (filesystem-local info
          shouldn't leak over LAN — see route docstring above).
        - `loaded_at` is the ISO-8601 UTC timestamp the YAML was last
          parsed (#109's hot-reload path updates this on every
          re-parse, so cohort viz can detect roster rotations).
        """
        # Pull from the shared cache — same source the verifier uses,
        # so what GET /alchemists reports is exactly what POST /bundles
        # checks against. Hot-reload happens transparently inside
        # `load_alchemists_cached()` (#109).
        al = _load_alchemists_cached()

        alchemists_out = sorted(
            (
                {"id": ident, "pubkey": pubkey}
                for pubkey, ident in al.members.items()
            ),
            key=lambda e: (e["id"], e["pubkey"]),
        )

        # Loopback-only path leak guard. `server_address[0]` is the
        # bind IP we're listening on (set by `serve_in_thread` /
        # `serve()`). Anything other than the loopback range omits
        # the path so a LAN peer can't infer the operator's home dir.
        bind_ip = (self.server.server_address[0] or "")
        loopback = bind_ip.startswith("127.") or bind_ip in (
            "localhost", "::1",
        )
        loaded_from = (
            str(al.path) if (al.path is not None and loopback) else None
        )

        return self._respond(200, {
            "alchemists": alchemists_out,
            "loaded_from": loaded_from,
            "loaded_at": al.loaded_at or None,
        })

    # ── #93 phase 3: bundle write API (§4.2 of SHAPE-ROTATOR-OS-SPEC.md) ──
    # `MAX_BUNDLE_BYTES` caps incoming POST bodies. Spec doesn't pin
    # a number; 4 MiB is generous for the use case (depth bundle =
    # encrypted markdown file; surface bundle = small JSON; transcript
    # batch = ~30 segments = small). Keeps the handler bounded against
    # a slow-loris adversary trying to wedge a connection with a huge
    # `Content-Length`.
    _MAX_BUNDLE_BYTES = 4 * 1024 * 1024

    # Map verifier reasons to HTTP status. Spec §4.2 only enumerates
    # 400 / 403 / 409 — there is no 401 in the bundle write surface,
    # so a signature failure folds into 403 alongside the alchemist
    # whitelist failure (both are "your key is not authorized to write
    # this envelope" from the server's perspective).
    _VERIFY_REASON_TO_STATUS: dict[str, int] = {
        "shape_invalid": 400,
        "kind_unknown": 400,
        "pubkey_malformed": 400,
        "encryption_malformed": 400,
        "author_not_alchemist": 403,
        "signature_invalid": 403,
        "version_not_monotonic": 409,
        # NOTE: the verifier still surfaces
        # `encryption_recipient_not_in_reservoir` when callers opt-in by
        # passing `reservoir=`, but the POST /bundles handler does NOT
        # opt in (per #112: the relay shouldn't pre-screen recipient
        # strings — the alchemist signature gate is the trust boundary,
        # and reservoir mismatches just produce ciphertext nobody can
        # decrypt, which is identical in effect to honest delivery of a
        # garbage recipient). So this map intentionally omits the
        # reservoir-recipient reason — POST will never surface it.
    }

    # ── #108 ask 3: stage discriminator on POST /bundles 4xx ────────
    # Map verify-reasons (and the non-verify error paths) to a coarse
    # `stage` tag so clients can distinguish failure classes
    # (envelope shape vs signature vs version vs recipients) without
    # string-matching on the `error` field. Backwards-compatible: the
    # original `error` + `cid` fields stay; `stage` is additive.
    #
    # Stages (per #108):
    #   - "shape"             envelope structure / kind / pubkey /
    #                         encryption block didn't pass shape check
    #   - "signature"         author not in alchemist roster, OR the
    #                         Ed25519 signature didn't verify
    #   - "version"           version not strictly greater than the
    #                         highest-seen for this record_id
    #   - "recipients"        a recipient string isn't in the local
    #                         reservoir (verifier still emits this when
    #                         called with `reservoir=`; the POST path
    #                         doesn't pass one per #112, but the map
    #                         covers the puller's pull path)
    #   - "json"              body wasn't valid JSON (or wasn't a
    #                         JSON object)
    #   - "payload_too_large" Content-Length exceeded MAX_BUNDLE_BYTES
    #   - "content_type"      Content-Type wasn't application/json
    _VERIFY_REASON_TO_STAGE: dict[str, str] = {
        "shape_invalid": "shape",
        "kind_unknown": "shape",
        "pubkey_malformed": "shape",
        "encryption_malformed": "shape",
        "author_not_alchemist": "signature",
        "signature_invalid": "signature",
        "version_not_monotonic": "version",
        "encryption_recipient_not_in_reservoir": "recipients",
    }

    def _do_bundles_post(self) -> None:
        """Handle `POST /bundles` — verify and persist a signed envelope.

        Spec §4.2:
            POST /bundles HTTP/1.1
            Content-Type: application/json

            { "magic": "swf-bundle-v1", "kind": "cohort.depth", ... }

            201 Created  with {"cid": "<cid>"} on success
            400          if envelope malformed
            403          if author.pubkey not in alchemist list
            409          if version is not strictly greater than known

        This route runs the phase-1 verifier (`swf.bundles.verify_bundle`)
        which covers shape -> alchemist whitelist -> signature ->
        version monotonicity. swf-node does NOT validate payload
        structure (per spec, that is the application's job).

        Peer-to-peer propagation is intentionally out of scope here.
        The spec mentions "propagating to peers" but the issue's
        phasing places the two-peer LAN test at phase 6. Phase 3 only
        persists locally and emits a `bundle_added` event so phase 4's
        SSE subscribe has a clean hook.
        """
        # 1. Content-Type gate. Case-insensitive on type, ignore params
        #    (charset, boundary). Reject non-JSON early so a misrouted
        #    multipart upload doesn't get parsed as JSON.
        ctype_raw = self.headers.get("Content-Type") or ""
        ctype = ctype_raw.split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            return self._respond(415, {
                "error": "unsupported_media_type",
                "expected": "application/json",
                "stage": "content_type",
            })

        # 2. Body size gate. We honor the declared Content-Length and
        #    refuse to read more than _MAX_BUNDLE_BYTES. A missing /
        #    non-numeric Content-Length is treated as 0 (rejected as
        #    malformed JSON below).
        try:
            n = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            n = 0
        if n > self._MAX_BUNDLE_BYTES:
            # Drain the body in chunks so the kernel doesn't RST the
            # client mid-write when we close. We bound the drain to
            # `n` (declared size) with a per-chunk timeout, so a slow-
            # loris adversary can't keep us reading forever — the
            # outer socket timeout fires after 15s. Memory stays
            # bounded at the chunk size regardless of `n`.
            with contextlib.suppress(OSError):
                self.connection.settimeout(15)
            remaining = n
            chunk = 64 * 1024
            # Client gave up — fine; we still emit the response
            # below in case the response buffer made it out.
            try:
                while remaining > 0:
                    got = self.rfile.read(min(remaining, chunk))
                    if not got:
                        break
                    remaining -= len(got)
            except Exception:
                pass
            self.close_connection = True
            return self._respond(413, {
                "error": "payload_too_large",
                "max_bytes": self._MAX_BUNDLE_BYTES,
                "stage": "payload_too_large",
            })

        # 3. Read + parse. JSON errors are 400 with a tag the wall /
        #    research-agent can match on programmatically.
        with contextlib.suppress(OSError):
            self.connection.settimeout(15)
        try:
            raw = self.rfile.read(n) if n > 0 else b""
        except Exception as exc:
            return self._respond(400, {
                "error": "malformed_json",
                "detail": f"read failed: {exc}",
                "stage": "json",
            })
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._respond(400, {
                "error": "malformed_json",
                "stage": "json",
            })
        if not isinstance(envelope, dict):
            # `validate_shape` would catch this too, but we'd rather
            # not feed a bare list / string to the verifier and let
            # the shape stage tag it generic-`shape_invalid`.
            return self._respond(400, {
                "error": "malformed_json",
                "stage": "json",
            })

        # 4. Verify (shape + encryption shape + alchemist whitelist +
        #    signature + monotonicity). Alchemist list is loaded once
        #    and cached; tests reset via
        #    `_reset_alchemists_cache_for_tests`.
        #
        #    Per #112, the POST handler intentionally does NOT pass a
        #    `reservoir=` to `verify_bundle`. swf-node is a relay over
        #    opaque ciphertext, so screening recipient strings adds no
        #    security boundary the alchemist signature gate doesn't
        #    already provide — if you trust a publisher to sign the
        #    envelope, you trust them to pick valid recipients, and if
        #    they don't, the bundle just becomes garbage to whoever
        #    pulls it (identical in effect to honest delivery of an
        #    unknown recipient). The reservoir cache helpers remain
        #    available for the hivemind sink's encryption path (which
        #    uses reservoir pubkeys as recipients, not for verification).
        from swf import bundles as _bundles

        alchemists = _load_alchemists_cached()
        try:
            conn = self._open_bundles_conn()
        except sqlite3.OperationalError as exc:
            return self._respond(500, {"error": f"bundles store unavailable: {exc}"})
        try:
            _bundles.ensure_schema(conn)

            # Idempotency carve-out: if the exact CID is already in
            # the store, this is a re-POST of a previously-accepted
            # envelope. Skip the verifier (which would otherwise
            # reject the re-POST as `version_not_monotonic` because
            # the prior version equals the incoming version) and
            # return 201 with the same cid. Byte-identical canonical
            # form guarantees the envelope was already verified once.
            try:
                early_cid = _bundles.cid_for(envelope)
            except Exception:
                early_cid = None
            if early_cid and _bundles.get_by_cid(conn, early_cid) is not None:
                return self._respond(201, {"cid": early_cid})

            result = _bundles.verify_bundle(
                envelope,
                alchemists=alchemists,
                conn=conn,
            )
            if not result.ok:
                status = self._VERIFY_REASON_TO_STATUS.get(
                    result.reason, 400,
                )
                # #108 ask 3: include a `stage` discriminator so the
                # alchemist app can surface accurate UI ("your key
                # isn't in the active roster" vs "envelope was
                # malformed") without string-matching on `error`.
                # Falls back to "shape" for any unknown verifier
                # reason — the verifier's shape stage is the
                # default-deny gate, so a future-added reason landing
                # here without a stage entry is most likely a shape
                # case anyway.
                stage = self._VERIFY_REASON_TO_STAGE.get(
                    result.reason, "shape",
                )
                return self._respond(status, {
                    "error": result.reason,
                    "cid": result.cid,
                    "stage": stage,
                })

            # 5. Persist. `insert` is idempotent on `cid`; a re-POST
            #    of the same envelope returns `was_new=False` but the
            #    post-condition (the bundle is in the store) is
            #    satisfied so we still return 201. Returning 200 would
            #    just teach clients that idempotency is partial.
            cid, was_new = _bundles.insert(envelope, conn=conn)
            conn.commit()
        finally:
            conn.close()

        # 6. Friendly handoff to phase 4: emit a `bundle_added` event
        #    so the SSE subscribe hook (phase 4) can stream new
        #    bundles to subscribers without polling the store. The
        #    payload is the indexable summary (NOT the full envelope —
        #    SSE clients fetch the body via GET /bundles/by_cid/<cid>
        #    if they need the payload bytes). Best-effort; a bus
        #    failure is logged but doesn't fail the POST since the
        #    bundle is already durably stored.
        try:
            from swf import event_bus
            author = envelope.get("author") or {}
            event_bus.emit("bundle_added", {
                "cid": cid,
                "kind": envelope.get("kind"),
                "record_id": envelope.get("record_id"),
                "version": envelope.get("version"),
                "author_pubkey": author.get("pubkey") if isinstance(author, dict) else None,
                "signed_at": author.get("signed_at") if isinstance(author, dict) else None,
            })
        except Exception as exc:
            logger.error("bundle_added emit failed: %s", exc)

        # 7. #93 phase 6: peer-to-peer propagation. When a NEW bundle
        #    landed (`was_new=True`), fan it out to every known LAN
        #    peer's `/bundles` endpoint on a daemon thread so the
        #    HTTP response isn't blocked on peer round-trips. The
        #    `was_new=False` re-POST path skips propagation: the
        #    bundle is already known, so neighbors that aren't already
        #    aware will receive it via the original first-receipt
        #    chain (loop prevention via the same `was_new` short-
        #    circuit on the receiving side).
        #
        #    `exclude_pubkeys` carries the bundle's own author so we
        #    don't bounce it back to origin (the receiving side would
        #    short-circuit on `was_new=False` anyway, but skipping
        #    the round-trip saves one POST per neighbor of the author).
        if was_new:
            try:
                from swf.bundles import propagate_bundle_async
                from swf.indrex import db_path as _idx_db
                author = envelope.get("author") or {}
                author_pubkey = (
                    author.get("pubkey") if isinstance(author, dict) else None
                )
                exclude: set[str] = set()
                if isinstance(author_pubkey, str) and author_pubkey:
                    exclude.add(author_pubkey)
                propagate_bundle_async(
                    envelope,
                    db_path=_idx_db(),
                    exclude_pubkeys=exclude,
                )
            except Exception as exc:
                # Daemon-thread spawn should never raise, but if it
                # does we MUST NOT fail the HTTP response — the
                # bundle is already durably stored.
                logger.error("bundle propagation spawn failed: %s", exc)

        return self._respond(201, {"cid": cid})

    # ── Phase 2 sync handlers (docs/SYNC.md §4 + §7.4) ────────────────────
    # All three GET handlers + the POST handler share a single connection
    # pattern: open the indrex DB, `ensure_schema(conn)` from the sync
    # substrate, do the work, close. The handlers are stateless — the
    # peer-server thread pool gives us a fresh request per call.

    #: Spec §3.5 / §9.3 — 64 KiB envelope cap.
    _SYNC_MAX_ENVELOPE_BYTES = 64 * 1024
    #: Default + max page size for /sync/record/ (spec §4.2).
    _SYNC_RECORD_DEFAULT_LIMIT = 100
    _SYNC_RECORD_MAX_LIMIT = 1000
    #: Default + max for /sync/record/<r>/history (spec §7.2).
    _SYNC_HISTORY_DEFAULT_LIMIT = 50
    _SYNC_HISTORY_MAX_LIMIT = 1000

    def _open_sync_conn(self) -> sqlite3.Connection:
        """Open the indrex DB for sync reads / writes.

        Same shape as `_open_bundles_conn` — a writable connection
        because `ensure_schema` may need to CREATE TABLE on a node
        that's never had a sync envelope written. WAL means readers
        don't block; the sync apply path commits on its own.
        """
        from swf.indrex import db_path as _idx_db
        conn = sqlite3.connect(str(_idx_db()), timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _sync_record_id_valid(self, record_id: str) -> bool:
        """`record_id` regex per spec §3.1."""
        return bool(record_id) and bool(
            re.match(r"^[a-z0-9._-]{1,128}$", record_id),
        )

    def _do_sync_manifest(self) -> None:
        """`GET /sync/manifest` — return this peer's view of every record.

        Spec §4.1. The response wraps `build_manifest(conn)`'s output
        with `schema`, `node_pubkey`, and `generated_at_ms` per the
        spec's example body. Empty `records` is a normal response —
        a freshly-booted node has nothing to serve.

        Cohort-keys not configured is NOT fatal here: the manifest
        endpoint advertises what we have locally and is read-only. A
        peer with no cohort serves an empty manifest. The spec's
        "503 no_cohort_keys" applies to *incoming* sync attempts that
        would otherwise apply envelopes (the POST path); GET is fine.
        """
        from swf.identity import get_or_create_identity
        from swf.sync import build_manifest, ensure_schema as _sync_schema

        try:
            conn = self._open_sync_conn()
        except sqlite3.OperationalError as exc:
            return self._respond(500, {"error": "sync_store_unavailable",
                                       "detail": str(exc)})
        try:
            _sync_schema(conn)
            manifest = build_manifest(conn)
        finally:
            conn.close()

        try:
            node_pubkey_b64 = get_or_create_identity().pub_b64
        except Exception:
            node_pubkey_b64 = ""

        import time as _time
        return self._respond(200, {
            "schema": "swf.sync.manifest.v1",
            "node_pubkey": node_pubkey_b64,
            "generated_at_ms": int(_time.time() * 1000),
            "records": manifest["records"],
            "manifest_hash": manifest["manifest_hash"],
        })

    def _do_sync_record(self, record_id: str, qs: dict) -> None:
        """`GET /sync/record/<record_id>?since=<ts>&limit=<n>` — spec §4.2.

        Returns up to `limit` envelopes with `wall_ts_ms > since`,
        newest-first by `(wall_ts_ms DESC, content_hash DESC)`.
        404 when the record is unknown locally.
        """
        from swf.sync import (
            ensure_schema as _sync_schema,
            get_record_envelopes,
        )

        if not self._sync_record_id_valid(record_id):
            return self._respond(400, {"error": "invalid_record_id"})

        # Parse `since` (default 0; non-negative int per spec).
        since_raw = (qs.get("since") or ["0"])[0]
        try:
            since_ms = int(since_raw)
        except ValueError:
            return self._respond(400, {"error": "invalid_since"})
        if since_ms < 0:
            return self._respond(400, {"error": "invalid_since"})

        # Parse `limit` (default 100, max 1000).
        limit_raw = (qs.get("limit") or [str(self._SYNC_RECORD_DEFAULT_LIMIT)])[0]
        try:
            limit = int(limit_raw)
        except ValueError:
            return self._respond(400, {"error": "invalid_limit"})
        if limit < 1 or limit > self._SYNC_RECORD_MAX_LIMIT:
            return self._respond(400, {"error": "invalid_limit"})

        try:
            conn = self._open_sync_conn()
        except sqlite3.OperationalError as exc:
            return self._respond(500, {"error": "sync_store_unavailable",
                                       "detail": str(exc)})
        try:
            _sync_schema(conn)
            # over-fetch by 1 so we can answer `more`
            envelopes = get_record_envelopes(
                conn, record_id, since_ms=since_ms, limit=limit + 1,
            )
            row = conn.execute(
                "SELECT COUNT(*) FROM sync_records WHERE record_id=?",
                (record_id,),
            ).fetchone()
            exists = bool(row and row[0])
        finally:
            conn.close()

        if not exists:
            return self._respond(404, {
                "error": "not_found", "record_id": record_id,
            })

        more = len(envelopes) > limit
        envelopes = envelopes[:limit]
        return self._respond(200, {
            "schema": "swf.sync.record.v1",
            "record_id": record_id,
            "envelopes": envelopes,
            "more": more,
            "warnings": [],
        })

    def _do_sync_record_history(self, record_id: str, qs: dict) -> None:
        """`GET /sync/record/<record_id>/history` — spec §7.2."""
        from swf.sync import (
            ensure_schema as _sync_schema,
            get_record_history,
        )

        if not self._sync_record_id_valid(record_id):
            return self._respond(400, {"error": "invalid_record_id"})

        limit_raw = (qs.get("limit") or [str(self._SYNC_HISTORY_DEFAULT_LIMIT)])[0]
        try:
            limit = int(limit_raw)
        except ValueError:
            return self._respond(400, {"error": "invalid_limit"})
        if limit < 1 or limit > self._SYNC_HISTORY_MAX_LIMIT:
            return self._respond(400, {"error": "invalid_limit"})

        try:
            conn = self._open_sync_conn()
        except sqlite3.OperationalError as exc:
            return self._respond(500, {"error": "sync_store_unavailable",
                                       "detail": str(exc)})
        try:
            _sync_schema(conn)
            envelopes = get_record_history(conn, record_id, limit=limit + 1)
        finally:
            conn.close()

        if not envelopes:
            return self._respond(404, {
                "error": "not_found", "record_id": record_id,
            })
        more = len(envelopes) > limit
        envelopes = envelopes[:limit]
        return self._respond(200, {
            "schema": "swf.sync.record_history.v1",
            "record_id": record_id,
            "envelopes": envelopes,
            "more": more,
        })

    # Apply-result reason → HTTP status. Spec §4.4 + §9.6.
    _SYNC_REASON_TO_STATUS = {
        "shape_invalid": 400,
        "kind_unknown": 400,
        "envelope_too_large": 413,
        "content_too_deep": 400,
        "content_hash_mismatch": 400,
        "author_not_in_cohort": 403,
        "record_author_mismatch": 403,
        "signature_invalid": 403,
        "clock_too_far_ahead": 400,
        "record_id_owned_by_other_author": 409,
    }

    def _do_sync_local_record_post(self) -> None:
        """`POST /sync/local_record` — spec §7.4 / §9.5.

        Agent-bearer-gated. The Electron app submits a record
        edit; the server signs it with the local identity and
        applies it. Returns the full signed envelope so the
        Electron side can update its local view.

        Body shape (input):
            {"record_id": "amiller",
             "record_type": "person",
             "content": {...},
             "prev_hash": "sha256:<hex>" | null}

        The server:
          1. Validates the agent-bearer token (loopback bypass).
          2. Loads cohort-keys; if `record_id` is owned by some
             OTHER pubkey, returns 403 `not_authorized_author`.
          3. Computes wall_ts_ms = now, author_pubkey = identity.
          4. Builds the envelope, signs, hashes content, runs
             `apply_envelope`.
          5. Returns the envelope at 201 (new) or 200 (replay).
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        from swf.identity import get_or_create_identity
        from swf.sync import (
            SYNC_MAGIC,
            apply_envelope,
            canonicalize as _sync_canonicalize,
            content_hash as _sync_content_hash,
            ensure_schema as _sync_schema,
            load_cohort_keys_cached,
            sign_envelope as _sync_sign,
        )

        # 1. Agent-bearer token. Uses the same `_check_token` predicate
        # as the existing search routes (loopback bypass, env-set
        # bearer required otherwise) per spec §7.4.
        if not self._check_token():
            return self._respond(401, {"error": "unauthorized"})

        # 2. Content-Type + size.
        ctype_raw = self.headers.get("Content-Type") or ""
        ctype = ctype_raw.split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            return self._respond(415, {
                "error": "unsupported_media_type",
                "expected": "application/json",
            })

        try:
            n = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            n = 0
        # Envelope cap applies post-canonicalization (we'll re-check
        # after signing); but the input body MUST be smaller than the
        # cap or it can't possibly fit. Pre-check before reading.
        if n > self._SYNC_MAX_ENVELOPE_BYTES:
            return self._respond(413, {
                "error": "envelope_too_large",
                "max_bytes": self._SYNC_MAX_ENVELOPE_BYTES,
            })

        body = self._read_json_body(max_bytes=self._SYNC_MAX_ENVELOPE_BYTES)
        if not isinstance(body, dict):
            return self._respond(400, {"error": "malformed_json"})

        record_id = body.get("record_id")
        record_type = body.get("record_type", "person")
        content = body.get("content")
        prev_hash = body.get("prev_hash")
        if not isinstance(record_id, str) or not self._sync_record_id_valid(record_id):
            return self._respond(400, {"error": "invalid_record_id"})
        if not isinstance(record_type, str):
            return self._respond(400, {"error": "invalid_record_type"})
        if not isinstance(content, (dict, list)):
            return self._respond(400, {"error": "invalid_content"})
        if prev_hash is not None and not isinstance(prev_hash, str):
            return self._respond(400, {"error": "invalid_prev_hash"})

        # 3. Local identity → author_pubkey.
        try:
            ident = get_or_create_identity()
        except Exception as exc:
            return self._respond(500, {"error": "identity_unavailable",
                                       "detail": str(exc)})
        # Derive hex from the in-memory key — identity's public form is
        # base64url; sync envelopes use ed25519:<hex>. Round-trip via
        # cryptography's raw export.
        pub_raw = ident.pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        author_pubkey = "ed25519:" + pub_raw.hex()

        # 4. Cohort-keys gate. Missing cohort → 503 `no_cohort_keys`
        # (spec §8.2). Mismatched author → 403 `not_authorized_author`
        # (the local pubkey doesn't match cohort-keys' expected author
        # for this `record_id`).
        cohort_keys = load_cohort_keys_cached()
        if not cohort_keys:
            return self._respond(503, {"error": "no_cohort_keys"})
        expected = cohort_keys.pubkey_for_handle(record_id)
        if expected is None:
            # `record_id` isn't a known cohort handle. Accept iff this
            # pubkey is at least cohort-known (the apply-side pin will
            # gate further writes to the same record_id by other authors).
            if not cohort_keys.is_known_pubkey(author_pubkey):
                return self._respond(403, {"error": "author_not_in_cohort"})
        elif expected != author_pubkey:
            return self._respond(403, {
                "error": "not_authorized_author",
                "expected_pubkey": expected,
            })

        # 5. Build the envelope.
        import time as _time
        envelope: dict = {
            "magic": SYNC_MAGIC,
            "kind": record_type,
            "record_id": record_id,
            "author_pubkey": author_pubkey,
            "wall_ts_ms": int(_time.time() * 1000),
            "prev_hash": prev_hash,
            "content": content,
            "content_hash": _sync_content_hash(content),
        }
        envelope["signature"] = _sync_sign(envelope, priv=ident.priv)

        # 6. Final envelope size check (the cap is on the canonical
        # form, which is what apply_envelope uses anyway — but a
        # 200/201 on a >64 KiB envelope after signing would be a
        # contract bug).
        if len(_sync_canonicalize(envelope, drop_signature=True)) > self._SYNC_MAX_ENVELOPE_BYTES:
            return self._respond(413, {
                "error": "envelope_too_large",
                "max_bytes": self._SYNC_MAX_ENVELOPE_BYTES,
            })

        # 7. Apply.
        try:
            conn = self._open_sync_conn()
        except sqlite3.OperationalError as exc:
            return self._respond(500, {"error": "sync_store_unavailable",
                                       "detail": str(exc)})
        try:
            _sync_schema(conn)
            result = apply_envelope(conn, envelope, cohort_keys=cohort_keys)
        finally:
            conn.close()

        if not result.ok:
            status = self._SYNC_REASON_TO_STATUS.get(result.reason, 400)
            return self._respond(status, {
                "error": result.reason,
                "record_id": record_id,
            })

        status = 201 if result.was_new else 200
        return self._respond(status, {
            "envelope": envelope,
            "was_new": result.was_new,
            "became_latest": result.became_latest,
            "fork_detected": result.fork_detected,
        })

    def do_POST(self):  # noqa: N802 (stdlib API)
        from urllib.parse import urlparse as _urlparse
        path = _urlparse(self.path).path

        # /contribute and /visit were the legacy push-contribution
        # routes (community.db model). Removed in #43 PR C; the wall
        # now reads everything from indrex.db via /graph + /events.
        if path in ("/contribute", "/visit"):
            return self._respond(410, {"error": f"{path} removed in #43 PR C"})

        # ── #93 phase 3: bundle write API (§4.2 of SHAPE-ROTATOR-OS-SPEC.md) ──
        # POST a fully-signed envelope; we run the phase-1 verifier
        # locally and persist on success. Peer-to-peer fan-out is OUT
        # OF SCOPE for phase 3 — the spec mentions propagation but the
        # issue's own phasing places the two-peer LAN test at phase 6.
        # The next phase (phase 4) hooks SSE onto the `bundle_added`
        # event we emit at the end of `_do_bundles_post`. TODO(phase-6):
        # propagate accepted bundles to peers from this dispatch site.
        if path == "/bundles":
            return self._do_bundles_post()

        # ── Phase 2 sync: local-write route (docs/SYNC.md §7.4 / §9.5) ──
        # Agent-bearer-gated. Body shape:
        #     {"record_id": "...", "record_type": "person",
        #      "content": {...}, "prev_hash": "sha256:<hex>"|null}
        # The server computes `wall_ts_ms` + `author_pubkey`, signs
        # with the local identity, runs the apply pipeline, and
        # returns the full envelope on success.
        if path == "/sync/local_record":
            return self._do_sync_local_record_post()

        # ── #93 phase 5: hivemind sink (§4.3 of SHAPE-ROTATOR-OS-SPEC.md) ──
        # Voxterm clients post UNSIGNED transcript batches here; the
        # sink (in `swf.hivemind`) validates schema, wraps in a
        # `kind: transcript.batch` envelope, signs with the convent
        # box's alchemist Ed25519 key, runs the phase-1 verifier, and
        # persists via `bundles.insert`. Registered unconditionally —
        # the route works on any swf-node (the convent-box-only-ness
        # is enforced by `--hivemind-sink` gating mDNS advertisement
        # and the operator's signing-key configuration); a node
        # without a signing key returns 500 + `sink_misconfigured`,
        # which is the correct semantics: the sink isn't ready.
        if path == "/hivemind/transcripts":
            from swf.hivemind.route import _do_hivemind_transcripts
            return _do_hivemind_transcripts(self)

        # ── SPEC v0.3 search router (Phases 1-3) ──────────────────
        # All three routes type-validate every field strictly. Red-team
        # pass 2 found that `.strip()` on a non-string crashed the
        # request handler; we now return 400 with a structured error
        # instead of leaking traceback messages or dropping the socket.
        if path == "/web_search":
            if self._content_length_over(self._MAX_SEARCH_BODY_BYTES):
                return self._respond(413, {"error": "request body too large"})
            body = self._read_json_body(max_bytes=self._MAX_SEARCH_BODY_BYTES) or {}
            q_raw = body.get("q")
            if not isinstance(q_raw, str):
                return self._respond(400, {"error": "q must be a string"})
            q = q_raw.strip()
            if not q:
                return self._respond(400, {"error": "missing q"})
            if len(q.encode("utf-8")) > 4096:
                return self._respond(400, {"error": "q too long (max 4 KiB)"})
            policy_raw = body.get("policy")
            if policy_raw is not None and not isinstance(policy_raw, str):
                return self._respond(400, {"error": "policy must be a string"})
            policy_name = (policy_raw or "default").strip() or "default"
            top_k_raw = body.get("top_k")
            if top_k_raw is None:
                top_k = 10
            elif isinstance(top_k_raw, bool) or not isinstance(top_k_raw, int):
                return self._respond(400, {"error": "top_k must be an integer"})
            else:
                top_k = top_k_raw
            top_k = max(1, min(50, top_k))
            caller_raw = body.get("caller")
            if caller_raw is not None and not isinstance(caller_raw, str):
                return self._respond(400, {"error": "caller must be a string or null"})
            request_id_raw = body.get("request_id")
            if request_id_raw is not None and not isinstance(request_id_raw, str):
                return self._respond(400, {"error": "request_id must be a string or null"})
            confirm_raw = body.get("confirm_public_egress", False)
            if not isinstance(confirm_raw, bool):
                return self._respond(400, {
                    "error": "confirm_public_egress must be true or false",
                })
            # Time the full handler so the metrics collector can
            # surface p50/p95 latencies and total/error counters in the
            # Metrics tab. Failure path also records — that's how the
            # error-rate panel learns there are bad runs to investigate.
            import time as _time
            _t0 = _time.monotonic()
            _ok = True
            try:
                from swf.search import web_search as _web_search
                resp = _web_search(
                    q,
                    policy_name=policy_name,
                    caller=caller_raw,
                    requested_top_k=top_k,
                    request_id=request_id_raw,
                    confirm_public_egress=confirm_raw,
                )
            except Exception as e:
                _ok = False
                # Don't leak traceback details over the wire.
                logger.error("web_search internal error: %s", e)
                try:
                    from swf.community_full import metrics as _cmet
                    _cmet.record_search((_time.monotonic() - _t0) * 1000.0, ok=False)
                except Exception:
                    pass
                return self._respond(500, {"error": "web_search failed"})
            try:
                from swf.community_full import metrics as _cmet
                _cmet.record_search((_time.monotonic() - _t0) * 1000.0, ok=_ok)
            except Exception:
                pass
            return self._respond(200, resp.to_json())

        # ── SPEC v0.3 §21 friend responder (Phase 3) ─────────────
        if path == "/friend_search":
            if self._content_length_over(self._MAX_SEARCH_BODY_BYTES):
                return self._respond(413, {"error": "request body too large"})
            body = self._read_json_body(max_bytes=self._MAX_SEARCH_BODY_BYTES) or {}
            q_raw = body.get("q")
            if not isinstance(q_raw, str):
                return self._respond(400, {"error": "q must be a string"})
            top_k_raw = body.get("top_k")
            if top_k_raw is not None and (isinstance(top_k_raw, bool)
                                          or not isinstance(top_k_raw, int)):
                return self._respond(400, {"error": "top_k must be an integer"})
            qid_raw = body.get("qid")
            if qid_raw is not None and not isinstance(qid_raw, str):
                return self._respond(400, {"error": "qid must be a string"})
            # §21.1 max_rounds_per_minute is keyed by source IP (the
            # placeholder LAN-trust path; ticket-nullifier keying lands
            # with TODO-2 / Phase 4 DCNET). client_address is a (host,
            # port) tuple — unwrap defensively in case a custom
            # transport wraps it differently.
            #
            # Pass-4 finding #5: a dual-stack listener delivers an
            # IPv4 client as `::ffff:1.2.3.4` over IPv6. Without
            # normalization the same client gets DOUBLE the bucket
            # under v4 and v4-mapped-v6 forms. Collapse to canonical
            # IPv4 when applicable.
            try:
                raw_ip = self.client_address[0]
                import ipaddress as _ipa
                try:
                    parsed = _ipa.ip_address(raw_ip)
                    if isinstance(parsed, _ipa.IPv6Address) and parsed.ipv4_mapped:
                        source_ip: str | None = str(parsed.ipv4_mapped)
                    else:
                        source_ip = str(parsed)
                except ValueError:
                    source_ip = raw_ip  # opaque transport — pass through
            except Exception:
                source_ip = None
            try:
                from swf.search.friend_responder import respond as friend_respond
                bundle = friend_respond({"q": q_raw,
                                         "top_k": top_k_raw,
                                         "qid": qid_raw},
                                        source_ip=source_ip)
            except Exception as e:
                logger.error("friend_search internal error: %s", e)
                return self._respond(500, {"error": "friend_search failed"})
            return self._respond(200, bundle)

        # ── SPEC v0.3 §29.10 local reputation (Phase 5) ──────────
        # Wall calls this when the user clicks / saves / marks-useful.
        # Body: {"provider_pubkey": "...", "event": "open"|"save"|...,
        #        "notes": "...optional"}. Local-only; never networked.
        # When bound on a non-loopback interface, requires the same
        # admin token as /admin/peers — a LAN peer should not be able
        # to spam-bump arbitrary providers' reputation. Loopback bind
        # stays auth-free for the wall.
        if path == "/search_feedback":
            # Load-test agent caught: previous code called a helper
            # that didn't exist on this class. The right helper is
            # `_check_token` — which auto-allows loopback callers and
            # requires `Authorization: Bearer <SWF_AGENT_TOKEN>` when
            # the server is bound on a non-loopback interface.
            if not self._check_token():
                return self._respond(401, {
                    "error": "bearer token required when bound non-loopback",
                })
            if self._content_length_over(self._MAX_SEARCH_BODY_BYTES):
                return self._respond(413, {"error": "request body too large"})
            body = self._read_json_body(max_bytes=self._MAX_SEARCH_BODY_BYTES) or {}
            pubkey_raw = body.get("provider_pubkey")
            event_raw = body.get("event")
            if not isinstance(pubkey_raw, str) or not isinstance(event_raw, str):
                return self._respond(400, {
                    "error": "provider_pubkey and event must be strings",
                })
            pubkey = pubkey_raw.strip()
            event = event_raw.strip()
            if not pubkey or not event:
                return self._respond(400, {
                    "error": "provider_pubkey and event are required",
                })
            notes_raw = body.get("notes")
            if notes_raw is not None and not isinstance(notes_raw, str):
                return self._respond(400, {"error": "notes must be a string or null"})
            try:
                from swf.search.reputation import EVENT_DELTA, bump
                if event not in EVENT_DELTA:
                    return self._respond(400, {
                        "error": f"unknown event: {event}",
                        "known_events": sorted(EVENT_DELTA.keys()),
                    })
                new_score = bump(pubkey, event, notes=notes_raw)
            except Exception as e:
                logger.error("feedback internal error: %s", e)
                return self._respond(500, {"error": "feedback failed"})
            return self._respond(200, {
                "provider_pubkey": pubkey,
                "event": event,
                "new_score": round(new_score, 4),
            })

        # /admin/pending/<id>/{merge,reject} and /admin/peers/trust
        # were removed in v0.5 along with the review queue. Auto-merge
        # is the only ingest path; trust_level is implicitly "trusted"
        # for any signature-valid peer.
        if path.startswith("/admin/pending/") or path == "/admin/peers/trust":
            return self._respond(410, {"error": "endpoint removed: ingest is auto-merge"})

        # ── peer + agent routes (all modes) ────────────────────────
        if path in ("/search", "/local_search"):
            body = self._read_json_body() or {}
            q = (body.get("q") or "").strip()
            if not q:
                return self._respond(400, {"error": "missing q"})
            limit = int(body.get("limit") or _DEFAULT_LIMIT)
            limit = max(1, min(_MAX_LIMIT, limit))
            # /local_search is the deprecated alias
            source = body.get("source", "local") if path == "/search" else "local"
            try:
                from swf.search_router import expand_sources, is_privileged, search
                resolved = expand_sources(source)
            except ValueError as e:
                return self._respond(400, {"error": str(e)})
            if any(is_privileged(r) for r in resolved) and not self._check_token():
                return self._respond(401, {
                    "error": "bearer token required for non-local/non-peer sources",
                    "privileged_sources": [r.name for r in resolved if is_privileged(r)],
                })
            try:
                out = search(q=q, source=source, limit=limit)
            except Exception as e:
                return self._respond(500, {"error": f"search failed: {e}"})
            if path == "/local_search":
                self.send_response(200)
                self.send_header("Deprecation", "true")
                self.send_header("Link", "</search>; rel=\"successor-version\"")
                payload = json.dumps(out).encode("utf-8")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            return self._respond(200, out)

        if path in ("/fetch", "/fetch_url"):
            body = self._read_json_body() or {}
            url = (body.get("url") or "").strip()
            if not url:
                return self._respond(400, {"error": "missing url"})
            if not self._check_token():
                return self._respond(401, {"error": "bearer token required for /fetch"})
            start_char = int(body.get("start_char") or 0)
            max_chars = int(body.get("max_chars") or 16000)
            try:
                from swf.web.fetch import fetch_url
                out = fetch_url(url, start_char=start_char, max_chars=max_chars)
            except Exception as e:
                return self._respond(500, {"error": f"fetch failed: {e}"})
            payload = json.dumps({"content": out}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if path == "/fetch_url":
                self.send_header("Deprecation", "true")
                self.send_header("Link", "</fetch>; rel=\"successor-version\"")
            self.end_headers()
            self.wfile.write(payload)
            return

        if path in ("/fetch/batch", "/fetch_urls"):
            body = self._read_json_body() or {}
            urls = body.get("urls") or []
            if not urls or not isinstance(urls, list):
                return self._respond(400, {"error": "missing urls list"})
            if not self._check_token():
                return self._respond(401, {"error": "bearer token required for /fetch/batch"})
            max_chars_each = int(body.get("max_chars_each") or 6000)
            try:
                from swf.web.fetch import fetch_urls_parallel
                out = fetch_urls_parallel(urls, max_chars_each=max_chars_each)
            except Exception as e:
                return self._respond(500, {"error": f"fetch_urls failed: {e}"})
            payload = json.dumps({"content": out}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if path == "/fetch_urls":
                self.send_header("Deprecation", "true")
                self.send_header("Link", "</fetch/batch>; rel=\"successor-version\"")
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/metasearch":
            # /web_search is now the SPEC v0.3 envelope (handled earlier).
            # /metasearch is the legacy * fan-out path; keep it for the
            # research-agent until it migrates.
            body = self._read_json_body() or {}
            q = (body.get("q") or "").strip()
            if not q:
                return self._respond(400, {"error": "missing q"})
            limit = int(body.get("limit") or _DEFAULT_LIMIT)
            limit = max(1, min(_MAX_LIMIT, limit))
            if not self._check_token():
                return self._respond(401, {"error": "bearer token required for /metasearch"})
            try:
                from swf.search_router import search
                out = search(q=q, source="*", limit=limit)
            except Exception as e:
                return self._respond(500, {"error": f"metasearch failed: {e}"})
            return self._respond(200, out)

        return self._respond(404, {"error": "not found", "path": path})

    def log_request(self, code="-", size="-"):  # noqa: N802
        # SPEC v0.3 §24: raw_queries=false by default. The default
        # BaseHTTPRequestHandler.log_request logs self.requestline, which
        # contains the full URI including the query string (e.g.
        # /search?q=foo). We redact the query string so /search?q=<user-query>
        # never lands in our access log — path is fine, query parameters
        # are the leak. See docs/SPEC_v0.3_INTEGRATION_NOTES.md bug #7.
        try:
            parts = self.requestline.split(" ", 2)
            if len(parts) == 3:
                method, target, version = parts
                target = target.split("?", 1)[0]
                redacted = f"{method} {target} {version}"
            else:
                redacted = self.requestline.split("?", 1)[0]
        except Exception:
            redacted = "?"
        try:
            code_str = str(code.value)  # http.HTTPStatus
        except AttributeError:
            code_str = str(code)
        self.log_message('"%s" %s %s', redacted, code_str, str(size))

    def log_message(self, fmt, *args):  # noqa: N802
        # #79: was gated on RA_VERBOSE; the logger level (DEBUG when
        # SWF_VERBOSE / RA_VERBOSE is set, INFO otherwise) handles the
        # gate. Per-request access log lines are debug-grade.
        logger.debug("%s - %s", self.address_string(), fmt % args)


_loopback_reset_count = 0
_loopback_reset_lock = threading.Lock()


def _bump_loopback_reset() -> None:
    global _loopback_reset_count
    with _loopback_reset_lock:
        _loopback_reset_count += 1


def loopback_reset_count() -> int:
    """Total ConnectionResetError / BrokenPipeError / timeout events from
    a loopback peer that the server swallowed silently (#82). Exposed via
    metrics so an operator can see if a local probe is hammering the
    daemon."""
    with _loopback_reset_lock:
        return _loopback_reset_count


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that swallows the noisy "RST mid-handshake"
    pattern observed in #82.

    Background: a local probe (browser pre-connect, curl smoke loop,
    misbehaving dev tool) opens a TCP connection to 127.0.0.1:7777 and
    closes it before sending a request line. The stdlib's default
    `handle_error` logs a full traceback to stderr for every such
    event — at sufficient rate, the log fills with `ConnectionResetError`
    backtraces that bury the legitimate scraper output.

    We only swallow the specific safe set (ConnectionResetError,
    BrokenPipeError, ConnectionAbortedError, socket.timeout) AND only
    when the source is loopback. Anything else falls back to the
    default behaviour so real errors remain visible. The count is
    exposed via `loopback_reset_count()` so a watchdog can still tell
    the difference between "quiet" and "actively being probed."""

    def handle_error(self, request, client_address):
        import socket as _socket
        exc = sys.exc_info()[1]
        is_swallowable = isinstance(
            exc,
            (ConnectionResetError, BrokenPipeError,
             ConnectionAbortedError, _socket.timeout),
        )
        is_loopback = bool(
            client_address
            and isinstance(client_address[0], str)
            and (client_address[0].startswith("127.")
                 or client_address[0] == "::1")
        )
        if is_swallowable and is_loopback:
            _bump_loopback_reset()
            return
        return super().handle_error(request, client_address)


def serve(bind: str, port: int) -> None:
    server = _QuietThreadingHTTPServer((bind, port), _Handler)
    # NB: this exact string ("listening on http://") is grep-load-bearing
    # for operator watchdog scripts that gate on the boot line. The
    # bracket-prefix formatter (#79 _logging.py) reproduces the
    # `[peer-server] ` prefix from the logger name, so the on-the-wire
    # format stays byte-identical.
    logger.info(
        "listening on http://%s:%s · db=%s", bind, port, _DB_PATH,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
        server.shutdown()


def serve_in_thread(bind: str, port: int) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start the server on a background thread. Useful for tests and for
    running alongside the research agent in a single process.

    Returns (server, thread). Call `server.shutdown()` to stop.
    """
    server = _QuietThreadingHTTPServer((bind, port), _Handler)
    t = threading.Thread(
        target=server.serve_forever, name=f"swf-peer:{port}", daemon=True
    )
    t.start()
    return server, t


_SUBCOMMANDS = {"init", "doctor", "migrate", "version", "backup", "restore"}


# ── Subcommand handlers ────────────────────────────────────────────


def _cmd_version(_argv: list[str]) -> int:
    """`swf-node version` — print the package version."""
    sys.stdout.write(f"swf-node {SWF_VERSION}\n")
    return 0


def _cmd_init(argv: list[str]) -> int:
    """`swf-node init` — explicit identity + config bootstrap.

    Idempotent: refuses to overwrite an existing identity unless
    `--force` is passed, and only ever appends to a config skeleton.
    """
    parser = argparse.ArgumentParser(
        prog="swf-node init",
        description=(
            "Generate the Ed25519 identity (if missing) and write a "
            "commented config skeleton to ~/.config/swf/config.toml."
        ),
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Overwrite an existing identity. Be careful — peers TOFU "
             "your old pubkey, so rotating breaks their cached trust.",
    )
    args = parser.parse_args(argv)

    from swf.identity import get_or_create_identity, private_key_path
    from swf.paths import config_dir

    key_path = private_key_path()
    if key_path.exists() and not args.force:
        ident = get_or_create_identity()
        sys.stdout.write(
            f"identity present: {ident.fingerprint()} (at {key_path})\n"
            "use `swf-node init --force` to rotate (you'll lose peer "
            "trust until friends re-add you)\n"
        )
    else:
        if key_path.exists() and args.force:
            sys.stdout.write(f"rotating identity at {key_path}\n")
            key_path.unlink()
        ident = get_or_create_identity()
        sys.stdout.write(
            f"identity created: {ident.fingerprint()} at {key_path}\n"
        )

    config_path = config_dir() / "config.toml"
    if config_path.exists():
        sys.stdout.write(f"config present: {config_path}\n")
    else:
        config_path.write_text(_CONFIG_SKELETON)
        sys.stdout.write(f"config written: {config_path}\n")

    sys.stdout.write(
        "\nnext: `swf-node doctor` to verify, then `swf-node` to start.\n"
    )
    return 0


_CONFIG_SKELETON = """\
# swf-node configuration. All values can be overridden by env vars.
# Lines beginning with `#` are commented defaults — uncomment + edit
# to change them.

# Network
# SWF_BIND       = "127.0.0.1"   # set to 0.0.0.0 to accept LAN peers
# SWF_PORT       = 7777
# SWF_NO_MDNS    = false
# SWF_FULL       = false         # aggregator mode (requires extras)

# Identity / state
# SWF_CONFIG_DIR    = "~/.config/swf"
# SWF_KNOWLEDGE_DIR = "~/world_knowledge"
# SWF_STATE_DIR     = "~/.local/share/swf"

# Privacy
# SWF_DEFAULT_SHARE_SCOPE = "friends"   # private | local_only | friends | public
# SWF_AGENT_TOKEN         = ""          # required when SWF_BIND is non-loopback

# Optional integrations
# SEARXNG_URL = "http://127.0.0.1:8888"

# Logging
# SWF_LOG_LEVEL = "INFO"
"""


def _cmd_doctor(argv: list[str]) -> int:
    """`swf-node doctor` — extended health check.

    Wraps the existing `--check` self-test with mDNS round-trip,
    optional SearXNG probe, and per-peer reachability. Exit non-zero
    on any fail.
    """
    parser = argparse.ArgumentParser(
        prog="swf-node doctor",
        description="Extended health check (identity + DBs + mDNS + peers).",
    )
    parser.add_argument(
        "--no-mdns", action="store_true",
        default=os.environ.get("SWF_NO_MDNS") in ("1", "true", "yes"),
        help="Skip the mDNS register-and-self-browse probe.",
    )
    args = parser.parse_args(argv)

    failures = 0
    sys.stdout.write("== swf-node doctor ==\n\n")

    # Run the existing --check pipeline first; it's the closest thing
    # to a single-source-of-truth health surface today.
    sys.stdout.write("[1] core checks (--check)\n")
    rc = _run_self_check()
    if rc != 0:
        failures += 1
        sys.stdout.write(f"    → FAIL (exit {rc})\n")
    sys.stdout.write("\n")

    # mDNS probe: register a service, browse for it, deregister.
    if args.no_mdns:
        sys.stdout.write("[2] mDNS round-trip: skipped (--no-mdns)\n")
    else:
        sys.stdout.write("[2] mDNS round-trip: ")
        try:
            ok = _doctor_mdns_roundtrip()
            sys.stdout.write("ok\n" if ok else "FAIL (no self-broadcast)\n")
            if not ok:
                failures += 1
        except Exception as exc:
            sys.stdout.write(f"FAIL ({exc})\n")
            failures += 1
    sys.stdout.write("\n")

    # SearXNG, if configured.
    sys.stdout.write("[3] SearXNG: ")
    searxng_url = os.environ.get("SEARXNG_URL")
    if not searxng_url:
        sys.stdout.write("skipped (SEARXNG_URL not set)\n")
    else:
        try:
            with urllib.request.urlopen(  # noqa: S310
                f"{searxng_url.rstrip('/')}/healthz", timeout=2,
            ) as resp:
                sys.stdout.write(
                    f"ok ({resp.status} from {searxng_url})\n"
                )
        except Exception as exc:
            sys.stdout.write(f"unreachable ({exc})\n")
            failures += 1
    sys.stdout.write("\n")

    # Peers from peers.yaml.
    sys.stdout.write("[4] configured peers:\n")
    try:
        from swf.peers import load_peers
        peers = load_peers().peers
        if not peers:
            sys.stdout.write("    (none — `swf-peer add` to wire one up)\n")
        for p in peers:
            ok, detail = _doctor_peer_probe(p.url)
            mark = "ok" if ok else "FAIL"
            sys.stdout.write(f"    [{mark}] {p.name:20s} {p.url}  {detail}\n")
            if not ok:
                failures += 1
    except Exception as exc:
        sys.stdout.write(f"    (could not load peers.yaml: {exc})\n")
        failures += 1
    sys.stdout.write("\n")

    sys.stdout.write(
        f"== {failures} failure(s) ==\n"
        if failures else "== all clear ==\n"
    )
    return min(failures, 255)


def _doctor_mdns_roundtrip() -> bool:
    """Register a probe service, browse for it, return True iff we
    hear our own broadcast within 2 seconds. Used by `doctor`."""
    import time as _time

    from swf.discovery import _SERVICE_TYPE, register_mdns
    try:
        from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf
    except Exception:
        return False

    reg = register_mdns(
        port=17777,
        node_name="swf-doctor-probe",
        pubkey="probe",
    )
    seen: list[str] = []

    class _Listener(ServiceListener):
        def add_service(self, zc, type_, name):
            seen.append(name)
        def update_service(self, zc, type_, name): ...
        def remove_service(self, zc, type_, name): ...

    browser_zc = Zeroconf(ip_version=IPVersion.V4Only)
    try:
        ServiceBrowser(browser_zc, _SERVICE_TYPE, _Listener())
        deadline = _time.time() + 2.0
        while _time.time() < deadline:
            if any("swf-doctor-probe" in n for n in seen):
                return True
            _time.sleep(0.05)
        return False
    finally:
        with contextlib.suppress(Exception):
            reg.stop()
        browser_zc.close()


def _doctor_peer_probe(url: str) -> tuple[bool, str]:
    """GET /.well-known/indrex on the peer; return (ok, detail)."""
    base = url.rstrip("/")
    try:
        with urllib.request.urlopen(  # noqa: S310
            f"{base}/.well-known/indrex", timeout=3,
        ) as resp:
            if resp.status != 200:
                return False, f"http {resp.status}"
            doc = json.loads(resp.read(8192))
            fp = doc.get("fingerprint") or "?"
            ver = doc.get("version") or "?"
            return True, f"v{ver} fp={fp[:10]}"
    except Exception as exc:
        return False, str(exc)[:60]


def _cmd_migrate(_argv: list[str]) -> int:
    """`swf-node migrate` — apply additive schema migrations to the
    indrex DB explicitly (instead of waiting for the next write-path
    call to do it implicitly)."""
    from swf.indrex import db_path
    from swf.search.migration import ensure_schema

    path = db_path()
    if not path.exists():
        sys.stdout.write(
            f"no indrex at {path} — nothing to migrate. "
            "the daemon will create it on first use.\n"
        )
        return 0

    conn = sqlite3.connect(str(path))
    try:
        before = _columns(conn, "pages_meta")
        ensure_schema(conn)
        conn.commit()
        after = _columns(conn, "pages_meta")
        added = sorted(set(after) - set(before))
        sys.stdout.write(
            f"schema OK · pages_meta has {len(after)} column(s)\n"
        )
        if added:
            sys.stdout.write(f"added: {', '.join(added)}\n")
    finally:
        conn.close()
    return 0


def _cmd_backup(argv: list[str]) -> int:
    """`swf-node backup` — snapshot indrex + config to a tarball.

    Thin wrapper around `swf.backup.backup_to_tarball`; resolves the
    knowledge_dir + config_dir from env / paths helpers and prints a
    human-readable summary.
    """
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="swf-node backup",
        description=(
            "Snapshot the indrex DB and ~/.config/swf/ into a single "
            "tarball. Safe to run while the daemon is serving — uses "
            "the SQLite online-backup API."
        ),
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help=(
            "Tarball path. Default: "
            "`./swf-node-backup-<UTC-timestamp>.tar.gz`."
        ),
    )
    args = parser.parse_args(argv)

    from swf.backup import BackupError, backup_to_tarball
    from swf.indrex import db_path
    from swf.paths import config_dir

    knowledge_dir = db_path().parent
    cfg_dir = config_dir()

    try:
        manifest = backup_to_tarball(
            output_path=args.output,
            knowledge_dir=knowledge_dir,
            config_dir=cfg_dir,
        )
    except BackupError as exc:
        logger.error("backup failed: %s", exc)
        return 1

    output = args.output or Path.cwd()
    sys.stdout.write(
        f"backup written: {output}\n"
        f"  schema_version: {manifest['schema_version']}\n"
        f"  swf_node_version: {manifest['swf_node_version']}\n"
        f"  files captured: {len(manifest['files'])}\n",
    )
    for entry in manifest["files"]:
        sys.stdout.write(
            f"    {entry['path']}  "
            f"({entry['size']:>10} B  sha256={entry['sha256'][:12]}…)\n",
        )
    return 0


def _cmd_restore(argv: list[str]) -> int:
    """`swf-node restore` — inverse of `backup`.

    Verifies sha256s, refuses to clobber existing state without
    `--force`, then writes the captured files back into the target
    config / knowledge dirs.
    """
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="swf-node restore",
        description=(
            "Restore a swf-node backup tarball. By default targets "
            "$SWF_KNOWLEDGE_DIR / $SWF_CONFIG_DIR (or the standard "
            "~/world_knowledge and ~/.config/swf)."
        ),
    )
    parser.add_argument(
        "tarball", type=Path,
        help="Path to the backup tarball produced by `swf-node backup`.",
    )
    parser.add_argument(
        "--target-config-dir", type=Path, default=None,
        help="Override the destination config dir.",
    )
    parser.add_argument(
        "--target-knowledge-dir", type=Path, default=None,
        help="Override the destination knowledge dir.",
    )
    parser.add_argument(
        "--force", action="store_true",
        help=(
            "Overwrite an existing indrex DB or config files. "
            "Without this, the restore aborts if any target exists "
            "to avoid clobbering live data."
        ),
    )
    args = parser.parse_args(argv)

    from swf.backup import BackupError, restore_from_tarball
    from swf.indrex import db_path
    from swf.paths import config_dir

    target_knowledge = args.target_knowledge_dir or db_path().parent
    target_config = args.target_config_dir or config_dir()

    try:
        result = restore_from_tarball(
            tarball=args.tarball,
            target_knowledge_dir=target_knowledge,
            target_config_dir=target_config,
            force=args.force,
        )
    except BackupError as exc:
        logger.error("restore failed: %s", exc)
        return 1

    sys.stdout.write(
        f"restore complete: {len(result['restored'])} file(s) written\n"
        f"  knowledge dir: {target_knowledge}\n"
        f"  config dir:    {target_config}\n",
    )
    for path in result["restored"]:
        sys.stdout.write(f"    + {path}\n")
    if result["skipped"]:
        sys.stdout.write(f"  skipped: {len(result['skipped'])}\n")
        for path in result["skipped"]:
            sys.stdout.write(f"    - {path}\n")
    return 0


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    """Return column names for `table`; empty list if table missing."""
    try:
        return [row[1] for row in conn.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()]
    except Exception:
        return []


def main() -> int:
    """Entry point. Dispatches to a subcommand handler when the first
    positional looks like one (`swf-node init`, `swf-node doctor`,
    `swf-node migrate`, `swf-node version`, `swf-node backup`,
    `swf-node restore`), otherwise falls through to the existing
    argparse-based serve flow. The zero-arg case (`swf-node`) starts
    the daemon — backwards-compatible."""
    # #79: bootstrap stdlib logging into the swf.* tree before we hit
    # any module-level loggers (peer_server.logger, peer_scraper.logger,
    # bundles.puller.logger, etc). Idempotent — fine to call from
    # subcommand handlers' own paths if they're added later. Library
    # callers that import swf.* without going through this entry point
    # are responsible for their own logging config.
    from swf._logging import bootstrap as _log_bootstrap
    _log_bootstrap()

    argv = sys.argv[1:]
    if argv and argv[0] in _SUBCOMMANDS:
        cmd, rest = argv[0], argv[1:]
        if cmd == "init":
            return _cmd_init(rest)
        if cmd == "doctor":
            return _cmd_doctor(rest)
        if cmd == "migrate":
            return _cmd_migrate(rest)
        if cmd == "version":
            return _cmd_version(rest)
        if cmd == "backup":
            return _cmd_backup(rest)
        if cmd == "restore":
            return _cmd_restore(rest)
    return _serve(argv)


def _serve(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="swf-node",
        description=(
            "swf-node — self-sovereign LAN-first peer search.\n\n"
            "Subcommands: init | doctor | migrate | version | "
            "backup | restore. "
            "Run `swf-node <subcommand> --help` for each."
        ),
    )
    parser.add_argument(
        "--bind",
        default=os.environ.get("SWF_BIND", "127.0.0.1"),
        help="Interface to bind (default 127.0.0.1). Set 0.0.0.0 or a LAN IP to accept from friends.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SWF_PORT", "7777")),
        help="Port to listen on (default 7777).",
    )
    parser.add_argument(
        "--no-mdns",
        action="store_true",
        default=os.environ.get("SWF_NO_MDNS") in ("1", "true", "yes"),
        help="Do not advertise via mDNS. Advertisement is on by default when bound on a non-loopback interface.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        default=os.environ.get("SWF_FULL") in ("1", "true", "yes"),
        help=(
            "Run as a FULL NODE: in addition to serving this peer's own indrex, "
            "scrape every LAN peer's /community/slice, build the union "
            "community.db, and expose /graph + SSE /events + /admin/* on the "
            "same port. Requires the [community-full] extras."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        default=False,
        help=(
            "Run a read-only self-test: verify identity, DB schemas, "
            "HMAC secret mode, route registry, and §29.2 invariants are "
            "all wired correctly. Prints one line per check; exits 0 on "
            "all-pass, otherwise the number of failures (capped at 255). "
            "Does not start the HTTP server."
        ),
    )
    parser.add_argument(
        "--debug-discovery",
        action="store_true",
        default=False,
        help=(
            "Print this node's view of the LAN: own identity + IP, "
            "every DiscoveredPeer (mDNS + peers.yaml + Tailscale), "
            "and every row in `indrex.peers`. Exits without starting "
            "the HTTP server. Use on both laptops when peers aren't "
            "appearing — if mDNS shows the other side with `pubkey: "
            "None`, it's the pubkey-in-TXT-record bug."
        ),
    )
    parser.add_argument(
        "--hivemind-sink",
        action="store_true",
        default=os.environ.get("SWF_HIVEMIND_SINK") in ("1", "true", "yes"),
        help=(
            "Run as the convent box's hivemind sink (#93 phase 5, spec §4.3). "
            "Advertises `_sr-hivemind._tcp.local.` via mDNS so "
            "voxterm clients on the LAN discover us, and accepts "
            "`POST /hivemind/transcripts` payloads — wrapping each in a "
            "signed `kind: transcript.batch` envelope. Requires the "
            "convent box's alchemist Ed25519 private key at "
            "$SWF_CONVENT_SIGNING_KEY (or ~/.config/swf/convent-signing.key); "
            "the corresponding pubkey MUST be listed in .alchemists.yml or "
            "every signed bundle will be rejected by the verifier."
        ),
    )
    args = parser.parse_args(argv)

    if args.check:
        return _run_self_check()
    if args.debug_discovery:
        return _run_debug_discovery()

    # Eagerly load (or create) this peer's Ed25519 identity. First-run
    # behavior: a fresh keypair is generated at ~/.config/swf/identity.key
    # with mode 0600. The pubkey fingerprint is logged so the operator
    # knows what's signing their slices. Idempotent on subsequent starts.
    try:
        from swf.identity import get_or_create_identity, private_key_path
        existed_before = private_key_path().exists()
        ident = get_or_create_identity()
        logger.info(
            "identity %s  (%s at %s)",
            ident.fingerprint(),
            "existing" if existed_before else "created",
            private_key_path(),
        )
    except Exception as exc:
        logger.error("identity load/create failed: %s", exc)
        return 1

    # Auto-write the commented config skeleton on first start so the
    # operator finds a reference at ~/.config/swf/config.toml without
    # having to run `swf-node init` first. The daemon does not read
    # this file (env vars + flags drive configuration); it's
    # documentation. `swf-node init` does the same write explicitly.
    try:
        from swf.paths import config_dir as _config_dir
        _config_path = _config_dir() / "config.toml"
        if not _config_path.exists():
            _config_path.write_text(_CONFIG_SKELETON)
            logger.info("wrote config skeleton: %s", _config_path)
    except Exception as exc:
        logger.warning("config skeleton write skipped: %s", exc)

    # Auto-register mDNS only when bound on a reachable interface. On
    # 127.0.0.1 there's nothing to advertise (nobody else can reach us),
    # so skip to avoid spurious LAN noise.
    #
    # mDNS broadcast MUST carry the producer's pubkey in its TXT
    # record — the consumer's `_seed_peers_from_discovery` filters
    # out DiscoveredPeer entries with `dp.pubkey is None`, so a
    # pubkey-less advertisement is invisible to the auto-seed path.
    # Without this we shipped 5 PRs of single-graph pull machinery
    # that quietly never auto-discovered any peer across the LAN.
    mdns_handle = None
    should_mdns = (not args.no_mdns) and args.bind not in ("127.0.0.1", "localhost")
    if should_mdns:
        try:
            from swf.discovery import register_mdns, start_ip_change_watchdog

            mdns_handle = register_mdns(
                port=args.port, node_name=_hostname(),
                pubkey=ident.pub_b64,
            )
            # When a VPN flips on/off the host's outbound IPv4 changes
            # but mDNS keeps advertising the stale address. The
            # watchdog polls every 30s and re-registers on a change
            # so peers find us at the new IP without operator action.
            start_ip_change_watchdog(mdns_handle)
        except Exception as exc:
            logger.warning("mDNS register skipped: %s", exc)

    if args.full:
        from swf.identity import get_or_create_identity
        _start_full_subsystems(own_pubkey=get_or_create_identity().pub_b64,
                                own_port=args.port)

    hivemind_handle = None
    if args.hivemind_sink:
        try:
            hivemind_handle = _start_hivemind_sink(
                bind=args.bind, port=args.port,
            )
        except SystemExit:
            raise
        except Exception as exc:
            logger.error("--hivemind-sink failed to start: %s", exc)
            return 1

    # ── Phase 2 sync subsystem (docs/SYNC.md) ─────────────────────────
    # Ensure the sync sqlite schema is in place BEFORE the HTTP server
    # starts serving (so the first /sync/manifest request doesn't race
    # the DDL). Then spawn the background sync loop as a daemon thread
    # AFTER serve() begins listening — sync_loop polls peers, never
    # blocks the request path.
    #
    # `SWF_SYNC_DISABLE=1` disables the loop entirely (spec §8.5);
    # the HTTP routes still serve, but we never poll outbound. Used
    # when the operator wants search/bundles only.
    sync_disabled = os.environ.get("SWF_SYNC_DISABLE") in ("1", "true", "yes")
    try:
        from swf.indrex import db_path as _idx_db
        from swf.sync.schema import ensure_schema as _sync_ensure_schema
        _conn = sqlite3.connect(str(_idx_db()), timeout=5.0)
        try:
            _sync_ensure_schema(_conn)
        finally:
            _conn.close()
    except Exception as exc:
        logger.warning("sync schema init skipped: %s", exc)

    try:
        if not sync_disabled:
            from swf.sync.sync_loop import start_sync_loop
            start_sync_loop()
        serve(args.bind, args.port)
    finally:
        # Stop the daemon-thread subsystems started by --full BEFORE
        # tearing down mDNS / the hivemind handle. They're idempotent
        # if --full wasn't set; calling them on every shutdown keeps
        # the path simple. Without this the daemon threads keep ticking
        # in the background until the interpreter actually exits, which
        # is harmless on a real shutdown but spam-noisy in tests and
        # makes graceful-restart sequences (e.g. systemd --reload-style
        # restart) unpredictable.
        if args.full:
            _stop_full_subsystems()
        if not sync_disabled:
            with contextlib.suppress(Exception):
                from swf.sync.sync_loop import stop_sync_loop
                stop_sync_loop()
        if mdns_handle is not None:
            with contextlib.suppress(Exception):
                mdns_handle.stop()
        if hivemind_handle is not None:
            with contextlib.suppress(Exception):
                hivemind_handle.stop()
    return 0


def _start_hivemind_sink(*, bind: str, port: int):
    """Wire up the hivemind sink for `--hivemind-sink` mode (#93 phase 5).

    Three things in order:
      1. Load the convent box's Ed25519 signing key. If
         `SWF_CONVENT_SIGNING_KEY` isn't set and there's no fallback
         file at `~/.config/swf/convent-signing.key`, fail fast — a
         sink that can't sign isn't a sink.
      2. Cross-check that the corresponding pubkey IS in `.alchemists.yml`.
         If it isn't, every bundle the sink signs will be rejected by
         the phase-1 verifier as `author_not_alchemist`. Exit 1 with a
         clear error so the operator fixes the misconfig BEFORE
         voxterm clients start posting.
      3. Start the mDNS advertisement (`_sr-hivemind._tcp.local.`)
         iff bound on a non-loopback interface. Loopback bind is
         logged + skipped (mDNS-on-loopback is meaningless); the HTTP
         route still works for local curl / tests.

    Returns the mDNS handle (or None on loopback / when zeroconf is
    missing). Raises `SystemExit(1)` on misconfiguration so the daemon
    doesn't bind a port that will silently reject every transcript.
    """
    from swf import hivemind
    from swf.hivemind.sink import (
        load_signing_key,
        signing_key_path,
        signing_pubkey_hex,
    )

    # 1. Load + validate signing key.
    try:
        priv = load_signing_key()
    except FileNotFoundError as exc:
        logger.error(
            "--hivemind-sink: %s. "
            "set SWF_CONVENT_SIGNING_KEY=/path/to/seed (32 raw bytes), "
            "or place a 32-byte seed at ~/.config/swf/convent-signing.key",
            exc,
        )
        raise SystemExit(1) from exc
    except ValueError as exc:
        logger.error("--hivemind-sink: %s", exc)
        raise SystemExit(1) from exc

    pubkey_hex = signing_pubkey_hex(priv)
    pubkey_str = f"ed25519:{pubkey_hex}"
    logger.info(
        "hivemind sink: signing key loaded (%s); pubkey=%s…",
        signing_key_path(), pubkey_hex[:12],
    )

    # 2. Verify pubkey is listed in .alchemists.yml.
    alchemists = _load_alchemists_cached()
    if not alchemists.is_alchemist_pubkey(pubkey_str):
        logger.error(
            "--hivemind-sink: convent pubkey %s is NOT listed in "
            ".alchemists.yml (%s); every signed bundle would be "
            "rejected as author_not_alchemist. Add the convent box "
            "to .alchemists.yml and restart.",
            pubkey_str, alchemists.path,
        )
        raise SystemExit(1)
    logger.info(
        "hivemind sink: convent pubkey is listed in alchemists.yml (%s)",
        alchemists.path,
    )

    # 3. Start mDNS advertisement (loopback-bound = skip).
    handle = hivemind.start_advertisement(
        port=port,
        node_name=_hostname(),
        pubkey_hex=pubkey_hex,
        bind=bind,
    )
    if handle is None:
        logger.info(
            "hivemind sink: bound on %s (loopback or wildcard); "
            "mDNS advertisement skipped — POST /hivemind/transcripts "
            "still serves locally",
            bind,
        )
    elif handle.registered:
        logger.info(
            "hivemind sink: advertising %s on port %s",
            hivemind.HIVEMIND_SERVICE_TYPE, port,
        )
    else:
        # zeroconf rejected the registration; the always-on
        # `[hivemind-mdns]` log already printed the specific reason.
        # Echo a peer-server-level summary so operators don't miss
        # the consequence: no LAN voxterm client will discover us.
        logger.warning(
            "hivemind sink: mDNS advertisement FAILED — "
            "voxterm clients on the LAN will NOT discover this sink "
            "automatically; operators must point them at "
            "http://<this-host>:%s/hivemind/transcripts by hand",
            port,
        )
    return handle


# ─── self-test (--check) ──────────────────────────────────────────────
#
# TODO-12: operator-friendly install sanity. Pure read-only — never
# creates or migrates anything. A missing DB is reported as `[skip]`,
# not a hard failure, because a fresh install legitimately has none of
# the runtime DBs until the first /web_search lazily creates them. Any
# OTHER failure (wrong schema, identity unloadable, route handlers
# missing, HMAC secret mode-leaked) is a hard fail and bumps the exit
# code so an init script can react.

# pages_meta after TODO-8 must carry these six columns plus the `url`
# primary key. Listed without `url` because the check matches against
# the CHECK list ⊂ actual-columns — TODO-8 may add more, that's fine,
# but it must not drop one of these.
_EXPECTED_PAGES_META_COLS: tuple[str, ...] = (
    "share_scope",
    "sensitivity_label",
    "source_type",
    "content_hash",
    "fetched_at_ms",
    "deleted_at_ms",
)

# Routes the SPEC v0.3 §15 router must have wired. LAN_FRIEND_DCNET is
# intentionally excluded — it ships as `route_not_implemented` until the
# DC-net library lands (see TODO-1).
_REQUIRED_ROUTES: tuple[str, ...] = (
    "LOCAL_CACHE",
    "LOCAL_INDREX",
    "LAN_FRIEND_DIRECT_PLACEHOLDER",
    "SELF_PUBLIC_EGRESS",
)


def _check_identity() -> tuple[bool, str]:
    try:
        from swf.identity import get_or_create_identity
        ident = get_or_create_identity()
    except Exception as exc:
        return False, f"identity load failed: {exc}"
    pub = ident.pub_b64 or ""
    # Ed25519 pubkeys are 32 bytes → 43 chars unpadded base64url.
    if len(pub) < 40:
        return False, f"pubkey too short ({len(pub)} chars)"
    fp = ident.fingerprint()
    # blake2b-truncated-to-8-bytes hex == 16 hex chars.
    if len(fp) != 16 or not all(c in "0123456789abcdef" for c in fp):
        return False, f"bad fingerprint shape: {fp!r}"
    return True, f"pubkey={pub[:12]}… fp={fp}"


def _check_indrex_schema() -> tuple[str, str]:
    """Returns (status, detail) where status is 'ok', 'skip', or 'fail'."""
    from swf.indrex import db_path as indrex_db_path
    p = indrex_db_path()
    if not p.exists():
        return "skip", f"db not found at {p}"
    try:
        uri = f"file:{p}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    except sqlite3.OperationalError as exc:
        return "fail", f"open failed: {exc}"
    try:
        try:
            conn.execute("SELECT 1 FROM pages LIMIT 1")
        except sqlite3.OperationalError as exc:
            return "fail", f"pages missing: {exc}"
        try:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(pages_meta)").fetchall()]
        except sqlite3.OperationalError as exc:
            return "fail", f"pages_meta missing: {exc}"
        if not cols:
            return "fail", "pages_meta missing"
        missing = [c for c in _EXPECTED_PAGES_META_COLS if c not in cols]
        if missing:
            return "fail", (
                f"pages_meta missing columns {missing} "
                f"(have {sorted(cols)}); apply TODO-8 schema"
            )
    finally:
        conn.close()
    return "ok", f"pages + pages_meta(6+ cols) at {p}"


def _check_table_present(
    *,
    label: str,
    db_path,
    required_tables: tuple[str, ...],
) -> tuple[str, str]:
    p = db_path()
    if not p.exists():
        return "skip", f"db not found at {p}"
    try:
        uri = f"file:{p}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    except sqlite3.OperationalError as exc:
        return "fail", f"open failed: {exc}"
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        present = {r[0] for r in rows}
        missing = [t for t in required_tables if t not in present]
        if missing:
            return "fail", f"missing tables {missing} (have {sorted(present)})"
    finally:
        conn.close()
    return "ok", f"{label}: {list(required_tables)} at {p}"


def _check_cache_secret() -> tuple[str, str]:
    from swf.search.local_cache import secret_path
    p = secret_path()
    if not p.exists():
        return "skip", f"secret not found at {p}"
    try:
        size = p.stat().st_size
    except OSError as exc:
        return "fail", f"stat failed: {exc}"
    if size != 32:
        return "fail", f"size={size}, expected 32"
    if os.name == "posix":
        mode = p.stat().st_mode & 0o777
        if mode != 0o600:
            return "fail", f"mode={oct(mode)}, expected 0o600"
        return "ok", f"32 bytes, mode 0600 at {p}"
    # Non-POSIX: best-effort; the create path doesn't enforce mode.
    return "ok", f"32 bytes at {p} (mode check skipped on {os.name})"


def _check_routes_wired() -> tuple[bool, str]:
    try:
        from swf.search.response import DeliveryPath
        from swf.search.router import _HANDLERS
    except Exception as exc:
        return False, f"router import failed: {exc}"
    missing = []
    for name in _REQUIRED_ROUTES:
        try:
            path = DeliveryPath(name)
        except ValueError:
            missing.append(name)
            continue
        if path not in _HANDLERS:
            missing.append(name)
    if missing:
        return False, f"missing handlers: {missing}"
    return True, f"{len(_REQUIRED_ROUTES)} routes wired"


def _check_invariants_live() -> tuple[bool, str]:
    """Build one valid envelope + one invalid envelope; confirm the
    §29.2 invariant checker accepts the first and rejects the second.
    This is the dynamic equivalent of `tests/search/test_response.py`
    running on the user's actual install."""
    try:
        from swf.search.response import (
            DeliveryPath,
            InvariantError,
            OriginPath,
            PrivacyLevel,
            SearchResponse,
            Status,
        )
    except Exception as exc:
        return False, f"response import failed: {exc}"

    # 1. Valid local-only envelope.
    try:
        SearchResponse.make(
            status=Status.OK,
            request_id="req_check_ok",
            created_ms=1, completed_ms=2,
            delivery_path=DeliveryPath.LOCAL_INDREX,
            origin_paths=[OriginPath.LOCAL_INDREX],
            dominant_origin_path=OriginPath.LOCAL_INDREX,
            privacy_level=PrivacyLevel.LOCAL_ONLY,
            network_used_this_request=False,
            public_egress_used_this_request=False,
        )
    except Exception as exc:
        return False, f"valid envelope rejected: {exc!r}"

    # 2. LOCAL_CACHE with empty origin_paths is the canonical §29.2 #2
    #    violation: must raise InvariantError.
    try:
        SearchResponse.make(
            status=Status.OK,
            request_id="req_check_violation",
            created_ms=1, completed_ms=2,
            delivery_path=DeliveryPath.LOCAL_CACHE,
            origin_paths=[],
            dominant_origin_path=OriginPath.LOCAL_CACHE,
            privacy_level=PrivacyLevel.LOCAL_REPLAY,
            network_used_this_request=False,
            public_egress_used_this_request=False,
        )
    except InvariantError:
        return True, "LOCAL_ONLY accepted, LOCAL_CACHE+empty rejected"
    except Exception as exc:
        return False, f"unexpected error on violation: {exc!r}"
    return False, "InvariantError NOT raised on LOCAL_CACHE+empty origin_paths"


_PUBKEY_RE = re.compile(r"^ed25519:[0-9a-f]{64}$")


def _check_alchemists_yml() -> tuple[str, str]:
    """Validate `.alchemists.yml` parses cleanly with at least one
    well-formed entry.

    SKIP if the file isn't configured / present (env var unset AND no
    file at the default `~/.config/swf/.alchemists.yml`). FAIL on
    YAML errors, missing schema_version, or any pubkey that doesn't
    match `^ed25519:[0-9a-f]{64}$`. PASS prints the entry count.

    Operators commonly hit two failure modes silently: a malformed
    YAML (one of the indents fell off during a CLI edit) and a
    pubkey copied from a chat that lost the `ed25519:` prefix. Both
    fail at boot today with `author_not_alchemist` 500s during
    `--hivemind-sink`; surfacing them at `--check` time saves the
    operator a debugging round.
    """
    from pathlib import Path

    import yaml

    explicit = os.environ.get("SWF_ALCHEMISTS_FILE")
    cfg_env = os.environ.get("SWF_CONFIG_DIR")
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    if cfg_env:
        candidates.append(Path(cfg_env) / ".alchemists.yml")
    candidates.append(Path.home() / ".config" / "swf" / ".alchemists.yml")

    found: Path | None = None
    for p in candidates:
        try:
            if p.is_file():
                found = p
                break
        except OSError:
            continue
    if found is None:
        return "skip", (
            "no .alchemists.yml configured "
            f"(checked {len(candidates)} location(s))"
        )

    # Load the YAML by hand so we can flag missing/wrong schema_version
    # as FAIL — `bundles.load_alchemists` is forgiving by design and
    # would silently accept a missing schema_version.
    try:
        raw = yaml.safe_load(found.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return "fail", f"YAML parse failed for {found}: {exc}"
    if not isinstance(raw, dict):
        return "fail", (
            f"{found}: expected top-level mapping, got "
            f"{type(raw).__name__}"
        )
    sv = raw.get("schema_version")
    if not isinstance(sv, int) or isinstance(sv, bool) or sv != 1:
        return "fail", (
            f"{found}: schema_version must be int 1 (got {sv!r})"
        )

    # Defer entry parsing to `bundles.load_alchemists` so the canonical
    # loader is the source of truth for valid-entry semantics, then
    # cross-check the regex separately because the loader accepts
    # `ed25519:<anything>` (lenient) whereas operators want the strict
    # 64-hex-char form caught at startup.
    entries = raw.get("alchemists")
    if not isinstance(entries, list) or not entries:
        return "fail", f"{found}: 'alchemists' must be a non-empty list"
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return "fail", f"{found}: entry #{idx} is not a mapping"
        pub = entry.get("pubkey")
        if not isinstance(pub, str) or not _PUBKEY_RE.match(pub):
            return "fail", (
                f"{found}: entry #{idx} has malformed pubkey "
                f"(want ed25519:<64-hex>, got {pub!r})"
            )

    try:
        from swf.bundles import load_alchemists
        loaded = load_alchemists(path=found)
    except Exception as exc:
        return "fail", f"loader crashed on {found}: {exc!r}"
    if not loaded.members:
        return "fail", f"{found}: zero valid entries after load"
    return "ok", f"{len(loaded.members)} alchemist(s) at {found}"


def _check_reservoir_yml() -> tuple[str, str]:
    """Validate `.reservoir.yml` parses cleanly with at least one
    age recipient.

    SKIP if the file isn't configured / present. FAIL on YAML errors,
    or any pubkey that doesn't start with `age1` (pyrage will
    cryptographically validate the bech32 body when the key is used —
    a startup-time prefix check catches obvious typos like a leading
    space or a copy that picked up the YAML quote chars).
    """
    from pathlib import Path

    import yaml

    explicit = os.environ.get("SWF_RESERVOIR_FILE")
    cfg_env = os.environ.get("SWF_CONFIG_DIR")
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    if cfg_env:
        candidates.append(Path(cfg_env) / ".reservoir.yml")
    candidates.append(Path.home() / ".config" / "swf" / ".reservoir.yml")

    found: Path | None = None
    for p in candidates:
        try:
            if p.is_file():
                found = p
                break
        except OSError:
            continue
    if found is None:
        return "skip", (
            "no .reservoir.yml configured "
            f"(checked {len(candidates)} location(s))"
        )

    try:
        raw = yaml.safe_load(found.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return "fail", f"YAML parse failed for {found}: {exc}"
    if not isinstance(raw, dict):
        return "fail", (
            f"{found}: expected top-level mapping, got "
            f"{type(raw).__name__}"
        )

    entries = raw.get("keys")
    if not isinstance(entries, list) or not entries:
        return "fail", f"{found}: 'keys' must be a non-empty list"
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return "fail", f"{found}: entry #{idx} is not a mapping"
        pub = entry.get("pubkey")
        if not isinstance(pub, str) or not pub.startswith("age1"):
            return "fail", (
                f"{found}: entry #{idx} pubkey must start with 'age1' "
                f"(got {pub!r})"
            )

    try:
        from swf.bundles import load_reservoir
        loaded = load_reservoir(path=found)
    except Exception as exc:
        return "fail", f"loader crashed on {found}: {exc!r}"
    if not loaded.pubkeys():
        return "fail", f"{found}: zero valid entries after load"
    return "ok", f"{len(loaded.pubkeys())} recipient(s) at {found}"


def _check_convent_signing_key() -> tuple[str, str]:
    """Validate `SWF_CONVENT_SIGNING_KEY` (when set) points to a 32-byte
    Ed25519 seed AND that the derived pubkey is in `.alchemists.yml`.

    SKIP when the env var is unset (the default — most peers don't
    run the hivemind sink). FAIL when the env var is set but the file
    is missing / wrong size / unloadable. Returns `("warn", msg)` —
    NOT a hard fail — when the key loads but its pubkey isn't in the
    alchemist list: the sink will refuse to start with this state, so
    surfacing it at `--check` time is the friendliest place to flag
    the misconfig before the operator runs `swf-node --hivemind-sink`.
    """
    env = os.environ.get("SWF_CONVENT_SIGNING_KEY")
    if not env:
        return "skip", "SWF_CONVENT_SIGNING_KEY unset"
    from pathlib import Path
    p = Path(env)
    if not p.exists():
        return "fail", f"signing key not found at {p}"
    try:
        raw = p.read_bytes()
    except OSError as exc:
        return "fail", f"read failed for {p}: {exc}"
    if len(raw) != 32:
        return "fail", f"{p}: size={len(raw)}, expected 32 raw bytes"
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        priv = Ed25519PrivateKey.from_private_bytes(raw)
        pub_hex = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
    except Exception as exc:
        return "fail", f"{p}: not a valid Ed25519 seed: {exc!r}"

    pubkey_str = f"ed25519:{pub_hex}"

    # Cross-check against the alchemist list, but ONLY when it's
    # loadable — if alchemists.yml is missing/malformed, the
    # alchemist-yml check above already FAILed and we'd be
    # double-reporting if we FAILed here too. WARN keeps the signal
    # but defers to the alchemist check for the underlying file
    # error.
    try:
        from swf.bundles import load_alchemists
        alchemists = load_alchemists()
    except Exception:
        alchemists = None

    if alchemists is None or not alchemists.members:
        return "warn", (
            f"loaded {pub_hex[:12]}… from {p}; alchemists.yml "
            "not loadable, cross-check skipped"
        )

    if pubkey_str in alchemists.members:
        ident = alchemists.members.get(pubkey_str) or "<unnamed>"
        return "ok", (
            f"matches alchemist {ident} (pubkey={pub_hex[:12]}…)"
        )
    return "warn", (
        f"loaded {pub_hex[:12]}… from {p} but pubkey is NOT in "
        f"{alchemists.path}; --hivemind-sink would refuse to start"
    )


def _run_self_check() -> int:
    """Run every check, print one line each, return failure count
    (capped at 255 so it fits in a Unix exit code).

    Status tiers, lowest to highest severity:
      * `[ok]`    — check passed.
      * `[skip]`  — check is N/A on this install (e.g. no
                    `.alchemists.yml` configured). Reported but does
                    NOT count as a failure (a fresh install must be
                    able to exit 0 even with no optional config).
      * `[warn]`  — soft failure: the check found a misconfiguration
                    that will bite the operator at runtime, but the
                    daemon can still boot. Reported but does NOT
                    count toward the exit-code failure count. Used
                    for "convent signing key loaded but pubkey isn't
                    in alchemists.yml" — `--hivemind-sink` will refuse
                    to start with this state, so flagging it at
                    `--check` time is friendlier than a 500 from the
                    sink.
      * `[FAIL]`  — hard failure: counted toward the exit code so
                    init scripts can react.
    """
    from swf.search import local_cache, reputation, tickets

    checks: list[tuple[str, callable]] = [
        ("identity", _check_identity),
        ("indrex schema", _check_indrex_schema),
        ("cache schema", lambda: _check_table_present(
            label="cache",
            db_path=local_cache.db_path,
            required_tables=("cache_entries",),
        )),
        ("reputation schema", lambda: _check_table_present(
            label="reputation",
            db_path=reputation.db_path,
            required_tables=("provider_scores",),
        )),
        ("tickets schema", lambda: _check_table_present(
            label="tickets",
            db_path=tickets.db_path,
            required_tables=(
                "anonymous_tickets",
                "spent_ticket_nullifiers",
                "issuer_keys",
            ),
        )),
        ("cache HMAC secret", _check_cache_secret),
        ("routes wired", _check_routes_wired),
        ("invariants live", _check_invariants_live),
        ("alchemists.yml", _check_alchemists_yml),
        ("reservoir.yml", _check_reservoir_yml),
        ("convent signing key", _check_convent_signing_key),
    ]

    failures = 0
    passed = 0
    skipped = 0
    warned = 0
    total = len(checks)
    for name, fn in checks:
        try:
            result = fn()
        except Exception as exc:
            sys.stdout.write(f"[FAIL] {name}: unhandled exception: {exc!r}\n")
            failures += 1
            continue
        # Functions return either (bool, detail) or (status_str, detail).
        if isinstance(result, tuple) and len(result) == 2:
            status, detail = result
        else:
            sys.stdout.write(f"[FAIL] {name}: malformed check result {result!r}\n")
            failures += 1
            continue
        if status is True or status == "ok":
            sys.stdout.write(f"[ok] {name}: {detail}\n")
            passed += 1
        elif status == "skip":
            sys.stdout.write(f"[skip] {name}: {detail}\n")
            # Pass-4 finding #6: skip is NOT a failure. The module
            # docstring at line ~911 promises "missing DB is reported
            # as `[skip]`, not a hard failure, because a fresh install
            # legitimately has none of the runtime DBs until the first
            # /web_search lazily creates them." A non-zero exit on a
            # fresh install would misfire init scripts that treat
            # non-zero as fatal. Skip is reported but not counted.
            skipped += 1
        elif status == "warn":
            # WARN is the soft-failure tier added for the operator-UX
            # bundle config checks: visible enough that the operator
            # spots it, but not counted toward the exit code so init
            # scripts don't misfire on a state the daemon can still
            # boot through.
            sys.stdout.write(f"[warn] {name}: {detail}\n")
            warned += 1
        else:
            sys.stdout.write(f"[FAIL] {name}: {detail}\n")
            failures += 1

    parts = [f"{passed}/{total} checks passed"]
    if skipped:
        parts.append(f"{skipped} skipped")
    if warned:
        parts.append(f"{warned} warned")
    if len(parts) == 1:
        sys.stdout.write(parts[0] + "\n")
    else:
        sys.stdout.write(f"{parts[0]} ({', '.join(parts[1:])})\n")
    sys.stdout.flush()
    return min(failures, 255)


def _run_debug_discovery() -> int:
    """Print everything this node knows about the LAN. No server
    starts, no DB writes — read-only diagnostic. Use on both
    machines when peers aren't appearing."""
    sys.stdout.write("=== own identity ===\n")
    try:
        from swf.identity import get_or_create_identity
        ident = get_or_create_identity()
        sys.stdout.write(
            f"  pubkey:   {ident.pub_b64}\n"
            f"  fp:       {ident.fingerprint()}\n"
        )
    except Exception as exc:
        sys.stdout.write(f"  identity load failed: {exc}\n")

    sys.stdout.write("\n=== own LAN IP (what mDNS would advertise) ===\n")
    try:
        from swf.discovery import _outbound_ipv4
        sys.stdout.write(f"  outbound_ipv4: {_outbound_ipv4()!r}\n")
    except Exception as exc:
        sys.stdout.write(f"  outbound_ipv4 failed: {exc}\n")

    sys.stdout.write("\n=== discover_all_peers() ===\n")
    try:
        from swf.discovery import discover_all_peers
        peers = discover_all_peers(mdns_timeout=2.5)
        if not peers:
            sys.stdout.write("  (none)\n")
        for p in peers:
            sys.stdout.write(
                f"  src={p.source:9} url={p.url:36} "
                f"name={p.name!r} pubkey={p.pubkey!r}\n"
            )
    except Exception as exc:
        sys.stdout.write(f"  discover_all_peers failed: {exc}\n")

    sys.stdout.write("\n=== indrex.peers (what the scraper iterates) ===\n")
    try:
        from swf.indrex import db_path
        from swf.peer_scraper import list_peers
        rows = list_peers(db_path())
        if not rows:
            sys.stdout.write("  (none)\n")
        for p in rows:
            sys.stdout.write(
                f"  pk={p.pubkey[:24]}…  nick={p.nickname!r:14} "
                f"cursor={p.last_pull_cursor:>4}  "
                f"epoch={p.last_seen_epoch[:12]!r:14} "
                f"fails={p.consecutive_failures} "
                f"trust={p.trust_level}\n"
            )
    except Exception as exc:
        sys.stdout.write(f"  list_peers failed: {exc}\n")

    sys.stdout.write("\n=== troubleshooting ===\n")
    sys.stdout.write(
        "  • Both nodes must run with --bind 0.0.0.0 (or a LAN IP),\n"
        "    NOT 127.0.0.1 — mDNS skips loopback binds by design.\n"
        "  • SWF_NO_MDNS=1 disables advertisement; unset to enable.\n"
        "  • If discover_all_peers() shows the other node but its\n"
        "    `pubkey` is None, the producer's mDNS isn't including\n"
        "    the pk TXT record (regression).\n"
        "  • If indrex.peers is empty after a few minutes of --full,\n"
        "    the auto-seed never saw a pubkey-bearing peer. Add the\n"
        "    other side manually to ~/.config/swf/peers.yaml as a\n"
        "    workaround.\n"
        "  • Tailscale and Wi-Fi 5GHz/2.4GHz isolation can block\n"
        "    mDNS multicast even when both nodes are 'on the same\n"
        "    network'.\n"
    )
    return 0


def _start_full_subsystems(*, own_pubkey: str | None = None,
                            own_port: int | None = None):
    """Start full-mode subsystems under --full: metrics.db init,
    metrics collector, indrex peer-scraper. The legacy
    community-full machinery (presence, slice scraper, ingest, etc)
    was removed in #43 PR C — single-graph indrex now owns peer
    state. /graph + /events still served by the same
    ThreadingHTTPServer (single port, single binary)."""
    try:
        from swf.community_full import db as cdb
    except ImportError as exc:
        logger.error(
            "--full requires the [community-full] extras "
            "(pip install -e '.[community-full]')  → %s",
            exc,
        )
        raise SystemExit(2) from None
    cdb.init()
    logger.info(
        "FULL NODE: /graph, /events, /metrics/* live on "
        "the same port as the peer",
    )
    # Issue #43 PR A: indrex peer-scraper. Walks indrex.peers every
    # 60s, pulls each peer's /index/pages bundle, verifies + ingests.
    try:
        from swf import peer_scraper as _idx_scraper
        _idx_scraper.start()
        logger.info("indrex peer-scraper started")
    except Exception as exc:
        logger.warning("indrex scraper start skipped: %s", exc)
    # #93 phase 6 follow-up: pull-side bundle replication. Walks
    # indrex.peers every SWF_BUNDLE_PULL_INTERVAL_SECS (60s default),
    # pulls each peer's /bundles?received_since=<hw> stream, verifies
    # + inserts. Catches up an offline-then-rejoin peer past anything
    # the push-side broadcast missed. Set the interval to 0 to
    # disable (test convenience; production should leave it on).
    try:
        from swf import bundles as _bundles
        interval_raw = os.environ.get("SWF_BUNDLE_PULL_INTERVAL_SECS")
        if interval_raw is None:
            interval_secs: float = float(_bundles.DEFAULT_PULL_INTERVAL_SECS)
        else:
            try:
                interval_secs = float(interval_raw)
            except ValueError:
                interval_secs = float(_bundles.DEFAULT_PULL_INTERVAL_SECS)
        if interval_secs > 0:
            _bundles.start_puller(interval_secs=interval_secs)
            logger.info(
                "bundle puller started (interval=%gs)", interval_secs,
            )
        else:
            logger.info(
                "bundle puller disabled (SWF_BUNDLE_PULL_INTERVAL_SECS=0)",
            )
    except Exception as exc:
        logger.warning("bundle puller start skipped: %s", exc)
    # Self-contained metrics collector. Spawns a daemon thread that
    # ticks every SWF_METRICS_INTERVAL_SECS, sampling process +
    # push-style metrics into metrics.db. Powers the /metrics/snapshot
    # and /metrics/series HTTP endpoints.
    try:
        from swf.community_full import metrics as cmetrics
        cmetrics.start()
        logger.info("metrics collector started")
    except Exception as exc:
        logger.warning("metrics start skipped: %s", exc)


def _stop_full_subsystems() -> None:
    """Best-effort stop for the daemon-thread subsystems that
    `_start_full_subsystems` brought up (indrex peer-scraper + bundle
    puller). Idempotent — safe to call when the subsystems weren't
    started, when one of them crashed mid-start, or when one was
    already stopped (each `stop()` is itself idempotent).

    The metrics collector doesn't expose a stop() — it's a low-frequency
    daemon thread that exits cleanly on interpreter shutdown — so we
    skip it here and let the process tear-down handle it.
    """
    try:
        from swf import peer_scraper as _idx_scraper
        _idx_scraper.stop()
    except Exception as exc:
        logger.warning("peer_scraper.stop() skipped: %s", exc)
    try:
        from swf import bundles as _bundles
        _bundles.stop_puller()
    except Exception as exc:
        logger.warning("bundles.stop_puller() skipped: %s", exc)


if __name__ == "__main__":
    raise SystemExit(main())
