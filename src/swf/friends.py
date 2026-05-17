"""In-process peer HTTP client. Replaces `swf/local_friends.py` for the
path that doesn't need SearXNG.

The agent's `web_search` calls `query_friends(q)`, we fan out to every
peer in `peers.yaml` in parallel, merge responses by canonical URL.
If a peer has a pinned pubkey, we use it (today as a name-check; full
signature verification lands with 0.7+ transport).

SearXNG's `local_friends.py` engine still exists for users who run
SearXNG for its web UI. Both read the same `peers.yaml`.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from swf.canonical import canonical_url_safe
from swf.peers import load_peers

_UA = "searxng-wth-frnds/indrex-client"

logger = logging.getLogger(__name__)


def _log(msg: str) -> None:
    # #79: legacy verbose-gated info log. The logger level handles the gate.
    logger.debug("%s", msg)


@dataclass
class FriendResult:
    url: str
    title: str
    snippet: str
    seen_at: str
    peer: str          # friend's name / hostname
    peer_pubkey: str | None
    rtt_ms: int

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "title": self.title,
            "snippet": self.snippet,
            "seen_at": self.seen_at,
            "peer": self.peer,
            "peer_pubkey": self.peer_pubkey,
            "rtt_ms": self.rtt_ms,
            "source": f"friend:{self.peer}",
        }


def _query_peer(peer_base: str, expected_pubkey: str | None, query: str, limit: int, timeout: float) -> tuple[str, list[FriendResult], str | None]:
    t0 = time.time()
    url = f"{peer_base.rstrip('/')}/search?q={urllib.parse.quote(query)}&limit={limit}"
    req = urllib.request.Request(
        url, headers={"User-Agent": _UA, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.URLError as exc:
        return peer_base, [], f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
    except Exception as exc:
        return peer_base, [], f"{type(exc).__name__}: {exc}"

    try:
        payload = json.loads(raw)
    except Exception as exc:
        return peer_base, [], f"bad-json: {exc}"

    peer_name = payload.get("peer") or peer_base
    rtt = int((time.time() - t0) * 1000)

    # Pinned-pubkey soft check. A full transport-layer auth arrives with
    # 0.7 (Noise KK or TLS-pinned). Today we record pubkey drift but
    # don't drop results on it (peers behind 0.4 still work).
    if expected_pubkey:
        # Fetch /.well-known/indrex once opportunistically to compare.
        # Cheap because the peer responded already. Skip on error.
        try:
            wk_req = urllib.request.Request(
                peer_base.rstrip("/") + "/.well-known/indrex",
                headers={"User-Agent": _UA, "Accept": "application/json"},
            )
            with urllib.request.urlopen(wk_req, timeout=2.0) as wk_resp:
                wk = json.loads(wk_resp.read())
            actual = wk.get("pubkey")
            if actual and actual != expected_pubkey:
                _log(
                    f"PUBKEY DRIFT at {peer_base}: pinned={expected_pubkey[:16]}… "
                    f"actual={actual[:16]}…"
                )
                # Soft degrade: keep results but tag them.
                peer_name = peer_name + "?"
        except Exception:
            pass

    out: list[FriendResult] = []
    for r in payload.get("results") or []:
        canon = canonical_url_safe(r.get("url") or "")
        if not canon:
            continue
        out.append(
            FriendResult(
                url=canon,
                title=r.get("title") or canon,
                snippet=r.get("snippet") or "",
                seen_at=r.get("seen_at") or "",
                peer=peer_name,
                peer_pubkey=expected_pubkey,
                rtt_ms=rtt,
            )
        )
    return peer_base, out, None


def query_friends(q: str, limit: int = 8, timeout: float = 2.5) -> list[FriendResult]:
    """Fan out `q` to every peer in peers.yaml + SWF_PEERS env var.
    Returns deduped-by-URL list tagged with which peer served each hit."""
    cfg = load_peers()
    targets = [(p.canonical(), p.pubkey) for p in cfg.enabled_peers]
    env_extra = os.environ.get("SWF_PEERS", "").strip()
    if env_extra:
        for u in env_extra.split(","):
            u = u.strip().rstrip("/")
            if u and u not in {t[0] for t in targets}:
                targets.append((u, None))
    if not targets:
        return []

    merged: list[FriendResult] = []
    seen: set[str] = set()

    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        futs = {
            pool.submit(_query_peer, base, pk, q, limit, timeout): base
            for base, pk in targets
        }
        for fut in as_completed(futs):
            base, rows, err = fut.result()
            if err:
                _log(f"{base} → {err}")
                continue
            _log(f"{base} → {len(rows)} rows")
            for r in rows:
                if r.url in seen:
                    continue
                seen.add(r.url)
                merged.append(r)

    return merged
