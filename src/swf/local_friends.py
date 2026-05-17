# SPDX-License-Identifier: AGPL-3.0-or-later
"""SearXNG offline engine that aggregates queries across trusted peers.

Drop this file into `/usr/local/searxng/searx/engines/local_friends.py`
(bind-mount via docker-compose) and register it in `settings.yml`:

    - name: local friends
      engine: local_friends
      shortcut: lf
      categories: [general]
      peers_file: /etc/swf/peers.yaml
      per_peer_timeout: 2.5
      limit: 10
      weight: 3.0                 # < local indrex (4.0), > public (1.0)
      disabled: false
      timeout: 4.0                 # must be > per_peer_timeout

Reads the same `peers.yaml` the `swf-peer` CLI writes. One file per
deployment, one source of truth, no SearXNG config reload needed when
adding/removing peers. SearXNG reloads engines on its own schedule.

v0.2 posture: plain HTTP, LAN trust, no auth. Identity verification
(Ed25519 pubkey pinning) is the 0.4 ship; see INDREX.md.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import typing as t
import urllib.error
import urllib.parse
import urllib.request

from searx.result_types import EngineResults, MainResult

logger = logging.getLogger(__name__)

# ── SearXNG engine contract ────────────────────────────────────────────────

engine_type = "offline"
categories = ["general"]
shortcut = "lf"
disabled = False
timeout = 4.0
paging = False

about = {
    "website": "https://github.com/dmarzzz/searxng-wth-frnds",
    "require_api_key": False,
    "results": "JSON",
}


# ── Module-level config (set in init) ─────────────────────────────────────

peers_file: str = "/etc/swf/peers.yaml"
per_peer_timeout: float = 2.5
limit: int = 10


_UA = "searxng-wth-frnds/local_friends"


def init(engine_settings: dict[str, t.Any]) -> bool:
    """Init hook; never fails even if peers file is missing (engine returns
    empty in that case)."""
    global peers_file, per_peer_timeout, limit  # pylint: disable=global-statement
    peers_file = os.path.expanduser(engine_settings.get("peers_file") or peers_file)
    per_peer_timeout = float(engine_settings.get("per_peer_timeout") or per_peer_timeout)
    limit = int(engine_settings.get("limit") or limit)
    # Engine stays loaded even if no peers configured yet.
    return True


# ── Peer loading (inlined — engine lives inside the searxng container and
# cannot import from the swf package on the host) ─────────────────────────


def _load_peer_urls() -> list[str]:
    """Parse peers.yaml. Accept the exact shape `swf/peers.py` writes.
    Minimal hand-parser so we don't need PyYAML inside the container.
    """
    if not os.path.exists(peers_file):
        return []
    try:
        with open(peers_file, encoding="utf-8") as fh:
            text = fh.read()
    except Exception:
        return []

    urls: list[str] = []
    cur_url: str | None = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s == "peers:":
            continue
        if s.startswith("- ") or s.startswith("-\n") or s == "-":
            if cur_url:
                urls.append(cur_url.rstrip("/"))
            cur_url = None
            s = s[2:] if s.startswith("- ") else ""
        if ":" in s:
            k, _, v = s.partition(":")
            k = k.strip()
            v = v.strip()
            if k == "url" and v:
                cur_url = v
    if cur_url:
        urls.append(cur_url.rstrip("/"))
    # Optional env override: `SWF_EXTRA_PEERS="http://a,http://b"`
    env_extra = os.environ.get("SWF_EXTRA_PEERS", "").strip()
    if env_extra:
        for u in env_extra.split(","):
            u = u.strip().rstrip("/")
            if u and u not in urls:
                urls.append(u)
    return urls


# ── HTTP fan-out ──────────────────────────────────────────────────────────


def _query_one(peer_base: str, query: str) -> list[dict]:
    url = f"{peer_base}/search?q={urllib.parse.quote(query)}&limit={limit}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": _UA, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=per_peer_timeout) as resp:
            payload = json.loads(resp.read())
    except Exception:
        return []

    peer_name = payload.get("peer") or peer_base
    out: list[dict] = []
    for r in payload.get("results") or []:
        url_ = r.get("url") or ""
        if not url_:
            continue
        out.append(
            {
                "url": url_,
                "title": r.get("title") or url_,
                "snippet": (r.get("snippet") or "")[:300],
                "seen_at": r.get("seen_at") or "",
                "peer": peer_name,
                "peer_base": peer_base,
            }
        )
    return out


# ── Entry point ───────────────────────────────────────────────────────────


def search(query: str, params) -> EngineResults:
    res = EngineResults()
    q = (query or "").strip()
    if not q:
        return res

    peers = _load_peer_urls()
    if not peers:
        return res

    # Parallel fan-out across peers. SearXNG's overall engine timeout is
    # enforced by a thread-join on the OfflineProcessor side; we keep our
    # own per-peer timeouts short so a single slow peer doesn't starve
    # the merge.
    merged: list[dict] = []
    seen: set[str] = set()
    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, len(peers))
        ) as pool:
            futs = {pool.submit(_query_one, p, q): p for p in peers}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    rows = fut.result()
                except Exception:
                    continue
                for r in rows:
                    if r["url"] in seen:
                        continue
                    seen.add(r["url"])
                    merged.append(r)
    except Exception as exc:
        logger.debug("pool error: %s", exc)
        return res

    # Order: keep insertion order (peer-relevance-ish, per-peer bm25 rank).
    for r in merged[:limit]:
        res.add(
            MainResult(
                url=r["url"],
                title=r["title"],
                content=r["snippet"],
                metadata=f"friend:{r['peer']}·{r['seen_at'][:10]}"
                if r["seen_at"]
                else f"friend:{r['peer']}",
            )
        )
    return res
