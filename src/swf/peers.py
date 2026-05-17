"""Peer config loading and data model.

Peers config lives at `~/.config/swf/peers.yaml`:

    peers:
      - name: alice-laptop
        url: http://192.168.1.42:7777
        pubkey: null       # populated on TOFU first-contact in later ships
      - name: bob-desktop
        url: http://192.168.1.73:7777

Spec ref: INDREX.md section D (LAN discovery and peer transport).
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Peer:
    name: str
    url: str
    pubkey: str | None = None  # populated later (0.4); present here for fwd-compat

    def canonical(self) -> str:
        """Return base URL with trailing slash stripped."""
        return self.url.rstrip("/")


@dataclass
class PeerConfig:
    peers: list[Peer] = field(default_factory=list)

    @property
    def enabled_peers(self) -> list[Peer]:
        return [p for p in self.peers if p.url]


def config_path() -> Path:
    """Return `~/.config/swf/peers.yaml`, or `$SWF_CONFIG_DIR/peers.yaml`."""
    base = Path(os.environ.get("SWF_CONFIG_DIR", Path.home() / ".config" / "swf"))
    return base / "peers.yaml"


def load_peers() -> PeerConfig:
    """Load peers config. Absent file → empty PeerConfig; never raises."""
    path = config_path()
    if not path.exists():
        return PeerConfig()
    try:
        import yaml  # PyYAML is a hard dep; see pyproject
    except Exception:
        # Fallback: parse a tiny subset by hand so the package imports
        # cleanly even when yaml isn't installed.
        return _parse_peers_plain(path.read_text(encoding="utf-8"))
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return PeerConfig()
    return _from_dict(data)


def save_peers(cfg: PeerConfig) -> Path:
    """Write peers config to `config_path()` (creating parent dirs). Atomic."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# Managed by `swf-peer`. Hand-editing is fine.", "peers:"]
    if not cfg.peers:
        lines.append("  []")
    for p in cfg.peers:
        lines.append(f"  - name: {p.name}")
        lines.append(f"    url: {p.url}")
        if p.pubkey:
            lines.append(f"    pubkey: {p.pubkey}")
    body = "\n".join(lines) + "\n"

    tmp = path.with_suffix(".tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)
    return path


def _from_dict(data: dict) -> PeerConfig:
    raw = (data or {}).get("peers") or []
    peers = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        url = str(row.get("url") or "").strip()
        if not name or not url:
            continue
        pubkey = row.get("pubkey")
        peers.append(Peer(name=name, url=url, pubkey=pubkey))
    return PeerConfig(peers=peers)


def _parse_peers_plain(text: str) -> PeerConfig:
    """Fallback hand-parser for when PyYAML isn't installed. Not a general
    YAML parser; only handles the shape `save_peers` writes."""
    peers: list[Peer] = []
    cur: dict | None = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s == "peers:":
            continue
        if s.startswith("- "):
            if cur:
                _commit(cur, peers)
            cur = {}
            s = s[2:]  # strip leading '- '
        if cur is None:
            continue
        if ":" in s:
            k, _, v = s.partition(":")
            cur[k.strip()] = v.strip() or None
    if cur:
        _commit(cur, peers)
    return PeerConfig(peers=peers)


def _commit(cur: dict, peers: list[Peer]) -> None:
    name = (cur.get("name") or "").strip()
    url = (cur.get("url") or "").strip()
    if not name or not url:
        return
    peers.append(Peer(name=name, url=url, pubkey=cur.get("pubkey")))


def peer_urls(extra: Iterable[str] | None = None) -> list[str]:
    """Return the canonical URLs of all configured peers, plus any extras
    from the environment (comma-separated `SWF_PEERS`).
    """
    cfg = load_peers()
    urls = [p.canonical() for p in cfg.enabled_peers]
    env_extra = os.environ.get("SWF_PEERS", "").strip()
    if env_extra:
        for u in env_extra.split(","):
            u = u.strip().rstrip("/")
            if u and u not in urls:
                urls.append(u)
    if extra:
        for u in extra:
            u = (u or "").strip().rstrip("/")
            if u and u not in urls:
                urls.append(u)
    return urls
