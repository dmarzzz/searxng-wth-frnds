"""Peer discovery: mDNS primary, Tailscale fallback, explicit config last.

Returns the full set of reachable peers by unioning three sources:

  1. `peers.yaml` (explicit, user-managed via `swf-peer`). Authoritative.
  2. mDNS advertisements on the local LAN (`_indrex._tcp.local.`).
  3. Tailscale tailnet peers (detected via `tailscale status --json`,
     probed for `/.well-known/indrex`).

Spec ref: INDREX.md section D.

v0.3 posture: plain TXT, no circle-secret encryption yet. Encryption
of mDNS advertisements ships alongside identity in 0.4 (pubkey shown
in clear is fine; it's an identifier, not a secret). Circle-secret
service-name fingerprinting ships in 0.5 when we have the shared key.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field

from swf import __version__ as SWF_VERSION
from swf.peers import Peer, load_peers

_SERVICE_TYPE = "_indrex._tcp.local."

logger = logging.getLogger(__name__)


# ── node event ring (docs/SYNC.md §13) ────────────────────────────────
#
# `browse_mdns` is called periodically by callers like
# `discover_all_peers` (each peer-scraper tick) and the sync loop's
# default discover_fn. We piggyback on those existing invocations to
# emit `mdns_peer_appeared` / `mdns_peer_disappeared` into the
# unified node event log, with a per-pubkey re-announce dedupe so
# mDNS's natural re-broadcast doesn't spam the renderer feed.
#
# State is module-level (per-process) and guarded by a lock — the
# emit hot path on the zeroconf callback thread must not block the
# main scraper.
_mdns_seen_pubkeys: set[str] = set()
_mdns_last_appear_ms: dict[str, int] = {}
# instance_name → (pubkey, peer_name). Populated on appear so the
# disappear callback (which only gets the instance name; the
# zeroconf cache has already evicted the TXT record by then) can
# resolve the right pubkey to fire `mdns_peer_disappeared` with.
_mdns_instance_to_peer: dict[str, tuple[str, str]] = {}
_mdns_state_lock = threading.Lock()
# 60s dedupe window: mDNS service caches re-announce every ~25s on
# many implementations; we want one appear event per real
# online→offline→online transition, not one per re-broadcast.
_MDNS_APPEAR_DEDUPE_MS = 60_000


def _own_pubkey_for_mdns_filter() -> str:
    """Resolve our own pubkey so the appear/disappear emitters don't
    fire for self-loop mDNS broadcasts. Best-effort + cached on the
    identity module's side; failure returns empty string (which won't
    match any real pubkey)."""
    try:
        from swf.identity import get_or_create_identity
        return (get_or_create_identity().pub_b64 or "")
    except Exception:
        return ""


def _emit_mdns_appeared(
    *,
    instance_name: str,
    peer_pubkey: str,
    peer_name: str,
    peer_url: str,
    txt: dict,
) -> None:
    """Fire `mdns_peer_appeared` with the 60s dedupe gate.

    Wrapped in try/except so a ring-buffer failure never breaks
    discovery. Called under no locks held by the caller other than
    the zeroconf listener's own internal lock.
    """
    now_ms = int(time.time() * 1000)
    with _mdns_state_lock:
        last = _mdns_last_appear_ms.get(peer_pubkey, 0)
        # Always record the instance→peer mapping so the disappear
        # callback can resolve the pubkey, even when the appear event
        # itself is suppressed by the dedupe window.
        _mdns_instance_to_peer[instance_name] = (peer_pubkey, peer_name)
        if (now_ms - last) < _MDNS_APPEAR_DEDUPE_MS:
            # Within the re-announce window; don't re-fire.
            _mdns_seen_pubkeys.add(peer_pubkey)
            return
        _mdns_last_appear_ms[peer_pubkey] = now_ms
        _mdns_seen_pubkeys.add(peer_pubkey)
    try:
        from swf.sync.event_log import emit_node_event
        # Surface a short summary of the TXT record so the renderer
        # can show what version / protocol the peer advertises
        # without us shipping a dict-of-arbitrary-bytes.
        txt_summary = " ".join(
            f"{k}={v}"
            for k, v in sorted((txt or {}).items())
            if k in ("v", "proto", "node", "port")
        )
        emit_node_event(
            "mdns_peer_appeared",
            category="mdns",
            peer_pubkey=peer_pubkey,
            peer_name=peer_name,
            peer_url=peer_url,
            txt_record_summary=txt_summary,
        )
    except Exception:
        # Event emission must never break discovery.
        pass


def _emit_mdns_disappeared(*, peer_pubkey: str, peer_name: str) -> None:
    """Fire `mdns_peer_disappeared` and clear the appear-dedupe stamp.

    Clearing the stamp means a re-announce after a real removal will
    re-fire `mdns_peer_appeared` immediately rather than getting eaten
    by the 60s window.
    """
    with _mdns_state_lock:
        _mdns_seen_pubkeys.discard(peer_pubkey)
        _mdns_last_appear_ms.pop(peer_pubkey, None)
    try:
        from swf.sync.event_log import emit_node_event
        emit_node_event(
            "mdns_peer_disappeared",
            category="mdns",
            peer_pubkey=peer_pubkey,
            peer_name=peer_name,
        )
    except Exception:
        pass


def reset_mdns_dedupe_for_tests() -> None:
    """Test-only: clear the per-pubkey appear-dedupe state."""
    with _mdns_state_lock:
        _mdns_seen_pubkeys.clear()
        _mdns_last_appear_ms.clear()
        _mdns_instance_to_peer.clear()


def _log(msg: str) -> None:
    # #79: legacy verbose-gated info log. The logger level (DEBUG when
    # RA_VERBOSE / SWF_VERBOSE is set, INFO otherwise) handles the gate
    # for us; we keep this helper as a thin shim so the call sites
    # below don't have to all change at once.
    logger.debug("%s", msg)


def _outbound_ipv4() -> str:
    """Find the local IP that LAN peers will actually be able to reach.

    Tried in order:

      1. `SWF_LAN_IP` env override — when nothing else works, the
         operator can pin the right address explicitly.
      2. UDP-connect to the all-hosts multicast group (`224.0.0.1`).
         Multicast never transits a VPN tunnel, so the OS picks the
         LAN interface for the egress, even on multi-homed machines.
      3. UDP-connect to a public IP (`8.8.8.8`). The original
         heuristic. Picks an internet-egress interface — which on a
         VPN'd machine is the VPN tunnel IP, not the LAN IP.
      4. Enumerate interfaces and pick the first RFC-1918 / non-
         loopback / non-link-local address.
      5. Fall back to `127.0.0.1` (mDNS advertise will then be
         skipped by the caller's own loopback guard).

    Why the layering: `_outbound_ipv4` is what mDNS advertises as
    the SRV A-record. If we advertise a VPN tunnel IP, peers on the
    same Wi-Fi can't reach us. The multicast probe is the cheapest
    way to ask the OS "which interface is on my LAN" without
    enumerating every NIC.
    """
    # 1. Operator override — wins unconditionally, BUT pass-4 finding
    # #8: validate that the env var is actually an IP. A junk value
    # like "not.an.ip" used to be returned verbatim; downstream
    # `socket.inet_aton` then raised inside the broad `except` in
    # `_MdnsRegistration.start()` and the operator got NO warning that
    # mDNS wasn't advertising. Now: log to stderr and fall through.
    env = (os.environ.get("SWF_LAN_IP") or "").strip()
    if env:
        import ipaddress as _ipa
        try:
            _ipa.ip_address(env)
            return env
        except ValueError:
            logger.warning(
                "SWF_LAN_IP=%r is not a valid IP address — "
                "falling through to auto-detect.", env,
            )

    # 2. Multicast probe: 224.0.0.1 is RFC 1112 "all-hosts" on the
    # local segment, scoped to TTL=1. The kernel picks the LAN
    # egress interface even when a VPN owns the default route.
    ip = _probe_egress_ip("224.0.0.1", 9)  # port doesn't matter
    if ip and not _is_loopback(ip):
        return ip

    # 3. Public-internet probe (the original behavior). Works on
    # single-homed machines; picks the wrong interface on VPN'd
    # ones.
    ip = _probe_egress_ip("8.8.8.8", 80)
    if ip and not _is_loopback(ip):
        return ip

    # 4. Last resort: enumerate via getaddrinfo and pick a private IP.
    private = _first_private_ipv4()
    if private:
        return private

    return "127.0.0.1"


def _probe_egress_ip(target_ip: str, target_port: int) -> str | None:
    """UDP-connect (no packet sent) and read the local-side IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, target_port))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "0.0.0.0"


def _first_private_ipv4() -> str | None:
    """Enumerate all addresses tied to the local hostname and return
    the first RFC-1918 one. Best-effort — empty when the host has no
    private addresses (rare; usually means the user's LAN is on a
    weird subnet)."""
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None,
                                   family=socket.AF_INET)
    except socket.gaierror:
        return None
    for _f, _t, _p, _c, sockaddr in infos:
        ip = sockaddr[0]
        if _is_loopback(ip):
            continue
        if _is_rfc1918(ip):
            return ip
    return None


def _is_rfc1918(ip: str) -> bool:
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".", 2)[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    return False


def _short_hostname(name: str) -> str:
    """Strip a trailing `.local` from a hostname.

    Bonjour service-instance names are `<simple>._service._tcp.local.`.
    macOS's `socket.gethostname()` often already returns `foo.local`,
    which produced the malformed instance `foo.local._indrex._tcp.local.`
    that some clients silently fail to browse."""
    n = name.strip(".")
    if n.lower().endswith(".local"):
        n = n[:-6]
    return n


@dataclass
class DiscoveredPeer:
    name: str
    url: str
    source: str  # "config" | "mdns" | "tailscale"
    pubkey: str | None = None
    meta: dict = field(default_factory=dict)

    def to_peer(self) -> Peer:
        return Peer(name=self.name, url=self.url, pubkey=self.pubkey)


# ── mDNS via python-zeroconf ──────────────────────────────────────────────


class _MdnsRegistration:
    """Registers our peer_server on the LAN via mDNS. Idempotent start/stop."""

    def __init__(self, port: int, node_name: str, pubkey: str | None = None):
        self.port = port
        self.node_name = node_name
        self.pubkey = pubkey or ""
        self._zeroconf = None
        self._info = None

    def start(self) -> None:
        try:
            from zeroconf import IPVersion, ServiceInfo, Zeroconf
        except Exception as exc:
            _log(f"zeroconf unavailable, skipping mDNS registration: {exc}")
            return
        addr = _outbound_ipv4()
        # Keep instance name stable across restarts so peers rediscover us.
        # Strip any `.local` already in node_name to avoid the malformed
        # `foo.local._indrex._tcp.local.` instance name.
        #
        # Two-node-on-one-host disambiguation: the instance name MUST be
        # unique per-process on a given host, otherwise Bonjour dedupes
        # both registrations into a single visible advertisement and the
        # second node is silently invisible to mDNS browsers (this was
        # observed in a local two-node E2E test where both processes
        # advertised as `<hostname>` and only one showed up in
        # `dns-sd -B`). We include the port — it's already unique per
        # process on a host (you can't bind two listeners to the same
        # port), and it's stable across restarts (operators don't change
        # ports day-to-day). The human-readable node name stays in the
        # `node` TXT record for UI display, and `pk` carries the
        # cryptographic identity for security-sensitive consumers.
        short = _short_hostname(self.node_name)
        instance = f"{short}-{self.port}.{_SERVICE_TYPE}"
        txt = {
            b"v": SWF_VERSION.encode(),
            b"proto": b"searxng-wth-frnds/v0.3",
            b"node": short.encode(),
            b"port": str(self.port).encode(),
        }
        if self.pubkey:
            txt[b"pk"] = self.pubkey.encode()
        self._zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self._info = ServiceInfo(
            _SERVICE_TYPE,
            instance,
            addresses=[socket.inet_aton(addr)],
            port=self.port,
            properties=txt,
            server=f"{short}.local.",
        )
        try:
            self._zeroconf.register_service(self._info)
            _log(f"registered mDNS instance={instance} at {addr}:{self.port}")
        except Exception as exc:
            _log(f"mDNS register failed: {exc}")

    def stop(self) -> None:
        if self._zeroconf is None:
            return
        try:
            if self._info is not None:
                self._zeroconf.unregister_service(self._info)
            self._zeroconf.close()
            _log("unregistered mDNS")
        except Exception:
            pass


def register_mdns(port: int, node_name: str | None = None, pubkey: str | None = None) -> _MdnsRegistration:
    """Start advertising this peer_server via mDNS. Returns a handle whose
    `.stop()` unregisters. Zero-dep fallback: if `zeroconf` isn't
    installed, the call is a no-op (returns a handle that does nothing).
    """
    reg = _MdnsRegistration(port=port, node_name=node_name or socket.gethostname(), pubkey=pubkey)
    reg.start()
    return reg


# ── network-change watchdog ───────────────────────────────────────
#
# Field bugs covered by this watchdog:
#   1. VPN flips on/off → outbound IPv4 changes, mDNS still advertises
#      stale address. Re-register so peers find us at the new IP.
#   2. Operator joins a new Wi-Fi network → IP also changes, AND
#      previously-discovered peers from the old network are now
#      unreachable on this side too. Peers that hit `verify:http_error`
#      on the previous network are stuck in exponential backoff
#      (up to 1h) even though the new network might have them online
#      under a different address.
#
# On every IP change we:
#   - re-register our mDNS advertisement (so producers find us)
#   - fire registered hooks (so the scraper can clear its discovery
#     URL cache and reset backoff counters)
#   - emit an `ip_changed` log line for the operator
#
# Hooks instead of direct calls so `discovery.py` doesn't import the
# scraper (avoids the circular dep: scraper imports discovery).

_WATCH_INTERVAL_S = 30.0
_watchdog_thread = None  # type: ignore[var-annotated]
_watchdog_stop = threading.Event()
_ip_change_hooks: list = []
_ip_change_hooks_lock = threading.Lock()


def register_ip_change_hook(fn) -> None:
    """Register a callable invoked on every detected IP change.
    The callable receives `(old_ip: str, new_ip: str)` and MUST NOT
    raise (the watchdog catches but we'd rather you didn't). Hooks
    are called sequentially in registration order.

    Used by the peer scraper to clear its discovery URL cache and
    reset every peer's backoff counter — since the old failures were
    against a now-irrelevant network."""
    with _ip_change_hooks_lock:
        if fn not in _ip_change_hooks:
            _ip_change_hooks.append(fn)


def clear_ip_change_hooks() -> None:
    """For tests."""
    with _ip_change_hooks_lock:
        _ip_change_hooks.clear()


def _fire_ip_change_hooks(old_ip: str, new_ip: str) -> None:
    with _ip_change_hooks_lock:
        hooks = list(_ip_change_hooks)
    for fn in hooks:
        try:
            fn(old_ip, new_ip)
        except Exception as exc:
            _log(f"ip-change hook {fn!r} failed: {exc}")


def start_ip_change_watchdog(reg: _MdnsRegistration) -> None:
    """Spawn the background watcher. No-op if already running.
    `reg` is the live registration object; the watchdog mutates it
    in place via stop()/re-instantiate-and-start()."""
    global _watchdog_thread
    if _watchdog_thread is not None and _watchdog_thread.is_alive():
        return

    state = {"reg": reg, "ip": _outbound_ipv4()}

    def _loop():
        while not _watchdog_stop.is_set():
            _watchdog_stop.wait(timeout=_WATCH_INTERVAL_S)
            if _watchdog_stop.is_set():
                return
            try:
                new_ip = _outbound_ipv4()
            except Exception:
                continue
            if new_ip == state["ip"]:
                continue
            old_ip = state["ip"]
            state["ip"] = new_ip
            _log(f"outbound IPv4 changed {old_ip} → {new_ip}; "
                 f"re-registering mDNS + firing network-change hooks")
            with contextlib.suppress(Exception):
                state["reg"].stop()
            try:
                fresh = _MdnsRegistration(
                    port=state["reg"].port,
                    node_name=state["reg"].node_name,
                    pubkey=state["reg"].pubkey,
                )
                fresh.start()
                state["reg"] = fresh
            except Exception as exc:
                _log(f"mDNS re-register failed after IP flip: {exc}")
            _fire_ip_change_hooks(old_ip, new_ip)

    _watchdog_stop.clear()
    _watchdog_thread = threading.Thread(
        target=_loop, daemon=True, name="swf-network-watchdog",
    )
    _watchdog_thread.start()


def stop_ip_change_watchdog() -> None:
    """Stop the watcher; for tests + clean shutdown."""
    global _watchdog_thread
    _watchdog_stop.set()
    t = _watchdog_thread
    if t is not None and t.is_alive():
        t.join(timeout=2.0)
    _watchdog_thread = None


def _parse_txt_dict(props: dict) -> dict:
    """Normalize zeroconf's bytes-keyed dict into a str-keyed dict."""
    out: dict = {}
    for k, v in (props or {}).items():
        try:
            k_s = k.decode() if isinstance(k, bytes) else str(k)
            v_s = v.decode() if isinstance(v, bytes) else (str(v) if v is not None else "")
            out[k_s] = v_s
        except Exception:
            continue
    return out


def browse_mdns(timeout: float = 1.5) -> list[DiscoveredPeer]:
    """Browse the LAN for `_indrex._tcp.local.` services. Returns after
    `timeout` seconds (mDNS is async; we sleep to collect responses).

    Filters out our own advertisement by hostname match.
    """
    try:
        from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf
    except Exception as exc:
        _log(f"zeroconf unavailable: {exc}")
        return []

    hits: dict[str, DiscoveredPeer] = {}
    own_pk = _own_pubkey_for_mdns_filter()

    # Surface NotRunningException specifically so we can skip-and-retry
    # instead of letting the browser callback raise into the zeroconf
    # event loop (which would leave the browser permanently blind).
    try:
        from zeroconf import NotRunningException  # type: ignore
    except Exception:  # pragma: no cover — older zeroconf
        try:
            from zeroconf._exceptions import NotRunningException  # type: ignore
        except Exception:
            class NotRunningException(Exception): pass  # type: ignore

    class _Listener(ServiceListener):
        def add_service(self, zc, type_, name):  # noqa: D401,N802
            # Startup race: a service-found event can fire before
            # zeroconf's async core finishes initializing. Skip this
            # tick — the service will be re-announced and we'll catch
            # it next time. Without this, the exception bubbles into
            # zeroconf's dispatcher and leaves the browser dead.
            try:
                info = zc.get_service_info(type_, name, timeout=1000)
            except NotRunningException:
                _log(f"mdns: zeroconf not ready yet, deferring {name}")
                return
            if info is None or not info.addresses:
                return
            addr = socket.inet_ntoa(info.addresses[0])
            port = info.port
            txt = _parse_txt_dict(info.properties)
            node = txt.get("node") or name.replace(_SERVICE_TYPE, "").strip(".")
            # Self-loop filtering happens downstream in
            # `peer_scraper._seed_peers_from_discovery` and
            # `_bootstrap_from_peers_yaml` — they compare the discovered
            # `pubkey` against the local node's own pubkey, which is
            # the cryptographically correct identity test. We used to
            # filter here by hostname (`node == own_host`), but that
            # broke the legitimate two-nodes-on-one-host case
            # (dev/test, redundant operators) — both nodes share the
            # hostname, so a hostname filter eats the peer entirely.
            url = f"http://{addr}:{port}"
            pubkey = txt.get("pk") or None
            hits[url] = DiscoveredPeer(
                name=node,
                url=url,
                source="mdns",
                pubkey=pubkey,
                meta={"protocol": txt.get("proto", ""), "version": txt.get("v", "")},
            )
            _log(f"mdns discovered {node} at {url}")
            # Emit `mdns_peer_appeared` (subject to 60s dedupe). Skip
            # our own broadcast — `own_pk` is the identity-resolved
            # base64url pubkey; the TXT `pk` field carries the same
            # form. Peers without a pubkey (legacy or misconfigured)
            # also skip — there's no stable identifier to dedupe on.
            if pubkey and pubkey != own_pk:
                _emit_mdns_appeared(
                    instance_name=name,
                    peer_pubkey=pubkey,
                    peer_name=node,
                    peer_url=url,
                    txt=txt,
                )

        def update_service(self, zc, type_, name):
            self.add_service(zc, type_, name)

        def remove_service(self, zc, type_, name):
            # zeroconf invokes this when a TTL expires or the peer
            # explicitly unregisters. The TXT record has already
            # been evicted from the zeroconf cache, so we resolve
            # the pubkey via the instance→peer map we populated on
            # appear.
            with _mdns_state_lock:
                entry = _mdns_instance_to_peer.pop(name, None)
            if entry is not None:
                pubkey, peer_name = entry
                _emit_mdns_disappeared(
                    peer_pubkey=pubkey, peer_name=peer_name,
                )

    try:
        zc = Zeroconf(ip_version=IPVersion.V4Only)
        try:
            ServiceBrowser(zc, _SERVICE_TYPE, _Listener())
            time.sleep(timeout)
        finally:
            zc.close()
    except Exception as exc:
        _log(f"mdns browse error: {exc}")

    return list(hits.values())


# ── Tailscale fallback ────────────────────────────────────────────────────


def detect_tailscale_peers(timeout: float = 2.0) -> list[DiscoveredPeer]:
    """If `tailscale` is installed and authenticated, enumerate peers
    from `tailscale status --json` and probe each for `/.well-known/indrex`
    on the default `_indrex._tcp` port (7777). Silently returns [] when
    Tailscale isn't present.
    """
    try:
        proc = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0 or not proc.stdout:
        return []
    try:
        data = json.loads(proc.stdout)
    except Exception:
        return []

    peers = (data.get("Peer") or {}).values()
    out: list[DiscoveredPeer] = []
    for p in peers:
        hostname = (p.get("HostName") or "").strip()
        if not hostname or not (p.get("Online") and p.get("TailscaleIPs")):
            continue
        ip = p.get("TailscaleIPs", [None])[0]
        if not ip:
            continue
        # Fixed default port; users with custom ports still work through
        # explicit peers.yaml. (Making this configurable per-peer is a v0.3.1
        # task and is low priority given peers.yaml already covers it.)
        url = f"http://{ip}:7777"
        # Probe opportunistically; non-indrex hosts in the tailnet won't
        # respond and we quietly skip them.
        if _probe_indrex(url, timeout=1.0):
            out.append(
                DiscoveredPeer(
                    name=hostname,
                    url=url,
                    source="tailscale",
                )
            )
            _log(f"tailscale peer {hostname} at {url}")
    return out


def _probe_indrex(base_url: str, timeout: float = 1.0) -> bool:
    import urllib.error
    import urllib.request

    try:
        req = urllib.request.Request(
            base_url.rstrip("/") + "/.well-known/indrex",
            headers={"User-Agent": "swf-discovery"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read())
        return (payload.get("protocol") or "").startswith("searxng-wth-frnds")
    except Exception:
        return False


# ── Union ────────────────────────────────────────────────────────────────


def discover_all_peers(mdns_timeout: float = 1.5) -> list[DiscoveredPeer]:
    """Union of config + mDNS + Tailscale, deduplicated by URL.

    Precedence on collision: config > mdns > tailscale. That way user-pinned
    pubkeys in peers.yaml always win over anything picked up over the wire.
    """
    out: list[DiscoveredPeer] = []
    seen: set[str] = set()

    cfg = load_peers()
    for p in cfg.enabled_peers:
        url = p.canonical()
        if url in seen:
            continue
        seen.add(url)
        out.append(DiscoveredPeer(name=p.name, url=url, source="config", pubkey=p.pubkey))

    for dp in browse_mdns(timeout=mdns_timeout):
        if dp.url in seen:
            continue
        seen.add(dp.url)
        out.append(dp)

    for dp in detect_tailscale_peers():
        if dp.url in seen:
            continue
        seen.add(dp.url)
        out.append(dp)

    return out
