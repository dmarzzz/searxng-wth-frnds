"""Hivemind mDNS advertisement: `_sr-hivemind._tcp.local.`.

Phase 5 of #93. Spec §4.3 (post-amendment, see below):
    Voxterm probes the LAN via mDNS for service
    `_sr-hivemind._tcp.local`. The convent box's swf-node advertises
    this when run with `--hivemind-sink`.

**Service-name length amendment.** The spec originally specified
`_shape-rotator-hivemind._tcp.local.`, but RFC 6335 caps DNS service
names at 15 bytes. `shape-rotator-hivemind` is 22 bytes — zeroconf
rejects the registration with `Service name (shape-rotator-hivemind)
must be <= 15 bytes`, and the advertisement silently never happens.
Shortened to `sr-hivemind` (the `sr-` prefix preserves the Shape
Rotator semantic). Voxterm clients MUST be updated in lockstep; see
the consumer-side spec amendment in the viz repo.

We mirror the design of `swf.discovery._MdnsRegistration` (the indrex
peer advertisement) but on a different service type, with a different
TXT record schema:

    version  = "swf-bundle-v1"            (the envelope magic; voxterm
                                            uses this to feature-gate)
    pubkey   = "<64 hex chars>"          (the convent's alchemist
                                            pubkey, raw hex — voxterm
                                            pins the sink by this so a
                                            spoofed sink on the same
                                            LAN is rejected before any
                                            transcripts are POSTed)
    proto    = "shape-rotator-hivemind/v1"

Loopback bind = no advertisement: mDNS-on-loopback is meaningless (no
peer can browse it), so we log + return None. The HTTP route still
works locally for tests / curl.

Public surface:
    HIVEMIND_SERVICE_TYPE
    start_advertisement(*, port, node_name, pubkey_hex, bind=None)
        → handle (or None on loopback / when zeroconf is missing)
"""
from __future__ import annotations

import logging
import socket

#: Spec §4.3 service type (post-amendment). Trailing dot is required
#: by Bonjour. Must fit in 15 bytes per RFC 6335 — see module docstring.
HIVEMIND_SERVICE_TYPE = "_sr-hivemind._tcp.local."

#: Magic the TXT record advertises. Tied to `swf.bundles.BUNDLE_MAGIC`
#: (`swf-bundle-v1`) so a future v2 sink advertises a distinguishable
#: value and old voxterm clients skip it.
_TXT_VERSION = "swf-bundle-v1"
_TXT_PROTO = "shape-rotator-hivemind/v1"

logger = logging.getLogger(__name__)


def _is_loopback_bind(bind: str | None) -> bool:
    """True if `bind` is loopback (or unset and we're running on
    127.0.0.1 by default)."""
    if not bind:
        return False
    return (
        bind.startswith("127.")
        or bind in ("localhost", "::1", "0.0.0.0")
        # 0.0.0.0 is a wildcard, not strictly loopback, but mDNS-on-
        # 0.0.0.0 is what we want to advertise (zeroconf binds to all
        # interfaces). So we DO want to advertise on 0.0.0.0. Keep the
        # check explicit to make the asymmetry obvious — see below.
    ) and bind != "0.0.0.0"


def _log(msg: str) -> None:
    """Verbose informational logging — surfaces at DEBUG.

    Pre-#79 this was gated on RA_VERBOSE / SWF_HIVEMIND_VERBOSE; the
    logger level (DEBUG when SWF_VERBOSE/RA_VERBOSE is set, INFO
    otherwise) handles the gate. For *failure* paths use `_log_error`
    — operators MUST see registration failures or they have no way to
    know voxterm clients won't discover them."""
    logger.debug("%s", msg)


def _log_error(msg: str) -> None:
    """Always-on error logging. A silent mDNS-register failure was
    the entire reason the original `_shape-rotator-hivemind` service
    name went unnoticed — the advertisement quietly failed, the boot
    log claimed success, and `dns-sd -B` was empty for weeks. Errors
    on the registration path are the load-bearing operator signal,
    so they bypass the verbose gate (logger level WARNING+ always
    shows ERROR)."""
    logger.error("%s", msg)


class _HivemindRegistration:
    """Advertises the convent box's swf-node as a hivemind sink.

    Idempotent start/stop. `start()` is a no-op if zeroconf is
    unavailable — the HTTP sink still works (voxterm clients can be
    pointed at the URL by hand), and we leave the operator's environment
    unbroken.
    """

    def __init__(
        self,
        *,
        port: int,
        node_name: str,
        pubkey_hex: str,
    ):
        self.port = port
        self.node_name = node_name
        self.pubkey_hex = pubkey_hex
        self._zeroconf = None
        self._info = None

    def start(self) -> None:
        try:
            from zeroconf import IPVersion, ServiceInfo, Zeroconf
        except Exception as exc:
            _log(f"zeroconf unavailable, skipping advertisement: {exc}")
            return

        # Outbound IPv4 picker — reuse `swf.discovery._outbound_ipv4`
        # so VPN-aware logic + `SWF_LAN_IP` overrides work for the
        # hivemind advert too (pulled in lazily so testing this module
        # doesn't load discovery at import time).
        from swf.discovery import _outbound_ipv4, _short_hostname
        addr = _outbound_ipv4()

        short = _short_hostname(self.node_name)
        # Disambiguate the instance name from the indrex advertisement
        # so a single host can advertise both without Bonjour name-
        # collision warnings ("Multiple registrations for <foo>").
        instance = f"{short}-hivemind.{HIVEMIND_SERVICE_TYPE}"
        txt = {
            b"version": _TXT_VERSION.encode(),
            b"proto": _TXT_PROTO.encode(),
            b"node": short.encode(),
        }
        if self.pubkey_hex:
            # Voxterm pins on this — see module docstring.
            txt[b"pubkey"] = self.pubkey_hex.encode()

        self._zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self._info = ServiceInfo(
            HIVEMIND_SERVICE_TYPE,
            instance,
            addresses=[socket.inet_aton(addr)],
            port=self.port,
            properties=txt,
            server=f"{short}.local.",
        )
        try:
            self._zeroconf.register_service(self._info)
            _log(
                f"registered {instance} at {addr}:{self.port} "
                f"(pubkey={self.pubkey_hex[:12]}…)",
            )
        except Exception as exc:
            # Always-on (NOT gated on verbose). A silent failure here
            # was exactly how `_shape-rotator-hivemind` (22 bytes)
            # went undiscovered for weeks — zeroconf raised, the
            # log was muted, the boot path then claimed success.
            _log_error(f"register failed: {exc}")
            # Mark the registration as failed so callers can detect it
            # (peer_server's boot log can downgrade its "advertising"
            # message to "advertisement FAILED, voxterm clients won't
            # discover this sink"). Set both to None — `stop()` already
            # handles the None case.
            self._zeroconf = None
            self._info = None
            return

    @property
    def registered(self) -> bool:
        """True iff `start()` actually got the service into Bonjour.
        False means we tried but zeroconf rejected the registration
        (e.g. service name too long, port collision); the caller's
        boot log should announce the failure rather than claim
        advertisement success. The HTTP route works regardless."""
        return self._zeroconf is not None and self._info is not None

    def stop(self) -> None:
        if self._zeroconf is None:
            return
        try:
            if self._info is not None:
                self._zeroconf.unregister_service(self._info)
            self._zeroconf.close()
            _log("unregistered")
        except Exception:
            pass


def start_advertisement(
    *,
    port: int,
    node_name: str | None = None,
    pubkey_hex: str,
    bind: str | None = None,
) -> _HivemindRegistration | None:
    """Start advertising the hivemind sink. Returns the handle, or None
    when loopback-bound (advertisement is meaningless on loopback).

    `node_name` defaults to `socket.gethostname()`. `pubkey_hex` must
    be the convent's alchemist pubkey (raw 64-char hex), so voxterm can
    pin against `.alchemists.yml` after discovery.

    `bind` is the address the swf-node was given (so we can detect
    loopback). When omitted, we always advertise — useful for tests
    that mock the mDNS layer.
    """
    if bind is not None and (
        bind.startswith("127.") or bind in ("localhost", "::1")
    ):
        _log(
            f"bind={bind!r} is loopback; skipping mDNS "
            "advertisement (HTTP route still available locally)",
        )
        return None

    reg = _HivemindRegistration(
        port=port,
        node_name=node_name or socket.gethostname(),
        pubkey_hex=pubkey_hex,
    )
    reg.start()
    return reg
