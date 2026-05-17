"""Smoke tests for the hivemind mDNS advertisement (#93 phase 5).

We do NOT assert on real LAN browse behaviour — that's phase 6's
two-peer integration test. These tests stub the zeroconf layer (same
strategy as `tests/test_network_change_resilience.py`'s
monkeypatch on `swf.discovery._MdnsRegistration`) and confirm:
  - service-type constant matches spec §4.3
  - `start_advertisement` calls `start()` on the registration
  - loopback bind = no advertisement (handle is None)
  - the TXT record carries the documented keys (version, pubkey, proto)
"""
from __future__ import annotations

import socket

import pytest

from swf import hivemind
from swf.hivemind import mdns as _mdns


def test_service_type_matches_spec():
    """Spec §4.3 (post-amendment 2026-05-09): `_sr-hivemind._tcp.local`.
    Trailing dot required by Bonjour. The original draft used
    `_shape-rotator-hivemind` (22 bytes), which RFC 6335 rejects —
    DNS service names must be ≤ 15 bytes. `sr-hivemind` (11 bytes)
    fits and preserves the Shape Rotator semantic."""
    assert hivemind.HIVEMIND_SERVICE_TYPE == "_sr-hivemind._tcp.local."
    # Double-check the public surface exports the same symbol via the
    # subpackage's mdns module too.
    assert _mdns.HIVEMIND_SERVICE_TYPE == hivemind.HIVEMIND_SERVICE_TYPE


def test_service_name_fits_rfc6335_15_byte_limit():
    """Regression for the silent-registration-failure bug: zeroconf
    rejects DNS service names > 15 bytes. Pin the constraint so a
    future rename can't accidentally re-break LAN discovery."""
    # `_<service>._tcp.local.` — extract the <service> portion
    # between the leading underscore and the next dot.
    svc = hivemind.HIVEMIND_SERVICE_TYPE.split(".")[0].lstrip("_")
    assert len(svc) <= 15, (
        f"service name {svc!r} ({len(svc)} bytes) exceeds RFC 6335's "
        "15-byte cap; zeroconf will silently reject the registration"
    )


def test_start_advertisement_loopback_returns_none(monkeypatch):
    """Loopback bind = mDNS advertisement is a no-op."""
    # No need to mock — the loopback gate fires before any zeroconf
    # interaction, so this works even on a CI box without zeroconf.
    handle = hivemind.start_advertisement(
        port=7777, node_name="testbox", pubkey_hex="ab" * 32,
        bind="127.0.0.1",
    )
    assert handle is None

    handle = hivemind.start_advertisement(
        port=7777, node_name="testbox", pubkey_hex="ab" * 32,
        bind="localhost",
    )
    assert handle is None


def test_start_advertisement_calls_register_with_correct_service(monkeypatch):
    """When NOT loopback, we end up calling `Zeroconf.register_service`
    with a `ServiceInfo` whose service type, port, and TXT record match
    the spec. We mock zeroconf at the import boundary to capture the
    args without touching the real LAN."""
    captured: dict = {}

    class _FakeServiceInfo:
        def __init__(self, type_, name, addresses, port, properties, server):
            captured["type_"] = type_
            captured["name"] = name
            captured["addresses"] = addresses
            captured["port"] = port
            captured["properties"] = properties
            captured["server"] = server

    class _FakeZeroconf:
        def __init__(self, *args, **kwargs):
            captured["zc_init"] = (args, kwargs)
        def register_service(self, info):
            captured["registered"] = info
        def unregister_service(self, info):
            captured["unregistered"] = info
        def close(self):
            captured["closed"] = True

    class _IPVersion:
        V4Only = "v4only"

    fake_zeroconf = type("M", (), {
        "ServiceInfo": _FakeServiceInfo,
        "Zeroconf": _FakeZeroconf,
        "IPVersion": _IPVersion,
    })()

    monkeypatch.setitem(__import__("sys").modules, "zeroconf", fake_zeroconf)

    # Stub the IP picker so we don't probe real networks.
    monkeypatch.setattr(
        "swf.discovery._outbound_ipv4", lambda: "192.168.99.42",
    )

    handle = hivemind.start_advertisement(
        port=7777,
        node_name="convent-laptop",
        pubkey_hex="ab" * 32,
        bind="0.0.0.0",
    )
    assert handle is not None

    # Service type matches spec (post-amendment 2026-05-09).
    assert captured["type_"] == "_sr-hivemind._tcp.local."
    # Instance name disambiguates from the indrex advert
    # ("convent-laptop-hivemind." not just "convent-laptop.").
    assert "convent-laptop-hivemind" in captured["name"]
    assert captured["name"].endswith(
        "._sr-hivemind._tcp.local.",
    )
    # Port = swf-node's bound port.
    assert captured["port"] == 7777
    # IP comes from the stubbed `_outbound_ipv4`.
    assert captured["addresses"] == [socket.inet_aton("192.168.99.42")]

    # TXT record schema — bytes-keyed dict.
    props = captured["properties"]
    assert props[b"version"] == b"swf-bundle-v1"
    assert props[b"proto"] == b"shape-rotator-hivemind/v1"
    assert props[b"pubkey"] == ("ab" * 32).encode()
    assert props[b"node"] == b"convent-laptop"

    # `registered` flag tracks success.
    assert handle.registered is True

    # Cleanup hits unregister + close.
    handle.stop()
    assert captured.get("unregistered") is captured["registered"]
    assert captured.get("closed") is True


def test_register_failure_is_loud_and_marks_handle_unregistered(monkeypatch, caplog):
    """Regression for the silent-failure bug: zeroconf rejecting the
    registration (e.g. service name too long) MUST surface as an
    ERROR-level log even WITHOUT verbose logging, AND the handle's
    `registered` property must report False so the peer_server boot
    log can downgrade its 'advertising' message to a clear failure
    notice. #79 migrated `_log_error` to `logger.error(...)` — caplog
    is now the right capture surface."""
    import logging
    class _FakeServiceInfo:
        def __init__(self, *args, **kwargs):
            pass

    class _FakeZeroconf:
        def __init__(self, *args, **kwargs):
            pass

        def register_service(self, info):
            raise OSError(
                "Service name (shape-rotator-hivemind) must be <= 15 bytes",
            )

        def close(self):
            pass

    class _IPVersion:
        V4Only = "v4only"

    fake_zeroconf = type("M", (), {
        "ServiceInfo": _FakeServiceInfo,
        "Zeroconf": _FakeZeroconf,
        "IPVersion": _IPVersion,
    })()

    monkeypatch.setitem(__import__("sys").modules, "zeroconf", fake_zeroconf)
    monkeypatch.setattr(
        "swf.discovery._outbound_ipv4", lambda: "192.168.99.42",
    )
    # Verbose explicitly OFF — the failure path must NOT depend on it.
    monkeypatch.delenv("RA_VERBOSE", raising=False)
    monkeypatch.delenv("SWF_HIVEMIND_VERBOSE", raising=False)

    with caplog.at_level(logging.ERROR, logger="swf.hivemind.mdns"):
        handle = hivemind.start_advertisement(
            port=7777,
            node_name="testbox",
            pubkey_hex="ab" * 32,
            bind="0.0.0.0",
        )
    assert handle is not None
    assert handle.registered is False

    # Exactly one ERROR record from `swf.hivemind.mdns` carrying the
    # zeroconf failure message.
    matching = [
        r for r in caplog.records
        if r.name == "swf.hivemind.mdns"
        and r.levelno >= logging.ERROR
        and "register failed" in r.getMessage()
    ]
    assert matching, f"expected ERROR record; got {caplog.records!r}"
    assert "must be <= 15 bytes" in matching[0].getMessage()


def test_start_advertisement_zeroconf_missing_returns_handle_with_noop_stop(
    monkeypatch,
):
    """If zeroconf isn't installed (or import fails), we MUST NOT
    crash — the handle's `start()` is a no-op, and `stop()` likewise.
    The HTTP route still works; mDNS is a discovery convenience, not
    a correctness requirement."""
    import sys
    real_zc = sys.modules.pop("zeroconf", None)
    monkeypatch.setitem(sys.modules, "zeroconf", None)
    try:
        # Force re-import inside `start()` to hit the fake.
        handle = hivemind.start_advertisement(
            port=7777,
            node_name="ghost",
            pubkey_hex="cd" * 32,
            bind="0.0.0.0",
        )
        assert handle is not None
        handle.stop()  # must not raise
    finally:
        if real_zc is not None:
            sys.modules["zeroconf"] = real_zc


def test_start_advertisement_node_name_default_uses_hostname(monkeypatch):
    """`node_name=None` falls back to `socket.gethostname()`. We don't
    care what the actual hostname is — just that the call doesn't
    crash and returns a handle on a non-loopback bind."""
    captured: dict = {}

    class _FakeServiceInfo:
        def __init__(self, type_, name, **_):
            captured["name"] = name

    class _FakeZeroconf:
        def __init__(self, *args, **kwargs): pass
        def register_service(self, info): pass
        def unregister_service(self, info): pass
        def close(self): pass

    class _IPVersion:
        V4Only = "v4only"

    fake_zeroconf = type("M", (), {
        "ServiceInfo": _FakeServiceInfo,
        "Zeroconf": _FakeZeroconf,
        "IPVersion": _IPVersion,
    })()

    monkeypatch.setitem(__import__("sys").modules, "zeroconf", fake_zeroconf)
    monkeypatch.setattr("swf.discovery._outbound_ipv4", lambda: "10.0.0.1")

    handle = hivemind.start_advertisement(
        port=7777, pubkey_hex="ef" * 32, bind="0.0.0.0",
    )
    assert handle is not None
    # The instance name should at least contain the `-hivemind.` suffix.
    assert "-hivemind." in captured["name"]
