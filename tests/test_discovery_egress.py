"""Tests for `swf.discovery._outbound_ipv4` — the function that picks
the IP we advertise via mDNS.

The bug it guards against: on a VPN'd machine, the original probe
opened a UDP socket toward `8.8.8.8` and read its local-side IP. The
OS bound that to the VPN tunnel interface, so we'd advertise a
non-LAN-routable address and other peers on the same Wi-Fi couldn't
reach us. The fix layers:
  1. SWF_LAN_IP env override
  2. multicast (224.0.0.1) probe — bypasses VPN
  3. public (8.8.8.8) probe — old behavior, fallback
  4. RFC-1918 enumeration via getaddrinfo
  5. 127.0.0.1
"""
from __future__ import annotations

import socket

import pytest


@pytest.fixture
def discovery(monkeypatch):
    """Reload `swf.discovery` so module-level state is fresh."""
    import sys
    sys.modules.pop("swf.discovery", None)
    import swf.discovery as d
    return d


# ─── env override ─────────────────────────────────────────────────

def test_swf_lan_ip_env_wins_over_everything(discovery, monkeypatch):
    monkeypatch.setenv("SWF_LAN_IP", "192.168.99.42")
    # Even if the multicast/public probes return something else, the
    # env var takes precedence.
    monkeypatch.setattr(discovery, "_probe_egress_ip",
                        lambda *a, **kw: "10.1.1.1")
    assert discovery._outbound_ipv4() == "192.168.99.42"


def test_empty_env_var_does_not_short_circuit(discovery, monkeypatch):
    monkeypatch.setenv("SWF_LAN_IP", "")
    monkeypatch.setattr(discovery, "_probe_egress_ip",
                        lambda host, port: "192.168.1.42")
    assert discovery._outbound_ipv4() == "192.168.1.42"


# ─── multicast preferred over public ──────────────────────────────

def test_multicast_probe_used_first(discovery, monkeypatch):
    """On a multi-homed machine, the multicast probe gives the LAN
    egress IP. We must prefer it over the public probe even when both
    succeed."""
    monkeypatch.delenv("SWF_LAN_IP", raising=False)
    calls = []
    def fake_probe(host, port):
        calls.append(host)
        if host == "224.0.0.1":
            return "192.168.1.42"
        if host == "8.8.8.8":
            return "10.1.18.156"  # the VPN tunnel — would have lost
        return None
    monkeypatch.setattr(discovery, "_probe_egress_ip", fake_probe)
    assert discovery._outbound_ipv4() == "192.168.1.42"
    # Multicast was tried first and succeeded; public probe never ran.
    assert calls == ["224.0.0.1"]


# ─── multicast falls through to public probe ──────────────────────

def test_falls_through_to_public_probe_on_multicast_failure(
    discovery, monkeypatch
):
    """If multicast can't bind (some firewalled / restricted
    environments), fall through to the original public-IP heuristic."""
    monkeypatch.delenv("SWF_LAN_IP", raising=False)
    def fake_probe(host, port):
        if host == "224.0.0.1":
            return None
        if host == "8.8.8.8":
            return "192.168.1.42"
        return None
    monkeypatch.setattr(discovery, "_probe_egress_ip", fake_probe)
    assert discovery._outbound_ipv4() == "192.168.1.42"


# ─── loopback rejected ────────────────────────────────────────────

def test_loopback_result_is_rejected(discovery, monkeypatch):
    """If a probe returns a loopback (broken /etc/hosts setup), keep
    looking."""
    monkeypatch.delenv("SWF_LAN_IP", raising=False)
    def fake_probe(host, port):
        return "127.0.0.1"  # always loopback
    monkeypatch.setattr(discovery, "_probe_egress_ip", fake_probe)
    monkeypatch.setattr(discovery, "_first_private_ipv4",
                        lambda: "192.168.1.42")
    assert discovery._outbound_ipv4() == "192.168.1.42"


def test_zeros_treated_as_loopback(discovery):
    assert discovery._is_loopback("0.0.0.0") is True
    assert discovery._is_loopback("127.0.0.1") is True
    assert discovery._is_loopback("127.5.5.5") is True
    assert discovery._is_loopback("192.168.1.1") is False


# ─── enumeration fallback ────────────────────────────────────────

def test_first_private_ipv4_picks_rfc1918(discovery, monkeypatch):
    fake_addrs = [
        (socket.AF_INET, 0, 0, "", ("169.254.1.5", 0)),  # link-local
        (socket.AF_INET, 0, 0, "", ("192.168.1.42", 0)),
        (socket.AF_INET, 0, 0, "", ("172.20.5.1", 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **kw: fake_addrs)
    monkeypatch.setattr(socket, "gethostname", lambda: "x")
    assert discovery._first_private_ipv4() == "192.168.1.42"


def test_first_private_ipv4_skips_non_rfc1918(discovery, monkeypatch):
    fake_addrs = [
        (socket.AF_INET, 0, 0, "", ("8.8.8.8", 0)),  # public — skip
        (socket.AF_INET, 0, 0, "", ("172.32.0.1", 0)),  # 172.32 is NOT RFC-1918
    ]
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **kw: fake_addrs)
    monkeypatch.setattr(socket, "gethostname", lambda: "x")
    assert discovery._first_private_ipv4() is None


# ─── RFC-1918 helper ─────────────────────────────────────────────

def test_is_rfc1918_table(discovery):
    assert discovery._is_rfc1918("10.0.0.1") is True
    assert discovery._is_rfc1918("10.255.255.255") is True
    assert discovery._is_rfc1918("192.168.1.1") is True
    assert discovery._is_rfc1918("172.16.0.1") is True
    assert discovery._is_rfc1918("172.31.0.1") is True
    # 172.32 is OUTSIDE the 172.16/12 private range
    assert discovery._is_rfc1918("172.32.0.1") is False
    assert discovery._is_rfc1918("172.15.0.1") is False
    assert discovery._is_rfc1918("8.8.8.8") is False
    assert discovery._is_rfc1918("169.254.1.1") is False
    assert discovery._is_rfc1918("garbage") is False


# ─── absolute fallback ───────────────────────────────────────────

def test_falls_back_to_loopback_when_everything_fails(
    discovery, monkeypatch
):
    monkeypatch.delenv("SWF_LAN_IP", raising=False)
    monkeypatch.setattr(discovery, "_probe_egress_ip",
                        lambda *a, **kw: None)
    monkeypatch.setattr(discovery, "_first_private_ipv4", lambda: None)
    assert discovery._outbound_ipv4() == "127.0.0.1"
