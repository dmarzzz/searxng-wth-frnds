"""Regression test: mDNS advertisement MUST include the pubkey.

Caught in the field — `swf-node --full` on a second laptop never
discovered the first because `register_mdns` was called without
`pubkey=...`. The TXT record then lacked `pk`, the consumer's
DiscoveredPeer.pubkey came back as None, and
`_seed_peers_from_discovery` filtered the row out (it requires a
pubkey to know what to verify against). End result: 5 PRs of
single-graph machinery silently never auto-discovered anything.
"""
from __future__ import annotations

from swf.discovery import _MdnsRegistration


def test_mdns_registration_carries_pubkey():
    """The internal _MdnsRegistration object must store the pubkey
    so the TXT record's `pk` key is present — that's what the
    consumer reads."""
    reg = _MdnsRegistration(port=7777, node_name="alice",
                            pubkey="my_pubkey_b64")
    assert reg.pubkey == "my_pubkey_b64"


def test_mdns_registration_pubkey_optional_for_back_compat():
    """The constructor still accepts None for callers that don't
    pass it (e.g. test fixtures, tools that aren't a real peer)."""
    reg = _MdnsRegistration(port=7777, node_name="alice")
    assert reg.pubkey == ""


def test_peer_server_main_passes_pubkey_to_register_mdns():
    """The actual fix lives in `peer_server.main`. We can't easily
    boot a server in a unit test, but we can grep the source for
    the call site to pin the contract."""
    import inspect

    from swf import peer_server
    src = inspect.getsource(peer_server)
    # The register_mdns call MUST pass `pubkey=` — anything else is
    # the bug we shipped silently for 5 PRs.
    assert "register_mdns(" in src
    # Find the call and assert pubkey= is in its arg list. Cheap
    # textual check; brittle if the call is reformatted, but a
    # test failure here is a clear signal to re-verify.
    idx = src.index("register_mdns(\n")
    block = src[idx:idx + 400]
    assert "pubkey=" in block, (
        "register_mdns is being called without pubkey= — "
        "consumers will not auto-discover this node"
    )


# ── two-nodes-on-one-host disambiguation regression ─────────────────
#
# Field bug: two swf-node processes on the same Mac collided on the
# Bonjour instance name (`<hostname>._indrex._tcp.local.`) so only one
# advertisement was visible to mDNS browsers and the second node was
# silently invisible. Discovered during a local two-node E2E of #93's
# bundle propagation.

def test_mdns_instance_name_includes_port_for_uniqueness():
    """When two processes on the same host advertise, the instance
    name MUST disambiguate them. Port is unique per-process on a
    given host (you can't bind two listeners to the same port) and
    is stable across restarts (operators don't change ports
    day-to-day), so we use it as the disambiguator."""
    import inspect

    from swf import discovery as _disc
    src = inspect.getsource(_disc._MdnsRegistration.start)
    # The instance name construction MUST include the port. Cheap
    # textual check; the actual format is `f"{short}-{self.port}.{_SERVICE_TYPE}"`.
    assert "self.port" in src and "instance" in src, (
        "_MdnsRegistration.start should weave `self.port` into the "
        "instance name to disambiguate two processes on one host"
    )
    # Pin the construction so a refactor doesn't accidentally drop
    # the port back out of the instance name.
    assert 'f"{short}-{self.port}.' in src or \
           "f'{short}-{self.port}." in src, (
        "Expected instance name format `{short}-{port}.{_SERVICE_TYPE}`. "
        "If you've changed the format, ensure two processes on one host "
        "still get distinct instance names — test it with `dns-sd -B`."
    )


def test_discovery_does_not_self_filter_by_hostname():
    """The discovery side used to filter out peers whose `node` TXT
    record matched our own hostname — which broke same-host two-node
    setups (both nodes share the hostname; the legitimate peer was
    eaten). The pubkey-based self-filter in
    `peer_scraper._seed_peers_from_discovery` is the correct
    cryptographic identity test; the hostname filter is redundant
    and harmful. This test pins that the hostname filter is gone."""
    import inspect

    from swf import discovery as _disc
    src = inspect.getsource(_disc.browse_mdns)
    # If you re-introduce a hostname-based self-filter, the same-host
    # two-node case stops working. Use peer_scraper's pubkey filter
    # instead (already in place).
    assert "if node.lower() == own_host" not in src, (
        "discover_mdns_peers should NOT filter out same-hostname peers. "
        "Use peer_scraper's pubkey-based self-loop filter instead."
    )
