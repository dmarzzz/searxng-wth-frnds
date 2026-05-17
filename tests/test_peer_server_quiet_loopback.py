"""#82: ConnectionResetError noise from loopback probes is swallowed; an
explicit counter (`loopback_reset_count`) tracks how many we've absorbed
so an operator can tell `quiet` apart from `actively-being-probed`.

Real, non-loopback errors and non-swallowable exceptions still hit
the default `handle_error` path — we don't want to mask anything that
isn't the known harmless pattern."""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from swf import peer_server


@pytest.fixture(autouse=True)
def _reset_counter():
    """Each test starts with a clean counter."""
    with peer_server._loopback_reset_lock:
        peer_server._loopback_reset_count = 0
    yield


def _instance():
    """`_QuietThreadingHTTPServer.handle_error` doesn't touch instance
    state, so we can construct a bare instance via __new__ without
    actually binding a port."""
    return peer_server._QuietThreadingHTTPServer.__new__(
        peer_server._QuietThreadingHTTPServer,
    )


def _trigger(server, exc, addr):
    """Re-raise `exc` so `sys.exc_info()` is populated, then call
    `handle_error`. Returns whether the super's handle_error was hit."""
    super_called = []

    def _spy(self, request, client_address):
        super_called.append((request, client_address))

    with patch.object(
        peer_server.ThreadingHTTPServer, "handle_error", _spy,
    ):
        try:
            raise exc
        except type(exc):
            server.handle_error(None, addr)
    return bool(super_called)


def test_loopback_connection_reset_is_swallowed():
    s = _instance()
    fellthrough = _trigger(s, ConnectionResetError(), ("127.0.0.1", 51234))
    assert fellthrough is False
    assert peer_server.loopback_reset_count() == 1


def test_loopback_broken_pipe_is_swallowed():
    s = _instance()
    _trigger(s, BrokenPipeError(), ("127.0.0.1", 51234))
    assert peer_server.loopback_reset_count() == 1


def test_loopback_socket_timeout_is_swallowed():
    s = _instance()
    _trigger(s, TimeoutError(), ("127.0.0.1", 51234))
    assert peer_server.loopback_reset_count() == 1


def test_ipv6_loopback_is_swallowed():
    s = _instance()
    _trigger(s, ConnectionResetError(), ("::1", 51234))
    assert peer_server.loopback_reset_count() == 1


def test_non_loopback_reset_falls_through():
    """A real LAN peer that RSTs is a real signal; don't swallow it."""
    s = _instance()
    fellthrough = _trigger(
        s, ConnectionResetError(), ("192.168.1.50", 51234),
    )
    assert fellthrough is True
    assert peer_server.loopback_reset_count() == 0


def test_non_swallowable_exception_falls_through():
    """A genuine programming error or OSError should not be hidden,
    even from loopback."""
    s = _instance()
    fellthrough = _trigger(s, ValueError("boom"), ("127.0.0.1", 51234))
    assert fellthrough is True
    assert peer_server.loopback_reset_count() == 0
