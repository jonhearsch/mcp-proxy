"""
Regression test for the reload/shutdown signal conflation bug: sending the
process a self-directed SIGTERM to unblock a live-reload restart must not be
mistaken for a real external shutdown request.
"""

import signal

from mcp_proxy.server import ResilientMCPProxy


def _make_proxy():
    return ResilientMCPProxy(config_path="unused.json")


def test_external_signal_sets_shutdown_event():
    proxy = _make_proxy()
    assert not proxy.restart_event.is_set()

    proxy._handle_signal(signal.SIGTERM, None)

    assert proxy.shutdown_event.is_set()


def test_reload_self_signal_does_not_set_shutdown_event():
    proxy = _make_proxy()
    # _monitor_for_reload() always sets restart_event before self-signaling.
    proxy.restart_event.set()

    proxy._handle_signal(signal.SIGTERM, None)

    assert not proxy.shutdown_event.is_set()


def test_sigint_behaves_the_same_as_sigterm():
    proxy = _make_proxy()
    proxy.restart_event.set()

    proxy._handle_signal(signal.SIGINT, None)

    assert not proxy.shutdown_event.is_set()
