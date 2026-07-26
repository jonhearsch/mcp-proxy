"""
Regression test: restart backoff must escalate during a crash streak but
reset after a clean run, rather than permanently mutating self.restart_delay
(the configured initial delay) for the lifetime of the process.
"""

import mcp_proxy.server as server_module
from mcp_proxy.server import ResilientMCPProxy


def test_backoff_resets_after_clean_run_between_crashes(monkeypatch):
    initial_delay = 5
    proxy = ResilientMCPProxy(config_path="unused.json", restart_delay=initial_delay)

    # Isolate run_with_restart() from everything except the backoff logic
    # under test: no real signal handlers, config loading, proxy creation,
    # file watching, or port checks.
    monkeypatch.setattr(proxy, "setup_signal_handlers", lambda: None)
    monkeypatch.setattr(proxy, "create_proxy", lambda: True)
    monkeypatch.setattr(proxy, "setup_file_watcher", lambda: None)
    monkeypatch.setattr(proxy, "stop_file_watcher", lambda: None)
    monkeypatch.setattr(proxy, "wait_for_port_available", lambda timeout=10: True)
    monkeypatch.setattr(
        server_module,
        "load_config_with_retry",
        lambda *a, **k: (True, {"mcpServers": {"x": {"command": "npx", "args": []}}}),
    )

    call_count = 0

    def fake_run_server_with_reload():
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            # A clean run that was followed by a live-reload request.
            proxy.restart_event.set()
            return
        raise RuntimeError(f"simulated crash #{call_count}")

    monkeypatch.setattr(proxy, "run_server_with_reload", fake_run_server_with_reload)

    recorded_delays = []

    def spy_sleep_backoff(current_delay):
        # Records what run_with_restart() thought the current backoff was,
        # without actually sleeping. Ends the loop after the second crash
        # (the one after the clean run) so the test terminates.
        recorded_delays.append(current_delay)
        if len(recorded_delays) >= 2:
            proxy.shutdown_event.set()
        return current_delay * 1.5

    monkeypatch.setattr(proxy, "_sleep_backoff", spy_sleep_backoff)

    proxy.run_with_restart()

    assert call_count == 3
    # Both crashes (call #1, before the clean run, and call #3, after it)
    # should have seen the same, un-escalated initial delay.
    assert recorded_delays == [initial_delay, initial_delay]
    # self.restart_delay itself is never mutated -- it's the configured
    # initial value for the whole lifetime of the process.
    assert proxy.restart_delay == initial_delay
