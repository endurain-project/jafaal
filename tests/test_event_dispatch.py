"""Tests for non-blocking ``AuthEventSink`` dispatch.

Event delivery runs host code (SMTP, webhooks) on the auth hot path. These tests
pin the two properties that keep a slow or hostile sink from becoming an outage:
the caller is never blocked, and the backlog is bounded.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

import jafaal
import jafaal.ports as jafaal_ports


class _SlowSink:
    """Sink whose delivery blocks until the test releases it."""

    def __init__(self):
        self.released = threading.Event()
        self.started = threading.Event()
        self.completed = 0

    async def on_new_device_login(self, event):
        self.started.set()
        await asyncio.get_running_loop().run_in_executor(None, self.released.wait)
        self.completed += 1


@pytest.fixture
def drain():
    """Guarantee the shared dispatch queue is empty before and after a test."""
    jafaal_ports.wait_for_pending_events(5.0)
    yield
    assert jafaal_ports.wait_for_pending_events(5.0)


def test_sync_dispatch_returns_before_the_sink_finishes(drain):
    sink = _SlowSink()
    jafaal.configure_event_sink(sink)
    try:
        started = time.perf_counter()
        jafaal_ports.dispatch_event("on_new_device_login", object())
        elapsed = time.perf_counter() - started

        # The whole point: the caller is not paying for the sink's I/O. Without
        # the background loop this would block for as long as the sink runs.
        assert elapsed < 0.5
        assert sink.started.wait(5.0), "delivery never reached the sink"
        assert sink.completed == 0
    finally:
        sink.released.set()
        jafaal.configure_event_sink(jafaal.NullAuthEventSink())


def test_delivery_eventually_reaches_the_sink(drain):
    sink = _SlowSink()
    sink.released.set()
    jafaal.configure_event_sink(sink)
    try:
        jafaal_ports.dispatch_event("on_new_device_login", object())
        assert jafaal_ports.wait_for_pending_events(5.0)
        assert sink.completed == 1
    finally:
        jafaal.configure_event_sink(jafaal.NullAuthEventSink())


def test_hung_sink_is_abandoned_at_the_deadline(monkeypatch, drain, caplog):
    monkeypatch.setattr(jafaal_ports, "EVENT_DISPATCH_TIMEOUT_SECONDS", 0.05)

    class HungSink:
        async def on_new_device_login(self, event):
            await asyncio.sleep(30)

    jafaal.configure_event_sink(HungSink())
    try:
        jafaal_ports.dispatch_event("on_new_device_login", object())
        # The slot must come back without waiting out the 30s sleep, or a hung
        # remote would permanently consume dispatch capacity.
        assert jafaal_ports.wait_for_pending_events(5.0)
    finally:
        jafaal.configure_event_sink(jafaal.NullAuthEventSink())
    assert any("exceeded" in message for message in caplog.messages)


def test_backlog_is_bounded_rather_than_unbounded(monkeypatch, drain, caplog):
    monkeypatch.setattr(jafaal_ports, "MAX_INFLIGHT_EVENTS", 2)
    sink = _SlowSink()
    jafaal.configure_event_sink(sink)
    try:
        for _ in range(5):
            jafaal_ports.dispatch_event("on_new_device_login", object())
        # Three of the five must have been dropped, not queued: an unbounded
        # queue turns a login flood behind a slow sink into memory exhaustion.
        assert sum("already in flight" in message for message in caplog.messages) == 3
    finally:
        sink.released.set()
        jafaal.configure_event_sink(jafaal.NullAuthEventSink())


def test_failing_sink_never_breaks_the_auth_path(drain, caplog):
    class BoomSink:
        async def on_new_device_login(self, event):
            raise RuntimeError("sink down")

    jafaal.configure_event_sink(BoomSink())
    try:
        jafaal_ports.dispatch_event("on_new_device_login", object())
        assert jafaal_ports.wait_for_pending_events(5.0)
    finally:
        jafaal.configure_event_sink(jafaal.NullAuthEventSink())
    assert any("RuntimeError" in message for message in caplog.messages)


def test_unknown_event_method_is_skipped(drain):
    class OldSink:
        """A host sink written before ``on_new_device_login`` existed."""

    jafaal.configure_event_sink(OldSink())
    try:
        jafaal_ports.dispatch_event("on_new_device_login", object())
    finally:
        jafaal.configure_event_sink(jafaal.NullAuthEventSink())


async def test_async_dispatch_is_deadline_bounded(monkeypatch):
    monkeypatch.setattr(jafaal_ports, "EVENT_DISPATCH_TIMEOUT_SECONDS", 0.05)

    class HungSink:
        async def on_refresh_token_theft_detected(self, event):
            await asyncio.sleep(30)

    jafaal.configure_event_sink(HungSink())
    try:
        started = time.perf_counter()
        await jafaal_ports.adispatch_event("on_refresh_token_theft_detected", object())
        # Awaited inline by design, but a hung sink must not hang the request.
        assert time.perf_counter() - started < 5.0
    finally:
        jafaal.configure_event_sink(jafaal.NullAuthEventSink())
