"""Tests for the in-memory StateStore, including TTL and atomic lockout tiers."""

import time

import pytest

from jafaal.state_store import InMemoryStateStore, TieredFailureOutcome


@pytest.fixture
def store():
    return InMemoryStateStore()


def test_set_get_delete(store):
    assert store.get("a") is None
    store.set("a", b"1")
    assert store.get("a") == b"1"
    store.delete("a")
    assert store.get("a") is None


def test_ttl_expiry(store, monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr("jafaal.state_store.time.monotonic", lambda: clock["t"])
    store.set("k", b"v", ttl_seconds=10)
    assert store.get("k") == b"v"
    clock["t"] += 11
    assert store.get("k") is None  # expired and evicted


def test_get_and_delete(store):
    store.set("k", b"v")
    assert store.get_and_delete("k") == b"v"
    assert store.get_and_delete("k") is None


def test_delete_prefix(store):
    store.set("p:1", b"a")
    store.set("p:2", b"b")
    store.set("other", b"c")
    assert store.delete_prefix("p:") == 2
    assert store.get("p:1") is None
    assert store.get("other") == b"c"


def test_iter_keys_only_live(store, monkeypatch):
    clock = {"t": 0.0}
    monkeypatch.setattr("jafaal.state_store.time.monotonic", lambda: clock["t"])
    store.set("p:live", b"1")
    store.set("p:dead", b"1", ttl_seconds=1)
    clock["t"] += 5
    assert list(store.iter_keys("p:")) == ["p:live"]


def test_increment_counts_up(store):
    assert store.increment("c", 60) == 1
    assert store.increment("c", 60) == 2
    assert store.increment("c", 60) == 3


def test_increment_is_isolated_per_key(store):
    assert store.increment("a", 60) == 1
    assert store.increment("b", 60) == 1
    assert store.increment("a", 60) == 2


def test_increment_self_expires_after_ttl(store, monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr("jafaal.state_store.time.monotonic", lambda: clock["t"])
    assert store.increment("c", 10) == 1
    assert store.increment("c", 10) == 2
    clock["t"] += 11  # window elapsed → counter evicted, next call restarts at 1
    assert store.increment("c", 10) == 1


def test_record_tiered_failure_locks_at_threshold(store):
    tiers = ((3, 60), (5, 300))
    out = None
    for _ in range(2):
        out = store.record_tiered_failure("c", "g", tiers, 3600)
        assert isinstance(out, TieredFailureOutcome)
        assert out.locked_until_epoch is None
        assert out.newly_locked is False
    # Third failure crosses the first tier.
    out = store.record_tiered_failure("c", "g", tiers, 3600)
    assert out.count == 3
    assert out.newly_locked is True
    assert out.locked_until_epoch is not None


def test_record_tiered_failure_does_not_inflate_while_locked(store):
    tiers = ((1, 300),)
    first = store.record_tiered_failure("c", "g", tiers, 3600)
    assert first.newly_locked is True
    # Already locked: subsequent calls return the same count, do not increment.
    second = store.record_tiered_failure("c", "g", tiers, 3600)
    assert second.count == first.count
    assert second.newly_locked is False


def test_record_tiered_failure_highest_tier_wins(store):
    tiers = ((2, 60), (4, 600))
    for _ in range(3):
        store.record_tiered_failure("c", "g", tiers, 3600)
    # Reset gate to force re-evaluation by using a fresh key set.
    out = store.record_tiered_failure("c2", "g2", ((1, 30), (2, 120)), 3600)
    assert out.newly_locked is True
    now = int(time.time())
    assert out.locked_until_epoch is not None and out.locked_until_epoch >= now
