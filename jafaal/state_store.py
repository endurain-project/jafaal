"""Ephemeral keyed state store for auth security bookkeeping.

JAFAAL keeps a little short-lived shared state — progressive-lockout counters,
pending-MFA logins, and the encrypted MFA setup secret — behind the
:class:`StateStore` port so the core never imports a concrete backend. The
default :class:`InMemoryStateStore` is process-local (correct for a single
process); a host running multiple workers or replicas configures a distributed
backend (e.g. Redis) via :func:`configure_state_store`.

Beyond plain key/value access the port exposes the few *atomic* primitives the
lockout stores need (:meth:`StateStore.get_and_delete`,
:meth:`StateStore.record_tiered_failure`) so their correctness does not depend on
the backend. Config delivery mirrors :mod:`jafaal.settings` and
:mod:`jafaal.ports` — a configured module accessor — except the store has a
working default, so :func:`get_state_store` never raises.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from jafaal.exceptions import StoreUnavailableError


class StateStoreUnavailableError(StoreUnavailableError):
    """Raised by a :class:`StateStore` when its backing store is unreachable.

    Lets the auth/MFA stores react to an infrastructure outage (surface a 503,
    or swallow a best-effort cleanup) without importing anything about the
    concrete backend. :class:`InMemoryStateStore` never raises it.
    """


@dataclass(frozen=True)
class TieredFailureOutcome:
    """Result of an atomic tiered-lockout increment.

    Attributes:
        count: The failure counter value after this attempt.
        locked_until_epoch: Wall-clock epoch (seconds) the lock is active until,
            or ``None`` when not locked.
        newly_locked: True only when *this* call created (or renewed) the lock.
    """

    count: int
    locked_until_epoch: int | None
    newly_locked: bool


@runtime_checkable
class StateStore(Protocol):
    """Ephemeral keyed state (counters, TTL flags, small blobs).

    The single seam through which the auth/MFA stores read and write short-lived
    shared state, so a store never needs to know whether it is backed by a
    process-local dict or Redis.
    """

    def get(self, key: str) -> bytes | None: ...

    def set(self, key: str, value: bytes, ttl_seconds: int | None = None) -> None: ...

    def delete(self, key: str) -> None: ...

    def delete_prefix(self, prefix: str) -> int: ...

    def get_and_delete(self, key: str) -> bytes | None: ...

    def iter_keys(self, prefix: str) -> Iterator[str]: ...

    def record_tiered_failure(
        self,
        counter_key: str,
        gate_key: str,
        tiers: tuple[tuple[int, int], ...],
        counter_ttl_seconds: int,
    ) -> TieredFailureOutcome: ...


class InMemoryStateStore:
    """Process-local :class:`StateStore` backed by a dict with per-key TTL expiry.

    Correct for a single process only — it is not shared across workers or
    replicas, so a multi-worker/replica deployment must configure a distributed
    backend instead. Access is guarded by a lock because FastAPI runs sync
    handlers in a threadpool.
    """

    def __init__(self) -> None:
        self._data: dict[str, tuple[bytes, float | None]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _is_expired(expiry: float | None) -> bool:
        return expiry is not None and expiry <= time.monotonic()

    def _live_value(self, key: str) -> bytes | None:
        """Return the unexpired value for ``key``, evicting it if it has expired."""
        entry = self._data.get(key)
        if entry is None:
            return None
        value, expiry = entry
        if self._is_expired(expiry):
            del self._data[key]
            return None
        return value

    def get(self, key: str) -> bytes | None:
        with self._lock:
            return self._live_value(key)

    def set(self, key: str, value: bytes, ttl_seconds: int | None = None) -> None:
        with self._lock:
            expiry = time.monotonic() + ttl_seconds if ttl_seconds is not None else None
            self._data[key] = (value, expiry)

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def delete_prefix(self, prefix: str) -> int:
        with self._lock:
            matching = [key for key in self._data if key.startswith(prefix)]
            for key in matching:
                del self._data[key]
            return len(matching)

    def get_and_delete(self, key: str) -> bytes | None:
        with self._lock:
            value = self._live_value(key)
            if value is not None:
                del self._data[key]
            return value

    def iter_keys(self, prefix: str) -> Iterator[str]:
        with self._lock:
            # Snapshot live matching keys under the lock; ``list(self._data)``
            # guards against the eviction that ``_live_value`` performs while
            # scanning.
            live_keys = [
                key for key in list(self._data) if key.startswith(prefix) and self._live_value(key) is not None
            ]
        return iter(live_keys)

    def record_tiered_failure(
        self,
        counter_key: str,
        gate_key: str,
        tiers: tuple[tuple[int, int], ...],
        counter_ttl_seconds: int,
    ) -> TieredFailureOutcome:
        now = int(time.time())
        with self._lock:
            # Already locked: return the current count without incrementing, so
            # a locked-out caller cannot keep inflating the counter.
            gate_bytes = self._live_value(gate_key)
            if gate_bytes is not None:
                gate_until = int(gate_bytes.decode())
                if gate_until > now:
                    counter_bytes = self._live_value(counter_key)
                    count = int(counter_bytes.decode()) if counter_bytes is not None else 0
                    return TieredFailureOutcome(count, gate_until, False)
                self._data.pop(gate_key, None)  # expired gate

            counter_bytes = self._live_value(counter_key)
            count = (int(counter_bytes.decode()) if counter_bytes is not None else 0) + 1
            self._data[counter_key] = (str(count).encode(), time.monotonic() + counter_ttl_seconds)

            lock_seconds = 0
            for threshold, tier_lock_seconds in tiers:  # ascending; last match wins
                if count >= threshold:
                    lock_seconds = tier_lock_seconds

            if lock_seconds > 0:
                gate_until = now + lock_seconds
                self._data[gate_key] = (str(gate_until).encode(), time.monotonic() + lock_seconds)
                return TieredFailureOutcome(count, gate_until, True)
            return TieredFailureOutcome(count, None, False)


# Module-global configured store. Unlike settings/ports, the state store has a
# working default (in-memory), so ``get_state_store`` never raises — JAFAAL runs
# out of the box in a single process and the host swaps in a distributed backend
# only when it needs one.
_state_store: StateStore = InMemoryStateStore()


def configure_state_store(store: StateStore) -> None:
    """Install the host-provided state store (e.g. a Redis-backed adapter).

    Args:
        store: A :class:`StateStore` implementation.
    """
    global _state_store
    _state_store = store


def get_state_store() -> StateStore:
    """Return the configured state store (the in-memory default until configured)."""
    return _state_store


def reset_state_store() -> None:
    """Reset to a fresh in-memory store. Intended for tests."""
    global _state_store
    _state_store = InMemoryStateStore()
