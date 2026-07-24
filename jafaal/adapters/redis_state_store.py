"""Distributed :class:`~jafaal.state_store.StateStore` backed by Redis.

The default :class:`jafaal.state_store.InMemoryStateStore` is process-local, so a
multi-worker or multi-replica deployment must share the ephemeral auth state
(progressive-lockout counters, pending-MFA logins, the MFA setup secret, and
TOTP-replay markers) through a common backend. This adapter does that with
Redis.

Requires the optional ``jafaal[redis]`` extra; :func:`jafaal.configure_state_store`
installs it::

    import jafaal
    from jafaal.adapters import RedisStateStore

    jafaal.configure_state_store(RedisStateStore(url="redis://localhost:6379/0"))

The client must return ``bytes`` (``decode_responses`` left at its default of
``False``) because the store contract — and JAFAAL's lockout code — read raw
bytes.

Atomicity of the tiered-lockout increment is provided by a Redis
``WATCH``/``MULTI`` optimistic transaction (redis-py's ``transaction`` helper,
which retries on a concurrent write), so no server-side scripting is required.
Lock gates are stamped with the application-process wall clock — identical to
:class:`~jafaal.state_store.InMemoryStateStore` — so deployments should keep app
servers roughly time-synchronised (NTP).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from jafaal._core import optional_deps
from jafaal.state_store import StateStoreUnavailableError, TieredFailureOutcome

try:
    import redis as _redis
    from redis.exceptions import RedisError as _RedisError
except ImportError:  # pragma: no cover - exercised via the missing-dep guard
    _redis = None  # type: ignore[assignment]
    _RedisError = None  # type: ignore[assignment,misc]

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = ["RedisStateStore"]

# Redis errors we translate into StateStoreUnavailableError. Empty when redis is
# not installed — no client can have been constructed, so no method runs.
_REDIS_ERRORS: tuple[type[BaseException], ...] = (_RedisError,) if _RedisError is not None else ()


def _to_int(raw: Any) -> int | None:
    """Decode a Redis bytes value to ``int``, or ``None`` if absent/invalid."""
    if raw is None:
        return None
    try:
        return int(raw.decode() if isinstance(raw, bytes) else raw)
    except (AttributeError, ValueError):
        return None


class RedisStateStore:
    """A :class:`~jafaal.state_store.StateStore` backed by Redis."""

    def __init__(self, client: Any | None = None, *, url: str | None = None, **client_kwargs: Any) -> None:
        """Create the store.

        Args:
            client: A pre-built redis client (e.g. ``redis.Redis``). When given,
                the ``redis`` package need not be importable by this module.
            url: A ``redis://`` URL used to build a client when ``client`` is
                omitted.
            **client_kwargs: Extra keyword arguments forwarded to
                ``redis.Redis`` / ``redis.Redis.from_url``.
        """
        if client is not None:
            self._client = client
            return
        redis_mod = optional_deps.require(_redis, package="redis", extra="redis", feature="Redis state store")
        self._client = redis_mod.Redis.from_url(url, **client_kwargs) if url else redis_mod.Redis(**client_kwargs)

    def get(self, key: str) -> bytes | None:
        try:
            return self._client.get(key)
        except _REDIS_ERRORS as err:
            raise StateStoreUnavailableError("Redis GET failed") from err

    def set(self, key: str, value: bytes, ttl_seconds: int | None = None) -> None:
        try:
            self._client.set(key, value, ex=ttl_seconds)
        except _REDIS_ERRORS as err:
            raise StateStoreUnavailableError("Redis SET failed") from err

    def delete(self, key: str) -> None:
        try:
            self._client.delete(key)
        except _REDIS_ERRORS as err:
            raise StateStoreUnavailableError("Redis DELETE failed") from err

    def delete_prefix(self, prefix: str) -> int:
        try:
            keys = list(self._client.scan_iter(match=f"{prefix}*", count=500))
            if keys:
                self._client.delete(*keys)
            return len(keys)
        except _REDIS_ERRORS as err:
            raise StateStoreUnavailableError("Redis prefix delete failed") from err

    def get_and_delete(self, key: str) -> bytes | None:
        try:
            with self._client.pipeline() as pipe:
                pipe.get(key)
                pipe.delete(key)
                value, _ = pipe.execute()
            return value
        except _REDIS_ERRORS as err:
            raise StateStoreUnavailableError("Redis GETDEL failed") from err

    def set_if_absent(self, key: str, value: bytes, ttl_seconds: int) -> bool:
        # ``SET key value NX EX ttl`` is a single atomic server-side command, so
        # exactly one of N concurrent callers gets a truthy reply. Redis returns
        # ``None`` (not ``False``) when NX declines, hence the explicit bool().
        try:
            return bool(self._client.set(key, value, nx=True, ex=ttl_seconds))
        except _REDIS_ERRORS as err:
            raise StateStoreUnavailableError("Redis SET NX failed") from err

    def increment(self, key: str, ttl_seconds: int) -> int:
        # INCR + EXPIRE in one pipeline: atomic increment, and the key carries a
        # TTL so fixed-window rate-limit counters self-expire. The window bucket
        # lives in the key, so refreshing the TTL each call is harmless (a new
        # window uses a new key and starts the count at 1).
        try:
            with self._client.pipeline() as pipe:
                pipe.incr(key)
                pipe.expire(key, ttl_seconds)
                count, _ = pipe.execute()
            return int(count)
        except _REDIS_ERRORS as err:
            raise StateStoreUnavailableError("Redis INCR failed") from err

    def iter_keys(self, prefix: str) -> Iterator[str]:
        try:
            keys = [key.decode() for key in self._client.scan_iter(match=f"{prefix}*", count=500)]
        except _REDIS_ERRORS as err:
            raise StateStoreUnavailableError("Redis SCAN failed") from err
        return iter(keys)

    def record_tiered_failure(
        self,
        counter_key: str,
        gate_key: str,
        tiers: tuple[tuple[int, int], ...],
        counter_ttl_seconds: int,
    ) -> TieredFailureOutcome:
        # Stamp gates with the app-process wall clock so gate values are
        # comparable to jafaal._internal.security_stores (which reads them back
        # against datetime.now(UTC)) — identical to InMemoryStateStore.
        now = int(time.time())

        def _txn(pipe: Any) -> TieredFailureOutcome:
            # WATCH mode: reads execute immediately until ``multi()`` is called.
            gate_until = _to_int(pipe.get(gate_key))
            if gate_until is not None and gate_until > now:
                # Already locked — return the count without incrementing so a
                # locked-out caller cannot keep inflating the counter.
                count = _to_int(pipe.get(counter_key)) or 0
                pipe.multi()
                return TieredFailureOutcome(count, gate_until, False)

            count = (_to_int(pipe.get(counter_key)) or 0) + 1
            lock_seconds = 0
            for threshold, tier_lock_seconds in tiers:  # ascending; last match wins
                if count >= threshold:
                    lock_seconds = tier_lock_seconds

            pipe.multi()
            pipe.set(counter_key, count, ex=counter_ttl_seconds)
            if lock_seconds > 0:
                locked_until = now + lock_seconds
                pipe.set(gate_key, locked_until, ex=lock_seconds)
                return TieredFailureOutcome(count, locked_until, True)
            return TieredFailureOutcome(count, None, False)

        try:
            return self._client.transaction(_txn, counter_key, gate_key, value_from_callable=True)
        except _REDIS_ERRORS as err:
            raise StateStoreUnavailableError("Redis tiered-failure update failed") from err
