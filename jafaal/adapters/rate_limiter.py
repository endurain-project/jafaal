"""Reference :class:`~jafaal.rate_limit.RateLimiter` backed by the StateStore.

JAFAAL owns *which* endpoints are rate-limited (via ``jafaal.rate_limit.limit``);
the default limiter is a no-op, so nothing is enforced until a host installs a
real one. This batteries-included adapter is that real limiter: a fixed-window,
per-client-IP request counter kept in JAFAAL's configured
:class:`~jafaal.state_store.StateStore`. It therefore needs no extra dependency
and is **process-local by default** (the in-memory store) yet **automatically
distributed** the moment the host configures
:class:`jafaal.adapters.RedisStateStore` — lockout, TOTP-replay, and rate-limit
counters then all share one backend.

Budgets come from :class:`~jafaal.settings.AuthSettings`
(:class:`~jafaal.settings.RateLimitSettings`), so tuning is config, not code.
The client IP is resolved through :func:`jafaal._core.network.get_ip_address`, so
configure ``trusted_proxies`` behind a reverse proxy (otherwise every client
shares the proxy's address). Wire it in one line::

    import jafaal
    from jafaal.adapters import StateStoreRateLimiter

    jafaal.configure_rate_limiter(StateStoreRateLimiter())
    # ...or: create_auth_router(rate_limiter=StateStoreRateLimiter()).

Rate limiting is defense-in-depth, so this limiter **fails open** (does not
block) when the client IP is unknown, the budget is malformed, or the state
store is unavailable — a limiter-infrastructure fault must never take down
authentication. Per-account and per-IP progressive lockout still apply.
"""

from __future__ import annotations

import functools
import inspect
import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar, cast

from fastapi import Request

import jafaal.rate_limit as jafaal_rate_limit
import jafaal.settings as jafaal_settings
import jafaal.state_store as jafaal_state_store
from jafaal._core import network
from jafaal.exceptions import RateLimitedError, ServiceUnavailableError

logger = logging.getLogger(__name__)

__all__ = ["StateStoreRateLimiter"]

F = TypeVar("F", bound=Callable[..., Any])

# Unit → seconds for the "<count>/<unit>" budget strings (e.g. "10/minute").
_WINDOW_SECONDS: dict[str, int] = {
    "second": 1,
    "seconds": 1,
    "minute": 60,
    "minutes": 60,
    "hour": 3600,
    "hours": 3600,
    "day": 86400,
    "days": 86400,
}


def _parse_budget(raw: str) -> tuple[int, int]:
    """Parse a ``"<count>/<unit>"`` budget into ``(count, window_seconds)``.

    Args:
        raw: e.g. ``"10/minute"`` or ``"30/hour"``.

    Returns:
        ``(count, window_seconds)``.

    Raises:
        ValueError: If ``raw`` is not ``"<int>/<unit>"`` with a known unit.
    """
    count_str, sep, unit = raw.strip().partition("/")
    if not sep:
        raise ValueError(f"Invalid rate-limit budget {raw!r}; expected e.g. '10/minute'.")
    try:
        count = int(count_str.strip())
    except ValueError as err:
        raise ValueError(f"Invalid rate-limit budget {raw!r}; count must be an integer.") from err
    window = _WINDOW_SECONDS.get(unit.strip().lower())
    if window is None:
        raise ValueError(f"Invalid rate-limit budget {raw!r}; unit must be one of {sorted(set(_WINDOW_SECONDS))}.")
    return count, window


def _as_count(raw: bytes | None) -> int:
    """Read a counter value written by ``StateStore.increment``."""
    if raw is None:
        return 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


class StateStoreRateLimiter:
    """Sliding-window, per-client-IP rate limiter over the configured StateStore.

    Args:
        fail_open: What to do when the state store is unreachable. ``True``
            (default) serves the request unthrottled and logs it — the
            per-account progressive lockout is a separate, fail-*closed*
            control, so brute-force stays bounded. ``False`` refuses with a 503
            instead, for deployments that would rather drop traffic than serve
            it without a limiter.
    """

    def __init__(self, *, fail_open: bool = True) -> None:
        self._fail_open = fail_open

    def limit(self, category: str) -> Callable[[F], F]:
        """Return a decorator that enforces ``category``'s budget on the endpoint.

        Args:
            category: :data:`jafaal.rate_limit.SENSITIVE`,
                :data:`jafaal.rate_limit.POLLING`, or
                :data:`jafaal.rate_limit.WRITE`.

        Returns:
            A decorator wrapping the endpoint with per-request enforcement,
            matching the endpoint's sync/async nature.
        """

        def decorator(func: F) -> F:
            if inspect.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    self._enforce(category, args, kwargs)
                    return await func(*args, **kwargs)

                return cast(F, async_wrapper)

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                self._enforce(category, args, kwargs)
                return func(*args, **kwargs)

            return cast(F, sync_wrapper)

        return decorator

    def _enforce(self, category: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        """Count this request and raise 429 when the client is over budget.

        Uses a **sliding** window: the previous window's count is carried over,
        weighted by how much of it still overlaps the trailing ``window``
        seconds. A plain fixed window lets a client spend its whole budget at
        the end of one bucket and again at the start of the next — 2x the
        nominal rate across the boundary, which on a login endpoint is the
        difference between the configured limit and twice it.

        On a state-store outage the behaviour follows ``fail_open``. The default
        keeps auth reachable when the store blips (the per-account progressive
        lockout is independent and fails *closed*, so brute-force is still
        bounded); ``fail_open=False`` prefers refusing traffic to serving it
        unthrottled.

        Raises:
            RateLimitedError: 429 when the client has exceeded the category's
                budget in the trailing window (carries ``Retry-After``).
        """
        request = self._find_request(args, kwargs)
        if request is None:
            return

        try:
            settings = jafaal_settings.get_settings()
            if category == jafaal_rate_limit.SENSITIVE:
                raw = settings.rate_limits.sensitive
            elif category == jafaal_rate_limit.POLLING:
                raw = settings.rate_limits.polling
            else:
                raw = settings.rate_limits.write
            limit, window = _parse_budget(raw)
        except (ValueError, RuntimeError) as err:
            logger.warning("Rate limiter disabled for this request (bad or unavailable budget): %s", err)
            return
        if limit <= 0 or window <= 0:
            return

        client_ip = network.get_ip_address(request)
        now = int(time.time())
        bucket = now // window
        prefix = f"{settings.store_key_prefix}:ratelimit:{category}:{client_ip}"

        try:
            store = jafaal_state_store.get_state_store()
            # Two keys, kept for two windows so the previous one is still
            # readable while it is being weighted in.
            count = store.increment(f"{prefix}:{bucket}", window * 2)
            previous = store.get(f"{prefix}:{bucket - 1}")
        except jafaal_state_store.StateStoreUnavailableError as err:
            if self._fail_open:
                logger.warning("Rate limiter fail-open: state store unavailable", exc_info=err)
                return
            logger.error("Rate limiter fail-closed: state store unavailable", exc_info=err)
            raise ServiceUnavailableError("Rate limiting is temporarily unavailable. Please try again.") from err

        # Fraction of the previous window still inside the trailing window.
        elapsed = now % window
        overlap = (window - elapsed) / window
        effective = count + _as_count(previous) * overlap

        if effective > limit:
            retry_after = window - elapsed
            raise RateLimitedError(
                "Rate limit exceeded. Please slow down and try again shortly.",
                retry_after=retry_after,
            )

    @staticmethod
    def _find_request(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Request | None:
        """Locate the FastAPI ``Request`` among the endpoint's resolved arguments."""
        candidate = kwargs.get("request")
        if isinstance(candidate, Request):
            return candidate
        return next((arg for arg in args if isinstance(arg, Request)), None)
