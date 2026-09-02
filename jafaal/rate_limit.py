"""Pluggable rate limiting for the JAFAAL routers.

JAFAAL owns the *decision* of which endpoints are sensitive (login, MFA,
password reset, sign-up, OAuth) or write operations; the *enforcement* — the
limiter backend, its storage, and the concrete request budgets — is host
infrastructure. Routers therefore tag endpoints with a category via
:func:`limit`, and the host injects a :class:`RateLimiter` that maps each
category to a real limit (see :class:`~jafaal.settings.RateLimitSettings` for
the canonical budgets).

The default :class:`NoOpRateLimiter` enforces nothing, so JAFAAL imports and runs
without a limiter. :func:`limit` resolves the configured limiter *lazily* (on the
first request to each route, and again whenever the limiter is reconfigured), so
the host may install its limiter before **or** after importing the routers;
``create_auth_router()`` still installs it up front for clarity.
"""

from __future__ import annotations

import functools
import inspect
import threading
from collections.abc import Callable
from typing import Any, Protocol, TypeVar, cast, runtime_checkable

from jafaal._core.registry import ConfigSlot

F = TypeVar("F", bound=Callable[..., object])

#: Sensitive operations — login, MFA, password reset, sign-up, OAuth flows.
SENSITIVE: str = "sensitive"

#: Read-only polling operations with a more frequent bounded request budget.
POLLING: str = "polling"

#: Write operations — creating or mutating resources.
WRITE: str = "write"


@runtime_checkable
class RateLimiter(Protocol):
    """Maps a JAFAAL rate-limit category to an endpoint decorator.

    The host implementation resolves the category (``"sensitive"``,
    ``"polling"``, or ``"write"``) to a concrete budget and returns the
    decorator its limiter uses (e.g.
    ``slowapi``'s ``Limiter.limit("10/minute")``).
    """

    def limit(self, category: str) -> Callable[[F], F]: ...


class NoOpRateLimiter:
    """Default limiter that enforces nothing (returns the endpoint unchanged)."""

    def limit(self, category: str) -> Callable[[F], F]:
        def decorator(func: F) -> F:
            return func

        return decorator


_rate_limiter: ConfigSlot[RateLimiter] = ConfigSlot(default_factory=NoOpRateLimiter)


def configure_rate_limiter(limiter: RateLimiter) -> None:
    """Install the host-provided rate limiter.

    Call this before the routers are imported (``create_auth_router()`` does so
    automatically) so the endpoint decorators resolve the configured limiter.

    Args:
        limiter: A :class:`RateLimiter` implementation.
    """
    _rate_limiter.configure(limiter)


def get_rate_limiter() -> RateLimiter:
    """Return the configured rate limiter (the no-op default until configured)."""
    return _rate_limiter.get()


def is_enforcing() -> bool:
    """Return whether a real (non-no-op) rate limiter is installed.

    ``False`` means the :class:`NoOpRateLimiter` default is still in effect, so
    JAFAAL's endpoints are not rate-limited. ``create_auth_router`` uses this to
    warn at startup when enforcement is missing.
    """
    return not isinstance(_rate_limiter.get(), NoOpRateLimiter)


def reset_rate_limiter() -> None:
    """Reset to the no-op limiter. Intended for tests.

    :func:`limit` binds the configured limiter lazily and watches the limiter
    slot's generation counter, so resetting (or reconfiguring) the limiter
    re-binds every decorated route on its next request — no import-order
    juggling required.
    """
    _rate_limiter.reset()


def limit(category: str) -> Callable[[F], F]:
    """Rate-limit decorator for a JAFAAL endpoint category.

    The configured limiter is resolved *lazily*: the returned wrapper binds the
    limiter's decorator on its first call and re-binds automatically whenever the
    limiter is (re)configured (tracked via the limiter slot's generation
    counter). This means a host can install its limiter before or after the
    router modules are imported — unlike decoration-time binding, importing a
    router first no longer silently disables rate limiting.

    The wrapper preserves the endpoint's signature (via ``functools.wraps``) so
    FastAPI still resolves the real parameters, and matches the endpoint's
    sync/async nature so it runs in the correct execution context.

    Args:
        category: :data:`SENSITIVE`, :data:`POLLING`, or :data:`WRITE`.

    Returns:
        A decorator that wraps the endpoint and applies the configured limiter
        at request time.
    """

    def decorator(func: F) -> F:
        cache: dict[str, Any] = {"generation": None, "bound": None}
        lock = threading.Lock()

        def _bound() -> Callable[..., Any]:
            generation = _rate_limiter.generation
            if cache["generation"] != generation:
                with lock:
                    if cache["generation"] != generation:
                        cache["bound"] = get_rate_limiter().limit(category)(func)
                        cache["generation"] = generation
            return cache["bound"]

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await _bound()(*args, **kwargs)

            return cast(F, async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            return _bound()(*args, **kwargs)

        return cast(F, sync_wrapper)

    return decorator
