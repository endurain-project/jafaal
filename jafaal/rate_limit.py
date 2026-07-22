"""Pluggable rate limiting for the JAFAAL routers.

JAFAAL owns the *decision* of which endpoints are sensitive (login, MFA,
password reset, sign-up, OAuth) or write operations; the *enforcement* — the
limiter backend, its storage, and the concrete request budgets — is host
infrastructure. Routers therefore tag endpoints with a category via
:func:`limit`, and the host injects a :class:`RateLimiter` that maps each
category to a real limit (see :attr:`~jafaal.settings.AuthSettings.rate_limit_sensitive`
/ :attr:`~jafaal.settings.AuthSettings.rate_limit_write` for the canonical budgets).

The default :class:`NoOpRateLimiter` enforces nothing, so JAFAAL imports and runs
without a limiter. ``create_auth_router()`` installs the host limiter *before*
importing the sub-routers, so the decorators resolve the configured limiter; a
host that imports the routers directly must call :func:`configure_rate_limiter`
first.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeVar, runtime_checkable

from jafaal._core.registry import ConfigSlot

F = TypeVar("F", bound=Callable[..., object])

#: Sensitive operations — login, MFA, password reset, sign-up, OAuth flows.
SENSITIVE: str = "sensitive"

#: Write operations — creating or mutating resources.
WRITE: str = "write"


@runtime_checkable
class RateLimiter(Protocol):
    """Maps a JAFAAL rate-limit category to an endpoint decorator.

    The host implementation resolves the category (``"sensitive"`` / ``"write"``)
    to a concrete budget and returns the decorator its limiter uses (e.g.
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

    Caveat: :func:`limit` resolves the configured limiter at *decoration*
    (import) time, so router modules already imported keep the limiter they bound
    at import. Resetting (or reconfiguring) the limiter afterwards does **not**
    re-bind those decorated routes. A host whose tests need a different limiter
    must configure it *before* importing the router modules
    (``create_auth_router`` installs it in the right order); swapping it
    afterwards only affects routers imported later.
    """
    _rate_limiter.reset()


def limit(category: str) -> Callable[[F], F]:
    """Rate-limit decorator for a JAFAAL endpoint category.

    Resolves the configured limiter at decoration time, so the host must
    configure its limiter before the decorated router module is imported.

    Args:
        category: :data:`SENSITIVE` or :data:`WRITE`.

    Returns:
        The decorator returned by the configured limiter for ``category``.
    """
    return get_rate_limiter().limit(category)
