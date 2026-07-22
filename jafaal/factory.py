"""Assemble JAFAAL's sub-routers into one mountable ``APIRouter``.

:func:`create_auth_router` is the recommended integration entry point. It:

- installs the host's :class:`~jafaal.rate_limit.RateLimiter` *before* importing
  the sub-routers, so the per-endpoint rate-limit decorators resolve it;
- registers the :class:`~jafaal.exceptions.JafaalError` edge handler on the
  FastAPI ``app`` when one is provided; and
- returns an ``APIRouter`` aggregating every JAFAAL sub-router under conventional
  sub-prefixes, which the host mounts under its API root.

Each endpoint already declares its own auth guard (``Security(check_scopes, ...)``
for protected routes, nothing for the public login / SSO / token flows), so no
router-level dependency is injected here.

The default prefixes line up with the path assumptions baked into
:class:`~jafaal.settings.AuthSettings` — ``login_token_url``
(``/api/v1/auth/login``), the refresh-cookie path (``/api/v1/auth``) and the SSO
callback (``/api/v1/public/idp/callback/{slug}``) — assuming the host mounts the
aggregate under ``/api/v1``. Override :class:`RouterPrefixes` only in lockstep
with those settings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import APIRouter

import jafaal.rate_limit as jafaal_rate_limit
import jafaal.settings as jafaal_settings
import jafaal.state_store as jafaal_state_store
from jafaal.error_handler import register_exception_handlers
from jafaal.rate_limit import RateLimiter, configure_rate_limiter

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RouterPrefixes:
    """Sub-prefixes for the aggregated routers (relative to the host's API root).

    Defaults assume the aggregate is mounted under ``/api/v1`` and match the
    path assumptions in :class:`~jafaal.settings.AuthSettings`.
    """

    auth: str = "/auth"
    sessions: str = "/auth/sessions"
    api_keys: str = "/auth/api-keys"
    identity_providers: str = "/auth/idp"
    identity_providers_public: str = "/public/idp"
    password_reset: str = "/auth"
    sign_up: str = "/auth"


def _warn_on_insecure_defaults() -> None:
    """Log startup warnings when security-relevant defaults are still in effect.

    Two silent-by-default footguns are surfaced here, at the single integration
    entry point, so an operator sees them in the logs:

    * the no-op rate limiter (endpoints are not rate-limited); and
    * the process-local in-memory state store in a *deployed* environment (a
      multi-worker / multi-replica deployment then keeps lockout and TOTP-replay
      state per-worker, weakening both).
    """
    if not jafaal_rate_limit.is_enforcing():
        logger.warning(
            "JAFAAL rate limiting is not configured: the no-op limiter is active, so login / MFA / "
            "password-reset / refresh endpoints are NOT rate-limited. Pass rate_limiter= to "
            "create_auth_router() (or call jafaal.configure_rate_limiter(...)) with a real limiter in "
            "production. Per-account progressive lockout still applies."
        )

    deployed = jafaal_settings.is_configured() and jafaal_settings.get_settings().is_deployed
    if deployed and isinstance(jafaal_state_store.get_state_store(), jafaal_state_store.InMemoryStateStore):
        logger.warning(
            "JAFAAL is using the in-memory StateStore in a deployed environment. It is process-local, "
            "so a multi-worker / multi-replica deployment keeps progressive-lockout counters and "
            "TOTP-replay markers per-worker, weakening brute-force and replay protection. Configure a "
            "distributed backend via jafaal.configure_state_store(...) (e.g. jafaal.adapters.RedisStateStore)."
        )


def create_auth_router(
    *,
    app: FastAPI | None = None,
    rate_limiter: RateLimiter | None = None,
    prefixes: RouterPrefixes | None = None,
) -> APIRouter:
    """Build the aggregated JAFAAL auth router.

    Args:
        app: When provided, the :class:`~jafaal.exceptions.JafaalError` exception
            handler is registered on it. Omit it and call
            :func:`~jafaal.error_handler.register_exception_handlers` yourself if
            you assemble the app differently.
        rate_limiter: The host's rate limiter. Installed before the sub-routers
            are imported so their decorators resolve it. Defaults to the no-op
            limiter already in effect (no enforcement).
        prefixes: Override the default sub-prefixes (keep them in lockstep with
            :class:`~jafaal.settings.AuthSettings` path fields).

    Returns:
        An ``APIRouter`` the host mounts under its API root, e.g.::

            app.include_router(create_auth_router(app=app), prefix="/api/v1")
    """
    if rate_limiter is not None:
        configure_rate_limiter(rate_limiter)
    if app is not None:
        register_exception_handlers(app)
    prefixes = prefixes or RouterPrefixes()

    _warn_on_insecure_defaults()

    # Import the sub-routers lazily: the rate-limit decorators bind the
    # configured limiter at decoration (import) time, so the limiter must be
    # installed first (above).
    from jafaal.api_keys.router import router as api_keys_router
    from jafaal.identity_providers.public_router import router as idp_public_router
    from jafaal.identity_providers.router import router as idp_router
    from jafaal.password_reset_tokens.router import router as password_reset_router
    from jafaal.router import router as auth_router
    from jafaal.sessions.router import router as sessions_router
    from jafaal.sign_up_tokens.router import router as sign_up_router

    aggregate = APIRouter()
    aggregate.include_router(auth_router, prefix=prefixes.auth, tags=["auth"])
    aggregate.include_router(sessions_router, prefix=prefixes.sessions, tags=["sessions"])
    aggregate.include_router(api_keys_router, prefix=prefixes.api_keys, tags=["api_keys"])
    aggregate.include_router(idp_router, prefix=prefixes.identity_providers, tags=["identity_providers"])
    aggregate.include_router(
        idp_public_router,
        prefix=prefixes.identity_providers_public,
        tags=["identity_providers"],
    )
    aggregate.include_router(password_reset_router, prefix=prefixes.password_reset, tags=["password_reset"])
    aggregate.include_router(sign_up_router, prefix=prefixes.sign_up, tags=["sign_up"])
    return aggregate
