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

import jafaal.orm as jafaal_orm
import jafaal.ports as jafaal_ports
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
    webauthn: str = "/auth/webauthn"
    webauthn_public: str = "/public/webauthn"
    profile: str = "/profile"


def _warn_on_insecure_defaults() -> None:
    """Log startup warnings when security-relevant defaults are still in effect.

    Surfaced here, at the single integration entry point, so an operator sees
    them in the logs:

    * the no-op rate limiter (endpoints are not rate-limited);
    * a trust-all ``trusted_proxies`` in a *deployed* environment (any client
      can then spoof its source IP via ``X-Forwarded-For`` / ``X-Real-IP``);
    * no breached-password screening; and
    * symmetric (HS256) signing while registered clients exist, where every
      verifier also holds the power to mint.

    The in-memory state store and missing rate limiter are hard errors in a
    deployed environment. A null breach checker is also a hard error with
    deployed ``length_only`` policy unless its explicit risk opt-out is set.
    """
    deployed = jafaal_settings.is_configured() and jafaal_settings.get_settings().is_deployed

    if not deployed and not jafaal_rate_limit.is_enforcing():
        logger.warning(
            "JAFAAL rate limiting is not configured: the no-op limiter is active, so login / MFA / "
            "password-reset / refresh endpoints are NOT rate-limited. Install a real limiter — the "
            "batteries-included jafaal.adapters.StateStoreRateLimiter needs no extra dependency — via "
            "rate_limiter= on create_auth_router() (or jafaal.configure_rate_limiter(...)) in production. "
            "Per-account progressive lockout still applies."
        )

    if deployed and tuple(jafaal_settings.get_settings().network.trusted_proxies) == ("*",):
        logger.warning(
            "JAFAAL trusted_proxies is set to ('*',) in a deployed environment: every peer is trusted, so "
            "any client can spoof its source IP via X-Forwarded-For / X-Real-IP (poisoning session-IP audit "
            "records and IdP link-token IP checks). Set trusted_proxies to your reverse proxy's IPs/CIDRs."
        )

    if isinstance(jafaal_ports.get_password_breach_checker(), jafaal_ports.NullPasswordBreachChecker):
        logger.warning(
            "JAFAAL breached-password screening is not configured: the no-op checker is active, so a "
            "password known to be in a public breach corpus is accepted at sign-up, reset, and change. "
            "NIST SP 800-63B-4 §3.1.1.2 pairs 'no composition rules' with a blocklist check — JAFAAL's "
            "default policy drops the former, so install the latter: "
            "jafaal.configure_password_breach_checker(jafaal.adapters.HibpBreachChecker()) needs no "
            "credentials and sends only a five-character SHA-1 prefix."
        )

    _warn_on_symmetric_signing()


def _warn_on_symmetric_signing() -> None:
    """Warn when HS256 is signing tokens that leave the deployment.

    HS256 signs and verifies with the *same* secret, so every party that can
    verify a token can also mint one. That is fine while JAFAAL is the only thing
    reading its tokens, and it is why HS256 remains the zero-configuration
    default — an asymmetric algorithm needs key material the host has to generate
    and distribute.

    It stops being fine as soon as the tokens are handed to something else. Two
    signals say they are:

    * a **registered client** exists, so tokens are issued to an application that
      is not this process; and
    * ``jwks_uri`` is what a separate resource server would use to verify, and
      under HS256 there is nothing to publish — so a deployment that wants
      stateless verification cannot have it.

    Warned rather than refused: a single-process app that both issues and
    consumes its own tokens is a legitimate, common deployment, and HS256 is
    correct there.
    """
    if not jafaal_settings.is_configured():
        return
    settings = jafaal_settings.get_settings()
    if settings.tokens.is_asymmetric or not settings.oauth_clients:
        return
    logger.warning(
        f"JAFAAL is signing tokens with {settings.tokens.algorithm} (symmetric) while "
        f"{len(settings.oauth_clients)} OAuth client(s) are registered. The signing secret and the "
        "verification key are the same value, so anything able to verify a token can also mint one: a "
        "resource server cannot verify statelessly without being handed the power to issue. The JWKS "
        "endpoint has no key to publish and answers 404, and jwks_uri is omitted from the discovery "
        "document. Configure an asymmetric algorithm — tokens=TokenSettings(algorithm='ES256') with "
        "secrets=Secrets(private_key=<PEM>) — so verifiers get a public key instead."
    )


def _warn_on_router_prefix_mismatch(prefixes: RouterPrefixes) -> None:
    """Warn when the auth-path settings drift from the router prefixes.

    :attr:`~jafaal.settings.AuthSettings.login_token_url` (the Swagger password-
    flow URL) and :attr:`~jafaal.settings.AuthSettings.refresh_cookie_path` (the
    scope of the refresh cookie) must line up with where the auth router is
    actually mounted — i.e. end with :attr:`RouterPrefixes.auth`. A host that
    changes one without the other gets a silent, hard-to-debug break: Swagger's
    ``Authorize`` posts to the wrong URL, or the refresh cookie is scoped to a
    path that ``/refresh`` and ``/logout`` are not served under, so web sessions
    never refresh. Only the relative suffix is checked here (the host's mount
    root is applied later by ``include_router(prefix=...)``), which is exactly
    the coupling that drifts.
    """
    if not jafaal_settings.is_configured():
        return
    settings = jafaal_settings.get_settings()
    expected_login_suffix = f"{prefixes.auth}/login"
    if not settings.login_token_url.endswith(expected_login_suffix):
        logger.warning(
            f"AuthSettings.login_token_url={settings.login_token_url!r} does not end with the auth router "
            f"prefix {expected_login_suffix!r}; Swagger's 'Authorize' password flow will POST to the wrong "
            "URL. Keep login_token_url in lockstep with RouterPrefixes.auth."
        )
    if not settings.sessions.refresh_cookie_path.endswith(prefixes.auth):
        logger.warning(
            f"AuthSettings.refresh_cookie_path={settings.sessions.refresh_cookie_path!r} does not end with the auth "
            f"router prefix {prefixes.auth!r}; the refresh cookie will be scoped to a path that the /refresh "
            "and /logout endpoints are not served under, so web sessions will silently fail to refresh. Keep "
            "refresh_cookie_path in lockstep with RouterPrefixes.auth."
        )


def _ensure_rate_limiter_safe_for_deployment() -> None:
    """Refuse to run without an enforcing rate limiter in a deployed environment.

    The default :class:`~jafaal.rate_limit.NoOpRateLimiter` enforces nothing, so
    login / MFA / password-reset / refresh endpoints are not rate-limited (only
    per-account progressive lockout applies). Leaving that in place in a deployed
    environment is a silent brute-force / DoS exposure, so — mirroring
    :func:`_ensure_state_store_safe_for_deployment` — this is a hard failure at
    startup unless the host explicitly opts in via
    :attr:`~jafaal.settings.AuthSettings.allow_no_rate_limit_when_deployed`.

    Raises:
        RuntimeError: If the environment is deployed, no enforcing limiter is
            installed, and the opt-out flag is not set.
    """
    if not jafaal_settings.is_configured():
        return
    settings = jafaal_settings.get_settings()
    if not settings.is_deployed or settings.allow_no_rate_limit_when_deployed:
        return
    if not jafaal_rate_limit.is_enforcing():
        raise RuntimeError(
            "JAFAAL is running without a rate limiter in a deployed environment "
            f"(environment={settings.environment!r}). The no-op limiter enforces nothing, so "
            "login / MFA / password-reset / refresh endpoints are not rate-limited (only "
            "per-account progressive lockout applies), leaving a brute-force / DoS exposure. "
            "Install a limiter via create_auth_router(rate_limiter=...) or "
            "jafaal.configure_rate_limiter(...) — the batteries-included "
            "jafaal.adapters.StateStoreRateLimiter needs no extra dependency — or set "
            "AuthSettings.allow_no_rate_limit_when_deployed=True to accept the risk."
        )


def _ensure_state_store_safe_for_deployment() -> None:
    """Refuse to run on the in-memory state store in a deployed environment.

    The process-local :class:`~jafaal.state_store.InMemoryStateStore` is correct
    for a single process only; in a multi-worker / multi-replica deployment it
    fragments progressive-lockout counters and TOTP-replay markers per worker,
    weakening brute-force and replay protection. This is a hard failure at
    startup (not a warning) unless the host explicitly opts in via
    :attr:`~jafaal.settings.AuthSettings.allow_in_memory_state_store_when_deployed`
    (single-worker deployments only).

    Raises:
        RuntimeError: If the environment is deployed, the in-memory store is
            active, and the opt-out flag is not set.
    """
    if not jafaal_settings.is_configured():
        return
    settings = jafaal_settings.get_settings()
    if not settings.is_deployed or settings.allow_in_memory_state_store_when_deployed:
        return
    if isinstance(jafaal_state_store.get_state_store(), jafaal_state_store.InMemoryStateStore):
        raise RuntimeError(
            "JAFAAL is using the in-memory StateStore in a deployed environment "
            f"(environment={settings.environment!r}). It is process-local, so a multi-worker / "
            "multi-replica deployment keeps progressive-lockout counters and TOTP-replay markers "
            "per-worker, weakening brute-force and replay protection. Configure a distributed backend "
            "via jafaal.configure_state_store(...) (e.g. jafaal.adapters.RedisStateStore), or set "
            "AuthSettings.allow_in_memory_state_store_when_deployed=True for a single-worker deployment."
        )


def _ensure_password_breach_checker_safe_for_deployment() -> None:
    """Require blocklist screening for deployed length-only password policy."""
    if not jafaal_settings.is_configured() or not jafaal_ports.is_settings_provider_configured():
        return
    settings = jafaal_settings.get_settings()
    if not settings.is_deployed or settings.allow_no_password_breach_check_when_deployed:
        return
    policy = jafaal_ports.get_settings_provider().get_password_policy()
    if policy.password_type != "length_only":
        return
    if isinstance(jafaal_ports.get_password_breach_checker(), jafaal_ports.NullPasswordBreachChecker):
        raise RuntimeError(
            "JAFAAL is using a length_only password policy without a breached-password checker in a deployed "
            f"environment (environment={settings.environment!r}). NIST SP 800-63B-4 requires prospective "
            "subscriber-chosen passwords to be compared against a blocklist. Install one via "
            "jafaal.configure_password_breach_checker(...) or set "
            "AuthSettings.allow_no_password_breach_check_when_deployed=True to explicitly accept the risk."
        )


def verify_configuration() -> None:
    """Assert that every required host-supplied component is installed.

    JAFAAL resolves several host adapters lazily, so a missing one otherwise
    surfaces as a ``RuntimeError`` on the first request that needs it. Call this
    once at startup (e.g. in a FastAPI lifespan handler) to fail fast with a
    single, clear message listing everything that is missing.

    Checks the components JAFAAL cannot default: the ORM model mapping
    (:func:`jafaal.map_models`), the settings object, the session factory, the
    user repository, and the settings provider. The event sink, state store,
    rate limiter, and scope catalog all have working defaults and so are not
    required here. It also enforces deployed state-store, rate-limiter, and
    password blocklist guards.

    Raises:
        RuntimeError: If any required component is missing (the message
            enumerates all of them), or if the in-memory state store is used in a
            deployed environment without the opt-out.
    """
    missing: list[str] = []
    if not jafaal_orm.is_models_mapped():
        missing.append("ORM models — call jafaal.map_models(YourBase) after defining your Users model")
    if not jafaal_settings.is_configured():
        missing.append("AuthSettings — call jafaal.configure(AuthSettings(...))")
    if not jafaal_orm.is_sessionmaker_configured():
        missing.append("session factory — call jafaal.configure_sessionmaker(sessionmaker(bind=engine))")
    if not jafaal_ports.is_user_repository_configured():
        missing.append("UserRepository — call jafaal.configure_user_repository(...)")
    if not jafaal_ports.is_settings_provider_configured():
        missing.append("SettingsProvider — call jafaal.configure_settings_provider(...)")
    if missing:
        raise RuntimeError(
            "JAFAAL is not fully configured; the following required components are missing:\n"
            + "\n".join(f"  - {item}" for item in missing)
        )
    _ensure_state_store_safe_for_deployment()
    _ensure_rate_limiter_safe_for_deployment()
    _ensure_password_breach_checker_safe_for_deployment()


def create_auth_router(
    *,
    app: FastAPI | None = None,
    rate_limiter: RateLimiter | None = None,
    prefixes: RouterPrefixes | None = None,
    verify: bool = True,
) -> APIRouter:
    """Build the aggregated JAFAAL auth router.

    Args:
        app: When provided, the :class:`~jafaal.exceptions.JafaalError`
            exception handler and the issuer-derived RFC 8414 metadata route are
            registered on it. Omit it and install both explicitly if you
            assemble the app differently.
        rate_limiter: The host's rate limiter. Installed before the sub-routers
            are imported so their decorators resolve it. Defaults to the no-op
            limiter already in effect (no enforcement).
        prefixes: Override the default sub-prefixes (keep them in lockstep with
            :class:`~jafaal.settings.AuthSettings` path fields).
        verify: Run :func:`verify_configuration` first (default), so a missing
            host adapter fails here with one clear message instead of surfacing
            as a ``RuntimeError`` on the first request that needs it. Set
            ``False`` only when the router is built before the adapters are
            installed (then call :func:`verify_configuration` yourself once they
            are).

    Returns:
        An ``APIRouter`` the host mounts under its API root, e.g.::

            app.include_router(create_auth_router(app=app), prefix="/api/v1")

    Raises:
        RuntimeError: If ``verify`` is set and a required component is missing,
            or a deployed environment violates a state-store, rate-limiter, or
            password blocklist guard.
    """
    if rate_limiter is not None:
        configure_rate_limiter(rate_limiter)
    if app is not None:
        register_exception_handlers(app)
    prefixes = prefixes or RouterPrefixes()

    _warn_on_insecure_defaults()
    _warn_on_router_prefix_mismatch(prefixes)
    if verify:
        verify_configuration()
    else:
        # The deployment guards are not optional even when the adapter check is
        # deferred: they are what keeps a deployed environment from silently
        # running unprotected.
        _ensure_state_store_safe_for_deployment()
        _ensure_rate_limiter_safe_for_deployment()
        _ensure_password_breach_checker_safe_for_deployment()

    # Import the sub-routers here, after installing the limiter. The rate-limit
    # decorators bind the configured limiter lazily (on first request, re-binding
    # when it is reconfigured), so this import order is no longer load-bearing —
    # it is kept only for clarity.
    from jafaal.api_keys.router import router as api_keys_router
    from jafaal.identity_providers.public_router import router as idp_public_router
    from jafaal.identity_providers.router import router as idp_router
    from jafaal.jwks import router as jwks_router
    from jafaal.metadata import create_metadata_router, issuer_derived_metadata_path
    from jafaal.mfa.router import router as mfa_router
    from jafaal.password_reset_tokens.router import router as password_reset_router
    from jafaal.router import router as auth_router
    from jafaal.sessions.router import router as sessions_router
    from jafaal.sign_up_tokens.router import router as sign_up_router
    from jafaal.webauthn.router import public_router as webauthn_public_router
    from jafaal.webauthn.router import router as webauthn_router

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
    aggregate.include_router(mfa_router, prefix=prefixes.profile, tags=["mfa"])
    aggregate.include_router(webauthn_router, prefix=prefixes.webauthn, tags=["webauthn"])
    aggregate.include_router(webauthn_public_router, prefix=prefixes.webauthn_public, tags=["webauthn"])
    # Keep the aggregate metadata location for compatibility and mount the RFC
    # 8414 issuer-derived location directly on the application when available.
    # At request time the app-root handler resolves the named authorization route,
    # after the host has mounted this aggregate, so both copies advertise the
    # same real endpoint URLs without guessing the aggregate prefix.
    aggregate.include_router(jwks_router)
    aggregate.include_router(create_metadata_router(prefixes.auth))
    if app is not None:
        metadata_path = issuer_derived_metadata_path()
        installed_paths = set(getattr(app.state, "_jafaal_metadata_paths", ()))
        if metadata_path not in installed_paths:
            app.include_router(create_metadata_router(prefixes.auth, path=metadata_path))
            app.state._jafaal_metadata_paths = (*installed_paths, metadata_path)
    return aggregate


async def shutdown(*, drain_events_timeout: float = 5.0) -> None:
    """Release JAFAAL's process-wide resources. Call from the ASGI lifespan.

    JAFAAL holds three things that outlive a request and are not garbage: the
    pooled HTTP client used for outbound OIDC calls (keep-alive sockets to every
    configured identity provider), the optional background maintenance thread,
    and any in-flight :class:`~jafaal.ports.AuthEventSink` deliveries. Without an
    explicit shutdown those leak on reload, keep a process alive longer than it
    should, and drop notifications that were mid-flight::

        @contextlib.asynccontextmanager
        async def lifespan(app: FastAPI):
            jafaal.maintenance.start_background_scheduler()
            yield
            await jafaal.shutdown()

    Never raises: shutdown must not be able to fail a clean stop.

    Args:
        drain_events_timeout: Seconds to wait for pending event deliveries.
    """
    import jafaal.maintenance as jafaal_maintenance
    from jafaal.identity_providers.service import idp_service

    jafaal_maintenance.stop_background_scheduler()
    try:
        await idp_service.aclose()
    except Exception as err:  # pragma: no cover - defensive
        logger.warning(f"Error closing the identity-provider HTTP client: {type(err).__name__}", exc_info=err)
    if not jafaal_ports.wait_for_pending_events(drain_events_timeout):
        logger.warning(f"JAFAAL shut down with AuthEventSink deliveries still in flight after {drain_events_timeout}s")
