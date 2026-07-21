"""Application-supplied configuration for JAFAAL.

JAFAAL never reads environment variables or secret files itself. The host
application builds an :class:`AuthSettings` instance from whatever configuration
source it likes and installs it once at startup::

    import jafaal

    jafaal.configure(
        jafaal.AuthSettings(
            secret_key=my_secret,          # JWT signing key
            fernet_key=my_fernet_key,      # token-encryption key
            base_url="https://app.example",
            app_name="Example",
        )
    )

All JAFAAL components read the installed settings through :func:`get_settings`.
This mirrors the pattern used by the sibling ``safeuploads`` library (config is
data the host owns, injected in — not read from the environment by the library).

The object is immutable (``frozen``) and validated on construction, so
misconfiguration fails fast.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.fernet import Fernet

__all__ = [
    "ALLOWED_ALGORITHMS",
    "MIN_SECRET_KEY_LENGTH",
    "AuthSettings",
    "configure",
    "get_settings",
    "is_configured",
    "reset",
    "settings_generation",
]

# JWT signing algorithms JAFAAL will accept. Pinned to HS256: the key material
# is a symmetric secret, so asymmetric algorithms and ``alg=none`` must never be
# honoured. (joserfc additionally refuses HS384/HS512 by default.)
ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"HS256"})

# Minimum length (characters) for the HS256 signing key. HMAC-SHA256 security
# assumes a high-entropy key of at least 256 bits (32 bytes); a shorter secret
# is brute-forceable, so it is rejected at construction rather than silently
# accepted.
MIN_SECRET_KEY_LENGTH: int = 32


@dataclass(frozen=True)
class AuthSettings:
    """Immutable, host-supplied configuration for the auth library.

    Attributes:
        secret_key: HMAC key used to sign and verify JWTs.
        fernet_key: Fernet key used to encrypt at-rest tokens (IdP client
            secrets, MFA secrets, rotated refresh tokens). A url-safe base64
            32-byte key as produced by ``cryptography.fernet.Fernet.generate_key``.
        algorithm: JWT signing algorithm (only ``HS256`` is supported).
        access_token_expire_minutes: Access-token lifetime, in minutes.
        refresh_token_expire_days: Refresh-token lifetime, in days.
        issuer: JWT ``iss`` claim. Defaults to ``base_url`` when empty
            (see :attr:`resolved_issuer`).
        audience: JWT ``aud`` claim. Defaults to ``base_url`` when empty
            (see :attr:`resolved_audience`).
        session_idle_timeout_enabled: Whether idle-session expiry is enforced.
        session_idle_timeout_hours: Idle-session timeout, in hours.
        session_absolute_timeout_hours: Absolute session lifetime, in hours.
        base_url: Public base URL of the host app; used to build SSO redirect
            and error URLs and as the default JWT issuer/audience.
        allowed_redirect_schemes: URL schemes permitted for post-login
            redirects (SSO). Defaults to HTTPS only.
        sso_login_result_path: Host frontend path the SSO callback redirects to
            on a successful login, joined onto :attr:`base_url`.
        sso_error_path: Host frontend path the SSO callback redirects to on a
            login error, joined onto :attr:`base_url`.
        sso_link_result_path: Host frontend path the SSO callback redirects to
            after an account-link attempt, joined onto :attr:`base_url`.
        environment: Deployment environment string. ``production``/``demo`` are
            treated as deployed (drives the cookie ``Secure`` flag and demo-mode
            guards).
        allow_api_key_query_param: Whether API keys may be supplied via the
            ``?api_key=`` query string (a security risk; defaults to False so
            only the ``X-API-Key`` header is accepted).
        app_name: Human-readable application name; used as the MFA TOTP issuer
            shown in authenticator apps.
        user_agent: ``User-Agent`` header sent on outbound OIDC HTTP calls.
        refresh_cookie_name: Name of the refresh-token cookie.
        refresh_cookie_path: Path scope of the refresh-token cookie.
        login_token_url: OAuth2 password-flow token URL advertised to Swagger.
        api_key_prefix: Prefix for generated API keys (``<prefix>_<token>``).
        store_key_prefix: Namespace prefix for security-store keys
            (lockout counters, MFA setup secrets, ...).
        rate_limit_sensitive: Budget for sensitive endpoints (login, MFA,
            password reset, sign-up, OAuth), consumed by the host's
            :class:`~jafaal.rate_limit.RateLimiter`.
        rate_limit_write: Budget for write endpoints (e.g. logout, session
            revocation), consumed by the host's ``RateLimiter``.
        trusted_proxies: Peers whose ``X-Forwarded-For`` / ``X-Real-IP`` headers
            are honoured. ``("*",)`` trusts all peers (single-node default).
        ssrf_allowed_hosts: Hosts/CIDRs exempted from the SSRF private-address
            guard on outbound OIDC calls.
    """

    # --- secrets (required; the host provides them) ---
    secret_key: str
    fernet_key: str

    # --- JWT ---
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    issuer: str = ""
    audience: str = ""

    # --- sessions ---
    session_idle_timeout_enabled: bool = False
    session_idle_timeout_hours: int = 1
    session_absolute_timeout_hours: int = 24

    # --- URLs / redirects ---
    base_url: str = ""
    allowed_redirect_schemes: tuple[str, ...] = ("https",)
    sso_login_result_path: str = "/login"
    sso_error_path: str = "/login"
    sso_link_result_path: str = "/settings/security"

    # --- environment ---
    environment: str = "production"

    # --- security toggles ---
    allow_api_key_query_param: bool = False

    # --- rate limiting (canonical budgets for the host's RateLimiter) ---
    rate_limit_sensitive: str = "10/minute"
    rate_limit_write: str = "30/minute"

    # --- branding / identifiers ---
    app_name: str = "Jafaal"
    user_agent: str = "Jafaal (OIDC Client)"
    refresh_cookie_name: str = "jafaal_refresh_token"
    refresh_cookie_path: str = "/api/v1/auth"
    login_token_url: str = "/api/v1/auth/login"
    api_key_prefix: str = "jafaal"
    store_key_prefix: str = "jafaal:auth"

    # --- network / SSRF ---
    trusted_proxies: tuple[str, ...] = ("*",)
    ssrf_allowed_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.secret_key:
            raise ValueError("AuthSettings.secret_key is required")
        if len(self.secret_key) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(
                f"AuthSettings.secret_key is too short (got {len(self.secret_key)} characters, "
                f"need at least {MIN_SECRET_KEY_LENGTH}). HS256 requires a high-entropy key; "
                "generate one with e.g. secrets.token_urlsafe(32)."
            )
        if not self.fernet_key:
            raise ValueError("AuthSettings.fernet_key is required")
        try:
            Fernet(self.fernet_key.encode())
        except Exception as err:
            raise ValueError(
                "AuthSettings.fernet_key is not a valid Fernet key. Expected a url-safe "
                "base64-encoded 32-byte key, e.g. cryptography.fernet.Fernet.generate_key()."
            ) from err
        if self.algorithm not in ALLOWED_ALGORITHMS:
            raise ValueError(
                f"AuthSettings.algorithm={self.algorithm!r} is not in the allow-list {sorted(ALLOWED_ALGORITHMS)}"
            )
        if self.access_token_expire_minutes <= 0:
            raise ValueError("AuthSettings.access_token_expire_minutes must be positive")
        if self.refresh_token_expire_days <= 0:
            raise ValueError("AuthSettings.refresh_token_expire_days must be positive")

    @property
    def resolved_issuer(self) -> str:
        """JWT issuer, falling back to :attr:`base_url` when unset."""
        return self.issuer or self.base_url

    @property
    def resolved_audience(self) -> str:
        """JWT audience, falling back to :attr:`base_url` when unset."""
        return self.audience or self.base_url

    @property
    def is_deployed(self) -> bool:
        """Whether the environment is a deployed one (``production``/``demo``)."""
        return self.environment in ("production", "demo")


# ---------------------------------------------------------------------------
# Installed-settings accessor
# ---------------------------------------------------------------------------

_settings: AuthSettings | None = None
# Bumped on every (re)configure so cached, settings-derived singletons (e.g. the
# token manager) can detect staleness and rebuild.
_generation: int = 0


def configure(settings: AuthSettings) -> None:
    """Install the host-supplied :class:`AuthSettings` for the process.

    Call once at application startup, before serving requests. Re-calling
    replaces the settings and invalidates any settings-derived caches.

    Args:
        settings: The fully-built, validated settings instance.
    """
    global _settings, _generation
    if not isinstance(settings, AuthSettings):
        raise TypeError(f"expected AuthSettings, got {type(settings).__name__}")
    _settings = settings
    _generation += 1


def get_settings() -> AuthSettings:
    """Return the installed :class:`AuthSettings`.

    Raises:
        RuntimeError: If :func:`configure` has not been called.
    """
    if _settings is None:
        raise RuntimeError(
            "JAFAAL is not configured. Call jafaal.configure(AuthSettings(...)) "
            "at application startup before using the library."
        )
    return _settings


def is_configured() -> bool:
    """Return whether :func:`configure` has been called."""
    return _settings is not None


def settings_generation() -> int:
    """Return the current settings generation counter.

    Cached, settings-derived singletons compare against this to detect that
    :func:`configure` has been called again and rebuild themselves.
    """
    return _generation


def reset() -> None:
    """Clear the installed settings. Intended for test isolation."""
    global _settings, _generation
    _settings = None
    _generation += 1
