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

from jafaal._core.registry import ConfigSlot

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
        secret_key_fallbacks: Additional HMAC keys accepted when *verifying*
            JWTs (never used to sign), so tokens issued before a ``secret_key``
            rotation still validate during the overlap window.
        fernet_key_fallbacks: Additional Fernet keys accepted when *decrypting*
            at-rest tokens (never used to encrypt), enabling ``fernet_key``
            rotation without a bulk re-encrypt.
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
        allow_in_memory_state_store_when_deployed: Permit the process-local
            in-memory :class:`~jafaal.state_store.StateStore` in a *deployed*
            environment. Off by default: :func:`jafaal.create_auth_router`
            refuses to start with the in-memory store when deployed, because a
            multi-worker/replica deployment would fragment progressive-lockout
            and TOTP-replay state per-worker. Set ``True`` only for a genuine
            single-worker deployment.
        strict_session_binding: When ``True``, every access-token-authenticated
            request verifies the token's ``sid`` session still exists and is
            valid, so logout / single-session revocation is immediate instead of
            bounded by the access-token lifetime. Off by default (stateless
            access-token validation); adds one indexed session lookup per request.
        login_ip_lockout_enabled: When ``True`` (default), a per-source-IP backoff
            bounds how many accounts one IP can lock out by spraying failed
            logins across usernames (the per-account lockout is otherwise a cheap
            targeted-DoS lever). Relies on an accurate client IP (configure
            ``trusted_proxies`` behind a reverse proxy); disable if a shared
            egress IP (large NAT / load balancer) causes false lockouts.
        audit_include_pii: When True (default), audit records carry direct
            identifiers (plaintext username, client IP, email). Set False to
            drop them (substituting a one-way username hash) for PII-minimal
            audit retention.
        argon2_time_cost: Argon2 time cost (iterations) for password hashing.
        argon2_memory_cost: Argon2 memory cost, in KiB.
        argon2_parallelism: Argon2 parallelism (lanes).
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
            are honoured. Empty by default, which trusts only the direct TCP
            peer (the safe default: proxy headers from arbitrary clients are
            ignored, so a client cannot spoof its source IP). Set explicit proxy
            IPs/CIDRs when running behind a reverse proxy, or ``("*",)`` to trust
            every peer (only safe when a trusted proxy always overwrites the
            header).
        ssrf_allowed_hosts: Hosts/CIDRs exempted from the SSRF private-address
            guard on outbound OIDC calls.
        step_up_idp_reauth_enabled: Whether an SSO-only account (no local
            password and no MFA) may satisfy step-up verification by
            re-authenticating at a linked identity provider. When ``False`` such
            accounts are refused sensitive operations (step-up fails closed).
        step_up_reauth_max_age_seconds: Maximum age, in seconds, of the IdP
            authentication (the ID token ``auth_time`` claim) accepted as
            "fresh" for step-up. Also sent as the OIDC ``max_age`` on the
            re-authentication request so the provider re-prompts the user.
        step_up_grant_ttl_seconds: Lifetime, in seconds, of the single-use
            step-up grant minted after a successful IdP re-authentication;
            the caller must retry the sensitive operation within this window.
    """

    # --- secrets (required; the host provides them) ---
    secret_key: str
    fernet_key: str

    # --- key rotation (additional keys accepted for verification/decryption) ---
    # Older keys kept alongside the primary so secrets encrypted (or tokens
    # signed) before a rotation still validate. New material is always produced
    # with the primary key; these are decrypt-/verify-only.
    secret_key_fallbacks: tuple[str, ...] = ()
    fernet_key_fallbacks: tuple[str, ...] = ()

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
    # Off by default so a deployed multi-worker/replica setup cannot silently run
    # on the process-local in-memory state store (which would fragment lockout /
    # TOTP-replay state). create_auth_router() enforces this.
    allow_in_memory_state_store_when_deployed: bool = False

    # When True, every access-token-authenticated request also verifies that the
    # token's session (its ``sid`` claim) still exists and is valid, so logout and
    # single-session revocation take effect immediately instead of waiting for the
    # short-lived access token to expire. Off by default: access tokens are
    # validated statelessly (no per-request session lookup). A deactivated *user*
    # is rejected immediately regardless (the user row is loaded every request);
    # this toggle adds the same immediacy for *session* revocation at the cost of
    # one extra indexed query per request.
    strict_session_binding: bool = False

    # Bound how many accounts a single source IP can lock out by spraying failed
    # logins across usernames (the per-account lockout is otherwise a cheap
    # targeted-DoS lever). After enough total failures from one IP its logins are
    # throttled; reset on any successful login from that IP. Relies on an
    # accurate client IP (configure trusted_proxies behind a reverse proxy).
    # Disable if a shared egress IP (large NAT / load balancer) trips it.
    login_ip_lockout_enabled: bool = True

    # --- audit ---
    # When False, the jafaal.audit stream drops direct identifiers (plaintext
    # username, client IP, email) and substitutes a one-way username hash, so
    # audit records can be retained without storing PII. On by default so a SIEM
    # sees the identifiers it needs to spot targeted brute-force.
    audit_include_pii: bool = True

    # --- password hashing (Argon2 cost; defaults match pwdlib/argon2-cffi) ---
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4

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
    # Empty by default: trust only the direct peer (proxy headers are ignored),
    # so a client cannot spoof X-Forwarded-For / X-Real-IP. Set explicit proxy
    # IPs/CIDRs behind a reverse proxy, or ("*",) to trust all peers.
    trusted_proxies: tuple[str, ...] = ()
    ssrf_allowed_hosts: tuple[str, ...] = ()

    # --- step-up (IdP re-authentication) ---
    # Lets an SSO-only account (no local password, no MFA) satisfy step-up by
    # re-authenticating at a linked IdP (OIDC prompt=login + a verified, fresh
    # auth_time), so hosts can delegate the second factor entirely to the IdP.
    # When disabled, such accounts fail closed for sensitive operations.
    step_up_idp_reauth_enabled: bool = True
    step_up_reauth_max_age_seconds: int = 300
    step_up_grant_ttl_seconds: int = 120

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
        if self.argon2_time_cost <= 0:
            raise ValueError("AuthSettings.argon2_time_cost must be positive")
        if self.argon2_memory_cost <= 0:
            raise ValueError("AuthSettings.argon2_memory_cost must be positive")
        if self.argon2_parallelism <= 0:
            raise ValueError("AuthSettings.argon2_parallelism must be positive")
        if self.step_up_reauth_max_age_seconds <= 0:
            raise ValueError("AuthSettings.step_up_reauth_max_age_seconds must be positive")
        if self.step_up_grant_ttl_seconds <= 0:
            raise ValueError("AuthSettings.step_up_grant_ttl_seconds must be positive")
        for index, fallback in enumerate(self.secret_key_fallbacks):
            if len(fallback) < MIN_SECRET_KEY_LENGTH:
                raise ValueError(
                    f"AuthSettings.secret_key_fallbacks[{index}] is too short (got {len(fallback)} "
                    f"characters, need at least {MIN_SECRET_KEY_LENGTH})."
                )
        for index, fallback in enumerate(self.fernet_key_fallbacks):
            try:
                Fernet(fallback.encode())
            except Exception as err:
                raise ValueError(f"AuthSettings.fernet_key_fallbacks[{index}] is not a valid Fernet key.") from err

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

# Backed by the shared ConfigSlot so settings use the same configure/get/reset
# machinery as the ports/scopes/state-store/rate-limiter singletons. The slot's
# generation counter is what settings-derived caches (the token manager) watch
# to rebuild after a reconfigure.
_slot: ConfigSlot[AuthSettings] = ConfigSlot(
    missing_message=(
        "JAFAAL is not configured. Call jafaal.configure(AuthSettings(...)) "
        "at application startup before using the library."
    )
)


def configure(settings: AuthSettings) -> None:
    """Install the host-supplied :class:`AuthSettings` for the process.

    Call once at application startup, before serving requests. Re-calling
    replaces the settings and invalidates any settings-derived caches.

    Args:
        settings: The fully-built, validated settings instance.
    """
    if not isinstance(settings, AuthSettings):
        raise TypeError(f"expected AuthSettings, got {type(settings).__name__}")
    _slot.configure(settings)


def get_settings() -> AuthSettings:
    """Return the installed :class:`AuthSettings`.

    Raises:
        RuntimeError: If :func:`configure` has not been called.
    """
    return _slot.get()


def is_configured() -> bool:
    """Return whether :func:`configure` has been called."""
    return _slot.is_configured()


def settings_generation() -> int:
    """Return the current settings generation counter.

    Cached, settings-derived singletons compare against this to detect that
    :func:`configure` has been called again and rebuild themselves.
    """
    return _slot.generation


def reset() -> None:
    """Clear the installed settings. Intended for test isolation."""
    _slot.reset()
