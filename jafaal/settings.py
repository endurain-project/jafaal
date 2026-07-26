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

from dataclasses import dataclass, field, fields
from urllib.parse import urlparse

from cryptography.fernet import Fernet

from jafaal._core import jwk_keys
from jafaal._core.registry import ConfigSlot

__all__ = [
    "ALLOWED_ALGORITHMS",
    "DEPLOYED_ENVIRONMENTS",
    "KNOWN_ENVIRONMENTS",
    "LOCAL_ENVIRONMENTS",
    "MIN_SECRET_KEY_LENGTH",
    "AuthSettings",
    "configure",
    "get_settings",
    "is_configured",
    "reset",
    "settings_generation",
]

# JWT signing algorithms JAFAAL will accept. ``HS256`` (symmetric, the default)
# plus the asymmetric RSA/EC family (opt-in via ``private_key``): sign with a
# private key, publish the public key at the JWKS endpoint, verify statelessly.
# ``alg=none`` and non-listed algorithms are never honoured, and the same
# allow-list is passed to ``jwt.decode`` so it cannot drift from signing.
ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"HS256"}) | jwk_keys.ASYMMETRIC_ALGORITHMS

# Minimum length (characters) for the HS256 signing key. HMAC-SHA256 security
# assumes a high-entropy key of at least 256 bits (32 bytes); a shorter secret
# is brute-forceable, so it is rejected at construction rather than silently
# accepted.
MIN_SECRET_KEY_LENGTH: int = 32

# Environment names treated as *deployed*. This single predicate gates four
# security controls at once — the refresh cookie's ``Secure`` flag and
# ``__Secure-``/``__Host-`` prefix, the in-memory-state-store startup refusal,
# and the missing-rate-limiter startup refusal — so the value must never be a
# free-form string: a typo (``"prod"``, ``"Production"``, ``"live"``) would
# silently turn all four off. ``AuthSettings.__post_init__`` therefore rejects
# anything outside :data:`KNOWN_ENVIRONMENTS`.
DEPLOYED_ENVIRONMENTS: frozenset[str] = frozenset({"production", "demo", "staging"})

# Environment names treated as local/non-deployed: served over plain http, so
# ``Secure`` cookies would never be stored and the single-process defaults are
# appropriate.
LOCAL_ENVIRONMENTS: frozenset[str] = frozenset({"development", "local", "test", "testing"})

#: Every accepted :attr:`AuthSettings.environment` value.
KNOWN_ENVIRONMENTS: frozenset[str] = DEPLOYED_ENVIRONMENTS | LOCAL_ENVIRONMENTS


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
        algorithm: JWT signing algorithm. ``HS256`` (default, symmetric) or an
            asymmetric RSA/EC algorithm (RS256/384/512, PS256/384/512,
            ES256/384/512): signs with ``private_key`` and publishes the public
            key at the JWKS endpoint.
        private_key: PEM private key used to sign JWTs when ``algorithm`` is
            asymmetric (must be empty for HS256).
        private_key_fallbacks: Additional verify-only keys (PEM, public or
            private) kept in the published JWKS during a signing-key rotation
            overlap.
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
        environment: Deployment environment string. Must be one of
            :data:`KNOWN_ENVIRONMENTS`; the :data:`DEPLOYED_ENVIRONMENTS`
            members (``production``/``demo``/``staging``) are treated as
            deployed (drives the cookie ``Secure`` flag, the cookie name
            prefix, and the fail-closed startup guards). An unrecognised value
            is rejected at construction rather than silently treated as local.
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
        trusted_proxies: Peers and forwarding hops whose ``X-Forwarded-For`` /
            ``X-Real-IP`` headers are honoured. Empty by default, which trusts
            only the direct TCP peer (the safe default: proxy headers from
            arbitrary clients are ignored, so a client cannot spoof its source
            IP). Set explicit proxy IPs/CIDRs when running behind a reverse
            proxy — list **every** hop your infrastructure adds (e.g. both the
            CDN egress ranges and the reverse proxy), because the forwarded
            chain is resolved right-to-left and stops at the first hop that is
            not listed here. ``("*",)`` trusts every hop (only safe when a
            trusted proxy always overwrites the header).
        ssrf_allowed_hosts: Hosts/CIDRs exempted from the SSRF private-address
            guard on outbound OIDC calls.
        idp_require_https: When ``True`` (default), identity-provider endpoints
            (the browser-facing authorization endpoint and the server-side
            token, userinfo, JWKS, discovery and revocation URLs) must use
            ``https``, refusing to transmit authorization codes, tokens and
            client credentials in cleartext. Set ``False`` to allow ``http://``
            IdP endpoints for local or self-hosted development.
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
        jwt_leeway_seconds: Clock-skew tolerance (seconds) applied to the
            ``exp``/``nbf`` claims of JAFAAL's own JWTs. ``0`` (default) is
            strict; a small value avoids spurious 401s across skewed nodes.
        password_max_length: Maximum accepted password length, enforced before
            hashing (defaults to 128; must be at least 64). The legacy bcrypt
            verifier truncates at 72 bytes — Argon2 (used for all new hashes)
            does not.
        mfa_totp_replay_fail_open: When ``False`` (default), TOTP replay
            protection fails closed on a state-store outage (the code is
            rejected as a 503); ``True`` accepts the code and logs the degraded
            check instead.
        allow_no_rate_limit_when_deployed: Permit a deployed environment to run
            with the no-op rate limiter. Off by default: ``create_auth_router``
            / ``verify_configuration`` refuse to start deployed without an
            enforcing limiter unless this is set.
        access_token_denylist_enabled: When ``True``, revoked access-token
            ``jti`` values are recorded and checked per request so ``/revoke``
            kills an access token immediately (one state-store lookup per
            request). Off by default (access tokens lapse at expiry; revoke the
            refresh token / session for immediate effect).
        reauthorize_scopes_per_request: When ``True``, an access token's scopes
            are intersected with the tier its account currently holds, so a
            demotion applies immediately rather than at token expiry. Strictly
            narrowing — a token never gains a scope it was not issued with. Off
            by default.
        refresh_cookie_prefix: Optional refresh-cookie name-prefix hardening
            (``""``, ``"__Secure-"``, or ``"__Host-"``), applied only in a
            deployed environment. ``"__Host-"`` requires ``refresh_cookie_path``
            to be ``"/"``. See :attr:`effective_refresh_cookie_name`.
        webauthn_rp_id: WebAuthn Relying Party ID — the registrable domain
            passkeys are scoped to (no scheme/port). Defaults to the ``base_url``
            host (see :attr:`resolved_webauthn_rp_id`).
        webauthn_rp_name: Human-readable Relying Party name shown by the
            authenticator. Defaults to :attr:`app_name`.
        webauthn_origins: Exact origins (scheme + host + port) a passkey ceremony
            may complete from. Defaults to the origin of ``base_url`` (see
            :attr:`resolved_webauthn_origins`).
        webauthn_user_verification: User-verification requirement for ceremonies
            (``"required"``, ``"preferred"`` (default), or ``"discouraged"``).
        webauthn_attestation: Attestation conveyance requested at registration
            (``"none"`` (default) or ``"direct"``).
        webauthn_second_factor_enabled: When ``True``, a user with registered
            passkeys must present one as a second factor after password login.
            Off by default (passkeys remain usable for passwordless login).
        webauthn_challenge_ttl_seconds: Lifetime, in seconds, of a WebAuthn
            challenge held in the state store before it must be redeemed.
    """

    # --- secrets (required; the host provides them) ---
    # ``repr=False`` on every field holding key material: the dataclass-generated
    # ``__repr__`` would otherwise print the JWT signing key and the at-rest
    # encryption key verbatim into any traceback frame dump, error-tracker
    # payload, or ``logger.debug(settings)`` call. See the custom ``__repr__``
    # below, which renders these as ``<redacted>``.
    secret_key: str = field(repr=False)
    fernet_key: str = field(repr=False)

    # --- key rotation (additional keys accepted for verification/decryption) ---
    # Older keys kept alongside the primary so secrets encrypted (or tokens
    # signed) before a rotation still validate. New material is always produced
    # with the primary key; these are decrypt-/verify-only.
    secret_key_fallbacks: tuple[str, ...] = field(default=(), repr=False)
    fernet_key_fallbacks: tuple[str, ...] = field(default=(), repr=False)

    # --- JWT ---
    algorithm: str = "HS256"
    # Asymmetric signing (opt-in). When ``algorithm`` is an RSA/EC algorithm
    # (e.g. RS256 / ES256), ``private_key`` (PEM) signs the JWTs and its public
    # key is published at the JWKS endpoint so resource servers can verify
    # statelessly. ``private_key_fallbacks`` are verify-only public/private PEMs
    # kept in the JWKS during a signing-key rotation overlap. ``secret_key`` is
    # still required regardless of ``algorithm`` — it keys the HMAC hashing of
    # refresh / CSRF tokens.
    private_key: str = field(default="", repr=False)
    private_key_fallbacks: tuple[str, ...] = field(default=(), repr=False)
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    issuer: str = ""
    audience: str = ""
    # OAuth client identifier stamped into the ``client_id`` claim RFC 9068
    # requires. JAFAAL is a first-party issuer with no client registry, so this
    # defaults to the token audience (see :attr:`resolved_client_id`).
    client_id: str = ""
    # Clock-skew tolerance (seconds) applied when validating the ``exp`` / ``nbf``
    # claims of JAFAAL's own JWTs. 0 keeps validation strict (the historical
    # behaviour); a small value (e.g. 30) avoids spurious 401s when issuing and
    # validating nodes have slightly skewed clocks. Kept small so an expired
    # token is not honoured for long.
    jwt_leeway_seconds: int = 0

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

    # Origins allowed to drive the web refresh flow. The refresh cookie is
    # HttpOnly + SameSite=Strict, and /refresh additionally refuses a request
    # that a browser marks as off-site (via the unforgeable ``Sec-Fetch-Site``
    # header or a mismatched ``Origin``). Defaults to the origin of ``base_url``;
    # set it explicitly when the frontend is served from a different origin than
    # the API (e.g. app.example.com calling api.example.com).
    csrf_trusted_origins: tuple[str, ...] = ()

    # --- environment ---
    # Must be one of KNOWN_ENVIRONMENTS (validated in __post_init__). Defaults to
    # the safest value: "production" turns on every deployed-environment control,
    # so forgetting to set it cannot weaken the deployment.
    environment: str = "production"

    # --- security toggles ---
    allow_api_key_query_param: bool = False
    # Off by default so a deployed multi-worker/replica setup cannot silently run
    # on the process-local in-memory state store (which would fragment lockout /
    # TOTP-replay state). create_auth_router() enforces this.
    allow_in_memory_state_store_when_deployed: bool = False

    # Off by default so a deployed environment cannot silently run without a real
    # rate limiter (the no-op default enforces nothing on login / MFA / password
    # reset / refresh, leaving only per-account progressive lockout).
    # create_auth_router() / verify_configuration() refuse to start in a deployed
    # environment when no enforcing limiter is installed unless this is set. Mirror
    # of allow_in_memory_state_store_when_deployed: both fail closed by default.
    allow_no_rate_limit_when_deployed: bool = False

    # When True, every access-token-authenticated request also verifies that the
    # token's session (its ``sid`` claim) still exists and is valid, so logout and
    # single-session revocation take effect immediately instead of waiting for the
    # short-lived access token to expire. Off by default: access tokens are
    # validated statelessly (no per-request session lookup). A deactivated *user*
    # is rejected immediately regardless (the user row is loaded every request);
    # this toggle adds the same immediacy for *session* revocation at the cost of
    # one extra indexed query per request.
    strict_session_binding: bool = False

    # When True, revoked access-token ``jti`` values are recorded in the state
    # store and checked on every access-token-authenticated request, so
    # ``/revoke`` of an access token takes effect immediately (at the cost of one
    # indexed state-store lookup per request). Off by default: access tokens are
    # short-lived and lapse at expiry, and revoking the refresh token (which
    # deletes the session) is the always-effective revocation path.
    access_token_denylist_enabled: bool = False

    # When True, the scopes carried by an access token are intersected with the
    # tier the account holds on *this* request, so demoting an administrator
    # takes effect immediately instead of when their current token expires. It is
    # strictly an intersection: a token can only lose authority, never gain it.
    # Off by default — access tokens are short-lived, and the user row is already
    # loaded every request, so this adds no query, only the narrowing.
    reauthorize_scopes_per_request: bool = False

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
    # Maximum accepted password length. Enforced before hashing (NIST SP 800-63B
    # recommends accepting at least 64 characters so passphrases are allowed,
    # while bounding input to avoid unbounded work). Note: the legacy bcrypt
    # verifier truncates at 72 bytes; Argon2 (the default and only algorithm used
    # for new hashes) has no such limit.
    password_max_length: int = 128

    # --- MFA ---
    # TOTP single-use replay protection is defense-in-depth layered on top of the
    # (unchanged) TOTP signature check, but it needs the shared state store. When
    # the store is unreachable this fails *closed* by default: the MFA code is
    # rejected (surfaced as a 503) rather than accepted without replay protection.
    # Set True to prefer availability (accept the code, log + audit the degraded
    # check) over the stronger single-use guarantee.
    mfa_totp_replay_fail_open: bool = False

    # --- rate limiting (canonical budgets for the host's RateLimiter) ---
    rate_limit_sensitive: str = "10/minute"
    rate_limit_write: str = "30/minute"

    # --- branding / identifiers ---
    app_name: str = "Jafaal"
    user_agent: str = "Jafaal (OIDC Client)"
    refresh_cookie_name: str = "jafaal_refresh_token"
    refresh_cookie_path: str = "/api/v1/auth"
    # Optional cookie-name prefix hardening applied to the refresh cookie in a
    # *deployed* environment: "__Secure-" asserts the cookie was set with Secure
    # (compatible with the path-scoped refresh cookie), "__Host-" additionally
    # binds it to the exact host with Path=/ and no Domain (requires
    # refresh_cookie_path="/"). Empty by default. See effective_refresh_cookie_name.
    refresh_cookie_prefix: str = ""
    login_token_url: str = "/api/v1/auth/login"
    api_key_prefix: str = "jafaal"
    store_key_prefix: str = "jafaal:auth"

    # --- network / SSRF ---
    # Empty by default: trust only the direct peer (proxy headers are ignored),
    # so a client cannot spoof X-Forwarded-For / X-Real-IP. Behind a reverse
    # proxy list every forwarding hop (the chain is walked right-to-left and
    # stops at the first unlisted hop), or ("*",) to trust all of them.
    trusted_proxies: tuple[str, ...] = ()
    ssrf_allowed_hosts: tuple[str, ...] = ()

    # When True (default), identity-provider endpoints (the browser-facing
    # authorization endpoint and the server-side token, userinfo, JWKS,
    # discovery and revocation URLs) must use https, refusing to transmit
    # authorization codes, tokens and client credentials in cleartext. Set to
    # False to allow http:// IdP endpoints for local or self-hosted development.
    idp_require_https: bool = True

    # --- step-up (IdP re-authentication) ---
    # Lets an SSO-only account (no local password, no MFA) satisfy step-up by
    # re-authenticating at a linked IdP (OIDC prompt=login + a verified, fresh
    # auth_time), so hosts can delegate the second factor entirely to the IdP.
    # When disabled, such accounts fail closed for sensitive operations.
    step_up_idp_reauth_enabled: bool = True
    step_up_reauth_max_age_seconds: int = 300
    step_up_grant_ttl_seconds: int = 120

    # --- WebAuthn / passkeys ---
    # Relying Party (RP) identity for the WebAuthn ceremonies. ``webauthn_rp_id``
    # is the registrable domain the passkey is scoped to (e.g. "example.com" — no
    # scheme or port); it must be a registrable suffix of every origin the app is
    # served from. ``webauthn_origins`` are the exact origins (scheme + host +
    # port, e.g. "https://example.com") the browser is allowed to complete a
    # ceremony from. Both default to values derived from ``base_url`` when empty
    # (see resolved_webauthn_rp_id / resolved_webauthn_origins); the WebAuthn
    # endpoints fail fast if neither an explicit value nor a usable base_url is
    # available. ``webauthn_rp_name`` is the human-readable RP name shown by the
    # authenticator (defaults to app_name).
    webauthn_rp_id: str = ""
    webauthn_rp_name: str = ""
    webauthn_origins: tuple[str, ...] = ()
    # User-verification requirement for passkey ceremonies: "required" forces the
    # authenticator to verify the user (PIN/biometric — a true second factor),
    # "preferred" (default) verifies when the authenticator supports it, and
    # "discouraged" skips it (presence-only).
    webauthn_user_verification: str = "preferred"
    # Attestation conveyance requested at registration. "none" (default) asks for
    # no attestation statement (best for privacy and interoperability); "direct"
    # requests the authenticator's attestation so the host can inspect the model
    # (AAGUID). JAFAAL does not verify attestation certificates — request
    # "direct" only if the host processes them.
    webauthn_attestation: str = "none"
    # When True, a user who has registered passkeys must present one as a second
    # factor after a successful password login (the login returns an
    # MFA-required challenge, satisfiable by a passkey assertion). Off by default:
    # passkeys are usable for passwordless login but do not gate the password
    # path. Passwordless authentication is always available regardless of this
    # flag.
    webauthn_second_factor_enabled: bool = False
    # Lifetime, in seconds, of a WebAuthn registration/authentication challenge
    # held in the state store before it must be redeemed. Kept short (a ceremony
    # is interactive and immediate) to bound replay of a leaked challenge.
    webauthn_challenge_ttl_seconds: int = 300

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
        if self.algorithm in jwk_keys.ASYMMETRIC_ALGORITHMS:
            if not self.private_key:
                raise ValueError(
                    f"AuthSettings.algorithm={self.algorithm!r} is asymmetric and requires a private_key (PEM)."
                )
            try:
                jwk_keys.import_private_signing_key(self.private_key, self.algorithm)
            except ValueError as err:
                raise ValueError(f"AuthSettings.private_key is invalid: {err}") from err
            for index, fallback in enumerate(self.private_key_fallbacks):
                try:
                    jwk_keys.import_verification_key(fallback, self.algorithm)
                except ValueError as err:
                    raise ValueError(f"AuthSettings.private_key_fallbacks[{index}] is invalid: {err}") from err
        elif self.private_key or self.private_key_fallbacks:
            raise ValueError(
                f"AuthSettings.private_key / private_key_fallbacks are set but algorithm={self.algorithm!r} is "
                "symmetric (HS256). Use an asymmetric algorithm (e.g. RS256 / ES256) or remove the keys."
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
        if self.webauthn_user_verification not in ("required", "preferred", "discouraged"):
            raise ValueError(
                "AuthSettings.webauthn_user_verification must be 'required', 'preferred', or "
                f"'discouraged' (got {self.webauthn_user_verification!r})."
            )
        if self.webauthn_attestation not in ("none", "direct"):
            raise ValueError(
                f"AuthSettings.webauthn_attestation must be 'none' or 'direct' (got {self.webauthn_attestation!r})."
            )
        if self.webauthn_challenge_ttl_seconds <= 0:
            raise ValueError("AuthSettings.webauthn_challenge_ttl_seconds must be positive")
        if self.jwt_leeway_seconds < 0:
            raise ValueError("AuthSettings.jwt_leeway_seconds must be non-negative")
        if self.environment not in KNOWN_ENVIRONMENTS:
            # Rejected rather than defaulted: ``is_deployed`` gates the cookie
            # ``Secure`` flag, the cookie name prefix, and the two fail-closed
            # startup guards, so an unrecognised value (a typo such as "prod")
            # would silently disable all four in production.
            raise ValueError(
                f"AuthSettings.environment={self.environment!r} is not a recognised environment. "
                f"Use one of {sorted(KNOWN_ENVIRONMENTS)} — {sorted(DEPLOYED_ENVIRONMENTS)} are treated "
                "as deployed (refresh cookies get Secure, and startup fails closed without a distributed "
                "state store and an enforcing rate limiter)."
            )
        if self.password_max_length < 64:
            raise ValueError(
                "AuthSettings.password_max_length must be at least 64 so long passphrases are "
                "accepted (NIST SP 800-63B recommends allowing at least 64 characters)."
            )
        if self.refresh_cookie_prefix not in ("", "__Secure-", "__Host-"):
            raise ValueError(
                "AuthSettings.refresh_cookie_prefix must be '', '__Secure-', or '__Host-' "
                f"(got {self.refresh_cookie_prefix!r})."
            )
        if self.refresh_cookie_prefix == "__Host-" and self.refresh_cookie_path != "/":
            raise ValueError(
                "AuthSettings.refresh_cookie_prefix='__Host-' requires refresh_cookie_path='/': "
                "the __Host- prefix mandates Path=/ and no Domain. Use '__Secure-' to keep a "
                "path-scoped refresh cookie."
            )
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

    def __repr__(self) -> str:
        """Render the settings with every key-bearing field redacted.

        Defined explicitly (a manual ``__repr__`` in the class body wins over the
        dataclass-generated one) so that secrets can never reach a log line, a
        traceback frame dump, or an error-tracker payload. Fields declared with
        ``field(repr=False)`` — the JWT signing key, the Fernet at-rest key, the
        asymmetric private key, and all their rotation fallbacks — are shown as
        ``<redacted>`` rather than silently omitted, so the value is still
        visibly *present* when debugging a configuration problem.

        The ``repr=False`` flag on the field is the single source of truth: a new
        secret field only has to be declared with it to be covered here.
        """
        rendered = ", ".join(
            f"{spec.name}=<redacted>" if not spec.repr else f"{spec.name}={getattr(self, spec.name)!r}"
            for spec in fields(self)
        )
        return f"{type(self).__name__}({rendered})"

    @property
    def resolved_issuer(self) -> str:
        """JWT issuer, falling back to :attr:`base_url` when unset."""
        return self.issuer or self.base_url

    @property
    def resolved_audience(self) -> str:
        """JWT audience, falling back to :attr:`base_url` when unset."""
        return self.audience or self.base_url

    @property
    def resolved_client_id(self) -> str:
        """``client_id`` claim value, falling back to the resolved audience.

        RFC 9068 §2.2 requires ``client_id`` on an access token. JAFAAL issues
        first-party tokens and has no client registry, so the audience (i.e. the
        application the token is for) is the meaningful identifier unless the
        host sets one explicitly.
        """
        return self.client_id or self.resolved_audience

    @property
    def is_deployed(self) -> bool:
        """Whether the environment is a deployed one.

        True for every name in :data:`DEPLOYED_ENVIRONMENTS`
        (``production``/``demo``/``staging``). The value is validated at
        construction, so an unrecognised environment can never silently fall
        through to ``False``.
        """
        return self.environment in DEPLOYED_ENVIRONMENTS

    @property
    def _base_url_origin(self) -> tuple[str, ...]:
        """The scheme+host+port origin of :attr:`base_url`, or empty when unusable."""
        parsed = urlparse(self.base_url)
        if parsed.scheme and parsed.netloc:
            return (f"{parsed.scheme}://{parsed.netloc}",)
        return ()

    @property
    def resolved_csrf_trusted_origins(self) -> tuple[str, ...]:
        """Origins permitted to drive the web refresh flow.

        Returns the explicit :attr:`csrf_trusted_origins` when set, otherwise the
        origin of :attr:`base_url`. Empty when neither is available, in which
        case the ``Origin`` comparison is skipped and only the browser's
        ``Sec-Fetch-Site`` signal is enforced.
        """
        return self.csrf_trusted_origins or self._base_url_origin

    @property
    def effective_refresh_cookie_name(self) -> str:
        """Refresh-cookie name including any ``__Secure-`` / ``__Host-`` prefix.

        The prefix is applied only in a *deployed* environment, where the cookie
        is served with ``Secure`` — browsers reject ``__Secure-`` / ``__Host-``
        cookies that arrive without it, which would otherwise break local http
        development. Reads and writes of the refresh cookie must go through this
        name so the set/clear/read sides stay in lockstep.
        """
        if self.refresh_cookie_prefix and self.is_deployed:
            return f"{self.refresh_cookie_prefix}{self.refresh_cookie_name}"
        return self.refresh_cookie_name

    @property
    def resolved_webauthn_rp_id(self) -> str:
        """WebAuthn Relying Party ID, falling back to the ``base_url`` host.

        Returns the explicit :attr:`webauthn_rp_id` when set, otherwise the
        hostname parsed from :attr:`base_url` (no scheme or port). Empty when
        neither is available — the WebAuthn endpoints treat that as a
        misconfiguration and fail fast.
        """
        if self.webauthn_rp_id:
            return self.webauthn_rp_id
        return urlparse(self.base_url).hostname or ""

    @property
    def resolved_webauthn_rp_name(self) -> str:
        """WebAuthn Relying Party display name, falling back to :attr:`app_name`."""
        return self.webauthn_rp_name or self.app_name

    @property
    def resolved_webauthn_origins(self) -> tuple[str, ...]:
        """Expected WebAuthn origins, falling back to the scheme+host of ``base_url``.

        Returns the explicit :attr:`webauthn_origins` when set, otherwise a
        single origin derived from :attr:`base_url` (scheme + host + port).
        Empty when neither is available.
        """
        return self.webauthn_origins or self._base_url_origin


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
