"""Application-supplied configuration for JAFAAL.

JAFAAL never reads environment variables or secret files itself. The host
application builds an :class:`AuthSettings` instance from whatever configuration
source it likes and installs it once at startup::

    import jafaal

    jafaal.configure(
        jafaal.AuthSettings(
            secrets=jafaal.Secrets(
                secret_key=my_secret,       # JWT signing / MAC key
                fernet_key=my_fernet_key,   # at-rest token encryption key
            ),
            base_url="https://app.example",
            app_name="Example",
        )
    )

All JAFAAL components read the installed settings through :func:`get_settings`.

**Shape.** Configuration is grouped by concern — :class:`Secrets`,
:class:`TokenSettings`, :class:`SessionSettings`, :class:`PasswordSettings`,
:class:`MfaSettings`, :class:`WebAuthnSettings`, :class:`SsoSettings`,
:class:`NetworkSettings`, :class:`RateLimitSettings`, :class:`ApiKeySettings`,
:class:`AuditSettings` — rather than being one flat list of options. A host
configuring passkeys reads one small class instead of scanning sixty unrelated
fields, each group carries its own validation and documentation, and a group can
gain options without enlarging the top-level surface. Only the handful of values
that genuinely describe the *deployment* (identity, environment, and the two
fail-closed opt-outs) sit at the top level.

Every object is immutable (``frozen``) and validated on construction, so
misconfiguration fails fast, and every key-bearing field is redacted from
``repr`` so secrets cannot reach a log line or traceback frame dump.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field, fields
from typing import Any
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
    "ApiKeySettings",
    "AuditSettings",
    "AuthSettings",
    "MfaSettings",
    "NetworkSettings",
    "OAuthClient",
    "PasswordSettings",
    "RateLimitSettings",
    "Secrets",
    "SessionSettings",
    "SsoSettings",
    "TokenSettings",
    "WebAuthnSettings",
    "configure",
    "get_settings",
    "is_configured",
    "reset",
    "settings_generation",
]

# JWT signing algorithms JAFAAL will accept. ``HS256`` (symmetric, the default)
# plus the asymmetric RSA/EC family (opt-in via ``Secrets.private_key``): sign
# with a private key, publish the public key at the JWKS endpoint, verify
# statelessly. ``alg=none`` and non-listed algorithms are never honoured, and the
# same allow-list is passed to ``jwt.decode`` so it cannot drift from signing.
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


def _redacting_repr(instance: Any) -> str:
    """Render a settings dataclass with every ``repr=False`` field redacted.

    Fields declared with ``field(repr=False)`` hold key material. Showing them as
    ``<redacted>`` rather than omitting them keeps the value visibly *present*
    when debugging a configuration problem, while guaranteeing the secret itself
    never reaches a log line, a traceback frame dump, or an error-tracker
    payload. The ``repr=False`` flag is the single source of truth: a new secret
    field only has to be declared with it to be covered.
    """
    rendered = ", ".join(
        f"{spec.name}=<redacted>" if not spec.repr else f"{spec.name}={getattr(instance, spec.name)!r}"
        for spec in fields(instance)
    )
    return f"{type(instance).__name__}({rendered})"


# ===========================================================================
# Secrets
# ===========================================================================


@dataclass(frozen=True)
class Secrets:
    """Key material, and the rotation fallbacks that keep it rotatable.

    Attributes:
        secret_key: HMAC key. Signs and verifies HS256 JWTs, and is stretched
            (HKDF, per purpose) into the keys that MAC every stored token digest
            — refresh tokens, CSRF tokens, API keys, reset/sign-up/link tokens,
            the WebAuthn user handle. Required regardless of ``algorithm``.
        fernet_key: Fernet key used to encrypt at-rest tokens (IdP client
            secrets, MFA secrets, rotated refresh tokens). A url-safe base64
            32-byte key as produced by ``cryptography.fernet.Fernet.generate_key``.
        secret_key_fallbacks: Additional HMAC keys accepted when *verifying*
            (never used to sign or to write a new digest), so credentials issued
            before a ``secret_key`` rotation stay valid during the overlap.
        fernet_key_fallbacks: Additional Fernet keys accepted when *decrypting*
            (never used to encrypt), enabling ``fernet_key`` rotation without a
            bulk re-encrypt.
        private_key: PEM private key used to sign JWTs when
            :attr:`TokenSettings.algorithm` is asymmetric (must be empty for
            HS256).
        private_key_fallbacks: Verify-only keys (PEM, public or private) kept in
            the published JWKS during a signing-key rotation overlap.
    """

    secret_key: str = field(repr=False)
    fernet_key: str = field(repr=False)
    secret_key_fallbacks: tuple[str, ...] = field(default=(), repr=False)
    fernet_key_fallbacks: tuple[str, ...] = field(default=(), repr=False)
    private_key: str = field(default="", repr=False)
    private_key_fallbacks: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if not self.secret_key:
            raise ValueError("Secrets.secret_key is required")
        if len(self.secret_key) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(
                f"Secrets.secret_key is too short (got {len(self.secret_key)} characters, "
                f"need at least {MIN_SECRET_KEY_LENGTH}). HS256 requires a high-entropy key; "
                "generate one with e.g. secrets.token_urlsafe(32)."
            )
        if not self.fernet_key:
            raise ValueError("Secrets.fernet_key is required")
        try:
            Fernet(self.fernet_key.encode())
        except Exception as err:
            raise ValueError(
                "Secrets.fernet_key is not a valid Fernet key. Expected a url-safe "
                "base64-encoded 32-byte key, e.g. cryptography.fernet.Fernet.generate_key()."
            ) from err
        for index, fallback in enumerate(self.secret_key_fallbacks):
            if len(fallback) < MIN_SECRET_KEY_LENGTH:
                raise ValueError(
                    f"Secrets.secret_key_fallbacks[{index}] is too short (got {len(fallback)} "
                    f"characters, need at least {MIN_SECRET_KEY_LENGTH})."
                )
        for index, fallback in enumerate(self.fernet_key_fallbacks):
            try:
                Fernet(fallback.encode())
            except Exception as err:
                raise ValueError(f"Secrets.fernet_key_fallbacks[{index}] is not a valid Fernet key.") from err

    def __repr__(self) -> str:
        """Render with every key-bearing field as ``<redacted>``."""
        return _redacting_repr(self)


# ===========================================================================
# Tokens
# ===========================================================================


@dataclass(frozen=True)
class TokenSettings:
    """JWT issuance, lifetimes, and the opt-in immediate-revocation controls.

    Attributes:
        algorithm: JWT signing algorithm. ``HS256`` (default, symmetric) or an
            asymmetric RSA/EC algorithm (RS256/384/512, PS256/384/512,
            ES256/384/512), which signs with :attr:`Secrets.private_key` and
            publishes the public key at the JWKS endpoint.
        access_token_expire_minutes: Access-token lifetime, in minutes.
        refresh_token_expire_days: Refresh-token lifetime, in days.
        issuer: JWT ``iss`` claim. Defaults to ``base_url`` when empty
            (see :attr:`AuthSettings.resolved_issuer`).
        audience: JWT ``aud`` claim. Defaults to ``base_url`` when empty
            (see :attr:`AuthSettings.resolved_audience`).
        client_id: Value of the ``client_id`` claim RFC 9068 requires on an
            access token. JAFAAL is a first-party issuer with no client
            registry, so this defaults to the resolved audience.
        leeway_seconds: Clock-skew tolerance applied to the ``exp``/``nbf``
            claims of JAFAAL's own JWTs. ``0`` (default) is strict; a small
            value avoids spurious 401s across slightly skewed nodes. Kept small
            so an expired token is not honoured for long.
        denylist_enabled: When ``True``, revoked access-token ``jti`` values are
            recorded and checked per request so ``/revoke`` kills an access
            token immediately (one state-store lookup per request). Off by
            default: access tokens are short-lived and lapse at expiry, and
            revoking the refresh token (which deletes the session) is the
            always-effective revocation path.
        reauthorize_scopes_per_request: When ``True``, an access token's scopes
            are intersected with what the host's
            :class:`~jafaal.ports.ScopeResolver` grants the account on *this*
            request, so a demotion applies immediately rather than at token
            expiry. Strictly narrowing — a token never gains a scope it was not
            issued with. Off by default; adds no query (the user row is already
            loaded every request), only the narrowing. Applies to access tokens
            only: API keys are narrowed unconditionally, because they are
            long-lived (``expires_at`` is optional) and so cannot rely on expiry
            to shed stale authority.
    """

    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    issuer: str = ""
    audience: str = ""
    client_id: str = ""
    leeway_seconds: int = 0
    denylist_enabled: bool = False
    reauthorize_scopes_per_request: bool = False

    def __post_init__(self) -> None:
        if self.algorithm not in ALLOWED_ALGORITHMS:
            raise ValueError(
                f"TokenSettings.algorithm={self.algorithm!r} is not in the allow-list {sorted(ALLOWED_ALGORITHMS)}"
            )
        if self.access_token_expire_minutes <= 0:
            raise ValueError("TokenSettings.access_token_expire_minutes must be positive")
        if self.refresh_token_expire_days <= 0:
            raise ValueError("TokenSettings.refresh_token_expire_days must be positive")
        if self.leeway_seconds < 0:
            raise ValueError("TokenSettings.leeway_seconds must be non-negative")

    @property
    def is_asymmetric(self) -> bool:
        """Whether :attr:`algorithm` signs with a private key rather than a shared secret."""
        return self.algorithm in jwk_keys.ASYMMETRIC_ALGORITHMS


# ===========================================================================
# Sessions and the refresh cookie
# ===========================================================================


@dataclass(frozen=True)
class SessionSettings:
    """Session lifetime, revocation strictness, and refresh-cookie delivery.

    Attributes:
        idle_timeout_enabled: Whether *idle*-session expiry is enforced. The
            absolute lifetime below is always enforced and does not depend on
            this flag.
        idle_timeout_hours: Idle-session timeout, in hours.
        absolute_timeout_hours: Hard ceiling on how long a session may live,
            measured from ``created_at`` and **always enforced**. A session's
            ``expires_at`` is capped at this deadline on every rotation, so
            refreshing cannot slide the window forward indefinitely — without
            the cap, a client that refreshes once per ``refresh_token_expire_days``
            keeps one login alive forever, which is exactly the unbounded
            refresh-token lifetime RFC 9700 §4.14.2 warns against. Defaults to
            30 days: long enough not to be user-hostile, finite enough that a
            stolen session eventually dies on its own.
        strict_binding: When ``True``, every access-token-authenticated request
            verifies the token's ``sid`` session still exists and is valid, so
            logout / single-session revocation is immediate instead of bounded
            by the access-token lifetime. Off by default (stateless
            access-token validation); adds one indexed session lookup per
            request. A deactivated *user* is rejected immediately regardless.
        refresh_cookie_name: Name of the refresh-token cookie.
        refresh_cookie_path: Path scope of the refresh-token cookie. Must line
            up with where the auth router is mounted, or web sessions silently
            fail to refresh.
        refresh_cookie_prefix: Optional cookie-name-prefix hardening, applied
            only in a *deployed* environment (browsers reject these prefixes on
            a cookie that arrives without ``Secure``, which would break local
            http development). ``"__Secure-"`` asserts the cookie was set with
            ``Secure``; ``"__Host-"`` additionally binds it to the exact host
            and requires ``refresh_cookie_path="/"``.
        csrf_trusted_origins: Origins allowed to drive the web refresh flow and
            the cookie-issuing login endpoints. Defaults to the origin of
            ``base_url``; set explicitly when the frontend is served from a
            different origin than the API.
    """

    idle_timeout_enabled: bool = False
    idle_timeout_hours: int = 1
    absolute_timeout_hours: int = 720
    strict_binding: bool = False
    refresh_cookie_name: str = "jafaal_refresh_token"
    refresh_cookie_path: str = "/api/v1/auth"
    refresh_cookie_prefix: str = ""
    csrf_trusted_origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.idle_timeout_hours <= 0:
            raise ValueError("SessionSettings.idle_timeout_hours must be positive")
        if self.absolute_timeout_hours <= 0:
            raise ValueError(
                "SessionSettings.absolute_timeout_hours must be positive: a session's lifetime is "
                "always bounded, so there is no value meaning 'never expires'."
            )
        if self.refresh_cookie_prefix not in ("", "__Secure-", "__Host-"):
            raise ValueError(
                "SessionSettings.refresh_cookie_prefix must be '', '__Secure-', or '__Host-' "
                f"(got {self.refresh_cookie_prefix!r})."
            )
        if self.refresh_cookie_prefix == "__Host-" and self.refresh_cookie_path != "/":
            raise ValueError(
                "SessionSettings.refresh_cookie_prefix='__Host-' requires refresh_cookie_path='/': "
                "the __Host- prefix mandates Path=/ and no Domain. Use '__Secure-' to keep a "
                "path-scoped refresh cookie."
            )


# ===========================================================================
# Passwords
# ===========================================================================


@dataclass(frozen=True)
class PasswordSettings:
    """Argon2 cost parameters and the accepted password length bound.

    Attributes:
        argon2_time_cost: Argon2 time cost (iterations).
        argon2_memory_cost: Argon2 memory cost, in KiB.
        argon2_parallelism: Argon2 parallelism (lanes).
        max_length: Maximum accepted password length, enforced *before* hashing
            so an unauthenticated caller cannot force unbounded Argon2 work.
            Must be at least 64 so long passphrases are accepted (NIST
            SP 800-63B). Passwords are never truncated.
    """

    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4
    max_length: int = 128

    def __post_init__(self) -> None:
        if self.argon2_time_cost <= 0:
            raise ValueError("PasswordSettings.argon2_time_cost must be positive")
        if self.argon2_memory_cost <= 0:
            raise ValueError("PasswordSettings.argon2_memory_cost must be positive")
        if self.argon2_parallelism <= 0:
            raise ValueError("PasswordSettings.argon2_parallelism must be positive")
        if self.max_length < 64:
            raise ValueError(
                "PasswordSettings.max_length must be at least 64 so long passphrases are "
                "accepted (NIST SP 800-63B recommends allowing at least 64 characters)."
            )


# ===========================================================================
# Multi-factor authentication
# ===========================================================================


@dataclass(frozen=True)
class MfaSettings:
    """TOTP replay-protection policy.

    Attributes:
        totp_replay_fail_open: TOTP single-use replay protection is
            defense-in-depth on top of the (unchanged) TOTP signature check, but
            it needs the shared state store. When ``False`` (default) an
            unreachable store fails *closed*: the code is rejected as a 503
            rather than accepted without replay protection. ``True`` prefers
            availability — the code is accepted and the degraded check is logged
            and audited.
    """

    totp_replay_fail_open: bool = False


# ===========================================================================
# WebAuthn / passkeys
# ===========================================================================


@dataclass(frozen=True)
class WebAuthnSettings:
    """Relying-Party identity and ceremony policy for passkeys.

    Attributes:
        rp_id: Relying Party ID — the registrable domain passkeys are scoped to
            (e.g. ``"example.com"``; no scheme or port). Must be a registrable
            suffix of every origin the app is served from. Defaults to the
            ``base_url`` host.
        rp_name: Human-readable Relying Party name shown by the authenticator.
            Defaults to ``app_name``.
        origins: Exact origins (scheme + host + port) a ceremony may complete
            from. Defaults to the origin of ``base_url``.
        user_verification: User-verification requirement for the *second-factor*
            ceremony: ``"required"`` forces the authenticator to verify the user
            (PIN/biometric), ``"preferred"`` (default) verifies where supported,
            ``"discouraged"`` skips it. The passwordless ceremony always
            requires user verification regardless of this value — there the
            passkey is the entire authentication.
        attestation: Attestation conveyance requested at registration. ``"none"``
            (default) asks for no attestation statement (best for privacy and
            interoperability); ``"direct"`` requests it so the host can inspect
            the authenticator model. JAFAAL does not verify attestation
            certificates — request ``"direct"`` only if the host processes them.
        second_factor_enabled: When ``True``, a user with registered passkeys
            must present one as a second factor after a successful password
            login. Off by default; passwordless authentication is always
            available regardless.
        challenge_ttl_seconds: Lifetime of a challenge held in the state store
            before it must be redeemed. Kept short (a ceremony is interactive
            and immediate) to bound replay of a leaked challenge.
    """

    rp_id: str = ""
    rp_name: str = ""
    origins: tuple[str, ...] = ()
    user_verification: str = "preferred"
    attestation: str = "none"
    second_factor_enabled: bool = False
    challenge_ttl_seconds: int = 300

    def __post_init__(self) -> None:
        if self.user_verification not in ("required", "preferred", "discouraged"):
            raise ValueError(
                "WebAuthnSettings.user_verification must be 'required', 'preferred', or "
                f"'discouraged' (got {self.user_verification!r})."
            )
        if self.attestation not in ("none", "direct"):
            raise ValueError(f"WebAuthnSettings.attestation must be 'none' or 'direct' (got {self.attestation!r}).")
        if self.challenge_ttl_seconds <= 0:
            raise ValueError("WebAuthnSettings.challenge_ttl_seconds must be positive")


# ===========================================================================
# Single sign-on
# ===========================================================================


@dataclass(frozen=True)
class SsoSettings:
    """Identity-provider flows: transport policy and step-up.

    Notably absent is anything describing *where* to send the browser after a
    flow. Post-login, post-link and post-step-up targets all come from the
    initiating request's ``redirect_uri``, matched exactly against the calling
    :class:`OAuthClient`'s registration. A configured frontend path would be a
    second, weaker redirect rule sitting beside the exact-match one — and the
    weaker rule is the one an attacker would use.

    Attributes:
        idp_require_https: When ``True`` (default), identity-provider endpoints
            (the browser-facing authorization endpoint and the server-side
            token, userinfo, JWKS, discovery and revocation URLs) must use
            ``https``, refusing to transmit authorization codes, tokens and
            client credentials in cleartext. Set ``False`` only for local or
            self-hosted development.
        step_up_idp_reauth_enabled: Whether an SSO-only account (no local
            password and no MFA) may satisfy step-up verification by
            re-authenticating at a linked identity provider. When ``False`` such
            accounts are refused sensitive operations (step-up fails closed).
        step_up_reauth_max_age_seconds: Maximum age of the IdP authentication
            (the ID token ``auth_time`` claim) accepted as "fresh" for step-up.
            Also sent as the OIDC ``max_age`` so the provider re-prompts.
        step_up_grant_ttl_seconds: Lifetime of the single-use step-up grant
            minted after a successful IdP re-authentication; the caller must
            retry the sensitive operation within this window.
        id_token_leeway_seconds: Clock-skew tolerance applied to an IdP ID
            token's ``exp``/``iat``/``nbf``. These clocks belong to someone
            else, and a strict ``0`` rejects a token whose ``iat`` is a single
            second ahead of ours — OIDC Core §3.1.3.7 (10) anticipates an
            implementer allowance.
        max_response_bytes: Largest response body accepted from an identity
            provider (discovery, JWKS, userinfo). Timeouts bound how long JAFAAL
            waits, not how much it accepts, and the JWKS is cached — so without
            a cap one hostile response is a persistent memory cost.
    """

    idp_require_https: bool = True
    step_up_idp_reauth_enabled: bool = True
    step_up_reauth_max_age_seconds: int = 300
    step_up_grant_ttl_seconds: int = 120
    id_token_leeway_seconds: int = 60
    max_response_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if self.step_up_reauth_max_age_seconds <= 0:
            raise ValueError("SsoSettings.step_up_reauth_max_age_seconds must be positive")
        if self.step_up_grant_ttl_seconds <= 0:
            raise ValueError("SsoSettings.step_up_grant_ttl_seconds must be positive")
        if self.id_token_leeway_seconds < 0:
            raise ValueError("SsoSettings.id_token_leeway_seconds must be non-negative")
        if self.max_response_bytes <= 0:
            raise ValueError("SsoSettings.max_response_bytes must be positive")


# ===========================================================================
# Network
# ===========================================================================


@dataclass(frozen=True)
class NetworkSettings:
    """Proxy trust, SSRF policy, and the outbound user agent.

    Attributes:
        trusted_proxies: Peers and forwarding hops whose ``X-Forwarded-For`` /
            ``X-Real-IP`` headers are honoured. Empty by default, which trusts
            only the direct TCP peer — the safe default: proxy headers from
            arbitrary clients are ignored, so a client cannot spoof its source
            IP. Behind a reverse proxy list **every** hop your infrastructure
            adds (e.g. both the CDN egress ranges and the reverse proxy),
            because the forwarded chain is resolved right-to-left and stops at
            the first hop that is not listed. ``("*",)`` trusts every hop (only
            safe when a trusted proxy always overwrites the header).
        ssrf_allowed_hosts: Hosts/CIDRs exempted from the SSRF private-address
            guard on outbound OIDC calls.
        user_agent: ``User-Agent`` header sent on outbound OIDC HTTP calls.
    """

    trusted_proxies: tuple[str, ...] = ()
    ssrf_allowed_hosts: tuple[str, ...] = ()
    user_agent: str = "Jafaal (OIDC Client)"


# ===========================================================================
# Rate limiting
# ===========================================================================


@dataclass(frozen=True)
class RateLimitSettings:
    """Canonical request budgets for the host's :class:`~jafaal.rate_limit.RateLimiter`.

    Attributes:
        sensitive: Budget for sensitive endpoints (login, MFA, password reset,
            sign-up, OAuth, API-key minting).
        write: Budget for write endpoints (logout, refresh, session and API-key
            revocation, introspection).
    """

    sensitive: str = "10/minute"
    write: str = "30/minute"


# ===========================================================================
# API keys
# ===========================================================================


@dataclass(frozen=True)
class ApiKeySettings:
    """API-key format and transport policy.

    Attributes:
        prefix: Prefix for generated API keys (``<prefix>_<token>``).
        allow_query_param: Whether API keys may be supplied via the
            ``?api_key=`` query string. Off by default: credentials in query
            strings appear in access logs, proxy histories, and browser history.
            Enable only for integrations that genuinely cannot set a header.
    """

    prefix: str = "jafaal"
    allow_query_param: bool = False


# ===========================================================================
# Audit
# ===========================================================================


@dataclass(frozen=True)
class AuditSettings:
    """Privacy policy for the ``jafaal.audit`` stream.

    Attributes:
        include_pii: When ``True`` (default), audit records carry direct
            identifiers (plaintext username, client IP, email) — the signal a
            SIEM needs to spot targeted brute-force. Set ``False`` to drop them
            (substituting a one-way username hash) for PII-minimal retention.
    """

    include_pii: bool = True


# ===========================================================================
# OAuth clients (RFC 8252 public clients)
# ===========================================================================

#: Token-delivery modes a registered client may be configured with.
#:
#: ``body`` is the RFC 6749 §5.1 response: every token in the JSON body. It is
#: the only correct mode for a non-browser client.
#:
#: ``cookie`` additionally moves the refresh token into an ``HttpOnly``,
#: ``SameSite=Strict`` cookie and returns a CSRF token in its place, per
#: RFC 9700 §7.2's advice not to expose refresh tokens to page script. The
#: response is then a superset of the RFC 6749 token response minus
#: ``refresh_token``.
TOKEN_DELIVERY_MODES: frozenset[str] = frozenset({"body", "cookie"})

#: Loopback hosts RFC 8252 §7.3 permits a plain-``http`` redirect URI to use.
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})


@dataclass(frozen=True)
class OAuthClient:
    """A registered public client, and the policy that applies to its tokens.

    The client is the **unit of policy**. Delivery mode and scope ceiling are
    properties of the registration, never of the request: a value a caller can
    choose per-request is a value an attacker can choose, and JAFAAL previously
    carried both in a header (``X-Client-Type``) that had to be defended with
    mismatch detection. Configuration removes the attack surface instead of
    guarding it.

    Registration also supplies the one thing RFC 9700 §4.1 makes mandatory and
    that is impossible without it: **exact** ``redirect_uri`` matching. Without a
    registered list there is nothing to match against, and an authorization code
    can be steered to an attacker-controlled target.

    Clients are public (RFC 8252): a native app or browser cannot keep a secret,
    so PKCE — not client authentication — binds a code to its requester.

    Attributes:
        client_id: The identifier the client sends as ``client_id``. Any stable
            opaque string; a reverse-DNS name (``com.example.app``) is
            conventional for native apps.
        redirect_uris: Every URI the client may receive an authorization code
            at, matched **exactly** (byte-for-byte, per RFC 9700 §4.1.3 — no
            prefix, wildcard, or path-suffix matching). A plain-``http`` URI is
            accepted only for loopback (RFC 8252 §7.3). Not required for a
            client that only uses the direct login and refresh endpoints.
        token_delivery: ``"body"`` (default, RFC 6749 §5.1) or ``"cookie"``
            (RFC 9700 §7.2 — refresh token as an ``HttpOnly`` cookie, CSRF token
            in the body). Browser clients want ``cookie``; everything else wants
            ``body``.
        scopes: Ceiling on what this client's tokens may carry, intersected with
            what the host's :class:`~jafaal.ports.ScopeResolver` grants the user.
            Empty (default) means "whatever the user holds", which is correct for
            a first-party app that *is* the application. Set it for any client
            you do not control: without a ceiling, registering a client grants it
            the user's entire account, and JAFAAL has no consent screen to ask
            the user about it.
        name: Human-readable label, used in logs and audit records.
    """

    client_id: str
    redirect_uris: tuple[str, ...] = ()
    token_delivery: str = "body"
    scopes: tuple[str, ...] = ()
    name: str = ""

    def __post_init__(self) -> None:
        if not self.client_id:
            raise ValueError("OAuthClient.client_id is required")
        if self.token_delivery not in TOKEN_DELIVERY_MODES:
            raise ValueError(
                f"OAuthClient(client_id={self.client_id!r}).token_delivery must be one of "
                f"{sorted(TOKEN_DELIVERY_MODES)} (got {self.token_delivery!r})."
            )
        for uri in self.redirect_uris:
            _validate_redirect_uri(self.client_id, uri)

    def permits(self, redirect_uri: str) -> bool:
        """Return whether ``redirect_uri`` is registered for this client.

        Compared in constant time and byte-for-byte. RFC 9700 §4.1.3 requires
        exact matching precisely because every relaxation (prefix, wildcard,
        sub-path) has been used to exfiltrate authorization codes.
        """
        matched = False
        for registered in self.redirect_uris:
            matched |= hmac.compare_digest(registered, redirect_uri)
        return matched

    @property
    def uses_cookie_delivery(self) -> bool:
        """Whether this client's refresh token is delivered as a cookie.

        The single predicate every delivery decision branches on — cookie write,
        CSRF binding, off-site rejection, and the ``202`` MFA status — so those
        four cannot drift apart.
        """
        return self.token_delivery == "cookie"

    def narrow(self, granted: tuple[str, ...]) -> tuple[str, ...]:
        """Intersect ``granted`` with this client's ceiling.

        Strictly narrowing: a client can only ever receive less than the user
        holds, never more. An empty ceiling means no narrowing.

        Args:
            granted: The scopes the user is entitled to.

        Returns:
            The scopes this client's token may carry.
        """
        if not self.scopes:
            return granted
        ceiling = set(self.scopes)
        return tuple(scope for scope in granted if scope in ceiling)


def _validate_redirect_uri(client_id: str, uri: str) -> None:
    """Reject a redirect URI that is malformed or transmits a code in cleartext.

    Args:
        client_id: Owning client, for the error message.
        uri: The candidate redirect URI.

    Raises:
        ValueError: If the URI is empty, carries a fragment (RFC 6749 §3.1.2),
            or uses plain ``http`` for a non-loopback host (RFC 8252 §7.3 allows
            ``http`` only for loopback, because anything else puts the
            authorization code on the wire in clear).
    """
    if not uri:
        raise ValueError(f"OAuthClient(client_id={client_id!r}) redirect_uri must not be empty.")
    if "#" in uri:
        raise ValueError(
            f"OAuthClient(client_id={client_id!r}) redirect_uri {uri!r} must not carry a fragment (RFC 6749 §3.1.2)."
        )
    parsed = urlparse(uri)
    if parsed.scheme == "http" and (parsed.hostname or "") not in _LOOPBACK_HOSTS:
        raise ValueError(
            f"OAuthClient(client_id={client_id!r}) redirect_uri {uri!r} uses plain http for a non-loopback "
            f"host. RFC 8252 §7.3 permits http only for loopback ({sorted(_LOOPBACK_HOSTS)}); use https or a "
            "private-use scheme."
        )


# ===========================================================================
# Root
# ===========================================================================


@dataclass(frozen=True)
class AuthSettings:
    """Immutable, host-supplied configuration for the auth library.

    Only values describing the deployment as a whole live here; everything else
    is grouped by concern (see the module docstring).

    Attributes:
        secrets: Key material and its rotation fallbacks. The one required
            group.
        base_url: Public base URL of the host app. Used to build SSO redirect
            and error URLs, and as the default JWT issuer/audience, WebAuthn RP
            ID and origin, and CSRF trusted origin.
        app_name: Human-readable application name; used as the MFA TOTP issuer
            shown in authenticator apps and as the default WebAuthn RP name.
        environment: Deployment environment. Must be one of
            :data:`KNOWN_ENVIRONMENTS`; the :data:`DEPLOYED_ENVIRONMENTS`
            members are treated as deployed, which drives the cookie ``Secure``
            flag, the cookie-name prefix, and the two fail-closed startup
            guards. An unrecognised value is rejected at construction rather
            than silently treated as local. Defaults to the safest value, so
            forgetting to set it cannot weaken a deployment.
        store_key_prefix: Namespace prefix for state-store keys (lockout
            counters, MFA setup secrets, WebAuthn challenges, ...).
        login_token_url: URL FastAPI's Swagger *Authorize* dialog posts the
            username/password form to. Cosmetic — it configures the
            ``OAuth2PasswordBearer`` scheme's ``tokenUrl`` and nothing else;
            JAFAAL does not implement the OAuth password grant.
        login_ip_lockout_enabled: When ``True`` (default), a per-source-IP
            backoff bounds how many accounts one IP can lock out by spraying
            failed logins across usernames (the per-account lockout is
            otherwise a cheap targeted-DoS lever). Relies on an accurate client
            IP (configure ``network.trusted_proxies`` behind a reverse proxy);
            disable if a shared egress IP causes false lockouts.
        allow_in_memory_state_store_when_deployed: Permit the process-local
            in-memory :class:`~jafaal.state_store.StateStore` in a *deployed*
            environment. Off by default: startup refuses, because a
            multi-worker/replica deployment would fragment progressive-lockout
            and TOTP-replay state per worker. Set ``True`` only for a genuine
            single-worker deployment.
        allow_no_rate_limit_when_deployed: Permit a deployed environment to run
            with the no-op rate limiter. Off by default; mirror of the above.
        tokens: JWT issuance and revocation policy.
        sessions: Session lifetime and refresh-cookie delivery.
        passwords: Argon2 cost and length bounds.
        mfa: TOTP replay policy.
        webauthn: Passkey Relying-Party identity and ceremony policy.
        sso: Identity-provider flows and step-up.
        network: Proxy trust and SSRF policy.
        rate_limits: Canonical request budgets.
        api_keys: API-key format and transport policy.
        audit: Audit-stream privacy policy.
    """

    secrets: Secrets

    # --- deployment identity ---
    base_url: str = ""
    app_name: str = "Jafaal"
    environment: str = "production"
    store_key_prefix: str = "jafaal:auth"
    login_token_url: str = "/api/v1/auth/login"

    # --- registered public clients (RFC 8252) ---
    # Empty by default: a deployment that only serves its own first-party web
    # frontend needs none. Register one per native app that drives the
    # authorization-code flow; the authorization endpoint refuses any
    # client_id / redirect_uri pair not listed here.
    oauth_clients: tuple[OAuthClient, ...] = ()

    # --- deployment-wide security toggles ---
    login_ip_lockout_enabled: bool = True
    allow_in_memory_state_store_when_deployed: bool = False
    allow_no_rate_limit_when_deployed: bool = False

    # --- grouped configuration ---
    tokens: TokenSettings = field(default_factory=TokenSettings)
    sessions: SessionSettings = field(default_factory=SessionSettings)
    passwords: PasswordSettings = field(default_factory=PasswordSettings)
    mfa: MfaSettings = field(default_factory=MfaSettings)
    webauthn: WebAuthnSettings = field(default_factory=WebAuthnSettings)
    sso: SsoSettings = field(default_factory=SsoSettings)
    network: NetworkSettings = field(default_factory=NetworkSettings)
    rate_limits: RateLimitSettings = field(default_factory=RateLimitSettings)
    api_keys: ApiKeySettings = field(default_factory=ApiKeySettings)
    audit: AuditSettings = field(default_factory=AuditSettings)

    def __post_init__(self) -> None:
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
        # Cross-group rule: the signing algorithm and the key material that
        # backs it are configured separately, so their consistency can only be
        # checked here.
        if self.tokens.is_asymmetric:
            if not self.secrets.private_key:
                raise ValueError(
                    f"tokens.algorithm={self.tokens.algorithm!r} is asymmetric and requires secrets.private_key (PEM)."
                )
            try:
                jwk_keys.import_private_signing_key(self.secrets.private_key, self.tokens.algorithm)
            except ValueError as err:
                raise ValueError(f"Secrets.private_key is invalid: {err}") from err
            for index, fallback in enumerate(self.secrets.private_key_fallbacks):
                try:
                    jwk_keys.import_verification_key(fallback, self.tokens.algorithm)
                except ValueError as err:
                    raise ValueError(f"Secrets.private_key_fallbacks[{index}] is invalid: {err}") from err
        elif self.secrets.private_key or self.secrets.private_key_fallbacks:
            raise ValueError(
                "Secrets.private_key / private_key_fallbacks are set but "
                f"tokens.algorithm={self.tokens.algorithm!r} is symmetric (HS256). Use an asymmetric "
                "algorithm (e.g. RS256 / ES256) or remove the keys."
            )
        seen_client_ids: set[str] = set()
        for client in self.oauth_clients:
            if client.client_id in seen_client_ids:
                raise ValueError(
                    f"AuthSettings.oauth_clients contains duplicate client_id {client.client_id!r}; "
                    "the first match would silently win and the second's redirect_uris would never apply."
                )
            seen_client_ids.add(client.client_id)

    def oauth_client(self, client_id: str) -> OAuthClient | None:
        """Return the registered client with ``client_id``, or ``None``.

        Args:
            client_id: The identifier presented by the caller.

        Returns:
            The matching :class:`OAuthClient`, or ``None`` when unregistered.
        """
        for client in self.oauth_clients:
            if hmac.compare_digest(client.client_id, client_id):
                return client
        return None

    def __repr__(self) -> str:
        """Render the settings, delegating secret redaction to each group's repr."""
        return _redacting_repr(self)

    # --- derived values that span groups ---

    @property
    def is_deployed(self) -> bool:
        """Whether the environment is a deployed one.

        True for every name in :data:`DEPLOYED_ENVIRONMENTS`. The value is
        validated at construction, so an unrecognised environment can never
        silently fall through to ``False``.
        """
        return self.environment in DEPLOYED_ENVIRONMENTS

    @property
    def resolved_issuer(self) -> str:
        """JWT issuer, falling back to :attr:`base_url` when unset."""
        return self.tokens.issuer or self.base_url

    @property
    def resolved_audience(self) -> str:
        """JWT audience, falling back to :attr:`base_url` when unset."""
        return self.tokens.audience or self.base_url

    @property
    def resolved_client_id(self) -> str:
        """``client_id`` claim value, falling back to the resolved audience.

        RFC 9068 §2.2 requires ``client_id`` on an access token. JAFAAL issues
        first-party tokens and has no client registry, so the audience (i.e. the
        application the token is for) is the meaningful identifier unless the
        host sets one explicitly.
        """
        return self.tokens.client_id or self.resolved_audience

    @property
    def _base_url_origin(self) -> tuple[str, ...]:
        """The scheme+host+port origin of :attr:`base_url`, or empty when unusable."""
        parsed = urlparse(self.base_url)
        if parsed.scheme and parsed.netloc:
            return (f"{parsed.scheme}://{parsed.netloc}",)
        return ()

    @property
    def resolved_csrf_trusted_origins(self) -> tuple[str, ...]:
        """Origins permitted to drive the cookie-issuing web flows.

        Returns the explicit :attr:`SessionSettings.csrf_trusted_origins` when
        set, otherwise the origin of :attr:`base_url`. Empty when neither is
        available, in which case the ``Origin`` comparison is skipped and only
        the browser's ``Sec-Fetch-Site`` signal is enforced.
        """
        return self.sessions.csrf_trusted_origins or self._base_url_origin

    @property
    def effective_refresh_cookie_name(self) -> str:
        """Refresh-cookie name including any ``__Secure-`` / ``__Host-`` prefix.

        The prefix is applied only in a *deployed* environment, where the cookie
        is served with ``Secure`` — browsers reject ``__Secure-`` / ``__Host-``
        cookies that arrive without it, which would otherwise break local http
        development. Reads and writes of the refresh cookie must go through this
        name so the set/clear/read sides stay in lockstep.
        """
        if self.sessions.refresh_cookie_prefix and self.is_deployed:
            return f"{self.sessions.refresh_cookie_prefix}{self.sessions.refresh_cookie_name}"
        return self.sessions.refresh_cookie_name

    @property
    def resolved_webauthn_rp_id(self) -> str:
        """WebAuthn Relying Party ID, falling back to the ``base_url`` host.

        Empty when neither is available — the WebAuthn endpoints treat that as a
        misconfiguration and fail fast.
        """
        if self.webauthn.rp_id:
            return self.webauthn.rp_id
        return urlparse(self.base_url).hostname or ""

    @property
    def resolved_webauthn_rp_name(self) -> str:
        """WebAuthn Relying Party display name, falling back to :attr:`app_name`."""
        return self.webauthn.rp_name or self.app_name

    @property
    def resolved_webauthn_origins(self) -> tuple[str, ...]:
        """Expected WebAuthn origins, falling back to the origin of ``base_url``."""
        return self.webauthn.origins or self._base_url_origin


# ---------------------------------------------------------------------------
# Installed-settings accessor
# ---------------------------------------------------------------------------

# Backed by the shared ConfigSlot so settings use the same configure/get/reset
# machinery as the ports/scopes/state-store/rate-limiter singletons. The slot's
# generation counter is what settings-derived caches (the token manager, the
# HKDF subkeys, the password hasher) watch to rebuild after a reconfigure.
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
