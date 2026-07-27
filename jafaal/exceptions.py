"""Framework-agnostic authentication error hierarchy.

The JAFAAL core raises these instead of ``fastapi.HTTPException``; a single edge
handler (``jafaal.error_handler`` / ``create_auth_router``) maps them to HTTP
responses once, at the boundary. **No ``fastapi`` import here** — a non-HTTP host
can switch on the stable :attr:`JafaalError.code` slug and ignore the
:attr:`JafaalError.status_code` / :attr:`JafaalError.headers` HTTP hints.

Contract:
- ``code`` — stable, machine-readable slug (the framework-neutral API contract).
- ``status_code`` — default HTTP status (a hint for HTTP hosts).
- ``headers`` — default response headers hint (e.g. ``WWW-Authenticate``).
- ``detail`` — human-readable message (per-instance, defaults to
  ``default_detail``).
"""

from __future__ import annotations


class JafaalError(Exception):
    """Base class for all JAFAAL domain errors."""

    code: str = "error"
    status_code: int = 500
    default_detail: str = "An unexpected error occurred."
    headers: dict[str, str] | None = None

    def __init__(self, detail: str | None = None, *, headers: dict[str, str] | None = None) -> None:
        self.detail = detail if detail is not None else self.default_detail
        if headers is not None:
            self.headers = headers
        super().__init__(self.detail)


# ===========================================================================
# Categories (default status / headers)
# ===========================================================================


class AuthenticationError(JafaalError):
    """The caller could not be authenticated (401)."""

    code = "authentication_error"
    status_code = 401
    default_detail = "Authentication required."
    headers = {"WWW-Authenticate": "Bearer"}


class AuthorizationError(JafaalError):
    """The caller is authenticated but not permitted (403)."""

    code = "authorization_error"
    status_code = 403
    default_detail = "You do not have permission to perform this action."


class InvalidRequestError(JafaalError):
    """The request is malformed or semantically invalid (400)."""

    code = "invalid_request"
    status_code = 400
    default_detail = "The request is invalid."


class UnprocessableError(InvalidRequestError):
    """The request is well-formed but cannot be processed (422)."""

    code = "unprocessable"
    status_code = 422
    default_detail = "The request could not be processed."


class NotFoundError(JafaalError):
    """The requested resource does not exist (404)."""

    code = "not_found"
    status_code = 404
    default_detail = "The requested resource was not found."


class ConflictError(JafaalError):
    """The request conflicts with the current state (409)."""

    code = "conflict"
    status_code = 409
    default_detail = "The request conflicts with the current state."


class PreconditionFailedError(JafaalError):
    """A precondition for the request was not met (412)."""

    code = "precondition_failed"
    status_code = 412
    default_detail = "A precondition for this request was not met."


class RateLimitedError(JafaalError):
    """The caller has been rate limited (429).

    ``retry_after`` (seconds) is surfaced as the ``Retry-After`` header.
    """

    code = "rate_limited"
    status_code = 429
    default_detail = "Too many requests. Please try again later."

    def __init__(
        self,
        detail: str | None = None,
        *,
        retry_after: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.retry_after = retry_after
        merged = dict(headers) if headers else {}
        if retry_after is not None and "Retry-After" not in merged:
            merged["Retry-After"] = str(retry_after)
        super().__init__(detail, headers=merged or None)


class UpstreamError(JafaalError):
    """An upstream provider returned a bad response (502)."""

    code = "upstream_error"
    status_code = 502
    default_detail = "The upstream provider returned an error."


class UpstreamTimeoutError(UpstreamError):
    """An upstream provider timed out (504)."""

    code = "upstream_timeout"
    status_code = 504
    default_detail = "The upstream provider timed out."


class ServiceUnavailableError(JafaalError):
    """A required dependency is temporarily unavailable (503)."""

    code = "service_unavailable"
    status_code = 503
    default_detail = "The service is temporarily unavailable."


class InternalError(JafaalError):
    """An unexpected internal error (500)."""

    code = "internal_error"
    status_code = 500
    default_detail = "An internal error occurred."


# ===========================================================================
# Catchable leaves
# ===========================================================================


class InvalidCredentialsError(AuthenticationError):
    """Username/password (or equivalent) did not verify."""

    code = "invalid_credentials"
    default_detail = "Unable to authenticate with provided credentials."


class TokenExpiredError(AuthenticationError):
    """A JWT (access/refresh) has expired."""

    code = "token_expired"
    default_detail = "The token has expired."


class InvalidTokenError(AuthenticationError):
    """A JWT is malformed, has a bad signature, or fails claim validation."""

    code = "invalid_token"
    default_detail = "The token is invalid."


class SessionExpiredError(AuthenticationError):
    """The server-side session is missing or expired."""

    code = "session_expired"
    default_detail = "The session has expired. Please log in again."


class InvalidApiKeyError(AuthenticationError):
    """The supplied API key is unknown, revoked, or malformed."""

    code = "invalid_api_key"
    default_detail = "The API key is invalid."
    headers = {"WWW-Authenticate": "ApiKey"}


class StaleRefreshTokenError(AuthenticationError):
    """A rotated/replayed refresh token was presented; clear the cookie.

    Replaces the old ``ClearRefreshTokenCookieHTTPException``: the edge handler
    reads :attr:`clear_refresh_cookie` and emits the refresh-cookie deletion
    headers on the response.
    """

    code = "stale_refresh_token"
    default_detail = "The refresh token is no longer valid. Please log in again."
    clear_refresh_cookie = True


class MissingScopeError(AuthorizationError):
    """The principal lacks one or more required scopes.

    Carries an RFC 6750 §3 ``WWW-Authenticate`` challenge built from the scopes
    the endpoint requires:
    ``Bearer error="insufficient_scope", scope="users:read users:write"``. The
    ``scope`` attribute is a **space-delimited** list per RFC 6749 §3.3 — a
    client parsing the challenge to decide what to re-request needs that exact
    shape, so it is built here rather than at each raise site.
    """

    code = "missing_scope"
    default_detail = "You do not have the required permissions."

    def __init__(
        self,
        detail: str | None = None,
        *,
        missing: frozenset[str] | set[str] | None = None,
        required: frozenset[str] | set[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.missing: frozenset[str] = frozenset(missing or ())
        self.required: frozenset[str] = frozenset(required or ()) or self.missing
        super().__init__(detail, headers=headers or self._challenge())

    def _challenge(self) -> dict[str, str]:
        """Build the RFC 6750 ``insufficient_scope`` challenge header."""
        challenge = 'Bearer error="insufficient_scope"'
        if self.required:
            challenge += f', scope="{" ".join(sorted(self.required))}"'
        return {"WWW-Authenticate": challenge}


class StepUpReauthRequiredError(AuthenticationError):
    """Step-up needs a fresh identity-provider re-authentication.

    Raised for an SSO-only account (no local password and no MFA) that has at
    least one usable identity-provider link: a valid access token alone cannot
    satisfy step-up, so the caller must complete a fresh IdP re-authentication
    to obtain a single-use step-up grant and then retry the operation.
    ``reauth_idp_ids`` lists the linked providers eligible for re-authentication.

    Aligns with RFC 9470 (OAuth 2.0 Step-Up Authentication): the
    ``WWW-Authenticate`` header advertises ``insufficient_user_authentication``
    so a standards-aware client knows to trigger a stronger authentication.
    """

    code = "step_up_reauth_required"
    default_detail = "Re-authenticate with your identity provider to continue."
    headers = {"WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'}

    def __init__(
        self,
        detail: str | None = None,
        *,
        reauth_idp_ids: list[int] | tuple[int, ...] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.reauth_idp_ids: list[int] = list(reauth_idp_ids or ())
        super().__init__(detail, headers=headers)


class InvalidMFACodeError(InvalidRequestError):
    """A supplied TOTP/backup MFA code did not verify (400)."""

    code = "invalid_mfa_code"
    default_detail = "Invalid MFA code."


class OAuthError(InvalidRequestError):
    """An RFC 6749 §5.2 error response from the token endpoint.

    OAuth defines its *own* error wire format, and a conformant client parses
    that and nothing else: a JSON body with an ``error`` member drawn from a
    fixed registry, optionally ``error_description`` and ``error_uri``. Putting
    an OAuth error code inside a human-readable ``detail`` string looks
    conformant and is not — no client library will ever read it.

    So this carries the code as data, and the edge handler renders the OAuth
    shape for it while every other :class:`JafaalError` keeps JAFAAL's own
    ``{"detail", "code"}`` shape. The two audiences are different: OAuth clients
    read this one, application front-ends read the other.

    Attributes:
        oauth_error: The RFC 6749 §5.2 error code (e.g. ``invalid_grant``).
    """

    code = "oauth_error"
    default_detail = "The request is invalid."
    #: Rendered as the ``error`` member; overridden per instance.
    oauth_error: str = "invalid_request"

    def __init__(
        self,
        oauth_error: str,
        detail: str | None = None,
        *,
        status_code: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.oauth_error = oauth_error
        if status_code is not None:
            self.status_code = status_code
        super().__init__(detail, headers=headers)


class InvalidClientError(OAuthError):
    """RFC 6749 §5.2 ``invalid_client`` — the client is unknown or unauthorised.

    401 rather than 400, as §5.2 specifies for a client-authentication failure.
    """

    code = "invalid_client"

    def __init__(self, detail: str | None = None, *, headers: dict[str, str] | None = None) -> None:
        super().__init__("invalid_client", detail, status_code=401, headers=headers)


class InvalidGrantError(OAuthError):
    """RFC 6749 §5.2 ``invalid_grant``.

    The authorization code or refresh token is invalid, expired, revoked, was
    issued to another client, or its ``redirect_uri`` does not match. Every one
    of those maps to the *same* code deliberately: distinguishing them turns the
    token endpoint into an oracle for probing which codes and clients exist.
    """

    code = "invalid_grant"

    def __init__(self, detail: str | None = None, *, headers: dict[str, str] | None = None) -> None:
        super().__init__("invalid_grant", detail, headers=headers)


class UnsupportedGrantTypeError(OAuthError):
    """RFC 6749 §5.2 ``unsupported_grant_type``."""

    code = "unsupported_grant_type"

    def __init__(self, detail: str | None = None, *, headers: dict[str, str] | None = None) -> None:
        super().__init__("unsupported_grant_type", detail, headers=headers)


class InvalidScopeError(OAuthError):
    """RFC 6749 §5.2 ``invalid_scope`` — the requested scope is unknown or excessive."""

    code = "invalid_scope"

    def __init__(self, detail: str | None = None, *, headers: dict[str, str] | None = None) -> None:
        super().__init__("invalid_scope", detail, headers=headers)


class PasswordPolicyError(UnprocessableError):
    """A password failed the configured policy (422)."""

    code = "password_policy"
    default_detail = "The password does not meet the required policy."


class StoreUnavailableError(ServiceUnavailableError):
    """A security state store (lockout counters, MFA secret) is unreachable.

    Unifies the former ``AuthSecurityStoreUnavailableError`` and
    ``MFASecretStoreUnavailableError``.
    """

    code = "store_unavailable"
    default_detail = "A required storage backend is unavailable."


class IdentityProviderError(UpstreamError):
    """An external identity provider returned an error (502)."""

    code = "identity_provider_error"
    default_detail = "The identity provider returned an error."


class IdentityProviderTimeoutError(UpstreamTimeoutError):
    """An external identity provider timed out (504)."""

    code = "identity_provider_timeout"
    default_detail = "The identity provider timed out."


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "ConflictError",
    "IdentityProviderError",
    "IdentityProviderTimeoutError",
    "InternalError",
    "InvalidApiKeyError",
    "InvalidClientError",
    "InvalidCredentialsError",
    "InvalidGrantError",
    "InvalidMFACodeError",
    "InvalidRequestError",
    "InvalidScopeError",
    "InvalidTokenError",
    "JafaalError",
    "MissingScopeError",
    "NotFoundError",
    "OAuthError",
    "PasswordPolicyError",
    "PreconditionFailedError",
    "RateLimitedError",
    "ServiceUnavailableError",
    "SessionExpiredError",
    "StaleRefreshTokenError",
    "StepUpReauthRequiredError",
    "StoreUnavailableError",
    "TokenExpiredError",
    "UnprocessableError",
    "UnsupportedGrantTypeError",
    "UpstreamError",
    "UpstreamTimeoutError",
]
