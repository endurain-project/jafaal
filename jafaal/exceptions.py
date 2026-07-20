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
    """The principal lacks one or more required scopes."""

    code = "missing_scope"
    default_detail = "You do not have the required permissions."

    def __init__(
        self,
        detail: str | None = None,
        *,
        missing: frozenset[str] | set[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.missing: frozenset[str] = frozenset(missing or ())
        super().__init__(detail, headers=headers)


class InvalidMFACodeError(InvalidRequestError):
    """A supplied TOTP/backup MFA code did not verify (400)."""

    code = "invalid_mfa_code"
    default_detail = "Invalid MFA code."


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
    "InvalidCredentialsError",
    "InvalidMFACodeError",
    "InvalidRequestError",
    "InvalidTokenError",
    "JafaalError",
    "MissingScopeError",
    "NotFoundError",
    "PasswordPolicyError",
    "PreconditionFailedError",
    "RateLimitedError",
    "ServiceUnavailableError",
    "SessionExpiredError",
    "StaleRefreshTokenError",
    "StoreUnavailableError",
    "TokenExpiredError",
    "UnprocessableError",
    "UpstreamError",
    "UpstreamTimeoutError",
]
