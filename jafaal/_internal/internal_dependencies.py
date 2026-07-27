"""Auth-internal FastAPI dependencies and credential-extraction helpers.

This is the low-level, auth-internal dependency layer. By convention, higher-level
code does **not** import it directly; it consumes identity through
:mod:`jafaal.dependencies` and :class:`~jafaal.identity_service.IdentityService`
instead.

Provides FastAPI dependencies that resolve and validate JWT access/refresh
tokens (cookie or Authorization header) and accept API keys as an alternative
credential. Defines :class:`AuthContext`, the unified credential representation
passed to endpoints that accept either auth method.

Scope enforcement is intentionally not provided here: the canonical,
principal-resolving ``check_scopes`` lives in :mod:`jafaal.dependencies` (it goes
through :class:`~jafaal.identity_service.IdentityService`, which also asserts the
user exists and is active). Use that instead.
"""

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Final

from fastapi import (
    Depends,
    Form,
    Query,
    Request,
)
from fastapi.security import (
    APIKeyHeader,
    OAuth2PasswordBearer,
)
from joserfc.errors import MissingClaimError

import jafaal._internal.token_manager as jafaal_token_manager
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_service as jafaal_identity_service
import jafaal.orm as jafaal_orm
import jafaal.scopes as jafaal_scopes
import jafaal.settings as jafaal_settings
from jafaal.principal import AccessTokenCred, Principal

logger = logging.getLogger(__name__)

# Define the OAuth2 scheme for handling bearer tokens. The advertised ``scopes``
# feed the Swagger "Authorize" picker only; it is built once at import, so it
# lists JAFAAL's own scopes (host application scopes are still minted and
# enforced, just not shown in the picker).
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    scopes=dict(jafaal_scopes.get_scope_catalog().descriptions),
    auto_error=False,
)

# Define the API key header for the client type
header_client_type_scheme = APIKeyHeader(name="X-Client-Type")

# Same header, but optional: the RFC 6749 §6 refresh request has no way to carry
# it, so the token endpoint infers the client type instead of demanding it.
header_client_type_optional_scheme = APIKeyHeader(name="X-Client-Type", auto_error=False)

#: The only ``grant_type`` JAFAAL's token endpoint implements (RFC 6749 §6).
REFRESH_TOKEN_GRANT: Final = "refresh_token"  # noqa: S105 - a grant-type name, not a credential


class ClientType(StrEnum):
    """The validated set of ``X-Client-Type`` values.

    A :class:`~enum.StrEnum`, so members compare and interpolate as their plain
    string value (``ClientType.WEB == "web"``) — keeping every existing
    ``== "web"`` / ``== "mobile"`` comparison working — while callers can rely on
    the value being exactly one of these two options once it has passed through
    :func:`get_client_type`.
    """

    WEB = "web"
    MOBILE = "mobile"


def _parse_client_type(value: str) -> ClientType:
    """Coerce a raw ``X-Client-Type`` value, rejecting anything unrecognised."""
    try:
        return ClientType(value)
    except ValueError as err:
        raise jafaal_exceptions.InvalidRequestError(
            f"Invalid X-Client-Type header: expected 'web' or 'mobile', got {value!r}."
        ) from err


def get_client_type(
    client_type: Annotated[str, Depends(header_client_type_scheme)],
) -> ClientType:
    """Validate the ``X-Client-Type`` header at the request boundary.

    This is the single validation point for the client type: the header is
    required (a missing one is rejected as 401/403 by the underlying scheme),
    and a present-but-unrecognised value is rejected here with a 400. Every
    downstream handler can therefore rely on the client type being exactly
    ``web`` or ``mobile`` instead of guessing (e.g. treating any non-``web``
    value as mobile).

    Args:
        client_type: The raw ``X-Client-Type`` header value.

    Returns:
        The validated :class:`ClientType`.

    Raises:
        JafaalError: 400 if the header value is not ``web`` or ``mobile``.
    """
    return _parse_client_type(client_type)


def get_grant_type(
    grant_type: Annotated[str | None, Form()] = None,
) -> str | None:
    """Validate the optional RFC 6749 ``grant_type`` form field.

    Present only on JAFAAL's token endpoint (``/auth/refresh``), which accepts
    the standard RFC 6749 §6 request shape in addition to its own cookie/header
    form. Absent means the caller is using JAFAAL's native shape.

    Args:
        grant_type: The ``grant_type`` form field, if supplied.

    Returns:
        The validated grant type, or ``None`` when not supplied.

    Raises:
        JafaalError: 400 (``unsupported_grant_type``) for any other grant. JAFAAL
            is a first-party issuer with no authorization endpoint, so
            ``refresh_token`` is the only grant it implements.
    """
    if grant_type is None:
        return None
    if grant_type != REFRESH_TOKEN_GRANT:
        raise jafaal_exceptions.InvalidRequestError(
            f"unsupported_grant_type: this token endpoint implements only {REFRESH_TOKEN_GRANT!r} "
            f"(got {grant_type!r}). JAFAAL is a first-party issuer and has no authorization endpoint."
        )
    return grant_type


def get_refresh_client_type(
    client_type: Annotated[str | None, Depends(header_client_type_optional_scheme)] = None,
    grant_type: Annotated[str | None, Depends(get_grant_type)] = None,
) -> ClientType:
    """Resolve the client type for the token endpoint, inferring it when absent.

    ``X-Client-Type`` is a JAFAAL-specific header that a stock OAuth client has
    no way to send. When the caller uses the RFC 6749 §6 request shape the header
    is therefore optional: carrying the refresh token in the request body is
    itself proof that the caller is not relying on the browser cookie, so the
    ``mobile`` delivery mode (tokens in the response body, no CSRF token) is the
    correct and only sensible interpretation.

    An explicit header always wins, so a native client can still ask for the web
    delivery mode.

    Args:
        client_type: The raw ``X-Client-Type`` header value, if sent.
        grant_type: The validated RFC 6749 ``grant_type``, if sent.

    Returns:
        The resolved :class:`ClientType`.

    Raises:
        JafaalError: 400 if the header is present but unrecognised; 403 if
            neither the header nor a standard grant request identifies the
            client.
    """
    if client_type is not None:
        return _parse_client_type(client_type)
    if grant_type == REFRESH_TOKEN_GRANT:
        return ClientType.MOBILE
    raise jafaal_exceptions.AuthorizationError(
        "X-Client-Type header is required (expected 'web' or 'mobile'), or use the "
        f"RFC 6749 form request with grant_type={REFRESH_TOKEN_GRANT!r}."
    )


# Define the API key header for third-party API key auth
header_api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass
class AuthContext:
    """
    Unified authentication context.

    Carries the resolved user identity and scopes
    regardless of whether authentication was via JWT
    or API key.

    Attributes:
        user_id: Authenticated user's ID.
        scopes: List of granted scope strings.
        auth_type: Source of authentication
            (``"jwt"`` or ``"api_key"``).
    """

    user_id: jafaal_orm.UserId
    scopes: list[str]
    auth_type: str


# Define the API key header for CSRF token
header_csrf_token_scheme = APIKeyHeader(name="X-CSRF-Token", auto_error=False)


def _resolve_and_cache_principal(
    access_token: str,
    request: Request,
    identity_service: jafaal_identity_service.IdentityService,
) -> Principal:
    """Resolve and cache a Principal from a JWT access token.

    Checks ``request.state.principal`` first so that multiple
    dependencies in the same request share a single DB lookup.
    On cache miss, delegates to
    :meth:`~jafaal.identity_service.IdentityService.resolve_from_access_token`
    and stores the result on ``request.state``.

    Args:
        access_token: Raw JWT access token string.
        request: Current HTTP request used for caching.
        identity_service: Per-request IdentityService.

    Returns:
        Principal: Cached or freshly-resolved principal.

    Raises:
        JafaalError: 401 if the token is invalid or
            the user is not found.
    """
    cached: Principal | None = getattr(request.state, "principal", None)
    if cached is not None:
        return cached
    principal = identity_service.resolve_from_access_token(access_token)
    request.state.principal = principal
    return principal


def get_token(
    non_cookie_token: Annotated[str | None, Depends(oauth2_scheme)],
    cookie_token: str | None,
    client_type: ClientType,
    token_type: jafaal_token_manager.TokenType,
) -> str | None:
    """
    Retrieves the authentication token based on client type and token type.

    Args:
        non_cookie_token (str | None): Token provided via Authorization header.
        cookie_token (str | None): Token provided via cookie.
        client_type (str): Type of client requesting the token ("web" or "mobile").
        token_type (TokenType): Type of token being requested (ACCESS or REFRESH).

    Returns:
        str: The authentication token appropriate for the client type and token type.

    Raises:
        JafaalError: If the required token is missing, or if the client type is invalid.
    """
    # Access tokens always come from the Authorization header (all clients), per
    # RFC 6750 §2.1 — never a cookie, so they are not sent ambiently.
    if token_type == jafaal_token_manager.TokenType.ACCESS:
        if non_cookie_token is None:
            raise jafaal_exceptions.AuthenticationError("Access token missing from Authorization header")
        return non_cookie_token

    # Refresh tokens: cookie (web) or Authorization header (mobile)
    if token_type == jafaal_token_manager.TokenType.REFRESH:
        if client_type == "web":
            if cookie_token is None:
                raise jafaal_exceptions.AuthenticationError("Refresh token missing from cookie")
            return cookie_token
        if client_type == "mobile":
            if non_cookie_token is None:
                raise jafaal_exceptions.AuthenticationError("Refresh token missing from Authorization header")
            return non_cookie_token

    raise jafaal_exceptions.AuthorizationError(
        "Invalid client type or token type",
        headers={"WWW-Authenticate": "Bearer"},
    )


## ACCESS TOKEN VALIDATION
def get_access_token(
    access_token: Annotated[str | None, Depends(oauth2_scheme)],
    _client_type: str = Depends(header_client_type_scheme),
) -> str:
    """
    Retrieves the access token from the Authorization header.

    Args:
        access_token (str | None): Access token provided via the Authorization header (OAuth2 scheme).
        _client_type (str): The type of client making the request, extracted from a custom header.

    Returns:
        str: The access token from the Authorization header.

    Raises:
        JafaalError: If the access token is missing from the Authorization header.
    """
    if access_token is None:
        raise jafaal_exceptions.AuthenticationError("Access token missing from Authorization header")
    return access_token


def _validate_access_token_impl(
    access_token: str,
    token_manager: jafaal_token_manager.TokenManager,
) -> None:
    """Shared implementation for access-token validation.

    Args:
        access_token: The access token to validate.
        token_manager: The configured token manager.

    Raises:
        JafaalError: If the token is missing claims, expired, or otherwise
            invalid. Unexpected exceptions are wrapped as a 500 so the global
            error handler can record them.
    """
    try:
        token_manager.validate_access_expiration_logged(access_token)
    except jafaal_exceptions.JafaalError:
        raise
    except Exception as err:
        logger.error(
            f"Unexpected error during access token validation: {type(err).__name__}",
            exc_info=err,
            extra={"access_token": "[REDACTED]"},
        )
        raise jafaal_exceptions.InternalError("Internal server error during token validation") from err


def validate_access_token_expiration(
    access_token: Annotated[str, Depends(get_access_token)],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
) -> None:
    """FastAPI dependency that validates only the *expiration* (and signature)
    of the access token from the Authorization header.

    This is the lightweight, expiry-only gate. It does **not** resolve the
    user, load the account, or check active status. Non-auth routers that need
    full identity resolution must use
    :func:`jafaal.dependencies.validate_access_token` (the principal-resolving
    validator) instead.

    Args:
        access_token (str): The access token to be validated.
        token_manager (jafaal_token_manager.TokenManager): The token manager instance used for validation.

    Raises:
        JafaalError: If the token is expired or invalid.
    """
    _validate_access_token_impl(access_token, token_manager)


def get_sub_from_access_token(
    request: Request,
    access_token: Annotated[str, Depends(get_access_token)],
    identity_service: Annotated[
        jafaal_identity_service.IdentityService,
        Depends(jafaal_identity_service.get_identity_service),
    ],
) -> jafaal_orm.UserId:
    """Retrieve the user ID from the access token.

    Resolves and caches the :class:`~jafaal.principal.Principal`
    on ``request.state`` then returns ``principal.user_id``.
    Subsequent calls within the same request hit the cache
    instead of issuing another DB lookup.

    Args:
        request: Current HTTP request for state caching.
        access_token: JWT from the Authorization header.
        identity_service: Per-request IdentityService.

    Returns:
        int: Authenticated user's primary key.

    Raises:
        JafaalError: 401 if the token is invalid,
            expired, or the user is not found.
    """
    principal = _resolve_and_cache_principal(access_token, request, identity_service)
    return principal.user_id


def get_sid_from_access_token(
    request: Request,
    access_token: Annotated[str, Depends(get_access_token)],
    identity_service: Annotated[
        jafaal_identity_service.IdentityService,
        Depends(jafaal_identity_service.get_identity_service),
    ],
) -> str:
    """Retrieve the session ID from the access token.

    Resolves and caches the :class:`~jafaal.principal.Principal`
    on ``request.state`` then extracts the session ID from the
    :class:`~jafaal.principal.AccessTokenCred`.

    Args:
        request: Current HTTP request for state caching.
        access_token: JWT from the Authorization header.
        identity_service: Per-request IdentityService.

    Returns:
        str: Session ID (``sid`` claim) from the token.

    Raises:
        JafaalError: 401 if the token is invalid,
            expired, or the credential type is unexpected.
    """
    principal = _resolve_and_cache_principal(access_token, request, identity_service)
    cred = principal.credential
    if not isinstance(cred, AccessTokenCred):
        raise jafaal_exceptions.InvalidTokenError("Invalid credential type for session ID")
    return cred.session_id


## REFRESH TOKEN VALIDATION
def get_refresh_token(
    request: Request,
    non_cookie_refresh_token: Annotated[str | None, Depends(oauth2_scheme)],
    client_type: Annotated[ClientType, Depends(get_refresh_client_type)],
    grant_type: Annotated[str | None, Depends(get_grant_type)] = None,
    form_refresh_token: Annotated[str | None, Form(alias="refresh_token")] = None,
) -> str | None:
    """
    Retrieves the refresh token from the request, in RFC 6749 order of preference.

    Three carriers are accepted, because the same endpoint serves three kinds of
    caller:

    1. the RFC 6749 §6 form body (``grant_type=refresh_token&refresh_token=...``),
       so a stock OAuth client can drive the refresh without knowing anything
       JAFAAL-specific;
    2. the refresh-token cookie, for web clients (the token is ``HttpOnly`` and
       never handed to page script); and
    3. the ``Authorization`` header, for native clients using JAFAAL's own shape.

    Args:
        request: The incoming request, used to read the refresh-token cookie.
        non_cookie_refresh_token: The refresh token provided via the Authorization header (if present).
        client_type: The resolved client type.
        grant_type: The validated RFC 6749 ``grant_type``, if supplied.
        form_refresh_token: The RFC 6749 ``refresh_token`` form field, if supplied.

    Returns:
        str: The resolved refresh token.

    Raises:
        JafaalError: If no valid refresh token is found or the client type is invalid.
    """
    if grant_type == REFRESH_TOKEN_GRANT:
        # Standard request shape: the token is in the body and nowhere else, so a
        # missing one is a malformed request rather than a missing credential.
        if not form_refresh_token:
            raise jafaal_exceptions.InvalidRequestError(
                f"invalid_request: 'refresh_token' is required when grant_type={REFRESH_TOKEN_GRANT!r}."
            )
        return form_refresh_token

    cookie_refresh_token = request.cookies.get(jafaal_settings.get_settings().effective_refresh_cookie_name)
    return get_token(
        non_cookie_refresh_token, cookie_refresh_token, client_type, jafaal_token_manager.TokenType.REFRESH
    )


def _validate_refresh_token_impl(
    refresh_token: str,
    token_manager: jafaal_token_manager.TokenManager,
) -> None:
    """Validate a refresh token's signature, claims, expiry, and token use.

    Args:
        refresh_token: The raw refresh-token JWT.
        token_manager: The configured token manager.

    Raises:
        JafaalError: 401 if the token is invalid, expired, or not a refresh
            token; :class:`~jafaal.exceptions.StaleRefreshTokenError` when it is
            missing a required claim (so the edge handler clears the cookie).
    """
    try:
        # Validate the token expiration and type
        token_manager.validate_token_expiration(
            refresh_token,
            jafaal_token_manager.TokenType.REFRESH,
        )
    except jafaal_exceptions.JafaalError as http_err:
        is_expired = isinstance(http_err, jafaal_exceptions.TokenExpiredError)
        logger.log(
            logging.DEBUG if is_expired else logging.ERROR,
            f"Refresh token validation failed: {http_err.detail}",
            exc_info=None if is_expired else http_err,
            extra={"refresh_token": "[REDACTED]"},
        )
        # A refresh cookie that cannot possibly be valid here (it is missing a
        # required claim, so it was not minted by this configuration) would
        # otherwise strand the SPA: every page load resends the same cookie,
        # /refresh 401s, and the client never recovers. Signal the edge handler
        # to clear the cookie so the user lands on the login page instead of
        # looping. Restricted to ``MissingClaimError`` failures so a transient
        # problem does not log anyone out.
        if isinstance(http_err.__cause__, MissingClaimError):
            raise jafaal_exceptions.StaleRefreshTokenError(http_err.detail) from http_err
        raise
    except Exception as err:
        logger.error(
            f"Unexpected error during refresh token validation: {type(err).__name__}",
            exc_info=err,
            extra={"refresh_token": "[REDACTED]"},
        )
        raise jafaal_exceptions.InternalError("Internal server error during token validation") from err


def validate_refresh_token(
    refresh_token: Annotated[str, Depends(get_refresh_token)],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
) -> None:
    """
    Validates the expiration of a refresh token using the provided token manager.

    Prefer :func:`get_validated_refresh_token`, which performs the same checks
    and hands back the validated claims, so an endpoint cannot read ``sub`` /
    ``sid`` without having validated the token first.

    Args:
        refresh_token (str): The refresh token to be validated, extracted via dependency injection.
        token_manager (jafaal_token_manager.TokenManager): The token manager instance used to validate the token, injected via dependency.

    Raises:
        JafaalError: If the refresh token is expired or invalid, or if an unexpected error occurs during validation.

    Logs:
        Errors and unexpected exceptions are logged with context, including a redacted refresh token.
    """
    _validate_refresh_token_impl(refresh_token, token_manager)


@dataclass(frozen=True)
class ValidatedRefreshToken:
    """A refresh token that has passed full validation, with its claims.

    Existing only via :func:`get_validated_refresh_token`, so possessing an
    instance *is* the proof that the signature, ``iss``/``aud``, expiry, and
    ``token_use`` were all checked. The claim readers take this type rather than
    a raw ``str`` so an endpoint cannot read ``sub`` / ``sid`` off a token nobody
    validated — previously that safety depended on the endpoint also remembering
    to declare the separate validation dependency, and an endpoint that forgot
    would silently accept an expired (or access-type) token.

    Attributes:
        token: The raw refresh-token JWT as presented.
        user_id: The ``sub`` claim, coerced to the host's primary-key type.
        session_id: The ``sid`` claim.
    """

    token: str
    user_id: jafaal_orm.UserId
    session_id: str


def _validate_and_read_refresh_token(
    refresh_token: str,
    token_manager: jafaal_token_manager.TokenManager,
) -> ValidatedRefreshToken:
    """Fully validate a refresh token and read its ``sub`` / ``sid`` claims.

    The single implementation behind both the mandatory and the optional
    dependency, so neither can end up validating less than the other.

    Args:
        refresh_token: The raw refresh-token JWT.
        token_manager: The configured token manager.

    Returns:
        The validated token and its claims.

    Raises:
        JafaalError: 401 if the token is invalid, expired, not a refresh token,
            or carries a malformed ``sub`` / ``sid``.
    """
    _validate_refresh_token_impl(refresh_token, token_manager)

    claims = token_manager.decode_token(refresh_token).claims

    sub = claims.get("sub")
    if not isinstance(sub, int | str) or sub == "":
        raise jafaal_exceptions.InvalidTokenError("Invalid token: 'sub' claim is missing or malformed")
    try:
        # Coerced to the host user table's primary-key type (int or UUID).
        user_id = jafaal_orm.coerce_user_id(sub)
    except (ValueError, TypeError) as err:
        raise jafaal_exceptions.InvalidTokenError("Invalid token: 'sub' claim is malformed") from err

    sid = claims.get("sid")
    if not isinstance(sid, str):
        raise jafaal_exceptions.InvalidTokenError("Invalid token: 'sid' claim must be a string")

    return ValidatedRefreshToken(token=refresh_token, user_id=user_id, session_id=sid)


def get_validated_refresh_token(
    refresh_token: Annotated[str, Depends(get_refresh_token)],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
) -> ValidatedRefreshToken:
    """Validate the refresh token once and return it with its claims.

    The single entry point for refresh-token-authenticated endpoints. Validating
    and decoding in one place also means the JWT signature is verified once per
    request instead of once per claim the endpoint reads.

    Args:
        refresh_token: The raw refresh token from the cookie or Authorization header.
        token_manager: The configured token manager.

    Returns:
        The validated token and its ``sub`` / ``sid`` claims.

    Raises:
        JafaalError: 401 if the token is invalid, expired, not a refresh token,
            or carries a malformed ``sub`` / ``sid``.
    """
    return _validate_and_read_refresh_token(refresh_token, token_manager)


def get_refresh_client_type_optional(
    client_type: Annotated[str | None, Depends(header_client_type_optional_scheme)] = None,
) -> ClientType:
    """Resolve the delivery mode on the multi-grant token endpoint.

    ``/auth/token`` serves both the authorization-code and refresh grants, and
    only the latter has a native cookie shape that needs a declared client type.
    Demanding the header unconditionally (as
    :func:`get_refresh_client_type` does) would reject a perfectly well-formed
    ``grant_type=authorization_code`` request from a stock OAuth client, which
    has no reason to know about a JAFAAL-specific header. An absent header
    therefore means ``mobile`` — body delivery, no cookie, no CSRF token — which
    is the only sensible reading of a caller that is not relying on the browser
    cookie.

    Args:
        client_type: The raw ``X-Client-Type`` header value, if sent.

    Returns:
        The resolved :class:`ClientType`.

    Raises:
        JafaalError: 400 if the header is present but unrecognised.
    """
    if client_type is None:
        return ClientType.MOBILE
    return _parse_client_type(client_type)


def get_validated_refresh_token_optional(
    request: Request,
    non_cookie_refresh_token: Annotated[str | None, Depends(oauth2_scheme)],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    grant_type: Annotated[str | None, Form()] = None,
    form_refresh_token: Annotated[str | None, Form(alias="refresh_token")] = None,
) -> ValidatedRefreshToken | None:
    """Validate a refresh token when one is actually part of this request.

    The multi-grant token endpoint cannot use the mandatory
    :func:`get_validated_refresh_token`: FastAPI resolves dependencies before the
    endpoint body runs, so requiring a refresh token there would reject every
    ``grant_type=authorization_code`` request before it could be dispatched.

    Returns ``None`` — rather than raising — only when no refresh token is
    present *at all*. A token that **is** present is always fully validated, so
    this is not a weaker check: it cannot be used to skip validation, only to
    signal "this request is not a refresh".

    Args:
        request: The incoming request, used to read the refresh cookie.
        non_cookie_refresh_token: Bearer token from the Authorization header.
        token_manager: The configured token manager.
        grant_type: The ``grant_type`` form field, if supplied.
        form_refresh_token: The RFC 6749 ``refresh_token`` form field.

    Returns:
        The validated token and its claims, or ``None`` when absent.

    Raises:
        JafaalError: 401 if a token is present but invalid, expired, or not a
            refresh token.
    """
    raw = form_refresh_token
    if raw is None and grant_type != REFRESH_TOKEN_GRANT:
        # No body token: fall back to the carriers JAFAAL's native shape uses.
        raw = non_cookie_refresh_token or request.cookies.get(
            jafaal_settings.get_settings().effective_refresh_cookie_name
        )
    if not raw:
        return None
    return _validate_and_read_refresh_token(raw, token_manager)


def get_sub_from_refresh_token(
    validated: Annotated[ValidatedRefreshToken, Depends(get_validated_refresh_token)],
) -> jafaal_orm.UserId:
    """
    Retrieves the user ID ('sub' claim) from a validated refresh token.

    Args:
        validated: The validated refresh token and its claims.

    Returns:
        The user ID associated with the provided refresh token.
    """
    return validated.user_id


def get_sid_from_refresh_token(
    validated: Annotated[ValidatedRefreshToken, Depends(get_validated_refresh_token)],
) -> str:
    """
    Retrieves the session ID ('sid') from a validated refresh token.

    Args:
        validated: The validated refresh token and its claims.

    Returns:
        The session ID associated with the provided refresh token.
    """
    return validated.session_id


def get_and_return_refresh_token(
    validated: Annotated[ValidatedRefreshToken, Depends(get_validated_refresh_token)],
) -> str:
    """
    Returns the raw refresh token, once validated.

    Args:
        validated: The validated refresh token and its claims.

    Returns:
        str: The provided refresh token.
    """
    return validated.token


## API KEY + UNIFIED AUTH
async def validate_api_key(
    raw_key: str,
    request: Request,
    identity_service: jafaal_identity_service.IdentityService,
) -> "AuthContext":
    """Validate a raw API key and return an AuthContext.

    Delegates to
    :meth:`~jafaal.identity_service.IdentityService.resolve_from_api_key`
    and adapts the returned
    :class:`~jafaal.principal.Principal` to the
    :class:`AuthContext` shape endpoints accepting either
    credential type consume.

    Args:
        raw_key: The plain-text API key from the
            request header or query parameter.
        request: The current HTTP request (for audit
            logging and state caching).
        identity_service: Per-request IdentityService.

    Returns:
        AuthContext with user_id, scopes, and
        auth_type set to ``"api_key"``.

    Raises:
        JafaalError: 401 if the key is not found,
            revoked, or expired.
    """
    principal = identity_service.resolve_from_api_key(raw_key, request)
    return AuthContext(
        user_id=principal.user_id,
        scopes=list(principal.scopes),
        auth_type="api_key",
    )


async def validate_access_token_or_api_key(
    request: Request,
    identity_service: Annotated[
        jafaal_identity_service.IdentityService,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    access_token: str | None = Depends(oauth2_scheme),
    api_key_header: str | None = Depends(header_api_key_scheme),
    api_key_query: str | None = Query(None, alias="api_key"),
) -> "AuthContext":
    """Accept either a JWT bearer token or an API key.

    API keys should be supplied via the ``X-API-Key`` request header.
    Query-string delivery (``?api_key=``) is disabled by default because
    credentials in query strings appear in access logs, proxy histories,
    and browser history. It can be enabled via the
    ``allow_api_key_query_param`` setting on
    :class:`~jafaal.settings.AuthSettings` for self-hosted deployments
    that require it (e.g. webhook integrations that cannot set custom
    headers).

    Tries JWT first (Authorization: Bearer header). If none is
    present, falls back to the ``X-API-Key`` header, then the
    ``?api_key=`` query parameter if allowed. Raises 401 if none
    is supplied.

    Delegates to :class:`~jafaal.identity_service.IdentityService`
    for credential resolution and caches the resolved
    :class:`~jafaal.principal.Principal` on
    ``request.state.principal`` so that other dependencies in
    the same request can share the result without a second DB
    lookup.

    Args:
        request: The current HTTP request.
        identity_service: Per-request IdentityService.
        access_token: Optional Bearer token from the
            Authorization header.
        api_key_header: Optional API key from the
            ``X-API-Key`` header.
        api_key_query: Optional API key from the
            ``?api_key=`` query parameter (only honoured
            when ``AuthSettings.allow_api_key_query_param`` is ``True``).

    Returns:
        AuthContext with resolved user_id, scopes, and
        auth_type (``"jwt"`` or ``"api_key"``).

    Raises:
        JafaalError: 401 if no valid credential is
            provided.
    """
    # --- Cache check: return early if Principal already resolved ---
    cached: Principal | None = getattr(request.state, "principal", None)
    if cached is not None:
        auth_type = "api_key" if cached.is_api_key() else "jwt"
        return AuthContext(
            user_id=cached.user_id,
            scopes=list(cached.scopes),
            auth_type=auth_type,
        )

    # --- JWT path ---
    if access_token is not None:
        principal = identity_service.resolve_from_access_token(access_token)
        request.state.principal = principal
        return AuthContext(
            user_id=principal.user_id,
            scopes=list(principal.scopes),
            auth_type="jwt",
        )

    # --- API key path ---
    settings = jafaal_settings.get_settings()
    raw_key = api_key_header
    if raw_key is None and api_key_query is not None and settings.api_keys.allow_query_param:
        logger.warning(
            "API key supplied via query string (?api_key=). "
            "This is a security risk: credentials appear in access logs "
            "and browser history. Set X-API-Key header instead."
        )
        raw_key = api_key_query
    if raw_key is not None:
        principal = identity_service.resolve_from_api_key(raw_key, request)
        request.state.principal = principal
        return AuthContext(
            user_id=principal.user_id,
            scopes=list(principal.scopes),
            auth_type="api_key",
        )

    raise jafaal_exceptions.AuthenticationError("Not authenticated. Provide a Bearer token or an API key.")


def get_user_id_from_auth(
    auth: Annotated[
        "AuthContext",
        Depends(validate_access_token_or_api_key),
    ],
) -> jafaal_orm.UserId:
    """Extract the user ID from a unified AuthContext.

    Use this in place of ``get_sub_from_access_token``
    on endpoints that accept both JWT and API key auth.

    Args:
        auth: Resolved AuthContext from
            validate_access_token_or_api_key.

    Returns:
        The authenticated user's ID.
    """
    return auth.user_id
