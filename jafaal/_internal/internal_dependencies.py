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

#: The only ``grant_type`` JAFAAL's token endpoint implements for rotation
#: (RFC 6749 §6).
REFRESH_TOKEN_GRANT: Final = "refresh_token"  # noqa: S105 - a grant-type name, not a credential


def get_grant_type(
    grant_type: Annotated[str | None, Form()] = None,
) -> str | None:
    """Validate the optional RFC 6749 ``grant_type`` form field.

    Present on the ``/auth/refresh`` alias, which accepts the standard RFC 6749
    §6 request shape in addition to its own cookie/header form. Absent means the
    caller is using JAFAAL's native shape.

    Args:
        grant_type: The ``grant_type`` form field, if supplied.

    Returns:
        The validated grant type, or ``None`` when not supplied.

    Raises:
        UnsupportedGrantTypeError: For any other grant. This alias serves only
            the refresh grant; the authorization-code grant lives on
            ``/auth/token``.
    """
    if grant_type is None:
        return None
    if grant_type != REFRESH_TOKEN_GRANT:
        raise jafaal_exceptions.UnsupportedGrantTypeError(
            f"This endpoint implements only {REFRESH_TOKEN_GRANT!r} (got {grant_type!r}). "
            "Use /auth/token for the authorization-code grant."
        )
    return grant_type


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


## ACCESS TOKEN VALIDATION
def get_access_token(
    access_token: Annotated[str | None, Depends(oauth2_scheme)],
) -> str:
    """
    Retrieves the access token from the Authorization header.

    Args:
        access_token (str | None): Access token provided via the Authorization header (OAuth2 scheme).

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
    grant_type: Annotated[str | None, Depends(get_grant_type)] = None,
    form_refresh_token: Annotated[str | None, Form(alias="refresh_token")] = None,
) -> str | None:
    """Retrieve the refresh token from whichever carrier the request used.

    Three carriers are accepted, because the same endpoint serves three kinds of
    caller:

    1. the RFC 6749 §6 form body (``grant_type=refresh_token&refresh_token=...``),
       so a stock OAuth client can drive the refresh without knowing anything
       JAFAAL-specific;
    2. the refresh-token cookie, for clients registered with
       ``token_delivery="cookie"`` (the token is ``HttpOnly`` and never handed to
       page script); and
    3. the ``Authorization`` header, for clients that hold the token themselves.

    The carrier is *not* used to decide anything about the response: delivery
    mode comes from the registered client named in the token's ``client_id``
    claim. This is only about finding the credential.

    Args:
        request: The incoming request, used to read the refresh-token cookie.
        non_cookie_refresh_token: The refresh token provided via the Authorization header (if present).
        grant_type: The validated RFC 6749 ``grant_type``, if supplied.
        form_refresh_token: The RFC 6749 ``refresh_token`` form field, if supplied.

    Returns:
        str: The resolved refresh token.

    Raises:
        JafaalError: If no refresh token is present in any carrier.
    """
    if grant_type == REFRESH_TOKEN_GRANT:
        # Standard request shape: the token is in the body and nowhere else, so a
        # missing one is a malformed request rather than a missing credential.
        if not form_refresh_token:
            raise jafaal_exceptions.InvalidRequestError(
                f"'refresh_token' is required when grant_type={REFRESH_TOKEN_GRANT!r}."
            )
        return form_refresh_token

    cookie_refresh_token = request.cookies.get(jafaal_settings.get_settings().effective_refresh_cookie_name)
    # Cookie first. A browser SPA routinely attaches its *access* token to every
    # request, so preferring the Authorization header would make /refresh pick
    # the wrong token on the most common front-end setup. A client that holds its
    # own refresh token has no cookie, so this order never shadows its credential.
    token = cookie_refresh_token or non_cookie_refresh_token
    if token is None:
        raise jafaal_exceptions.AuthenticationError(
            "Refresh token missing: send it in the refresh cookie, the Authorization header, or as an "
            f"RFC 6749 form request with grant_type={REFRESH_TOKEN_GRANT!r}."
        )
    return token


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


@dataclass(frozen=True)
class ValidatedRefreshToken:
    """A refresh token that has passed full validation, with its claims.

    Constructed by :func:`validate_and_read_refresh_token`, directly at the
    multi-grant token endpoint or through :func:`get_validated_refresh_token`.
    Possessing an instance is the proof that the signature, ``iss``/``aud``,
    expiry, and ``token_use`` were checked. The claim readers take this type
    rather than a raw ``str`` so an endpoint cannot read ``sub`` / ``sid`` off a
    token nobody validated.

    Attributes:
        token: The raw refresh-token JWT as presented.
        user_id: The ``sub`` claim, coerced to the host's primary-key type.
        session_id: The ``sid`` claim.
        client: The registered client named by the ``client_id`` claim
            (RFC 9068 §2.2). Read from the signed token rather than the request,
            so the caller cannot switch delivery mode or widen scope at rotation
            time — the client is fixed when the session is created.
        scope: The scopes this grant actually carries, read from the signed
            token's ``scope`` claim. RFC 6749 §6 forbids a rotation from issuing
            a scope the original grant did not include, so this is replayed as
            the bound on the replacement tokens — otherwise a client that asked
            for a narrow scope at login would silently get the full set back on
            its first refresh.
    """

    token: str
    user_id: jafaal_orm.UserId
    session_id: str
    client: jafaal_settings.OAuthClient
    scope: tuple[str, ...] = ()


def validate_and_read_refresh_token(
    refresh_token: str,
    token_manager: jafaal_token_manager.TokenManager,
) -> ValidatedRefreshToken:
    """Fully validate a refresh token and read its ``sub`` / ``sid`` claims.

    This is the single implementation behind the mandatory refresh dependency
    and the multi-grant token endpoint, so neither can validate less than the
    other.

    Args:
        refresh_token: The raw refresh-token JWT.
        token_manager: The configured token manager.

    Returns:
        The validated token and its claims.

    Raises:
        JafaalError: 401 if the token is invalid, expired, not a refresh token,
            or carries a malformed ``sub`` / ``sid`` / ``client_id``.
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

    client_id = claims.get("client_id")
    if not isinstance(client_id, str):
        raise jafaal_exceptions.InvalidTokenError("Invalid token: 'client_id' claim must be a string")
    client = jafaal_settings.get_settings().oauth_client(client_id)
    if client is None:
        # The client was de-registered (or renamed) since the token was issued.
        # Its sessions must stop rotating: continuing would mean guessing a
        # delivery mode and scope ceiling that the host has withdrawn.
        raise jafaal_exceptions.InvalidTokenError(
            "Invalid token: it was issued to a client that is no longer registered"
        )

    # ``scope`` is essential in the claims registry, so validation above has
    # already rejected a token without it.
    scope = jafaal_token_manager.scopes_from_claims(claims)
    if scope is None:
        raise jafaal_exceptions.InvalidTokenError("Invalid token: 'scope' claim must be a space-delimited string")

    return ValidatedRefreshToken(
        token=refresh_token,
        user_id=user_id,
        session_id=sid,
        client=client,
        scope=tuple(scope),
    )


def get_validated_refresh_token(
    refresh_token: Annotated[str, Depends(get_refresh_token)],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
) -> ValidatedRefreshToken:
    """Validate the refresh token once and return it with its claims.

    The dependency entry point for refresh-token-authenticated extension
    endpoints. Validating and decoding in one place also means the JWT signature
    is verified once per request instead of once per claim the endpoint reads.

    Args:
        refresh_token: The raw refresh token from the cookie or Authorization header.
        token_manager: The configured token manager.

    Returns:
        The validated token and its ``sub`` / ``sid`` claims.

    Raises:
        JafaalError: 401 if the token is invalid, expired, not a refresh token,
            or carries a malformed ``sub`` / ``sid``.
    """
    return validate_and_read_refresh_token(refresh_token, token_manager)


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
