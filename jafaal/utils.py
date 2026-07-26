"""Authentication utilities for the auth router.

Provides credential verification, JWT/CSRF token creation, and the
``complete_login`` / ``create_mobile_pkce_session_response`` helpers used by
both password and PKCE login flows.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import (
    Request,
    Response,
)
from sqlalchemy.orm import Session

import jafaal._internal.password_hasher as jafaal_password_hasher
import jafaal._internal.token_manager as jafaal_token_manager
import jafaal.audit as jafaal_audit
import jafaal.credentials.crud as jafaal_credentials_crud
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.utils as idp_utils
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.utils as oauth_state_utils
import jafaal.ports as jafaal_ports
import jafaal.schema as jafaal_schema
import jafaal.sessions.utils as jafaal_sessions_utils
import jafaal.settings as jafaal_settings
from jafaal._core import network


def authenticate_user(
    username: str,
    password: str,
    password_hasher: jafaal_password_hasher.PasswordHasher,
    db: Session,
) -> jafaal_ports.UserProtocol:
    """
    Authenticates a user by verifying the provided username and password.

    Args:
        username (str): The username of the user attempting to authenticate.
        password (str): The plaintext password provided by the user.
        password_hasher (jafaal_password_hasher.PasswordHasher): An instance of the password hasher for verifying and updating password hashes.
        db (Session): The database session used for querying and updating user data.

    Returns:
        jafaal_ports.UserProtocol: The authenticated user object if authentication is successful.

    Raises:
        JafaalError: If the username does not exist, the password is invalid, or
            the password exceeds ``AuthSettings.password_max_length``.
    """
    # Get the user from the database
    user = jafaal_ports.get_user_repository().get_by_username(username, db)

    # Bound the input before any (deliberately slow) hashing work. Argon2 is
    # tuned to hundreds of milliseconds and hashes the whole input, so an
    # unauthenticated caller could otherwise post a multi-megabyte "password" on
    # every request. Checked before the user lookup result is used so the
    # rejection costs the same whether or not the account exists.
    if len(password) > jafaal_settings.get_settings().password_max_length:
        raise jafaal_exceptions.InvalidCredentialsError("Unable to authenticate with provided credentials")

    # Check if the user exists and if the password is correct
    if not user:
        # Run a dummy Argon2 verify so that the wall-clock latency of
        # the "user not found" branch matches the "user found, wrong
        # password" branch. Without this, Argon2's deliberately-tuned
        # ~hundreds-of-milliseconds verify time is trivially observable
        # from the network and lets an attacker enumerate valid
        # usernames without ever tripping FailedLoginAttempts (lockout
        # is only recorded on 401, which the attacker does not care
        # about while probing existence).
        password_hasher.dummy_verify()
        raise jafaal_exceptions.InvalidCredentialsError("Unable to authenticate with provided credentials")

    # Load the user's local password hash from the auth-owned credential
    # table. A missing row means the account has no local password.
    credential = jafaal_credentials_crud.get_credential(user.id, db)
    stored_hash = credential.password_hash if credential is not None else None

    # User has no local password (SSO-only account). Treat identically
    # to "wrong password" so neither the response body nor the timing
    # discloses the account's auth modality. The dummy verify keeps
    # the latency consistent with a normal Argon2 verify.
    if stored_hash is None:
        password_hasher.dummy_verify()
        raise jafaal_exceptions.InvalidCredentialsError("Unable to authenticate with provided credentials")

    # Verify password and get updated hash if applicable
    is_password_valid, updated_hash = password_hasher.verify_and_update(password, stored_hash)
    if not is_password_valid:
        raise jafaal_exceptions.InvalidCredentialsError("Unable to authenticate with provided credentials")

    # Update user hash if applicable
    if updated_hash:
        jafaal_credentials_crud.upsert_password_hash(user.id, updated_hash, db)

    # Return the user if the password is correct
    return user


def create_tokens(
    user: jafaal_ports.UserProtocol,
    token_manager: jafaal_token_manager.TokenManager,
    session_id: str | None = None,
) -> tuple[str, datetime, str, datetime, str, str]:
    """
    Generates session tokens for a user, including access token, refresh token, and CSRF token.

    Args:
        user (jafaal_ports.UserProtocol): The user object for whom the tokens are being created.
        token_manager (jafaal_token_manager.TokenManager): The token manager responsible for token creation.
        session_id (str | None, optional): An optional session ID. If not provided, a new unique session ID is generated.

    Returns:
        tuple[str, datetime, str, datetime, str, str]:
            A tuple containing:
                - session_id (str): The session identifier.
                - access_token_exp (datetime): Expiration datetime of the access token.
                - access_token (str): The access token string.
                - refresh_token_exp (datetime): Expiration datetime of the refresh token.
                - refresh_token (str): The refresh token string.
                - csrf_token (str): The CSRF token string.
    """
    if session_id is None:
        # Generate a unique session ID
        session_id = str(uuid4())

    # Create the access, refresh tokens and csrf token
    access_token_exp, access_token = token_manager.create_token(session_id, user, jafaal_token_manager.TokenType.ACCESS)

    refresh_token_exp, refresh_token = token_manager.create_token(
        session_id, user, jafaal_token_manager.TokenType.REFRESH
    )

    csrf_token = token_manager.create_csrf_token()

    return (
        session_id,
        access_token_exp,
        access_token,
        refresh_token_exp,
        refresh_token,
        csrf_token,
    )


def mint_access_token(
    user: jafaal_ports.UserProtocol,
    token_manager: jafaal_token_manager.TokenManager,
    session_id: str,
) -> tuple[datetime, str]:
    """
    Mint a single fresh access token for an existing session.

    Used by the in-grace refresh replay path, which keeps the
    existing (replayed) refresh token but still needs to hand the
    client a new, full-lifetime access token.

    Args:
        user: The user the token is issued for.
        token_manager: Token manager responsible for token creation.
        session_id: Existing session identifier to bind the token to.

    Returns:
        Tuple of (access_token_exp, access_token).
    """
    return token_manager.create_token(session_id, user, jafaal_token_manager.TokenType.ACCESS)


def _is_secure_cookie_environment() -> bool:
    """Return ``True`` when refresh cookies must be served with ``Secure``.

    Single source of truth for the cookie ``Secure`` flag used by the
    password login, refresh, and SSO token-exchange flows. Delegates to
    :attr:`AuthSettings.is_deployed` (``production``/``demo``) so the
    behaviour stays identical across all three flows and avoids the prior
    bug where the SSO path used ``FRONTEND_PROTOCOL`` and could issue
    a non-Secure refresh cookie when that env var was missing or
    mis-set in production.
    """
    return jafaal_settings.get_settings().is_deployed


def set_refresh_token_cookie(
    response: Response,
    refresh_token: str,
) -> None:
    """Set the canonical refresh-token cookie with consistent attributes.

    All web-client refresh-cookie writes (initial login, ``/refresh``,
    SSO token exchange) must go through this helper so that
    ``HttpOnly``, ``SameSite=Strict``, ``Path``, expiry, and the
    ``Secure`` flag stay in lockstep.
    """
    settings = jafaal_settings.get_settings()
    clear_refresh_token_cookies(response)
    response.set_cookie(
        key=settings.effective_refresh_cookie_name,
        value=refresh_token,
        expires=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        httponly=True,
        path=settings.refresh_cookie_path,
        secure=_is_secure_cookie_environment(),
        samesite="strict",
    )


def clear_refresh_token_cookies(response: Response) -> None:
    """Clear the refresh-token cookie.

    Args:
        response: Response object to receive the cookie-deletion header.

    Returns:
        None.

    Raises:
        None.
    """
    settings = jafaal_settings.get_settings()
    response.delete_cookie(
        key=settings.effective_refresh_cookie_name,
        path=settings.refresh_cookie_path,
        secure=_is_secure_cookie_environment(),
        httponly=True,
        samesite="strict",
    )


def build_token_response(
    response: Response,
    client_type: str,
    session_id: str,
    access_token: str,
    access_token_exp: datetime,
    refresh_token: str,
    refresh_token_exp: datetime,
    csrf_token: str | None,
) -> dict:
    """Build the token-response body for login and refresh.

    Single source of truth for token delivery, shared by the password
    login, SSO login, and ``/refresh`` flows so they cannot drift:

    - Web clients receive the refresh token as an ``HttpOnly`` cookie
      (set here via :func:`set_refresh_token_cookie`) and the CSRF token
      in the body.
    - Mobile clients receive the refresh token in the body and no CSRF
      token.

    ``expires_in`` / ``refresh_token_expires_in`` are seconds-until-expiry
    per RFC 6749 §5.1.

    Args:
        response: HTTP response used to set the web refresh cookie.
        client_type: ``"web"`` or any other value (treated as mobile).
        session_id: Session identifier.
        access_token: Newly minted access token.
        access_token_exp: Access-token expiry datetime.
        refresh_token: Newly minted refresh token.
        refresh_token_exp: Refresh-token expiry datetime.
        csrf_token: CSRF token (only returned to web clients).

    Returns:
        dict: Response body for the client type.

    Raises:
        None.
    """
    now = datetime.now(UTC)
    body = {
        "session_id": session_id,
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": int((access_token_exp - now).total_seconds()),
        "refresh_token_expires_in": int((refresh_token_exp - now).total_seconds()),
    }

    if client_type == "web":
        # Web: Refresh token as httpOnly cookie (XSS protection); CSRF
        # token in body for in-memory storage. Cookie attributes are
        # centralised in set_refresh_token_cookie so login, /refresh, and
        # SSO token exchange stay in lockstep.
        set_refresh_token_cookie(response, refresh_token)
        body["csrf_token"] = csrf_token
    else:
        # Mobile: All tokens in JSON body for secure platform storage.
        body["refresh_token"] = refresh_token

    return body


def complete_login(
    response: Response,
    request: Request,
    user: jafaal_ports.UserProtocol,
    client_type: str,
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
) -> dict:
    """
    Handles the completion of the login process by generating session and authentication tokens,
    storing the session in the database, and returning tokens in response body.

    Token delivery follows the OAuth 2.0 Security BCP (RFC 9700) advice for
    browser clients rather than RFC 6749 §5.1 literally: the access token is
    returned in the body for in-memory storage, while the refresh token is set as
    an ``HttpOnly``, ``SameSite=Strict`` cookie instead of being handed to page
    script. The body is therefore a superset of the RFC 6749 token response
    (extra ``session_id`` / ``csrf_token``, and no ``refresh_token`` for web).

    This unified model works for both username/password and SSO login flows.

    Args:
        response (Response): The HTTP response object to set refresh cookie.
        request (Request): The HTTP request object containing client information.
        user (jafaal_ports.UserProtocol): The authenticated user object.
        client_type (str): The type of client ("web" or "mobile").
        token_manager (jafaal_token_manager.TokenManager): Utility for token generation and management.
        db (Session): Database session for storing session information.

    Returns:
        dict: Contains session_id, access_token, csrf_token, token_type, expires_in, and refresh_token_expires_in.

    Raises:
        JafaalError: If the client type is invalid, raises a 403 Forbidden error.
    """
    if client_type not in ["web", "mobile"]:
        raise jafaal_exceptions.AuthorizationError(
            "Invalid client type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create the tokens
    (
        session_id,
        access_token_exp,
        access_token,
        refresh_token_exp,
        refresh_token,
        csrf_token,
    ) = create_tokens(user, token_manager)

    # Decide whether this login is from a not-previously-seen device *before*
    # the new session is written. Only pay the lookup when a host sink actually
    # wants the event (the default null sink and older sinks skip it).
    sink = jafaal_ports.get_event_sink()
    emit_new_device = not isinstance(sink, jafaal_ports.NullAuthEventSink) and hasattr(sink, "on_new_device_login")
    known_device = True
    if emit_new_device:
        try:
            known_device = jafaal_sessions_utils.is_known_device(user.id, request, db)
        except Exception:
            # Never let new-device detection break login; treat as known.
            known_device = True

    # Create the session and store it in the database
    # Note: csrf_token is NOT stored on initial login (csrf_token_hash = None).
    # This enables the page-reload bootstrap where the first /refresh call
    # after page reload establishes the CSRF binding. The httpOnly cookie is
    # sufficient authentication for the bootstrap refresh.
    jafaal_sessions_utils.create_session(
        session_id,
        user,
        request,
        refresh_token,
        db,
    )

    # Token delivery based on client type (web cookie vs mobile body) is
    # centralised in build_token_response so login, /refresh, and SSO
    # token exchange share one delivery contract.
    jafaal_audit.record(
        jafaal_audit.Event.LOGIN_SUCCESS,
        user_id=user.id,
        username=user.username,
        session_id=session_id,
        client_type=client_type,
        ip=network.get_ip_address(request),
    )

    # Best-effort security notification: a login from a device fingerprint not
    # seen on any prior session. Never blocks or fails the login.
    if emit_new_device and not known_device:
        _fingerprint, device_description = jafaal_sessions_utils.device_fingerprint(request)
        jafaal_ports.dispatch_event(
            "on_new_device_login",
            jafaal_ports.NewDeviceLogin(
                user_id=user.id,
                username=user.username,
                ip=network.get_ip_address(request),
                device_description=device_description,
                session_id=session_id,
            ),
        )
    return build_token_response(
        response,
        client_type,
        session_id,
        access_token,
        access_token_exp,
        refresh_token,
        refresh_token_exp,
        csrf_token,
    )


def create_mobile_pkce_session_response(
    response: Response,
    request: Request,
    user: jafaal_ports.UserProtocol,
    code_challenge: str,
    code_challenge_method: str,
    db: Session,
) -> jafaal_schema.MobileSessionResponse:
    """
    Create a session for mobile password login with PKCE exchange flow.

    This function is exclusively for mobile clients. Web clients should use
    complete_login() which provides secure token delivery via httpOnly cookies.

    Similar to SSO flow, but for password authentication.
    Returns session_id instead of tokens—tokens obtained via
    POST /public/idp/session/{session_id}/tokens with code_verifier.

    Args:
        response: FastAPI response object
        request: FastAPI request object
        user: Authenticated user object
        code_challenge: PKCE code challenge (base64url-encoded SHA256)
        code_challenge_method: PKCE method (must be S256)
        db: Database session

    Returns:
        jafaal_schema.MobileSessionResponse: Contains session_id and mfa_required flag

    Raises:
        JafaalError: If PKCE parameters are invalid

    Notes:
        - Mobile-only: Web clients use complete_login() with httpOnly cookies
        - Session created without tokens (pending exchange)
        - OAuth state record stores PKCE challenge
        - Client must POST to /public/idp/session/{session_id}/tokens
        - Reuses existing token exchange endpoint from SSO flow
    """
    # Validate PKCE challenge format
    if code_challenge_method != "S256":
        raise jafaal_exceptions.InvalidRequestError("Only S256 PKCE method is supported")

    idp_utils.validate_pkce_challenge(code_challenge, code_challenge_method)

    # Generate session ID
    session_id = str(uuid4())

    # Create OAuth state record for PKCE (reuse SSO infrastructure)
    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()
    client_ip = network.get_ip_address(request)

    oauth_state_crud.create_oauth_state(
        db=db,
        state_id=state_id,
        nonce=nonce,
        client_type="mobile",  # This function is mobile-only
        ip_address=client_ip,
        redirect_path=None,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    # Create session linked to oauth_state (enables PKCE exchange)
    jafaal_sessions_utils.create_session(
        session_id,
        user,
        request,
        None,  # No refresh token yet
        db,
        oauth_state_id=state_id,
    )

    # Return session_id for token exchange (no tokens yet)
    return jafaal_schema.MobileSessionResponse(
        session_id=session_id,
        mfa_required=False,
        message=("Complete authentication by exchanging tokens at /public/idp/session/{session_id}/tokens"),
    )
