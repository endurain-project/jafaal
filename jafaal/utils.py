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
import jafaal.ports as jafaal_ports
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
    if len(password) > jafaal_settings.get_settings().passwords.max_length:
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
    client: jafaal_settings.OAuthClient | None = None,
) -> tuple[str, datetime, str, datetime, str, str]:
    """
    Generates session tokens for a user, including access token, refresh token, and CSRF token.

    Args:
        user (jafaal_ports.UserProtocol): The user object for whom the tokens are being created.
        token_manager (jafaal_token_manager.TokenManager): The token manager responsible for token creation.
        session_id (str | None, optional): An optional session ID. If not provided, a new unique session ID is generated.
        client: The registered client the tokens are issued to. Its scope
            ceiling narrows what the tokens carry.

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
    access_token_exp, access_token = token_manager.create_token(
        session_id, user, jafaal_token_manager.TokenType.ACCESS, client
    )

    refresh_token_exp, refresh_token = token_manager.create_token(
        session_id, user, jafaal_token_manager.TokenType.REFRESH, client
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
    client: jafaal_settings.OAuthClient | None = None,
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
        client: The registered client the token is issued to.

    Returns:
        Tuple of (access_token_exp, access_token).
    """
    return token_manager.create_token(session_id, user, jafaal_token_manager.TokenType.ACCESS, client)


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
        expires=datetime.now(UTC) + timedelta(days=settings.tokens.refresh_token_expire_days),
        httponly=True,
        path=settings.sessions.refresh_cookie_path,
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
        path=settings.sessions.refresh_cookie_path,
        secure=_is_secure_cookie_environment(),
        httponly=True,
        samesite="strict",
    )


def apply_no_store(response: Response) -> None:
    """Mark ``response`` as uncacheable, per RFC 6749 §5.1.

    §5.1 requires ``Cache-Control: no-store`` on *any* response carrying tokens,
    and ``Pragma: no-cache`` alongside it for HTTP/1.0 intermediaries. Without
    it a proxy, a browser back/forward cache, or a CDN in front of the API may
    retain an access token — or, under body delivery, a refresh token — and
    serve it to someone else.

    Applied to every credential-bearing response, not just the token endpoint:
    the direct login endpoint and the MFA challenge hand back equally sensitive
    material.
    """
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def build_token_response(
    response: Response,
    client: jafaal_settings.OAuthClient,
    session_id: str,
    access_token: str,
    access_token_exp: datetime,
    refresh_token: str,
    refresh_token_exp: datetime,
    csrf_token: str | None,
    scope: str | None = None,
) -> dict:
    """Build the RFC 6749 §5.1 token response for ``client``.

    Single source of truth for token delivery, shared by the password login,
    authorization-code, and ``/refresh`` flows so they cannot drift.

    Delivery follows the client's registered ``token_delivery``, never a
    request-supplied value:

    - ``cookie`` — the refresh token is set as an ``HttpOnly``,
      ``SameSite=Strict`` cookie (RFC 9700 §7.2: do not expose refresh tokens
      to page script) and a CSRF token is returned in its place.
    - ``body`` — the literal RFC 6749 §5.1 response, refresh token included.

    ``expires_in`` is seconds-until-expiry per §5.1;
    ``refresh_token_expires_in`` and ``session_id`` are JAFAAL extensions, which
    §5.1 explicitly permits. The response is marked ``no-store`` because §5.1
    requires it of every token-bearing response.

    Args:
        response: HTTP response used to set the refresh cookie.
        client: The registered client receiving the tokens.
        session_id: Session identifier.
        access_token: Newly minted access token.
        access_token_exp: Access-token expiry datetime.
        refresh_token: Newly minted refresh token.
        refresh_token_exp: Refresh-token expiry datetime.
        csrf_token: CSRF token (only returned under ``cookie`` delivery).
        scope: Space-delimited granted scopes. RFC 6749 §5.1 requires this when
            it differs from what was requested; JAFAAL always sends it so a
            client never has to decode the access token to learn what it got.

    Returns:
        dict: Response body for the client.

    Raises:
        None.
    """
    apply_no_store(response)
    now = datetime.now(UTC)
    body = {
        "session_id": session_id,
        "access_token": access_token,
        # RFC 6749 §7.1 / RFC 6750 §4: the type is case-insensitive but is
        # registered as "Bearer". Emitted consistently everywhere.
        "token_type": "Bearer",
        "expires_in": int((access_token_exp - now).total_seconds()),
        "refresh_token_expires_in": int((refresh_token_exp - now).total_seconds()),
    }
    if scope is not None:
        body["scope"] = scope

    if client.uses_cookie_delivery:
        # Refresh token as httpOnly cookie (XSS protection); CSRF token in body
        # for in-memory storage. Cookie attributes are centralised in
        # set_refresh_token_cookie so login, /refresh, and the code exchange
        # stay in lockstep.
        set_refresh_token_cookie(response, refresh_token)
        body["csrf_token"] = csrf_token
    else:
        # All tokens in the JSON body for secure platform storage.
        body["refresh_token"] = refresh_token

    return body


def granted_scope(user: jafaal_ports.UserProtocol, client: jafaal_settings.OAuthClient) -> str:
    """Return the space-delimited scopes a token for ``user``/``client`` carries.

    Mirrors exactly what :meth:`TokenManager.create_token` stamps, so the
    advertised ``scope`` and the token's ``scope`` claim cannot disagree.
    """
    return " ".join(client.narrow(jafaal_ports.get_scope_resolver().scopes_for(user)))


def complete_login(
    response: Response,
    request: Request,
    user: jafaal_ports.UserProtocol,
    client: jafaal_settings.OAuthClient,
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
) -> dict:
    """Mint a session and its token bundle for an authenticated user.

    Shared by password login and the authorization-code exchange, so both flows
    produce byte-identical token semantics, auditing, and new-device detection.

    Token delivery follows ``client.token_delivery``. For a browser client
    (``cookie``) the response follows RFC 9700 §7.2 rather than RFC 6749 §5.1
    literally: the access token is returned in the body for in-memory storage,
    while the refresh token is set as an ``HttpOnly``, ``SameSite=Strict``
    cookie instead of being handed to page script.

    Args:
        response: The HTTP response object, used to set the refresh cookie.
        request: The HTTP request, for IP and device fingerprinting.
        user: The authenticated user.
        client: The registered client the tokens are issued to.
        token_manager: Utility for token generation.
        db: Database session for storing session information.

    Returns:
        dict: The RFC 6749 §5.1 token response (see :func:`build_token_response`).
    """
    # Create the tokens
    (
        session_id,
        access_token_exp,
        access_token,
        refresh_token_exp,
        refresh_token,
        csrf_token,
    ) = create_tokens(user, token_manager, client=client)

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

    # Token delivery (cookie vs body) is centralised in build_token_response so
    # login, /refresh, and the code exchange share one delivery contract.
    jafaal_audit.record(
        jafaal_audit.Event.LOGIN_SUCCESS,
        user_id=user.id,
        username=user.username,
        session_id=session_id,
        client_id=client.client_id,
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
        client,
        session_id,
        access_token,
        access_token_exp,
        refresh_token,
        refresh_token_exp,
        csrf_token,
        granted_scope(user, client),
    )
