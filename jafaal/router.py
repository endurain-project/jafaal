import contextlib
import logging
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import (
    BackgroundTasks,
    Depends,
    Form,
    Query,
    Request,
    Response,
    Security,
    status,
)
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

import jafaal._internal.internal_dependencies as jafaal_internal_dependencies
import jafaal._internal.password_hasher as jafaal_password_hasher
import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.services.authorization_code_service as authorization_code_service
import jafaal._internal.services.token_admin_service as token_admin_service
import jafaal._internal.token_manager as jafaal_token_manager
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.audit as jafaal_audit
import jafaal.dependencies as jafaal_dependencies
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.utils as idp_utils
import jafaal.identity_service as jafaal_identity_service
import jafaal.mfa.service as mfa_service
import jafaal.orm as jafaal_orm
import jafaal.ports as jafaal_ports
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.schema as jafaal_schema
import jafaal.scopes as jafaal_scopes
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.models as jafaal_sessions_models
import jafaal.sessions.rotated_refresh_tokens.utils as jafaal_sessions_rotated_tokens_utils
import jafaal.sessions.utils as jafaal_sessions_utils
import jafaal.settings as jafaal_settings
import jafaal.utils as jafaal_utils
import jafaal.webauthn.crud as webauthn_crud
from jafaal._core import network

logger = logging.getLogger(__name__)

# Define the API router
router = jafaal_orm.auth_router()


def _raise_auth_security_store_unavailable(
    err: jafaal_security_stores.AuthSecurityStoreUnavailableError,
) -> None:
    """
    Return a controlled response when auth security storage is down.

    Args:
        err: Auth security storage outage.

    Returns:
        None.

    Raises:
        JafaalError: Always raised with a 503 status.
    """
    logger.error("Auth security storage unavailable during authentication", exc_info=err)
    raise jafaal_exceptions.StoreUnavailableError("Authentication temporarily unavailable") from err


@contextlib.contextmanager
def _translate_store_outage() -> Generator[None]:
    """Translate an auth-security-store outage into a 503 at the router edge.

    Wraps the several security-store touch points in the login / MFA flows so the
    "log the outage, raise ``StoreUnavailableError``" policy lives in exactly one
    place instead of a repeated ``try/except`` at each call site.

    Raises:
        JafaalError: 503 if the wrapped operation hits a store outage.
    """
    try:
        yield
    except jafaal_security_stores.AuthSecurityStoreUnavailableError as err:
        _raise_auth_security_store_unavailable(err)


def _replay_in_grace_refresh(
    response: Response,
    client: jafaal_settings.OAuthClient,
    session: jafaal_sessions_models.UsersSessions,
    token_user_id: jafaal_orm.UserId,
    replay_refresh_token: str,
    replay_refresh_token_exp: datetime,
    granted_scope: tuple[str, ...],
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
) -> dict:
    """Replay the replacement token for an idempotent in-grace refresh retry.

    The presented refresh token was already rotated but is still inside the grace
    window (a lost rotation response, or a racing/duplicate refresh), so instead
    of a 401 the exact replacement minted on the original rotation is replayed.
    The session is NOT re-rotated (no new rotated record, no ``rotation_count``
    bump), so duplicate/concurrent refreshes converge on one outcome. A fresh
    access token is minted (stateless, safe to re-issue) and, under cookie
    delivery, a fresh CSRF token is bound to the otherwise-unchanged session.

    The replay itself has already been claimed single-use by the caller (see
    :func:`~jafaal.sessions.rotated_refresh_tokens.utils.claim_grace_replay_token`);
    a second presentation of the same rotated token is handled as reuse.

    Args:
        response: HTTP response used to set the refresh cookie.
        client: The registered client the session belongs to.
        session: The session whose token is being replayed.
        token_user_id: User ID from the refresh token's ``sub`` claim.
        replay_refresh_token: The claimed replacement refresh token.
        replay_refresh_token_exp: Expiry of the replacement refresh token.
        granted_scope: Scopes the replayed grant carries, so the reissued access
            token matches the one whose response was lost.
        token_manager: Token manager for minting the access/CSRF tokens.
        db: Database session.

    Returns:
        The token-response body for the client.

    Raises:
        JafaalError: 401 if the user is missing or inactive.
    """
    # Validate the user is still present and active before re-issuing.
    replay_user = jafaal_ports.get_user_repository().get_by_id(token_user_id, db)
    if replay_user is None:
        logger.warning(f"User ID {token_user_id} not found during token refresh replay")
        raise jafaal_exceptions.AuthenticationError("Unable to authenticate")

    jafaal_user_guards.check_user_is_active(replay_user)

    # Mint a fresh, stateless access token (safe to re-issue every retry).
    replay_access_token_exp, replay_access_token = jafaal_utils.mint_access_token(
        replay_user, token_manager, session.id, client, granted_scope
    )

    # A cookie client lost its CSRF token along with the rotation response, so
    # mint a fresh one and bind it to the session (the refresh token itself is
    # unchanged). Body-delivery clients do not use CSRF.
    replay_csrf_token: str | None = None
    if client.uses_cookie_delivery:
        replay_csrf_token = token_manager.create_csrf_token()
        jafaal_sessions_utils.update_session_csrf_token(session.id, replay_csrf_token, db)

    return jafaal_utils.build_token_response(
        response,
        client,
        session.id,
        replay_access_token,
        replay_access_token_exp,
        replay_refresh_token,
        replay_refresh_token_exp,
        replay_csrf_token,
        jafaal_utils.granted_scope(replay_user, client, granted_scope),
    )


def _mfa_required_response(
    response: Response,
    client: jafaal_settings.OAuthClient,
    mfa_token: str,
    username: str,
) -> jafaal_schema.MFARequiredResponse:
    """Build the "second factor required" body.

    A cookie client additionally gets ``202 Accepted``: the credential was
    correct but the login is not complete, so a ``200`` would be
    indistinguishable from a finished login to a browser client that only
    inspects the status code. Body-delivery clients keep ``200`` because the flag
    in the body is what their SDK branches on.

    The response is marked ``no-store``: the ``mfa_token`` is a bearer ticket
    that completes a password-verified login, so it must not be cached by an
    intermediary any more than an access token would be (RFC 6749 §5.1).

    Args:
        response: HTTP response whose status code may be adjusted.
        client: The registered client making the request.
        mfa_token: The opaque pending-login ticket to hand back.
        username: The username to echo for display.

    Returns:
        The MFA-required response body.
    """
    jafaal_utils.apply_no_store(response)
    if client.uses_cookie_delivery:
        response.status_code = status.HTTP_202_ACCEPTED
    return jafaal_schema.MFARequiredResponse(
        mfa_required=True,
        mfa_token=mfa_token,
        username=username,
    )


@router.post(
    "/login",
    summary="First-party direct login (not an OAuth grant)",
    description=(
        "Authenticates an end user with their username and password and issues tokens to a **registered "
        "client**.\n\n"
        "**This is not an OAuth 2.0 grant.** It is deliberately not the resource-owner password-credentials "
        "grant, which OAuth 2.1 removes: it is a first-party API for an application that owns both the "
        "login form and the user directory, and it is never advertised in `/.well-known/"
        "oauth-authorization-server`. A third-party client must use `/auth/authorize` + `/auth/token`.\n\n"
        "`client_id` is required and must name a client registered via `AuthSettings.oauth_clients`; its "
        "registration decides whether the refresh token comes back in the body or as an `HttpOnly` cookie, "
        "and how wide the tokens may be.\n\n"
        "The endpoint may return `202 Accepted` with an MFA challenge instead of tokens."
    ),
    response_model=(
        jafaal_schema.MFARequiredResponse | jafaal_schema.TokenResponseWeb | jafaal_schema.TokenResponseMobile
    ),
)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def login_for_access_token(
    response: Response,
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    failed_attempts: Annotated[
        jafaal_security_stores.FailedLoginStore,
        Depends(jafaal_security_stores.get_failed_login_attempts),
    ],
    pending_mfa_store: Annotated[
        jafaal_security_stores.PendingMFAStore,
        Depends(jafaal_security_stores.get_pending_mfa_store),
    ],
    password_hasher: Annotated[
        jafaal_password_hasher.PasswordHasher,
        Depends(jafaal_password_hasher.get_password_hasher),
    ],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[
        Session,
        Depends(jafaal_orm.get_db),
    ],
):
    """Authenticate a user directly and issue tokens to a registered client.

    Protection Mechanisms:
    - Rate limiting: 10 requests per minute per IP (SENSITIVE tier, prevents DoS attacks)
    - Progressive lockout: Per-username tracking prevents targeted brute-force:
      * 5 failures: 5 minute lockout
      * 10 failures: 30 minute lockout
      * 20 failures: 24 hour lockout

    Args:
        response: The HTTP response object.
        request: The HTTP request object.
        form_data: The RFC 6749 §4.3.2 form shape — ``username``, ``password``,
            required ``client_id``, and an optional ``scope``.
        failed_attempts: Failed login attempts tracker for progressive lockout.
        pending_mfa_store: Store for pending MFA logins.
        password_hasher: The password hasher used for verifying passwords.
        token_manager: The token manager used for token operations.
        db: Database session.

    Returns:
        The token response, or an MFA challenge when a second factor is required.

    Raises:
        JafaalError: If authentication fails, the user is inactive, the account
            is locked, or ``client_id`` is missing or unregistered.
    """
    client = authorization_code_service.resolve_login_client(form_data.client_id, request)
    # RFC 6749 §3.3: the caller may ask for less than it is entitled to. Validated
    # here (catalog membership + the client's ceiling) and carried through to the
    # token minter — including across the MFA challenge — so a narrow request
    # cannot be widened by finishing the login in two steps.
    requested_scope = tuple(form_data.scopes)
    authorization_code_service.validate_requested_scope(" ".join(form_data.scopes), client)

    client_ip = network.get_ip_address(request)

    # Per-source-IP backoff: refuse when this IP has sprayed enough failed logins
    # across usernames to trip the IP lockout, so a single IP cannot cheaply lock
    # out many accounts. Checked before the per-username lockout so a spraying IP
    # is stopped regardless of the target account.
    with _translate_store_outage():
        if failed_attempts.is_ip_locked_out(client_ip):
            ip_lockout_until = failed_attempts.get_ip_lockout_time(client_ip)
            if ip_lockout_until:
                seconds_remaining = int((ip_lockout_until - datetime.now(UTC)).total_seconds())
                raise jafaal_exceptions.RateLimitedError(
                    f"Too many failed login attempts from this network. Try again in {seconds_remaining} seconds.",
                    retry_after=seconds_remaining,
                )

    # Check if username is locked out from too many failed login attempts
    with _translate_store_outage():
        if failed_attempts.is_locked_out(form_data.username):
            lockout_until = failed_attempts.get_lockout_time(form_data.username)
            if lockout_until:
                seconds_remaining = int((lockout_until - datetime.now(UTC)).total_seconds())
                raise jafaal_exceptions.RateLimitedError(
                    f"Account locked due to too many failed login attempts. Try again in {seconds_remaining} seconds.",
                    retry_after=seconds_remaining,
                )

    # Authenticate user
    try:
        user = jafaal_utils.authenticate_user(form_data.username, form_data.password, password_hasher, db)
    except jafaal_exceptions.JafaalError as err:
        # Record failed attempt on authentication errors (401 Unauthorized)
        if isinstance(err, jafaal_exceptions.AuthenticationError):
            jafaal_audit.record(
                jafaal_audit.Event.LOGIN_FAILURE,
                outcome=jafaal_audit.Outcome.FAILURE,
                level=logging.WARNING,
                username=form_data.username,
                ip=network.get_ip_address(request),
                reason=err.code,
            )
            with _translate_store_outage():
                failed_attempts.record_failed_attempt(form_data.username)
                failed_attempts.record_ip_failure(client_ip)
        raise err

    # Check if the user is active
    jafaal_user_guards.check_user_is_active(user)

    # A second factor is required when the account has TOTP MFA enabled, or —
    # when webauthn_second_factor_enabled — has at least one registered passkey.
    # The pending login is satisfied by either factor: /auth/mfa/verify (TOTP or
    # backup code) or /auth/webauthn/mfa/* (passkey assertion).
    require_second_factor = mfa_service.is_mfa_enabled_for_user(user.id, db) or (
        jafaal_settings.get_settings().webauthn.second_factor_enabled
        and webauthn_crud.user_has_credentials(user.id, db)
    )
    if require_second_factor:
        # Store the user for pending MFA verification. The returned ticket is
        # the caller's proof that *it* satisfied the password factor; without
        # it the second factor alone cannot complete a login.
        with _translate_store_outage():
            mfa_token = pending_mfa_store.add_pending_login(
                form_data.username, user.id, client.client_id, requested_scope
            )

        # Don't reset failed login attempts yet - wait for MFA verification
        # This prevents bypassing lockout by triggering MFA flow
        return _mfa_required_response(response, client, mfa_token, form_data.username)

    # Password authentication successful and no MFA required
    # Reset failed login attempts counter
    with _translate_store_outage():
        failed_attempts.reset_attempts(form_data.username)
        failed_attempts.reset_ip_attempts(client_ip)

    return jafaal_utils.complete_login(response, request, user, client, token_manager, db, requested_scope)


@router.post(
    "/mfa/verify",
    response_model=(jafaal_schema.TokenResponseWeb | jafaal_schema.TokenResponseMobile),
)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def verify_mfa_and_login(
    response: Response,
    request: Request,
    mfa_request: jafaal_schema.MFALoginRequest,
    failed_attempts: Annotated[
        jafaal_security_stores.FailedLoginStore,
        Depends(jafaal_security_stores.get_failed_login_attempts),
    ],
    pending_mfa_store: Annotated[
        jafaal_security_stores.PendingMFAStore,
        Depends(jafaal_security_stores.get_pending_mfa_store),
    ],
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[
        Session,
        Depends(jafaal_orm.get_db),
    ],
):
    """Verify a second factor and complete the pending login.

    Args:
        response: The HTTP response object.
        request: The HTTP request object.
        mfa_request: The ``mfa_token`` ticket issued by ``/auth/login``, the MFA
            code, and the ``client_id`` the login was started for.
        failed_attempts: Failed login attempts tracker for progressive lockout.
        pending_mfa_store: Store for pending MFA logins.
        identity_service: Identity service used to verify backup codes.
        token_manager: The token manager used for token operations.
        db: Database session.

    Returns:
        The token response.

    Raises:
        JafaalError: If the ticket is unknown/expired, the MFA code is invalid,
            the user is not found, or ``client_id`` is unregistered.
    """
    client = authorization_code_service.resolve_login_client(mfa_request.client_id, request)

    # Resolve the pending login from the opaque ticket. Because the ticket is a
    # 256-bit secret handed only to the caller that passed the password step,
    # this lookup is itself an authentication check — an attacker holding a
    # valid one-time code but no ticket cannot reach the verification below.
    # It also means this endpoint is no longer a "is user X mid-login?" oracle,
    # so the timing-equalising dummy verify the username-addressed version
    # needed here is obsolete (and its ~50 ms Argon2 cost is not spent on every
    # rejected request).
    with _translate_store_outage():
        pending = pending_mfa_store.get_pending_login(mfa_request.mfa_token)
    if pending is None:
        logger.warning("No pending MFA login found for the presented ticket")
        raise jafaal_exceptions.InvalidRequestError(
            "No pending MFA login found. Please start the login again.",
        )

    user_id = pending.user_id
    username = pending.username
    username_log_id = jafaal_security_stores.username_log_identifier(username)

    # Check if user is locked out from too many failed attempts
    with _translate_store_outage():
        if pending_mfa_store.is_locked_out(username):
            lockout_until = pending_mfa_store.get_lockout_time(username)
            if lockout_until:
                seconds_remaining = int((lockout_until - datetime.now(UTC)).total_seconds())
                raise jafaal_exceptions.RateLimitedError(
                    f"Too many failed MFA attempts. Account locked for {seconds_remaining} seconds.",
                    retry_after=seconds_remaining,
                )

    # Verify the MFA code (TOTP or backup code)
    if not mfa_service.verify_user_mfa(user_id, mfa_request.mfa_code, identity_service, db):
        # Record failed attempt and apply lockout if threshold exceeded
        with _translate_store_outage():
            failed_count = pending_mfa_store.record_failed_attempt(username)
        logger.warning(f"Invalid MFA code for {username_log_id}. Failed attempts: {failed_count}")
        jafaal_audit.record(
            jafaal_audit.Event.MFA_FAILURE,
            outcome=jafaal_audit.Outcome.FAILURE,
            level=logging.WARNING,
            user_id=user_id,
            username=username,
            ip=network.get_ip_address(request),
            failed_attempts=failed_count,
        )
        raise jafaal_exceptions.InvalidMFACodeError("Invalid MFA code, backup code or backup code already used.")

    # Consume the ticket atomically: one password step authorises exactly one
    # completed login, so a leaked ticket cannot be replayed after use.
    with _translate_store_outage():
        claimed = pending_mfa_store.claim_pending_login(mfa_request.mfa_token)
    if claimed is None or claimed.user_id != user_id:
        logger.warning(f"Pending MFA login for {username_log_id} was missing or already claimed")
        raise jafaal_exceptions.InvalidRequestError(
            "No pending MFA login found. Please start the login again.",
        )

    # The second factor must finish against the client the password step was
    # started for: the registration decides token delivery and the scope
    # ceiling, so a swap here would widen a login mid-flow.
    if claimed.client_id != client.client_id:
        logger.warning(f"Pending MFA login for {username_log_id} was claimed by a different client")
        raise jafaal_exceptions.InvalidRequestError(
            "This login was started for a different client. Please start the login again.",
        )

    # Get the user and complete login
    user = jafaal_ports.get_user_repository().get_by_id(user_id, db)
    if not user:
        logger.warning(f"User ID {user_id} not found during MFA verification")
        raise jafaal_exceptions.AuthenticationError("Unable to authenticate")

    # Check if the user is still active
    jafaal_user_guards.check_user_is_active(user)

    # MFA verification successful - reset both MFA and login failed attempts counters
    jafaal_audit.record(
        jafaal_audit.Event.MFA_SUCCESS,
        user_id=user_id,
        username=username,
        ip=network.get_ip_address(request),
    )
    with _translate_store_outage():
        pending_mfa_store.reset_attempts(username)
        failed_attempts.reset_attempts(username)
        failed_attempts.reset_ip_attempts(network.get_ip_address(request))

    # The scope comes from the claimed ticket, not from this request: the
    # password step is where the client asked, and re-reading it here would let
    # step two widen what step one requested.
    return jafaal_utils.complete_login(response, request, user, client, token_manager, db, claimed.scope)


async def _grant_refresh_token(
    response: Response,
    request: Request,
    background_tasks: BackgroundTasks,
    refresh: jafaal_internal_dependencies.ValidatedRefreshToken,
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
    x_csrf_token: str | None,
) -> dict:
    """Rotate a refresh token and return a fresh token bundle.

    The implementation behind both ``/auth/token`` (with
    ``grant_type=refresh_token``) and the ``/auth/refresh`` alias, so the two
    paths cannot drift.

    Every refresh rotates the token; presenting an already-rotated one past a
    short grace window is treated as theft and invalidates the token family.

    The client is read from the token's own ``client_id`` claim, not the request,
    so a caller cannot switch delivery mode or widen scope at rotation time.

    CSRF bootstrap for page reload:
        On page reload, in-memory tokens are lost but the httpOnly cookie
        persists.
        - If no CSRF header: allow refresh (page-reload scenario)
        - If CSRF header provided: validate it (legitimate request with cached token)
        - The httpOnly + SameSite=Strict cookie, plus the off-site rejection
          below, are the primary protection; the CSRF token is defense-in-depth.

    Args:
        response: The HTTP response object.
        request: The HTTP request object.
        background_tasks: Used to defer the opportunistic IdP token refresh.
        refresh: The validated refresh token, its ``sub`` / ``sid`` claims, and
            the registered client it was issued to.
        token_manager: Utility for creating tokens.
        db: Database session.
        x_csrf_token: CSRF token header (cookie clients only, optional on page reload).

    Returns:
        dict: The RFC 6749 §5.1 token response.

    Raises:
        JafaalError: If session not found, refresh token invalid,
                       user is inactive, or CSRF token is invalid (when provided).
    """
    token_user_id = refresh.user_id
    token_session_id = refresh.session_id
    refresh_token_value = refresh.token
    client = refresh.client

    # Get the session from the database
    session = jafaal_sessions_crud.get_session_by_id_not_expired(token_session_id, db)

    # Check if the session was found
    if session is None:
        # RFC 6749 §5.2: a refresh token that no longer resolves to a grant is
        # ``invalid_grant``, not a missing resource. A 404 would also tell the
        # caller the difference between "revoked" and "never valid", which is an
        # oracle the code-grant path deliberately avoids.
        raise jafaal_exceptions.InvalidGrantError("The refresh token is invalid, expired, or was revoked.")

    # Defense-in-depth: ensure the session belongs to the user named in
    # the refresh token's `sub` claim. The refresh-token hash stored on
    # the session is already bound to this user, so a mismatched token
    # would fail hash verification below — but asserting ownership here
    # makes the invariant explicit and fails fast (rather than relying on
    # the implicit binding) if a token's `sub`/`sid` claims are ever
    # decoupled from the persisted session.
    if session.user_id != token_user_id:
        logger.warning(
            f"Refresh token session owner mismatch: token sub={token_user_id}, session user_id={session.user_id}"
        )
        raise jafaal_exceptions.InvalidTokenError("Invalid refresh token")

    # Validate session hasn't exceeded idle or absolute timeout
    jafaal_sessions_utils.validate_session_timeout(session)

    # Verify CSRF for cookie clients only; body-delivery clients don't use CSRF
    # tokens.
    #
    # Two layers, because each covers the other's blind spot:
    #
    # 1. Off-site rejection (always enforced under cookie delivery). ``Origin``
    #    and ``Sec-Fetch-Site`` are forbidden header names, so page script cannot
    #    forge or strip them — unlike a custom ``X-CSRF-Token`` header, which a
    #    cross-site attacker simply omits. This is what makes the bootstrap rule
    #    below genuinely safe rather than merely optional for the attacker.
    # 2. CSRF-token binding (when the client sends one). Page-reload bootstrap:
    #    on EVERY reload the in-memory tokens (incl.
    #    the CSRF token) are lost while the httpOnly refresh cookie persists, so
    #    the client POSTs here without an X-CSRF-Token header to bootstrap a new
    #    one. That must keep working after a binding has been minted, otherwise
    #    the user is logged out on reload. When the client DOES send a header it
    #    MUST be valid (prevents partial-CSRF, where script can read the cookie
    #    but not the bound token).
    #
    # The refresh cookie's HttpOnly + SameSite=Strict attributes remain the
    # primary protection; both checks here are defense-in-depth.
    if client.uses_cookie_delivery:
        network.reject_off_site_request(request, operation="Refresh")
        if (
            x_csrf_token
            and session.csrf_token_hash is not None
            and not jafaal_sessions_utils.verify_csrf_token(x_csrf_token, session.csrf_token_hash)
        ):
            raise jafaal_exceptions.AuthorizationError(
                "Invalid CSRF token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Verify session has a refresh token (not pending PKCE exchange)
    if not session.refresh_token:
        raise jafaal_exceptions.InvalidTokenError("Tokens not yet exchanged via PKCE. Complete SSO/PKCE flow first.")

    # Check for token reuse BEFORE validating token
    # Uses HMAC-SHA256 internally for deterministic, secure lookup
    is_reused, in_grace = jafaal_sessions_rotated_tokens_utils.check_token_reuse(refresh_token_value, db)

    if is_reused and in_grace:
        # Idempotent in-grace replay: the presented token was already rotated but
        # is still inside the grace window (a lost rotation response, or a
        # racing/duplicate refresh from a background uploader). Claim the
        # original replacement — single-use — and replay it instead of
        # re-rotating, so duplicate/concurrent refreshes converge.
        #
        # Losing the claim means the one legitimate retry was already served, so
        # this is a *third* presentation of a superseded token. That is reuse,
        # not a retry, and falls through to the theft path below rather than
        # handing out the live credential again.
        replay = jafaal_sessions_rotated_tokens_utils.claim_grace_replay_token(refresh_token_value, db)
        if replay is not None:
            return _replay_in_grace_refresh(
                response,
                client,
                session,
                token_user_id,
                replay[0],
                replay[1],
                refresh.scope,
                token_manager,
                db,
            )
        in_grace = False

    if is_reused and not in_grace:
        # Token theft detected - invalidate entire family. Runs in its own
        # transaction because this request ends in a 401: revoking inside the
        # request's unit of work would be rolled back with it, leaving the
        # stolen token usable.
        jafaal_sessions_rotated_tokens_utils.invalidate_token_family(session.token_family_id)
        # Best-effort security notification so the host can alert the user; the
        # 401 below is unaffected by delivery success/failure.
        await jafaal_ports.adispatch_event(
            "on_refresh_token_theft_detected",
            jafaal_ports.RefreshTokenTheftDetected(
                user_id=token_user_id,
                token_family_id=session.token_family_id,
            ),
        )
        raise jafaal_exceptions.InvalidTokenError("Token reuse detected. All sessions invalidated.")

    is_valid = jafaal_sessions_utils.verify_refresh_token(refresh_token_value, session.refresh_token)

    if not is_valid:
        raise jafaal_exceptions.InvalidTokenError("Invalid refresh token")

    # get user
    user = jafaal_ports.get_user_repository().get_by_id(token_user_id, db)

    if user is None:
        logger.warning(f"User ID {token_user_id} not found during token refresh")
        raise jafaal_exceptions.AuthenticationError("Unable to authenticate")

    # Check if the user is active
    jafaal_user_guards.check_user_is_active(user)

    # Create the new token bundle first so the rotated record can persist the
    # replacement refresh token used for idempotent in-grace replay.
    #
    # The presented token's own ``scope`` claim bounds the replacement: RFC 6749
    # §6 forbids a rotation from adding a scope the original grant did not carry,
    # so re-deriving it from the account would silently undo a narrow request on
    # the very first refresh.
    (
        session_id,
        new_access_token_exp,
        new_access_token,
        new_refresh_token_exp,
        new_refresh_token,
        new_csrf_token,
    ) = jafaal_utils.create_tokens(user, token_manager, session.id, client, refresh.scope)

    # Captured before the claim: the conditional UPDATE may synchronise the ORM
    # instance, and the rotated record must record the rotation the *old* token
    # belonged to, not the one replacing it.
    rotated_from_count = session.rotation_count
    token_family_id = session.token_family_id

    # Claim the rotation BEFORE recording the rotated token. The claim is a
    # conditional UPDATE gated on the session still holding the digest verified
    # above, so exactly one of N concurrent requests carrying the same refresh
    # token proceeds. Doing it first is what keeps the loser off the rotated-
    # token INSERT, whose UNIQUE index would otherwise raise an unhandled
    # IntegrityError (a 500) instead of a defined response.
    # Note: rotate_session increments rotation_count, refreshes
    # last_rotation_at, and caps expires_at at the session's absolute deadline.
    if not jafaal_sessions_utils.rotate_session(
        session,
        new_refresh_token,
        db,
        new_csrf_token=new_csrf_token,
    ):
        # Another request rotated this session first. The presented token is no
        # longer current; the client should retry, which will either replay that
        # rotation's result in-grace or be told to log in again.
        raise jafaal_exceptions.StaleRefreshTokenError(
            "This refresh token was already rotated by a concurrent request. Retry with the current token."
        )

    # Store the rotated (old) refresh token together with the encrypted
    # replacement so a retry within the grace window can replay it.
    # store_rotated_token hashes the old token with HMAC-SHA256 for lookup
    # and encrypts the replacement at rest.
    jafaal_sessions_rotated_tokens_utils.store_rotated_token(
        refresh_token_value,
        token_family_id,
        rotated_from_count,
        db,
        replacement_refresh_token=new_refresh_token,
        replacement_refresh_token_exp=new_refresh_token_exp,
    )

    # Opportunistically refresh IdP tokens for all linked identity providers.
    # Deferred to a background task on its own session: it performs outbound
    # HTTP to every linked provider, which must not run inside this request's
    # transaction (it would hold the rotated session row's lock open across the
    # network call) nor add the round trip to the client's refresh latency.
    background_tasks.add_task(idp_utils.refresh_idp_tokens_if_needed, user.id)

    jafaal_audit.record(
        jafaal_audit.Event.TOKEN_REFRESHED,
        user_id=user.id,
        session_id=session_id,
        client_id=client.client_id,
        rotation_count=session.rotation_count,
    )

    # Token delivery (cookie vs body) is centralised in
    # jafaal_utils.build_token_response so login, /refresh, and the code exchange
    # share one delivery contract.
    return jafaal_utils.build_token_response(
        response,
        client,
        session_id,
        new_access_token,
        new_access_token_exp,
        new_refresh_token,
        new_refresh_token_exp,
        new_csrf_token,
        jafaal_utils.granted_scope(user, client, refresh.scope),
    )


def _authorize_error_redirect(
    redirect_uri: str,
    err: jafaal_exceptions.OAuthError,
    state: str | None,
) -> RedirectResponse:
    """Report an authorization error by redirecting, per RFC 6749 §4.1.2.1.

    Once ``client_id`` and ``redirect_uri`` are known-good, §4.1.2.1 says every
    subsequent failure MUST be delivered to that URI as ``error`` /
    ``error_description`` / ``state`` query parameters. Rendering JSON instead
    strands the client: a native app waiting on its redirect never learns the
    request failed, and the user is left on a blank browser tab.

    ``iss`` is included here as well as on the success response: RFC 9207 §2
    requires the issuer identifier on *every* authorization response, so a client
    that validates it unconditionally does not have to special-case failures.

    Args:
        redirect_uri: The already-validated redirect target.
        err: The OAuth error to report.
        state: The client's ``state``, echoed back so it can match the response
            to its request (and detect CSRF).

    Returns:
        A 302 to the client's redirect URI carrying the error.
    """
    params = {
        "error": err.oauth_error,
        "error_description": err.detail,
        "iss": jafaal_settings.get_settings().resolved_issuer,
    }
    if state is not None:
        params["state"] = state
    return RedirectResponse(
        url=idp_utils.append_query_params(redirect_uri, params),
        # 302 rather than 307: the browser is following a navigation, and the
        # method must not be preserved.
        status_code=status.HTTP_302_FOUND,
    )


@router.get(
    "/authorize",
    status_code=status.HTTP_302_FOUND,
    summary="OAuth 2.0 authorization endpoint (RFC 6749 §4.1, PKCE required)",
    description=(
        "Starts the authorization-code flow for a **registered public client** (RFC 8252 native app).\n\n"
        "The user is sent to the selected identity provider; when they come back, JAFAAL redirects the "
        "browser to the client's registered `redirect_uri` with `code` and `state`, which the client "
        "redeems at `/auth/token` with `grant_type=authorization_code` and its `code_verifier`.\n\n"
        "PKCE is mandatory (`code_challenge_method=S256`), `response_type=code` is the only supported "
        "response type, and `redirect_uri` must match one registered for the `client_id` **exactly**.\n\n"
        "Errors are reported per RFC 6749 §4.1.2.1: as a redirect carrying `error`/`error_description`/"
        "`state` once the client and redirect URI validate, and as a JSON body before that."
    ),
)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def authorize(
    request: Request,
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    response_type: Annotated[str, Query(description="Must be 'code'.")],
    client_id: Annotated[str, Query(description="A client registered via AuthSettings.oauth_clients.")],
    redirect_uri: Annotated[str, Query(description="Must exactly match one of the client's registered URIs.")],
    code_challenge: Annotated[str, Query(description="PKCE challenge, base64url SHA-256 (43-128 chars).")],
    code_challenge_method: Annotated[str, Query(description="Must be 'S256'.")],
    idp: Annotated[str, Query(description="Slug of the identity provider to authenticate with.")],
    state: Annotated[str | None, Query(description="Opaque value echoed back with the code.")] = None,
    scope: Annotated[str | None, Query(description="Space-delimited scopes to request.")] = None,
):
    """Start an RFC 6749 authorization-code flow for a registered public client.

    Args:
        request: The incoming HTTP request.
        db: Database session.
        response_type: Must be ``code``.
        client_id: The registered client making the request.
        redirect_uri: Where to deliver the authorization code.
        code_challenge: PKCE challenge (RFC 7636).
        code_challenge_method: PKCE method; only ``S256``.
        idp: Slug of the identity provider to authenticate against.
        state: Opaque client value, returned unmodified with the code.
        scope: Space-delimited scopes to request. Omitted means "everything this
            client and user are entitled to"; the granted set is always reported
            in the token response.

    Returns:
        A redirect to the identity provider's authorization endpoint, or — for a
        failure after the redirect URI validates — to the client's redirect URI
        carrying the error.

    Raises:
        OAuthError: 400/401 if the client is unregistered or the redirect URI is
            not registered for it. RFC 6749 §4.1.2.1 requires these two to be
            reported to the user agent rather than redirected, because an
            unvalidated redirect target must never be used — that is exactly the
            open redirect that leaks the code.
    """
    # Validated before anything is persisted or redirected, and deliberately the
    # only failure mode that renders instead of redirecting.
    client = authorization_code_service.validate_client_and_redirect_uri(client_id, redirect_uri)

    # From here the redirect target is trusted, so §4.1.2.1 applies: report by
    # redirect so the waiting client actually learns what went wrong.
    try:
        authorization_code_service.validate_authorization_request(response_type, code_challenge, code_challenge_method)
        authorization_code_service.validate_requested_scope(scope, client)

        authorization_url = await idp_utils.begin_idp_authorization(
            idp_slug=idp,
            request=request,
            db=db,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            client_id=client_id,
            redirect_uri=redirect_uri,
            client_state=state,
            requested_scope=scope,
        )
    except jafaal_exceptions.OAuthError as err:
        return _authorize_error_redirect(redirect_uri, err, state)
    except jafaal_exceptions.JafaalError as err:
        # A non-OAuth failure (e.g. an unknown or disabled `idp` slug) still has
        # to reach the client. RFC 6749 §4.1.2.1 has no code for "your idp
        # parameter is wrong", and `invalid_request` is its designated bucket
        # for a request that is otherwise malformed.
        return _authorize_error_redirect(
            redirect_uri,
            jafaal_exceptions.OAuthError("invalid_request", err.detail),
            state,
        )
    return RedirectResponse(url=authorization_url, status_code=status.HTTP_302_FOUND)


@router.post(
    "/token",
    response_model=(jafaal_schema.TokenResponseWeb | jafaal_schema.TokenResponseMobile),
    summary="OAuth 2.0 token endpoint (RFC 6749 §4.1.3 and §6)",
    description=(
        "Implements two grants:\n\n"
        "* `authorization_code` — redeem a code from `/auth/authorize` with the PKCE `code_verifier`, "
        "`client_id`, and the same `redirect_uri`.\n"
        "* `refresh_token` — rotate a refresh token.\n\n"
        "`/auth/refresh` is an alias that serves the refresh grant plus JAFAAL's native cookie/header "
        "request shape."
    ),
)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
async def token_endpoint(
    response: Response,
    request: Request,
    background_tasks: BackgroundTasks,
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    grant_type: Annotated[str, Form(description="'authorization_code' or 'refresh_token'.")],
    refresh: Annotated[
        jafaal_internal_dependencies.ValidatedRefreshToken | None,
        Depends(jafaal_internal_dependencies.get_validated_refresh_token_optional),
    ] = None,
    code: Annotated[str | None, Form(description="Authorization code from /auth/authorize.")] = None,
    code_verifier: Annotated[str | None, Form(description="PKCE verifier for the code.")] = None,
    redirect_uri: Annotated[str | None, Form(description="Must equal the authorization request's.")] = None,
    client_id: Annotated[str | None, Form(description="The client redeeming the code.")] = None,
    x_csrf_token: Annotated[str | None, Depends(jafaal_internal_dependencies.header_csrf_token_scheme)] = None,
):
    """Serve the OAuth token endpoint for both supported grants.

    Args:
        response: The HTTP response object.
        request: The HTTP request object.
        background_tasks: Used by the refresh grant for deferred IdP work.
        token_manager: Utility for minting tokens.
        db: Database session.
        grant_type: The requested grant.
        refresh: Validated refresh token, present only for the refresh grant.
        code: The authorization code (code grant).
        code_verifier: The PKCE verifier (code grant).
        redirect_uri: The redirect URI from the authorization request (code grant).
        client_id: The redeeming client (code grant).
        x_csrf_token: CSRF header, honoured by the refresh grant for cookie clients.

    Returns:
        The RFC 6749 §5.1 token response.

    Raises:
        OAuthError: ``unsupported_grant_type`` for an unknown grant,
            ``invalid_request`` for a missing parameter, ``invalid_grant`` for a
            code or refresh token that does not verify.
    """
    if grant_type == authorization_code_service.GRANT_AUTHORIZATION_CODE:
        return _grant_authorization_code(
            response=response,
            request=request,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            client_id=client_id,
            token_manager=token_manager,
            db=db,
        )

    if grant_type == jafaal_internal_dependencies.REFRESH_TOKEN_GRANT:
        if refresh is None:
            raise jafaal_exceptions.OAuthError(
                "invalid_request",
                f"'refresh_token' is required when grant_type={jafaal_internal_dependencies.REFRESH_TOKEN_GRANT!r}.",
            )
        return await _grant_refresh_token(
            response,
            request,
            background_tasks,
            refresh,
            token_manager,
            db,
            x_csrf_token,
        )

    raise jafaal_exceptions.UnsupportedGrantTypeError(
        f"This token endpoint implements {authorization_code_service.GRANT_AUTHORIZATION_CODE!r} and "
        f"{jafaal_internal_dependencies.REFRESH_TOKEN_GRANT!r} (got {grant_type!r})."
    )


def _grant_authorization_code(
    *,
    response: Response,
    request: Request,
    code: str | None,
    code_verifier: str | None,
    redirect_uri: str | None,
    client_id: str | None,
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
) -> dict:
    """Redeem an authorization code for a token bundle (RFC 6749 §4.1.3).

    Args:
        response: HTTP response, used to set the web refresh cookie.
        request: The incoming HTTP request.
        code: The authorization code.
        code_verifier: The PKCE verifier.
        redirect_uri: The redirect URI from the authorization request.
        client_id: The redeeming client.
        token_manager: Utility for minting tokens.
        db: Database session.

    Returns:
        The token-response body.

    Raises:
        OAuthError: ``invalid_request`` if a required parameter is missing,
            ``invalid_grant`` if the code does not verify or was already
            redeemed.
    """
    missing = [
        name
        for name, value in (
            ("code", code),
            ("code_verifier", code_verifier),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
        )
        if not value
    ]
    if missing:
        raise jafaal_exceptions.OAuthError(
            "invalid_request",
            f"{', '.join(missing)} required when grant_type={authorization_code_service.GRANT_AUTHORIZATION_CODE!r}.",
        )
    # Narrowed by the check above; restated for the type checker.
    assert code and code_verifier and redirect_uri and client_id  # noqa: S101

    client = authorization_code_service.resolve_client(client_id)
    if client.uses_cookie_delivery:
        network.reject_off_site_request(request, operation="Token exchange")

    session_obj, oauth_state = authorization_code_service.resolve_authorization_code(code, client_id, redirect_uri, db)

    body = authorization_code_service.complete_pkce_exchange(
        session_obj=session_obj,
        oauth_state=oauth_state,
        code_verifier=code_verifier,
        client=client,
        response=response,
        token_manager=token_manager,
        db=db,
    )
    jafaal_audit.record(
        jafaal_audit.Event.AUTHORIZATION_CODE_REDEEMED,
        user_id=session_obj.user_id,
        session_id=session_obj.id,
        client_id=client_id,
        ip=network.get_ip_address(request),
    )
    return body


@router.post(
    "/refresh",
    response_model=(jafaal_schema.TokenResponseWeb | jafaal_schema.TokenResponseMobile),
    summary="Refresh-token alias of the token endpoint",
    description=(
        "Serves `grant_type=refresh_token` plus JAFAAL's native request shape: the `HttpOnly` refresh "
        "cookie or an `Authorization` header. Standards-based clients should use `/auth/token`."
    ),
)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
async def refresh_token(
    response: Response,
    request: Request,
    background_tasks: BackgroundTasks,
    refresh: Annotated[
        jafaal_internal_dependencies.ValidatedRefreshToken,
        Depends(jafaal_internal_dependencies.get_validated_refresh_token),
    ],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[
        Session,
        Depends(jafaal_orm.get_db),
    ],
    x_csrf_token: Annotated[str | None, Depends(jafaal_internal_dependencies.header_csrf_token_scheme)] = None,
):
    """Rotate a refresh token using JAFAAL's native or the RFC 6749 §6 shape.

    Args:
        response: The HTTP response object.
        request: The HTTP request object.
        background_tasks: Used to defer the opportunistic IdP token refresh.
        refresh: The validated refresh token, its claims, and its client.
        token_manager: Utility for creating tokens.
        db: Database session.
        x_csrf_token: CSRF token header (cookie clients only, optional on page reload).

    Returns:
        The RFC 6749 §5.1 token response.

    Raises:
        JafaalError: If the session or refresh token is invalid.
    """
    return await _grant_refresh_token(
        response,
        request,
        background_tasks,
        refresh,
        token_manager,
        db,
        x_csrf_token,
    )


@router.post("/logout", response_model=jafaal_schema.LogoutResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
async def logout(
    response: Response,
    request: Request,
    refresh: Annotated[
        jafaal_internal_dependencies.ValidatedRefreshToken,
        Depends(jafaal_internal_dependencies.get_validated_refresh_token),
    ],
    db: Annotated[
        Session,
        Depends(jafaal_orm.get_db),
    ],
):
    """
    Log out a user by validating and deleting their session.

    Args:
        response: The HTTP response object to modify cookies.
        request: The HTTP request object.
        refresh: The validated refresh token, its claims, and its client.
        db: Database session for CRUD operations.

    Returns:
        dict: A message indicating successful logout.

    Raises:
        JafaalError: If refresh token is invalid (401 Unauthorized).
    """
    token_user_id = refresh.user_id
    refresh_token_value = refresh.token
    client = refresh.client

    # Get the session from the database
    session = jafaal_sessions_crud.get_session_by_id_not_expired(refresh.session_id, db)

    # Check if the session was found
    if session is not None:
        # Verify session has a refresh token (not pending code redemption)
        if not session.refresh_token:
            raise jafaal_exceptions.InvalidTokenError("Tokens not yet exchanged. Cannot log out an incomplete session.")

        # Verify the refresh token
        is_valid = jafaal_sessions_utils.verify_refresh_token(refresh_token_value, session.refresh_token)

        # If the refresh token is not valid, raise an exception
        if not is_valid:
            raise jafaal_exceptions.InvalidTokenError("Invalid refresh token")

        # Delete the session from the database
        jafaal_sessions_crud.delete_session(session.id, token_user_id, db)

        # Clear all IdP refresh tokens for security
        await idp_utils.clear_all_idp_tokens(token_user_id, db)

        jafaal_audit.record(
            jafaal_audit.Event.LOGOUT,
            user_id=token_user_id,
            session_id=session.id,
            client_id=client.client_id,
            ip=network.get_ip_address(request),
        )

    if client.uses_cookie_delivery:
        jafaal_utils.clear_refresh_token_cookies(response)
    return {"message": "Logout successful"}


@router.post("/introspect", response_model=jafaal_schema.TokenIntrospectionResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
def introspect_token_endpoint(
    response: Response,
    _scopes: Annotated[
        None,
        Security(jafaal_dependencies.check_auth_scopes, scopes=[jafaal_scopes.AUTH_INTROSPECT]),
    ],
    token: Annotated[str, Form()],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    token_type_hint: Annotated[str | None, Form()] = None,
):
    """Introspect a JAFAAL token (RFC 7662).

    Protected: the caller must present a credential (JWT or API key) carrying the
    ``auth:introspect`` scope — grant it to a resource-server API key via
    ``jafaal.configure_api_key_scopes([..., jafaal.scopes.AUTH_INTROSPECT])``.

    Args:
        response: The HTTP response object, marked ``no-store``.
        token: The token to introspect (form field).
        token_type_hint: Optional RFC 7662 hint; ignored (the token's
            ``token_use`` claim is authoritative).

    Returns:
        The RFC 7662 introspection response.
    """
    # RFC 7662 §4: the response describes a live credential (its subject, scope,
    # and remaining validity), so it must not be cached by an intermediary any
    # more than the token itself would be.
    jafaal_utils.apply_no_store(response)
    return token_admin_service.introspect_token(token, token_manager, db)


@router.post("/revoke", response_model=None, status_code=status.HTTP_200_OK)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
def revoke_token_endpoint(
    response: Response,
    token: Annotated[str, Form()],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    client_id: Annotated[str | None, Form(description="The registered client the token was issued to.")] = None,
    token_type_hint: Annotated[str | None, Form()] = None,
) -> dict:
    """Revoke a JAFAAL token (RFC 7009).

    ``client_id`` is required and the token must have been issued to it. RFC 7009
    §2.1 has a public client identify itself and §5 has the server verify the
    token was its own; without both, possession of a leaked token is a
    force-logout primitive against the account it belongs to. A token issued to
    another client is treated as unknown — a silent 200 — so the endpoint does
    not answer "whose token is this?".

    A refresh token deletes its session (and, with ``tokens.denylist_enabled``,
    denylists the session id so its access tokens die with it). An access token
    is denylisted by ``jti`` under the same setting. Always returns 200, even for
    an unknown token.

    Args:
        response: The HTTP response object, marked ``no-store``.
        token: The token to revoke (form field).
        client_id: The registered client presenting the request (form field).
        token_type_hint: Optional RFC 7009 hint; ignored (the token's
            ``token_use`` claim is authoritative).

    Returns:
        An empty object (RFC 7009 mandates a 200 with no error).

    Raises:
        InvalidClientError: If ``client_id`` is absent or unregistered. That is a
            malformed *request*, not an unrecognised token, so §2.2's "answer 200
            for an invalid token" does not apply.
    """
    # The request body carried a live credential; a cached response keyed on it
    # is a cached credential. RFC 7009 §2.1 inherits RFC 6749 §5.1's no-store.
    jafaal_utils.apply_no_store(response)
    if not client_id:
        raise jafaal_exceptions.InvalidClientError(
            "client_id is required. Send the id of the registered client the token was issued to."
        )
    client = authorization_code_service.resolve_client(client_id)
    token_admin_service.revoke_token(token, client.client_id, token_manager, db)
    return {}
