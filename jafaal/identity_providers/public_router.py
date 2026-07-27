"""Public (unauthenticated) HTTP routes for identity provider SSO flows."""

import logging
from typing import Annotated, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from fastapi import Depends, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

import jafaal._internal.password_hasher as jafaal_password_hasher
import jafaal._internal.services.authorization_code_service as authorization_code_service
import jafaal._internal.token_manager as jafaal_token_manager
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.audit as jafaal_audit
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.schema as idp_schema
import jafaal.identity_providers.service as idp_service
import jafaal.identity_providers.utils as idp_utils
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.models as oauth_state_models
import jafaal.orm as jafaal_orm
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.utils as jafaal_sessions_utils
import jafaal.settings as jafaal_settings
from jafaal._core import network

logger = logging.getLogger(__name__)

# Define the API router
router = jafaal_orm.auth_router()


def _append_query_params(url: str, params: dict[str, str]) -> str:
    """Append query parameters to a URL or relative path, preserving any existing query."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _audit_state_ip_mismatch(
    oauth_state: oauth_state_models.OAuthState,
    idp_slug: str,
    request: Request,
) -> None:
    """Audit a callback arriving from a different IP than the one that started it.

    The client IP recorded when the authorization request was minted is a
    *detection* signal, not an access control: the browser leg of an SSO round
    trip legitimately changes address (mobile hand-off between cellular and
    Wi-Fi, IPv6 privacy-address rotation, a CDN or corporate proxy picking a
    different egress). Rejecting on mismatch would lock out real users far more
    often than it would stop an attacker — who is already blocked by the state's
    single-use claim, the OIDC ``nonce``, and the upstream PKCE binding.

    So the mismatch is recorded on the audit stream instead, where a SIEM can
    correlate it with the other signals (a state minted in one country and
    redeemed in another within seconds is worth an alert; a phone changing
    networks is not).

    Args:
        oauth_state: The state row being consumed.
        idp_slug: Provider slug, for the audit record.
        request: The incoming callback request.
    """
    recorded_ip = oauth_state.ip_address
    if not recorded_ip:
        return
    callback_ip = network.get_ip_address(request)
    if callback_ip is None or callback_ip == recorded_ip:
        return
    logger.info(f"OAuth callback source IP differs from the address that initiated the flow (idp={idp_slug})")
    jafaal_audit.record(
        jafaal_audit.Event.OAUTH_STATE_IP_MISMATCH,
        outcome=jafaal_audit.Outcome.SUCCESS,
        level=logging.INFO,
        idp=idp_slug,
        ip=callback_ip,
        initiated_ip=recorded_ip,
        purpose=oauth_state.purpose,
    )


def _build_link_result_url(redirect_path: str | None, idp_name: str | None, *, success: bool) -> str:
    """Build the post-link redirect that carries the result to the originating client.

    Honors a caller-supplied return path captured at link initiation (validated
    there against open redirects): a relative path is resolved against the
    configured frontend host, while a custom URI scheme is handed off directly to
    the native client. Falls back to the security settings path when no return
    path was provided.

    Args:
        redirect_path: The validated return path or custom scheme, or None.
        idp_name: Provider display name (included on success).
        success: Whether the link succeeded.

    Returns:
        The absolute URL (or custom-scheme URL) to redirect the browser to.
    """
    params = {"idp_link": "success" if success else "error"}
    if success and idp_name is not None:
        params["idp_name"] = idp_name
    if redirect_path and idp_utils.is_custom_scheme_redirect(redirect_path):
        return _append_query_params(redirect_path, params)
    settings = jafaal_settings.get_settings()
    base = redirect_path or settings.sso.link_result_path
    return f"{settings.base_url}{_append_query_params(base, params)}"


@router.get(
    "",
    response_model=list[idp_schema.IdentityProviderPublic],
    status_code=status.HTTP_200_OK,
)
def get_enabled_identity_providers(db: Annotated[Session, Depends(jafaal_orm.get_db)]):
    """
    Retrieve a list of enabled identity providers from the database.

    Args:
        db (Session): SQLAlchemy database session dependency.

    Returns:
        List[IdentityProviderPublic]: A list of enabled identity providers, each represented as an IdentityProviderPublic schema.
    """
    providers = idp_crud.get_enabled_identity_providers(db)
    return [
        idp_schema.IdentityProviderPublic(
            id=p.id,
            name=p.name,
            slug=p.slug,
            icon=p.icon,
        )
        for p in providers
    ]


@router.get("/login/{idp_slug}", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def initiate_login(
    idp_slug: str,
    request: Request,
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    code_challenge: Annotated[
        str,
        Query(
            description="PKCE code challenge (base64url-encoded SHA256, 43-128 chars). REQUIRED (RFC 7636).",
        ),
    ],
    code_challenge_method: Annotated[
        str,
        Query(
            description="PKCE method (must be S256). REQUIRED (RFC 7636).",
        ),
    ],
    redirect: Annotated[
        str | None,
        Query(
            alias="redirect",
            description="Frontend redirect path after successful login",
        ),
    ] = None,
):
    """
    Initiates the login process for a given identity provider using OAuth.

    PKCE (Proof Key for Code Exchange, RFC 7636) is REQUIRED for all clients.
    Both code_challenge and code_challenge_method=S256 must be provided.

    Rate Limit: 10 requests per minute per IP
    Args:
        idp_slug (str): The slug identifier for the identity provider.
        request (Request): The incoming HTTP request object.
        db (Session): Database session dependency.
        redirect (str | None): Optional frontend path to redirect to after login.
        code_challenge (str): PKCE code challenge (base64url-encoded SHA256, 43-128 chars). REQUIRED.
        code_challenge_method (str): PKCE method (only S256 supported). REQUIRED.

    Returns:
        RedirectResponse: A redirect response to the identity provider's authorization URL.

    Raises:
        JafaalError: If the identity provider is not found, disabled, or PKCE validation fails.
    """
    try:
        # Validate redirect URL to prevent open redirect vulnerability
        idp_utils.validate_redirect_url(redirect)

        # Preserve mobile intent for custom-scheme redirects.
        # The browser step of the flow cannot reliably carry X-Client-Type,
        # so the validated redirect target is the authoritative signal for
        # mobile handoff flows such as Gadgetbridge.
        if idp_utils.is_custom_scheme_redirect(redirect):
            client_type = "mobile"
        else:
            client_type = request.headers.get("X-Client-Type", "web")
            if client_type not in ["web", "mobile"]:
                client_type = "web"  # Default to web if invalid

        authorization_url = await idp_utils.begin_idp_authorization(
            idp_slug=idp_slug,
            request=request,
            db=db,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            client_type=client_type,
            redirect_path=redirect,
        )

        return RedirectResponse(url=authorization_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    except jafaal_exceptions.JafaalError:
        raise
    except Exception as err:
        logger.error(f"Error in initiate_login: {err}", exc_info=err)
        raise jafaal_exceptions.InternalError("Failed to initiate login") from err


@router.get("/callback/{idp_slug}", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def handle_callback(
    request: Request,
    response: Response,
    idp_slug: str,
    password_hasher: Annotated[
        jafaal_password_hasher.PasswordHasher,
        Depends(jafaal_password_hasher.get_password_hasher),
    ],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    code: str = Query(..., description="Authorization code from IdP"),
    state: str = Query(..., description="State parameter for CSRF protection"),
):
    """
    Handle OAuth callback from an identity provider.

    This endpoint processes the OAuth authorization callback from external identity providers.
    It supports two modes: login mode (default) and link mode (for linking IdP to existing account).
    Args:
        idp_slug (str): The slug identifier of the identity provider.
        password_hasher (jafaal_password_hasher.PasswordHasher): Password hasher dependency for session management.
        token_manager (jafaal_token_manager.TokenManager): Token manager dependency for creating session tokens.
        db (Session): Database session dependency.
        code (str): Authorization code received from the identity provider.
        state (str): State parameter used for CSRF protection (database state ID).
        request (Request): The incoming HTTP request.

    Returns:
        RedirectResponse: A redirect response to either:
            - Settings page (link mode): /settings with success parameters
            - Login page (login mode): /login with session_id for token exchange
            - Error page: /login with error parameter if callback fails

    Raises:
        JafaalError: If the identity provider is not found, disabled, or if callback processing fails.

    Notes:
        - In link mode: Redirects to settings without creating a new session
        - In login mode: Creates session, redirects with session_id (client must exchange for tokens)
        - All clients must call /tokens exchange endpoint with PKCE verifier to get JWT tokens
        - On error: Redirects to login page with error parameter
        - All redirects use HTTP 307 (Temporary Redirect) status code
    """
    oauth_state = None
    try:
        # Get the identity provider
        idp = idp_crud.get_identity_provider_by_slug(idp_slug, db)
        if not idp or not idp.enabled:
            raise jafaal_exceptions.NotFoundError("Identity provider not found or disabled")

        # Lookup OAuth state from database (mandatory for all clients)
        oauth_state = oauth_state_crud.get_oauth_state_by_id_and_not_used(state, db)

        if not oauth_state:
            logger.warning(f"OAuth state not found in database: {state[:8]}...")
            raise jafaal_exceptions.InvalidRequestError("Invalid or expired OAuth state")

        # Bind the OAuth state to the IdP named in the callback URL.
        # The `idp` is resolved from the URL slug while the `oauth_state`
        # is looked up by the opaque `state` parameter; without this check
        # a state minted during one provider's login could be replayed
        # against a different provider's callback. Cross-provider misuse is
        # already blocked cryptographically (the code is exchanged at the
        # URL-IdP's token endpoint and the ID token is verified against that
        # IdP's JWKS), but asserting the binding here fails fast and protects
        # deployments where two IdP entries share an authorization server.
        if oauth_state.idp_id is not None and oauth_state.idp_id != idp.id:
            logger.warning(
                f"OAuth state IdP mismatch for state {state[:8]}...: "
                f"state.idp_id={oauth_state.idp_id}, callback idp.id={idp.id}"
            )
            raise jafaal_exceptions.InvalidRequestError("Invalid or expired OAuth state")

        _audit_state_ip_mismatch(oauth_state, idp.slug, request)

        # Mark state as used atomically (prevents replay attacks).
        # Two concurrent callbacks can both reach this point with the same
        # `oauth_state` row in memory; only the caller whose conditional UPDATE
        # actually flips `used=False -> True` is allowed to continue. Losing
        # races (replays, double-submits) abort here with a generic 400 so we
        # do not leak whether the state existed but was already consumed.
        #
        # Claimed on its own session so the claim commits immediately, for two
        # reasons. It must be durable independently of the rest of this request:
        # otherwise an attacker who can make the callback fail after this point
        # would release the state and be free to replay the authorization code.
        # And the request transaction must not stay open across the several
        # outbound HTTP calls handle_callback then makes (discovery, token
        # exchange, JWKS, userinfo), which would pin a pooled connection — and
        # this row's lock — for their combined timeout.
        with jafaal_orm.autonomous_session() as claim_db:
            claimed = oauth_state_crud.mark_oauth_state_used(state, claim_db)
        if not claimed:
            logger.warning(f"OAuth state replay/race rejected: {state[:8]}...")
            jafaal_audit.record(
                jafaal_audit.Event.OAUTH_STATE_REPLAY_REJECTED,
                outcome=jafaal_audit.Outcome.BLOCKED,
                level=logging.WARNING,
                idp=idp.slug,
                ip=network.get_ip_address(request),
            )
            raise jafaal_exceptions.InvalidRequestError("Invalid or expired OAuth state")

        logger.debug(f"OAuth callback received for state {state[:8]}... (client_type={oauth_state.client_type})")

        # Process the OAuth callback (service will handle both DB and cookie state)
        result = await idp_service.idp_service.handle_callback(
            idp, code, state, request, password_hasher, db, oauth_state
        )

        user = result["user"]
        is_link_mode = result.get("mode") == "link"

        # STEP-UP RE-AUTH MODE: the single-use grant was already minted inside
        # handle_callback after verifying the fresh IdP sign-in. Return the
        # browser to the app's security page with a success flag; the client
        # then retries the sensitive operation, which consumes the grant.
        if result.get("mode") == "stepup":
            settings = jafaal_settings.get_settings()
            redirect_url = (
                f"{settings.base_url}{_append_query_params(settings.sso.link_result_path, {'step_up': 'success'})}"
            )
            logger.info(f"IdP step-up re-authentication successful for user {user.username} via {idp.name}")
            return RedirectResponse(
                url=redirect_url,
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )

        # Handle link mode differently - redirect to the originating page (the
        # caller's validated return path) without creating a new session.
        if is_link_mode:
            redirect_url = _build_link_result_url(oauth_state.redirect_path, idp.name, success=True)

            logger.info(f"IdP link successful for user {user.username}, IdP {idp.name}")

            return RedirectResponse(
                url=redirect_url,
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )

        # LOGIN MODE: Create session WITHOUT tokens (tokens created during exchange)
        # Validate that the user is active before creating a session
        jafaal_user_guards.check_user_is_active(user)

        # Generate session ID
        session_id = str(uuid4())

        # Create the session and store it in the database
        if not oauth_state:
            raise jafaal_exceptions.InternalError("OAuth state required for token exchange")

        jafaal_sessions_utils.create_session(
            session_id,
            user,
            request,
            None,
            db,
            oauth_state_id=oauth_state.id,
        )

        # Redirect to frontend with session_id for token exchange.
        #
        # Every value goes through _append_query_params (which percent-encodes),
        # never string concatenation: ``redirect_path`` is caller-supplied and
        # only validated as "a relative path with no traversal", so a value like
        # ``/dashboard&session_id=<attacker>`` would otherwise inject extra
        # parameters into the URL the frontend parses.
        settings = jafaal_settings.get_settings()

        # A flow started at /auth/authorize by a registered client gets the
        # standard RFC 6749 §4.1.2 response instead: an authorization code and
        # the client's own ``state``, delivered to the exact redirect_uri the
        # client registered. This is what lets a stock OAuth library (AppAuth,
        # openid-client, MSAL) drive JAFAAL without bespoke code.
        if oauth_state.client_id and oauth_state.redirect_uri:
            authorization_code = authorization_code_service.issue_authorization_code(oauth_state.id, db)
            params = {"code": authorization_code}
            if oauth_state.client_state:
                params["state"] = oauth_state.client_state
            logger.info(
                f"SSO login successful for user {user.username} via {idp.name} (client_id={oauth_state.client_id})"
            )
            return RedirectResponse(
                url=_append_query_params(oauth_state.redirect_uri, params),
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )

        params = {"sso": "success", "session_id": session_id}

        redirect_path = result.get("redirect_path")
        if redirect_path:
            params["redirect"] = redirect_path
            # Signal the frontend that this is a custom-scheme redirect.
            # The frontend will skip its own token exchange and instead
            # pass the session_id to the mobile app via the custom scheme.
            if idp_utils.is_custom_scheme_redirect(redirect_path):
                params["external_redirect"] = "true"

        redirect_url = f"{settings.base_url}{_append_query_params(settings.sso.login_result_path, params)}"

        logger.info(f"SSO login successful for user {user.username} via {idp.name} (session_id={session_id})")

        return RedirectResponse(
            url=redirect_url,
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        )

    except jafaal_exceptions.JafaalError:
        raise
    except Exception as err:
        logger.error(f"Error in SSO callback: {err}", exc_info=err)

        # A failed LINK returns the browser to its originating page with an error
        # flag; a failed LOGIN falls back to the login page. Link attempts are
        # identified by the user_id stored on the OAuth state at initiation.
        if oauth_state is not None and oauth_state.client_id and oauth_state.redirect_uri:
            # RFC 6749 §4.1.2.1: a failure *after* the redirect_uri has been
            # validated is reported back to the client at that URI. Without this
            # a native app sits on its callback listener until it times out,
            # with no way to tell a denial from a crash.
            error_params = {"error": "server_error"}
            if oauth_state.client_state:
                error_params["state"] = oauth_state.client_state
            error_url = _append_query_params(oauth_state.redirect_uri, error_params)
        elif oauth_state is not None and oauth_state.user_id is not None:
            error_url = _build_link_result_url(oauth_state.redirect_path, None, success=False)
        else:
            settings = jafaal_settings.get_settings()
            error_url = f"{settings.base_url}{_append_query_params(settings.sso.error_path, {'error': 'sso_failed'})}"

        return RedirectResponse(url=error_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.post(
    "/session/{session_id}/tokens",
    response_model=idp_schema.TokenExchangeResponse,
    status_code=status.HTTP_200_OK,
)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def exchange_tokens_for_session(
    session_id: str,
    request: Request,
    response: Response,
    token_exchange: idp_schema.TokenExchangeRequest,
    password_hasher: Annotated[
        jafaal_password_hasher.PasswordHasher,
        Depends(jafaal_password_hasher.get_password_hasher),
    ],
    token_manager: Annotated[
        jafaal_token_manager.TokenManager,
        Depends(jafaal_token_manager.get_token_manager),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
):
    """
    Exchange a PKCE code verifier for JWT tokens.

    After OAuth callback or password PKCE login creates a session, clients
    call this endpoint to prove they possess the code_verifier (PKCE) and
    receive the actual JWT tokens. This prevents token leakage through
    browser redirects and ensures only the legitimate client can access the
    tokens.

    Security Features:
    - PKCE verification (SHA256 hash of verifier must match challenge)
    - One-time exchange (tokens_exchanged flag prevents replay)
    - Rate limited (10 requests/minute)
    - Session must be linked to OAuth state with PKCE data

    Rate Limit: 10 requests per minute per IP

    Args:
        session_id (str): Session ID from OAuth callback redirect.
        request (Request): FastAPI request object (for rate limiting).
        response (Response): FastAPI response object.
        token_exchange (TokenExchangeRequest): Request body with code_verifier.
        token_manager (TokenManager): Token manager dependency.
        db (Session): Database session dependency.

    Returns:
        TokenExchangeResponse: JWT tokens (access, refresh, csrf) and metadata.

    Raises:
        JafaalError:
            - 404 NOT_FOUND: Session not found or not linked to OAuth state
            - 400 BAD_REQUEST: Invalid code_verifier or tokens already exchanged
            - 409 CONFLICT: Tokens already exchanged for this session
    """
    try:
        # Retrieve session with OAuth state relationship
        session_with_state = jafaal_sessions_crud.get_session_with_oauth_state(session_id, db)

        if not session_with_state:
            logger.warning(f"Token exchange failed: session {session_id[:8]}... not found")
            raise jafaal_exceptions.NotFoundError("Session not found or not eligible for token exchange")

        session_obj, oauth_state = session_with_state

        # Verify session is linked to an OAuth state (mobile flow)
        if not oauth_state:
            logger.warning(f"Token exchange failed: session {session_id[:8]}... has no OAuth state")
            raise jafaal_exceptions.NotFoundError("Session not eligible for PKCE token exchange")

        # A flow started at /auth/authorize is redeemed at /auth/token with its
        # authorization code, not here. Accepting the session id as well would
        # give that flow a second, weaker redemption path — one that skips the
        # client_id and redirect_uri bindings entirely.
        if oauth_state.client_id:
            logger.warning(f"Session {session_id[:8]}... belongs to an authorization-code flow")
            raise jafaal_exceptions.InvalidRequestError(
                "This session was created by /auth/authorize; redeem its authorization code at "
                "/auth/token with grant_type=authorization_code."
            )

        # Fast-path informational check; the authoritative protection is the
        # atomic conditional UPDATE inside complete_pkce_exchange, which closes
        # the TOCTOU race two concurrent exchanges would otherwise win.
        if session_obj.tokens_exchanged:
            logger.warning(f"Token exchange replay attempt for session {session_id[:8]}...")
            raise jafaal_exceptions.ConflictError("Tokens already exchanged for this session")

        # Resolved before minting tokens or claiming the one-shot session, so a
        # mismatched X-Client-Type cannot burn an otherwise valid PKCE session
        # by flipping tokens_exchanged first.
        client_type = authorization_code_service.resolve_client_type(oauth_state, request.headers.get("X-Client-Type"))

        # A web exchange plants an HttpOnly refresh cookie, so it carries the
        # same off-site rejection as /auth/login and /auth/refresh. Checked only
        # after the client type is resolved, so a native caller (which sends no
        # browser fetch metadata) is unaffected.
        if client_type == "web":
            network.reject_off_site_request(request, operation="Token exchange")

        body = authorization_code_service.complete_pkce_exchange(
            session_obj=session_obj,
            oauth_state=oauth_state,
            code_verifier=token_exchange.code_verifier,
            client_type=client_type,
            response=response,
            token_manager=token_manager,
            db=db,
        )

        logger.info(f"Token exchange successful for session {session_id[:8]}... (client_type={client_type})")

        return idp_schema.TokenExchangeResponse(
            session_id=session_id,
            access_token=cast(str, body["access_token"]),
            refresh_token=cast("str | None", body.get("refresh_token")),
            csrf_token=cast("str | None", body.get("csrf_token")),
            expires_in=cast(int, body["expires_in"]),
            refresh_token_expires_in=cast(int, body["refresh_token_expires_in"]),
            token_type="Bearer",
        )

    except jafaal_exceptions.JafaalError:
        raise
    except Exception as err:
        logger.error(f"Error in token exchange for session {session_id[:8]}...: {err}", exc_info=err)
        raise jafaal_exceptions.InternalError("Failed to exchange tokens") from err
