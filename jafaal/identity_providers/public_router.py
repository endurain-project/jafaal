"""Public (unauthenticated) HTTP routes for identity provider SSO flows.

There is exactly one way into an SSO login: ``GET /auth/authorize``, the RFC 6749
§4.1 authorization endpoint. This module owns the *other* half of that round
trip — the provider's callback — plus the read-only list of enabled providers.

Every browser redirect this module emits targets a ``redirect_uri`` that was
validated against a registered :class:`~jafaal.settings.OAuthClient` before the
flow started. There is no configured "frontend path" fallback: HTTPS and
private-use targets are exact, and only an IP-loopback port may vary.
"""

import hmac
import logging
from typing import Annotated
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from fastapi import Depends, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

import jafaal._internal.password_hasher as jafaal_password_hasher
import jafaal._internal.services.authorization_code_service as authorization_code_service
import jafaal._internal.token_manager as jafaal_token_manager
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.audit as jafaal_audit
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.models as idp_models
import jafaal.identity_providers.schema as idp_schema
import jafaal.identity_providers.service as idp_service
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.models as oauth_state_models
import jafaal.orm as jafaal_orm
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.sessions.utils as jafaal_sessions_utils
import jafaal.settings as jafaal_settings
from jafaal._core import network

logger = logging.getLogger(__name__)

# Define the API router
router = jafaal_orm.auth_router()

#: Authorization-response error codes forwarded to JAFAAL's own client unchanged
#: — RFC 6749 §4.1.2.1 plus the OIDC Core 1.0 §3.1.2.6 additions. Between them
#: they cover every reason a provider legitimately refuses.
#:
#: A code outside the set is provider-specific (or simply attacker-supplied: the
#: callback is a public endpoint, so the query string is not trustworthy until a
#: state has been resolved and claimed). It is logged and reported as
#: ``access_denied``, so the error response JAFAAL emits stays inside the
#: registry its own clients parse against.
_PASSTHROUGH_AUTHORIZATION_ERRORS: frozenset[str] = frozenset(
    {
        # RFC 6749 §4.1.2.1
        "invalid_request",
        "unauthorized_client",
        "access_denied",
        "unsupported_response_type",
        "invalid_scope",
        "server_error",
        "temporarily_unavailable",
        # OIDC Core 1.0 §3.1.2.6
        "interaction_required",
        "login_required",
        "account_selection_required",
        "consent_required",
        "invalid_request_uri",
        "invalid_request_object",
        "request_not_supported",
        "request_uri_not_supported",
        "registration_not_supported",
    }
)

#: Longest ``error_description`` forwarded to the client. The provider (or, before
#: the state is claimed, whoever hit the endpoint) controls this string and a
#: redirect URL is a bounded resource, so it is truncated rather than trusted.
_MAX_ERROR_DESCRIPTION_CHARS = 200


def _append_query_params(url: str, params: dict[str, str]) -> str:
    """Append query parameters to a URL or relative path, preserving any existing query."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _provider_error_params(error: str, error_description: str | None) -> dict[str, str]:
    """Translate a provider's authorization error into JAFAAL's own error response.

    JAFAAL is the authorization server its client is talking to, so what goes
    back to that client must be JAFAAL's error — not a verbatim proxy of the
    upstream's. Unrecognised codes collapse to ``access_denied`` and the
    description is bounded.

    ``error_uri`` is deliberately **not** forwarded. RFC 6749 §4.1.2.1 governs
    the error *this* server returns, and nothing obliges it to hand its clients
    a provider-supplied URL that a UI would render as a "more information" link.
    It is logged instead, where an operator can follow it.

    Args:
        error: The ``error`` parameter as received.
        error_description: The ``error_description`` parameter as received.

    Returns:
        The error parameters to deliver to the client's redirect URI.
    """
    code = error if error in _PASSTHROUGH_AUTHORIZATION_ERRORS else "access_denied"
    if code != error:
        logger.info(f"Identity provider returned unregistered authorization error {error!r}; reporting access_denied")
    params = {"error": code}
    description = (error_description or "").strip()
    if description:
        params["error_description"] = description[:_MAX_ERROR_DESCRIPTION_CHARS]
    return params


def _reject_issuer_mismatch(
    idp: idp_models.IdentityProvider,
    response_iss: str | None,
) -> None:
    """Assert an RFC 9207 ``iss`` in the callback names the provider we asked.

    RFC 9207 has the authorization server put its issuer identifier in the
    authorization *response*, so a client cannot be tricked into redeeming a code
    at a server other than the one that issued it (the mix-up attack). JAFAAL is
    already well defended here — the callback path names the provider, the state
    is bound to ``idp_id``, and the ID token's ``iss`` is pinned to the
    discovered issuer — but those checks all happen *after* the code has been
    sent to a token endpoint. This one runs before, which is the point of the
    parameter.

    Only enforced when the provider actually sends it: RFC 9207 is an extension
    and a provider that predates it omits the parameter entirely. A provider
    that sends a *wrong* one is a different matter, and is refused.

    Args:
        idp: The provider named by the callback path.
        response_iss: The ``iss`` authorization-response parameter, if present.

    Raises:
        InvalidRequestError: If ``iss`` is present and does not match the
            provider's configured issuer.
    """
    if not response_iss:
        return
    configured = (idp.issuer_url or "").rstrip("/")
    if not configured:
        # A provider configured by explicit endpoints rather than discovery has
        # no issuer to compare against; there is nothing to check.
        return
    if not hmac.compare_digest(configured, response_iss.rstrip("/")):
        logger.warning(f"Authorization response for {idp.slug} carried iss={response_iss!r}, expected {configured!r}")
        jafaal_audit.record(
            jafaal_audit.Event.OAUTH_ISSUER_MISMATCH,
            outcome=jafaal_audit.Outcome.BLOCKED,
            level=logging.WARNING,
            idp=idp.slug,
            expected_issuer=configured,
            response_issuer=response_iss,
        )
        raise jafaal_exceptions.InvalidRequestError("The authorization response came from an unexpected issuer.")


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


def _resolve_callback_target(
    idp_slug: str,
    state: str,
    iss: str | None,
    db: Session,
) -> tuple[idp_models.IdentityProvider, oauth_state_models.OAuthState]:
    """Resolve the provider and the unused OAuth state a callback names.

    Everything here fails *before* there is a validated redirect target, so its
    errors are rendered rather than redirected.

    Args:
        idp_slug: Provider slug from the callback URL.
        state: The opaque state parameter.
        iss: The provider's ``iss`` parameter, if it sent one.
        db: Active database session.

    Returns:
        The provider and its OAuth state.

    Raises:
        NotFoundError: If the provider is unknown or disabled.
        InvalidRequestError: If the issuer does not match, or the state is
            unknown, expired, or already used.
    """
    idp = idp_crud.get_identity_provider_by_slug(idp_slug, db)
    if not idp or not idp.enabled:
        raise jafaal_exceptions.NotFoundError("Identity provider not found or disabled")

    # RFC 9207 mix-up defence, checked before the code is sent anywhere.
    _reject_issuer_mismatch(idp, iss)

    oauth_state = oauth_state_crud.get_oauth_state_by_id_and_not_used(state, db)
    if not oauth_state:
        logger.warning(f"OAuth state not found in database: {state[:8]}...")
        raise jafaal_exceptions.InvalidRequestError("Invalid or expired OAuth state")

    return idp, oauth_state


def _claim_callback_state(
    idp: idp_models.IdentityProvider,
    oauth_state: oauth_state_models.OAuthState,
    state: str,
    request: Request,
) -> None:
    """Bind the state to this provider and claim it, single-use.

    Args:
        idp: The provider named by the callback URL.
        oauth_state: The state resolved from the ``state`` parameter.
        state: The raw state parameter, for the conditional update.
        request: The incoming request, for source-IP auditing.

    Raises:
        InvalidRequestError: If the state belongs to another provider, or was
            already consumed (replay or a lost race).
    """
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


def _return_to_client(oauth_state: oauth_state_models.OAuthState, params: dict[str, str]) -> RedirectResponse:
    """Redirect the browser back to the client that started the flow.

    ``oauth_state.redirect_uri`` was validated against the initiating client's
    registered list before the flow began, so it is safe to navigate to here.
    Values go through :func:`_append_query_params`, which percent-encodes,
    rather than string concatenation — otherwise a value could inject additional
    parameters into the URL the client parses.

    Every response carries ``iss`` (RFC 9207). A client configured against more
    than one authorization server otherwise has no way to tell which one
    answered, which is what makes the mix-up attack work: an attacker who can
    influence which server the flow started at gets a code issued by a server it
    controls accepted as if it came from this one. ``state`` does not close it —
    the honest server's own ``state`` is what is replayed.

    Args:
        oauth_state: The state row carrying the validated redirect target and the
            client's opaque ``state``.
        params: Result parameters to deliver.

    Returns:
        A 302 to the client's redirect URI.

    Raises:
        InternalError: If the state carries no redirect URI. Unreachable through
            the routes, which all validate one at initiation; asserted rather
            than defaulted so a future caller cannot introduce an unvalidated
            redirect by omission.
    """
    if not oauth_state.redirect_uri:
        raise jafaal_exceptions.InternalError("OAuth state has no validated redirect_uri")
    params = {**params, "iss": jafaal_settings.get_settings().resolved_issuer}
    if oauth_state.client_state:
        params = {**params, "state": oauth_state.client_state}
    return RedirectResponse(
        url=_append_query_params(oauth_state.redirect_uri, params),
        # 302: the browser is following a navigation and the method must not be
        # preserved.
        status_code=status.HTTP_302_FOUND,
    )


@router.get(
    "",
    response_model=list[idp_schema.IdentityProviderPublic],
    status_code=status.HTTP_200_OK,
)
def get_enabled_identity_providers(db: Annotated[Session, Depends(jafaal_orm.get_db)]):
    """Retrieve the enabled identity providers, for rendering a login picker.

    Args:
        db: SQLAlchemy database session dependency.

    Returns:
        The enabled providers, each as an ``IdentityProviderPublic``.
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


@router.get("/callback/{idp_slug}", status_code=status.HTTP_302_FOUND)
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
    code: str | None = Query(None, description="Authorization code from IdP; absent on an error response"),
    state: str = Query(..., description="State parameter for CSRF protection"),
    error: str | None = Query(None, description="RFC 6749 §4.1.2.1 error code, when the provider refused"),
    error_description: str | None = Query(None, description="Human-readable detail accompanying `error`"),
    error_uri: str | None = Query(None, description="Provider's error page; logged, never forwarded"),
    iss: str | None = Query(None, description="RFC 9207 issuer identifier; verified when the provider sends it"),
):
    """Handle the OAuth callback from an identity provider.

    Serves the return leg of three flows, distinguished by what the OAuth state
    records:

    * **login** — started at ``/auth/authorize``. Issues an RFC 6749 §4.1.2
      authorization code and delivers it, with the client's ``state``, to the
      registered ``redirect_uri``. The client redeems it at ``/auth/token``.
    * **link** — attaching a provider to an already-authenticated account.
    * **step-up** — proving a fresh sign-in for a sensitive operation; the grant
      is minted inside the service once the sign-in verifies.

    All three end in a redirect to the client's registered ``redirect_uri``,
    including failures — RFC 6749 §4.1.2.1, and the only way a native app waiting
    on its callback listener ever learns the flow failed.

    A refused authorization request arrives as ``error`` (plus ``state``) with no
    ``code``, so ``code`` is optional here: requiring it would turn every "the
    user pressed Deny" into a validation error, leave the state redeemable, and
    strand the waiting client — the exact outcome the redirect rule exists to
    prevent.

    Args:
        request: The incoming HTTP request.
        response: The HTTP response object.
        idp_slug: The slug identifier of the identity provider.
        password_hasher: Password hasher used during provisioning.
        token_manager: Token manager, used by the provisioning path.
        db: Database session.
        code: Authorization code received from the identity provider.
        state: The opaque state id minted at initiation.
        error: The provider's error code, when it refused the request.
        error_description: Human-readable detail accompanying ``error``.
        error_uri: The provider's error page; logged, never forwarded onward.
        iss: The RFC 9207 issuer identifier. Verified against the provider's
            configured issuer when present; providers predating the extension
            omit it.

    Returns:
        RedirectResponse: To the client's registered redirect URI.

    Raises:
        JafaalError: If the state cannot be resolved at all. There is then no
            validated redirect target to report the failure to, so it must be
            rendered instead.
    """
    oauth_state = None
    try:
        # Split in two so the error paths keep their reporting channel: nothing
        # resolved yet means there is no validated redirect target and the
        # failure must be rendered, whereas a failure after the state resolves
        # is reported *at* the client's redirect URI (RFC 6749 §4.1.2.1).
        # Both halves are pure database work and this endpoint must stay async
        # for the provider round trips below, so each runs in a worker thread.
        idp, oauth_state = await run_in_threadpool(_resolve_callback_target, idp_slug, state, iss, db)
        await run_in_threadpool(_claim_callback_state, idp, oauth_state, state, request)

        logger.debug(f"OAuth callback received for state {state[:8]}... (purpose={oauth_state.purpose})")

        # RFC 6749 §4.1.2.1: a refused authorization request comes back as
        # ``error`` (+ the ``state``) and no ``code``. It reaches this point
        # through exactly the same gauntlet as a success — state resolution, the
        # IdP binding, the single-use claim — because the authorization request
        # is finished either way and its state must not stay redeemable.
        if error:
            if error_uri:
                logger.info(f"Identity provider {idp.slug} error_uri: {error_uri}")
            jafaal_audit.record(
                jafaal_audit.Event.IDP_AUTHORIZATION_DENIED,
                outcome=jafaal_audit.Outcome.FAILURE,
                level=logging.WARNING,
                idp=idp.slug,
                ip=network.get_ip_address(request),
                purpose=oauth_state.purpose,
                error=error,
            )
            logger.info(f"Identity provider {idp.slug} refused the authorization request: {error}")
            return _return_to_client(oauth_state, _provider_error_params(error, error_description))

        if not code:
            # Neither half of a well-formed authorization response. Reported to
            # the client the same way any other post-validation failure is.
            logger.warning(f"OAuth callback for {idp.slug} carried neither 'code' nor 'error'")
            raise jafaal_exceptions.InvalidRequestError(
                "The identity provider callback carried neither an authorization code nor an error."
            )

        # Process the OAuth callback (service will handle both DB and cookie state)
        result = await idp_service.idp_service.handle_callback(
            idp, code, state, request, password_hasher, db, oauth_state
        )

        user = result["user"]

        # STEP-UP RE-AUTH MODE: the single-use grant was already minted inside
        # handle_callback after verifying the fresh IdP sign-in. Return the
        # browser to the client with a success flag; the client then retries the
        # sensitive operation, which consumes the grant.
        if result.get("mode") == "stepup":
            logger.info(f"IdP step-up re-authentication successful for user {user.username} via {idp.name}")
            return _return_to_client(oauth_state, {"step_up": "success"})

        # LINK MODE: the provider was attached to an already-authenticated
        # account. No session is created.
        if result.get("mode") == "link":
            logger.info(f"IdP link successful for user {user.username}, IdP {idp.name}")
            return _return_to_client(oauth_state, {"idp_link": "success", "idp_name": idp.name})

        # LOGIN MODE: create the session WITHOUT tokens. The client redeems the
        # authorization code below at /auth/token, and that exchange is what
        # mints them.
        jafaal_user_guards.check_user_is_active(user)

        session_id = str(uuid4())
        jafaal_sessions_utils.create_session(
            session_id,
            user,
            request,
            None,
            db,
            oauth_state_id=oauth_state.id,
        )

        # The RFC 6749 §4.1.2 authorization response: a code plus the client's
        # own ``state``, delivered to the exact redirect_uri the client
        # registered. This is what lets a stock OAuth library (AppAuth,
        # openid-client, MSAL) drive JAFAAL with no bespoke code.
        authorization_code = authorization_code_service.issue_authorization_code(oauth_state.id, db)
        logger.info(f"SSO login successful for user {user.username} via {idp.name} (client={oauth_state.client_id})")
        return _return_to_client(oauth_state, {"code": authorization_code})

    except jafaal_exceptions.JafaalError as err:
        # RFC 6749 §4.1.2.1: a failure *after* the redirect_uri has been
        # validated is reported back to the client at that URI. Without this a
        # native app sits on its callback listener until it times out, with no
        # way to tell a denial from a crash.
        #
        # When the state could not be resolved there is no validated target, so
        # the error has to be rendered instead — the same rule, and the same
        # reason, as /auth/authorize.
        if oauth_state is None or not oauth_state.redirect_uri:
            raise
        logger.warning(f"SSO callback failed after redirect validation: {err.detail}")
        return _return_to_client(oauth_state, {"error": "access_denied", "error_description": err.detail})
    except Exception as err:
        logger.error(f"Error in SSO callback: {err}", exc_info=err)
        if oauth_state is None or not oauth_state.redirect_uri:
            raise jafaal_exceptions.InternalError("Failed to complete the SSO callback") from err
        return _return_to_client(
            oauth_state,
            {"error": "server_error", "error_description": "The provider callback could not be completed."},
        )
