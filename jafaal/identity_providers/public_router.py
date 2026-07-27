"""Public (unauthenticated) HTTP routes for identity provider SSO flows.

There is exactly one way into an SSO login: ``GET /auth/authorize``, the RFC 6749
§4.1 authorization endpoint. This module owns the *other* half of that round
trip — the provider's callback — plus the read-only list of enabled providers.

Every browser redirect this module emits targets a ``redirect_uri`` that was
matched exactly against a registered :class:`~jafaal.settings.OAuthClient` before
the flow started. There is no configured "frontend path" fallback and no
scheme-level allow-list: a URI is either registered, byte-for-byte, or JAFAAL
will not send a browser to it.
"""

import logging
from typing import Annotated
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
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.models as oauth_state_models
import jafaal.orm as jafaal_orm
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.sessions.utils as jafaal_sessions_utils
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


def _return_to_client(oauth_state: oauth_state_models.OAuthState, params: dict[str, str]) -> RedirectResponse:
    """Redirect the browser back to the client that started the flow.

    ``oauth_state.redirect_uri`` was matched exactly against the initiating
    client's registered list before the flow began, so it is safe to navigate to
    here. Values go through :func:`_append_query_params`, which percent-encodes,
    rather than string concatenation — otherwise a value could inject additional
    parameters into the URL the client parses.

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
    code: str = Query(..., description="Authorization code from IdP"),
    state: str = Query(..., description="State parameter for CSRF protection"),
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

    Args:
        request: The incoming HTTP request.
        response: The HTTP response object.
        idp_slug: The slug identifier of the identity provider.
        password_hasher: Password hasher used during provisioning.
        token_manager: Token manager, used by the provisioning path.
        db: Database session.
        code: Authorization code received from the identity provider.
        state: The opaque state id minted at initiation.

    Returns:
        RedirectResponse: To the client's registered redirect URI.

    Raises:
        JafaalError: If the state cannot be resolved at all. There is then no
            validated redirect target to report the failure to, so it must be
            rendered instead.
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

        logger.debug(f"OAuth callback received for state {state[:8]}... (purpose={oauth_state.purpose})")

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
