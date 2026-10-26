"""Identity-provider link management: the owner's routes and the administrator's.

* :data:`router` (mounted under the ``profile`` prefix): the caller lists, links
  and unlinks their own providers.
* :data:`admin_router` (mounted under the ``users`` prefix): an administrator
  lists and unlinks another user's.

Linking is a three-step handoff because a browser navigation cannot carry a
bearer header: the SPA trades its bearer (plus step-up) for a short-lived,
single-use link token, then navigates to the ``link`` route with it. The route
claims the token atomically and redirects to the provider; the provider's
callback completes the link through the shared callback route.
"""

import hmac
from typing import Annotated

from fastapi import Depends, Query, Request, Response, Security, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.services.authorization_code_service as authorization_code_service
import jafaal._internal.services.identity_link_service as link_service
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.dependencies as jafaal_dependencies
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.link_tokens.schema as idp_link_token_schema
import jafaal.identity_providers.link_tokens.utils as jafaal_link_tokens
import jafaal.identity_providers.links.schema as links_schema
import jafaal.identity_providers.service as idp_service
import jafaal.identity_service as jafaal_identity_service
import jafaal.oauth_state.utils as oauth_state_utils
import jafaal.orm as jafaal_orm
import jafaal.principal as jafaal_principal
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.schema as jafaal_schema
import jafaal.settings as jafaal_settings
import jafaal.utils as jafaal_utils
from jafaal._core import network
from jafaal.orm import UserId

router = jafaal_orm.auth_router()
admin_router = jafaal_orm.auth_router()

_PROFILE = Security(jafaal_dependencies.check_scopes, scopes=["profile"])
_READ = Security(jafaal_dependencies.check_scopes, scopes=["identity_providers:read"])
_WRITE = Security(jafaal_dependencies.check_scopes, scopes=["identity_providers:write"])


def _link_cookie_name() -> str:
    """Return the name of the cookie that binds a link token to its browser."""
    return f"{jafaal_settings.get_settings().effective_refresh_cookie_name}_idp_link"


def _require_browser_binding(request: Request, token: str) -> None:
    """Refuse a link navigation from a browser that did not mint the token.

    Protects against forced linking: an attacker mints a token for their own
    account and lures a victim to the ``link`` URL, so that the victim's provider
    identity is attached to the attacker's account. The cookie set at mint time
    lives only in the minting browser, so the victim's navigation lacks it.
    Checked before the token is claimed, so a refusal does not spend it.
    """
    if not jafaal_settings.get_settings().sso.idp_link_browser_binding:
        return
    bound = request.cookies.get(_link_cookie_name())
    if bound is None or not hmac.compare_digest(bound.encode(), token.encode()):
        raise jafaal_exceptions.InvalidTokenError("Invalid or expired link token")


def _read_links(user_id: UserId, db: Session) -> list[links_schema.IdentityProviderLinkRead]:
    """Return a user's links in the narrow shape these routes expose."""
    return [
        links_schema.IdentityProviderLinkRead(
            idp_id=link.idp_id,
            idp_name=link.idp_name or "",
            idp_slug=link.idp_slug or "",
            linked_at=link.linked_at,
            last_login=link.last_login,
        )
        for link in link_service.get_user_identity_provider_links(user_id, db)
    ]


# ===========================================================================
# The caller's own links
# ===========================================================================


@router.get("/idp", response_model=list[links_schema.IdentityProviderLinkRead])
def list_my_identity_providers(
    _check_scope: Annotated[None, _READ],
    principal: Annotated[jafaal_principal.Principal, Depends(jafaal_dependencies.get_current_principal)],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> list[links_schema.IdentityProviderLinkRead]:
    """List the identity providers linked to the caller's account.

    Returns the provider and the link and last-login timestamps; never the
    provider's subject or any token held on the link.
    """
    return _read_links(principal.user_id, db)


@router.post("/idp/{idp_id}/link/token", response_model=idp_link_token_schema.IdpLinkTokenResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def create_identity_provider_link_token(
    request: Request,
    response: Response,
    idp_id: int,
    body: idp_link_token_schema.IdpLinkTokenRequest,
    _check_scope: Annotated[None, _PROFILE],
    principal: Annotated[jafaal_principal.Principal, Depends(jafaal_dependencies.get_current_principal)],
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    step_up_store: Annotated[
        jafaal_security_stores.StepUpStore,
        Depends(jafaal_security_stores.get_step_up_attempts),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> idp_link_token_schema.IdpLinkTokenResponse:
    """Mint a short-lived, single-use token for linking a provider.

    A SPA that authenticates with a bearer header cannot attach it to the
    top-level browser navigation the link flow needs, so it trades the bearer for
    this token and navigates to the ``link`` route with it. Linking gives the
    account a new way to sign in, so the caller must pass step-up verification
    first, as for unlinking.

    Raises:
        JafaalError: Step-up errors; 404 if the provider is missing or disabled;
            409 if it is already linked.
    """
    jafaal_utils.apply_no_store(response)
    link_token = link_service.generate_link_token(
        idp_id, body, request, principal.user_id, identity_service, step_up_store, db
    )
    if jafaal_settings.get_settings().sso.idp_link_browser_binding:
        response.set_cookie(
            key=_link_cookie_name(),
            value=link_token.token,
            max_age=jafaal_link_tokens.TOKEN_EXPIRY_SECONDS,
            httponly=True,
            secure=jafaal_utils._is_secure_cookie_environment(),
            samesite="strict",
            path="/",
        )
    return link_token


@router.get("/idp/{idp_id}/link", status_code=status.HTTP_302_FOUND)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def link_identity_provider(
    request: Request,
    idp_id: int,
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    token: Annotated[str, Query(min_length=1, max_length=256, description="Token from `link/token`")],
    client_id: Annotated[str, Query(description="Registered client the flow returns to")],
    redirect_uri: Annotated[str, Query(description="Registered redirect URI for `client_id`")],
    state: Annotated[str | None, Query(max_length=2048, description="Client state, echoed on return")] = None,
) -> RedirectResponse:
    """Claim a link token and send the browser to the identity provider.

    A browser navigation, so it carries no bearer: the single-use token is the
    credential. It is claimed atomically (a replay, an expired token, or one
    minted for another provider is refused) before anything is redirected.
    ``client_id`` and ``redirect_uri`` pass the same registration gate as
    ``/auth/authorize``, so the link flow is no more an open redirect than a
    login. The provider's callback completes the link and returns the browser to
    ``redirect_uri`` with ``idp_link=success``.

    Failures are rendered rather than redirected: until the token is claimed there
    is no account to report to, and an unverified redirect target is never used.

    Raises:
        JafaalError: 401/400 for an invalid, expired, reused or mismatched token;
            404 if the provider is missing or disabled; 409 if already linked.
    """
    authorization_code_service.validate_client_and_redirect_uri(client_id, redirect_uri)
    _require_browser_binding(request, token)
    client_ip = network.get_ip_address(request)
    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()

    def _prepare():
        user_id = link_service.validate_and_claim_browser_link_token(token, idp_id, client_ip, db)
        idp = idp_service.get_identity_provider(idp_id, db)
        if not idp or not idp.enabled:
            raise jafaal_exceptions.NotFoundError("Identity provider not found or disabled")
        user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)
        jafaal_user_guards.check_user_is_active(user)
        idp_service.create_link_oauth_state(
            db,
            state_id=state_id,
            idp_id=idp.id,
            nonce=nonce,
            ip_address=client_ip,
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            client_state=state,
        )
        return idp, user_id

    # Async for the provider round trip below, so the database work runs in a
    # worker thread rather than on the loop.
    idp, user_id = await run_in_threadpool(_prepare)
    authorization_url = await idp_service.idp_service.initiate_link(idp, request, user_id, db, oauth_state_id=state_id)
    # The URL the browser arrived on carries the token: keep it out of caches and
    # out of any Referer sent from the provider's page.
    redirect = RedirectResponse(
        url=authorization_url,
        status_code=status.HTTP_302_FOUND,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )
    redirect.delete_cookie(_link_cookie_name(), path="/")  # the token is spent
    return redirect


@router.post("/idp/{idp_id}/unlink", status_code=status.HTTP_204_NO_CONTENT)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def unlink_identity_provider(
    request: Request,
    idp_id: int,
    body: jafaal_schema.StepUpVerification,
    _check_scope: Annotated[None, _PROFILE],
    principal: Annotated[jafaal_principal.Principal, Depends(jafaal_dependencies.get_current_principal)],
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    step_up_store: Annotated[
        jafaal_security_stores.StepUpStore,
        Depends(jafaal_security_stores.get_step_up_attempts),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> None:
    """Unlink a provider from the caller's account.

    Requires step-up verification, and refuses to remove the account's **last**
    sign-in method (no local password, no passkey, and this is its only link).
    The provider's tokens held on the link are revoked at the provider
    (best-effort) and the account owner is notified through
    ``on_idp_account_unlinked``.

    Raises:
        JafaalError: Step-up errors; 404 if the provider or link does not exist;
            400 (``last_sign_in_method``) if it is the last way to sign in.
    """
    user_id = principal.user_id
    await run_in_threadpool(
        link_service.prepare_identity_provider_unlink, idp_id, body, user_id, identity_service, step_up_store, db
    )
    await idp_service.idp_service.revoke_idp_token(user_id, idp_id, db)
    await run_in_threadpool(
        lambda: link_service.finalize_identity_provider_unlink(
            user_id, idp_id, db, by_admin=False, actor_user_id=user_id
        )
    )


# ===========================================================================
# Administrator access to another user's links
# ===========================================================================


@admin_router.get("/{user_id}/identity-providers", response_model=list[links_schema.IdentityProviderLinkRead])
def list_user_identity_providers(
    user_id: UserId,
    _check_scope: Annotated[None, _READ],
    principal: Annotated[jafaal_principal.Principal, Depends(jafaal_dependencies.get_current_principal)],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> list[links_schema.IdentityProviderLinkRead]:
    """List the identity providers linked to a user's account.

    The caller must be that user or a superuser.
    """
    jafaal_user_guards.assert_can_access_user(principal, user_id)
    jafaal_user_guards.get_user_by_id_or_404(user_id, db)
    return _read_links(user_id, db)


@admin_router.delete("/{user_id}/identity-providers/{idp_id}", status_code=status.HTTP_204_NO_CONTENT)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def admin_unlink_identity_provider(
    request: Request,
    user_id: UserId,
    idp_id: int,
    _check_scope: Annotated[None, _WRITE],
    principal: Annotated[jafaal_principal.Principal, Depends(jafaal_dependencies.get_current_principal)],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    force: Annotated[
        bool,
        Query(description="Remove the link even if it is the account's last sign-in method."),
    ] = False,
) -> None:
    """Unlink a provider from a user's account.

    Needs no step-up from the caller: the ``identity_providers:write`` scope and
    the object-level access check are the authorization. The last-sign-in-method
    rule applies unless ``force=true``. **Forcing is a trade-off**: it can leave
    an account with no way to sign in, recoverable only by a password reset or an
    administrator, so it is audited and reserved for the case where the link
    itself is the problem (a compromised provider account, an offboarded
    identity). The provider's tokens held on the link are revoked at the provider
    (best-effort) and the owner is notified through ``on_idp_account_unlinked``.

    Raises:
        JafaalError: 403 if the caller may not act on ``user_id``; 404 if the
            provider or link does not exist; 400 (``last_sign_in_method``) if it
            is the last way to sign in and ``force`` is not set.
    """
    jafaal_user_guards.assert_can_access_user(principal, user_id)
    await run_in_threadpool(link_service.check_admin_identity_provider_unlink, user_id, idp_id, db, force=force)
    await idp_service.idp_service.revoke_idp_token(user_id, idp_id, db)
    await run_in_threadpool(
        lambda: link_service.finalize_identity_provider_unlink(
            user_id, idp_id, db, by_admin=True, actor_user_id=principal.user_id, forced=force
        )
    )


__all__ = ["admin_router", "router"]
