"""Identity-provider link management: the owner's routes and the administrator's.

* :data:`router` (mounted under the ``profile`` prefix): the caller lists, links
  and unlinks their own providers.
* :data:`admin_router` (mounted under the ``users`` prefix): an administrator
  lists and unlinks another user's.

Linking starts with an authenticated ``POST`` that returns the provider's
authorization URL, which the client then navigates to; the provider's callback
completes the link through the shared callback route.
"""

from typing import Annotated

from fastapi import Depends, Query, Request, Response, Security, status
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.services.authorization_code_service as authorization_code_service
import jafaal._internal.services.identity_link_service as link_service
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.dependencies as jafaal_dependencies
import jafaal.identity_providers.links.schema as links_schema
import jafaal.identity_providers.models as idp_models
import jafaal.identity_providers.service as idp_service
import jafaal.identity_service as jafaal_identity_service
import jafaal.oauth_state.utils as oauth_state_utils
import jafaal.orm as jafaal_orm
import jafaal.principal as jafaal_principal
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.schema as jafaal_schema
import jafaal.utils as jafaal_utils
from jafaal._core import network
from jafaal.orm import UserId

router = jafaal_orm.auth_router()
admin_router = jafaal_orm.auth_router()

_PROFILE = Security(jafaal_dependencies.check_scopes, scopes=["profile"])
_READ = Security(jafaal_dependencies.check_scopes, scopes=["identity_providers:read"])
_WRITE = Security(jafaal_dependencies.check_scopes, scopes=["identity_providers:write"])


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


@router.post("/idp/{idp_id}/link", response_model=links_schema.IdpLinkResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def link_identity_provider(
    request: Request,
    response: Response,
    idp_id: int,
    body: links_schema.IdpLinkRequest,
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
) -> links_schema.IdpLinkResponse:
    """Start linking a provider and return the URL the browser navigates to.

    Linking gives the account a new way to sign in, so the caller must pass
    step-up verification first, as for unlinking. The bearer authenticates this
    request; the browser then navigates to the returned ``authorization_url``, and
    the provider's callback completes the link and returns the browser to
    ``redirect_uri`` with ``idp_link=success``.

    The response also sets a short-lived ``HttpOnly`` cookie that binds the flow
    to this browser, and the callback refuses to finish it from any other: without
    that, an attacker could start a link for their own account and get a victim to
    finish it, attaching the victim's provider identity to the attacker's account.
    The cookie needs the app and the API to be same-site; a client whose
    authorization navigation happens in a different browser than this request
    (a native app using the system browser) cannot carry it, and needs
    ``SsoSettings.idp_link_browser_binding`` off.

    ``client_id`` and ``redirect_uri`` pass the same registration gate as
    ``/auth/authorize``, so the link flow is no more an open redirect than a login.

    Raises:
        JafaalError: Step-up errors; 401/400 if the client or redirect URI is
            unregistered; 404 if the provider is missing or disabled; 409 if it is
            already linked.
    """
    jafaal_utils.apply_no_store(response)
    authorization_code_service.validate_client_and_redirect_uri(body.client_id, body.redirect_uri)
    client_ip = network.get_ip_address(request)
    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()

    def _prepare() -> idp_models.IdentityProvider:
        idp = link_service.prepare_identity_provider_link(
            idp_id, body, principal.user_id, identity_service, step_up_store, db
        )
        idp_service.create_link_oauth_state(
            db,
            state_id=state_id,
            idp_id=idp.id,
            nonce=nonce,
            ip_address=client_ip,
            user_id=principal.user_id,
            client_id=body.client_id,
            redirect_uri=body.redirect_uri,
            client_state=body.state,
        )
        return idp

    # Async for the provider round trip below, so the database work runs in a
    # worker thread rather than on the loop.
    idp = await run_in_threadpool(_prepare)
    authorization_url = await idp_service.idp_service.initiate_link(
        idp, request, principal.user_id, db, oauth_state_id=state_id
    )
    oauth_state_utils.set_browser_binding(response, state_id)
    return links_schema.IdpLinkResponse(authorization_url=authorization_url)


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
