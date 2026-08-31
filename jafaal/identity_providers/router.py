"""HTTP routes for managing identity providers (admin only)."""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request, Security, status
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

import jafaal._internal.services.authorization_code_service as authorization_code_service
import jafaal.dependencies as jafaal_dependencies
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.dependencies as idp_dependencies
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.models as idp_models
import jafaal.identity_providers.schema as idp_schema
import jafaal.identity_providers.service as idp_service
import jafaal.identity_providers.utils as idp_utils
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.utils as oauth_state_utils
import jafaal.orm as jafaal_orm
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.settings as jafaal_settings
from jafaal._core import network

# Define the API router
router = jafaal_orm.auth_router()


@router.get(
    "",
    response_model=list[idp_schema.IdentityProvider],
    status_code=status.HTTP_200_OK,
)
def list_identity_providers(
    _check_scopes: Annotated[
        None,
        Security(jafaal_dependencies.check_scopes, scopes=["identity_providers:read"]),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> list[idp_schema.IdentityProvider]:
    """
    Retrieve a list of all identity providers.

    Args:
        db: SQLAlchemy database session dependency.
        _check_scopes: Authenticated user with the
            'identity_providers:read' scope.

    Returns:
        A list of all configured identity providers.
    """
    return [
        idp_schema.IdentityProvider.model_validate(provider) for provider in idp_crud.get_all_identity_providers(db)
    ]


@router.get(
    "/templates",
    response_model=list[idp_schema.IdentityProviderTemplate],
    status_code=status.HTTP_200_OK,
)
def list_idp_templates(
    _check_scopes: Annotated[
        None,
        Security(jafaal_dependencies.check_scopes, scopes=["identity_providers:read"]),
    ],
) -> list[idp_schema.IdentityProviderTemplate]:
    """
    Get the list of pre-configured IdP templates (admin only).

    Args:
        _check_scopes: Authenticated user with the
            'identity_providers:read' scope.

    Returns:
        A list of identity provider templates.
    """
    return idp_utils.get_idp_templates()


@router.post(
    "",
    response_model=idp_schema.IdentityProvider,
    status_code=status.HTTP_201_CREATED,
)
def create_identity_provider(
    _check_scopes: Annotated[
        None,
        Security(jafaal_dependencies.check_scopes, scopes=["identity_providers:write"]),
    ],
    idp_data: idp_schema.IdentityProviderCreate,
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> idp_schema.IdentityProvider:
    """
    Create a new identity provider.

    Args:
        idp_data: Data required to create the identity provider.
        db: SQLAlchemy database session dependency.
        _check_scopes: Authenticated user with the
            'identity_providers:write' scope.

    Returns:
        The newly created identity provider.

    Raises:
        JafaalError: 409 if the slug already exists, 500 on
            database errors.
    """
    return idp_schema.IdentityProvider.model_validate(idp_crud.create_identity_provider(idp_data, db))


@router.put(
    "/{idp_id}",
    response_model=idp_schema.IdentityProvider,
    status_code=status.HTTP_200_OK,
)
def update_identity_provider(
    idp_id: int,
    _validate_id: Annotated[Callable, Depends(idp_dependencies.validate_idp_id)],
    _check_scopes: Annotated[
        None,
        Security(jafaal_dependencies.check_scopes, scopes=["identity_providers:write"]),
    ],
    idp_data: idp_schema.IdentityProviderUpdate,
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> idp_schema.IdentityProvider:
    """
    Update an existing identity provider.

    Args:
        idp_id: The unique identifier of the identity provider to update.
        idp_data: The data to update the identity provider with.
        db: SQLAlchemy database session dependency.
        _check_scopes: Authenticated user with the
            'identity_providers:write' scope.

    Returns:
        The updated identity provider.

    Raises:
        JafaalError: 404 if the provider is not found, 409 on slug
            conflict, 500 on database errors.
    """
    return idp_schema.IdentityProvider.model_validate(idp_crud.update_identity_provider(idp_id, idp_data, db))


@router.delete("/{idp_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_identity_provider(
    idp_id: int,
    _validate_id: Annotated[Callable, Depends(idp_dependencies.validate_idp_id)],
    _check_scopes: Annotated[
        None,
        Security(jafaal_dependencies.check_scopes, scopes=["identity_providers:write"]),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> None:
    """
    Delete an identity provider by ID.

    Args:
        idp_id: The unique identifier of the identity provider to delete.
        _check_scopes: Authenticated user with the
            'identity_providers:write' scope.
        db: SQLAlchemy database session dependency.

    Raises:
        JafaalError: 404 if the provider is not found, 409 if users
            are still linked to the provider.
    """
    idp_crud.delete_identity_provider(idp_id, db)


@router.post("/step-up/reauth/{idp_id}", status_code=status.HTTP_200_OK)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
async def initiate_step_up_reauth(
    idp_id: int,
    request: Request,
    body: idp_schema.StepUpReauthRequest,
    token_user_id: Annotated[
        jafaal_orm.UserId,
        Depends(jafaal_dependencies.get_sub_from_access_token),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> dict[str, str]:
    """Begin a fresh IdP re-authentication to satisfy step-up (SSO accounts).

    For an SSO-only account (no local password or MFA), sensitive operations
    raise ``step_up_reauth_required``. The client calls this endpoint for one of
    its linked providers, then navigates (top-level) to the returned
    ``authorization_url``. After the user re-authenticates at the IdP, the SSO
    callback verifies the fresh sign-in and mints a single-use step-up grant;
    the client then retries the original operation, which consumes the grant.

    The caller must already be linked to the target identity provider (you can
    only re-authenticate an identity you own). ``prompt=login`` and ``max_age``
    are sent so the provider re-prompts the user, and the callback verifies the
    ID token's ``auth_time`` is recent.

    ``client_id``/``redirect_uri`` go through the same registration gate as
    ``/auth/authorize``. A step-up round trip ends in a browser redirect just
    like a login does, so it gets the same open-redirect protection — there is
    no second, weaker rule for "internal" redirects.

    Args:
        idp_id: The linked identity provider to re-authenticate against.
        request: The current HTTP request (for client IP capture).
        body: The registered client and the redirect URI to return to.
        token_user_id: The authenticated user (from the access token ``sub``).
        db: SQLAlchemy database session.

    Returns:
        ``{"authorization_url": ...}`` for the client to navigate to.

    Raises:
        JafaalError: 400 if IdP step-up re-auth is disabled or the provider is
            not linked to the caller; 401/400 if the client or redirect URI is
            unregistered; 404 if the provider is missing or disabled.
    """
    settings = jafaal_settings.get_settings()
    if not settings.sso.step_up_idp_reauth_enabled:
        raise jafaal_exceptions.InvalidRequestError("Identity-provider step-up re-authentication is disabled.")

    authorization_code_service.validate_client_and_redirect_uri(body.client_id, body.redirect_uri)

    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()

    def _prepare_reauth() -> idp_models.IdentityProvider:
        """Resolve the provider, assert the link, and park the OAuth state."""
        idp = idp_crud.get_identity_provider(idp_id, db)
        if not idp or not idp.enabled:
            raise jafaal_exceptions.NotFoundError("Identity provider not found or disabled")

        link = links_crud.get_user_identity_provider_by_user_id_and_idp_id(token_user_id, idp_id, db)
        if not link:
            raise jafaal_exceptions.InvalidRequestError("This identity provider is not linked to your account.")

        oauth_state_crud.create_oauth_state(
            db=db,
            state_id=state_id,
            nonce=nonce,
            ip_address=network.get_ip_address(request),
            idp_id=idp_id,
            user_id=token_user_id,
            purpose="stepup",
            client_id=body.client_id,
            redirect_uri=body.redirect_uri,
            client_state=body.state,
        )
        return idp

    # This endpoint must stay async for the provider round trip below, so its
    # database work is handed to a worker thread rather than run on the loop.
    idp = await run_in_threadpool(_prepare_reauth)

    authorization_url = await idp_service.idp_service.initiate_link(
        idp,
        request,
        token_user_id,
        db,
        oauth_state_id=state_id,
        authorize_extra_params={
            "prompt": "login",
            "max_age": str(settings.sso.step_up_reauth_max_age_seconds),
        },
    )
    return {"authorization_url": authorization_url}
