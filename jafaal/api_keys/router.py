"""User API key management endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

import jafaal._internal.internal_dependencies as jafaal_internal_dependencies
import jafaal._internal.services.step_up_service as step_up_service
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.api_keys.crud as jafaal_api_keys_crud
import jafaal.api_keys.schema as api_keys_schema
import jafaal.api_keys.utils as api_keys_utils
import jafaal.dependencies as jafaal_dependencies
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_service as jafaal_identity_service
import jafaal.orm as jafaal_orm

# Define the API router
router = APIRouter()


@router.get(
    "",
    response_model=list[api_keys_schema.UsersApiKeyRead],
    status_code=status.HTTP_200_OK,
)
async def get_user_api_keys(
    token_user_id: Annotated[
        int,
        Depends(jafaal_internal_dependencies.get_sub_from_access_token),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> list[api_keys_schema.UsersApiKeyRead]:
    """
    Retrieve all API keys for the authenticated user.

    Args:
        token_user_id: User ID from access token.
        db: Database session dependency.

    Returns:
        List of API key objects. Raw keys and hashes
        are never included.
    """
    return jafaal_api_keys_crud.get_api_keys_by_user_id(token_user_id, db)  # type: ignore[return-value]


@router.post(
    "",
    response_model=api_keys_schema.UsersApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
async def create_user_api_key(
    data: api_keys_schema.UsersApiKeyCreate,
    token_user_id: Annotated[
        int,
        Depends(jafaal_internal_dependencies.get_sub_from_access_token),
    ],
    identity_service: Annotated[
        jafaal_identity_service.IdentityService,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    step_up_store: Annotated[
        jafaal_dependencies.StepUpStore,
        Depends(jafaal_dependencies.get_step_up_attempts),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> api_keys_schema.UsersApiKeyCreated:
    """
    Create a new API key for the authenticated user.

    The raw key is returned once in this response and
    cannot be retrieved again. Requested scopes must be
    supported by API-key authentication.

    Step-up verification is required (current password,
    plus MFA code when MFA is enabled). API keys grant
    persistent, long-lived access — a stolen access
    token alone must not be sufficient to mint one.

    Args:
        data: Key creation data (name, scopes, expiry,
            step-up credentials).
        token_user_id: User ID from access token.
        identity_service: Identity service dependency.
        db: Database session dependency.

    Returns:
        Created API key including the raw key string.

    Raises:
        AuthenticationError: 401 if step-up verification fails.
        InvalidRequestError: 400 if scopes are not supported for API keys.
        NotFoundError: 404 if the user is not found.
    """
    jafaal_user_guards.get_user_by_id_or_404(token_user_id, db)

    step_up_service.verify_step_up_credentials(
        token_user_id,
        data.current_password,
        data.mfa_code,
        identity_service,
        step_up_store,
        db,
    )

    try:
        api_keys_utils.validate_api_key_scopes(data.scopes)
    except ValueError as exc:
        raise jafaal_exceptions.InvalidRequestError(str(exc)) from exc

    db_api_key, raw_key = jafaal_api_keys_crud.create_api_key(token_user_id, data, db)

    return api_keys_schema.UsersApiKeyCreated(
        id=db_api_key.id,
        user_id=db_api_key.user_id,
        name=db_api_key.name,
        key_prefix=db_api_key.key_prefix,
        scopes=db_api_key.scopes,
        expires_at=db_api_key.expires_at,
        last_used_at=db_api_key.last_used_at,
        created_at=db_api_key.created_at,
        is_active=db_api_key.is_active,
        key=raw_key,
    )


@router.patch(
    "/{api_key_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_user_api_key(
    api_key_id: str,
    token_user_id: Annotated[
        int,
        Depends(jafaal_internal_dependencies.get_sub_from_access_token),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> None:
    """
    Revoke an API key (soft-disable).

    The key record is retained for audit purposes but
    will be rejected on any subsequent use.

    Args:
        api_key_id: UUID of the API key to revoke.
        token_user_id: User ID from access token.
        db: Database session dependency.

    Returns:
        None.

    Raises:
        JafaalError: 404 if the key is not found or
            does not belong to the authenticated user.
    """
    jafaal_api_keys_crud.revoke_api_key(api_key_id, token_user_id, db)


@router.delete(
    "/{api_key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_user_api_key(
    api_key_id: str,
    token_user_id: Annotated[
        int,
        Depends(jafaal_internal_dependencies.get_sub_from_access_token),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> None:
    """
    Permanently delete an API key.

    Hard-delete. The key is gone and cannot be used
    or recovered after this operation.

    Args:
        api_key_id: UUID of the API key to delete.
        token_user_id: User ID from access token.
        db: Database session dependency.

    Returns:
        None.

    Raises:
        JafaalError: 404 if the key is not found or
            does not belong to the authenticated user.
    """
    jafaal_api_keys_crud.delete_api_key(api_key_id, token_user_id, db)
