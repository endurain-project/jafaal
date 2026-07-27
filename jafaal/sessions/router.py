"""User session API endpoints."""

import logging
from typing import Annotated

from fastapi import (
    Depends,
    Query,
    Security,
    status,
)
from sqlalchemy.orm import Session

import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.dependencies as jafaal_dependencies
import jafaal.orm as jafaal_orm
import jafaal.principal as jafaal_principal
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.schema as jafaal_sessions_schema
import jafaal.settings as jafaal_settings
from jafaal.orm import UserId

logger = logging.getLogger(__name__)

# Define the API router
router = jafaal_orm.auth_router()


@router.get(
    "/user/{user_id}",
    response_model=list[jafaal_sessions_schema.UsersSessionsRead],
    status_code=status.HTTP_200_OK,
)
def read_sessions_user(
    user_id: UserId,
    _check_scope: Annotated[
        None,
        Security(jafaal_dependencies.check_scopes, scopes=["sessions:read"]),
    ],
    principal: Annotated[
        jafaal_principal.Principal,
        Depends(jafaal_dependencies.get_current_principal),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> list[jafaal_sessions_schema.UsersSessionsRead]:
    """
    Retrieve all sessions associated with a specific user.

    Args:
        user_id: The ID of the user whose sessions to retrieve.
        _check_scope: Scope validation dependency.
        principal: The authenticated principal (object-level access check).
        db: Database session dependency.

    Returns:
        List of session objects for the specified user.
    """
    jafaal_user_guards.assert_can_access_user(principal, user_id)
    if jafaal_settings.get_settings().environment != "demo":
        return [
            jafaal_sessions_schema.UsersSessionsRead.model_validate(session)
            for session in jafaal_sessions_crud.get_user_sessions(user_id, db)
        ]
    else:
        logger.info("Session retrieval in demo environment - returning empty")
        return []


@router.delete(
    "/{session_id}/user/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
def delete_session_user(
    session_id: str,
    user_id: UserId,
    _check_scope: Annotated[
        None,
        Security(jafaal_dependencies.check_scopes, scopes=["sessions:write"]),
    ],
    principal: Annotated[
        jafaal_principal.Principal,
        Depends(jafaal_dependencies.get_current_principal),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> None:
    """
    Delete a user session.

    Args:
        session_id: The ID of the session to delete.
        user_id: The ID of the user who owns the session.
        _check_scope: Scope validation dependency.
        principal: The authenticated principal (object-level access check).
        db: Database session dependency.

    Returns:
        None.

    Raises:
        JafaalError: If session not found or unauthorized.
    """
    jafaal_user_guards.assert_can_access_user(principal, user_id)
    jafaal_sessions_crud.delete_session(session_id, user_id, db)


@router.delete(
    "/user/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
@jafaal_rate_limit.limit(jafaal_rate_limit.WRITE)
def delete_sessions_user(
    user_id: UserId,
    _check_scope: Annotated[
        None,
        Security(jafaal_dependencies.check_scopes, scopes=["sessions:write"]),
    ],
    principal: Annotated[
        jafaal_principal.Principal,
        Depends(jafaal_dependencies.get_current_principal),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    exclude_session_id: Annotated[
        str | None,
        Query(description="Session to keep intact (e.g. the caller's current session)"),
    ] = None,
) -> None:
    """
    Delete every session for a user, optionally keeping one intact.

    Backs the "revoke other sessions" action: pass the caller's current
    ``exclude_session_id`` to sign out every other device while staying
    logged in, or omit it (an admin acting on another user) to revoke
    all of that user's sessions.

    Args:
        user_id: The ID of the user whose sessions to revoke.
        _check_scope: Scope validation dependency.
        principal: The authenticated principal (object-level access check).
        db: Database session dependency.
        exclude_session_id: Optional session to leave intact.

    Returns:
        None.
    """
    jafaal_user_guards.assert_can_access_user(principal, user_id)
    jafaal_sessions_crud.delete_sessions_by_user(
        user_id,
        db,
        exclude_session_id=exclude_session_id,
    )
