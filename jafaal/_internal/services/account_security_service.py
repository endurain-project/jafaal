"""Auth-owned account security workflows."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.services.step_up_service as step_up_service
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.audit as jafaal_audit
import jafaal.password_policy as jafaal_password_policy
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.schema as jafaal_sessions_schema
import jafaal.settings as jafaal_settings
from jafaal.orm import UserId

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from jafaal.identity_service import IdentityService


def get_user_sessions(
    token_user_id: UserId,
    db: Session,
) -> list[jafaal_sessions_schema.UsersSessionsRead]:
    """Retrieve active sessions for the authenticated user."""
    if jafaal_settings.get_settings().environment == "demo":
        logger.info("Session retrieval attempted in demo environment - returning empty list")
        return []

    return [
        jafaal_sessions_schema.UsersSessionsRead.model_validate(session)
        for session in jafaal_sessions_crud.get_user_sessions(token_user_id, db)
    ]


def delete_user_session(
    session_id: str,
    token_user_id: UserId,
    db: Session,
) -> None:
    """Delete one authenticated user's session."""
    jafaal_sessions_crud.delete_session(session_id, token_user_id, db)
    jafaal_audit.record(
        jafaal_audit.Event.SESSION_REVOKED,
        user_id=token_user_id,
        session_id=session_id,
        scope="single",
    )


def delete_other_user_sessions(
    token_user_id: UserId,
    current_session_id: str,
    db: Session,
) -> int:
    """Revoke all of the user's sessions except their current one.

    Backs the self-service "sign out other devices" action: every
    session the user owns is deleted except ``current_session_id``
    (the caller's own session, derived from their access token), so
    the caller stays signed in while every other device is evicted.

    Args:
        token_user_id: ID of the authenticated user.
        current_session_id: The caller's current session, preserved.
        db: SQLAlchemy session.

    Returns:
        Number of sessions revoked.
    """
    revoked = jafaal_sessions_crud.delete_sessions_by_user(
        token_user_id,
        db,
        exclude_session_id=current_session_id,
    )
    logger.info(f"User {token_user_id} revoked {revoked} other session(s)")
    jafaal_audit.record(
        jafaal_audit.Event.SESSION_REVOKED,
        user_id=token_user_id,
        session_id=current_session_id,
        scope="others",
        revoked=revoked,
    )
    return revoked


def change_own_password(
    user_id: UserId,
    current_password: str,
    new_password: str,
    mfa_code: str | None,
    identity_service: IdentityService,
    step_up_store: jafaal_security_stores.StepUpStore,
    db: Session,
    revoke_other_sessions: bool = False,
    current_session_id: str | None = None,
) -> None:
    """
    Change a user's own password after step-up verification.

    Args:
        user_id: ID of the authenticated user.
        current_password: Current password supplied for step-up.
        new_password: New plaintext password to store.
        mfa_code: Optional MFA code supplied for step-up.
        identity_service: Identity service dependency.
        step_up_store: Step-up lockout store.
        db: SQLAlchemy session.
        revoke_other_sessions: When True, delete all of the user's
            other sessions (keeping ``current_session_id``) so a
            password change can evict a suspected attacker.
        current_session_id: Session ID of the caller, preserved when
            ``revoke_other_sessions`` is True so the caller is not
            logged out.

    Returns:
        None.

    Raises:
        JafaalError: If step-up verification or persistence fails.
    """
    step_up_service.verify_step_up_credentials(
        user_id,
        current_password,
        mfa_code,
        identity_service,
        step_up_store,
        db,
    )

    db_user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)
    hashed_password = jafaal_password_policy.validate_and_hash_for_user(
        identity_service,
        db_user.is_superuser,
        new_password,
    )
    identity_service.set_local_password_hash(user_id, hashed_password)
    jafaal_security_stores.clear_pending_mfa_for_user(user_id)

    if revoke_other_sessions:
        revoked = jafaal_sessions_crud.delete_sessions_by_user(
            user_id,
            db,
            exclude_session_id=current_session_id,
        )
        logger.info(f"User {user_id} revoked {revoked} other session(s) after password change")
        jafaal_audit.record(
            jafaal_audit.Event.SESSION_REVOKED,
            user_id=user_id,
            session_id=current_session_id,
            scope="others",
            revoked=revoked,
            reason="password_change",
        )

    logger.info(f"User {user_id} changed password (step-up verified)")
    jafaal_audit.record(jafaal_audit.Event.PASSWORD_CHANGED, user_id=user_id, actor="self")


def change_managed_user_password(
    user_id: UserId,
    new_password: str,
    identity_service: IdentityService,
    db: Session,
) -> None:
    """
    Change a managed user's password and revoke auth state.

    Args:
        user_id: ID of the user whose password is changed.
        new_password: New plaintext password to store.
        identity_service: Identity service dependency.
        db: SQLAlchemy session.

    Returns:
        None.

    Raises:
        JafaalError: If password persistence fails.
    """
    db_user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)
    hashed_password = jafaal_password_policy.validate_and_hash_for_user(
        identity_service,
        db_user.is_superuser,
        new_password,
    )
    identity_service.set_local_password_hash(user_id, hashed_password)
    jafaal_sessions_crud.delete_sessions_by_user(user_id, db)
    jafaal_security_stores.clear_pending_mfa_for_user(user_id)
    jafaal_audit.record(
        jafaal_audit.Event.PASSWORD_CHANGED,
        level=logging.WARNING,
        user_id=user_id,
        actor="admin",
    )
    jafaal_audit.record(
        jafaal_audit.Event.SESSION_REVOKED,
        user_id=user_id,
        scope="all",
        reason="password_change",
    )
