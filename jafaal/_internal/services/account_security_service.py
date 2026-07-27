"""Auth-owned account security workflows."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.services.credential_sweep as credential_sweep
import jafaal._internal.services.step_up_service as step_up_service
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.audit as jafaal_audit
import jafaal.password_policy as jafaal_password_policy
import jafaal.ports as jafaal_ports
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.schema as jafaal_sessions_schema
import jafaal.settings as jafaal_settings
from jafaal.orm import UserId

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from jafaal.identity_service import LocalCredentialStore


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
    identity_service: LocalCredentialStore,
    step_up_store: jafaal_security_stores.StepUpStore,
    db: Session,
    revoke_other_sessions: bool = True,
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
        revoke_other_sessions: Delete all of the user's other sessions (keeping
            ``current_session_id``). Defaults to ``True``: "change my password"
            is what a user does when they think they are compromised, and
            leaving the attacker's session live is the one outcome that makes
            the action pointless. Pass ``False`` for a routine rotation where
            staying signed in elsewhere is wanted.
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
        jafaal_ports.is_superuser(db_user),
        new_password,
    )
    identity_service.set_local_password_hash(user_id, hashed_password)

    # Everything the old password could still reach — other sessions, API keys,
    # outstanding reset tokens, a pending-MFA ticket, a step-up grant, a live
    # passkey-registration challenge. The list lives in one place; see
    # credential_sweep for why each entry is on it.
    revoked = credential_sweep.revoke_derived_credentials(
        user_id,
        db,
        reason="password_change",
        revoke_sessions=revoke_other_sessions,
        keep_session_id=current_session_id,
    )

    if revoke_other_sessions:
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
    identity_service: LocalCredentialStore,
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
        jafaal_ports.is_superuser(db_user),
        new_password,
    )
    identity_service.set_local_password_hash(user_id, hashed_password)
    credential_sweep.revoke_derived_credentials(user_id, db, reason="admin_password_change")
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
