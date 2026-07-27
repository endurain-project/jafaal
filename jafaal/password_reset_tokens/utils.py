"""Utility functions for password reset token operations."""

import logging
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.audit as jafaal_audit
import jafaal.credentials.crud as jafaal_credentials_crud
import jafaal.exceptions as jafaal_exceptions
import jafaal.password_policy as jafaal_password_policy
import jafaal.password_reset_tokens.crud as password_reset_tokens_crud
import jafaal.password_reset_tokens.schema as password_reset_tokens_schema
import jafaal.ports as jafaal_ports
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.token_hashing as token_hashing
from jafaal.identity_service import IdentityService
from jafaal.orm import UserId, session_scope

logger = logging.getLogger(__name__)


def create_password_reset_token(user_id: UserId, db: Session) -> tuple[str, datetime]:
    """
    Create and persist a password reset token for a user.

    Args:
        user_id: ID of the user requesting the reset.
        db: Active SQLAlchemy session.

    Returns:
        A ``(token, expires_at)`` tuple: the plaintext token to deliver to the
        user and the exact expiry persisted on the row (so callers surface the
        authoritative expiry rather than recomputing ``now()``). Only the token
        hash is stored in the database.
    """
    # Generate token and hash
    token, token_hash = token_hashing.generate_token_and_hash(token_hashing.KeyPurpose.PASSWORD_RESET)

    # Compute the expiry once so the persisted row and the returned value agree.
    expires_at = datetime.now(UTC) + timedelta(hours=1)

    # Create token object
    reset_token = password_reset_tokens_schema.PasswordResetToken(
        id=str(uuid4()),
        user_id=user_id,
        token_hash=token_hash,
        created_at=datetime.now(UTC),
        expires_at=expires_at,
        used=False,
    )

    # Save to database
    password_reset_tokens_crud.create_password_reset_token(reset_token, db)

    # Return the plain token (not the hash) and its authoritative expiry
    return token, expires_at


async def request_password_reset(email: str, db: Session) -> None:
    """
    Handle a password-reset request for ``email``.

    Enumeration-safe: when the address maps to an active account, a single-use
    reset token is minted and a :class:`~jafaal.ports.PasswordResetRequested`
    event is emitted for the host to deliver (email, SMS, ...). Otherwise nothing
    happens. The function never reveals whether the account exists, and
    event-delivery failures are swallowed (logged) so they cannot change the
    caller's response.

    Args:
        email: The email address supplied in the reset request.
        db: Active SQLAlchemy session.
    """
    user = jafaal_ports.get_user_repository().get_by_email(email, db)
    if user is None or not user.is_active:
        # Don't reveal whether the address maps to an (active) account.
        return

    token, expires_at = create_password_reset_token(user.id, db)
    jafaal_audit.record(
        jafaal_audit.Event.PASSWORD_RESET_REQUESTED,
        user_id=user.id,
        email=user.email,
        expires_at=expires_at.isoformat(),
    )
    event = jafaal_ports.PasswordResetRequested(
        user_id=user.id,
        email=user.email,
        display_name=user.username,
        token=token,
        expires_at=expires_at,
        locale=None,
    )
    try:
        await jafaal_ports.get_event_sink().on_password_reset_requested(event)
    except Exception:
        # Best-effort delivery: never surface a failure — doing so would leak
        # account existence and break the enumeration-safe contract.
        logger.exception("Failed to deliver password-reset event for user %s", user.id)


def use_password_reset_token(
    token: str,
    new_password: str,
    identity_service: IdentityService,
    db: Session,
) -> None:
    """
    Reset a user's password using a valid reset token.

    Args:
        token: Plaintext reset token from the email link.
        new_password: New plaintext password to set.
        identity_service: Identity service dependency.
        db: Active SQLAlchemy session.

    Returns:
        None

    Raises:
        JafaalError: 400 if the token is invalid or expired.
        JafaalError: 422 if the new password fails the account's password policy.
        JafaalError: 500 if password update or token marking fails.
    """
    # Hash the provided token to find the database record. Every candidate
    # digest is tried (primary key first, then any secret_key_fallbacks), so a
    # token minted before a signing-key rotation is still redeemable.
    token_user_id: UserId | None = None
    for token_hash in token_hashing.digest_candidates(token, token_hashing.KeyPurpose.PASSWORD_RESET):
        token_user_id = password_reset_tokens_crud.claim_password_reset_token(token_hash, db)
        if token_user_id is not None:
            break
    if token_user_id is None:
        jafaal_audit.record(
            jafaal_audit.Event.PASSWORD_RESET_COMPLETED,
            outcome=jafaal_audit.Outcome.FAILURE,
            level=logging.WARNING,
            reason="invalid_or_expired_token",
        )
        raise jafaal_exceptions.InvalidRequestError("Invalid or expired password reset token")

    db_user = jafaal_user_guards.get_user_by_id_or_404(token_user_id, db)
    hashed_password = jafaal_password_policy.validate_and_hash_for_user(
        identity_service,
        jafaal_ports.is_superuser(db_user),
        new_password,
    )

    try:
        jafaal_credentials_crud.upsert_password_hash(
            token_user_id,
            hashed_password,
            db,
            commit=False,
        )
        password_reset_tokens_crud.mark_user_password_reset_tokens_used(token_user_id, db)
        jafaal_sessions_crud.delete_sessions_by_user(token_user_id, db, commit=False)
        db.flush()
    except jafaal_exceptions.JafaalError:
        db.rollback()
        raise
    except SQLAlchemyError as err:
        db.rollback()
        raise jafaal_exceptions.InternalError("Failed to reset password") from err

    # Drop any in-flight pending-MFA login that was started with the
    # now-rotated password.
    jafaal_security_stores.clear_pending_mfa_for_user(token_user_id)
    jafaal_audit.record(jafaal_audit.Event.PASSWORD_RESET_COMPLETED, user_id=token_user_id)
    jafaal_audit.record(
        jafaal_audit.Event.SESSION_REVOKED,
        user_id=token_user_id,
        scope="all",
        reason="password_reset",
    )


def delete_invalid_tokens_from_db() -> None:
    """
    Remove expired password reset tokens from the database.

    Opens a new session, deletes expired tokens, and logs the count if any were
        removed.

    Returns:
        None
    """
    # Create a new database session using context manager
    with session_scope() as db:
        # Get num tokens deleted
        num_deleted = password_reset_tokens_crud.delete_expired_password_reset_tokens(db)

        # Log the number of deleted tokens
        if num_deleted > 0:
            logger.info(f"Deleted {num_deleted} expired password reset tokens")
