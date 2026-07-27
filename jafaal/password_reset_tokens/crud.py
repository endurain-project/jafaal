"""CRUD operations for password reset tokens."""

from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, select
from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

import jafaal.password_reset_tokens.models as password_reset_tokens_models
import jafaal.password_reset_tokens.schema as password_reset_tokens_schema
from jafaal._core import db_errors
from jafaal.orm import UserId


@db_errors.handle_db_errors
def create_password_reset_token(
    token: password_reset_tokens_schema.PasswordResetToken,
    db: Session,
) -> password_reset_tokens_models.PasswordResetToken:
    """Create and persist a new password reset token.

    Args:
        token: Schema object with token data to persist.
        db: SQLAlchemy database session.

    Returns:
        The persisted PasswordResetToken ORM instance.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    # Create a new password reset token
    db_token = password_reset_tokens_models.PasswordResetToken(
        id=token.id,
        user_id=token.user_id,
        token_hash=token.token_hash,
        created_at=token.created_at,
        expires_at=token.expires_at,
        used=token.used,
    )

    # Add the token to the database
    db.add(db_token)
    db.flush()
    db.refresh(db_token)

    return db_token


@db_errors.handle_db_errors
def get_password_reset_token_by_hash(
    token_hash: str, db: Session
) -> password_reset_tokens_models.PasswordResetToken | None:
    """Retrieve an unused, unexpired token matching the given hash.

    Args:
        token_hash: The hashed token value to look up.
        db: SQLAlchemy database session.

    Returns:
        The matching PasswordResetToken if found and valid, None otherwise.

    Raises:
        JafaalError: 500 error if database query fails.
    """
    stmt = select(password_reset_tokens_models.PasswordResetToken).where(
        password_reset_tokens_models.PasswordResetToken.token_hash == token_hash,
        password_reset_tokens_models.PasswordResetToken.used.is_(False),
        password_reset_tokens_models.PasswordResetToken.expires_at > datetime.now(UTC),
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def claim_password_reset_token(token_hash: str, db: Session) -> UserId | None:
    """Atomically claim a valid password reset token.

    Args:
        token_hash: Keyed HMAC-SHA256 digest of the plaintext reset token.
        db: SQLAlchemy database session.

    Returns:
        User ID owning the claimed token, or None if the token is missing,
        expired, or already used.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    stmt = (
        sa_update(password_reset_tokens_models.PasswordResetToken)
        .where(
            password_reset_tokens_models.PasswordResetToken.token_hash == token_hash,
            password_reset_tokens_models.PasswordResetToken.used.is_(False),
            password_reset_tokens_models.PasswordResetToken.expires_at > datetime.now(UTC),
        )
        .values(used=True)
        .returning(password_reset_tokens_models.PasswordResetToken.user_id)
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def mark_user_password_reset_tokens_used(user_id: UserId, db: Session) -> int:
    """Mark all unused password reset tokens for a user as used.

    Args:
        user_id: User ID whose reset tokens should be invalidated.
        db: SQLAlchemy database session.

    Returns:
        Number of rows marked as used.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    stmt = (
        sa_update(password_reset_tokens_models.PasswordResetToken)
        .where(
            password_reset_tokens_models.PasswordResetToken.user_id == user_id,
            password_reset_tokens_models.PasswordResetToken.used.is_(False),
        )
        .values(used=True)
    )
    result = cast(CursorResult[Any], db.execute(stmt))
    return result.rowcount or 0


@db_errors.handle_db_errors
def mark_password_reset_token_used(
    token_id: str, db: Session
) -> password_reset_tokens_models.PasswordResetToken | None:
    """Mark a password reset token as used.

    Args:
        token_id: The unique identifier of the token to mark.
        db: SQLAlchemy database session.

    Returns:
        Updated PasswordResetToken instance if found, None otherwise.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    stmt = select(password_reset_tokens_models.PasswordResetToken).where(
        password_reset_tokens_models.PasswordResetToken.id == token_id,
    )
    db_token = db.execute(stmt).scalar_one_or_none()

    if db_token:
        # Mark the token as used
        db_token.used = True
        db.flush()
        db.refresh(db_token)

    return db_token


@db_errors.handle_db_errors
def delete_expired_password_reset_tokens(db: Session) -> int:
    """Delete all expired password reset tokens.

    Args:
        db: SQLAlchemy database session.

    Returns:
        Number of deleted rows.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    stmt = sa_delete(password_reset_tokens_models.PasswordResetToken).where(
        password_reset_tokens_models.PasswordResetToken.expires_at < datetime.now(UTC)
    )
    result = cast(CursorResult[Any], db.execute(stmt))
    db.flush()
    return result.rowcount
