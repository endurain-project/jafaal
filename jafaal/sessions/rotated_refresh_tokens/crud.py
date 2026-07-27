"""CRUD operations for rotated refresh tokens."""

from datetime import datetime
from typing import Any, cast

from sqlalchemy import CursorResult, delete, select, update
from sqlalchemy.orm import Session

import jafaal.sessions.rotated_refresh_tokens.models as rotated_token_models
import jafaal.sessions.rotated_refresh_tokens.schema as rotated_token_schema
from jafaal._core import db_errors


@db_errors.handle_db_errors
def get_rotated_token_by_hash(
    hashed_token: str,
    db: Session,
) -> rotated_token_models.RotatedRefreshToken | None:
    """
    Retrieve a rotated token by its hashed value.

    Args:
        hashed_token: The hashed refresh token to search for.
        db: SQLAlchemy database session.

    Returns:
        The RotatedRefreshToken if found, None otherwise.

    Raises:
        JafaalError: If database error occurs.
    """
    stmt = select(rotated_token_models.RotatedRefreshToken).where(
        rotated_token_models.RotatedRefreshToken.hashed_token == hashed_token
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def create_rotated_token(
    rotated_token: rotated_token_schema.RotatedRefreshTokenCreate,
    db: Session,
) -> rotated_token_models.RotatedRefreshToken:
    """
    Store a rotated refresh token in the database.

    Args:
        rotated_token: The rotated token data to store.
        db: SQLAlchemy database session.

    Returns:
        The created RotatedRefreshToken object.

    Raises:
        JafaalError: If database error occurs.
    """
    db_rotated_token = rotated_token_models.RotatedRefreshToken(
        token_family_id=rotated_token.token_family_id,
        hashed_token=rotated_token.hashed_token,
        rotation_count=rotated_token.rotation_count,
        rotated_at=rotated_token.rotated_at,
        expires_at=rotated_token.expires_at,
        replacement_refresh_token=rotated_token.replacement_refresh_token,
        replacement_refresh_token_exp=rotated_token.replacement_refresh_token_exp,
    )

    db.add(db_rotated_token)
    db.flush()
    db.refresh(db_rotated_token)

    return db_rotated_token


@db_errors.handle_db_errors
def claim_replacement_token(rotated_token_id: int, db: Session) -> bool:
    """Atomically consume a rotated record's stored replacement token.

    The in-grace replay is single-use. Clearing
    ``replacement_refresh_token`` is the claim: a conditional ``UPDATE``
    gated on the column still being populated, so two concurrent replays
    of the same rotated token cannot both win — exactly the pattern
    :func:`~jafaal.sessions.crud.claim_session_for_token_exchange` uses
    for authorization codes.

    Args:
        rotated_token_id: Primary key of the rotated-token record.
        db: SQLAlchemy database session.

    Returns:
        ``True`` if this caller claimed the replay, ``False`` if it had
        already been consumed (or was never stored).

    Raises:
        JafaalError: If database error occurs.
    """
    stmt = (
        update(rotated_token_models.RotatedRefreshToken)
        .where(
            rotated_token_models.RotatedRefreshToken.id == rotated_token_id,
            rotated_token_models.RotatedRefreshToken.replacement_refresh_token.is_not(None),
        )
        .values(replacement_refresh_token=None)
    )
    result = cast(CursorResult[Any], db.execute(stmt))
    db.flush()
    return result.rowcount == 1


@db_errors.handle_db_errors
def delete_expired_tokens(cutoff_time: datetime, db: Session) -> int:
    """
    Delete rotated tokens older than the cutoff time.

    Args:
        cutoff_time: Tokens with expires_at before this deleted.
        db: SQLAlchemy database session.

    Returns:
        Number of tokens deleted.

    Raises:
        JafaalError: If database error occurs.
    """
    stmt = delete(rotated_token_models.RotatedRefreshToken).where(
        rotated_token_models.RotatedRefreshToken.expires_at < cutoff_time
    )
    result = cast(CursorResult[Any], db.execute(stmt))
    db.flush()
    return result.rowcount


@db_errors.handle_db_errors
def delete_by_family(token_family_id: str, db: Session) -> int:
    """
    Delete all rotated tokens for a specific token family.

    Args:
        token_family_id: The family ID to delete tokens for.
        db: SQLAlchemy database session.

    Returns:
        Number of tokens deleted.

    Raises:
        JafaalError: If database error occurs.
    """
    stmt = delete(rotated_token_models.RotatedRefreshToken).where(
        rotated_token_models.RotatedRefreshToken.token_family_id == token_family_id
    )
    result = cast(CursorResult[Any], db.execute(stmt))
    db.flush()
    return result.rowcount
