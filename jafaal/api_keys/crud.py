"""CRUD operations for user API keys."""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

import jafaal.api_keys.models as api_keys_models
import jafaal.api_keys.schema as api_keys_schema
import jafaal.api_keys.utils as api_keys_utils
import jafaal.audit as jafaal_audit
import jafaal.exceptions as jafaal_exceptions
import jafaal.settings as jafaal_settings
from jafaal._core import db_errors
from jafaal.orm import UserId

logger = logging.getLogger(__name__)


@db_errors.handle_db_errors
def get_api_keys_by_user_id(
    user_id: UserId,
    db: Session,
) -> list[api_keys_models.UsersApiKeys]:
    """
    Retrieve all API keys for a user.

    Args:
        user_id: The ID of the owning user.
        db: SQLAlchemy database session.

    Returns:
        List of API key objects ordered by creation
        date descending.

    Raises:
        JafaalError: If a database error occurs.
    """
    stmt = (
        select(api_keys_models.UsersApiKeys)
        .where(api_keys_models.UsersApiKeys.user_id == user_id)
        .order_by(api_keys_models.UsersApiKeys.created_at.desc())
    )
    return list(db.execute(stmt).scalars().all())


@db_errors.handle_db_errors
def get_api_key_by_id(
    api_key_id: str,
    user_id: UserId,
    db: Session,
) -> api_keys_models.UsersApiKeys | None:
    """
    Retrieve a single API key by its ID and owner.

    Args:
        api_key_id: The UUID of the API key.
        user_id: The ID of the owning user.
        db: SQLAlchemy database session.

    Returns:
        The API key object if found, None otherwise.

    Raises:
        JafaalError: If a database error occurs.
    """
    stmt = select(api_keys_models.UsersApiKeys).where(
        api_keys_models.UsersApiKeys.id == api_key_id,
        api_keys_models.UsersApiKeys.user_id == user_id,
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def get_api_key_by_hash(
    key_hash: str,
    db: Session,
) -> api_keys_models.UsersApiKeys | None:
    """
    Retrieve an API key by its stored digest.

    Used during request authentication to look up the key record from the keyed
    digest of the incoming value.

    Args:
        key_hash: Keyed HMAC-SHA256 digest of the raw key.
        db: SQLAlchemy database session.

    Returns:
        The API key object if found, None otherwise.

    Raises:
        JafaalError: If a database error occurs.
    """
    stmt = select(api_keys_models.UsersApiKeys).where(api_keys_models.UsersApiKeys.key_hash == key_hash)
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def create_api_key(
    user_id: UserId,
    data: api_keys_schema.UsersApiKeyCreate,
    db: Session,
) -> tuple[
    api_keys_models.UsersApiKeys,
    str,
]:
    """
    Create a new API key for a user.

    Generates a cryptographically random key, hashes it
    with SHA-256, and stores only the hash. Returns both
    the ORM object and the raw key so the caller can
    include it in the response (shown once only).

    Args:
        user_id: The ID of the owning user.
        data: Validated creation schema.
        db: SQLAlchemy database session.

    Returns:
        Tuple of (UsersApiKeys ORM object, raw key string).

    Raises:
        JafaalError: If a database error occurs.
    """
    raw_key = api_keys_utils.generate_api_key()
    # Key format is "<prefix>_<random>"; the stored key_prefix is the first 8
    # chars of the random part (after the configured prefix + underscore).
    prefix_len = len(jafaal_settings.get_settings().api_keys.prefix) + 1
    key_prefix = raw_key[prefix_len : prefix_len + 8]
    key_hash = api_keys_utils.hash_api_key(raw_key)
    scopes_json = api_keys_utils.scopes_to_json(data.scopes)

    db_api_key = api_keys_models.UsersApiKeys(
        id=str(uuid.uuid4()),
        user_id=user_id,
        name=data.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        scopes=scopes_json,
        expires_at=data.expires_at,
        last_used_at=None,
        created_at=datetime.now(UTC),
        is_active=True,
    )
    db.add(db_api_key)
    db.flush()
    db.refresh(db_api_key)

    logger.info(
        "API key created",
        extra={
            "user_id": user_id,
            "key_prefix": key_prefix,
            "name": data.name,
        },
    )
    jafaal_audit.record(
        jafaal_audit.Event.API_KEY_CREATED,
        user_id=user_id,
        api_key_id=db_api_key.id,
        key_prefix=key_prefix,
        scopes=list(data.scopes),
        expires_at=data.expires_at.isoformat() if data.expires_at else None,
    )

    return db_api_key, raw_key


@db_errors.handle_db_errors
def update_last_used(
    api_key_id: str,
    db: Session,
) -> None:
    """
    Update the last_used_at timestamp for an API key.

    Args:
        api_key_id: The UUID of the API key.
        db: SQLAlchemy database session.

    Raises:
        NotFoundError: If the key is not found.
        InternalError: If a database error occurs.
    """
    stmt = select(api_keys_models.UsersApiKeys).where(api_keys_models.UsersApiKeys.id == api_key_id)
    db_api_key = db.execute(stmt).scalar_one_or_none()

    if db_api_key is None:
        raise jafaal_exceptions.NotFoundError(f"API key {api_key_id} not found")

    db_api_key.last_used_at = datetime.now(UTC)
    db.flush()


@db_errors.handle_db_errors
def rekey_api_key_digest(
    api_key_id: str,
    new_key_hash: str,
    db: Session,
) -> None:
    """
    Rewrite an API key's stored digest under the current primary signing key.

    Called when a key was located via a ``secret_key_fallbacks`` digest: unlike
    sessions (which re-key themselves on the next refresh) an API key is
    long-lived and never rewritten, so without this it would stop authenticating
    the moment the old key is dropped from the fallback list.

    Args:
        api_key_id: The UUID of the API key.
        new_key_hash: Digest computed under the primary subkey.
        db: SQLAlchemy database session.

    Raises:
        InternalError: If a database error occurs.
    """
    stmt = (
        update(api_keys_models.UsersApiKeys)
        .where(api_keys_models.UsersApiKeys.id == api_key_id)
        .values(key_hash=new_key_hash)
    )
    db.execute(stmt)
    db.flush()


@db_errors.handle_db_errors
def revoke_api_key(
    api_key_id: str,
    user_id: UserId,
    db: Session,
) -> None:
    """
    Revoke an API key by setting is_active to False.

    Soft-delete: the record is retained for audit purposes
    but the key will be rejected on next use.

    Args:
        api_key_id: The UUID of the API key.
        user_id: The ID of the owning user.
        db: SQLAlchemy database session.

    Raises:
        NotFoundError: If the key is not found or does not belong to the user.
        InternalError: If a database error occurs.
    """
    db_api_key = get_api_key_by_id(api_key_id, user_id, db)

    if db_api_key is None:
        raise jafaal_exceptions.NotFoundError(f"API key {api_key_id} not found for user {user_id}")

    db_api_key.is_active = False
    db.flush()

    logger.info(
        "API key revoked",
        extra={
            "api_key_id": api_key_id,
            "user_id": user_id,
        },
    )
    jafaal_audit.record(
        jafaal_audit.Event.API_KEY_REVOKED,
        level=logging.WARNING,
        user_id=user_id,
        api_key_id=api_key_id,
        key_prefix=db_api_key.key_prefix,
    )


@db_errors.handle_db_errors
def delete_api_key(
    api_key_id: str,
    user_id: UserId,
    db: Session,
) -> None:
    """
    Permanently delete an API key.

    Hard-delete for GDPR-style removal. The key hash is
    gone and cannot be authenticated against after this.

    Args:
        api_key_id: The UUID of the API key.
        user_id: The ID of the owning user.
        db: SQLAlchemy database session.

    Raises:
        NotFoundError: If the key is not found or does not belong to the user.
        InternalError: If a database error occurs.
    """
    db_api_key = get_api_key_by_id(api_key_id, user_id, db)

    if db_api_key is None:
        raise jafaal_exceptions.NotFoundError(f"API key {api_key_id} not found for user {user_id}")

    # Read the prefix before the row is gone; it is the only handle the audit
    # trail keeps on a hard-deleted key.
    key_prefix = db_api_key.key_prefix
    db.delete(db_api_key)
    db.flush()

    logger.info(
        "API key deleted",
        extra={
            "api_key_id": api_key_id,
            "user_id": user_id,
        },
    )
    jafaal_audit.record(
        jafaal_audit.Event.API_KEY_DELETED,
        level=logging.WARNING,
        user_id=user_id,
        api_key_id=api_key_id,
        key_prefix=key_prefix,
    )
