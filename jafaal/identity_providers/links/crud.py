"""CRUD operations for user identity provider links."""

from datetime import UTC, datetime

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.links.models as jafaal_identity_links_models
from jafaal._core import db_errors


@db_errors.handle_db_errors
def check_user_identity_providers_by_idp_id(
    idp_id: int,
    db: Session,
) -> bool:
    """
    Check if any user links exist for an identity provider.

    Args:
        idp_id: The ID of the identity provider.
        db: SQLAlchemy database session.

    Returns:
        True if at least one user is linked, False otherwise.

    Raises:
        JafaalError: 500 error if database query fails.
    """
    stmt = select(exists().where(jafaal_identity_links_models.IdentityLink.idp_id == idp_id))
    return db.execute(stmt).scalar() or False


@db_errors.handle_db_errors
def get_user_identity_providers_by_user_id(
    user_id: int,
    db: Session,
) -> list[jafaal_identity_links_models.IdentityLink]:
    """
    Retrieve all identity provider links for a user.

    Args:
        user_id: The ID of the user.
        db: SQLAlchemy database session.

    Returns:
        List of IdentityLink objects linked to the user.

    Raises:
        JafaalError: 500 error if database query fails.
    """
    stmt = select(jafaal_identity_links_models.IdentityLink).where(
        jafaal_identity_links_models.IdentityLink.user_id == user_id
    )
    return list(db.execute(stmt).scalars().all())


@db_errors.handle_db_errors
def get_user_identity_provider_by_user_id_and_idp_id(
    user_id: int,
    idp_id: int,
    db: Session,
) -> jafaal_identity_links_models.IdentityLink | None:
    """
    Retrieve identity provider link for a user.

    Args:
        user_id: The ID of the user.
        idp_id: The ID of the identity provider.
        db: SQLAlchemy database session.

    Returns:
        The IdentityLink instance if found, None
        otherwise.

    Raises:
        JafaalError: 500 error if database query fails.
    """
    stmt = select(jafaal_identity_links_models.IdentityLink).where(
        jafaal_identity_links_models.IdentityLink.user_id == user_id,
        jafaal_identity_links_models.IdentityLink.idp_id == idp_id,
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def get_user_identity_provider_by_subject_and_idp_id(
    idp_id: int,
    idp_subject: str,
    db: Session,
) -> jafaal_identity_links_models.IdentityLink | None:
    """
    Retrieve identity provider link by IdP and subject.

    Args:
        idp_id: The ID of the identity provider.
        idp_subject: The subject identifier from the IdP.
        db: SQLAlchemy database session.

    Returns:
        The matching IdentityLink record if found,
        None otherwise.

    Raises:
        JafaalError: 500 error if database query fails.
    """
    stmt = select(jafaal_identity_links_models.IdentityLink).where(
        jafaal_identity_links_models.IdentityLink.idp_id == idp_id,
        jafaal_identity_links_models.IdentityLink.idp_subject == idp_subject,
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def create_user_identity_provider(
    user_id: int,
    idp_id: int,
    idp_subject: str,
    db: Session,
) -> jafaal_identity_links_models.IdentityLink:
    """
    Create a link between a user and an identity provider.

    Args:
        user_id: The ID of the user to link.
        idp_id: The ID of the identity provider.
        idp_subject: The subject identifier from the IdP.
        db: SQLAlchemy database session.

    Returns:
        The newly created IdentityLink link object.

    Raises:
        ConflictError: 409 error if link already exists.
        InternalError: 500 error if database operation fails.
    """
    db_link = jafaal_identity_links_models.IdentityLink(
        user_id=user_id,
        idp_id=idp_id,
        idp_subject=idp_subject,
        last_login=func.now(),
    )
    db.add(db_link)
    try:
        db.commit()
    except IntegrityError as err:
        db.rollback()
        raise jafaal_exceptions.ConflictError("Identity provider already linked") from err
    db.refresh(db_link)
    return db_link


@db_errors.handle_db_errors
def update_user_identity_provider_last_login(
    user_id: int,
    idp_id: int,
    db: Session,
) -> jafaal_identity_links_models.IdentityLink | None:
    """
    Update last login timestamp for a user-IdP link.

    Args:
        user_id: The ID of the user.
        idp_id: The ID of the identity provider.
        db: SQLAlchemy database session.

    Returns:
        The updated IdentityLink link if found, None
        otherwise.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    db_link = get_user_identity_provider_by_user_id_and_idp_id(
        user_id,
        idp_id,
        db,
    )
    if db_link:
        db_link.last_login = datetime.now(UTC)
        db.commit()
        db.refresh(db_link)
    return db_link


@db_errors.handle_db_errors
def store_user_identity_provider_tokens(
    user_id: int,
    idp_id: int,
    encrypted_refresh_token: str,
    access_token_expires_at: datetime,
    db: Session,
) -> jafaal_identity_links_models.IdentityLink | None:
    """
    Store encrypted IdP tokens for a user-IdP link.

    Token must be pre-encrypted with Fernet before calling.

    Args:
        user_id: The ID of the user.
        idp_id: The ID of the identity provider.
        encrypted_refresh_token: Fernet-encrypted refresh token.
        access_token_expires_at: Access token expiry time.
        db: SQLAlchemy database session.

    Returns:
        The updated IdentityLink link if found, None
        otherwise.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    db_link = get_user_identity_provider_by_user_id_and_idp_id(
        user_id,
        idp_id,
        db,
    )
    if db_link:
        db_link.idp_refresh_token = encrypted_refresh_token
        db_link.idp_access_token_expires_at = access_token_expires_at
        db_link.idp_refresh_token_updated_at = datetime.now(UTC)
        db.commit()
        db.refresh(db_link)
    return db_link


@db_errors.handle_db_errors
def clear_user_identity_provider_refresh_token_by_user_id_and_idp_id(
    user_id: int,
    idp_id: int,
    db: Session,
) -> bool:
    """
    Clear IdP refresh token and metadata.

    Called when user logs out, token refresh fails, user unlinks
    IdP, or security requires token invalidation.

    Args:
        user_id: The ID of the user.
        idp_id: The ID of the identity provider.
        db: SQLAlchemy database session.

    Returns:
        True if token was cleared, False if link not found.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    db_link = get_user_identity_provider_by_user_id_and_idp_id(
        user_id,
        idp_id,
        db,
    )
    if db_link:
        db_link.idp_refresh_token = None
        db_link.idp_access_token_expires_at = None
        db_link.idp_refresh_token_updated_at = None
        db.commit()
        return True
    return False


@db_errors.handle_db_errors
def delete_user_identity_provider(
    user_id: int,
    idp_id: int,
    db: Session,
) -> bool:
    """
    Delete link between user and identity provider.

    Implements defense-in-depth by clearing sensitive token
    data before deletion.

    Args:
        user_id: The ID of the user.
        idp_id: The ID of the identity provider to unlink.
        db: SQLAlchemy database session.

    Returns:
        True if link was found and deleted, False otherwise.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    db_link = get_user_identity_provider_by_user_id_and_idp_id(
        user_id,
        idp_id,
        db,
    )
    if db_link:
        # Clear sensitive data first (defense in depth)
        db_link.idp_refresh_token = None
        db_link.idp_access_token_expires_at = None
        db_link.idp_refresh_token_updated_at = None
        db.commit()

        # Then delete the link
        db.delete(db_link)
        db.commit()
        return True
    return False


@db_errors.handle_db_errors
def get_identity_link_counts_for_users(
    user_ids: list[int],
    db: Session,
) -> dict[int, int]:
    """
    Return identity provider link count per user in a single query.

    Args:
        user_ids: List of user IDs to count links for.
        db: SQLAlchemy database session.

    Returns:
        Dict mapping user_id to the number of linked IdPs.
        Users with no links are not present in the result (default to 0).

    Raises:
        JafaalError: 500 error if database query fails.
    """
    if not user_ids:
        return {}
    stmt = (
        select(
            jafaal_identity_links_models.IdentityLink.user_id,
            func.count(jafaal_identity_links_models.IdentityLink.id).label("cnt"),
        )
        .where(jafaal_identity_links_models.IdentityLink.user_id.in_(user_ids))
        .group_by(jafaal_identity_links_models.IdentityLink.user_id)
    )
    rows = db.execute(stmt).all()
    return {row.user_id: row.cnt for row in rows}
