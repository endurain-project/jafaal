"""CRUD helpers for the ``users_local_credentials`` 1:1 companion table.

These helpers own persistence for a user's local password hash. They are the
single write/read path for the credential table and are consumed by the auth
boundary (``IdentityService``) rather than directly by non-auth modules.
"""

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

import jafaal.credentials.models as jafaal_credentials_models
from jafaal._core import db_errors
from jafaal.orm import UserId


@db_errors.handle_db_errors
def get_credential(
    user_id: UserId,
    db: Session,
) -> jafaal_credentials_models.LocalCredential | None:
    """
    Return a user's local credential row, or ``None`` when absent.

    A missing row means the account has no local password (for example an
    SSO-only account).

    Args:
        user_id: ID of the user to fetch the credential for.
        db: SQLAlchemy database session.

    Returns:
        The user's ``LocalCredential`` row, or ``None`` if none exists.

    Raises:
        JafaalError: 500 if a database error occurs.
    """
    stmt = select(jafaal_credentials_models.LocalCredential).where(
        jafaal_credentials_models.LocalCredential.user_id == user_id,
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def upsert_password_hash(
    user_id: UserId,
    password_hash: str,
    db: Session,
    commit: bool = True,
    *,
    must_change: bool | None = None,
) -> None:
    """
    Insert or update a user's local password hash.

    Creates the credential row when none exists yet, otherwise updates the
    stored hash in place. The 1:1 invariant with ``users`` is preserved.

    Args:
        user_id: ID of the user to write the credential for.
        password_hash: Argon2 password hash to store.
        db: SQLAlchemy database session.
        commit: Whether to commit immediately. Pass ``False`` to bundle the
            write into a larger transaction owned by the caller.
        must_change: Whether the new password must be replaced before the
            account can log in. ``None`` (the default) leaves the existing flag
            untouched, which is what the rehash-on-verify path needs: raising
            the Argon2 cost parameters rewrites the hash without the password
            having changed, and must not clear a pending change requirement.

    Returns:
        None.

    Raises:
        JafaalError: 500 if a database error occurs.
    """
    stmt = select(jafaal_credentials_models.LocalCredential).where(
        jafaal_credentials_models.LocalCredential.user_id == user_id,
    )
    credential = db.execute(stmt).scalar_one_or_none()
    if credential is None:
        credential = jafaal_credentials_models.LocalCredential(
            user_id=user_id,
            password_hash=password_hash,
            must_change_password=bool(must_change),
        )
        db.add(credential)
    else:
        credential.password_hash = password_hash
        if must_change is not None:
            credential.must_change_password = must_change

    if commit:
        db.flush()


@db_errors.handle_db_errors
def delete_credential(
    user_id: UserId,
    db: Session,
) -> None:
    """
    Delete a user's local credential row if one exists.

    Used to demote a local account to SSO-only. A no-op when the user has no
    credential row.

    Args:
        user_id: ID of the user whose credential should be removed.
        db: SQLAlchemy database session.

    Returns:
        None.

    Raises:
        JafaalError: 500 if a database error occurs.
    """
    db.execute(
        delete(jafaal_credentials_models.LocalCredential).where(
            jafaal_credentials_models.LocalCredential.user_id == user_id,
        )
    )
    db.flush()
