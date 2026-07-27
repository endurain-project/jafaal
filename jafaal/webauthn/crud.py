"""CRUD operations for WebAuthn (passkey) credentials.

Pure persistence for the ``webauthn_credentials`` table — no ``py_webauthn``
import here, so this module (and :func:`user_has_credentials` in particular) is
safe to call from the always-loaded auth router without the optional
``jafaal[webauthn]`` extra installed.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

import jafaal.webauthn.models as webauthn_models
from jafaal._core import db_errors
from jafaal.orm import UserId

logger = logging.getLogger(__name__)


@db_errors.handle_db_errors
def get_credentials_by_user_id(
    user_id: UserId,
    db: Session,
) -> list[webauthn_models.WebAuthnCredential]:
    """Return all passkeys owned by ``user_id``, newest first."""
    stmt = (
        select(webauthn_models.WebAuthnCredential)
        .where(webauthn_models.WebAuthnCredential.user_id == user_id)
        .order_by(webauthn_models.WebAuthnCredential.created_at.desc())
    )
    return list(db.execute(stmt).scalars().all())


@db_errors.handle_db_errors
def get_credential_by_credential_id(
    credential_id: str,
    db: Session,
) -> webauthn_models.WebAuthnCredential | None:
    """Look up a passkey by its base64url ``credential_id`` (used at authentication)."""
    stmt = select(webauthn_models.WebAuthnCredential).where(
        webauthn_models.WebAuthnCredential.credential_id == credential_id
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def get_credential_by_pk(
    pk: int,
    user_id: UserId,
    db: Session,
) -> webauthn_models.WebAuthnCredential | None:
    """Look up a passkey by surrogate key, scoped to its owner."""
    stmt = select(webauthn_models.WebAuthnCredential).where(
        webauthn_models.WebAuthnCredential.id == pk,
        webauthn_models.WebAuthnCredential.user_id == user_id,
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def user_has_credentials(
    user_id: UserId,
    db: Session,
) -> bool:
    """Return whether ``user_id`` has at least one registered passkey."""
    stmt = (
        select(func.count())
        .select_from(webauthn_models.WebAuthnCredential)
        .where(webauthn_models.WebAuthnCredential.user_id == user_id)
    )
    return bool(db.execute(stmt).scalar_one())


@db_errors.handle_db_errors
def create_credential(
    *,
    user_id: UserId,
    credential_id: str,
    public_key: str,
    sign_count: int,
    transports: str | None,
    aaguid: str | None,
    label: str | None,
    backup_eligible: bool | None,
    backup_state: bool | None,
    db: Session,
) -> webauthn_models.WebAuthnCredential:
    """Persist a newly registered passkey and return the stored row."""
    credential = webauthn_models.WebAuthnCredential(
        user_id=user_id,
        credential_id=credential_id,
        public_key=public_key,
        sign_count=sign_count,
        transports=transports,
        aaguid=aaguid,
        label=label,
        backup_eligible=backup_eligible,
        backup_state=backup_state,
        created_at=datetime.now(UTC),
    )
    db.add(credential)
    db.flush()
    db.refresh(credential)
    return credential


@db_errors.handle_db_errors
def update_sign_count(
    credential: webauthn_models.WebAuthnCredential,
    new_sign_count: int,
    db: Session,
) -> None:
    """Record the authenticator's new signature counter and last-used time."""
    credential.sign_count = new_sign_count
    credential.last_used_at = datetime.now(UTC)
    db.add(credential)
    db.flush()


@db_errors.handle_db_errors
def delete_credential(
    credential: webauthn_models.WebAuthnCredential,
    db: Session,
) -> None:
    """Delete a passkey."""
    db.delete(credential)
    db.flush()
