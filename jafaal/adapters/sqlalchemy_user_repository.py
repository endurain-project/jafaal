"""Reference SQLAlchemy :class:`~jafaal.ports.UserRepository`.

A generic adapter over a host user model mapped via :func:`jafaal.map_models` (see
:mod:`jafaal.user_model`). It covers the common case where the auth-relevant
columns (``username``, ``email``, ``is_active``, ``is_verified``) are enough to
create a row.

**Transaction behaviour.** The mutating methods (:meth:`create_local_user`,
:meth:`provision_from_idp`, :meth:`set_email_verified`) commit and refresh so the
generated primary key is populated before JAFAAL writes the linked credential.
This mirrors JAFAAL's "CRUD helpers own their commit" convention.

**Extending.** If your user table has additional NOT NULL columns without
defaults, subclass and override :meth:`create_local_user` /
:meth:`provision_from_idp` to supply them. Override :meth:`sync_from_idp` (a
no-op here) to map refreshed IdP claims onto your profile columns.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select

import jafaal.orm as jafaal_orm
from jafaal.exceptions import NotFoundError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.orm import Session

    from jafaal.ports import IdpIdentity, UserProtocol

__all__ = ["SqlAlchemyUserRepository"]


class SqlAlchemyUserRepository:
    """A ``UserRepository`` backed by the host's SQLAlchemy user model."""

    #: Fallback e-mail domain used when an IdP identity carries no address.
    #: ``.invalid`` is a reserved, non-routable TLD (RFC 6761), so a synthesized
    #: address can never collide with (or be mistaken for) a deliverable one.
    idp_email_fallback_domain: str = "sso.invalid"

    def __init__(self, user_model: type | None = None) -> None:
        """Create the repository.

        Args:
            user_model: The host user class. When ``None`` (the default) it is
                resolved lazily from JAFAAL's registry via
                :func:`jafaal.orm.get_user_model` (the class mapped to the
                ``users`` table), so no wiring is required in the common case.
        """
        self._user_model = user_model

    def _model(self) -> Any:
        return self._user_model if self._user_model is not None else jafaal_orm.get_user_model()

    def get_by_id(self, user_id: Any, db: Session) -> UserProtocol | None:
        return db.get(self._model(), user_id)

    def get_by_email(self, email: str, db: Session) -> UserProtocol | None:
        model = self._model()
        return db.execute(select(model).where(model.email == email)).scalar_one_or_none()

    def get_by_username(self, username: str, db: Session) -> UserProtocol | None:
        model = self._model()
        return db.execute(select(model).where(model.username == username)).scalar_one_or_none()

    def create_local_user(
        self,
        username: str,
        email: str,
        db: Session,
        *,
        is_active: bool,
        is_verified: bool,
    ) -> UserProtocol:
        user = self._model()(username=username, email=email, is_active=is_active, is_verified=is_verified)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def provision_from_idp(self, identity: IdpIdentity, db: Session) -> UserProtocol:
        email = identity.email or f"{identity.suggested_username}@{self.idp_email_fallback_domain}"
        user = self._model()(
            username=identity.suggested_username,
            email=email,
            is_active=True,
            is_verified=identity.email_verified,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def sync_from_idp(self, user_id: Any, claims: Mapping[str, Any], db: Session) -> None:
        # Reference no-op: the host owns its profile shape. Override to map the
        # refreshed ``claims`` onto host-specific columns.
        return None

    def set_email_verified(self, user_id: Any, db: Session, *, activate: bool) -> None:
        user = db.get(self._model(), user_id)
        if user is None:
            raise NotFoundError("User not found")
        user.is_verified = True
        if activate:
            user.is_active = True
        db.commit()
