"""Extensible base user model for host applications.

JAFAAL does not own a concrete ``users`` table. Instead it ships declarative
SQLAlchemy *mixins* that carry only the columns the authentication layer needs,
leaving the table name, the primary-key type, and every profile column to the
host application.

A host app composes a primary-key mixin with its **own** declarative ``Base``,
adds whatever extra profile columns it needs, then maps JAFAAL's companion tables
into that base with :func:`jafaal.map_models`::

    from sqlalchemy import String
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    import jafaal
    from jafaal import IntPKUserMixin


    class Base(DeclarativeBase):
        ...  # the host owns the base (naming conventions, schema, other models)


    class Account(IntPKUserMixin, Base):
        __tablename__ = "users"

        # Application-specific profile columns:
        display_name: Mapped[str | None] = mapped_column(String(250))
        city: Mapped[str | None] = mapped_column(String(250))


    jafaal.map_models(Base, user_model=Account)

For a UUID primary key, subclass :class:`UUIDPKUserMixin` instead.

**Conventions.** The class may be called anything — ``Account``, ``Member``,
``Person`` — because it is handed to :func:`jafaal.map_models` explicitly rather
than discovered by name. Two things are still required, and both are schema, not
naming: it must be built on the base passed to :func:`jafaal.map_models` (so
JAFAAL's tables share the host's single registry — see :mod:`jafaal.orm`), and it
must map to the ``users`` table, which is what JAFAAL's foreign keys reference.
The reverse
relationships to JAFAAL's tables (``users_sessions``, ``local_credential``,
``auth_mfa`` …) and the ``mfa_enabled`` property are supplied by the mixin; the
host does not declare them.

The mixins are deliberately minimal. Only these fields are consumed by the
auth layer:

* ``id`` — primary key (``int`` or :class:`uuid.UUID`)
* ``username`` — unique login handle
* ``email`` — unique e-mail address
* ``is_active`` — whether the account may authenticate
* ``is_verified`` — whether the e-mail address has been verified

``is_superuser`` ships on the mixin as a convenience, but nothing in the auth
layer requires it: it feeds only the default
:class:`~jafaal.ports.TieredScopeResolver` and the admin password-length policy,
both of which read it defensively. A host with a richer authorisation model
implements :class:`~jafaal.ports.ScopeResolver` and can ignore the column
entirely.

Password hashes are **not** stored on the user model. They live in the
auth-owned ``users_local_credentials`` table (see :mod:`jafaal.credentials`),
so SSO-only accounts simply have no credential row.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String, Uuid
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship
from sqlalchemy.sql import func

if TYPE_CHECKING:
    from jafaal.api_keys.models import UsersApiKeys
    from jafaal.credentials.models import LocalCredential
    from jafaal.identity_providers.link_tokens.models import IdpLinkToken
    from jafaal.identity_providers.links.models import IdentityLink
    from jafaal.mfa.backup_codes.models import MFABackupCode
    from jafaal.mfa.models import UsersMFA
    from jafaal.oauth_state.models import OAuthState
    from jafaal.password_reset_tokens.models import PasswordResetToken
    from jafaal.sessions.models import UsersSessions
    from jafaal.sign_up_tokens.models import SignUpToken
    from jafaal.webauthn.models import WebAuthnCredential

__all__ = [
    "IntPKUserMixin",
    "UUIDPKUserMixin",
    "UserMixin",
]


class UserMixin:
    """Auth-relevant user columns, excluding the primary key.

    This mixin is not mapped on its own. Combine it with a concrete
    primary-key mixin (:class:`IntPKUserMixin` or :class:`UUIDPKUserMixin`)
    and the application's declarative ``Base`` to produce a mapped user
    model. Host applications add their own profile columns and relationships
    on the concrete subclass.
    """

    username: Mapped[str] = mapped_column(
        String(250),
        unique=True,
        index=True,
        nullable=False,
        comment="Unique login handle",
    )
    email: Mapped[str] = mapped_column(
        # RFC 5321 caps an e-mail address at 254 characters.
        String(254),
        unique=True,
        index=True,
        nullable=False,
        comment="Unique e-mail address",
    )
    is_active: Mapped[bool] = mapped_column(
        default=True,
        nullable=False,
        comment="Whether the account may authenticate",
    )
    is_superuser: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        comment="Whether the account holds administrative scope",
    )
    is_verified: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        comment="Whether the e-mail address has been verified",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Row creation timestamp (UTC)",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        comment="Last-update timestamp (UTC)",
    )

    # ------------------------------------------------------------------
    # Reverse relationships to JAFAAL's auth-owned tables.
    #
    # Declared via ``declared_attr`` so any host user model composing this
    # mixin automatically gets the counterparts that JAFAAL's models
    # ``back_populates``. All resolve by class name within JAFAAL's single
    # registry (:data:`jafaal.orm.Base`); the host declares none of them.
    # ------------------------------------------------------------------

    @declared_attr
    def users_sessions(cls) -> Mapped[list[UsersSessions]]:
        return relationship("UsersSessions", back_populates="users", cascade="all, delete-orphan")

    @declared_attr
    def users_api_keys(cls) -> Mapped[list[UsersApiKeys]]:
        return relationship("UsersApiKeys", back_populates="users", cascade="all, delete-orphan")

    @declared_attr
    def password_reset_tokens(cls) -> Mapped[list[PasswordResetToken]]:
        return relationship("PasswordResetToken", back_populates="users", cascade="all, delete-orphan")

    @declared_attr
    def sign_up_tokens(cls) -> Mapped[list[SignUpToken]]:
        return relationship("SignUpToken", back_populates="users", cascade="all, delete-orphan")

    @declared_attr
    def user_identity_providers(cls) -> Mapped[list[IdentityLink]]:
        return relationship("IdentityLink", back_populates="users", cascade="all, delete-orphan")

    @declared_attr
    def idp_link_tokens(cls) -> Mapped[list[IdpLinkToken]]:
        return relationship("IdpLinkToken", back_populates="users", cascade="all, delete-orphan")

    @declared_attr
    def oauth_states(cls) -> Mapped[list[OAuthState]]:
        return relationship("OAuthState", back_populates="users", cascade="all, delete-orphan")

    @declared_attr
    def mfa_backup_codes(cls) -> Mapped[list[MFABackupCode]]:
        return relationship("MFABackupCode", back_populates="users", cascade="all, delete-orphan")

    @declared_attr
    def webauthn_credentials(cls) -> Mapped[list[WebAuthnCredential]]:
        return relationship("WebAuthnCredential", back_populates="users", cascade="all, delete-orphan")

    @declared_attr
    def auth_mfa(cls) -> Mapped[UsersMFA | None]:
        return relationship("UsersMFA", back_populates="users", uselist=False, cascade="all, delete-orphan")

    @declared_attr
    def local_credential(cls) -> Mapped[LocalCredential | None]:
        return relationship("LocalCredential", back_populates="users", uselist=False, cascade="all, delete-orphan")

    @property
    def mfa_enabled(self) -> bool:
        """Return ``True`` when MFA is active for this user."""
        return bool(self.auth_mfa and self.auth_mfa.mfa_enabled)


class IntPKUserMixin(UserMixin):
    """User columns with an auto-incrementing integer primary key.

    Use for applications that prefer compact, sequential identifiers.
    """

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )


class UUIDPKUserMixin(UserMixin):
    """User columns with a UUID primary key.

    The identifier defaults to a random UUID4 generated application-side, so
    it is available before the row is flushed and does not leak account
    counts or creation order.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
