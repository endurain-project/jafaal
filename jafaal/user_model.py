"""Extensible base user model for host applications.

JAFAAL does not own a concrete ``users`` table. Instead it ships declarative
SQLAlchemy *mixins* that carry only the columns the authentication layer needs,
leaving the table name, the primary-key type, and every profile column to the
host application.

A host app composes a primary-key mixin with its own declarative ``Base`` and
adds whatever extra columns and relationships it needs::

    from sqlalchemy import String
    from sqlalchemy.orm import Mapped, mapped_column

    from myapp.database import Base  # the app's own DeclarativeBase
    from jafaal.user_model import IntPKUserMixin


    class User(IntPKUserMixin, Base):
        __tablename__ = "users"

        # Application-specific profile columns:
        display_name: Mapped[str | None] = mapped_column(String(250))
        city: Mapped[str | None] = mapped_column(String(250))

For a UUID primary key, subclass :class:`UUIDPKUserMixin` instead::

    class User(UUIDPKUserMixin, Base):
        __tablename__ = "users"

The mixins are deliberately minimal. Only these fields are consumed by the
auth layer:

* ``id`` — primary key (``int`` or :class:`uuid.UUID`)
* ``username`` — unique login handle
* ``email`` — unique e-mail address
* ``is_active`` — whether the account may authenticate
* ``is_superuser`` — whether the account holds administrative scope
* ``is_verified`` — whether the e-mail address has been verified

Password hashes are **not** stored on the user model. They live in the
auth-owned ``users_local_credentials`` table (see :mod:`jafaal.credentials`),
so SSO-only accounts simply have no credential row.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

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
