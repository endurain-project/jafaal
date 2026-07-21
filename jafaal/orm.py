"""JAFAAL's SQLAlchemy declarative base and database-session plumbing.

**Option A (jafaal owns the Base).** JAFAAL's companion tables and the host
application's user model must live in a *single* declarative registry so that
string relationships (``relationship("Users", ...)``) and cross-table foreign
keys (``ForeignKey("users.id")``) resolve. JAFAAL provides that registry here.

Host applications:

1. Build their user model on this ``Base``::

       from jafaal.orm import Base
       from jafaal import IntPKUserMixin

       class Users(IntPKUserMixin, Base):
           __tablename__ = "users"
           # ...app-specific profile columns...

   The class **must** be named ``Users`` and mapped to the ``users`` table —
   that is how JAFAAL's models resolve their relationships/foreign keys. The
   reverse relationships (``users_sessions``, ``local_credential`` …) are
   supplied by the mixin, so the host does not declare them.

2. Register a session factory bound to their own engine::

       from sqlalchemy import create_engine
       from sqlalchemy.orm import sessionmaker
       import jafaal

       engine = create_engine(...)
       jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False))
       jafaal.orm.Base.metadata.create_all(engine)  # or use migrations

JAFAAL never creates the engine itself; the host owns the connection.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy.orm import DeclarativeBase, Mapper, Session, sessionmaker

from jafaal._core.registry import ConfigSlot

__all__ = [
    "Base",
    "UserId",
    "coerce_user_id",
    "configure_sessionmaker",
    "get_db",
    "get_sessionmaker",
    "session_scope",
    "user_id_python_type",
]

#: The primary-key type of the host's user table. JAFAAL supports either an
#: integer PK (:class:`jafaal.IntPKUserMixin`) or a UUID PK
#: (:class:`jafaal.UUIDPKUserMixin`); values crossing the boundary (JWT ``sub``,
#: companion-table foreign keys, principals) use this union.
UserId = int | uuid.UUID


class Base(DeclarativeBase):
    """Declarative base shared by JAFAAL models and the host's user model."""


# ---------------------------------------------------------------------------
# Session factory (host-provided)
# ---------------------------------------------------------------------------

_session_factory: ConfigSlot[sessionmaker[Session]] = ConfigSlot(
    missing_message=(
        "JAFAAL has no session factory. Call jafaal.configure_sessionmaker(sessionmaker(bind=engine)) at startup."
    )
)


def configure_sessionmaker(factory: sessionmaker[Session]) -> None:
    """Install the host's session factory.

    Call once at startup with a ``sessionmaker`` bound to the application's
    engine. Both the :func:`get_db` request dependency and background
    maintenance tasks obtain sessions from it.

    Args:
        factory: A configured ``sessionmaker``.
    """
    _session_factory.configure(factory)


def get_sessionmaker() -> sessionmaker[Session]:
    """Return the installed session factory.

    Raises:
        RuntimeError: If :func:`configure_sessionmaker` has not been called.
    """
    return _session_factory.get()


def get_db() -> Generator[Session]:
    """FastAPI dependency that yields a request-scoped session.

    Rolls back on any unhandled exception so partial writes are never silently
    committed, then closes the session.
    """
    db = get_sessionmaker()()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def session_scope() -> Generator[Session]:
    """Context manager yielding a session for non-request (background) work.

    Replaces the former ``with session_scope() as db:`` usage in maintenance
    tasks. The caller is responsible for committing; the session is closed on
    exit (rolling back any pending transaction).
    """
    db = get_sessionmaker()()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# User-id typing helpers (int vs UUID primary key)
# ---------------------------------------------------------------------------


def _resolve_user_mapper() -> Mapper[Any]:
    """Return the mapper of the host's user class (the class mapped to ``users``).

    JAFAAL requires the host user model to be mapped to the ``users`` table on
    this ``Base`` (see :mod:`jafaal.user_model`), so it is unambiguous within the
    process.

    Raises:
        RuntimeError: If no class is mapped to the ``users`` table yet.
    """
    for mapper in Base.registry.mappers:
        table = mapper.local_table
        if table is not None and getattr(table, "name", None) == "users":
            return mapper
    raise RuntimeError(
        "JAFAAL could not find a mapped class for the 'users' table. Build your "
        "user model on jafaal.orm.Base (see jafaal.user_model)."
    )


def user_id_python_type() -> type:
    """Return the Python type of the host user table's primary key (``int``/``UUID``)."""
    return _resolve_user_mapper().primary_key[0].type.python_type


def coerce_user_id(value: Any) -> Any:
    """Coerce a boundary user-id value to the host user table's PK type.

    The JWT ``sub`` claim is JSON, so a UUID primary key arrives as a string;
    this converts it back to :class:`uuid.UUID` (or to ``int``) so repository
    lookups (``session.get(Users, id)``) receive the native key type. Integer
    hosts are unaffected — an ``int`` ``sub`` stays an ``int``.

    Args:
        value: The user id as received across the boundary (int, UUID, or str).

    Returns:
        The value coerced to the user table's primary-key type. ``None`` passes
        through unchanged.
    """
    if value is None:
        return None
    target = user_id_python_type()
    if isinstance(value, target) and not isinstance(value, bool):
        return value
    if target is uuid.UUID:
        return uuid.UUID(str(value))
    if target is int:
        return int(value)
    return value
