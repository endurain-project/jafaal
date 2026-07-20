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

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

__all__ = [
    "Base",
    "configure_sessionmaker",
    "get_db",
    "get_sessionmaker",
    "session_scope",
]


class Base(DeclarativeBase):
    """Declarative base shared by JAFAAL models and the host's user model."""


# ---------------------------------------------------------------------------
# Session factory (host-provided)
# ---------------------------------------------------------------------------

_session_factory: sessionmaker[Session] | None = None


def configure_sessionmaker(factory: sessionmaker[Session]) -> None:
    """Install the host's session factory.

    Call once at startup with a ``sessionmaker`` bound to the application's
    engine. Both the :func:`get_db` request dependency and background
    maintenance tasks obtain sessions from it.

    Args:
        factory: A configured ``sessionmaker``.
    """
    global _session_factory
    _session_factory = factory


def get_sessionmaker() -> sessionmaker[Session]:
    """Return the installed session factory.

    Raises:
        RuntimeError: If :func:`configure_sessionmaker` has not been called.
    """
    if _session_factory is None:
        raise RuntimeError(
            "JAFAAL has no session factory. Call jafaal.configure_sessionmaker(sessionmaker(bind=engine)) at startup."
        )
    return _session_factory


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
