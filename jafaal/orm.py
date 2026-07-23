"""JAFAAL's SQLAlchemy registry plumbing and database-session helpers.

**Option B (the host owns the ``Base``).** JAFAAL's companion tables and the host
application's user model must live in a *single* declarative registry so that
string relationships (``relationship("Users", ...)``) and cross-table foreign keys
(``ForeignKey("users.id")``) resolve. The host owns that registry; JAFAAL maps its
models **into** it.

Host applications:

1. Own a declarative base and build their ``Users`` model on it::

       from sqlalchemy.orm import DeclarativeBase
       from jafaal import IntPKUserMixin

       class Base(DeclarativeBase):
           ...  # the host's own base (naming conventions, schema, ...)

       class Users(IntPKUserMixin, Base):
           __tablename__ = "users"
           # ...app-specific profile columns...

   The class **must** be named ``Users`` and mapped to the ``users`` table — that
   is how JAFAAL's models resolve their relationships/foreign keys. The reverse
   relationships (``users_sessions``, ``local_credential`` …) are supplied by the
   mixin, so the host does not declare them. (A host that does not want to own a
   base may build ``Users`` on JAFAAL's convenience :data:`Base` and call
   :func:`map_models` with no argument.)

2. Map JAFAAL's tables into that base's registry, once, at startup::

       import jafaal
       jafaal.map_models(Base)   # define + map JAFAAL's companion tables

   This must happen **before** :func:`jafaal.create_auth_router` or any DB use —
   importing a JAFAAL model (or CRUD/router) before it is a configuration error.

3. Register a session factory bound to their own engine::

       from sqlalchemy import create_engine
       from sqlalchemy.orm import sessionmaker

       engine = create_engine(...)
       jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False))
       Base.metadata.create_all(engine)  # dev/tests; use jafaal.migrations in prod

JAFAAL never creates the engine itself; the host owns the connection.
"""

from __future__ import annotations

import importlib
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
    "get_active_base",
    "get_db",
    "get_sessionmaker",
    "get_user_model",
    "is_models_mapped",
    "is_sessionmaker_configured",
    "jafaal_table_names",
    "map_models",
    "mapper_registry",
    "session_scope",
    "user_id_python_type",
]

#: The primary-key type of the host's user table. JAFAAL supports either an
#: integer PK (:class:`jafaal.IntPKUserMixin`) or a UUID PK
#: (:class:`jafaal.UUIDPKUserMixin`); values crossing the boundary (JWT ``sub``,
#: companion-table foreign keys, principals) use this union.
UserId = int | uuid.UUID


class Base(DeclarativeBase):
    """JAFAAL's convenience declarative base.

    Under Option B the **host** owns the registry: define your own
    :class:`~sqlalchemy.orm.DeclarativeBase`, build ``Users`` on it, and pass it
    to :func:`map_models`. Use this default base only if you would rather not own
    one — build ``Users`` on it and call ``map_models()`` with no argument.
    """


#: JAFAAL's default registry (the one behind :data:`Base`). Exposed so a host may
#: build its own base on the *same* registry (``class Base(DeclarativeBase):
#: registry = jafaal.orm.mapper_registry``) instead of passing a base to
#: :func:`map_models`, if it prefers that style.
mapper_registry = Base.registry

# The active declarative base JAFAAL's models are mapped onto; ``None`` until
# ``map_models`` runs. Host-owned under Option B, or :data:`Base` by default.
_active_base: type[DeclarativeBase] | None = None

# Every module that defines a JAFAAL companion model. ``map_models`` imports each
# (order-independent — relationships resolve by name at ``registry.configure()``),
# and each module binds its classes to the active base via ``get_active_base()``.
_MODEL_MODULES: tuple[str, ...] = (
    "jafaal.credentials.models",
    "jafaal.sessions.models",
    "jafaal.sessions.rotated_refresh_tokens.models",
    "jafaal.api_keys.models",
    "jafaal.mfa.models",
    "jafaal.mfa.backup_codes.models",
    "jafaal.identity_providers.models",
    "jafaal.identity_providers.links.models",
    "jafaal.identity_providers.link_tokens.models",
    "jafaal.oauth_state.models",
    "jafaal.password_reset_tokens.models",
    "jafaal.sign_up_tokens.models",
)


def get_active_base() -> type[DeclarativeBase]:
    """Return the declarative base JAFAAL's models are mapped onto.

    Model modules call this at import time to obtain their base, so importing a
    model module (or any CRUD/router that imports one) before :func:`map_models`
    is a configuration error.

    Raises:
        RuntimeError: If :func:`map_models` has not been called yet.
    """
    if _active_base is None:
        raise RuntimeError(
            "JAFAAL's models are not mapped yet. Call jafaal.map_models(YourBase) "
            "(or jafaal.map_models() to use jafaal.orm.Base) once at startup — after "
            "defining your Users model and before create_auth_router() or any DB use."
        )
    return _active_base


def is_models_mapped() -> bool:
    """Return whether :func:`map_models` has been called."""
    return _active_base is not None


def map_models(base: type[DeclarativeBase] | None = None) -> None:
    """Define and map JAFAAL's companion tables into ``base``'s registry.

    Call once at startup, **after** defining your ``Users`` model and **before**
    :func:`jafaal.create_auth_router` or any database use. JAFAAL's models are
    mapped onto the base you pass, so your ``Users`` model and JAFAAL's tables
    share one registry — which is what resolves ``relationship("Users")`` and the
    ``users.id`` foreign keys.

    Args:
        base: The host's :class:`~sqlalchemy.orm.DeclarativeBase` subclass; your
            ``Users`` model must be built on it. Omit it to use JAFAAL's own
            :data:`Base` (the convenience default).

    Raises:
        RuntimeError: If called again with a different base, or if a model
            references a class (e.g. ``Users``) that is not mapped on ``base``.
    """
    global _active_base
    target = base if base is not None else Base
    if _active_base is not None:
        if _active_base is not target:
            raise RuntimeError("jafaal.map_models() was already called with a different base; call it once at startup.")
        return
    _active_base = target
    try:
        for module_name in _MODEL_MODULES:
            importlib.import_module(module_name)
        # Resolve every mapper/relationship now so misconfiguration (e.g. no
        # Users mapped on this base) fails fast at startup, not on first query.
        target.registry.configure()
    except Exception:
        _active_base = None  # let the host fix the problem and retry
        raise


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


def is_sessionmaker_configured() -> bool:
    """Return whether :func:`configure_sessionmaker` has been called."""
    return _session_factory.is_configured()


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
    the active base (see :mod:`jafaal.user_model`), so it is unambiguous within
    the process.

    Raises:
        RuntimeError: If models are not mapped, or no class is mapped to the
            ``users`` table.
    """
    for mapper in get_active_base().registry.mappers:
        table = mapper.local_table
        if table is not None and getattr(table, "name", None) == "users":
            return mapper
    raise RuntimeError(
        "JAFAAL could not find a mapped class for the 'users' table. Build your "
        "Users model on your declarative base and pass it to jafaal.map_models(...) "
        "(see jafaal.user_model)."
    )


def user_id_python_type() -> type:
    """Return the Python type of the host user table's primary key (``int``/``UUID``)."""
    return _resolve_user_mapper().primary_key[0].type.python_type


def get_user_model() -> type:
    """Return the host's user class (the class mapped to the ``users`` table).

    Resolves the single class the host built on :data:`Base` and mapped to
    ``users`` (see :mod:`jafaal.user_model`). Useful for reference adapters such
    as :class:`jafaal.adapters.SqlAlchemyUserRepository` that construct or query
    the user row without the host wiring the class in explicitly.

    Raises:
        RuntimeError: If no class is mapped to the ``users`` table yet.
    """
    return _resolve_user_mapper().class_


def jafaal_table_names() -> frozenset[str]:
    """Return the names of the tables owned by JAFAAL's own models.

    Every table mapped by a class defined under the ``jafaal`` package — i.e. all
    of JAFAAL's companion tables, but **not** the host's ``users`` table (whose
    model lives in the host application, outside ``jafaal.*``) nor any other host
    table sharing the registry.

    The migration tooling (:mod:`jafaal.migrations`) uses this to scope its
    operations to JAFAAL's tables and leave the host-owned ``users`` table alone.
    """
    names: set[str] = set()
    for mapper in get_active_base().registry.mappers:
        if not mapper.class_.__module__.startswith("jafaal."):
            continue
        table = mapper.local_table
        name = getattr(table, "name", None)
        if name:
            names.add(name)
    return frozenset(names)


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
