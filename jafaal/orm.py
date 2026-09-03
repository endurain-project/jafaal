"""JAFAAL's SQLAlchemy registry plumbing and database-session helpers.

**Option B (the host owns the ``Base``).** JAFAAL's companion tables and the host
application's user model must live in a *single* declarative registry so that
relationships and cross-table foreign keys (``ForeignKey("users.id")``) resolve.
The host owns that registry; JAFAAL maps its models **into** it.

Host applications:

1. Own a declarative base and build their user model on it::

       from sqlalchemy.orm import DeclarativeBase
       from jafaal import IntPKUserMixin

       class Base(DeclarativeBase):
           ...  # the host's own base (naming conventions, schema, ...)

       class Account(IntPKUserMixin, Base):
           __tablename__ = "users"
           # ...app-specific profile columns...

   The class may be called anything; it is handed to :func:`map_models`
   explicitly, so JAFAAL never looks it up by name. It must map to the ``users``
   table, which is what JAFAAL's foreign keys reference. The reverse
   relationships (``users_sessions``, ``local_credential`` …) are supplied by the
   mixin, so the host does not declare them. (A host that does not want to own a
   base may build its user model on JAFAAL's convenience :data:`Base` and call
   :func:`map_models` without one.)

2. Map JAFAAL's tables into that base's registry, once, at startup::

       import jafaal
       jafaal.map_models(Base, user_model=Account)

   This must happen **before** :func:`jafaal.create_auth_router` or any DB use —
   importing a JAFAAL model (or CRUD/router) before it is a configuration error.

3. Register a session factory bound to their own engine::

       from sqlalchemy import create_engine
       from sqlalchemy.orm import sessionmaker

       engine = create_engine(...)
       jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False))
       Base.metadata.create_all(engine)  # dev/tests; use jafaal.migrations in prod

JAFAAL never creates the engine itself; the host owns the connection.

**Transaction ownership.** Every JAFAAL function that accepts a ``Session``
participates in the *caller's* transaction and never commits — the CRUD layer
only flushes. JAFAAL's own endpoints open exactly one transaction per request via
:func:`transactional`; a host calling JAFAAL's services directly wraps them in
:func:`unit_of_work` (or its own ``session.begin()``), so JAFAAL's writes and the
host's commit or roll back together.
"""

from __future__ import annotations

import importlib
import logging
import uuid
from collections.abc import Callable, Coroutine, Generator
from contextlib import contextmanager
from typing import Any, cast

from fastapi import APIRouter, Request, Response
from fastapi.routing import APIRoute
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase, Mapper, Session, sessionmaker

from jafaal._core.registry import ConfigSlot

logger = logging.getLogger(__name__)

__all__ = [
    "Base",
    "TransactionalRoute",
    "UserId",
    "auth_router",
    "autonomous_session",
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
    "savepoint",
    "session_scope",
    "unit_of_work",
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
    one — build the user model on it and call ``map_models()`` without a base.
    """


#: JAFAAL's default registry (the one behind :data:`Base`). Exposed so a host may
#: build its own base on the *same* registry (``class Base(DeclarativeBase):
#: registry = jafaal.orm.mapper_registry``) instead of passing a base to
#: :func:`map_models`, if it prefers that style.
mapper_registry = Base.registry

# The active declarative base JAFAAL's models are mapped onto; ``None`` until
# ``map_models`` runs. Host-owned under Option B, or :data:`Base` by default.
_active_base: type[DeclarativeBase] | None = None

# The host's user class, supplied to ``map_models``. Every JAFAAL model resolves
# its ``users`` relationship through this, which is what frees the host to name
# the class whatever fits its own domain.
_user_model: ConfigSlot[type] = ConfigSlot(
    missing_message=(
        "JAFAAL does not know the host's user model. Call jafaal.map_models(Base, user_model=YourUserClass) at startup."
    )
)


def host_user_model() -> type:
    """Return the host's user class, for a relationship target.

    Used as ``relationship(host_user_model, ...)`` in JAFAAL's own models.
    SQLAlchemy calls it lazily at ``registry.configure()`` time, so the target
    resolves through the host's registration rather than through a hard-coded
    class name.
    """
    return get_user_model()


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
    "jafaal.webauthn.models",
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
            "JAFAAL's models are not mapped yet. Call "
            "jafaal.map_models(YourBase, user_model=YourUserClass) once at startup — after "
            "defining your user model and before create_auth_router() or any DB use. "
            "Omit the base to use jafaal.orm.Base."
        )
    return _active_base


def is_models_mapped() -> bool:
    """Return whether :func:`map_models` has been called."""
    return _active_base is not None


def map_models(base: type[DeclarativeBase] | None = None, *, user_model: type | None = None) -> None:
    """Define and map JAFAAL's companion tables into ``base``'s registry.

    Call once at startup, **after** defining your user model and **before**
    :func:`jafaal.create_auth_router` or any database use. JAFAAL's models are
    mapped onto the base you pass, so your user model and JAFAAL's tables share
    one registry — which is what resolves the ``users.id`` foreign keys.

    Args:
        base: The host's :class:`~sqlalchemy.orm.DeclarativeBase` subclass; your
            user model must be built on it. Omit it to use JAFAAL's own
            :data:`Base` (the convenience default).
        user_model: The host's user class. Passing it explicitly is what lets the
            class be called anything — ``Account``, ``Member``, ``Person``.
            Omitted, JAFAAL falls back to whichever class is mapped to the
            ``users`` table, which is unambiguous but silently constrains the
            host's schema; pass it.

    Raises:
        RuntimeError: If called again with a different base or user model, or if
            a model references a class that is not mapped on ``base``.
    """
    global _active_base
    target = base if base is not None else Base
    if _active_base is not None:
        if _active_base is not target:
            raise RuntimeError("jafaal.map_models() was already called with a different base; call it once at startup.")
        if user_model is not None and _user_model.is_configured() and _user_model.get() is not user_model:
            raise RuntimeError(
                "jafaal.map_models() was already called with a different user_model; call it once at startup."
            )
        return
    _active_base = target
    if user_model is not None:
        _user_model.configure(user_model)
    try:
        for module_name in _MODEL_MODULES:
            importlib.import_module(module_name)
        # Resolve every mapper/relationship now so misconfiguration (e.g. no
        # user model mapped on this base) fails fast at startup, not on first
        # query.
        target.registry.configure()
    except Exception:
        _active_base = None  # let the host fix the problem and retry
        _user_model.reset()
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


def get_db(request: Request) -> Generator[Session]:
    """FastAPI dependency that yields a request-scoped session.

    The session is yielded with **nothing committed** — JAFAAL's CRUD layer only
    ever flushes. The commit is issued once per request by
    :class:`TransactionalRoute` (the route class every JAFAAL router uses), or by
    the host when it drives JAFAAL's services itself.

    The session is published on ``request.state`` so the route class can find it
    without every endpoint having to declare it.

    Rolls back on any unhandled exception so partial writes are never silently
    committed, then closes the session.
    """
    db = get_sessionmaker()()
    request.state.jafaal_db = db
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Unit of work
#
# JAFAAL never commits below its own HTTP boundary. Every function that accepts
# a ``Session`` participates in the *caller's* transaction and only flushes, so
# a host can compose several JAFAAL operations — and its own writes — into one
# atomic unit. JAFAAL's own endpoints are that caller for the routes it ships,
# and open exactly one unit of work per request via :class:`TransactionalRoute`.
#
# The commit deliberately lives in the route handler rather than in ``get_db``'s
# teardown: FastAPI closes ``yield``-dependencies *after* the route handler
# returns (verified against the pinned FastAPI version by
# ``tests/test_transactions.py``), which is outside the window where a failing
# commit could still be turned into a response by the JafaalError edge handler.
# ---------------------------------------------------------------------------

_UOW_FLAG = "jafaal_unit_of_work"
_AFTER_COMMIT_CALLBACKS = "jafaal_after_commit_callbacks"


def defer_until_commit(db: Session, callback: Callable[[], None]) -> None:
    """Run ``callback`` only after the request transaction commits."""
    callbacks = db.info.setdefault(_AFTER_COMMIT_CALLBACKS, [])
    callbacks.append(callback)


def _run_after_commit_callbacks(db: Session) -> None:
    callbacks = db.info.pop(_AFTER_COMMIT_CALLBACKS, ())
    for callback in callbacks:
        try:
            callback()
        except Exception as err:  # pragma: no cover - defensive adapter boundary
            logger.warning("Post-commit callback failed: %s", type(err).__name__, exc_info=err)


def _discard_after_commit_callbacks(db: Session) -> None:
    db.info.pop(_AFTER_COMMIT_CALLBACKS, None)


@contextmanager
def unit_of_work(db: Session) -> Generator[Session]:
    """Commit ``db`` on clean exit, roll it back on failure.

    The supported way for a **host** to compose JAFAAL calls with its own writes::

        with jafaal.unit_of_work(db):
            user = repo.create_local_user(...)
            identity_service.set_local_password_hash(user.id, hashed)
            db.add(MyProfile(user_id=user.id))
        # one commit; any failure rolls back all three

    Re-entrant: when a unit of work is already open on this session, the inner
    block joins it and the *outermost* scope decides the outcome. That is what
    makes "JAFAAL never commits under you" hold even when a JAFAAL service calls
    another internally.

    Args:
        db: The session to own for the duration of the block.

    Yields:
        The same session, for convenience.

    Raises:
        Exception: Whatever the wrapped block raised, after rolling back.
    """
    if db.info.get(_UOW_FLAG):
        yield db
        return
    db.info[_UOW_FLAG] = True
    try:
        yield db
        db.commit()
        _run_after_commit_callbacks(db)
    except Exception:
        _discard_after_commit_callbacks(db)
        db.rollback()
        raise
    finally:
        db.info.pop(_UOW_FLAG, None)


class TransactionalRoute(APIRoute):
    """Route class that commits JAFAAL's request-scoped session exactly once.

    Every JAFAAL router is built with ``APIRouter(route_class=TransactionalRoute)``
    rather than decorating each endpoint, so a *new* endpoint cannot forget to
    commit — the failure mode of per-endpoint decoration, and one that shows up
    as silently discarded writes rather than an error.

    It wraps the whole endpoint invocation, so it runs while the ``get_db``
    dependency is still open and while a raised exception can still be mapped to
    a response by the registered handlers. A read-only request commits an empty
    transaction, which simply releases the connection's read snapshot.
    """

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original_handler = super().get_route_handler()

        async def transactional_handler(request: Request) -> Response:
            try:
                response = await original_handler(request)
            except Exception:
                _rollback_request_session(request)
                raise
            db = getattr(request.state, "jafaal_db", None)
            if db is not None:
                # Outside the try above on purpose: a failing commit must surface
                # as an error response, not be masked by the rollback path.
                db.commit()
                _run_after_commit_callbacks(db)
            return response

        return transactional_handler


def _rollback_request_session(request: Request) -> None:
    """Roll back the request's JAFAAL session, if one was opened."""
    db = getattr(request.state, "jafaal_db", None)
    if db is None:
        return
    try:
        _discard_after_commit_callbacks(db)
        db.rollback()
    except Exception as err:  # pragma: no cover - defensive
        logger.error(f"Rollback failed for the request session: {type(err).__name__}", exc_info=err)


def auth_router() -> APIRouter:
    """Return an ``APIRouter`` wired to :class:`TransactionalRoute`.

    Used by every JAFAAL router module so the transaction policy is applied in
    one place instead of being restated per module.
    """
    return APIRouter(route_class=TransactionalRoute)


@contextmanager
def autonomous_session() -> Generator[Session]:
    """A separate session that commits independently of the caller's transaction.

    The deliberate exception to "the caller owns the transaction", for writes
    whose durability must not depend on the surrounding request succeeding.
    There is exactly one such case in JAFAAL today: claiming a single-use OAuth
    state. Replay protection has to *stick* — if the claim were rolled back when
    the callback later fails, an attacker could deliberately fail the flow to
    release the state and replay the authorization code.

    Committing it separately also keeps the caller's transaction (and its pooled
    connection) from being held open across the several outbound HTTP calls the
    SSO callback then makes.

    Yields:
        A fresh session, committed on clean exit and rolled back on failure.
    """
    db = get_sessionmaker()()
    try:
        with unit_of_work(db):
            yield db
    finally:
        db.close()


@contextmanager
def savepoint(db: Session) -> Generator[Session]:
    """Run a block inside a SAVEPOINT so a failed flush stays recoverable.

    A statement that fails mid-transaction (a UNIQUE violation on flush, say)
    leaves SQLAlchemy's transaction in a pending-rollback state: every later
    statement on that session raises until someone unwinds it. Because JAFAAL
    runs inside the *caller's* transaction it must not unwind the whole thing —
    that would discard the host's pending work too — so a CRUD helper that wants
    to *catch* a constraint violation and translate it (e.g. into a 409) brackets
    the flush in a savepoint and rolls back only that.

    Delegates to ``Session.begin_nested()`` used as a context manager, which is
    the only form that works: unwinding the savepoint by hand
    (``nested.rollback()`` in an ``except``) leaves the *parent* transaction
    holding the captured flush exception, so the caller's later ``commit()``
    still raises ``PendingRollbackError``. SQLAlchemy's own ``__exit__`` clears
    it. ``tests/test_transactions.py`` pins this behaviour.

    Args:
        db: The active session.

    Yields:
        The same session, for convenience.
    """
    with db.begin_nested():
        yield db


@contextmanager
def session_scope() -> Generator[Session]:
    """Context manager yielding a session for non-request (background) work.

    Used by the maintenance tasks. The caller is responsible for committing
    (typically via :func:`unit_of_work`); the session is closed on exit, rolling
    back any pending transaction.
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
    """Return the mapper of the host's user class.

    Uses the class the host passed to :func:`map_models`. Falling back to "the
    class mapped to ``users``" keeps the zero-argument call working, but that
    fallback is why the class had to be discoverable by schema in the first
    place — pass ``user_model=`` and the host owns the naming entirely.

    Raises:
        RuntimeError: If models are not mapped, or no user class can be found.
    """
    if _user_model.is_configured():
        return cast("Mapper[Any]", sa_inspect(_user_model.get()))
    for mapper in get_active_base().registry.mappers:
        table = mapper.local_table
        if table is not None and getattr(table, "name", None) == "users":
            return mapper
    raise RuntimeError(
        "JAFAAL could not find the host's user model. Pass it explicitly — "
        "jafaal.map_models(Base, user_model=YourUserClass) — or map a class to the "
        "'users' table (see jafaal.user_model)."
    )


def get_user_model() -> type:
    """Return the host's user class.

    The class the host passed to :func:`map_models` (or, failing that, whichever
    class is mapped to ``users``). This is how JAFAAL's own models resolve their
    ``users`` relationship, so the host class needs no particular name.

    Raises:
        RuntimeError: If no user model has been registered or mapped yet.
    """
    return _resolve_user_mapper().class_


def user_id_python_type() -> type:
    """Return the Python type of the host user table's primary key (``int``/``UUID``)."""
    return _resolve_user_mapper().primary_key[0].type.python_type


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
