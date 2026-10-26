"""Naming of JAFAAL's tables, indexes and constraints while a migration runs.

Up to 0.3 the tables had no prefix (``oauth_states``); from 0.4 every one starts
with ``jafaal_`` so none can collide with a host's own table. ``0001_initial`` to
``0007_credential_must_change`` create and alter tables, and they cannot simply be
rewritten: a database stamped at any of them holds the unprefixed names, and
``0008_prefix_table_names`` renames it from there. But on a **fresh** database
those revisions would first create the unprefixed tables and so collide with a
host's same-named table before ``0008`` could rename anything.

So the prefix they use is chosen by the runner. :func:`use_prefix` is set to
``jafaal_`` for a fresh install heading to ``0008`` or later, and ``0008`` then
has nothing to rename. Everywhere else - an existing database, an explicit older
target, a downgrade, the replay that derives an older revision's schema - it is
empty, which is what those revisions always meant.

Indexes declared with ``index=True`` are named by the host's naming convention
(SQLAlchemy's default is ``ix_<table>_<column>``), so their names follow the
table's. :func:`index_name` and :func:`unique_name` derive them the same way the models do, so a
revision never hard-codes a name a host's convention would spell differently.
"""

from __future__ import annotations

from collections.abc import Generator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

__all__ = [
    "PREFIX",
    "current_prefix",
    "host_user_id_type",
    "index_name",
    "named",
    "table",
    "unique_name",
    "use_prefix",
]

#: The prefix every JAFAAL table name has from ``0008_prefix_table_names`` on.
PREFIX = "jafaal_"

_prefix: ContextVar[str] = ContextVar("jafaal_migration_table_prefix", default="")


@contextmanager
def use_prefix(prefix: str) -> Generator[None]:
    """Make the revisions that follow the prefix convention use ``prefix``."""
    token = _prefix.set(prefix)
    try:
        yield
    finally:
        _prefix.reset(token)


def current_prefix() -> str:
    """Return the prefix the running migration creates tables with."""
    return _prefix.get()


def table(name: str) -> str:
    """Return the table ``name`` as the running migration spells it."""
    return f"{_prefix.get()}{name}"


def named(name: str, prefix: str | None = None) -> str:
    """Return an explicit ``idx_...`` / ``uq_...`` name as the running migration spells it.

    The prefix goes after the marker, so ``uq_users_mfa_user_id`` becomes
    ``uq_jafaal_users_mfa_user_id``.

    Args:
        name: The unprefixed name.
        prefix: The prefix to apply; the running migration's when omitted.
    """
    marker, _, rest = name.partition("_")
    return f"{marker}_{_prefix.get() if prefix is None else prefix}{rest}"


def _convention_metadata() -> Any:
    from sqlalchemy import MetaData

    from jafaal.orm import get_active_base

    return MetaData(naming_convention=get_active_base().metadata.naming_convention)


def index_name(table_name: str, columns: Sequence[str], *, unique: bool = False) -> str:
    """Return the name the host's naming convention gives an ``index=True`` index.

    SQLAlchemy's default convention always names an index, so there is always
    one (``ix_<table>_<column>`` unless the host's convention says otherwise).

    Args:
        table_name: The table it is on, exactly as spelled.
        columns: The columns it covers, in order.
        unique: Whether the index is unique (``unique=True, index=True``).
    """
    from sqlalchemy import Column, Index, Integer, Table

    stand_in = Table(table_name, _convention_metadata(), *(Column(column, Integer) for column in columns))
    return str(Index(None, *(stand_in.c[column] for column in columns), unique=unique).name)


def unique_name(table_name: str, columns: Sequence[str]) -> str | None:
    """Return the name the host's naming convention gives a ``unique=True`` constraint.

    Returns:
        The name, or ``None`` when the convention has no ``uq`` key and the
        database names the constraint itself.
    """
    from sqlalchemy import Column, Integer, Table, UniqueConstraint

    stand_in = Table(table_name, _convention_metadata(), *(Column(column, Integer) for column in columns))
    constraint = UniqueConstraint(*columns)
    stand_in.append_constraint(constraint)
    return None if constraint.name is None else str(constraint.name)


def host_user_id_type() -> Any:
    """Return the type of the host's ``users.id``, which every ``user_id`` column copies.

    The one part of JAFAAL's schema the host decides: an integer or a UUID primary
    key (see :mod:`jafaal.user_model`). The models take it from the foreign key's
    target, so the revisions read it from the same place.

    Raises:
        RuntimeError: If the host's ``users`` table is not mapped on the active base.
    """
    from jafaal.orm import get_active_base

    users = get_active_base().metadata.tables.get("users")
    if users is None:
        raise RuntimeError(
            "JAFAAL's migrations need the host's user model mapped to the 'users' table; "
            "call jafaal.map_models(Base, user_model=YourUserClass) first."
        )
    return users.c.id.type
