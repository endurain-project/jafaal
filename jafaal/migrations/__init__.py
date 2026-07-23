"""Alembic migrations for JAFAAL's companion tables.

JAFAAL owns a single declarative registry shared with the host's ``Users`` model
(see :mod:`jafaal.orm`), so its tables and the host's live in one database. To let
JAFAAL evolve its schema without owning the host's Alembic history, these
migrations run on their **own** version table (``jafaal_alembic_version``) and are
scoped to JAFAAL's own tables — the host's ``users`` table is never touched.

Requires the optional ``jafaal[migrations]`` extra (Alembic). ``import jafaal``
never pulls this in; import it explicitly::

    import jafaal
    from jafaal import migrations

    migrations.upgrade(engine)                  # create/upgrade JAFAAL tables
    # migrations.stamp(engine)                  # existing DB already at head
    # migrations.verify_schema_current(engine)  # fail fast if not migrated

The host's ``users`` table must exist before the baseline runs (JAFAAL's tables
carry foreign keys to ``users.id``), so run the host's own migrations first.

Hosts that prefer a single, unified Alembic history can instead point their own
``env.py`` at their ``Base.metadata`` (the base passed to :func:`jafaal.map_models`)
and add this package's ``versions`` directory to their ``version_locations`` — but
the self-contained runner here needs no host wiring.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from jafaal._core import optional_deps

try:
    import alembic as _alembic
except ImportError:  # pragma: no cover - exercised via the missing-dep guard
    _alembic = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

__all__ = [
    "VERSION_TABLE",
    "db_revision",
    "downgrade",
    "head_revision",
    "jafaal_include_object",
    "stamp",
    "upgrade",
    "verify_schema_current",
]

#: Dedicated Alembic version table, kept separate from the host's
#: ``alembic_version`` so the two migration histories never collide in one DB.
VERSION_TABLE = "jafaal_alembic_version"

_MIGRATIONS_DIR = Path(__file__).resolve().parent


def jafaal_include_object(obj: Any, name: str | None, type_: str, reflected: bool, compare_to: Any) -> bool:
    """Alembic ``include_object`` hook scoping operations to JAFAAL's tables.

    Excludes the host's ``users`` table (and any other host table sharing the
    registry), so JAFAAL's migrations and autogenerate never add, drop, or diff
    them.
    """
    from jafaal.orm import jafaal_table_names

    if type_ == "table":
        return name in jafaal_table_names()
    return True


def _require_alembic() -> Any:
    return optional_deps.require(_alembic, package="alembic", extra="migrations", feature="Alembic migrations")


def _config(connection: Any = None) -> Any:
    """Build a programmatic Alembic ``Config`` bound to this package."""
    _require_alembic()
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    config.set_main_option("version_locations", str(_MIGRATIONS_DIR / "versions"))
    # Split version_locations on the OS path separator (Alembic 1.18+ default;
    # setting it explicitly silences the legacy-splitting deprecation warning and
    # is ignored by older Alembic).
    config.set_main_option("path_separator", "os")
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def _run(engine: Engine, command_name: str, *args: Any) -> None:
    _require_alembic()
    from alembic import command

    with engine.connect() as connection:
        config = _config(connection)
        getattr(command, command_name)(config, *args)


def upgrade(engine: Engine, revision: str = "head") -> None:
    """Create or upgrade JAFAAL's tables to ``revision`` (default ``head``)."""
    _run(engine, "upgrade", revision)


def downgrade(engine: Engine, revision: str) -> None:
    """Downgrade JAFAAL's tables to ``revision`` (e.g. ``"base"`` drops them all)."""
    _run(engine, "downgrade", revision)


def stamp(engine: Engine, revision: str = "head") -> None:
    """Record ``revision`` in the version table without running migrations.

    Use on an existing deployment whose JAFAAL tables were created with
    ``Base.metadata.create_all`` (or an older release): ``stamp(engine)`` marks it
    as being at head so future :func:`upgrade` calls apply only new revisions.
    """
    _run(engine, "stamp", revision)


def head_revision() -> str | None:
    """Return the newest revision shipped in this package."""
    _require_alembic()
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(_config()).get_current_head()


def db_revision(engine: Engine) -> str | None:
    """Return the JAFAAL migration revision currently recorded in ``engine``."""
    _require_alembic()
    from alembic.runtime.migration import MigrationContext

    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"version_table": VERSION_TABLE})
        return context.get_current_revision()


def verify_schema_current(engine: Engine) -> None:
    """Raise if the database is not migrated to the packaged head revision.

    A fail-fast startup check (mirroring :func:`jafaal.verify_configuration`): a
    host can call it after configuring the engine to catch a forgotten upgrade.

    Raises:
        RuntimeError: If the recorded revision differs from the packaged head.
    """
    head = head_revision()
    current = db_revision(engine)
    if current != head:
        raise RuntimeError(
            "JAFAAL database schema is out of date "
            f"(database revision={current!r}, expected head={head!r}). "
            "Run jafaal.migrations.upgrade(engine) at deploy time, or "
            "jafaal.migrations.stamp(engine) if the tables already exist."
        )
