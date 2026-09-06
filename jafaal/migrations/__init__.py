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

    migrations.adopt_existing_schema(engine)   # validate/stamp legacy tables, if any
    migrations.upgrade(engine)                  # create/upgrade JAFAAL tables
    migrations.verify_schema_current(engine)   # fail fast if not migrated

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
    "MAX_REVISION_LENGTH",
    "VERSION_TABLE",
    "SchemaCompatibilityError",
    "adopt_existing_schema",
    "db_revision",
    "downgrade",
    "head_revision",
    "jafaal_include_object",
    "upgrade",
    "verify_schema_current",
]

#: Dedicated Alembic version table, kept separate from the host's
#: ``alembic_version`` so the two migration histories never collide in one DB.
VERSION_TABLE = "jafaal_alembic_version"

#: Hard limit on a revision identifier's length.
#:
#: Alembic types the version table's ``version_num`` column as ``String(32)``
#: and offers no way to widen it, so a longer identifier is silently fine on
#: SQLite (which ignores ``VARCHAR`` lengths) and fails outright on Postgres.
#: ``tests/test_migrations.py`` asserts every packaged revision fits.
MAX_REVISION_LENGTH = 32

_MIGRATIONS_DIR = Path(__file__).resolve().parent


class SchemaCompatibilityError(RuntimeError):
    """An unversioned JAFAAL schema cannot safely be adopted."""


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


def _run_on_connection(connection: Any, command_name: str, *args: Any) -> None:
    _require_alembic()
    from alembic import command

    config = _config(connection)
    getattr(command, command_name)(config, *args)


def _run(engine: Engine, command_name: str, *args: Any) -> None:
    with engine.connect() as connection:
        _run_on_connection(connection, command_name, *args)


def upgrade(engine: Engine, revision: str = "head") -> None:
    """Create or upgrade JAFAAL's tables to ``revision`` (default ``head``)."""
    _run(engine, "upgrade", revision)


def downgrade(engine: Engine, revision: str) -> None:
    """Downgrade JAFAAL's tables to ``revision`` (e.g. ``"base"`` drops them all)."""
    _run(engine, "downgrade", revision)


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


def _format_foreign_key(difference: Any, state: str) -> str:
    constraint = difference[1]
    source_table = getattr(getattr(constraint, "table", None), "name", "<unknown>")
    source_columns = [getattr(column, "name", str(column)) for column in getattr(constraint, "columns", ())]
    elements = list(getattr(constraint, "elements", ()))
    referred_table = "<unknown>"
    referred_columns: list[str] = []
    if elements:
        referred_table = getattr(elements[0], "target_fullname", "<unknown>").rsplit(".", 1)[0]
        referred_columns = [getattr(element, "target_fullname", "<unknown>").rsplit(".", 1)[-1] for element in elements]
    return f"{source_table}: {state} foreign key {source_columns!r} referencing {referred_table}.{referred_columns!r}"


def _format_difference(difference: Any) -> str:
    if isinstance(difference, list):
        return "; ".join(_format_difference(item) for item in difference)
    if not isinstance(difference, tuple) or not difference:
        return f"incompatible schema difference {difference!r}"

    operation = difference[0]
    if operation == "add_fk" and len(difference) > 1:
        return _format_foreign_key(difference, "missing")
    if operation == "remove_fk" and len(difference) > 1:
        return _format_foreign_key(difference, "unexpected")
    if operation in {"add_index", "remove_index", "add_constraint", "remove_constraint"} and len(difference) > 1:
        obj = difference[1]
        state = "missing" if operation.startswith("add_") else "unexpected"
        kind = "index" if operation.endswith("index") else "unique constraint"
        table_name = getattr(getattr(obj, "table", None), "name", "<unknown>")
        return f"{table_name}: {state} {kind} {getattr(obj, 'name', None)!r}"
    if len(difference) > 3:
        table_name = difference[2]
        if operation == "add_column":
            return f"{table_name}: missing column {difference[3].name!r}"
        if operation == "remove_column":
            return f"{table_name}: unexpected column {difference[3].name!r}"
        if operation == "modify_type" and len(difference) > 6:
            return f"{table_name}.{difference[3]}: expected type {difference[6]}, found {difference[5]}"
        if operation == "modify_nullable" and len(difference) > 6:
            return (
                f"{table_name}.{difference[3]}: expected nullable={difference[6]!r}, found nullable={difference[5]!r}"
            )
        if operation == "modify_default" and len(difference) > 6:
            return f"{table_name}.{difference[3]}: expected server default {difference[6]}, found {difference[5]}"
        return f"{table_name}: incompatible schema operation {operation!r}"
    return f"incompatible schema operation {operation!r}: {difference!r}"


def _adoption_include_object(obj: Any, name: str | None, type_: str, reflected: bool, compare_to: Any) -> bool:
    if type_ == "index" and reflected and compare_to is None and not getattr(obj, "unique", False):
        # Host-created lookup indexes do not change JAFAAL's write contract.
        return False
    return jafaal_include_object(obj, name, type_, reflected, compare_to)


def _primary_key_differences(inspector: Any, metadata: Any, table_names: frozenset[str]) -> list[str]:
    differences = []
    for table_name in sorted(table_names):
        expected = [column.name for column in metadata.tables[table_name].primary_key.columns]
        actual = inspector.get_pk_constraint(table_name).get("constrained_columns") or []
        if actual != expected:
            differences.append(f"{table_name}: expected primary key {expected!r}, found {actual!r}")
    return differences


def _unexpected_uniqueness_differences(inspector: Any, metadata: Any, table_names: frozenset[str]) -> list[str]:
    from sqlalchemy import UniqueConstraint

    differences: list[str] = []
    for table_name in sorted(table_names):
        table = metadata.tables[table_name]
        expected = {
            tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        expected.update(tuple(column.name for column in index.columns) for index in table.indexes if index.unique)
        actual_objects = [
            ("index", item.get("name"), tuple(item.get("column_names") or ()))
            for item in inspector.get_indexes(table_name)
            if item.get("unique")
        ]
        actual_objects.extend(
            ("unique constraint", item.get("name"), tuple(item.get("column_names") or ()))
            for item in inspector.get_unique_constraints(table_name)
        )
        differences.extend(
            f"{table_name}: unexpected {kind} {name!r} on columns {list(columns)!r}"
            for kind, name, columns in actual_objects
            if columns not in expected
        )
    return differences


def adopt_existing_schema(engine: Engine) -> bool:
    """Validate and adopt complete, compatible, unversioned JAFAAL tables.

    Returns ``True`` only when this call records the installed head. An empty
    database or one that already has a JAFAAL revision is left unchanged and
    returns ``False``.

    Raises:
        SchemaCompatibilityError: If the host ``users`` table is absent, only
            some JAFAAL tables exist, or their physical schema is incompatible.
    """
    _require_alembic()
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import inspect

    from jafaal.orm import get_active_base, jafaal_table_names

    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"version_table": VERSION_TABLE})
        if context.get_current_revision() is not None:
            return False

        inspector = inspect(connection)
        physical_tables = set(inspector.get_table_names())
        expected_tables = jafaal_table_names()
        present_tables = physical_tables & expected_tables
        if not present_tables:
            return False
        if present_tables != expected_tables:
            missing = sorted(expected_tables - present_tables)
            raise SchemaCompatibilityError(
                "Cannot adopt a partial JAFAAL schema; missing tables: " + ", ".join(missing)
            )
        if "users" not in physical_tables:
            raise SchemaCompatibilityError("Cannot adopt JAFAAL schema without the host-owned 'users' table")

        metadata = get_active_base().metadata
        comparison_context = MigrationContext.configure(
            connection,
            opts={
                "compare_type": True,
                "compare_server_default": True,
                "include_object": _adoption_include_object,
            },
        )
        raw_differences = compare_metadata(comparison_context, metadata)
        differences = [_format_difference(difference) for difference in raw_differences]
        differences.extend(_primary_key_differences(inspector, metadata, expected_tables))
        differences.extend(_unexpected_uniqueness_differences(inspector, metadata, expected_tables))
        if differences:
            raise SchemaCompatibilityError("Cannot adopt an incompatible JAFAAL schema: " + "; ".join(differences))

        head = head_revision()
        if head is None:
            raise RuntimeError("JAFAAL has no packaged migration head")
        _run_on_connection(connection, "stamp", head)
        connection.commit()
        return True


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
            "Run jafaal.migrations.adopt_existing_schema(engine) for complete legacy unversioned tables, "
            "then jafaal.migrations.upgrade(engine) at deploy time."
        )
