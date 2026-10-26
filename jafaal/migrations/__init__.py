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
the self-contained runner here needs no host wiring. Only :func:`upgrade` creates
a fresh database with the ``jafaal_`` names directly; from a host's own history
``0001_initial`` first creates the unprefixed names and
``0008_prefix_table_names`` renames them.
"""

from __future__ import annotations

from collections.abc import Generator, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from jafaal._core import optional_deps
from jafaal.migrations import _names

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

#: The first revision after which every table carries the ``jafaal_`` prefix.
_PREFIXED_FROM = "0008_prefix_table_names"


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


def _fresh_install_prefix(connection: Any, revision: str) -> str:
    """Return the table prefix a run to ``revision`` should create tables with.

    ``jafaal_`` for a fresh database heading to :data:`_PREFIXED_FROM` or later, so
    JAFAAL never creates an unprefixed table that a host's own could already
    occupy; empty everywhere else (see :mod:`jafaal.migrations._names`). Fresh
    means no recorded revision and no JAFAAL table. An unprefixed table of the
    same name proves nothing, since it may be the host's; JAFAAL-specific old
    names (see :func:`jafaal.orm.is_legacy_schema`) mark an unversioned old
    schema, which is refused.

    Raises:
        SchemaCompatibilityError: If the database holds unversioned JAFAAL
            tables, which :func:`adopt_existing_schema` must validate first, or
            lacks the host's ``users`` table the new tables reference.
    """
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory
    from sqlalchemy import inspect

    from jafaal.orm import is_legacy_schema, jafaal_table_names

    context = MigrationContext.configure(connection, opts={"version_table": VERSION_TABLE})
    if context.get_current_revision() is not None:
        return ""
    present = set(inspect(connection).get_table_names())
    if present & jafaal_table_names():
        # Running the revisions over existing tables would either fail half-way
        # or record a revision the tables were never checked against.
        raise SchemaCompatibilityError(
            "The database holds unversioned JAFAAL tables; call adopt_existing_schema(engine) before upgrade(engine)"
        )
    if is_legacy_schema(present):
        # An unversioned pre-0.4 schema: creating the prefixed tables beside it
        # would leave its data behind.
        raise SchemaCompatibilityError(
            "The database holds unversioned, unprefixed JAFAAL tables from 0.3 or earlier; "
            "call adopt_existing_schema(engine) before upgrade(engine)"
        )
    if "users" not in present:
        raise SchemaCompatibilityError(
            "JAFAAL's tables reference the host-owned 'users' table, which does not exist; "
            "run the host's own migrations before jafaal.migrations.upgrade(engine)"
        )
    steps = {script.revision for script in ScriptDirectory.from_config(_config()).iterate_revisions(revision, "base")}
    return _names.PREFIX if _PREFIXED_FROM in steps else ""


def upgrade(engine: Engine, revision: str = "head") -> None:
    """Create or upgrade JAFAAL's tables to ``revision`` (default ``head``).

    On a fresh database the tables are created with their final ``jafaal_`` names
    directly. A 0.3 database (unprefixed names) is renamed in place by
    ``0008_prefix_table_names``, so **stop every process running 0.3 or earlier
    before running this**.

    Raises:
        SchemaCompatibilityError: If the database has JAFAAL tables but no
            recorded revision (call :func:`adopt_existing_schema` first), or no
            host ``users`` table to reference.
    """
    _require_alembic()
    # On its own connection: inspecting begins a transaction, and Alembic only
    # commits one it began itself.
    with engine.connect() as connection:
        prefix = _fresh_install_prefix(connection, revision)
    with _names.use_prefix(prefix):
        _run(engine, "upgrade", revision)


def downgrade(engine: Engine, revision: str) -> None:
    """Downgrade JAFAAL's tables to ``revision`` (``"base"`` drops them all).

    Downgrading past ``0008_prefix_table_names`` restores the unprefixed names,
    and fails if a table of the host's has since taken one.
    """
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
        if operation == "modify_comment" and len(difference) > 6:
            return f"{table_name}.{difference[3]}: expected comment {difference[6]!r}, found {difference[5]!r}"
        if operation == "modify_default" and len(difference) > 6:
            return f"{table_name}.{difference[3]}: expected server default {difference[6]}, found {difference[5]}"
        return f"{table_name}: incompatible schema operation {operation!r}"
    return f"incompatible schema operation {operation!r}: {difference!r}"


def _adoption_include_object(tables: frozenset[str]) -> Any:
    """Build the ``include_object`` hook for comparing one candidate schema.

    Only the candidate's own tables are compared: under the unprefixed naming a
    host's unrelated ``identity_providers`` can sit in the same database, and the
    host's ``users`` table is never JAFAAL's to judge.
    """

    def include_object(obj: Any, name: str | None, type_: str, reflected: bool, compare_to: Any) -> bool:
        if type_ == "table":
            return name in tables
        # Host-created lookup indexes do not change JAFAAL's write contract.
        return not (type_ == "index" and reflected and compare_to is None and not getattr(obj, "unique", False))

    return include_object


#: Spellings of "the current time" as a server default. MariaDB reflects
#: ``func.now()`` as ``current_timestamp()``, which Alembic does not equate with
#: the ``now()`` the models render.
_CURRENT_TIME_DEFAULTS = frozenset({"now", "current_timestamp", "localtimestamp"})


def _compare_server_default(
    context: Any,
    inspected_column: Any,
    metadata_column: Any,
    inspected_default: str | None,
    metadata_default: Any,
    rendered_metadata_default: str | None,
) -> bool | None:
    """Treat every spelling of "the current time" as one default; defer the rest to Alembic."""

    def normalised(value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().strip("'\"").lower()
        while value.startswith("(") and value.endswith(")"):
            value = value[1:-1].strip()
        return value.removesuffix("()")

    if (
        normalised(inspected_default) in _CURRENT_TIME_DEFAULTS
        and normalised(rendered_metadata_default) in _CURRENT_TIME_DEFAULTS
    ):
        return False
    return None


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


class _MetadataOps:
    """Stand-in for ``alembic.op`` that applies a downgrade to a ``MetaData``.

    Lets an older revision's schema be derived from the migration that removes
    it, so nothing is maintained twice. Only the operations JAFAAL's downgrades
    use are supported; anything else raises, so a new kind of operation cannot
    silently yield a wrong schema.

    Each operation does to the metadata what it does to a database: a renamed
    table keeps its index names (the downgrade renames them itself), and the
    foreign keys of other tables follow it.
    """

    def __init__(self, metadata: Any) -> None:
        self._metadata = metadata

    def _table(self, table_name: str) -> Any:
        try:
            return self._metadata.tables[table_name]
        except KeyError:
            raise RuntimeError(f"downgrade refers to unknown table {table_name!r}") from None

    def drop_index(self, index_name: str, table_name: str | None = None, **kwargs: Any) -> None:
        tables = [self._table(table_name)] if table_name else list(self._metadata.tables.values())
        for table in tables:
            for index in list(table.indexes):
                if index.name == index_name:
                    table.indexes.discard(index)
                    if index._column_flag:
                        # An ``index=True`` column would bring the index back on
                        # the next copy of the table.
                        for column in index.columns:
                            column.index = None
                            if index.unique:
                                column.unique = None
                    return
        raise RuntimeError(f"downgrade drops unknown index {index_name!r}")

    def create_index(self, index_name: str, table_name: str, columns: Sequence[str], **kwargs: Any) -> None:
        from sqlalchemy import Index

        table = self._table(table_name)
        Index(index_name, *(table.c[column] for column in columns), unique=bool(kwargs.get("unique")))

    def rename_table(self, old_table_name: str, new_table_name: str, **kwargs: Any) -> None:
        from sqlalchemy import ForeignKeyConstraint

        table = self._table(old_table_name)
        old_names = {tuple(column.name for column in index.columns): index.name for index in table.indexes}
        self._metadata.remove(table)
        renamed = table.to_metadata(self._metadata, name=new_table_name)
        for index in renamed.indexes:
            # A database keeps an index's name through a table rename; the copy
            # would otherwise rename an ``index=True`` index by the convention.
            index.name = old_names.get(tuple(column.name for column in index.columns), index.name)

        for other in list(self._metadata.tables.values()):
            for constraint in list(other.foreign_key_constraints):
                targets = [element.target_fullname.rsplit(".", 1) for element in constraint.elements]
                if all(target_table != old_table_name for target_table, _ in targets):
                    continue
                columns = [column.name for column in constraint.columns]
                other.constraints.discard(constraint)
                for element in constraint.elements:
                    element.parent.foreign_keys.discard(element)
                    other.foreign_keys.discard(element)
                other.append_constraint(
                    ForeignKeyConstraint(
                        columns,
                        [
                            f"{new_table_name if target_table == old_table_name else target_table}.{target_column}"
                            for target_table, target_column in targets
                        ],
                        name=constraint.name,
                        ondelete=constraint.ondelete,
                        onupdate=constraint.onupdate,
                    )
                )

    def drop_constraint(self, constraint_name: str, table_name: str, type_: str | None = None, **kwargs: Any) -> None:
        table = self._table(table_name)
        for constraint in list(table.constraints):
            if constraint.name == constraint_name:
                table.constraints.discard(constraint)
                if getattr(constraint, "_column_flag", False):
                    for column in constraint.columns:
                        column.unique = None
                return
        raise RuntimeError(f"downgrade drops unknown constraint {constraint_name!r}")

    def create_unique_constraint(
        self, constraint_name: str, table_name: str, columns: Sequence[str], **kwargs: Any
    ) -> None:
        from sqlalchemy import UniqueConstraint

        table = self._table(table_name)
        table.append_constraint(UniqueConstraint(*columns, name=constraint_name))

    @contextmanager
    def batch_alter_table(self, table_name: str, **kwargs: Any) -> Generator[_MetadataBatchOps]:
        yield _MetadataBatchOps(self, table_name)

    def get_bind(self) -> Any:
        """Report a dialect no migration branches on, so the portable path is taken."""
        return SimpleNamespace(dialect=SimpleNamespace(name="metadata"))

    def drop_table(self, table_name: str, **kwargs: Any) -> None:
        self._metadata.remove(self._table(table_name))

    def add_column(self, table_name: str, column: Any, **kwargs: Any) -> None:
        self._table(table_name).append_column(column)

    def drop_column(self, table_name: str, column_name: str, **kwargs: Any) -> None:
        table = self._table(table_name)
        table._columns.remove(table.c[column_name])

    def __getattr__(self, name: str) -> Any:
        raise NotImplementedError(
            f"adoption cannot derive an older schema through op.{name}(); teach jafaal.migrations._MetadataOps"
        )


class _MetadataBatchOps:
    """The table-scoped operations of ``op.batch_alter_table`` for :class:`_MetadataOps`."""

    def __init__(self, ops: _MetadataOps, table_name: str) -> None:
        self._ops = ops
        self._table_name = table_name

    def drop_constraint(self, constraint_name: str, type_: str | None = None, **kwargs: Any) -> None:
        self._ops.drop_constraint(constraint_name, self._table_name, type_=type_)

    def create_unique_constraint(self, constraint_name: str, columns: Sequence[str], **kwargs: Any) -> None:
        self._ops.create_unique_constraint(constraint_name, self._table_name, columns)


def _copy_jafaal_metadata(metadata: Any) -> Any:
    """Copy JAFAAL's tables (prefixed or not) and the host's ``users`` table they reference."""
    from sqlalchemy import MetaData

    from jafaal.orm import get_active_base, jafaal_table_names, legacy_table_names

    copied = MetaData(naming_convention=get_active_base().metadata.naming_convention)
    known = jafaal_table_names() | legacy_table_names() | {"users"}
    for table_name in sorted(known & set(metadata.tables)):
        metadata.tables[table_name].to_metadata(copied)
    return copied


def _revision_schemas() -> list[tuple[str, Any]]:
    """Return ``(revision, metadata)`` for every revision, newest first.

    The head entry is a copy of the active metadata. Each older entry is derived
    by running the newer revision's ``downgrade`` against a copy of the one
    before it. The base state (no tables) is not a candidate.
    """
    from alembic.script import ScriptDirectory

    from jafaal.orm import get_active_base

    current = _copy_jafaal_metadata(get_active_base().metadata)
    schemas: list[tuple[str, Any]] = []
    for script in ScriptDirectory.from_config(_config()).walk_revisions():
        schemas.append((script.revision, current))
        if script.down_revision is None:
            break
        current = _copy_jafaal_metadata(current)
        module: Any = script.module
        original_op = module.op
        module.op = _MetadataOps(current)
        try:
            with _names.use_prefix(""):
                module.downgrade()
        finally:
            module.op = original_op
    return schemas


def _jafaal_tables_of(metadata: Any) -> frozenset[str]:
    from jafaal.orm import jafaal_table_names, legacy_table_names

    return frozenset(metadata.tables) & (jafaal_table_names() | legacy_table_names())


def _schema_differences(connection: Any, inspector: Any, metadata: Any) -> tuple[list[str], int]:
    """Describe how the unversioned JAFAAL tables differ from ``metadata``.

    Returns the readable differences and a count of individual discrepancies,
    used to rank which revision came closest.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext

    from jafaal.orm import jafaal_table_names, legacy_table_names

    expected_tables = _jafaal_tables_of(metadata)
    # The names this candidate's scheme can use: a host's unrelated
    # ``identity_providers`` is not "unexpected" when the candidate is prefixed.
    universe = legacy_table_names() if expected_tables & legacy_table_names() else jafaal_table_names()
    present_tables = frozenset(inspector.get_table_names()) & universe
    missing = sorted(expected_tables - present_tables)
    unexpected = sorted(present_tables - expected_tables)
    differences = []
    if missing:
        differences.append("missing tables: " + ", ".join(missing))
    if unexpected:
        differences.append("unexpected tables: " + ", ".join(unexpected))
    count = len(missing) + len(unexpected)

    # Compare column-level detail only where both sides have the table.
    common = expected_tables & present_tables
    comparison_context = MigrationContext.configure(
        connection,
        opts={
            "compare_type": True,
            "compare_server_default": _compare_server_default,
            "include_object": _adoption_include_object(common),
        },
    )
    detailed = [
        _format_difference(difference)
        for difference in compare_metadata(comparison_context, metadata)
        if not (isinstance(difference, tuple) and difference[0] in {"add_table", "remove_table"})
    ]
    detailed.extend(_primary_key_differences(inspector, metadata, common))
    detailed.extend(_unexpected_uniqueness_differences(inspector, metadata, common))
    return differences + detailed, count + len(detailed)


def adopt_existing_schema(engine: Engine) -> bool:
    """Validate and adopt complete, compatible, unversioned JAFAAL tables.

    The tables are matched exactly against the head schema, then against each
    earlier revision's schema, newest first - including the unprefixed schemas of
    0.3 and earlier. The first exact match is recorded as the database's revision,
    so a following :func:`upgrade` applies whatever revisions come after it. If
    two revisions describe the same schema, the newest is recorded. An older
    revision's schema is derived from the migrations' own ``downgrade``
    functions, never maintained separately.

    Columns, types, nullability, server defaults, primary keys, unique
    constraints, foreign keys and indexes are all compared. Additional
    non-unique indexes a host created are accepted; anything else is not.

    Returns ``True`` only when this call records a revision. An empty database
    or one that already has a JAFAAL revision is left unchanged and returns
    ``False``.

    Raises:
        SchemaCompatibilityError: If the host ``users`` table is absent, or no
            revision matches exactly; the message names the closest revision and
            lists its differences.
    """
    _require_alembic()
    from alembic import command
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import inspect

    from jafaal.orm import is_legacy_schema, jafaal_table_names, legacy_table_names

    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"version_table": VERSION_TABLE})
        if context.get_current_revision() is not None:
            return False

        inspector = inspect(connection)
        present = set(inspector.get_table_names())
        if present & jafaal_table_names():
            candidate_names = jafaal_table_names()
        elif is_legacy_schema(present):
            # Unprefixed tables from before 0.4, recognised by JAFAAL-specific
            # names: generic ones alone may be the host's own.
            candidate_names = legacy_table_names()
        else:
            return False
        if "users" not in present:
            raise SchemaCompatibilityError("Cannot adopt JAFAAL schema without the host-owned 'users' table")

        closest: tuple[str, list[str], int] | None = None
        for revision, metadata in _revision_schemas():
            if not _jafaal_tables_of(metadata) <= candidate_names:
                continue
            differences, weight = _schema_differences(connection, inspector, metadata)
            if not differences:
                command.stamp(_config(connection), revision)
                connection.commit()
                return True
            if closest is None or weight < closest[2]:
                closest = (revision, differences, weight)

        if closest is None:
            raise RuntimeError("JAFAAL has no packaged migration head")
        raise SchemaCompatibilityError(
            f"Cannot adopt an incompatible JAFAAL schema (closest revision {closest[0]}): " + "; ".join(closest[1])
        )


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
            "Run jafaal.migrations.adopt_existing_schema(engine) for legacy unversioned tables, "
            "then jafaal.migrations.upgrade(engine) at deploy time."
        )
