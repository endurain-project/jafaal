"""Tests for the packaged Alembic migrations (``jafaal.migrations``).

Runs against in-memory SQLite by default. Set
``JAFAAL_TEST_MIGRATIONS_DATABASE_URL`` to a **dedicated, disposable** database
to run the identical tests against a real server — the CI database matrix does
this for Postgres and MySQL, which is what proves a revision's DDL is portable
rather than merely SQLite-shaped.

It deliberately does not reuse ``JAFAAL_TEST_DATABASE_URL``: these tests drop
every table between cases, and that URL is the one the rest of the suite is
actively using.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("alembic")

from sqlalchemy import Column, Integer, MetaData, Table, UniqueConstraint, create_engine, inspect
from sqlalchemy.pool import StaticPool

import jafaal.orm as jafaal_orm
from jafaal import migrations

# conftest maps JAFAAL onto its host-owned Base at import; reuse that active base.
Base = jafaal_orm.get_active_base()

MIGRATIONS_DATABASE_URL = os.environ.get("JAFAAL_TEST_MIGRATIONS_DATABASE_URL")


def _fresh_engine():
    if MIGRATIONS_DATABASE_URL:
        # A real server persists between tests, so clear it down to bare earth
        # first — every case here starts from "no JAFAAL schema at all".
        engine = create_engine(MIGRATIONS_DATABASE_URL)
        existing = MetaData()
        existing.reflect(bind=engine)
        existing.drop_all(bind=engine)
        return engine
    # A single shared in-memory connection, so tables created by the migration
    # are visible to the follow-up inspection.
    return create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)


@pytest.fixture
def migration_engine():
    engine = _fresh_engine()
    try:
        yield engine
    finally:
        engine.dispose()


def _create_host_users(engine):
    # JAFAAL's tables carry foreign keys to users.id, so the host table exists first.
    Base.metadata.tables["users"].create(bind=engine)


def _drop_version_table(engine):
    with engine.begin() as connection:
        connection.exec_driver_sql(f"DROP TABLE {migrations.VERSION_TABLE}")


def _stamp_revision(engine, revision):
    from alembic import command

    with engine.connect() as connection:
        command.stamp(migrations._config(connection), revision)
        connection.commit()


def _copied_metadata():
    metadata = MetaData()
    Base.metadata.tables["users"].to_metadata(metadata)
    for table_name in jafaal_orm.jafaal_table_names():
        Base.metadata.tables[table_name].to_metadata(metadata)
    return metadata


def _drop_host_users(engine):
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.exec_driver_sql("DROP TABLE users CASCADE")
        elif engine.dialect.name == "mysql":
            connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS=0")
            connection.exec_driver_sql("DROP TABLE users")
            connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS=1")
        else:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.exec_driver_sql("DROP TABLE users")


def test_upgrade_creates_all_jafaal_tables(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)

    existing = set(inspect(engine).get_table_names())
    assert jafaal_orm.jafaal_table_names() <= existing
    # The run recorded its head in the dedicated version table (not the host's).
    assert migrations.VERSION_TABLE in existing
    assert "alembic_version" not in existing
    assert migrations.db_revision(engine) == migrations.head_revision()


def test_upgrade_matches_models_without_drift(migration_engine):
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext

    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)

    with engine.connect() as connection:
        context = MigrationContext.configure(
            connection,
            opts={
                "version_table": migrations.VERSION_TABLE,
                "target_metadata": Base.metadata,
                "include_object": migrations.jafaal_include_object,
                "compare_type": False,
            },
        )
        diffs = compare_metadata(context, Base.metadata)

    # No table/column added or removed relative to the models (cross-dialect type
    # affinity differences are intentionally out of scope for this drift guard).
    structural = [
        diff
        for diff in diffs
        if isinstance(diff, tuple) and diff[0] in {"add_table", "remove_table", "add_column", "remove_column"}
    ]
    assert structural == [], f"schema drift vs models: {structural}"


def test_downgrade_drops_jafaal_tables_but_keeps_users(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    migrations.downgrade(engine, "base")

    remaining = set(inspect(engine).get_table_names())
    assert "users" in remaining
    assert not (jafaal_orm.jafaal_table_names() & remaining)


def test_verify_schema_current_fails_then_passes(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    with pytest.raises(RuntimeError, match="out of date"):
        migrations.verify_schema_current(engine)

    migrations.upgrade(engine)
    migrations.verify_schema_current(engine)  # now current → no raise


def test_empty_database_is_not_adopted(migration_engine):
    engine = migration_engine
    assert migrations.adopt_existing_schema(engine) is False
    assert migrations.db_revision(engine) is None


def test_complete_unversioned_schema_is_adopted_idempotently(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    Base.metadata.create_all(
        bind=engine,
        tables=[Base.metadata.tables[name] for name in jafaal_orm.jafaal_table_names()],
    )
    assert migrations.db_revision(engine) is None
    assert migrations.adopt_existing_schema(engine) is True
    assert migrations.db_revision(engine) == migrations.head_revision()
    assert migrations.adopt_existing_schema(engine) is False


def test_partial_schema_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    Base.metadata.tables["identity_providers"].create(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"missing tables:"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_column_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE identity_providers DROP COLUMN name")

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"identity_providers.*missing column 'name'"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_unexpected_column_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE identity_providers ADD COLUMN legacy_value VARCHAR(20)")

    with pytest.raises(
        migrations.SchemaCompatibilityError, match=r"identity_providers.*unexpected column 'legacy_value'"
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_wrong_type_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    metadata.tables["identity_providers"].c.name.type = Integer()
    metadata.create_all(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"identity_providers.name.*expected type"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_wrong_nullability_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    metadata.tables["identity_providers"].c.name.nullable = True
    metadata.create_all(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"identity_providers.name.*nullable=False"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_server_default_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    metadata.tables["identity_providers"].c.created_at.server_default = None
    metadata.create_all(engine)

    with pytest.raises(
        migrations.SchemaCompatibilityError,
        match=r"identity_providers.created_at.*expected server default",
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_primary_key_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    copied_table = metadata.tables["password_reset_tokens"]
    columns = [
        Column(
            column.name,
            column.type,
            nullable=column.nullable,
            server_default=column.server_default,
        )
        for column in copied_table.columns
    ]
    metadata.remove(copied_table)
    Table("password_reset_tokens", metadata, *columns)
    metadata.create_all(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"password_reset_tokens.*expected primary key"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_unique_constraint_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    table = metadata.tables["users_identity_providers"]
    constraint = next(item for item in table.constraints if isinstance(item, UniqueConstraint))
    table.constraints.remove(constraint)
    metadata.create_all(engine)

    with pytest.raises(
        migrations.SchemaCompatibilityError, match=r"users_identity_providers.*missing unique constraint"
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_foreign_key_is_rejected_as_schema_error(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    table = metadata.tables["users_sessions"]
    foreign_key = next(iter(table.c.user_id.foreign_keys))
    table.c.user_id.foreign_keys.remove(foreign_key)
    table.foreign_keys.remove(foreign_key)
    table.constraints.remove(foreign_key.constraint)
    metadata.create_all(engine)

    with pytest.raises(
        migrations.SchemaCompatibilityError,
        match=r"users_sessions.*missing foreign key.*user_id.*users.*id",
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_required_index_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    expected_index = next(
        index for index in Base.metadata.tables["mfa_backup_codes"].indexes if index.name == "idx_user_unused_codes"
    )
    expected_index.drop(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"mfa_backup_codes.*missing index"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_additional_non_unique_index_is_accepted(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE INDEX idx_host_identity_provider_name ON identity_providers (name)")

    assert migrations.adopt_existing_schema(engine) is True


def test_additional_unique_index_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE UNIQUE INDEX uq_host_identity_provider_name ON identity_providers (name)")

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"identity_providers.*unexpected index"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_host_users_table_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    _drop_host_users(engine)

    try:
        with pytest.raises(migrations.SchemaCompatibilityError, match=r"host-owned 'users' table"):
            migrations.adopt_existing_schema(engine)

        assert migrations.db_revision(engine) is None
    finally:
        _create_host_users(engine)


def test_existing_head_and_older_revisions_are_preserved(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    assert migrations.adopt_existing_schema(engine) is False
    assert migrations.db_revision(engine) == migrations.head_revision()

    with engine.begin() as connection:
        connection.exec_driver_sql(f"DELETE FROM {migrations.VERSION_TABLE}")  # noqa: S608 - fixed identifier
        connection.exec_driver_sql(
            f"INSERT INTO {migrations.VERSION_TABLE} (version_num) "  # noqa: S608 - fixed identifier and revision
            "VALUES ('0006_oauth_requested_scope')"
        )
    assert migrations.adopt_existing_schema(engine) is False
    assert migrations.db_revision(engine) == "0006_oauth_requested_scope"


def test_verify_schema_current_names_adoption_remedy(migration_engine):
    with pytest.raises(RuntimeError, match=r"jafaal\.migrations\.adopt_existing_schema"):
        migrations.verify_schema_current(migration_engine)


def test_every_revision_id_fits_alembics_version_column():
    """Alembic types ``version_num`` as ``String(32)`` and cannot widen it.

    SQLite ignores ``VARCHAR`` lengths, so an over-long identifier passes there
    and then fails on Postgres the moment the version row is updated — breaking
    the upgrade for every deployment on a backend that enforces lengths. Checked
    statically so it is caught without needing a real server.
    """
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(migrations._config())
    too_long = {
        rev.revision: len(rev.revision)
        for rev in script.walk_revisions()
        if len(rev.revision) > migrations.MAX_REVISION_LENGTH
    }
    assert too_long == {}, f"revision ids exceed Alembic's {migrations.MAX_REVISION_LENGTH}-char column: {too_long}"


def test_an_incremental_revision_applies_to_an_older_database(migration_engine):
    """Exercise a revision's own DDL, not just the baseline.

    ``0001_initial`` builds every table from the *current* models, so on a fresh
    database each later revision finds its column already present and skips.
    That makes the incremental path — the one every existing deployment actually
    takes — invisible to the other tests here. This drops the column back off a
    database stamped at head and re-runs the upgrade, so ``add_column`` really
    executes. Against Postgres and MySQL in CI, that is what catches DDL a
    revision only got away with on SQLite.
    """
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)

    table, column = "users_local_credentials", "must_change_password"
    assert column in {col["name"] for col in inspect(engine).get_columns(table)}

    with engine.begin() as connection:
        connection.exec_driver_sql(f"ALTER TABLE {table} DROP COLUMN {column}")
        connection.exec_driver_sql(f"DELETE FROM {migrations.VERSION_TABLE}")  # noqa: S608 - fixed identifier
    _stamp_revision(engine, "0006_oauth_requested_scope")
    assert column not in {col["name"] for col in inspect(engine).get_columns(table)}

    migrations.upgrade(engine)

    assert column in {col["name"] for col in inspect(engine).get_columns(table)}
    assert migrations.db_revision(engine) == migrations.head_revision()
