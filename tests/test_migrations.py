"""Tests for the packaged Alembic migrations (``jafaal.migrations``).

Runs against in-memory SQLite by default. Set
``JAFAAL_TEST_MIGRATIONS_DATABASE_URL`` to a **dedicated, disposable** database
to run the identical tests against a real server — the CI database matrix does
this for Postgres, MySQL and MariaDB, which is what proves a revision's DDL is
portable rather than merely SQLite-shaped.

It deliberately does not reuse ``JAFAAL_TEST_DATABASE_URL``: these tests drop
every table between cases, and that URL is the one the rest of the suite is
actively using.

The failure that matters most here is **drift**: the migrations building a
schema that differs from what the models declare. Hosts using ``create_all`` in
tests and migrations in production would then run against two different
schemas. The revisions are explicit DDL, so ``test_upgrade_matches_models_exactly``
is the guard for that, on the fresh-install path and on the path an existing
database takes.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

pytest.importorskip("alembic")

from sqlalchemy import Column, Integer, MetaData, Table, UniqueConstraint, create_engine, event, inspect, text
from sqlalchemy.pool import StaticPool

import jafaal.orm as jafaal_orm
from jafaal import migrations
from jafaal.migrations import _names

# conftest maps JAFAAL onto its host-owned Base at import; reuse that active base.
Base = jafaal_orm.get_active_base()

MIGRATIONS_DATABASE_URL = os.environ.get("JAFAAL_TEST_MIGRATIONS_DATABASE_URL")

#: The last revision with unprefixed table names.
LEGACY_HEAD = "0007_credential_must_change"


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
    # are visible to the follow-up inspection. Foreign keys are enforced, as on
    # every other backend, so a rename or table rebuild that breaks them fails.
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def _foreign_keys(dbapi_connection, _record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


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


def _revision_metadata(revision):
    """The schema ``revision`` builds, derived from the migrations' own downgrades."""
    return next(metadata for rev, metadata in migrations._revision_schemas() if rev == revision)


def _differences(engine, metadata):
    with engine.connect() as connection:
        differences, _ = migrations._schema_differences(connection, inspect(connection), metadata)
    return differences


def _tables(engine):
    return set(inspect(engine).get_table_names())


def _drop_host_users(engine):
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.exec_driver_sql("DROP TABLE users CASCADE")
        elif engine.dialect.name in {"mysql", "mariadb"}:
            connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS=0")
            connection.exec_driver_sql("DROP TABLE users")
            connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS=1")
        else:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.exec_driver_sql("DROP TABLE users")
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")


# --------------------------------------------------------------------------- #
# Upgrade / downgrade
# --------------------------------------------------------------------------- #


def test_upgrade_creates_all_jafaal_tables(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)

    existing = _tables(engine)
    assert jafaal_orm.jafaal_table_names() <= existing
    # The run recorded its head in the dedicated version table (not the host's).
    assert migrations.VERSION_TABLE in existing
    assert "alembic_version" not in existing
    assert migrations.db_revision(engine) == migrations.head_revision()


def test_a_fresh_install_never_creates_an_unprefixed_table(migration_engine):
    """A fresh database gets the final names directly, so a host table of the
    same unprefixed name can never collide with JAFAAL's."""
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)

    assert all(name.startswith("jafaal_") for name in jafaal_orm.jafaal_table_names())
    assert not _tables(engine) & jafaal_orm.legacy_table_names()


def test_upgrade_matches_models_exactly(migration_engine):
    """Columns, types, nullability, defaults, keys and index names, not just tables."""
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)

    assert _differences(engine, _copied_metadata()) == []


def test_upgrading_through_every_revision_matches_models_exactly(migration_engine):
    """The path every existing deployment takes: one revision at a time, on the
    unprefixed names, then the rename. Every revision's own DDL really runs."""
    from alembic.script import ScriptDirectory

    engine = migration_engine
    _create_host_users(engine)
    revisions = [script.revision for script in ScriptDirectory.from_config(migrations._config()).walk_revisions()]
    for revision in reversed(revisions[1:]):
        migrations.upgrade(engine, revision)
        assert migrations.db_revision(engine) == revision
    assert jafaal_orm.legacy_table_names() <= _tables(engine)

    migrations.upgrade(engine)

    assert not _tables(engine) & jafaal_orm.legacy_table_names()
    assert _differences(engine, _copied_metadata()) == []


def test_downgrade_drops_jafaal_tables_but_keeps_users(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    migrations.downgrade(engine, "base")

    remaining = _tables(engine)
    assert "users" in remaining
    assert not (jafaal_orm.jafaal_table_names() & remaining)
    assert not (jafaal_orm.legacy_table_names() & remaining)


def test_upgrade_requires_the_host_users_table(migration_engine):
    with pytest.raises(migrations.SchemaCompatibilityError, match=r"host-owned 'users' table"):
        migrations.upgrade(migration_engine)

    assert migrations.db_revision(migration_engine) is None


def test_a_revision_fails_loudly_when_its_table_is_missing(migration_engine):
    """A revision never skips a change and still records itself as applied."""
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine, "0006_oauth_requested_scope")
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE users_local_credentials")

    with pytest.raises(Exception, match="users_local_credentials"):
        migrations.upgrade(engine)

    assert migrations.db_revision(engine) == "0006_oauth_requested_scope"


def test_verify_schema_current_fails_then_passes(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    with pytest.raises(RuntimeError, match="out of date"):
        migrations.verify_schema_current(engine)

    migrations.upgrade(engine)
    migrations.verify_schema_current(engine)  # now current → no raise


def test_verify_schema_current_names_adoption_remedy(migration_engine):
    with pytest.raises(RuntimeError, match=r"jafaal\.migrations\.adopt_existing_schema"):
        migrations.verify_schema_current(migration_engine)


# --------------------------------------------------------------------------- #
# The jafaal_ prefix rename (0008)
# --------------------------------------------------------------------------- #


def test_rows_and_foreign_keys_survive_the_rename(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine, LEGACY_HEAD)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (id, username, email, is_active, is_verified, is_superuser) "
                "VALUES (1, 'alice', 'alice@example.test', :true, :true, :false)"
            ),
            {"true": True, "false": False},
        )
        connection.execute(
            text(
                "INSERT INTO users_sessions (id, user_id, ip_address, device_type, operating_system, "
                "operating_system_version, browser, browser_version, created_at, last_activity_at, expires_at, "
                "tokens_exchanged, token_family_id, rotation_count) VALUES ('s-1', 1, '127.0.0.1', 'PC', 'Linux', "
                "'6', 'Firefox', '140', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, :false, 'family-1', 0)"
            ),
            {"false": False},
        )
        connection.execute(
            text(
                "INSERT INTO rotated_refresh_tokens (token_family_id, hashed_token, rotation_count, rotated_at, "
                "expires_at) VALUES ('family-1', 'hash-1', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )

    migrations.upgrade(engine)

    with engine.connect() as connection:
        assert connection.execute(text("SELECT user_id FROM jafaal_users_sessions")).scalar_one() == 1
        assert connection.execute(text("SELECT hashed_token FROM jafaal_rotated_refresh_tokens")).scalar_one() == (
            "hash-1"
        )
    referred = {fk["referred_table"] for fk in inspect(engine).get_foreign_keys("jafaal_rotated_refresh_tokens")}
    assert referred == {"jafaal_users_sessions"}


def test_the_rename_downgrades_to_the_unprefixed_schema_and_back(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)

    migrations.downgrade(engine, LEGACY_HEAD)

    tables = _tables(engine)
    assert jafaal_orm.legacy_table_names() <= tables
    assert not tables & jafaal_orm.jafaal_table_names()
    assert _differences(engine, _revision_metadata(LEGACY_HEAD)) == []

    migrations.upgrade(engine)

    assert _differences(engine, _copied_metadata()) == []


def test_the_rename_revision_knows_every_index_and_constraint(migration_engine):
    """``0008`` lists what it renames rather than reading the models, so it cannot
    drift with them; this is what catches a model change it does not cover."""
    from sqlalchemy import UniqueConstraint

    from jafaal.migrations import _names

    script = next(
        script
        for script in __import__("alembic.script", fromlist=["ScriptDirectory"])
        .ScriptDirectory.from_config(migrations._config())
        .walk_revisions()
        if script.revision == "0008_prefix_table_names"
    )
    rename = script.module

    listed_tables = {f"{_names.PREFIX}{table}" for table, _ in rename._TABLES}
    assert listed_tables == jafaal_orm.jafaal_table_names()
    assert {table for table, _ in rename._TABLES} == jafaal_orm.legacy_table_names()

    for table, indexes in rename._TABLES:
        model = Base.metadata.tables[f"{_names.PREFIX}{table}"]
        flagged = {
            (tuple(column.name for column in index.columns), bool(index.unique))
            for index in model.indexes
            if index._column_flag
        }
        assert set(indexes) == flagged, table
        named_indexes = {
            (index.name, tuple(column.name for column in index.columns))
            for index in model.indexes
            if not index._column_flag
        }
        assert named_indexes == {
            (_names.named(name, _names.PREFIX), columns) for t, name, columns in rename._NAMED_INDEXES if t == table
        }, table
        uniques = [constraint for constraint in model.constraints if isinstance(constraint, UniqueConstraint)]
        assert {
            (constraint.name, tuple(column.name for column in constraint.columns))
            for constraint in uniques
            if constraint.name is not None
        } == {
            (_names.named(name, _names.PREFIX), columns) for t, name, columns in rename._NAMED_UNIQUES if t == table
        }, table
        assert {
            tuple(column.name for column in constraint.columns) for constraint in uniques if constraint.name is None
        } == {columns for t, columns in rename._CONVENTION_UNIQUES if t == table}, table


@pytest.mark.parametrize("span", [f"{LEGACY_HEAD}:0008_prefix_table_names", "base:0008_prefix_table_names"])
def test_the_rename_can_be_rendered_as_sql(span):
    """``alembic upgrade --sql`` has no database to inspect."""
    import io

    from alembic import command

    config = migrations._config()
    config.set_main_option("sqlalchemy.url", "postgresql://offline/none")
    config.output_buffer = io.StringIO()

    command.upgrade(config, span, sql=True)

    sql = config.output_buffer.getvalue()
    assert "RENAME TO jafaal_oauth_states" in sql
    assert "RENAME CONSTRAINT uq_users_mfa_user_id TO uq_jafaal_users_mfa_user_id" in sql
    assert "RENAME TO ix_jafaal_users_sessions_user_id" in sql


# --------------------------------------------------------------------------- #
# Unversioned schemas: upgrade refuses, adoption validates
# --------------------------------------------------------------------------- #


def test_upgrade_refuses_an_unversioned_prefixed_schema(migration_engine):
    """Running the revisions over unchecked tables would record a revision they
    were never validated against."""
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match="adopt_existing_schema"):
        migrations.upgrade(engine)

    assert migrations.db_revision(engine) is None


def test_upgrade_refuses_an_unversioned_unprefixed_schema(migration_engine):
    """Creating empty prefixed tables beside the old ones would strand the data."""
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine, LEGACY_HEAD)
    _drop_version_table(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match="adopt_existing_schema"):
        migrations.upgrade(engine)

    assert not _tables(engine) & jafaal_orm.jafaal_table_names()
    assert migrations.db_revision(engine) is None


def test_upgrade_refuses_unversioned_tables_that_drifted(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE jafaal_sign_up_tokens")

    with pytest.raises(migrations.SchemaCompatibilityError):
        migrations.upgrade(engine)

    assert "jafaal_sign_up_tokens" not in _tables(engine)
    assert migrations.db_revision(engine) is None


def test_a_hosts_own_same_named_table_is_never_touched(migration_engine):
    """The collision the prefix exists to avoid: a host with its own
    ``password_reset_tokens`` can install JAFAAL without either seeing the other."""
    engine = migration_engine
    _create_host_users(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE password_reset_tokens (host_id INTEGER PRIMARY KEY, note VARCHAR(20))")
        connection.exec_driver_sql("INSERT INTO password_reset_tokens (host_id, note) VALUES (1, 'mine')")

    assert migrations.adopt_existing_schema(engine) is False
    migrations.upgrade(engine)

    assert _differences(engine, _copied_metadata()) == []
    assert {column["name"] for column in inspect(engine).get_columns("password_reset_tokens")} == {"host_id", "note"}
    with engine.connect() as connection:
        assert connection.execute(text("SELECT note FROM password_reset_tokens")).scalar_one() == "mine"


@pytest.mark.parametrize("versioned", [True, False], ids=["migrated", "create_all"])
def test_create_all_refuses_to_create_empty_tables_beside_a_0_3_schema(migration_engine, versioned):
    """The 0.3 -> 0.4 trap: an app calling ``create_all()`` at startup would get
    empty ``jafaal_*`` tables (no sessions, no MFA enrolments, no IdP configs)
    while its data sat in the old tables."""
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine, LEGACY_HEAD)
    if not versioned:
        _drop_version_table(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"adopt_existing_schema.*upgrade"):
        Base.metadata.create_all(engine)

    assert not _tables(engine) & jafaal_orm.jafaal_table_names()


def test_create_all_works_beside_a_hosts_own_same_named_table(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE identity_providers (host_id INTEGER PRIMARY KEY)")

    Base.metadata.create_all(engine)

    assert jafaal_orm.jafaal_table_names() <= _tables(engine)


def test_create_all_after_the_rename_is_a_no_op(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine, LEGACY_HEAD)
    migrations.upgrade(engine)

    Base.metadata.create_all(engine)

    assert _differences(engine, _copied_metadata()) == []


def test_a_hosts_own_same_named_table_does_not_break_adopting_the_prefixed_schema(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE identity_providers (host_id INTEGER PRIMARY KEY)")

    assert migrations.adopt_existing_schema(engine) is True
    assert migrations.db_revision(engine) == migrations.head_revision()


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


def test_an_unversioned_0_3_schema_is_adopted_then_renamed(migration_engine):
    """Adoption is how a 0.3 database created with ``create_all`` reaches 0.4."""
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine, LEGACY_HEAD)
    _drop_version_table(engine)

    assert migrations.adopt_existing_schema(engine) is True
    assert migrations.db_revision(engine) == LEGACY_HEAD

    migrations.upgrade(engine)

    assert not _tables(engine) & jafaal_orm.legacy_table_names()
    assert _differences(engine, _copied_metadata()) == []
    migrations.verify_schema_current(engine)


def test_an_older_unversioned_schema_is_adopted_at_its_revision_then_upgraded(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine, "0003_oauth_state_upstream_pkce")
    _drop_version_table(engine)

    assert migrations.adopt_existing_schema(engine) is True
    assert migrations.db_revision(engine) == "0003_oauth_state_upstream_pkce"

    migrations.upgrade(engine)

    assert _differences(engine, _copied_metadata()) == []


def test_an_older_schema_with_a_wrong_column_type_fails_closed(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine, "0003_oauth_state_upstream_pkce")
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE sign_up_tokens")
    metadata = _revision_metadata("0003_oauth_state_upstream_pkce")
    metadata.tables["sign_up_tokens"].c.token_hash.type = Integer()
    metadata.tables["sign_up_tokens"].create(engine)

    with pytest.raises(
        migrations.SchemaCompatibilityError,
        match=r"closest revision 0003_oauth_state_upstream_pkce.*sign_up_tokens\.token_hash",
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_partial_schema_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    Base.metadata.tables["jafaal_identity_providers"].create(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"missing tables:"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_column_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE jafaal_identity_providers DROP COLUMN name")

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"jafaal_identity_providers.*missing column 'name'"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_unexpected_column_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE jafaal_identity_providers ADD COLUMN legacy_value VARCHAR(20)")

    with pytest.raises(
        migrations.SchemaCompatibilityError, match=r"jafaal_identity_providers.*unexpected column 'legacy_value'"
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_wrong_type_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    metadata.tables["jafaal_identity_providers"].c.name.type = Integer()
    metadata.create_all(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"jafaal_identity_providers.name.*expected type"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_wrong_nullability_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    metadata.tables["jafaal_identity_providers"].c.name.nullable = True
    metadata.create_all(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"jafaal_identity_providers.name.*nullable=False"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_server_default_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    metadata.tables["jafaal_identity_providers"].c.created_at.server_default = None
    metadata.create_all(engine)

    with pytest.raises(
        migrations.SchemaCompatibilityError,
        match=r"jafaal_identity_providers.created_at.*expected server default",
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_primary_key_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    copied_table = metadata.tables["jafaal_password_reset_tokens"]
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
    Table("jafaal_password_reset_tokens", metadata, *columns)
    metadata.create_all(engine)

    with pytest.raises(
        migrations.SchemaCompatibilityError, match=r"jafaal_password_reset_tokens.*expected primary key"
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_unique_constraint_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    table = metadata.tables["jafaal_users_identity_providers"]
    constraint = next(item for item in table.constraints if isinstance(item, UniqueConstraint))
    table.constraints.remove(constraint)
    metadata.create_all(engine)

    with pytest.raises(
        migrations.SchemaCompatibilityError, match=r"jafaal_users_identity_providers.*missing unique constraint"
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_foreign_key_is_rejected_as_schema_error(migration_engine):
    engine = migration_engine
    metadata = _copied_metadata()
    table = metadata.tables["jafaal_users_sessions"]
    foreign_key = next(iter(table.c.user_id.foreign_keys))
    table.c.user_id.foreign_keys.remove(foreign_key)
    table.foreign_keys.remove(foreign_key)
    table.constraints.remove(foreign_key.constraint)
    metadata.create_all(engine)

    with pytest.raises(
        migrations.SchemaCompatibilityError,
        match=r"jafaal_users_sessions.*missing foreign key.*user_id.*users.*id",
    ):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_missing_required_index_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    expected_index = next(
        index
        for index in Base.metadata.tables["jafaal_mfa_backup_codes"].indexes
        if index.name == "idx_jafaal_user_unused_codes"
    )
    expected_index.drop(engine)

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"jafaal_mfa_backup_codes.*missing index"):
        migrations.adopt_existing_schema(engine)

    assert migrations.db_revision(engine) is None


def test_additional_non_unique_index_is_accepted(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE INDEX idx_host_identity_provider_name ON jafaal_identity_providers (name)")

    assert migrations.adopt_existing_schema(engine) is True


def test_additional_unique_index_is_rejected_without_revision(migration_engine):
    engine = migration_engine
    _create_host_users(engine)
    migrations.upgrade(engine)
    _drop_version_table(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE UNIQUE INDEX uq_host_identity_provider_name ON jafaal_identity_providers (name)"
        )

    with pytest.raises(migrations.SchemaCompatibilityError, match=r"jafaal_identity_providers.*unexpected index"):
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


# --------------------------------------------------------------------------- #
# Older-revision schemas derived from the downgrades
# --------------------------------------------------------------------------- #


def test_every_derived_schema_matches_the_real_migration(migration_engine):
    """The downgrade-derived schema of each revision equals what upgrading to it builds."""
    derived = migrations._revision_schemas()
    assert derived[0][0] == migrations.head_revision()
    assert [revision for revision, _ in derived][-1] == "0001_initial"
    for revision, metadata in derived:
        engine = _fresh_engine()
        try:
            _create_host_users(engine)
            migrations.upgrade(engine, revision)
            assert _differences(engine, metadata) == [], revision
        finally:
            engine.dispose()


def test_an_unsupported_downgrade_operation_is_refused():
    ops = migrations._MetadataOps(migrations._copy_jafaal_metadata(Base.metadata))

    with pytest.raises(NotImplementedError, match=r"op\.alter_column"):
        ops.alter_column("jafaal_oauth_states", "purpose")


def test_the_metadata_ops_reject_an_unknown_index():
    ops = migrations._MetadataOps(migrations._copy_jafaal_metadata(Base.metadata))

    with pytest.raises(RuntimeError, match="unknown index"):
        ops.drop_index("idx_missing", table_name="jafaal_oauth_states")


# --------------------------------------------------------------------------- #
# Scoping and static checks
# --------------------------------------------------------------------------- #


def test_host_tables_are_out_of_scope():
    """The scoping hook is what stops autogenerate from dropping the host's
    tables, which share the same registry."""
    assert migrations.jafaal_include_object(None, "users", "table", True, None) is False
    assert migrations.jafaal_include_object(None, "jafaal_oauth_states", "table", True, None) is True


def test_an_unprefixed_name_is_the_hosts():
    assert migrations.jafaal_include_object(None, "oauth_states", "table", True, None) is False


def test_legacy_names_are_the_prefixed_names_without_the_prefix():
    assert {
        name.removeprefix(_names.PREFIX) for name in jafaal_orm.jafaal_table_names()
    } == jafaal_orm.legacy_table_names()


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


# --------------------------------------------------------------------------- #
# A host with a UUID primary key and its own naming convention
# --------------------------------------------------------------------------- #

_CONVENTION_HOST = textwrap.dedent(
    """
    import os

    from sqlalchemy import MetaData, create_engine, event, inspect
    from sqlalchemy.orm import DeclarativeBase
    from sqlalchemy.pool import StaticPool

    import jafaal
    from jafaal import UUIDPKUserMixin, migrations


    class Base(DeclarativeBase):
        metadata = MetaData(
            naming_convention={
                "ix": "ix_%(table_name)s__%(column_0_N_name)s",
                "uq": "uq_%(table_name)s__%(column_0_N_name)s",
            }
        )


    class Person(UUIDPKUserMixin, Base):
        __tablename__ = "users"


    jafaal.map_models(Base, user_model=Person)


    def fresh_engine():
        url = os.environ.get("JAFAAL_TEST_MIGRATIONS_DATABASE_URL")
        if url:
            engine = create_engine(url)
            existing = MetaData()
            existing.reflect(bind=engine)
            existing.drop_all(bind=engine)
        else:
            engine = create_engine("sqlite://", poolclass=StaticPool)
            event.listen(engine, "connect", lambda c, _: c.execute("PRAGMA foreign_keys=ON"))
        Base.metadata.tables["users"].create(engine)
        return engine


    def differences(engine):
        metadata = migrations._copy_jafaal_metadata(Base.metadata)
        with engine.connect() as connection:
            return migrations._schema_differences(connection, inspect(connection), metadata)[0]


    fresh = fresh_engine()
    migrations.upgrade(fresh)
    assert differences(fresh) == [], differences(fresh)
    fresh.dispose()

    legacy = fresh_engine()
    migrations.upgrade(legacy, "0007_credential_must_change")
    names = {index["name"] for index in inspect(legacy).get_indexes("users_sessions")}
    assert "ix_users_sessions__user_id" in names, names
    migrations.upgrade(legacy)
    assert differences(legacy) == [], differences(legacy)
    names = {index["name"] for index in inspect(legacy).get_indexes("jafaal_users_sessions")}
    assert "ix_jafaal_users_sessions__user_id" in names, names
    legacy.dispose()

    print("CONVENTION_HOST_OK")
    """
)


def test_a_uuid_host_with_its_own_naming_convention_migrates_without_drift():
    """Index and constraint names come from the host's convention on both the
    fresh-install path and the rename, and every ``user_id`` copies the UUID key."""
    result = subprocess.run(
        [sys.executable, "-c", _CONVENTION_HOST],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"subprocess failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    assert "CONVENTION_HOST_OK" in result.stdout, result.stdout
