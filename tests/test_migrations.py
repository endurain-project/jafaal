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

from sqlalchemy import MetaData, create_engine, inspect
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


def _create_host_users(engine):
    # JAFAAL's tables carry foreign keys to users.id, so the host table exists first.
    Base.metadata.tables["users"].create(bind=engine)


def test_upgrade_creates_all_jafaal_tables():
    engine = _fresh_engine()
    _create_host_users(engine)
    migrations.upgrade(engine)

    existing = set(inspect(engine).get_table_names())
    assert jafaal_orm.jafaal_table_names() <= existing
    # The run recorded its head in the dedicated version table (not the host's).
    assert migrations.VERSION_TABLE in existing
    assert "alembic_version" not in existing
    assert migrations.db_revision(engine) == migrations.head_revision()


def test_upgrade_matches_models_without_drift():
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext

    engine = _fresh_engine()
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


def test_downgrade_drops_jafaal_tables_but_keeps_users():
    engine = _fresh_engine()
    _create_host_users(engine)
    migrations.upgrade(engine)
    migrations.downgrade(engine, "base")

    remaining = set(inspect(engine).get_table_names())
    assert "users" in remaining
    assert not (jafaal_orm.jafaal_table_names() & remaining)


def test_verify_schema_current_fails_then_passes():
    engine = _fresh_engine()
    _create_host_users(engine)
    with pytest.raises(RuntimeError, match="out of date"):
        migrations.verify_schema_current(engine)

    migrations.upgrade(engine)
    migrations.verify_schema_current(engine)  # now current → no raise


def test_stamp_marks_head_for_pre_existing_tables():
    engine = _fresh_engine()
    _create_host_users(engine)
    # Simulate a deployment whose tables were created out-of-band (create_all).
    Base.metadata.create_all(
        bind=engine,
        tables=[Base.metadata.tables[name] for name in jafaal_orm.jafaal_table_names()],
    )
    assert migrations.db_revision(engine) is None
    migrations.stamp(engine)
    assert migrations.db_revision(engine) == migrations.head_revision()


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


def test_an_incremental_revision_applies_to_an_older_database():
    """Exercise a revision's own DDL, not just the baseline.

    ``0001_initial`` builds every table from the *current* models, so on a fresh
    database each later revision finds its column already present and skips.
    That makes the incremental path — the one every existing deployment actually
    takes — invisible to the other tests here. This drops the column back off a
    database stamped at head and re-runs the upgrade, so ``add_column`` really
    executes. Against Postgres and MySQL in CI, that is what catches DDL a
    revision only got away with on SQLite.
    """
    engine = _fresh_engine()
    _create_host_users(engine)
    migrations.upgrade(engine)

    table, column = "users_local_credentials", "must_change_password"
    assert column in {col["name"] for col in inspect(engine).get_columns(table)}

    with engine.begin() as connection:
        connection.exec_driver_sql(f"ALTER TABLE {table} DROP COLUMN {column}")
        connection.exec_driver_sql(f"DELETE FROM {migrations.VERSION_TABLE}")  # noqa: S608 - fixed identifier
    migrations.stamp(engine, "0006_oauth_requested_scope")
    assert column not in {col["name"] for col in inspect(engine).get_columns(table)}

    migrations.upgrade(engine)

    assert column in {col["name"] for col in inspect(engine).get_columns(table)}
    assert migrations.db_revision(engine) == migrations.head_revision()
