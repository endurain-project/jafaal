"""Tests for the packaged Alembic migrations (``jafaal.migrations``)."""

from __future__ import annotations

import pytest

pytest.importorskip("alembic")

from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import StaticPool

import jafaal.orm as jafaal_orm
from jafaal import migrations

# conftest maps JAFAAL onto its host-owned Base at import; reuse that active base.
Base = jafaal_orm.get_active_base()


def _fresh_engine():
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
