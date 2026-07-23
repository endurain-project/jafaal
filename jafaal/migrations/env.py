"""Alembic environment for JAFAAL's migrations.

Driven programmatically by :mod:`jafaal.migrations` (an active connection is
passed via ``config.attributes["connection"]``), but also supports the standard
offline/online CLI paths. Migrations are scoped to JAFAAL's own tables and use a
dedicated version table so they never collide with the host's Alembic history.
"""

from __future__ import annotations

from alembic import context

from jafaal.migrations import VERSION_TABLE, jafaal_include_object
from jafaal.orm import get_active_base

target_metadata = get_active_base().metadata


def _configure(**kwargs) -> None:
    context.configure(
        target_metadata=target_metadata,
        version_table=VERSION_TABLE,
        include_object=jafaal_include_object,
        render_as_batch=True,
        compare_type=True,
        **kwargs,
    )


def run_migrations_offline() -> None:
    """Emit SQL for the migrations without a live database connection."""
    _configure(
        url=context.config.get_main_option("sqlalchemy.url"),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run the migrations against a live connection (shared or self-built)."""
    connection = context.config.attributes.get("connection", None)
    if connection is not None:
        _configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()
        return

    from sqlalchemy import engine_from_config, pool

    connectable = engine_from_config(
        context.config.get_section(context.config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as new_connection:
        _configure(connection=new_connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
