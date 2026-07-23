"""JAFAAL baseline: create all companion tables.

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-22

The baseline creates JAFAAL's tables directly from the shared declarative
metadata (scoped to JAFAAL-owned tables via ``jafaal_table_names``), so the
initial schema can never drift from the models. Future schema changes are added
as normal Alembic revisions layered on top of this one.

The host's ``users`` table must already exist — JAFAAL's tables carry foreign
keys to ``users.id`` — so run the host's own migrations before this baseline.
"""

from __future__ import annotations

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def _jafaal_tables():
    from jafaal.orm import get_active_base, jafaal_table_names

    names = jafaal_table_names()
    metadata = get_active_base().metadata
    return [table for table in metadata.sorted_tables if table.name in names]


def upgrade() -> None:
    from jafaal.orm import get_active_base

    get_active_base().metadata.create_all(bind=op.get_bind(), tables=_jafaal_tables())


def downgrade() -> None:
    from jafaal.orm import get_active_base

    get_active_base().metadata.drop_all(bind=op.get_bind(), tables=_jafaal_tables())
