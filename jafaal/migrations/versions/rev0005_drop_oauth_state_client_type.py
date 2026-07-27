"""Drop the pre-standards ``client_type`` and ``redirect_path`` columns.

Revision ID: 0005_drop_oauth_state_client_type
Revises: 0004_oauth_authorization_code
Create Date: 2026-07-28

Both columns existed to support a JAFAAL-specific login flow that no longer
exists:

* ``client_type`` recorded a ``web``/``mobile`` hint taken from the
  ``X-Client-Type`` request header. Token delivery is now a property of the
  registered :class:`~jafaal.settings.OAuthClient`, so there is nothing for a
  request to declare and nothing to persist.
* ``redirect_path`` held a caller-supplied frontend path validated only as "a
  relative path with no traversal". Every redirect target is now an exact match
  against a registered ``redirect_uri``, which is recorded in ``redirect_uri``.

Like the preceding revisions this is idempotent: on a fresh database the
baseline (``0001_initial``) materialises the current models, which no longer
carry either column, so this revision inspects the live schema and only drops
what is actually present.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_drop_oauth_state_client_type"
down_revision = "0004_oauth_authorization_code"
branch_labels = None
depends_on = None

_TABLE = "oauth_states"

_DROPPED: tuple[tuple[str, sa.types.TypeEngine, bool, str], ...] = (
    (
        "client_type",
        sa.String(length=10),
        False,
        "Client type: web or mobile",
    ),
    (
        "redirect_path",
        sa.String(length=500),
        True,
        "Frontend path after login",
    ),
)


def _existing_columns(bind: sa.engine.Connection) -> set[str]:
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(_TABLE)}


def _indexes(bind: sa.engine.Connection) -> list[dict]:
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        return []
    return [index for index in inspector.get_indexes(_TABLE) if index.get("name")]


def upgrade() -> None:
    bind = op.get_bind()
    present = _existing_columns(bind)
    if not present:
        return
    dropping = {name for name, _type, _nullable, _comment in _DROPPED}
    # Indexes first: SQLite refuses to drop a column any index still references,
    # and an orphaned index on other backends would break a later migration.
    for index in _indexes(bind):
        if dropping.intersection(index.get("column_names") or ()):
            op.drop_index(index["name"], table_name=_TABLE)
    for name, _type, _nullable, _comment in _DROPPED:
        if name in present:
            op.drop_column(_TABLE, name)


def downgrade() -> None:
    bind = op.get_bind()
    present = _existing_columns(bind)
    if not present:
        return
    for name, type_, nullable, comment in reversed(_DROPPED):
        if name in present:
            continue
        # Re-added nullable regardless of the original constraint: the rows that
        # exist now were written without these columns, so a NOT NULL restore
        # would fail on any non-empty table and there is no value to backfill —
        # the concept the column recorded no longer exists.
        op.add_column(_TABLE, sa.Column(name, type_, nullable=True, comment=comment))
        _ = nullable
