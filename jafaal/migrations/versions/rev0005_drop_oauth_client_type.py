"""Drop the pre-standards ``client_type`` and ``redirect_path`` columns.

Revision ID: 0005_drop_oauth_client_type
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
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from jafaal.migrations._names import table as tb

revision = "0005_drop_oauth_client_type"
down_revision = "0004_oauth_authorization_code"
branch_labels = None
depends_on = None

_TABLE = "oauth_states"

_DROPPED: tuple[tuple[str, sa.types.TypeEngine, str], ...] = (
    ("client_type", sa.String(length=10), "Client type: web or mobile"),
    ("redirect_path", sa.String(length=500), "Frontend path after login"),
)


def upgrade() -> None:
    for name, _type, _comment in _DROPPED:
        op.drop_column(tb(_TABLE), name)


def downgrade() -> None:
    # Re-added nullable: the rows that exist now were written without these
    # columns, and there is no value to backfill — the concept the column
    # recorded no longer exists. ``0001_initial`` creates ``client_type``
    # nullable for the same reason, so both describe one schema.
    for name, type_, comment in reversed(_DROPPED):
        op.add_column(tb(_TABLE), sa.Column(name, type_, nullable=True, comment=comment))
