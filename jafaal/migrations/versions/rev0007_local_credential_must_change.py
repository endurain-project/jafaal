"""Add ``must_change_password`` to ``users_local_credentials``.

Revision ID: 0007_local_credential_must_change
Revises: 0006_oauth_state_requested_scope
Create Date: 2026-08-17

A password an operator set — seeding the first administrator, or a CLI
``reset-password`` — is known to whoever set it. Marking the credential lets
login refuse it until the account owner replaces it, so a bootstrap password
cannot quietly become a permanent one.

Defaults to false, so every credential written before this revision (and every
one written by the ordinary sign-up and reset flows) is unaffected.

Like the preceding revisions this is idempotent to add: on a fresh database the
baseline (``0001_initial``) materialises every currently mapped JAFAAL table
directly from the models — including this column — so this revision inspects the
live schema and only adds what is missing on databases stamped before it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_local_credential_must_change"
down_revision = "0006_oauth_state_requested_scope"
branch_labels = None
depends_on = None

_TABLE = "users_local_credentials"
_COLUMN = "must_change_password"
_COMMENT = "Password must be replaced before the account can log in"


def _existing_columns(bind: sa.engine.Connection) -> set[str]:
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(_TABLE)}


def upgrade() -> None:
    bind = op.get_bind()
    present = _existing_columns(bind)
    if not present or _COLUMN in present:
        return
    op.add_column(
        _TABLE,
        sa.Column(
            _COLUMN,
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
            comment=_COMMENT,
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if _COLUMN in _existing_columns(bind):
        op.drop_column(_TABLE, _COLUMN)
