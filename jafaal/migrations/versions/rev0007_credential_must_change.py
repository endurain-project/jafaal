"""Add ``must_change_password`` to ``users_local_credentials``.

Revision ID: 0007_credential_must_change
Revises: 0006_oauth_requested_scope
Create Date: 2026-08-17

A password an operator set — seeding the first administrator, or a CLI
``reset-password`` — is known to whoever set it. Marking the credential lets
login refuse it until the account owner replaces it, so a bootstrap password
cannot quietly become a permanent one.

Defaults to false, so every credential written before this revision (and every
one written by the ordinary sign-up and reset flows) is unaffected.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from jafaal.migrations._names import table as tb

revision = "0007_credential_must_change"
down_revision = "0006_oauth_requested_scope"
branch_labels = None
depends_on = None

_TABLE = "users_local_credentials"
_COLUMN = "must_change_password"
_COMMENT = "Password must be replaced before the account can log in"


def upgrade() -> None:
    op.add_column(
        tb(_TABLE),
        sa.Column(
            _COLUMN,
            sa.Boolean(),
            nullable=False,
            server_default="0",
            comment=_COMMENT,
        ),
    )


def downgrade() -> None:
    op.drop_column(tb(_TABLE), _COLUMN)
