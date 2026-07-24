"""Add ``oauth_states.upstream_code_verifier`` (upstream PKCE support).

Revision ID: 0003_oauth_state_upstream_pkce
Revises: 0002_webauthn_credentials
Create Date: 2026-07-22

Adds the column that stores JAFAAL's own (Fernet-encrypted) PKCE
``code_verifier`` for the upstream identity-provider authorization-code flow, so
an intercepted authorization code cannot be redeemed without it (RFC 7636).

The column is idempotent to add: on a fresh database the baseline
(``0001_initial``) already materialises every currently mapped JAFAAL table
directly from the models -- including this column -- so this revision inspects
the live schema and only adds the column on existing databases stamped before
it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_oauth_state_upstream_pkce"
down_revision = "0002_webauthn_credentials"
branch_labels = None
depends_on = None

_TABLE = "oauth_states"
_COLUMN = "upstream_code_verifier"


def _has_column(bind: sa.engine.Connection) -> bool:
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        return False
    return any(col["name"] == _COLUMN for col in inspector.get_columns(_TABLE))


def upgrade() -> None:
    bind = op.get_bind()
    if _has_column(bind):
        return
    op.add_column(
        _TABLE,
        sa.Column(
            _COLUMN,
            sa.String(length=512),
            nullable=True,
            comment="Encrypted (Fernet) PKCE code_verifier JAFAAL sends to the upstream IdP token endpoint",
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind):
        return
    op.drop_column(_TABLE, _COLUMN)
