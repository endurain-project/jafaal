"""Add ``oauth_states.upstream_code_verifier`` (upstream PKCE support).

Revision ID: 0003_oauth_state_upstream_pkce
Revises: 0002_webauthn_credentials
Create Date: 2026-07-22

Adds the column that stores JAFAAL's own (Fernet-encrypted) PKCE
``code_verifier`` for the upstream identity-provider authorization-code flow, so
an intercepted authorization code cannot be redeemed without it (RFC 7636).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from jafaal.migrations._names import table as tb

revision = "0003_oauth_state_upstream_pkce"
down_revision = "0002_webauthn_credentials"
branch_labels = None
depends_on = None

_TABLE = "oauth_states"
_COLUMN = "upstream_code_verifier"


def upgrade() -> None:
    op.add_column(
        tb(_TABLE),
        sa.Column(
            _COLUMN,
            sa.String(length=512),
            nullable=True,
            comment="Encrypted (Fernet) PKCE code_verifier JAFAAL sends to the upstream IdP token endpoint",
        ),
    )


def downgrade() -> None:
    op.drop_column(tb(_TABLE), _COLUMN)
