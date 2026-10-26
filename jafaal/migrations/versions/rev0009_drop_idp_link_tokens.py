"""Drop ``jafaal_idp_link_tokens``.

Revision ID: 0009_drop_idp_link_tokens
Revises: 0008_prefix_table_names
Create Date: 2026-10-26

Linking an identity provider no longer hands a single-use token to a browser
navigation: an authenticated request parks the OAuth state and returns the
provider's authorization URL, and the callback checks the browser binding. The
table held only short-lived, single-use tokens (60 seconds), so nothing of value
is lost, and a link started before the upgrade is simply started again.

The table is always spelled with the ``jafaal_`` prefix: this revision follows
``0008_prefix_table_names``, so it only ever sees prefixed tables. The downgrade
recreates the empty table as ``0001_initial`` made it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from jafaal.migrations._names import PREFIX, host_user_id_type

revision = "0009_drop_idp_link_tokens"
down_revision = "0008_prefix_table_names"
branch_labels = None
depends_on = None

_TABLE = f"{PREFIX}idp_link_tokens"


def upgrade() -> None:
    op.drop_table(_TABLE)


def downgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id",
            sa.String(36),
            primary_key=True,
            index=True,
            comment="Opaque row identifier, not the link token",
        ),
        sa.Column(
            "token_hash",
            sa.String(64),
            nullable=False,
            unique=True,
            index=True,
            comment="SHA-256 hash of the one-time link token",
        ),
        sa.Column(
            "user_id",
            host_user_id_type(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
            comment="User ID linking the identity provider",
        ),
        sa.Column(
            "idp_id",
            sa.Integer(),
            sa.ForeignKey(f"{PREFIX}identity_providers.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
            comment="Identity provider ID being linked",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            comment="Token creation timestamp",
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            index=True,
            comment="Token expiry at 60 seconds (cleanup marker)",
        ),
        sa.Column(
            "used",
            sa.Boolean(),
            nullable=False,
            comment="Single-use flag (False - unused, True - used)",
        ),
        sa.Column("ip_address", sa.String(45), nullable=True, comment="Client IP address (IPv6 max length)"),
    )
