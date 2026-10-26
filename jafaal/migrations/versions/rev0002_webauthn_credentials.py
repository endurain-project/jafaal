"""Add the ``webauthn_credentials`` table (passkey support).

Revision ID: 0002_webauthn_credentials
Revises: 0001_initial
Create Date: 2026-07-22

Creates the companion table introduced with WebAuthn / passkey support, as
explicit DDL so the revision never changes with the model.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from jafaal.migrations._names import host_user_id_type
from jafaal.migrations._names import table as tb

revision = "0002_webauthn_credentials"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        tb("webauthn_credentials"),
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            host_user_id_type(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
            comment="User the credential belongs to",
        ),
        sa.Column(
            "credential_id",
            sa.String(512),
            nullable=False,
            unique=True,
            index=True,
            comment="Base64url-encoded credential id from the authenticator",
        ),
        sa.Column("public_key", sa.Text(), nullable=False, comment="Base64-encoded COSE public key"),
        sa.Column(
            "sign_count",
            sa.BigInteger(),
            nullable=False,
            comment="Authenticator signature counter (clone detection)",
        ),
        sa.Column("transports", sa.String(255), nullable=True, comment="Comma-joined transport hints"),
        sa.Column("aaguid", sa.String(36), nullable=True, comment="Authenticator model identifier (AAGUID)"),
        sa.Column("label", sa.String(255), nullable=True, comment="User-friendly credential name"),
        sa.Column("backup_eligible", sa.Boolean(), nullable=True),
        sa.Column("backup_state", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table(tb("webauthn_credentials"))
