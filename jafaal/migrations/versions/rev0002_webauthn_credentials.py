"""Add the ``webauthn_credentials`` table (passkey support).

Revision ID: 0002_webauthn_credentials
Revises: 0001_initial
Create Date: 2026-07-22

Creates the companion table introduced with WebAuthn / passkey support. The
table is created from the shared declarative metadata (so it can never drift
from the model) and uses ``checkfirst=True`` for idempotency: on a fresh
database the baseline (``0001_initial``) already materialises every currently
mapped JAFAAL table — including this one — so this revision becomes a no-op,
while existing databases stamped at ``0001_initial`` before passkeys existed get
the new table created here.
"""

from __future__ import annotations

from alembic import op

revision = "0002_webauthn_credentials"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

_TABLE = "webauthn_credentials"


def _table():
    from jafaal.orm import get_active_base

    return get_active_base().metadata.tables.get(_TABLE)


def upgrade() -> None:
    table = _table()
    if table is not None:
        table.create(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    table = _table()
    if table is not None:
        table.drop(bind=op.get_bind(), checkfirst=True)
