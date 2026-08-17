"""Add ``requested_scope`` to ``oauth_states``.

Revision ID: 0006_oauth_requested_scope
Revises: 0005_drop_oauth_client_type
Create Date: 2026-07-27

RFC 6749 §3.3 lets a client request a narrower ``scope`` than it could have, and
§5.1 makes the granted scope part of the token response. The authorization
request and the token exchange are separated by a browser round trip, so the
requested value has to survive on the state row to be applied when the code is
redeemed — otherwise a client asking for ``profile`` is handed its user's entire
account anyway.

Like the preceding revisions this is idempotent to add: on a fresh database the
baseline (``0001_initial``) materialises every currently mapped JAFAAL table
directly from the models — including this column — so this revision inspects the
live schema and only adds what is missing on databases stamped before it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_oauth_requested_scope"
down_revision = "0005_drop_oauth_client_type"
branch_labels = None
depends_on = None

_TABLE = "oauth_states"
_COLUMN = "requested_scope"
_COMMENT = "Space-delimited 'scope' from the authorization request, re-applied at token exchange"


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
    op.add_column(_TABLE, sa.Column(_COLUMN, sa.String(length=500), nullable=True, comment=_COMMENT))


def downgrade() -> None:
    bind = op.get_bind()
    if _COLUMN in _existing_columns(bind):
        op.drop_column(_TABLE, _COLUMN)
