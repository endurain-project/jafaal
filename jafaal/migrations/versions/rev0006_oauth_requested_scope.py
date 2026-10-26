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
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from jafaal.migrations._names import table as tb

revision = "0006_oauth_requested_scope"
down_revision = "0005_drop_oauth_client_type"
branch_labels = None
depends_on = None

_TABLE = "oauth_states"
_COLUMN = "requested_scope"
_COMMENT = "Space-delimited 'scope' from the authorization request, re-applied at token exchange"


def upgrade() -> None:
    op.add_column(tb(_TABLE), sa.Column(_COLUMN, sa.String(length=500), nullable=True, comment=_COMMENT))


def downgrade() -> None:
    op.drop_column(tb(_TABLE), _COLUMN)
