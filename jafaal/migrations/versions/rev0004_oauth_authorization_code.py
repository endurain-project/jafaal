"""Add the RFC 6749 authorization-code columns to ``oauth_states``.

Revision ID: 0004_oauth_authorization_code
Revises: 0003_oauth_state_upstream_pkce
Create Date: 2026-07-27

Adds the four columns the standards-based authorization-code flow needs:

* ``client_id`` / ``redirect_uri`` — the registered public client and the exact
  redirect target, re-checked when the code is redeemed (RFC 6749 §4.1.3,
  RFC 9700 §4.1);
* ``client_state`` — the client's opaque ``state``, echoed back with the code;
  and
* ``authorization_code_hash`` — the keyed digest of the issued code, unique so
  the database itself enforces one-code-one-row.

The two indexes are named by the host's naming convention, as the model's
``index=True`` columns are.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from jafaal.migrations._names import index_name
from jafaal.migrations._names import table as tb

revision = "0004_oauth_authorization_code"
down_revision = "0003_oauth_state_upstream_pkce"
branch_labels = None
depends_on = None

_TABLE = "oauth_states"
_CODE_HASH = "authorization_code_hash"

_COLUMNS: tuple[tuple[str, sa.types.TypeEngine, str], ...] = (
    (
        "client_id",
        sa.String(length=128),
        "Registered public client that initiated the authorization request",
    ),
    (
        "redirect_uri",
        sa.String(length=500),
        "Exact redirect_uri from the authorization request; re-checked at token exchange",
    ),
    (
        "client_state",
        sa.String(length=256),
        "Opaque client 'state', echoed back with the authorization code (RFC 6749 4.1.2)",
    ),
    (
        _CODE_HASH,
        sa.String(length=64),
        "HMAC-SHA256 of the issued authorization code (the plaintext is never stored)",
    ),
)

#: ``(column, unique)`` for each index this revision adds.
_INDEXES: tuple[tuple[str, bool], ...] = (
    # Unique so the database, not application code, guarantees an authorization
    # code maps to at most one state row.
    (_CODE_HASH, True),
    ("client_id", False),
)


def upgrade() -> None:
    for name, type_, comment in _COLUMNS:
        op.add_column(tb(_TABLE), sa.Column(name, type_, nullable=True, comment=comment))
    for column, unique in _INDEXES:
        op.create_index(index_name(tb(_TABLE), [column], unique=unique), tb(_TABLE), [column], unique=unique)


def downgrade() -> None:
    # Indexes must go first: SQLite refuses to drop a column that any index
    # still references.
    for column, unique in _INDEXES:
        op.drop_index(index_name(tb(_TABLE), [column], unique=unique), table_name=tb(_TABLE))
    for name, _type, _comment in reversed(_COLUMNS):
        op.drop_column(tb(_TABLE), name)
