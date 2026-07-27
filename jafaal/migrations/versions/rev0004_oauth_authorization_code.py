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

Like the preceding revisions these are idempotent to add: on a fresh database
the baseline (``0001_initial``) materialises every currently mapped JAFAAL table
directly from the models — including these columns — so this revision inspects
the live schema and only adds what is missing on databases stamped before it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_oauth_authorization_code"
down_revision = "0003_oauth_state_upstream_pkce"
branch_labels = None
depends_on = None

_TABLE = "oauth_states"
_CODE_HASH = "authorization_code_hash"
_INDEX = "ix_oauth_states_authorization_code_hash"
_CLIENT_INDEX = "ix_oauth_states_client_id"

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


def _existing_columns(bind: sa.engine.Connection) -> set[str]:
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(_TABLE)}


def _indexes(bind: sa.engine.Connection) -> list[dict]:
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        return []
    return [index for index in inspector.get_indexes(_TABLE) if index.get("name")]


def upgrade() -> None:
    bind = op.get_bind()
    present = _existing_columns(bind)
    if not present:
        return
    for name, type_, comment in _COLUMNS:
        if name in present:
            continue
        op.add_column(_TABLE, sa.Column(name, type_, nullable=True, comment=comment))

    existing_index_names = {index["name"] for index in _indexes(bind)}
    # Unique so the database, not application code, guarantees an authorization
    # code maps to at most one state row.
    if _CODE_HASH not in present and _INDEX not in existing_index_names:
        op.create_index(_INDEX, _TABLE, [_CODE_HASH], unique=True)
    if "client_id" not in present and _CLIENT_INDEX not in existing_index_names:
        op.create_index(_CLIENT_INDEX, _TABLE, ["client_id"])


def downgrade() -> None:
    bind = op.get_bind()
    present = _existing_columns(bind)
    if not present:
        return
    dropping = {name for name, _type, _comment in _COLUMNS}
    # Indexes must go first: SQLite refuses to drop a column that any index
    # still references, and leaving an orphaned index behind on other backends
    # would break the next upgrade.
    for index in _indexes(bind):
        if dropping.intersection(index.get("column_names") or ()):
            op.drop_index(index["name"], table_name=_TABLE)
    for name, _type, _comment in reversed(_COLUMNS):
        if name in present:
            op.drop_column(_TABLE, name)
