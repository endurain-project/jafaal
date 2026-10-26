"""Prefix every JAFAAL table, index and constraint name with ``jafaal_``.

Revision ID: 0008_prefix_table_names
Revises: 0007_credential_must_change
Create Date: 2026-10-26

JAFAAL's tables live in the host's database and the host's declarative registry,
so a generic name such as ``identity_providers`` or ``password_reset_tokens`` can
collide with a table the host already has. This revision renames each table, its
indexes and its named unique constraints (and, on PostgreSQL, its primary-key
index and ``id`` sequence); no column or row changes. Foreign keys between
JAFAAL's tables follow the rename on every supported database.

Indexes declared with ``index=True`` (and unique constraints, when the host's
naming convention names them) carry the table name the host's convention gives
them, so their old and new names are both derived from that convention.

A database created by this release already has the prefixed names (the earlier
revisions create them directly when a fresh install is heading here), and this
revision then does nothing. Otherwise every table is renamed, and a table or
index that is not there fails the migration rather than being skipped.

* PostgreSQL renames in place (``ALTER TABLE/INDEX ... RENAME``), which is
  instant and keeps the data pages.
* MySQL and MariaDB rename the table and each index in place
  (``RENAME INDEX``), never dropping an index a foreign key relies on.
* SQLite renames the table and recreates its indexes under the new names; a
  named unique constraint is swapped through a batch operation, which rebuilds
  the table that carries it (no other table references those).

Every code path of the previous release looks the old names up, so **stop every
process running 0.3 or earlier before this migration**; a rolling deployment
across it is not possible.
"""

from __future__ import annotations

from collections.abc import Callable

from alembic import op

from jafaal.migrations._names import PREFIX, current_prefix, index_name, named, unique_name

revision = "0008_prefix_table_names"
down_revision = "0007_credential_must_change"
branch_labels = None
depends_on = None

#: ``(unprefixed table, its index=True indexes as (columns, unique))`` for every
#: table. A unique index comes from ``unique=True, index=True`` on one column.
_TABLES: tuple[tuple[str, tuple[tuple[tuple[str, ...], bool], ...]], ...] = (
    ("identity_providers", ((("id",), False), (("slug",), True), (("enabled",), False))),
    (
        "oauth_states",
        (
            (("id",), False),
            (("idp_id",), False),
            (("user_id",), False),
            (("expires_at",), False),
            (("used",), False),
            (("client_id",), False),
            (("authorization_code_hash",), True),
        ),
    ),
    ("users_sessions", ((("user_id",), False), (("oauth_state_id",), False), (("token_family_id",), True))),
    ("rotated_refresh_tokens", ((("token_family_id",), False),)),
    ("users_local_credentials", ()),
    ("users_api_keys", ((("user_id",), False), (("key_hash",), True))),
    ("users_mfa", ((("user_id",), False),)),
    ("mfa_backup_codes", ((("user_id",), False), (("used",), False))),
    ("users_identity_providers", ((("id",), False), (("user_id",), False), (("idp_id",), False))),
    (
        "idp_link_tokens",
        (
            (("id",), False),
            (("token_hash",), True),
            (("user_id",), False),
            (("idp_id",), False),
            (("expires_at",), False),
        ),
    ),
    ("password_reset_tokens", ((("user_id",), False),)),
    ("sign_up_tokens", ((("user_id",), False),)),
    ("webauthn_credentials", ((("user_id",), False), (("credential_id",), True))),
)

#: Indexes with an explicit name: ``(table, unprefixed name, columns)``.
_NAMED_INDEXES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("mfa_backup_codes", "idx_user_unused_codes", ("user_id", "used")),
)

#: Unique constraints with an explicit name: ``(table, unprefixed name, columns)``.
_NAMED_UNIQUES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("users_mfa", "uq_users_mfa_user_id", ("user_id",)),
    ("users_identity_providers", "uq_identity_links_user_idp", ("user_id", "idp_id")),
    ("users_identity_providers", "uq_identity_links_idp_subject", ("idp_id", "idp_subject")),
)

#: Unique constraints from ``unique=True`` alone: ``(table, columns)``. Named only
#: by a host naming convention with a ``uq`` key; the database names them otherwise.
_CONVENTION_UNIQUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("rotated_refresh_tokens", ("hashed_token",)),
    ("mfa_backup_codes", ("code_hash",)),
)

#: Tables whose integer ``id`` PostgreSQL backs with a ``<table>_id_seq`` sequence.
_SEQUENCE_TABLES = frozenset(
    {
        "identity_providers",
        "rotated_refresh_tokens",
        "users_mfa",
        "mfa_backup_codes",
        "users_identity_providers",
        "webauthn_credentials",
    }
)


def _rename(*, to_prefixed: bool) -> None:
    """Rename every table, with its indexes and constraints, one way or the other."""

    def source(name: str) -> str:
        return name if to_prefixed else f"{PREFIX}{name}"

    def target(name: str) -> str:
        return f"{PREFIX}{name}" if to_prefixed else name

    def source_named(name: str) -> str:
        return name if to_prefixed else named(name, PREFIX)

    def target_named(name: str) -> str:
        return named(name, PREFIX) if to_prefixed else name

    bind = op.get_bind()
    dialect = bind.dialect.name
    quote: Callable[[str], str] = (
        bind.dialect.identifier_preparer.quote if dialect in {"postgresql", "mysql", "mariadb"} else str
    )

    def rename_index(table: str, old: str, new: str, columns: tuple[str, ...], unique: bool) -> None:
        if dialect == "postgresql":
            op.execute(f"ALTER INDEX {quote(old)} RENAME TO {quote(new)}")
        elif dialect in {"mysql", "mariadb"}:
            op.execute(f"ALTER TABLE {quote(table)} RENAME INDEX {quote(old)} TO {quote(new)}")
        else:
            op.drop_index(old, table_name=table)
            op.create_index(new, table, list(columns), unique=unique)

    def rename_unique(table: str, old: str, new: str, columns: tuple[str, ...]) -> None:
        if dialect == "postgresql":
            op.execute(f"ALTER TABLE {quote(table)} RENAME CONSTRAINT {quote(old)} TO {quote(new)}")
        elif dialect in {"mysql", "mariadb"}:
            # A unique constraint is a unique index here.
            op.execute(f"ALTER TABLE {quote(table)} RENAME INDEX {quote(old)} TO {quote(new)}")
        else:
            with op.batch_alter_table(table) as batch:
                batch.drop_constraint(old, type_="unique")
                batch.create_unique_constraint(new, list(columns))

    for table, indexes in _TABLES:
        op.rename_table(source(table), target(table))
        if dialect == "postgresql":
            # The primary-key index and the id sequence keep the old table's name
            # through a rename; a host convention may have named them otherwise.
            op.execute(
                f"ALTER INDEX IF EXISTS {quote(source(table) + '_pkey')} RENAME TO {quote(target(table) + '_pkey')}"
            )
            if table in _SEQUENCE_TABLES:
                op.execute(
                    f"ALTER SEQUENCE IF EXISTS {quote(source(table) + '_id_seq')} "
                    f"RENAME TO {quote(target(table) + '_id_seq')}"
                )
        for columns, unique in indexes:
            old = index_name(source(table), columns, unique=unique)
            new = index_name(target(table), columns, unique=unique)
            if old != new:
                rename_index(target(table), old, new, columns, unique)

    for table, name, columns in _NAMED_INDEXES:
        rename_index(target(table), source_named(name), target_named(name), columns, False)

    for table, name, columns in _NAMED_UNIQUES:
        rename_unique(target(table), source_named(name), target_named(name), columns)

    for table, columns in _CONVENTION_UNIQUES:
        old_name = unique_name(source(table), columns)
        new_name = unique_name(target(table), columns)
        if old_name is not None and new_name is not None and old_name != new_name:
            rename_unique(target(table), old_name, new_name, columns)


def upgrade() -> None:
    # A fresh install already created the prefixed tables in the earlier
    # revisions (see ``jafaal.migrations._names``); there is nothing to rename.
    if current_prefix() == PREFIX:
        return
    _rename(to_prefixed=True)


def downgrade() -> None:
    _rename(to_prefixed=False)
