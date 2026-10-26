"""JAFAAL baseline: create the companion tables.

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-22

The schema as it stood at this revision, written out as explicit DDL so it never
changes with the models: every later change is its own revision on top. The
tables, columns and comments are the current models' minus what the later
revisions add (``webauthn_credentials``, ``oauth_states.upstream_code_verifier``,
the authorization-code columns, ``requested_scope``, ``must_change_password``),
plus the ``client_type`` and ``redirect_path`` columns ``0005`` drops.
``client_type`` is created nullable, the shape ``0005``'s downgrade restores it
to, so every revision's schema is the one its downgrade describes.

Up to 0.3 this revision built the tables from the models instead, so a database
stamped here by an earlier release may differ from it; no published release
recorded anything older than ``0007_credential_must_change``.

Two things come from the host rather than from this file: the type of
``users.id`` (an integer or a UUID, copied by every ``user_id`` column) and the
naming convention of the host's declarative base, which names the ``index=True``
indexes exactly as it does for the models.

The host's ``users`` table must already exist — JAFAAL's tables carry foreign
keys to ``users.id`` — so run the host's own migrations before this baseline.

Table names come from :func:`jafaal.migrations._names.table`: unprefixed, except
on a fresh install heading to ``0008_prefix_table_names`` or later, which creates
the final ``jafaal_`` names directly.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from jafaal.migrations._names import host_user_id_type, named
from jafaal.migrations._names import table as tb

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

#: In creation order, so every foreign key's target exists first.
_TABLES = (
    "identity_providers",
    "oauth_states",
    "users_sessions",
    "rotated_refresh_tokens",
    "users_local_credentials",
    "users_api_keys",
    "users_mfa",
    "mfa_backup_codes",
    "users_identity_providers",
    "idp_link_tokens",
    "password_reset_tokens",
    "sign_up_tokens",
)


def _user_id(*, comment: str | None, nullable: bool = False, index: bool = True, **kwargs) -> sa.Column:
    return sa.Column(
        "user_id",
        host_user_id_type(),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=nullable,
        index=index,
        comment=comment,
        **kwargs,
    )


def _timestamp(name: str, *, nullable: bool = False, comment: str | None = None, **kwargs) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable, comment=comment, **kwargs)


def upgrade() -> None:
    op.create_table(
        tb("identity_providers"),
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("name", sa.String(100), nullable=False, comment="Display name of the IdP"),
        sa.Column("slug", sa.String(50), nullable=False, unique=True, index=True, comment="URL-safe identifier"),
        sa.Column("provider_type", sa.String(50), nullable=False, comment="Type: oidc, oauth2, saml"),
        sa.Column("enabled", sa.Boolean(), nullable=False, index=True, comment="Whether this provider is enabled"),
        sa.Column("client_id", sa.String(512), nullable=True, comment="OAuth2/OIDC client ID (encrypted)"),
        sa.Column("client_secret", sa.String(512), nullable=True, comment="OAuth2/OIDC client secret (encrypted)"),
        sa.Column("issuer_url", sa.String(500), nullable=True, comment="OIDC issuer/discovery URL"),
        sa.Column(
            "authorization_endpoint", sa.String(500), nullable=True, comment="OAuth2/OIDC authorization endpoint"
        ),
        sa.Column("token_endpoint", sa.String(500), nullable=True, comment="OAuth2/OIDC token endpoint"),
        sa.Column("userinfo_endpoint", sa.String(500), nullable=True, comment="OIDC userinfo endpoint"),
        sa.Column("jwks_uri", sa.String(500), nullable=True, comment="OIDC JWKS URI for token verification"),
        sa.Column("scopes", sa.String(500), nullable=True, comment="OAuth2/OIDC scopes to request"),
        sa.Column("icon", sa.String(100), nullable=True, comment="Icon name (FontAwesome) or custom URL"),
        sa.Column(
            "auto_create_users", sa.Boolean(), nullable=False, comment="Automatically create users on first login"
        ),
        sa.Column(
            "allow_email_linking",
            sa.Boolean(),
            nullable=False,
            comment="Allow linking to an existing local account by matching email (requires email_verified)",
        ),
        sa.Column("sync_user_info", sa.Boolean(), nullable=False, comment="Sync user info on each login"),
        sa.Column("user_mapping", sa.JSON(), nullable=True, comment="JSON mapping of IdP claims to user fields"),
        _timestamp("created_at", server_default=sa.func.now(), comment="When this provider was created"),
        _timestamp("updated_at", server_default=sa.func.now(), comment="When this provider was last updated"),
    )

    op.create_table(
        tb("oauth_states"),
        sa.Column(
            "id",
            sa.String(64),
            primary_key=True,
            index=True,
            comment="State parameter itself (secrets.token_urlsafe(32))",
        ),
        sa.Column(
            "idp_id",
            sa.Integer(),
            sa.ForeignKey(f"{tb('identity_providers')}.id", ondelete="CASCADE"),
            nullable=True,
            index=True,
            comment="Identity provider ID (may be null if mobile logic)",
        ),
        _user_id(nullable=True, comment="User ID (for link mode)"),
        sa.Column("purpose", sa.String(20), nullable=False, comment="Flow purpose: login | link | stepup"),
        sa.Column("code_challenge", sa.String(128), nullable=True, comment="Base64url-encoded SHA256(code_verifier)"),
        sa.Column("code_challenge_method", sa.String(10), nullable=True, comment="PKCE method (only S256 supported)"),
        sa.Column("nonce", sa.String(64), nullable=False, comment="OIDC nonce for ID token validation"),
        sa.Column("ip_address", sa.String(45), nullable=True, comment="Client IP address (IPv6 max length)"),
        _timestamp("created_at", server_default=sa.func.now(), comment="OAuth state creation timestamp"),
        _timestamp("expires_at", index=True, comment="Hard expiry at 10 minutes (cleanup marker)"),
        sa.Column(
            "used",
            sa.Boolean(),
            nullable=False,
            index=True,
            comment="True when state is consumed (prevents replay)",
        ),
        sa.Column("client_type", sa.String(10), nullable=True, comment="Client type: web or mobile"),
        sa.Column("redirect_path", sa.String(500), nullable=True, comment="Frontend path after login"),
    )

    op.create_table(
        tb("users_sessions"),
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        _user_id(comment="User ID that the session belongs"),
        sa.Column("refresh_token", sa.String(255), nullable=True, comment="Session hashed refresh token"),
        sa.Column("ip_address", sa.String(45), nullable=False, comment="Client IP address"),
        sa.Column("device_type", sa.String(45), nullable=False, comment="Device type"),
        sa.Column("operating_system", sa.String(45), nullable=False, comment="Operating system"),
        sa.Column("operating_system_version", sa.String(45), nullable=False, comment="Operating system version"),
        sa.Column("browser", sa.String(45), nullable=False, comment="Browser"),
        sa.Column("browser_version", sa.String(45), nullable=False, comment="Browser version"),
        _timestamp("created_at", comment="Session creation date (datetime)"),
        _timestamp("last_activity_at", comment="Last activity timestamp for idle timeout"),
        _timestamp("expires_at", comment="Session expiration date (datetime)"),
        sa.Column(
            "oauth_state_id",
            sa.String(64),
            sa.ForeignKey(f"{tb('oauth_states')}.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
            comment="Link to OAuth state for PKCE validation",
        ),
        sa.Column(
            "tokens_exchanged",
            sa.Boolean(),
            nullable=False,
            comment="Prevents duplicate token exchange for mobile",
        ),
        sa.Column(
            "token_family_id",
            sa.String(36),
            nullable=False,
            unique=True,
            index=True,
            comment="UUID identifying token family for reuse detection",
        ),
        sa.Column(
            "rotation_count",
            sa.Integer(),
            nullable=False,
            comment="Number of times refresh token has been rotated",
        ),
        _timestamp("last_rotation_at", nullable=True, comment="Timestamp of last token rotation"),
        sa.Column("csrf_token_hash", sa.String(255), nullable=True, comment="Hashed CSRF token for refresh validation"),
    )

    op.create_table(
        tb("rotated_refresh_tokens"),
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "token_family_id",
            sa.String(36),
            sa.ForeignKey(f"{tb('users_sessions')}.token_family_id", ondelete="CASCADE"),
            nullable=False,
            index=True,
            comment="UUID of the token family",
        ),
        sa.Column("hashed_token", sa.String(255), nullable=False, unique=True, comment="Hashed old refresh token"),
        sa.Column("rotation_count", sa.Integer(), nullable=False, comment="Which rotation this token belonged to"),
        _timestamp("rotated_at", comment="When this token was rotated"),
        _timestamp("expires_at", comment="Cleanup marker (rotated_at + 60 seconds)"),
        sa.Column(
            "replacement_refresh_token",
            sa.Text(),
            nullable=True,
            comment="Fernet-encrypted replacement refresh token for idempotent in-grace replay",
        ),
        _timestamp("replacement_refresh_token_exp", nullable=True, comment="Expiry of the replacement refresh token"),
    )

    op.create_table(
        tb("users_local_credentials"),
        _user_id(comment=None, index=False, primary_key=True),
        sa.Column("password_hash", sa.String(250), nullable=False, comment="Local account password hash"),
        _timestamp("created_at", server_default=sa.func.now()),
        _timestamp("updated_at", server_default=sa.func.now()),
    )

    op.create_table(
        tb("users_api_keys"),
        sa.Column("id", sa.String(36), primary_key=True, nullable=False, comment="Unique key identifier (UUID4)"),
        _user_id(comment="User ID that the API key belongs to"),
        sa.Column("name", sa.String(100), nullable=False, comment="User-friendly label for the key"),
        sa.Column(
            "key_prefix",
            sa.String(8),
            nullable=False,
            comment="First 8 chars of the random key part, used for UI identification",
        ),
        sa.Column(
            "key_hash",
            sa.String(64),
            nullable=False,
            unique=True,
            index=True,
            comment="SHA-256 hex digest of the full raw key",
        ),
        sa.Column("scopes", sa.Text(), nullable=False, comment="JSON-encoded list of granted scope strings"),
        _timestamp("expires_at", nullable=True, comment="Key expiration timestamp (NULL = no expiry)"),
        _timestamp("last_used_at", nullable=True, comment="Timestamp of last successful authentication"),
        _timestamp("created_at", comment="Key creation timestamp"),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            comment="Whether the key is active. False = revoked (soft delete)",
        ),
    )

    op.create_table(
        tb("users_mfa"),
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        _user_id(comment="FK to users — one row per user"),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, comment="Whether TOTP MFA is active for this user"),
        sa.Column("mfa_secret", sa.String(512), nullable=True, comment="Fernet-encrypted TOTP secret"),
        sa.UniqueConstraint("user_id", name=named("uq_users_mfa_user_id")),
    )

    op.create_table(
        tb("mfa_backup_codes"),
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        _user_id(comment="User who owns this backup code"),
        sa.Column("code_hash", sa.String(255), nullable=False, unique=True, comment="Argon2 hash of the backup code"),
        sa.Column("used", sa.Boolean(), nullable=False, index=True, comment="Whether this code has been consumed"),
        _timestamp("used_at", nullable=True, comment="When this code was used"),
        _timestamp("created_at", comment="When this code was generated"),
        _timestamp("expires_at", nullable=True, comment="Optional expiry for code rotation policy"),
    )
    op.create_index(named("idx_user_unused_codes"), tb("mfa_backup_codes"), ["user_id", "used"])

    op.create_table(
        tb("users_identity_providers"),
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, index=True),
        _user_id(comment="User ID"),
        sa.Column(
            "idp_id",
            sa.Integer(),
            sa.ForeignKey(f"{tb('identity_providers')}.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
            comment="Identity Provider ID",
        ),
        sa.Column("idp_subject", sa.String(500), nullable=False, comment="Subject/ID from the identity provider"),
        _timestamp("linked_at", server_default=sa.func.now(), comment="When this IdP was linked to the user"),
        _timestamp("last_login", nullable=True, comment="Last login using this IdP"),
        sa.Column("idp_refresh_token", sa.Text(), nullable=True, comment="Encrypted refresh token"),
        _timestamp("idp_access_token_expires_at", nullable=True, comment="Access token expiry time"),
        _timestamp("idp_refresh_token_updated_at", nullable=True, comment="Last refresh token update"),
        sa.UniqueConstraint("user_id", "idp_id", name=named("uq_identity_links_user_idp")),
        sa.UniqueConstraint("idp_id", "idp_subject", name=named("uq_identity_links_idp_subject")),
    )

    op.create_table(
        tb("idp_link_tokens"),
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
        _user_id(comment="User ID linking the identity provider"),
        sa.Column(
            "idp_id",
            sa.Integer(),
            sa.ForeignKey(f"{tb('identity_providers')}.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
            comment="Identity provider ID being linked",
        ),
        _timestamp("created_at", server_default=sa.func.now(), comment="Token creation timestamp"),
        _timestamp("expires_at", index=True, comment="Token expiry at 60 seconds (cleanup marker)"),
        sa.Column(
            "used",
            sa.Boolean(),
            nullable=False,
            comment="Single-use flag (False - unused, True - used)",
        ),
        sa.Column("ip_address", sa.String(45), nullable=True, comment="Client IP address (IPv6 max length)"),
    )

    for name, owner, token in (
        ("password_reset_tokens", "password reset token", "password reset token"),
        ("sign_up_tokens", "sign up token", "sign up token"),
    ):
        op.create_table(
            tb(name),
            sa.Column("id", sa.String(64), primary_key=True),
            _user_id(comment=f"User ID that the {owner} belongs to"),
            sa.Column("token_hash", sa.String(128), nullable=False, comment=f"Hashed {token}"),
            _timestamp("created_at", comment="Token creation date (datetime)"),
            _timestamp("expires_at", comment="Token expiration date (datetime)"),
            sa.Column("used", sa.Boolean(), nullable=False, comment="Token usage status"),
        )


def downgrade() -> None:
    for name in reversed(_TABLES):
        op.drop_table(tb(name))
