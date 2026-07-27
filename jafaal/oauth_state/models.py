"""SQLAlchemy ORM model for OAuth/SSO flow state persistence."""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from jafaal.orm import UserId, get_active_base, host_user_model

# JAFAAL's models bind to the host-owned declarative base at map_models() time.
Base = get_active_base()

if TYPE_CHECKING:
    from jafaal.identity_providers.models import IdentityProvider
    from jafaal.sessions.models import UsersSessions


class OAuthState(Base):
    """
    Server-side storage for OAuth/SSO flow state.

    This replaces cookie-based state with database persistence
    for enhanced security and mobile support. Stores PKCE
    challenges, OIDC nonce, and flow metadata.

    Attributes:
        id: Primary key, state parameter itself (random URL-safe token).
        idp_id: Foreign key to identity_provider.
        user_id: Foreign key to users (for link mode, nullable).
        purpose: Flow purpose (``login``, ``link``, or ``stepup``).
        code_challenge: PKCE challenge (base64url-encoded).
        code_challenge_method: PKCE method (always S256).
        upstream_code_verifier: Encrypted PKCE code_verifier JAFAAL replays to
            the upstream IdP token endpoint (RFC 7636).
        nonce: OIDC nonce for ID token validation.
        ip_address: Client IP for optional validation.
        created_at: Timestamp for expiry calculation.
        expires_at: Hard expiry at 10 minutes.
        used: Prevents replay attacks.
        client_id: The registered public client that started the flow.
        redirect_uri: Exact redirect URI from the authorization request, already
            matched against the client's registration and re-checked at token
            exchange (RFC 6749 §4.1.3). Every browser redirect the flow emits
            targets this URI and nothing else.
        client_state: The client's opaque ``state``, echoed back with the code.
        requested_scope: The space-delimited ``scope`` the client asked for in
            the authorization request (RFC 6749 §3.3), replayed as a narrowing
            bound when the code is redeemed. Distinct from the *upstream*
            provider scopes on :class:`~jafaal.identity_providers.models.IdentityProvider`.
        authorization_code_hash: Keyed digest of the issued authorization code.
        identity_provider: Relationship to IdentityProvider model.
        users: Relationship to Users model (nullable).
        users_sessions: Relationship to UsersSessions model.
    """

    __tablename__ = "oauth_states"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        index=True,
        comment="State parameter itself (secrets.token_urlsafe(32))",
    )

    idp_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("identity_providers.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Identity provider ID (may be null if mobile logic)",
    )

    user_id: Mapped[UserId | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="User ID (for link mode)",
    )

    purpose: Mapped[str] = mapped_column(
        String(20),
        default="login",
        nullable=False,
        comment="Flow purpose: login | link | stepup",
    )

    code_challenge: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="Base64url-encoded SHA256(code_verifier)",
    )

    code_challenge_method: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True,
        comment="PKCE method (only S256 supported)",
    )

    upstream_code_verifier: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        comment="Encrypted (Fernet) PKCE code_verifier JAFAAL sends to the upstream IdP token endpoint",
    )

    nonce: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="OIDC nonce for ID token validation",
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        comment="Client IP address (IPv6 max length)",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="OAuth state creation timestamp",
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Hard expiry at 10 minutes (cleanup marker)",
    )

    used: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="True when state is consumed (prevents replay)",
    )

    # --- RFC 6749 authorization-code flow (registered public clients) ---
    #
    # Populated only when the flow was started at ``/auth/authorize`` by a
    # registered client. A flow started through JAFAAL's own frontend leaves
    # them null and takes the native (session-id) delivery path instead.

    client_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Registered public client that initiated the authorization request",
    )

    redirect_uri: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Exact redirect_uri from the authorization request; re-checked at token exchange",
    )

    client_state: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        comment="Opaque client 'state', echoed back with the authorization code (RFC 6749 4.1.2)",
    )

    requested_scope: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Space-delimited 'scope' from the authorization request, re-applied at token exchange",
    )

    authorization_code_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        unique=True,
        index=True,
        comment="HMAC-SHA256 of the issued authorization code (the plaintext is never stored)",
    )

    # Relationships
    identity_provider: Mapped["IdentityProvider | None"] = relationship(
        "IdentityProvider", back_populates="oauth_states"
    )
    users: Mapped[Any] = relationship(host_user_model, back_populates="oauth_states")
    users_sessions: Mapped[list["UsersSessions"]] = relationship("UsersSessions", back_populates="oauth_state")
