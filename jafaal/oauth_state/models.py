"""SQLAlchemy ORM model for OAuth/SSO flow state persistence."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from jafaal.orm import UserId, get_active_base

# JAFAAL's models bind to the host-owned declarative base at map_models() time.
Base = get_active_base()

if TYPE_CHECKING:
    from jafaal.identity_providers.models import IdentityProvider
    from jafaal.sessions.models import UsersSessions
    from jafaal.user_model import UserMixin as Users


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
        redirect_path: Frontend path after login.
        client_type: web or mobile.
        ip_address: Client IP for optional validation.
        created_at: Timestamp for expiry calculation.
        expires_at: Hard expiry at 10 minutes.
        used: Prevents replay attacks.
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

    redirect_path: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Frontend path after login",
    )

    client_type: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        comment="Client type: web or mobile",
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

    # Relationships
    identity_provider: Mapped["IdentityProvider | None"] = relationship(
        "IdentityProvider", back_populates="oauth_states"
    )
    users: Mapped["Users | None"] = relationship("Users", back_populates="oauth_states")
    users_sessions: Mapped[list["UsersSessions"]] = relationship("UsersSessions", back_populates="oauth_state")
