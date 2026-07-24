"""Auth-owned WebAuthn / passkey credential model (table: ``webauthn_credentials``).

Stores each registered public-key credential. ``credential_id`` and
``public_key`` are kept as base64url/base64 text (not raw ``BLOB``) so the unique
index on ``credential_id`` is portable across SQLite/PostgreSQL/MySQL; the
service layer encodes/decodes when talking to ``py_webauthn``.
"""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from jafaal.orm import UserId, get_active_base

# JAFAAL's models bind to the host-owned declarative base at map_models() time.
Base = get_active_base()

if TYPE_CHECKING:
    from jafaal.user_model import UserMixin as Users


class WebAuthnCredential(Base):
    """A registered WebAuthn (passkey) credential.

    Attributes:
        id: Surrogate primary key.
        user_id: Owner (FK to ``users.id``).
        credential_id: Base64url of the authenticator's credential id (unique).
        public_key: Base64 of the COSE public key used to verify assertions.
        sign_count: Signature counter, updated on each authentication (clone
            detection).
        transports: Comma-joined transport hints (e.g. ``"internal,hybrid"``).
        aaguid: Authenticator model identifier (may be all-zero for privacy).
        label: User-friendly name for the credential.
        backup_eligible: Whether the credential can be backed up/synced.
        backup_state: Whether the credential is currently backed up/synced.
        created_at: Registration timestamp.
        last_used_at: Last successful authentication timestamp.
    """

    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[UserId] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="User the credential belongs to",
    )
    credential_id: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        unique=True,
        index=True,
        comment="Base64url-encoded credential id from the authenticator",
    )
    public_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Base64-encoded COSE public key",
    )
    sign_count: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        comment="Authenticator signature counter (clone detection)",
    )
    transports: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Comma-joined transport hints",
    )
    aaguid: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        comment="Authenticator model identifier (AAGUID)",
    )
    label: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="User-friendly credential name",
    )
    backup_eligible: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    backup_state: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    users: Mapped["Users"] = relationship(
        back_populates="webauthn_credentials",
    )
