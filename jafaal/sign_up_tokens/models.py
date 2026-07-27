"""Sign-up token database models."""

from datetime import datetime as datetime_type
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from jafaal.orm import UserId, get_active_base, host_user_model

# JAFAAL's models bind to the host-owned declarative base at map_models() time.
Base = get_active_base()

if TYPE_CHECKING:
    pass


class SignUpToken(Base):
    """
    Sign-up token database model.

    Attributes:
        id: Unique token identifier (string, 64 chars).
        user_id: ID of the user who owns the token.
        token_hash: Hashed sign-up token.
        created_at: Token creation date.
        expires_at: Token expiration date.
        used: Whether the token has been used.
        users: Relationship to the Users model.
    """

    __tablename__ = "sign_up_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[UserId] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment=("User ID that the sign up token belongs to"),
    )
    token_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Hashed sign up token",
    )
    created_at: Mapped[datetime_type] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Token creation date (datetime)",
    )
    expires_at: Mapped[datetime_type] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Token expiration date (datetime)",
    )
    used: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        comment="Token usage status",
    )

    # Define a relationship to the Users model
    users: Mapped[Any] = relationship(host_user_model, back_populates="sign_up_tokens")
