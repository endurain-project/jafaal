"""Utility functions for sign-up token operations."""

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy.orm import Session

import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.exceptions as jafaal_exceptions
import jafaal.password_policy as jafaal_password_policy
import jafaal.ports as jafaal_ports
import jafaal.schema as jafaal_schema
import jafaal.sign_up_tokens.crud as sign_up_tokens_crud
import jafaal.sign_up_tokens.schema as sign_up_tokens_schema
import jafaal.token_hashing as token_hashing
from jafaal.orm import UserId, session_scope

if TYPE_CHECKING:
    from jafaal.identity_service import IdentityService

logger = logging.getLogger(__name__)


def create_sign_up_token(user_id: UserId, db: Session) -> str:
    """
    Create and persist a sign-up token for a user.

    Args:
        user_id: ID of the user signing up.
        db: Active SQLAlchemy session.

    Returns:
        The plaintext token to deliver to the user.
        Only the hash is stored in the database.
    """
    # Generate token and hash
    token, token_hash = token_hashing.generate_token_and_hash()

    # Create token object
    reset_token = sign_up_tokens_schema.SignUpToken(
        id=str(uuid4()),
        user_id=user_id,
        token_hash=token_hash,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=24),  # 24 hour expiration
        used=False,
    )

    # Save to database
    sign_up_tokens_crud.create_sign_up_token(reset_token, db)

    # Return the plain token (not the hash)
    return token


def register_local_user(
    request: jafaal_schema.SignUpRequest,
    signup_config: jafaal_ports.SignupConfig,
    identity_service: "IdentityService",
    db: Session,
) -> jafaal_ports.UserProtocol:
    """Create a local (password) account during sign-up.

    Validates and hashes the password with the regular-tier policy, asks the
    host's ``UserRepository`` to create the user row with the sign-up-derived
    active/verified state, then persists the credential in JAFAAL's own
    credential table.

    Args:
        request: The sign-up request (username, email, password).
        signup_config: The host's sign-up configuration.
        identity_service: Identity service (password hashing + credential write).
        db: Active SQLAlchemy session.

    Returns:
        The newly created user.
    """
    hashed_password = jafaal_password_policy.validate_and_hash_for_user(
        identity_service,
        is_superuser=False,
        password=request.password,
    )
    # A new sign-up is immediately active + verified only when neither email
    # verification nor admin approval is required.
    is_usable = not (signup_config.require_email_verification or signup_config.require_admin_approval)
    user = jafaal_ports.get_user_repository().create_local_user(
        request.username,
        request.email,
        db,
        is_active=is_usable,
        is_verified=is_usable,
    )
    identity_service.set_local_password_hash(user.id, hashed_password)
    return user


async def request_email_verification(user: jafaal_ports.UserProtocol, db: Session) -> None:
    """Mint an email-verification token and emit ``EmailVerificationRequested``.

    The host delivers the token (e.g. by email). Delivery is best-effort:
    failures are logged, never surfaced.

    Args:
        user: The newly created user awaiting email verification.
        db: Active SQLAlchemy session.
    """
    token = create_sign_up_token(user.id, db)
    event = jafaal_ports.EmailVerificationRequested(
        user_id=user.id,
        email=user.email,
        display_name=user.username,
        token=token,
        expires_at=datetime.now(UTC) + timedelta(hours=24),
        locale=None,
    )
    try:
        await jafaal_ports.get_event_sink().on_email_verification_requested(event)
    except Exception:
        logger.exception("Failed to deliver email-verification event for user %s", user.id)


async def notify_pending_admin_approval(user: jafaal_ports.UserProtocol) -> None:
    """Emit ``SignupPendingAdminApproval`` for a newly verified account.

    JAFAAL emits a single event with the new user's context; the host decides
    which admins to notify and how (email, websocket, ...). Delivery is
    best-effort.

    Args:
        user: The user whose sign-up is awaiting admin approval.
    """
    event = jafaal_ports.SignupPendingAdminApproval(
        user_id=user.id,
        username=user.username,
        display_name=user.username,
    )
    try:
        await jafaal_ports.get_event_sink().on_signup_pending_admin_approval(event)
    except Exception:
        logger.exception("Failed to deliver signup-pending-approval event for user %s", user.id)


async def notify_signup_approved(user_id: UserId, db: Session) -> None:
    """Emit ``SignupApproved`` for a user an admin has approved.

    A convenience for a host that runs its own approval endpoint and wants the
    approval notification delivered through JAFAAL's event sink. Delivery is
    best-effort.

    Args:
        user_id: ID of the approved user.
        db: Active SQLAlchemy session.

    Raises:
        JafaalError: 404 if the user does not exist.
    """
    user = jafaal_user_guards.get_user_by_id_or_404(user_id, db)
    event = jafaal_ports.SignupApproved(
        user_id=user.id,
        email=user.email,
        display_name=user.username,
        locale=None,
    )
    try:
        await jafaal_ports.get_event_sink().on_signup_approved(event)
    except Exception:
        logger.exception("Failed to deliver signup-approved event for user %s", user.id)


def use_sign_up_token(token: str, db: Session) -> UserId:
    """
    Validate and consume a sign-up token.

    The token is claimed atomically (a single conditional UPDATE), so two
    concurrent confirmations of the same token cannot both succeed.

    Args:
        token: Plaintext sign-up token to validate.
        db: Active SQLAlchemy session.

    Returns:
        The user ID associated with the token.

    Raises:
        JafaalError: 400 if the token is invalid, expired, or already used.
    """
    # Hash the provided token to find the database record
    token_hash = token_hashing.sha256_hex(token)

    # Atomically mark the token used and return its owner. A None result means
    # the token was missing, expired, or already consumed.
    user_id = sign_up_tokens_crud.claim_sign_up_token(token_hash, db)
    if user_id is None:
        raise jafaal_exceptions.InvalidRequestError("Invalid or expired sign up token")

    return user_id


def delete_invalid_tokens_from_db() -> None:
    """
    Remove expired sign-up tokens from the database.

    Opens a new session, deletes expired tokens, and logs the count if any were
        removed.

    Returns:
        None
    """
    # Create a new database session using context manager
    with session_scope() as db:
        # Get num tokens deleted
        num_deleted = sign_up_tokens_crud.delete_expired_sign_up_tokens(db)

        # Log the number of deleted tokens
        if num_deleted > 0:
            logger.info(f"Deleted {num_deleted} expired sign up tokens")
