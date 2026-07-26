"""Session utility functions and classes."""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum

from fastapi import Request
from sqlalchemy.orm import Session
from user_agents import parse

import jafaal.exceptions as jafaal_exceptions
import jafaal.ports as jafaal_ports
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.models as jafaal_sessions_models
import jafaal.sessions.schema as jafaal_sessions_schema
import jafaal.settings as jafaal_settings
import jafaal.token_hashing as token_hashing
from jafaal._core import network, timeutils
from jafaal.orm import UserId, session_scope

logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """
    Device type enumeration.

    Attributes:
        MOBILE: Mobile device.
        TABLET: Tablet device.
        PC: Desktop/laptop device.
    """

    MOBILE = "Mobile"
    TABLET = "Tablet"
    PC = "PC"


@dataclass
class DeviceInfo:
    """
    Device information container.

    Attributes:
        device_type: Device type (mobile, tablet, PC).
        operating_system: OS name.
        operating_system_version: OS version string.
        browser: Browser name.
        browser_version: Browser version string.
    """

    device_type: DeviceType
    operating_system: str
    operating_system_version: str
    browser: str
    browser_version: str


def _hash_csrf_token(token: str) -> str:
    """Compute the keyed HMAC-SHA256 digest of a CSRF token.

    Keyed with the CSRF subkey derived from ``AuthSettings.secret_key``, so the
    MAC is unforgeable without the server secret and cannot be confused with a
    digest computed for any other purpose, while being microseconds-fast (unlike
    Argon2, which is designed for password storage).

    Args:
        token: The plain CSRF token string.

    Returns:
        Hex-encoded HMAC-SHA256 digest.

    Raises:
        RuntimeError: If JAFAAL has not been configured.
    """
    return token_hashing.hmac_sha256(token, token_hashing.KeyPurpose.CSRF)


def verify_csrf_token(candidate: str, stored_hmac: str) -> bool:
    """Verify a CSRF token candidate against its stored HMAC in constant time.

    Delegates to :func:`jafaal.token_hashing.verify_hmac`, which compares in
    constant time against the primary subkey and any ``secret_key_fallbacks``
    subkeys — so a binding minted before a signing-key rotation keeps verifying
    during the overlap window.

    Args:
        candidate: The CSRF token value from the request header.
        stored_hmac: The HMAC-SHA256 digest stored in the session.

    Returns:
        True if the candidate matches the stored HMAC, False otherwise.
    """
    return token_hashing.verify_hmac(candidate, token_hashing.KeyPurpose.CSRF, stored_hmac)


# --------------------------------------------------------------------------- #
# Refresh-token digests
#
# A refresh token is a signed JWT carrying a 128-bit random ``jti`` — it is
# high-entropy server-minted material, not a user-chosen secret, so the stored
# digest is a keyed HMAC-SHA256 (the strategy :mod:`jafaal.token_hashing`
# prescribes for exactly this case) rather than a password KDF. The keyed MAC
# still means database read access alone does not let an attacker verify a
# stolen token, while costing microseconds instead of the ~50 ms an Argon2
# verify costs — which /refresh would otherwise pay twice (verify the old token,
# hash the new one) on every single call, and /logout once.
# --------------------------------------------------------------------------- #


def hash_refresh_token(refresh_token: str) -> str:
    """Return the stored digest for a refresh token.

    Args:
        refresh_token: The raw refresh-token JWT.

    Returns:
        Hex-encoded HMAC-SHA256 digest under the session refresh-token subkey.
    """
    return token_hashing.hmac_sha256(refresh_token, token_hashing.KeyPurpose.REFRESH_SESSION)


def verify_refresh_token(candidate: str, stored_hash: str) -> bool:
    """Verify a presented refresh token against a session's stored digest.

    Accepts a digest written under a rotated-out ``secret_key`` (see
    :func:`jafaal.token_hashing.verify_hmac`), so rolling the signing key does
    not invalidate every live session. The next ``/refresh`` rewrites the row
    with a primary-key digest, so sessions re-key themselves as they rotate.

    Args:
        candidate: The raw refresh token presented by the caller.
        stored_hash: The digest persisted on the session row.

    Returns:
        True if the candidate matches the stored digest, False otherwise.
    """
    return token_hashing.verify_hmac(candidate, token_hashing.KeyPurpose.REFRESH_SESSION, stored_hash)


def validate_session_timeout(
    session: jafaal_sessions_models.UsersSessions,
) -> None:
    """
    Validate session hasn't exceeded idle or absolute timeout.

    Only enforces when SESSION_IDLE_TIMEOUT_ENABLED=true.
    Checks idle timeout (last_activity_at) and absolute
    timeout (created_at).

    Args:
        session: The session to validate.

    Raises:
        SessionExpiredError: 401 if the session has timed out.
    """
    # Skip validation if timeouts are disabled
    settings = jafaal_settings.get_settings()
    if not settings.session_idle_timeout_enabled:
        return

    now = datetime.now(UTC)

    # Check idle timeout
    idle_limit = timeutils.ensure_aware_utc(session.last_activity_at) + timedelta(
        hours=settings.session_idle_timeout_hours
    )
    if now > idle_limit:
        raise jafaal_exceptions.SessionExpiredError("Session expired due to inactivity")

    # Check absolute timeout
    absolute_limit = timeutils.ensure_aware_utc(session.created_at) + timedelta(
        hours=settings.session_absolute_timeout_hours
    )
    if now > absolute_limit:
        raise jafaal_exceptions.SessionExpiredError("Session expired. Please login again for security.")


def create_session_object(
    session_id: str,
    user: jafaal_ports.UserProtocol,
    request: Request,
    hashed_refresh_token: str | None,
    refresh_token_exp: datetime,
    oauth_state_id: str | None = None,
    csrf_token_hash: str | None = None,
) -> jafaal_sessions_schema.UsersSessionsInternal:
    """
    Create session object with device and request metadata.

    Args:
        session_id: Unique identifier for the session.
        user: The user associated with the session.
        request: HTTP request containing client information.
        hashed_refresh_token: Hashed refresh token.
        refresh_token_exp: Refresh token expiration datetime.
        oauth_state_id: Optional OAuth state ID for PKCE.
        csrf_token_hash: Hashed CSRF token for validation.

    Returns:
        Session object with user, device, and request details.
    """
    user_agent = get_user_agent(request)
    device_info = parse_user_agent(user_agent)

    now = datetime.now(UTC)

    return jafaal_sessions_schema.UsersSessionsInternal(
        id=session_id,
        user_id=user.id,
        refresh_token=hashed_refresh_token,
        ip_address=network.get_ip_address(request),
        device_type=device_info.device_type.value,
        operating_system=device_info.operating_system,
        operating_system_version=device_info.operating_system_version,
        browser=device_info.browser,
        browser_version=device_info.browser_version,
        created_at=now,
        last_activity_at=now,
        expires_at=refresh_token_exp,
        oauth_state_id=oauth_state_id,
        tokens_exchanged=False,
        token_family_id=session_id,
        rotation_count=0,
        last_rotation_at=None,
        csrf_token_hash=csrf_token_hash,
    )


def edit_session_object(
    request: Request,
    hashed_refresh_token: str,
    refresh_token_exp: datetime,
    session: jafaal_sessions_models.UsersSessions,
    csrf_token_hash: str | None = None,
) -> jafaal_sessions_schema.UsersSessionsInternal:
    """
    Create updated session object with new token and metadata.

    Args:
        request: The incoming HTTP request object.
        hashed_refresh_token: Hashed refresh token.
        refresh_token_exp: Refresh token expiration datetime.
        session: The existing session object to update.
        csrf_token_hash: Hashed CSRF token for validation.

    Returns:
        Updated session object with device and token details.
    """
    user_agent = get_user_agent(request)
    device_info = parse_user_agent(user_agent)

    now = datetime.now(UTC)
    new_rotation_count = session.rotation_count + 1

    return jafaal_sessions_schema.UsersSessionsInternal(
        id=session.id,
        user_id=session.user_id,
        refresh_token=hashed_refresh_token,
        ip_address=network.get_ip_address(request),
        device_type=device_info.device_type.value,
        operating_system=device_info.operating_system,
        operating_system_version=device_info.operating_system_version,
        browser=device_info.browser,
        browser_version=device_info.browser_version,
        created_at=session.created_at,
        last_activity_at=now,
        expires_at=refresh_token_exp,
        oauth_state_id=session.oauth_state_id,
        tokens_exchanged=session.tokens_exchanged,
        token_family_id=session.token_family_id,
        rotation_count=new_rotation_count,
        last_rotation_at=now,
        csrf_token_hash=csrf_token_hash,
    )


def create_session(
    session_id: str,
    user: jafaal_ports.UserProtocol,
    request: Request,
    refresh_token: str | None,
    db: Session,
    oauth_state_id: str | None = None,
    csrf_token: str | None = None,
) -> None:
    """
    Create new user session and store in database.

    Args:
        session_id: Unique identifier for the session.
        user: User for whom session is being created.
        request: The incoming HTTP request object.
        refresh_token: Refresh token to associate or None.
        db: Database session for storing.
        oauth_state_id: Optional OAuth state ID for PKCE.
        csrf_token: Plain CSRF token to hash and store.

    Raises:
        JafaalError: If database error occurs.
    """
    # Calculate the refresh token expiration date
    exp = datetime.now(UTC) + timedelta(days=jafaal_settings.get_settings().refresh_token_expire_days)

    # Compute HMAC-SHA256 of the CSRF token if provided
    csrf_hash = _hash_csrf_token(csrf_token) if csrf_token else None

    # Create a new session
    new_session = create_session_object(
        session_id,
        user,
        request,
        hash_refresh_token(refresh_token) if refresh_token else None,
        exp,
        oauth_state_id,
        csrf_hash,
    )

    # Add the session to the database
    jafaal_sessions_crud.create_session(new_session, db)


def edit_session(
    session: jafaal_sessions_models.UsersSessions,
    request: Request,
    new_refresh_token: str,
    db: Session,
    new_csrf_token: str | None = None,
) -> None:
    """
    Update existing user session with new refresh token.

    Args:
        session: Current user session object to edit.
        request: Incoming request containing session context.
        new_refresh_token: New refresh token to set.
        db: Database session for committing changes.
        new_csrf_token: Plain CSRF token to hash and store.

    Raises:
        JafaalError: If database error occurs.
    """
    # Calculate the refresh token expiration date
    exp = datetime.now(UTC) + timedelta(days=jafaal_settings.get_settings().refresh_token_expire_days)

    # Compute HMAC-SHA256 of the new CSRF token if provided
    csrf_hash = _hash_csrf_token(new_csrf_token) if new_csrf_token else None

    # Update the session.
    updated_session = edit_session_object(
        request,
        hash_refresh_token(new_refresh_token),
        exp,
        session,
        csrf_hash,
    )

    # Update the session in the database
    jafaal_sessions_crud.edit_session(updated_session, db)


def update_session_csrf_token(
    session_id: str,
    new_csrf_token: str,
    db: Session,
) -> None:
    """
    Bind a freshly minted CSRF token to an existing session.

    Hashes the CSRF token and updates only the session's CSRF hash,
    leaving the refresh token and rotation count untouched. Used by
    the in-grace refresh replay path for web clients.

    Args:
        session_id: The session to update.
        new_csrf_token: Plain CSRF token to hash and store.
        db: SQLAlchemy database session.

    Raises:
        JafaalError: If database error occurs.
    """
    jafaal_sessions_crud.update_session_csrf_hash(session_id, _hash_csrf_token(new_csrf_token), db)


def get_user_agent(request: Request) -> str:
    """
    Extract User-Agent string from request headers.

    Args:
        request: The incoming HTTP request object.

    Returns:
        User-Agent header value or empty string.
    """
    return request.headers.get("user-agent", "")


def parse_user_agent(user_agent: str) -> DeviceInfo:
    """
    Parse user agent string and extract device information.

    Args:
        user_agent: The user agent string to parse.

    Returns:
        Device information including type, OS, and browser
        details. Unknown fields default to "Unknown".
    """
    ua = parse(user_agent)
    device_type = DeviceType.MOBILE if ua.is_mobile else DeviceType.TABLET if ua.is_tablet else DeviceType.PC

    return DeviceInfo(
        device_type=device_type,
        operating_system=ua.os.family or "Unknown",
        operating_system_version=ua.os.version_string or "Unknown",
        browser=ua.browser.family or "Unknown",
        browser_version=ua.browser.version_string or "Unknown",
    )


def device_fingerprint(request: Request) -> tuple[str, str]:
    """Return a coarse device ``(fingerprint, human description)`` for a request.

    The fingerprint is a ``device_type|os|browser`` key used to decide whether a
    login comes from a device already seen on a prior session; the description is
    a human-readable summary suitable for a "new sign-in" notification.

    Args:
        request: The incoming HTTP request.

    Returns:
        Tuple of ``(fingerprint, description)``.
    """
    info = parse_user_agent(get_user_agent(request))
    fingerprint = f"{info.device_type.value}|{info.operating_system}|{info.browser}"
    description = f"{info.browser} on {info.operating_system} ({info.device_type.value})"
    return fingerprint, description


def is_known_device(user_id: UserId, request: Request, db: Session) -> bool:
    """Return ``True`` if the user has a prior session from the same device.

    Compares the request's coarse device fingerprint against the user's existing
    sessions. Used to decide whether to emit an ``on_new_device_login`` event.

    Args:
        user_id: The authenticating user's ID.
        request: The incoming HTTP request.
        db: SQLAlchemy database session.

    Returns:
        True when a prior session shares the request's device fingerprint.
    """
    fingerprint, _ = device_fingerprint(request)
    for session in jafaal_sessions_crud.get_user_sessions(user_id, db):
        existing = f"{session.device_type}|{session.operating_system}|{session.browser}"
        if existing == fingerprint:
            return True
    return False


def cleanup_idle_sessions() -> None:
    """
    Clean up idle sessions exceeding timeout threshold.

    Removes sessions inactive longer than the configured idle
    timeout period. Only runs if SESSION_IDLE_TIMEOUT_ENABLED.
    Logs count of cleaned sessions.

    Raises:
        JafaalError: If database error occurs.
    """
    settings = jafaal_settings.get_settings()
    if not settings.session_idle_timeout_enabled:
        return

    with session_scope() as db:
        try:
            cutoff_time = datetime.now(UTC) - timedelta(hours=settings.session_idle_timeout_hours)

            # Delete sessions with last_activity_at older than cutoff
            deleted_count = jafaal_sessions_crud.delete_idle_sessions(cutoff_time, db)

            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} idle sessions")
        except Exception as err:
            logger.error(f"Error in cleanup_idle_sessions: {err}", exc_info=err)
