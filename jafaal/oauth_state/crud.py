"""CRUD operations for OAuth state (PKCE, nonce, replay prevention)."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, select
from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

import jafaal.oauth_state.models as oauth_state_models
import jafaal.sessions.models as jafaal_sessions_models
from jafaal._core import db_errors
from jafaal.orm import UserId

logger = logging.getLogger(__name__)


@db_errors.handle_db_errors
def get_oauth_state_by_id_and_not_used(state_id: str, db: Session) -> oauth_state_models.OAuthState | None:
    """Retrieve an OAuth state by ID, validating it is not expired or used.

    Args:
        state_id: The state parameter to lookup.
        db: SQLAlchemy database session.

    Returns:
        The matching OAuthState if valid (not expired and unused),
        None otherwise.

    Raises:
        JafaalError: 500 error if database query fails.
    """
    stmt = select(oauth_state_models.OAuthState).where(
        oauth_state_models.OAuthState.id == state_id,
        oauth_state_models.OAuthState.used.is_(False),
        oauth_state_models.OAuthState.expires_at > datetime.now(UTC),
    )
    oauth_state = db.execute(stmt).scalar_one_or_none()

    if not oauth_state:
        logger.warning(f"OAuth state invalid or expired: {state_id[:8]}...")

    return oauth_state


@db_errors.handle_db_errors
def get_oauth_state_by_id(state_id: str, db: Session) -> oauth_state_models.OAuthState | None:
    """Retrieve an OAuth state by ID without validity checks.

    Args:
        state_id: The state parameter to lookup.
        db: SQLAlchemy database session.

    Returns:
        The matching OAuthState if found, None otherwise.

    Raises:
        JafaalError: 500 error if database query fails.
    """
    stmt = select(oauth_state_models.OAuthState).where(oauth_state_models.OAuthState.id == state_id)
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def get_oauth_state_by_id_not_expired(state_id: str, db: Session) -> oauth_state_models.OAuthState | None:
    """Retrieve an OAuth state by ID if it is still unexpired.

    Args:
        state_id: The state parameter to lookup.
        db: SQLAlchemy database session.

    Returns:
        The matching OAuthState if found and unexpired,
        None otherwise.

    Raises:
        JafaalError: 500 error if database query fails.
    """
    stmt = select(oauth_state_models.OAuthState).where(
        oauth_state_models.OAuthState.id == state_id,
        oauth_state_models.OAuthState.expires_at > datetime.now(UTC),
    )
    oauth_state = db.execute(stmt).scalar_one_or_none()

    if not oauth_state:
        logger.warning(f"OAuth state invalid or expired: {state_id[:8]}...")

    return oauth_state


@db_errors.handle_db_errors
def get_oauth_state_by_session_id(session_id: str, db: Session) -> oauth_state_models.OAuthState | None:
    """Retrieve an OAuth state via the session relationship.

    Used during token exchange to retrieve stored PKCE challenge
    and other OAuth metadata linked to a user session.

    Args:
        session_id: The session ID to lookup.
        db: SQLAlchemy database session.

    Returns:
        The linked OAuthState if found, None otherwise.

    Raises:
        JafaalError: 500 error if database query fails.
    """
    stmt = select(jafaal_sessions_models.UsersSessions).where(jafaal_sessions_models.UsersSessions.id == session_id)
    session = db.execute(stmt).scalar_one_or_none()

    if not session or not session.oauth_state_id:
        return None

    return get_oauth_state_by_id(session.oauth_state_id, db)


@db_errors.handle_db_errors
def create_oauth_state(
    db: Session,
    state_id: str,
    nonce: str,
    ip_address: str | None,
    idp_id: int | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    user_id: UserId | None = None,
    purpose: str = "login",
    client_id: str | None = None,
    redirect_uri: str | None = None,
    client_state: str | None = None,
    requested_scope: str | None = None,
) -> oauth_state_models.OAuthState:
    """Create and persist a new OAuth state with a 10-minute expiry.

    Args:
        db: SQLAlchemy database session.
        state_id: The state parameter (secrets.token_urlsafe(32)).
        nonce: OIDC nonce for ID token validation.
        ip_address: Client IP address at initiation. Recorded as a *detection*
            signal only — the callback compares it and audits a mismatch rather
            than rejecting, because the browser leg of an SSO round trip
            legitimately changes address (mobile hand-off, IPv6 privacy
            rotation, proxy egress). Replay is prevented by the single-use
            claim, the nonce, and the PKCE binding.
        idp_id: Identity provider ID.
        code_challenge: PKCE challenge (mandatory for a login flow).
        code_challenge_method: PKCE method (S256).
        user_id: User ID for link and step-up modes.
        purpose: Flow purpose (``login``, ``link``, or ``stepup``).
        client_id: The registered public client that started the flow.
        redirect_uri: The client's redirect URI, already matched exactly against
            its registration. Every browser redirect this flow later emits goes
            here and nowhere else.
        client_state: The client's opaque ``state``, echoed back with the code.
        requested_scope: The space-delimited ``scope`` from the authorization
            request, already validated against the catalog and the client's
            ceiling. Replayed as a narrowing bound when the code is redeemed, so
            a client that asked for less is not handed more.

    Returns:
        The persisted OAuthState instance.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    expires_at = datetime.now(UTC) + timedelta(minutes=10)

    oauth_state = oauth_state_models.OAuthState(
        id=state_id,
        idp_id=idp_id,
        nonce=nonce,
        ip_address=ip_address,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        user_id=user_id,
        purpose=purpose,
        expires_at=expires_at,
        used=False,
        client_id=client_id,
        redirect_uri=redirect_uri,
        client_state=client_state,
        requested_scope=requested_scope,
    )

    db.add(oauth_state)
    db.flush()
    db.refresh(oauth_state)

    logger.debug(f"OAuth state created: {state_id[:8]}... for IdP {idp_id}, client={client_id}")

    return oauth_state


@db_errors.handle_db_errors
def attach_authorization_code(state_id: str, code_hash: str, db: Session) -> bool:
    """Bind a freshly minted authorization code's digest to an OAuth state.

    Written as a conditional UPDATE that only matches a state with no code yet,
    so a state can never be made to issue two live codes — the same
    claim-don't-check discipline the rest of the flow uses.

    Args:
        state_id: The OAuth state the code belongs to.
        code_hash: Keyed digest of the issued code (never the plaintext).
        db: SQLAlchemy database session.

    Returns:
        ``True`` when the code was attached, ``False`` when the state was
        missing, expired, or already carries a code.

    Raises:
        JafaalError: 500 error if the database update fails.
    """
    stmt = (
        sa_update(oauth_state_models.OAuthState)
        .where(
            oauth_state_models.OAuthState.id == state_id,
            oauth_state_models.OAuthState.authorization_code_hash.is_(None),
            oauth_state_models.OAuthState.expires_at > datetime.now(UTC),
        )
        .values(authorization_code_hash=code_hash)
        .execution_options(synchronize_session=False)
    )
    result = cast(CursorResult[Any], db.execute(stmt))
    return result.rowcount == 1


@db_errors.handle_db_errors
def get_oauth_state_by_authorization_code_hashes(
    code_hashes: tuple[str, ...],
    db: Session,
) -> oauth_state_models.OAuthState | None:
    """Look up the unexpired OAuth state carrying any of ``code_hashes``.

    Takes every digest the code *could* have been stored under — the primary
    subkey plus one per ``secret_key_fallbacks`` entry — so a rotation mid-flight
    does not strand an authorization code that was minted seconds earlier.

    Args:
        code_hashes: Candidate digests, primary first.
        db: SQLAlchemy database session.

    Returns:
        The matching OAuthState, or ``None`` when unknown or expired.

    Raises:
        JafaalError: 500 error if the database query fails.
    """
    stmt = select(oauth_state_models.OAuthState).where(
        oauth_state_models.OAuthState.authorization_code_hash.in_(code_hashes),
        oauth_state_models.OAuthState.expires_at > datetime.now(UTC),
    )
    return db.execute(stmt).scalar_one_or_none()


@db_errors.handle_db_errors
def set_upstream_code_verifier(state_id: str, encrypted_verifier: str | None, db: Session) -> None:
    """Persist the encrypted upstream PKCE code_verifier on an OAuth state.

    Called while building the authorization URL (initiate_login / initiate_link)
    so the verifier can be replayed on the later token exchange. The value is
    already Fernet-encrypted by the caller and is never returned to a client.

    Args:
        state_id: The OAuth state ID to update.
        encrypted_verifier: The Fernet-encrypted PKCE code_verifier (the
            ``str | None`` result of ``encrypt_token_fernet``).
        db: SQLAlchemy database session.

    Raises:
        JafaalError: 500 error if the database update fails.
    """
    stmt = (
        sa_update(oauth_state_models.OAuthState)
        .where(oauth_state_models.OAuthState.id == state_id)
        .values(upstream_code_verifier=encrypted_verifier)
        .execution_options(synchronize_session=False)
    )
    db.execute(stmt)
    db.flush()


@db_errors.handle_db_errors
def mark_oauth_state_used(state_id: str, db: Session) -> bool:
    """Atomically mark an unused, unexpired OAuth state as used.

    Performs a single conditional UPDATE so concurrent attempts to
    consume the same state cannot both succeed (replay protection).

    Args:
        state_id: The state parameter to mark as used.
        db: SQLAlchemy database session.

    Returns:
        True if exactly one row was claimed, False if the state was
        missing, expired, or already consumed.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    stmt = (
        sa_update(oauth_state_models.OAuthState)
        .where(
            oauth_state_models.OAuthState.id == state_id,
            oauth_state_models.OAuthState.used.is_(False),
            oauth_state_models.OAuthState.expires_at > datetime.now(UTC),
        )
        .values(used=True)
        # Skip in-session synchronization: callers pre-load the state row (via
        # get_oauth_state_by_id_and_not_used) and only need the DB row marked
        # used + the rowcount. Evaluating the WHERE criteria in Python (the
        # default "evaluate" strategy) would compare the loaded ``expires_at``
        # against ``datetime.now(UTC)``, which raises on backends returning
        # naive datetimes (e.g. SQLite). The DB does the comparison.
        .execution_options(synchronize_session=False)
    )
    result = cast(CursorResult[Any], db.execute(stmt))
    db.flush()

    claimed = result.rowcount == 1
    if claimed:
        logger.debug(f"OAuth state marked as used: {state_id[:8]}...")
    else:
        logger.warning(f"Cannot mark OAuth state used (missing/expired/replay): {state_id[:8]}...")
    return claimed


@db_errors.handle_db_errors
def delete_oauth_state(oauth_state_id: str, db: Session) -> int:
    """Delete a single OAuth state by ID.

    Args:
        oauth_state_id: The OAuth state ID to delete.
        db: SQLAlchemy database session.

    Returns:
        Number of OAuth states deleted (0 or 1).

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    stmt = sa_delete(oauth_state_models.OAuthState).where(oauth_state_models.OAuthState.id == oauth_state_id)
    result = cast(CursorResult[Any], db.execute(stmt))
    db.flush()
    return result.rowcount


@db_errors.handle_db_errors
def delete_expired_oauth_states(db: Session) -> int:
    """Delete OAuth states past their expiry timestamp.

    Should be called every 5 minutes via background task.

    Args:
        db: SQLAlchemy database session.

    Returns:
        Number of OAuth states deleted.

    Raises:
        JafaalError: 500 error if database operation fails.
    """
    stmt = sa_delete(oauth_state_models.OAuthState).where(oauth_state_models.OAuthState.expires_at < datetime.now(UTC))
    result = cast(CursorResult[Any], db.execute(stmt))
    db.flush()

    deleted_count = result.rowcount
    if deleted_count > 0:
        logger.debug(f"Deleted {deleted_count} expired OAuth state(s)")
    return deleted_count
