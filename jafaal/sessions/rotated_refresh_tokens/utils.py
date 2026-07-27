"""Utility functions for refresh token reuse detection."""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

import jafaal.audit as jafaal_audit
import jafaal.orm as jafaal_orm
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.rotated_refresh_tokens.crud as rotated_token_crud
import jafaal.sessions.rotated_refresh_tokens.models as rotated_token_models
import jafaal.sessions.rotated_refresh_tokens.schema as rotated_token_schema
import jafaal.token_hashing as token_hashing
from jafaal._core import crypto, timeutils
from jafaal.orm import session_scope

logger = logging.getLogger(__name__)

# Grace period for token reuse (60 seconds)
# Allows for network retries/delays without false positives
TOKEN_REUSE_GRACE_PERIOD_SECONDS: int = 60

# Extra seconds a rotated record is retained beyond its grace window before the
# cleanup job removes it. Keeping the row a little longer than
# TOKEN_REUSE_GRACE_PERIOD_SECONDS guarantees that an in-grace retry landing near
# the boundary always finds its record (so it can be replayed) and that reuse
# just past the window is still detected as theft instead of silently becoming a
# plain "invalid token" because cleanup raced the boundary.
ROTATED_TOKEN_CLEANUP_BUFFER_SECONDS: int = 10


def hmac_hash_token(token: str) -> str:
    """
    Compute the keyed HMAC-SHA256 digest of a rotated token for secure lookup.

    Keyed with the rotated-refresh-token subkey derived from the server's
    ``secret_key``, providing defense-in-depth: even if the database is
    compromised, an attacker cannot verify stolen tokens without the key. The
    subkey is distinct from the one used for the session's own refresh-token
    digest, so a rotated-token digest can never be mistaken for a live one.

    Args:
        token: The raw refresh token to hash.

    Returns:
        Hex-encoded HMAC-SHA256 hash of the token.

    Raises:
        RuntimeError: If JAFAAL has not been configured.
    """
    return token_hashing.hmac_sha256(token, token_hashing.KeyPurpose.REFRESH_ROTATED)


def _find_rotated_token(
    raw_token: str,
    db: Session,
) -> rotated_token_models.RotatedRefreshToken | None:
    """Locate a rotated-token record, accepting digests from rotated-out keys.

    The digest is keyed by whichever ``secret_key`` was primary when the record
    was written, so a single equality lookup would stop finding rows the moment
    that key is rotated — silently blinding reuse/theft detection for the whole
    overlap window. Each candidate digest is tried, primary first.

    Args:
        raw_token: The raw refresh token being looked up.
        db: SQLAlchemy database session.

    Returns:
        The matching rotated-token record, or ``None``.
    """
    for digest in token_hashing.digest_candidates(raw_token, token_hashing.KeyPurpose.REFRESH_ROTATED):
        rotated_token = rotated_token_crud.get_rotated_token_by_hash(digest, db)
        if rotated_token is not None:
            return rotated_token
    return None


def store_rotated_token(
    raw_token: str,
    token_family_id: str,
    rotation_count: int,
    db: Session,
    *,
    replacement_refresh_token: str,
    replacement_refresh_token_exp: datetime,
) -> None:
    """
    Store an old refresh token after rotation for reuse detection.

    Uses HMAC-SHA256 with the server secret to hash the rotated
    token for deterministic lookups, and stores the replacement
    refresh token encrypted at rest so a legitimate retry inside
    the grace window can be replayed idempotently.

    Args:
        raw_token: The raw refresh token being rotated out.
        token_family_id: UUID of the token family.
        rotation_count: Current rotation count for this token.
        db: SQLAlchemy database session.
        replacement_refresh_token: The new refresh token minted
            to replace ``raw_token`` (replayed within grace).
        replacement_refresh_token_exp: Expiry of the replacement
            refresh token.

    Raises:
        JafaalError: If storage fails.
    """
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=TOKEN_REUSE_GRACE_PERIOD_SECONDS)

    # Use HMAC-SHA256 for deterministic, secure hashing
    hashed_token = hmac_hash_token(raw_token)

    rotated_token = rotated_token_schema.RotatedRefreshTokenCreate(
        token_family_id=token_family_id,
        hashed_token=hashed_token,
        rotation_count=rotation_count,
        rotated_at=now,
        expires_at=expires_at,
        replacement_refresh_token=crypto.encrypt_token_fernet(replacement_refresh_token),
        replacement_refresh_token_exp=replacement_refresh_token_exp,
    )

    rotated_token_crud.create_rotated_token(rotated_token, db)


def check_token_reuse(raw_token: str, db: Session) -> tuple[bool, bool]:
    """
    Check if a refresh token has been reused (already rotated).

    Uses HMAC-SHA256 with the server secret to hash the token
    for lookup, ensuring deterministic matching.

    Args:
        raw_token: The raw refresh token to check.
        db: SQLAlchemy database session.

    Returns:
        Tuple of (is_reused, in_grace_period):
            - (False, False): Token is valid, not reused.
            - (True, True): Reused but within 60s grace period.
            - (True, False): Reused after grace period - THEFT!

    Raises:
        JafaalError: If lookup fails.
    """
    # Use HMAC-SHA256 for deterministic lookup
    rotated_token = _find_rotated_token(raw_token, db)

    if not rotated_token:
        return (False, False)

    # Token was already rotated - check grace period
    now = datetime.now(UTC)
    expires_at = timeutils.ensure_aware_utc(rotated_token.expires_at)

    if now <= expires_at:
        # Within grace period - might be legitimate retry
        logger.warning(
            f"Token reuse within grace period for family {rotated_token.token_family_id}",
            extra={
                "token_family_id": rotated_token.token_family_id,
                "rotation_count": rotated_token.rotation_count,
            },
        )
        jafaal_audit.record(
            jafaal_audit.Event.TOKEN_REUSE_GRACE,
            outcome=jafaal_audit.Outcome.SUCCESS,
            token_family_id=rotated_token.token_family_id,
            rotation_count=rotated_token.rotation_count,
        )
        return (True, True)

    # Past grace period - likely theft!
    logger.error(
        f"Token reuse detected after grace period for family {rotated_token.token_family_id}",
        extra={
            "token_family_id": rotated_token.token_family_id,
            "rotation_count": rotated_token.rotation_count,
            "rotated_at": rotated_token.rotated_at.isoformat(),
        },
    )
    jafaal_audit.record(
        jafaal_audit.Event.TOKEN_THEFT_DETECTED,
        outcome=jafaal_audit.Outcome.BLOCKED,
        level=logging.ERROR,
        token_family_id=rotated_token.token_family_id,
        rotation_count=rotated_token.rotation_count,
    )
    return (True, False)


def claim_grace_replay_token(raw_token: str, db: Session) -> tuple[str, datetime] | None:
    """
    Consume the replacement refresh token for an in-grace retry.

    When a refresh token is presented again while still inside the
    grace window (a lost rotation response, or a racing retry), the
    replacement minted on the original rotation is replayed instead
    of issuing a brand-new token, so duplicate/concurrent refreshes
    converge on a single outcome.

    The replay is **single-use**. A lost response produces exactly one
    retry, so one replay is all a legitimate client ever needs; anything
    beyond that is reuse of a token the server has already superseded,
    which RFC 9700 §4.14.2 treats as evidence of compromise. Without the
    limit the grace window is a 60-second oracle that hands the *live*
    refresh token to anyone presenting a rotated one, repeatedly, and
    converts the reuse signal that theft detection depends on into a
    silent success.

    The claim is an atomic conditional ``UPDATE`` (see
    :func:`~jafaal.sessions.rotated_refresh_tokens.crud.claim_replacement_token`),
    so two concurrent replays cannot both succeed: one is served, the
    other is reported as reuse.

    Args:
        raw_token: The raw refresh token being replayed.
        db: SQLAlchemy database session.

    Returns:
        Tuple of (replacement_refresh_token, expiry) when this caller
        claimed a live in-grace replay, else ``None`` — meaning the
        window lapsed, no replacement was stored, or the single replay
        was already taken.

    Raises:
        JafaalError: If lookup or decryption fails.
    """
    rotated_token = _find_rotated_token(raw_token, db)

    if rotated_token is None:
        return None

    # Only replay inside the grace window; past it, reuse is theft.
    if datetime.now(UTC) > timeutils.ensure_aware_utc(rotated_token.expires_at):
        return None

    if not rotated_token.replacement_refresh_token or rotated_token.replacement_refresh_token_exp is None:
        return None

    replacement = crypto.decrypt_token_fernet(rotated_token.replacement_refresh_token)

    if replacement is None:
        return None

    # Consume the replay before handing the credential back. Losing this race
    # means another request already replayed it, so this caller is presenting a
    # token that has been superseded twice — reuse, not a retry.
    if not rotated_token_crud.claim_replacement_token(rotated_token.id, db):
        logger.warning(
            f"In-grace replay already consumed for family {rotated_token.token_family_id}; treating as reuse",
            extra={
                "token_family_id": rotated_token.token_family_id,
                "rotation_count": rotated_token.rotation_count,
            },
        )
        return None

    return (replacement, timeutils.ensure_aware_utc(rotated_token.replacement_refresh_token_exp))


def invalidate_token_family(token_family_id: str) -> int:
    """
    Invalidate all sessions in a token family due to reuse detection.

    Runs in its **own** transaction (:func:`jafaal.orm.autonomous_session`),
    because the caller always raises a 401 immediately afterwards: the request
    that detects the theft is, by definition, a failing request. Performing the
    revocation in that request's unit of work would roll it straight back — the
    stolen token would keep working, the legitimate user's sessions would never
    be killed, and the theft would be reported to the event sink without
    anything actually having been revoked.

    Args:
        token_family_id: The family ID to invalidate.

    Returns:
        Number of sessions invalidated.

    Raises:
        JafaalError: If invalidation fails.
    """
    with jafaal_orm.autonomous_session() as db:
        # Delete all sessions in the family
        num_sessions_deleted = jafaal_sessions_crud.delete_sessions_by_family(token_family_id, db)

        # Delete all rotated tokens for this family
        num_tokens_deleted = rotated_token_crud.delete_by_family(token_family_id, db)

    logger.error(
        f"Invalidated token family {token_family_id} due to reuse: "
        f"{num_sessions_deleted} sessions, {num_tokens_deleted} tokens",
        extra={
            "token_family_id": token_family_id,
            "sessions_deleted": num_sessions_deleted,
            "tokens_deleted": num_tokens_deleted,
        },
    )

    return num_sessions_deleted


def cleanup_expired_rotated_tokens() -> None:
    """
    Cleanup job to delete expired rotated tokens.

    Called by the scheduler to periodically remove tokens that
    have exceeded the grace period. Should run every 1 minute.
    Exceptions are caught and logged to avoid breaking the
    scheduler.

    Returns:
        None.
    """
    with session_scope() as db:
        try:
            # Retain rotated records a few seconds past their grace window so a
            # boundary retry can still be replayed and post-grace reuse is still
            # caught as theft (see ROTATED_TOKEN_CLEANUP_BUFFER_SECONDS).
            cutoff_time = datetime.now(UTC) - timedelta(seconds=ROTATED_TOKEN_CLEANUP_BUFFER_SECONDS)
            deleted_count = rotated_token_crud.delete_expired_tokens(cutoff_time, db)

            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} expired rotated tokens")
        except Exception as err:
            logger.error(f"Error in cleanup_expired_rotated_tokens: {err}", exc_info=err)
