"""Access-token revocation denylist (RFC 7009 for stateless JWTs).

JAFAAL access tokens are stateless JWTs, so revoking one before it expires
requires recording its ``jti`` and rejecting it during validation. The denylist
is kept in the shared :class:`~jafaal.state_store.StateStore` (so it works across
workers/replicas when a distributed backend is configured) with a TTL equal to
the token's remaining lifetime, after which the entry self-expires.

This is opt-in via :attr:`~jafaal.settings.AuthSettings.access_token_denylist_enabled`;
revoking a *refresh* token (which deletes its session) is always effective and
does not depend on this denylist.
"""

import logging

import jafaal.settings as jafaal_settings
from jafaal.state_store import StateStoreUnavailableError, get_state_store

logger = logging.getLogger(__name__)


def _key(jti: str) -> str:
    """Build the state-store key marking a revoked access-token ``jti``."""
    return f"{jafaal_settings.get_settings().store_key_prefix}:revoked_jti:{jti}"


def deny_access_token(jti: str, ttl_seconds: int) -> None:
    """Record an access-token ``jti`` as revoked for ``ttl_seconds``.

    Best-effort: a state-store outage is logged, not raised — the token is
    short-lived and revoking the associated refresh token remains effective.

    Args:
        jti: The access token's unique identifier.
        ttl_seconds: How long to keep the denylist entry (the token's remaining
            lifetime). Non-positive values are ignored (already expired).
    """
    if ttl_seconds <= 0:
        return
    try:
        get_state_store().set(_key(jti), b"1", ttl_seconds=ttl_seconds)
    except StateStoreUnavailableError as err:
        logger.warning("Could not record revoked access-token jti; revocation not persisted", exc_info=err)


def is_access_token_denied(jti: str) -> bool:
    """Return whether an access-token ``jti`` has been revoked.

    Fails **open** (returns ``False``) on a state-store outage: an infrastructure
    fault must not reject every token, and access tokens are short-lived with
    session revocation available as the primary mechanism.
    """
    try:
        return get_state_store().get(_key(jti)) is not None
    except StateStoreUnavailableError as err:
        logger.warning("Access-token revocation check skipped; state store unavailable", exc_info=err)
        return False
