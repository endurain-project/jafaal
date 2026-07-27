"""Token introspection (RFC 7662) and revocation (RFC 7009) for JAFAAL's tokens.

Route-facing helpers that back the ``/introspect`` and ``/revoke`` endpoints.
They operate on JAFAAL's own access/refresh JWTs:

* :func:`introspect_token` reports whether a token is currently valid (signature,
  expiry, issuer/audience, revocation denylist, and \u2014 for session-bound tokens
  \u2014 that the session still exists), with the standard RFC 7662 metadata.
* :func:`revoke_token` deletes the session behind a refresh token (always
  effective) and, when the opt-in denylist is enabled, records an access token's
  ``jti`` so it is rejected before it expires.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

import jafaal._internal.token_denylist as token_denylist
import jafaal._internal.token_manager as jafaal_token_manager
import jafaal.audit as jafaal_audit
import jafaal.exceptions as jafaal_exceptions
import jafaal.orm as jafaal_orm
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.utils as jafaal_sessions_utils
import jafaal.settings as jafaal_settings

logger = logging.getLogger(__name__)

# Small buffer added to a revoked access token's denylist TTL so the entry
# outlives the token even with a little clock skew between nodes.
_DENYLIST_TTL_BUFFER_SECONDS = 10


def _inactive() -> dict[str, Any]:
    """Return the RFC 7662 response for a token that is not active."""
    return {"active": False}


def introspect_token(
    token: str,
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
) -> dict[str, Any]:
    """Return the RFC 7662 introspection response for ``token``.

    A token is ``active`` only when its signature verifies, it is within its
    validity window, its issuer/audience match this server, its ``jti`` is not
    revoked, and \u2014 for a session-bound token \u2014 the session still exists (a
    refresh token must additionally still match the session's current hash, so a
    rotated one reads as inactive).

    Args:
        token: The token to introspect.
        token_manager: Configured token manager.
        db: Database session.

    Returns:
        The introspection response dict (``{"active": false}`` when not active).
    """
    try:
        decoded = token_manager.decode_token(token)
    except jafaal_exceptions.JafaalError:
        return _inactive()

    claims = decoded.claims
    now = datetime.now(UTC).timestamp()

    exp = claims.get("exp")
    if exp is None or now >= float(exp):
        return _inactive()
    nbf = claims.get("nbf")
    if nbf is not None and now < float(nbf) - token_manager.leeway_seconds:
        return _inactive()
    if claims.get("iss") != token_manager.issuer or claims.get("aud") != token_manager.audience:
        return _inactive()

    jti = claims.get("jti")
    if isinstance(jti, str) and token_denylist.is_access_token_denied(jti):
        return _inactive()

    sid = claims.get("sid")
    if sid is not None:
        session = jafaal_sessions_crud.get_session_by_id_not_expired(sid, db)
        if session is None:
            return _inactive()
        # A refresh token must still be the session's current one (not rotated).
        if jafaal_token_manager.token_use(claims) == jafaal_token_manager.TokenType.REFRESH.value and (
            not session.refresh_token or not jafaal_sessions_utils.verify_refresh_token(token, session.refresh_token)
        ):
            return _inactive()

    # RFC 7662 §2.2 defines ``scope`` as a space-delimited string regardless of
    # how the token itself carries it, so normalise both wire profiles here.
    scopes = jafaal_token_manager.scopes_from_claims(claims)
    return {
        "active": True,
        "sub": None if claims.get("sub") is None else str(claims.get("sub")),
        "scope": None if scopes is None else " ".join(scopes),
        "typ": jafaal_token_manager.token_use(claims),
        "token_type": "Bearer",
        "client_id": claims.get("client_id"),
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
        "nbf": claims.get("nbf"),
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "jti": jti,
        "sid": sid,
    }


def revoke_token(
    token: str,
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
) -> None:
    """Revoke ``token`` (RFC 7009). Silently no-ops on an unrecognised token.

    * Refresh token \u2192 delete its session (always effective), provided the token
      matches that session's current hash.
    * Access token \u2192 add its ``jti`` to the revocation denylist **when**
      :attr:`~jafaal.settings.AuthSettings.access_token_denylist_enabled` is set;
      otherwise the short-lived token simply lapses.

    Args:
        token: The token to revoke.
        token_manager: Configured token manager.
        db: Database session.
    """
    try:
        decoded = token_manager.decode_token(token)
    except jafaal_exceptions.JafaalError:
        return  # RFC 7009: an invalid token is a successful (no-op) revocation.

    claims = decoded.claims
    typ = jafaal_token_manager.token_use(claims)

    if typ == jafaal_token_manager.TokenType.REFRESH.value:
        _revoke_refresh_token(token, claims, db)
    elif typ == jafaal_token_manager.TokenType.ACCESS.value:
        _revoke_access_token(claims)


def _revoke_refresh_token(
    token: str,
    claims: dict[str, Any],
    db: Session,
) -> None:
    """Delete the session behind a refresh token, if the token matches it."""
    sid = claims.get("sid")
    sub = claims.get("sub")
    if sid is None or sub is None:
        return
    session = jafaal_sessions_crud.get_session_by_id_not_expired(sid, db)
    if session is None:
        return
    try:
        user_id = jafaal_orm.coerce_user_id(sub)
    except (ValueError, TypeError):
        return
    if session.user_id != user_id:
        return
    if not session.refresh_token or not jafaal_sessions_utils.verify_refresh_token(token, session.refresh_token):
        return  # The presented token does not belong to this session; do not revoke.

    jafaal_sessions_crud.delete_session(session.id, user_id, db)
    jafaal_audit.record(
        jafaal_audit.Event.TOKEN_REVOKED,
        user_id=user_id,
        session_id=session.id,
        token_type="refresh",
    )


def _revoke_access_token(claims: dict[str, Any]) -> None:
    """Denylist an access token's ``jti`` when the denylist is enabled."""
    if not jafaal_settings.get_settings().tokens.denylist_enabled:
        return
    jti = claims.get("jti")
    exp = claims.get("exp")
    if not isinstance(jti, str) or exp is None:
        return
    ttl = int(float(exp) - datetime.now(UTC).timestamp()) + _DENYLIST_TTL_BUFFER_SECONDS
    if ttl <= 0:
        return
    token_denylist.deny_access_token(jti, ttl)
    jafaal_audit.record(
        jafaal_audit.Event.TOKEN_REVOKED,
        token_type="access",
        jti=jti,
    )
