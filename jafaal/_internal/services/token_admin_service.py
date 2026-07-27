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

import hmac
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
        # Named for the claim it reports: §2.2's ``token_type`` is already the
        # RFC 6749 §7.1 type (below), so this cannot also be called a "type".
        "token_use": jafaal_token_manager.token_use(claims),
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
    client_id: str,
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
) -> None:
    """Revoke ``token`` (RFC 7009). Silently no-ops on an unrecognised token.

    * Refresh token → delete its session (always effective), provided the token
      matches that session's current hash. When the denylist is enabled the
      session id is denylisted too, so the access tokens minted from the same
      grant stop working immediately rather than lapsing minutes later (§2.1).
    * Access token → add its ``jti`` to the revocation denylist **when**
      :attr:`~jafaal.settings.TokenSettings.denylist_enabled` is set; otherwise
      the short-lived token simply lapses.

    **Client binding.** §2.1 has the client identify itself, and §5 has the
    server check the token was issued to it. Without that, possession of a leaked
    token is a force-logout primitive against its owner — anyone who observes a
    refresh token can kill the session. A token belonging to a *different* client
    is treated exactly like an unknown one: a silent no-op, per §2.2. Answering
    differently would turn the endpoint into an oracle for "does this token
    belong to client X?", which is the question an attacker is asking.

    Args:
        token: The token to revoke.
        client_id: The registered client presenting the request.
        token_manager: Configured token manager.
        db: Database session.
    """
    try:
        decoded = token_manager.decode_token(token)
    except jafaal_exceptions.JafaalError:
        return  # RFC 7009: an invalid token is a successful (no-op) revocation.

    claims = decoded.claims

    token_client_id = claims.get("client_id")
    if not isinstance(token_client_id, str) or not hmac.compare_digest(token_client_id, client_id):
        logger.warning("Revocation refused: the token was issued to a different client")
        jafaal_audit.record(
            jafaal_audit.Event.TOKEN_REVOKE_REFUSED,
            outcome=jafaal_audit.Outcome.BLOCKED,
            level=logging.WARNING,
            client_id=client_id,
            reason="client_mismatch",
        )
        return

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
    # RFC 7009 §2.1: revoking a refresh token SHOULD invalidate the access tokens
    # issued from the same grant. Deleting the session does not — access-token
    # validation is stateless — so denylist the session id, which is the only
    # handle those (unenumerable) tokens share. Bounded by the access-token
    # lifetime: nothing carrying this sid can outlive it.
    if jafaal_settings.get_settings().tokens.denylist_enabled:
        ttl = jafaal_settings.get_settings().tokens.access_token_expire_minutes * 60 + _DENYLIST_TTL_BUFFER_SECONDS
        token_denylist.deny_session(session.id, ttl)
    jafaal_audit.record(
        jafaal_audit.Event.TOKEN_REVOKED,
        user_id=user_id,
        session_id=session.id,
        token_type="refresh",
    )


def _revoke_access_token(claims: dict[str, Any]) -> None:
    """Denylist an access token's ``jti`` when the denylist is enabled.

    With the denylist off there is nothing to revoke against — validation is
    stateless, so the token stays usable until it expires. RFC 7009 §2.2 reserves
    its 200 for "revocation successful *or* the client submitted an invalid
    token", and a valid-but-still-live token is neither; the caller is being told
    the credential is dead when it is not. The endpoint still answers 200 (the
    RFC gives it no other code, and the refresh-token path is unaffected), but
    the no-op is logged and audited so an operator can see that revocation is
    not actually doing anything.
    """
    jti = claims.get("jti")
    if not jafaal_settings.get_settings().tokens.denylist_enabled:
        logger.warning(
            "Access-token revocation requested but tokens.denylist_enabled is False: the token stays "
            "valid until it expires. Enable the denylist to make /revoke effective for access tokens."
        )
        jafaal_audit.record(
            jafaal_audit.Event.TOKEN_REVOKE_INEFFECTIVE,
            outcome=jafaal_audit.Outcome.FAILURE,
            level=logging.WARNING,
            token_type="access",
            jti=jti if isinstance(jti, str) else None,
            reason="denylist_disabled",
        )
        return
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
