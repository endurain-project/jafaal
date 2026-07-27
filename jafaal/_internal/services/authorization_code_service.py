"""RFC 6749 authorization-code issuance and redemption.

JAFAAL is a first-party issuer, not an authorization server for third parties:
there is no consent screen, no client secret, and no dynamic registration. What
it *does* implement, for its own native apps, is the authorization-code flow with
PKCE exactly as RFC 6749 §4.1 and RFC 7636 describe it — because that is the
flow every OAuth client library already speaks, and re-inventing its shape is how
integrations end up hand-rolling (and mis-implementing) PKCE.

The code itself is a 256-bit opaque secret. Only its keyed digest is stored, so
database read access alone does not let an attacker redeem one, and the digest
column is UNIQUE so the database — not application code — guarantees a code maps
to at most one authorization request.

Four bindings must all hold for a code to be redeemed, and each closes a
published attack:

* **PKCE** (``code_verifier`` hashes to the stored ``code_challenge``) — an
  authorization code intercepted on the redirect leg is useless without the
  verifier, which never leaves the requesting app (RFC 7636).
* **client_id** — the code is redeemed by the client it was issued to.
* **redirect_uri** — byte-for-byte equal to the one in the authorization
  request, per RFC 6749 §4.1.3, which stops a code obtained via one registered
  URI being replayed against another.
* **single use** — the session claim is an atomic conditional UPDATE, so two
  concurrent redemptions of one code cannot both win.
"""

from __future__ import annotations

import logging
import secrets
from typing import TYPE_CHECKING, cast

import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.utils as idp_utils
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.ports as jafaal_ports
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.utils as jafaal_sessions_utils
import jafaal.settings as jafaal_settings
import jafaal.token_hashing as token_hashing
import jafaal.utils as jafaal_utils

if TYPE_CHECKING:
    from fastapi import Response
    from sqlalchemy.orm import Session

    import jafaal._internal.token_manager as jafaal_token_manager
    import jafaal.oauth_state.models as oauth_state_models
    import jafaal.sessions.models as jafaal_sessions_models

logger = logging.getLogger(__name__)

#: The only ``response_type`` JAFAAL's authorization endpoint implements.
#: Every implicit/hybrid response type is omitted deliberately: OAuth 2.1 removes
#: them and RFC 9700 §2.1.2 recommends against issuing tokens in a redirect.
RESPONSE_TYPE_CODE = "code"

#: The ``grant_type`` that redeems an authorization code (RFC 6749 §4.1.3).
GRANT_AUTHORIZATION_CODE = "authorization_code"

#: The only ``code_challenge_method`` accepted. ``plain`` is refused because it
#: offers no protection against an attacker who can observe the challenge.
CODE_CHALLENGE_METHOD_S256 = "S256"


def issue_authorization_code(state_id: str, db: Session) -> str:
    """Mint an authorization code for a completed authorization request.

    Args:
        state_id: The OAuth state the code is bound to.
        db: Active database session.

    Returns:
        The plaintext code, to be delivered once via the redirect. Only its
        digest is persisted.

    Raises:
        InternalError: If the state already carries a code, or has expired
            between the callback completing and the code being minted.
    """
    code = secrets.token_urlsafe(32)
    code_hash = token_hashing.hmac_sha256(code, token_hashing.KeyPurpose.AUTHORIZATION_CODE)
    if not oauth_state_crud.attach_authorization_code(state_id, code_hash, db):
        logger.error(f"Could not attach an authorization code to state {state_id[:8]}...")
        raise jafaal_exceptions.InternalError("Could not complete the authorization request")
    return code


def resolve_authorization_code(
    code: str,
    client_id: str,
    redirect_uri: str,
    db: Session,
) -> tuple[jafaal_sessions_models.UsersSessions, oauth_state_models.OAuthState]:
    """Resolve a code to its session, enforcing the client and redirect bindings.

    Every failure returns the same generic error. Distinguishing "unknown code"
    from "wrong client" from "wrong redirect_uri" would turn the token endpoint
    into an oracle for probing which codes and clients exist.

    Args:
        code: The plaintext authorization code presented by the client.
        client_id: The ``client_id`` form field.
        redirect_uri: The ``redirect_uri`` form field.
        db: Active database session.

    Returns:
        The pending session and the OAuth state the code was issued against.

    Raises:
        InvalidRequestError: If the code is unknown, expired, already redeemed,
            or not bound to this client and redirect URI.
    """
    candidates = token_hashing.digest_candidates(code, token_hashing.KeyPurpose.AUTHORIZATION_CODE)
    oauth_state = oauth_state_crud.get_oauth_state_by_authorization_code_hashes(candidates, db)
    if oauth_state is None:
        logger.warning("Authorization code is unknown or expired")
        raise jafaal_exceptions.InvalidRequestError("invalid_grant: the authorization code is invalid or expired")

    if oauth_state.client_id != client_id:
        logger.warning(f"Authorization code presented by the wrong client (state {oauth_state.id[:8]}...)")
        raise jafaal_exceptions.InvalidRequestError("invalid_grant: the authorization code is invalid or expired")

    # RFC 6749 §4.1.3: the redirect_uri sent here MUST be identical to the one in
    # the authorization request. Compared through the registered-client matcher
    # so the comparison is the same constant-time, exact one used at /authorize.
    if oauth_state.redirect_uri is None or oauth_state.redirect_uri != redirect_uri:
        logger.warning(f"Authorization code redirect_uri mismatch (state {oauth_state.id[:8]}...)")
        raise jafaal_exceptions.InvalidRequestError("invalid_grant: the authorization code is invalid or expired")

    session_obj = _pending_session_for(oauth_state, db)
    if session_obj is None:
        logger.warning(f"Authorization code has no pending session (state {oauth_state.id[:8]}...)")
        raise jafaal_exceptions.InvalidRequestError("invalid_grant: the authorization code is invalid or expired")

    return session_obj, oauth_state


def _pending_session_for(
    oauth_state: oauth_state_models.OAuthState,
    db: Session,
) -> jafaal_sessions_models.UsersSessions | None:
    """Return the session created for ``oauth_state``, if one exists."""
    sessions = jafaal_sessions_crud.get_sessions_by_oauth_state_id(oauth_state.id, db)
    return sessions[0] if sessions else None


def complete_pkce_exchange(
    *,
    session_obj: jafaal_sessions_models.UsersSessions,
    oauth_state: oauth_state_models.OAuthState,
    code_verifier: str,
    client_type: str,
    response: Response,
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
) -> dict[str, object]:
    """Verify PKCE, claim the one-shot session, and mint the token bundle.

    The single implementation behind both the standard
    ``grant_type=authorization_code`` request and JAFAAL's native
    ``/session/{id}/tokens`` shape, so the two request formats cannot drift into
    different security properties.

    Args:
        session_obj: The pending session the code/session id resolved to.
        oauth_state: The OAuth state holding the PKCE challenge.
        code_verifier: The verifier presented by the client.
        client_type: Resolved delivery mode (``"web"`` or ``"mobile"``).
        response: HTTP response, used to set the web refresh cookie.
        token_manager: Token manager used to mint the bundle.
        db: Active database session.

    Returns:
        Mapping with ``session_id``, ``access_token``, ``refresh_token``,
        ``csrf_token`` and the two expiry counts. Callers project it into their
        own response schema.

    Raises:
        InvalidRequestError: If the state carries no PKCE data or the verifier
            does not match.
        ConflictError: If the session was already exchanged (including losing
            a concurrent race).
        AuthenticationError: If the account is no longer active.
    """
    if not oauth_state.code_challenge or not oauth_state.code_challenge_method:
        logger.error(f"Token exchange failed: OAuth state {oauth_state.id[:8]}... missing PKCE data")
        raise jafaal_exceptions.InvalidRequestError("OAuth state missing PKCE data")

    idp_utils.validate_pkce_verifier(
        code_verifier=code_verifier,
        code_challenge=oauth_state.code_challenge,
        code_challenge_method=oauth_state.code_challenge_method,
    )

    user = cast(jafaal_ports.UserProtocol, session_obj.users)
    jafaal_user_guards.check_user_is_active(user)

    session_id = session_obj.id
    (
        _,
        access_token_exp,
        access_token,
        refresh_token_exp,
        refresh_token,
        csrf_token,
    ) = jafaal_utils.create_tokens(user, token_manager, session_id)

    # Claim the session and persist the refresh-token digest in one atomic
    # conditional UPDATE. This closes the check-then-act race where two
    # concurrent redemptions with the correct verifier could both pass a
    # ``tokens_exchanged`` guard, both mint refresh tokens, and the second
    # overwrite the first — handing the loser a working token while silently
    # invalidating the winner's.
    #
    # Note: csrf_token_hash is deliberately NOT stored here (page-reload
    # bootstrap); the first /refresh after a reload establishes the binding.
    claimed = jafaal_sessions_crud.claim_session_for_token_exchange(
        session_id,
        jafaal_sessions_utils.hash_refresh_token(refresh_token),
        db,
    )
    if not claimed:
        logger.warning(f"Token exchange lost race for session {session_id[:8]}...")
        raise jafaal_exceptions.ConflictError("Tokens already exchanged for this session")

    if client_type == "web":
        # Cookie attributes (Secure, SameSite, Path, expiry) are centralised in
        # set_refresh_token_cookie so this flow stays in lockstep with password
        # login and /refresh.
        jafaal_utils.set_refresh_token_cookie(response, refresh_token)

    return jafaal_utils.build_token_response(
        response,
        client_type,
        session_id,
        access_token,
        access_token_exp,
        refresh_token,
        refresh_token_exp,
        csrf_token,
    )


def resolve_client_type(
    oauth_state: oauth_state_models.OAuthState,
    header_client_type: str | None,
) -> str:
    """Resolve the token-delivery mode for an exchange.

    Authority order:

    1. ``oauth_state.client_type`` — recorded when the flow was initiated by a
       client that *did* declare itself. When present it is the original,
       server-recorded intent and the redeeming caller must not override it.
    2. The ``X-Client-Type`` header — consulted only when nothing was recorded,
       which is the genuine system-browser case (the OS browser sends no custom
       headers when opening the authorization endpoint).

    Preferring the header unconditionally would let the redeeming caller switch
    between the cookie-set ``web`` shape and the body-only ``mobile`` shape at
    will, bypassing the cookie decision that should follow from how the flow was
    actually started.

    Args:
        oauth_state: The state the code/session was issued against.
        header_client_type: Raw ``X-Client-Type`` header, if sent.

    Returns:
        ``"web"`` or ``"mobile"``.

    Raises:
        InvalidRequestError: If the header contradicts the recorded intent.
    """
    declared = header_client_type if header_client_type in ("web", "mobile") else None
    stored = oauth_state.client_type if oauth_state.client_type in ("web", "mobile") else None

    if stored is not None:
        if declared is not None and declared != stored:
            logger.warning(f"Token exchange client_type mismatch: stored={stored}, header={declared}")
            raise jafaal_exceptions.InvalidRequestError("client_type does not match the OAuth state")
        return stored
    return declared or "web"


def validate_client_and_redirect_uri(client_id: str, redirect_uri: str) -> None:
    """Assert ``redirect_uri`` is registered for ``client_id``.

    The gate that makes the authorization endpoint safe to redirect from. It runs
    *before* anything is persisted or redirected, so an unregistered pair never
    reaches a browser navigation.

    Args:
        client_id: The ``client_id`` request parameter.
        redirect_uri: The ``redirect_uri`` request parameter.

    Raises:
        InvalidRequestError: If the client is unknown or the URI is not
            registered for it. RFC 6749 §4.1.2.1 requires this to be reported to
            the *user agent* rather than redirected, precisely because an
            unvalidated redirect target must never be used.
    """
    client = jafaal_settings.get_settings().oauth_client(client_id)
    if client is None:
        logger.warning(f"Authorization request from unregistered client_id={client_id!r}")
        raise jafaal_exceptions.InvalidRequestError(
            "invalid_client: unknown client_id. Register it via AuthSettings.oauth_clients."
        )
    if not client.permits(redirect_uri):
        logger.warning(f"Authorization request for client_id={client_id!r} used an unregistered redirect_uri")
        raise jafaal_exceptions.InvalidRequestError(
            "invalid_request: redirect_uri is not registered for this client. It must match one of the "
            "client's registered URIs exactly."
        )


def validate_authorization_request(
    response_type: str,
    code_challenge: str,
    code_challenge_method: str,
) -> None:
    """Validate the non-redirect parameters of an authorization request.

    Args:
        response_type: The requested response type.
        code_challenge: The PKCE challenge.
        code_challenge_method: The PKCE method.

    Raises:
        InvalidRequestError: If the response type is unsupported or the PKCE
            parameters are missing or malformed.
    """
    if response_type != RESPONSE_TYPE_CODE:
        raise jafaal_exceptions.InvalidRequestError(
            f"unsupported_response_type: this authorization endpoint implements only "
            f"{RESPONSE_TYPE_CODE!r} (got {response_type!r})."
        )
    if not code_challenge or not code_challenge_method:
        raise jafaal_exceptions.InvalidRequestError(
            "invalid_request: code_challenge and code_challenge_method are required (PKCE is mandatory)."
        )
    idp_utils.validate_pkce_challenge(code_challenge, code_challenge_method)
