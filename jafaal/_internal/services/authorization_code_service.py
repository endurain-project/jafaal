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

import hmac
import logging
import secrets
from typing import TYPE_CHECKING, cast

import jafaal._internal.user_guards as jafaal_user_guards
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.utils as idp_utils
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.ports as jafaal_ports
import jafaal.scopes as jafaal_scopes
import jafaal.sessions.crud as jafaal_sessions_crud
import jafaal.sessions.utils as jafaal_sessions_utils
import jafaal.settings as jafaal_settings
import jafaal.token_hashing as token_hashing
import jafaal.utils as jafaal_utils
from jafaal._core import network

if TYPE_CHECKING:
    from fastapi import Request, Response
    from sqlalchemy.orm import Session

    import jafaal._internal.token_manager as jafaal_token_manager
    import jafaal.oauth_state.models as oauth_state_models
    import jafaal.sessions.models as jafaal_sessions_models

logger = logging.getLogger(__name__)

#: The single message every code-redemption failure returns. Distinguishing
#: "unknown code" from "wrong client" from "wrong redirect_uri" would turn the
#: token endpoint into an oracle for probing which codes and clients exist.
_INVALID_GRANT = "The authorization code is invalid, expired, or was issued to another client."

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
        raise jafaal_exceptions.InvalidGrantError(_INVALID_GRANT)

    if oauth_state.client_id != client_id:
        logger.warning(f"Authorization code presented by the wrong client (state {oauth_state.id[:8]}...)")
        raise jafaal_exceptions.InvalidGrantError(_INVALID_GRANT)

    # RFC 6749 §4.1.3: the redirect_uri sent here MUST be identical to the one in
    # the authorization request.
    if oauth_state.redirect_uri is None or not hmac.compare_digest(oauth_state.redirect_uri, redirect_uri):
        logger.warning(f"Authorization code redirect_uri mismatch (state {oauth_state.id[:8]}...)")
        raise jafaal_exceptions.InvalidGrantError(_INVALID_GRANT)

    session_obj = _pending_session_for(oauth_state, db)
    if session_obj is None:
        logger.warning(f"Authorization code has no pending session (state {oauth_state.id[:8]}...)")
        raise jafaal_exceptions.InvalidGrantError(_INVALID_GRANT)

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
    client: jafaal_settings.OAuthClient,
    response: Response,
    token_manager: jafaal_token_manager.TokenManager,
    db: Session,
) -> dict[str, object]:
    """Verify PKCE, claim the one-shot session, and mint the token bundle.

    Args:
        session_obj: The pending session the code resolved to.
        oauth_state: The OAuth state holding the PKCE challenge.
        code_verifier: The verifier presented by the client.
        client: The registered client redeeming the code; its
            ``token_delivery`` decides the response shape and its scope ceiling
            narrows the tokens.
        response: HTTP response, used to set the refresh cookie.
        token_manager: Token manager used to mint the bundle.
        db: Active database session.

    Returns:
        Mapping with ``session_id``, ``access_token``, ``refresh_token``,
        ``csrf_token``, ``scope`` and the two expiry counts.

    Raises:
        InvalidGrantError: If the state carries no PKCE data, the verifier does
            not match, or the session was already redeemed.
        AuthenticationError: If the account is no longer active.
    """
    if not oauth_state.code_challenge or not oauth_state.code_challenge_method:
        logger.error(f"Token exchange failed: OAuth state {oauth_state.id[:8]}... missing PKCE data")
        raise jafaal_exceptions.InvalidGrantError(_INVALID_GRANT)

    try:
        idp_utils.validate_pkce_verifier(
            code_verifier=code_verifier,
            code_challenge=oauth_state.code_challenge,
            code_challenge_method=oauth_state.code_challenge_method,
        )
    except jafaal_exceptions.JafaalError as err:
        # RFC 7636 §4.6: a verifier that does not match is an invalid grant, and
        # it answers with the same message as every other redemption failure so
        # the endpoint stays uninformative to a prober.
        raise jafaal_exceptions.InvalidGrantError(_INVALID_GRANT) from err

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
    ) = jafaal_utils.create_tokens(user, token_manager, session_id, client)

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
        # A code is single-use (RFC 6749 §4.1.2); a replay is invalid_grant, and
        # RFC 9700 §4.10 treats it as evidence of leakage.
        logger.warning(f"Token exchange lost race for session {session_id[:8]}...")
        raise jafaal_exceptions.InvalidGrantError(_INVALID_GRANT)

    return jafaal_utils.build_token_response(
        response,
        client,
        session_id,
        access_token,
        access_token_exp,
        refresh_token,
        refresh_token_exp,
        csrf_token,
        jafaal_utils.granted_scope(user, client),
    )


def resolve_client(client_id: str) -> jafaal_settings.OAuthClient:
    """Return the registered client for ``client_id``.

    Args:
        client_id: The ``client_id`` request parameter.

    Returns:
        The registered client.

    Raises:
        InvalidClientError: If no client is registered under that id. RFC 6749
            §4.1.2.1 requires this to be reported to the *user agent* rather than
            redirected, because there is no verified redirect target yet.
    """
    client = jafaal_settings.get_settings().oauth_client(client_id)
    if client is None:
        logger.warning(f"Request from unregistered client_id={client_id!r}")
        raise jafaal_exceptions.InvalidClientError("Unknown client_id. Register it via AuthSettings.oauth_clients.")
    return client


def resolve_login_client(client_id: str | None, request: Request) -> jafaal_settings.OAuthClient:
    """Resolve the registered client driving a direct (non-code) login.

    The client decides how its tokens are delivered and how wide they may be, so
    it must be named on every token-issuing request. It is looked up in the
    host's registry rather than trusted from the wire: an unregistered id is
    rejected, never defaulted.

    A cookie client also gets the off-site check here. A successful login plants
    an ``HttpOnly`` refresh cookie, so the same rejection that guards ``/refresh``
    must guard the write side: it stops a cross-site page from logging the
    victim's browser into an attacker-controlled account (login CSRF / session
    fixation).

    Shared by password login, MFA completion, and both WebAuthn login ceremonies
    so none of them can end up with a different rule.

    Args:
        client_id: The ``client_id`` sent with the request.
        request: The incoming request, for the off-site check.

    Returns:
        The registered client.

    Raises:
        InvalidClientError: If ``client_id`` is absent or unregistered.
    """
    if not client_id:
        raise jafaal_exceptions.InvalidClientError(
            "client_id is required. Register your application via AuthSettings.oauth_clients and send its id."
        )
    client = resolve_client(client_id)
    if client.uses_cookie_delivery:
        network.reject_off_site_request(request, operation="Login")
    return client


def validate_client_and_redirect_uri(client_id: str, redirect_uri: str) -> jafaal_settings.OAuthClient:
    """Resolve ``client_id`` and assert ``redirect_uri`` is registered for it.

    The gate that makes the authorization endpoint safe to redirect from. It runs
    *before* anything is persisted or redirected, so an unregistered pair never
    reaches a browser navigation.

    Args:
        client_id: The ``client_id`` request parameter.
        redirect_uri: The ``redirect_uri`` request parameter.

    Returns:
        The registered client.

    Raises:
        InvalidClientError: If the client is unknown.
        OAuthError: If the URI is not registered for it. RFC 6749 §4.1.2.1
            requires both to be reported to the *user agent* rather than
            redirected, precisely because an unvalidated redirect target must
            never be used.
    """
    client = resolve_client(client_id)
    if not client.permits(redirect_uri):
        logger.warning(f"Authorization request for client_id={client_id!r} used an unregistered redirect_uri")
        raise jafaal_exceptions.OAuthError(
            "invalid_request",
            "redirect_uri is not registered for this client. It must match one of the client's "
            "registered URIs exactly.",
        )
    return client


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
        OAuthError: If the response type is unsupported or the PKCE parameters
            are missing or malformed. These are raised *after* the redirect URI
            is validated, so the caller reports them by redirect per RFC 6749
            §4.1.2.1.
    """
    if response_type != RESPONSE_TYPE_CODE:
        raise jafaal_exceptions.OAuthError(
            "unsupported_response_type",
            f"This authorization endpoint implements only {RESPONSE_TYPE_CODE!r} (got {response_type!r}).",
        )
    if not code_challenge or not code_challenge_method:
        raise jafaal_exceptions.OAuthError(
            "invalid_request",
            "code_challenge and code_challenge_method are required (PKCE is mandatory).",
        )
    idp_utils.validate_pkce_challenge(code_challenge, code_challenge_method)


def validate_requested_scope(scope: str | None, client: jafaal_settings.OAuthClient) -> None:
    """Reject a ``scope`` request the client could never be granted.

    RFC 6749 §3.3 lets the server issue a narrower scope than requested, and
    JAFAAL always advertises what it actually granted in the token response. But
    a scope that is not in the catalog at all, or is outside the client's
    ceiling, is a client bug worth reporting rather than silently dropping.

    Args:
        scope: The space-delimited ``scope`` parameter, if sent.
        client: The registered client.

    Raises:
        InvalidScopeError: If any requested scope is unknown to the catalog or
            outside the client's ceiling.
    """
    if not scope:
        return
    catalog = jafaal_scopes.get_scope_catalog()
    known = set(catalog.regular) | set(catalog.admin)
    ceiling = set(client.scopes) if client.scopes else None
    for requested in scope.split():
        if requested not in known:
            raise jafaal_exceptions.InvalidScopeError(f"Unknown scope {requested!r}.")
        if ceiling is not None and requested not in ceiling:
            raise jafaal_exceptions.InvalidScopeError(f"Scope {requested!r} is not permitted for this client.")
