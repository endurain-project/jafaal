"""OAuth state utility functions for cleanup and maintenance."""

import hmac
import logging
import secrets

from fastapi import Request, Response

import jafaal.exceptions as jafaal_exceptions
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.settings as jafaal_settings
from jafaal.orm import session_scope

logger = logging.getLogger(__name__)


def create_state_id_and_nonce() -> tuple[str, str]:
    """Generate a new random state ID and nonce for OAuth flows.

    Returns:
        Tuple of (state_id, nonce), both URL-safe random 32-byte tokens.
    """
    state_id = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    return state_id, nonce


def binding_cookie_name() -> str:
    """Return the name of the cookie that binds a link flow's state to its browser."""
    return f"{jafaal_settings.get_settings().effective_refresh_cookie_name}_idp_link"


def set_browser_binding(response: Response, state_id: str) -> None:
    """Bind a link flow's state to the browser that is about to carry it.

    The cookie holds the state id and lives only in the browser that made the
    authenticated request, so a callback arriving from any other browser can be
    refused (:func:`require_browser_binding`). It is ``SameSite=Lax`` because the
    provider returns the browser by a cross-site navigation, which a ``Strict``
    cookie would not survive. A no-op when ``SsoSettings.idp_link_browser_binding``
    is off.

    Args:
        response: The response of the request that starts the flow.
        state_id: The OAuth state id the flow was parked under.
    """
    if not jafaal_settings.get_settings().sso.idp_link_browser_binding:
        return
    response.set_cookie(
        key=binding_cookie_name(),
        value=state_id,
        max_age=int(oauth_state_crud.STATE_LIFETIME.total_seconds()),
        httponly=True,
        secure=jafaal_settings.get_settings().is_deployed,
        samesite="lax",
        path="/",
    )


def require_browser_binding(request: Request, state_id: str) -> None:
    """Refuse a link callback from a browser that did not start the flow.

    Protects against forced linking: an attacker starts a link for their own
    account and lures a victim into finishing it, which would attach the victim's
    provider identity to the attacker's account. The cookie set by
    :func:`set_browser_binding` exists only in the attacker's browser, so the
    victim's callback lacks it. Checked before the state is claimed, so a refusal
    does not spend it.

    Args:
        request: The callback request.
        state_id: The ``state`` the callback carries.

    Raises:
        InvalidRequestError: If binding is on and the cookie is absent or names
            another state.
    """
    if not jafaal_settings.get_settings().sso.idp_link_browser_binding:
        return
    bound = request.cookies.get(binding_cookie_name())
    if bound is None or not hmac.compare_digest(bound.encode(), state_id.encode()):
        raise jafaal_exceptions.InvalidRequestError("Invalid or expired OAuth state")


def delete_expired_oauth_states_from_db() -> None:
    """Remove expired OAuth states from the database.

    Opens a new database session and delegates deletion to the CRUD
    layer. Intended to be invoked by the scheduler every 5 minutes
    to clean up stale OAuth flow state that was never completed
    or consumed (states expire 10 minutes after creation).

    Returns:
        None.
    """
    with session_scope() as db:
        num_deleted = oauth_state_crud.delete_expired_oauth_states(db)

        if num_deleted > 0:
            logger.info(f"Deleted {num_deleted} expired OAuth states from database")
