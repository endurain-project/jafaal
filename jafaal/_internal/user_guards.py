"""Shared user-lookup guards built on the :class:`~jafaal.ports.UserRepository`.

Small helpers that resolve a user through the configured repository (or check an
already-loaded user) and raise the same domain errors JAFAAL raised when it
called the host's user utilities. Kept dependency-light (only
:mod:`jafaal.exceptions` + :mod:`jafaal.ports`) so any layer can import it
without import cycles.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import jafaal.exceptions as jafaal_exceptions
import jafaal.ports as jafaal_ports

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from jafaal.principal import Principal


def get_user_by_id_or_404(user_id: Any, db: Session) -> jafaal_ports.UserProtocol:
    """Return the user with ``user_id`` or raise ``404``.

    For looking a user up *by request input* (an admin fetching a profile), where
    "no such user" genuinely is a 404. Resolving the user behind a **credential**
    must use :func:`resolve_credential_user` instead.

    Args:
        user_id: The user identifier to look up.
        db: Active SQLAlchemy session.

    Returns:
        The resolved user (guaranteed non-``None``).

    Raises:
        NotFoundError: 404 if no such user exists.
    """
    user = jafaal_ports.get_user_repository().get_by_id(user_id, db)
    if user is None:
        raise jafaal_exceptions.NotFoundError("User not found")
    return user


def resolve_credential_user(user_id: Any, db: Session) -> jafaal_ports.UserProtocol:
    """Return the account a presented credential belongs to, or raise ``401``.

    A structurally valid token or API key whose user row is gone is an
    *invalid credential*, not a missing resource: RFC 6750 §3.1 classes a token
    that is "revoked… or otherwise invalid" as ``invalid_token`` with a 401.
    Answering 404 would also make account deletion observable to anyone still
    holding a stale token.

    Args:
        user_id: The subject the credential names.
        db: Active SQLAlchemy session.

    Returns:
        The resolved user.

    Raises:
        InactiveAccountError: 401 if the account no longer exists.
    """
    user = jafaal_ports.get_user_repository().get_by_id(user_id, db)
    if user is None:
        raise jafaal_exceptions.InactiveAccountError("This account is no longer available.")
    return user


def check_user_is_active(user: jafaal_ports.UserProtocol) -> None:
    """Raise ``401`` if ``user`` cannot currently authenticate.

    Checks **both** flags. ``is_active`` is the account-level gate; ``is_verified``
    is the email one, and it was previously never consulted at login. That was
    safe only by accident: JAFAAL's own sign-up couples the two, so an
    unverified account also happened to be inactive. Any host repository that
    creates an active-but-unverified user — or ``provision_from_idp``, which
    hard-codes ``is_active=True`` and takes ``is_verified`` from the provider's
    claim — would have let an unverified address log in. The invariant is
    enforced here rather than left implicit in one particular sign-up flow.

    Args:
        user: The user to check.

    Raises:
        InactiveAccountError: 401 if the account is inactive or unverified.
    """
    if not user.is_active:
        raise jafaal_exceptions.InactiveAccountError("This account is not active.")
    if not user.is_verified:
        raise jafaal_exceptions.InactiveAccountError("This account's email address is not verified.")


def assert_can_access_user(principal: Principal, target_user_id: Any) -> None:
    """Enforce object-level access: caller must own the resource or be a superuser.

    Endpoints that take a ``user_id`` path parameter authorize by scope alone,
    which is safe only while the relevant scope is admin-only. This guard adds
    the missing object-level (BOLA/IDOR) check so that granting a scope to
    regular users can never let one user act on another user's resources: a
    non-superuser principal may only act on its own ``user_id``.

    Args:
        principal: The authenticated principal.
        target_user_id: The ``user_id`` the request is acting on.

    Raises:
        AuthorizationError: 403 if the principal is neither the owner nor a
            superuser.
    """
    if principal.is_superuser:
        return
    if principal.user_id != target_user_id:
        raise jafaal_exceptions.AuthorizationError("You do not have permission to access this resource")
