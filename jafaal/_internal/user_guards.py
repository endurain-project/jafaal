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


def check_user_is_active(user: jafaal_ports.UserProtocol) -> None:
    """Raise ``403`` if ``user`` is not active.

    Args:
        user: The user to check.

    Raises:
        AuthorizationError: 403 if the account is inactive.
    """
    if not user.is_active:
        raise jafaal_exceptions.AuthorizationError(
            "Inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )


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
