"""Shared user-lookup guards built on the :class:`~jafaal.ports.UserRepository`.

Small helpers that resolve a user through the configured repository (or check an
already-loaded user) and raise the same HTTP errors JAFAAL raised when it called
the host's user utilities. Kept dependency-light (only ``fastapi`` +
:mod:`jafaal.ports`) so any layer can import it without import cycles.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, status

import jafaal.ports as jafaal_ports

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def get_user_by_id_or_404(user_id: Any, db: Session) -> jafaal_ports.UserProtocol:
    """Return the user with ``user_id`` or raise ``404``.

    Args:
        user_id: The user identifier to look up.
        db: Active SQLAlchemy session.

    Returns:
        The resolved user (guaranteed non-``None``).

    Raises:
        HTTPException: 404 if no such user exists.
    """
    user = jafaal_ports.get_user_repository().get_by_id(user_id, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


def check_user_is_active(user: jafaal_ports.UserProtocol) -> None:
    """Raise ``403`` if ``user`` is not active.

    Args:
        user: The user to check.

    Raises:
        HTTPException: 403 if the account is inactive.
    """
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )
