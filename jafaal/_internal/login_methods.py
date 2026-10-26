"""Enforcement of the host's :class:`~jafaal.ports.LoginMethods` policy.

Each guard reads the policy through :func:`jafaal.ports.resolve_login_methods`
(never cached) and raises :class:`~jafaal.exceptions.LoginMethodDisabledError`
when the method is off. Call them before any credential is looked at, so the
refusal discloses nothing about an account.
"""

from __future__ import annotations

import logging

import jafaal.audit as jafaal_audit
import jafaal.exceptions as jafaal_exceptions
import jafaal.ports as jafaal_ports

logger = logging.getLogger(__name__)


def _refuse(method: str, detail: str) -> jafaal_exceptions.LoginMethodDisabledError:
    logger.info("Refused a %s login: the method is disabled by policy", method)
    jafaal_audit.record(
        jafaal_audit.Event.LOGIN_FAILURE,
        outcome=jafaal_audit.Outcome.BLOCKED,
        level=logging.WARNING,
        reason="login_method_disabled",
        method=method,
    )
    return jafaal_exceptions.LoginMethodDisabledError(detail)


def require_password_login() -> None:
    """Refuse unless password login is enabled."""
    if not jafaal_ports.resolve_login_methods().password:
        raise _refuse("password", "Password sign-in is disabled.")


def require_identity_provider_login() -> None:
    """Refuse unless identity-provider login is enabled."""
    if not jafaal_ports.resolve_login_methods().identity_providers:
        raise _refuse("identity_provider", "Sign-in with an identity provider is disabled.")


def require_passkey_login() -> None:
    """Refuse unless passwordless passkey login is enabled."""
    if not jafaal_ports.resolve_login_methods().passkeys:
        raise _refuse("passkey", "Passkey sign-in is disabled.")
