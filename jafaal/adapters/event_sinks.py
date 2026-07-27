"""Reference :class:`~jafaal.ports.AuthEventSink` implementations.

* :class:`LoggingAuthEventSink` — logs each event; a drop-in for local
  development and a starting point for a real delivery adapter.
* :class:`CompositeAuthEventSink` — fans one event out to several sinks (e.g.
  log *and* email), isolating failures.

Neither ever writes the plaintext ``token`` carried by the reset / verification
events: logging a still-valid credential would defeat the flow. The host's real
sink is the only place the token should be used, to build and deliver the link.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jafaal.ports import (
        AccountLocked,
        AuthEventSink,
        EmailVerificationRequested,
        IdpAccountLinked,
        NewDeviceLogin,
        PasswordResetRequested,
        RefreshTokenTheftDetected,
        SignupApproved,
        SignupPendingAdminApproval,
    )

__all__ = ["CompositeAuthEventSink", "LoggingAuthEventSink"]

_LOGGER = logging.getLogger("jafaal.adapters.events")


class LoggingAuthEventSink:
    """An ``AuthEventSink`` that logs events instead of delivering them.

    The plaintext token is deliberately **redacted** — only non-secret context
    (user id, e-mail, expiry) is logged.
    """

    def __init__(self, logger: logging.Logger | None = None, *, level: int = logging.INFO) -> None:
        """Create the sink.

        Args:
            logger: Logger to emit on. Defaults to ``jafaal.adapters.events``.
            level: Logging level for the emitted records (default ``INFO``).
        """
        self._logger = logger or _LOGGER
        self._level = level

    async def on_password_reset_requested(self, event: PasswordResetRequested) -> None:
        self._logger.log(
            self._level,
            "password reset requested (token redacted): user=%s email=%s expires_at=%s",
            event.user_id,
            event.email,
            event.expires_at,
        )

    async def on_email_verification_requested(self, event: EmailVerificationRequested) -> None:
        self._logger.log(
            self._level,
            "email verification requested (token redacted): user=%s email=%s expires_at=%s",
            event.user_id,
            event.email,
            event.expires_at,
        )

    async def on_signup_pending_admin_approval(self, event: SignupPendingAdminApproval) -> None:
        self._logger.log(
            self._level,
            "sign-up pending admin approval: user=%s username=%s",
            event.user_id,
            event.username,
        )

    async def on_signup_approved(self, event: SignupApproved) -> None:
        self._logger.log(
            self._level,
            "sign-up approved: user=%s email=%s",
            event.user_id,
            event.email,
        )

    async def on_new_device_login(self, event: NewDeviceLogin) -> None:
        self._logger.log(
            self._level,
            "new-device login: user=%s ip=%s device=%s",
            event.user_id,
            event.ip,
            event.device_description,
        )

    async def on_account_locked(self, event: AccountLocked) -> None:
        self._logger.log(
            self._level,
            "account locked (%s): %s=%s after %s failed attempts (%s)",
            event.store,
            event.subject_kind,
            event.subject,
            event.failed_attempts,
            event.lockout_label,
        )

    async def on_refresh_token_theft_detected(self, event: RefreshTokenTheftDetected) -> None:
        self._logger.log(
            self._level,
            "refresh-token theft detected: user=%s family=%s",
            event.user_id,
            event.token_family_id,
        )

    async def on_idp_account_linked(self, event: IdpAccountLinked) -> None:
        self._logger.log(
            self._level,
            "identity provider linked to existing account: user=%s idp=%s",
            event.user_id,
            event.idp_slug,
        )


class CompositeAuthEventSink:
    """Dispatch each event to several sinks in order.

    A failure in one sink is logged and swallowed so the remaining sinks still
    run, matching JAFAAL's best-effort delivery contract (a delivery failure
    must never change the HTTP response or leak account existence).
    """

    def __init__(self, sinks: Sequence[AuthEventSink]) -> None:
        """Create the composite.

        Args:
            sinks: The sinks to fan out to, invoked in order.
        """
        self._sinks: tuple[AuthEventSink, ...] = tuple(sinks)

    async def _dispatch(self, method_name: str, event: object) -> None:
        for sink in self._sinks:
            try:
                await getattr(sink, method_name)(event)
            except Exception:
                _LOGGER.exception("AuthEventSink %r failed handling %s", sink, method_name)

    async def on_password_reset_requested(self, event: PasswordResetRequested) -> None:
        await self._dispatch("on_password_reset_requested", event)

    async def on_email_verification_requested(self, event: EmailVerificationRequested) -> None:
        await self._dispatch("on_email_verification_requested", event)

    async def on_signup_pending_admin_approval(self, event: SignupPendingAdminApproval) -> None:
        await self._dispatch("on_signup_pending_admin_approval", event)

    async def on_signup_approved(self, event: SignupApproved) -> None:
        await self._dispatch("on_signup_approved", event)

    async def on_new_device_login(self, event: NewDeviceLogin) -> None:
        await self._dispatch("on_new_device_login", event)

    async def on_account_locked(self, event: AccountLocked) -> None:
        await self._dispatch("on_account_locked", event)

    async def on_refresh_token_theft_detected(self, event: RefreshTokenTheftDetected) -> None:
        await self._dispatch("on_refresh_token_theft_detected", event)

    async def on_idp_account_linked(self, event: IdpAccountLinked) -> None:
        await self._dispatch("on_idp_account_linked", event)
