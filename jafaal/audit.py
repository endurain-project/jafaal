"""Structured security-audit logging on the dedicated ``jafaal.audit`` logger.

JAFAAL emits every security-relevant event — login outcomes, progressive
lockouts, MFA results, refresh-token reuse/theft, API-key authentication, OAuth
state replay — as a *structured* record on the ``jafaal.audit`` logger,
separately from the human-readable ``jafaal.*`` application logs. A host wires an
audit sink (SIEM, file, message queue) by attaching a handler to that logger and
reading the structured fields off each ``LogRecord`` — no message-string parsing
required::

    import logging

    audit = logging.getLogger("jafaal.audit")   # or jafaal.audit.AUDIT_LOGGER_NAME
    audit.addHandler(my_json_handler)            # e.g. python-json-logger
    audit.setLevel(logging.INFO)
    audit.propagate = False                      # keep audit out of the app log

Every record carries these ``LogRecord`` attributes (supplied via ``extra=``):

* ``audit`` — always ``True``; a marker to filter audit records anywhere in the
  ``jafaal`` logger tree;
* ``event`` — a stable dotted slug from :class:`Event` (e.g. ``"login.failure"``)
  — the machine-readable contract; and
* ``outcome`` — ``"success"`` / ``"failure"`` / ``"blocked"`` (see
  :class:`Outcome`);

plus event-specific fields (``user_id``, ``username``, ``ip``, ``session_id``,
``key_prefix``, ``token_family_id``, ``reason``, ...). The log *message* is the
event slug, so even a plain text handler stays readable.

Privacy note: audit records may contain identifiers the application logs
deliberately omit — plaintext usernames from failed logins and client IPs —
because that is exactly the signal a SIEM needs to spot targeted brute-force.
Treat the ``jafaal.audit`` stream as sensitive and route it accordingly. JAFAAL
installs no handler itself; until the host attaches one, records propagate like
any other ``jafaal.*`` logger.
"""

from __future__ import annotations

import logging
from typing import Any, Final

__all__ = [
    "AUDIT_LOGGER_NAME",
    "Event",
    "Outcome",
    "logger",
    "record",
]

#: Name of the dedicated audit logger. Attach a handler to this to consume events.
AUDIT_LOGGER_NAME: Final = "jafaal.audit"

logger = logging.getLogger(AUDIT_LOGGER_NAME)


class Outcome:
    """Stable ``outcome`` field values."""

    SUCCESS: Final = "success"
    FAILURE: Final = "failure"
    BLOCKED: Final = "blocked"


class Event:
    """Stable ``event`` slugs — the machine-readable audit contract.

    New events may be added over time; existing slugs are not renamed.
    """

    LOGIN_SUCCESS: Final = "login.success"
    LOGIN_FAILURE: Final = "login.failure"
    LOCKOUT_APPLIED: Final = "lockout.applied"
    MFA_FAILURE: Final = "mfa.failure"
    TOKEN_REUSE_GRACE: Final = "token.reuse_grace"
    TOKEN_THEFT_DETECTED: Final = "token.theft_detected"
    API_KEY_AUTH_SUCCESS: Final = "api_key.auth_success"
    API_KEY_AUTH_FAILURE: Final = "api_key.auth_failure"
    OAUTH_STATE_REPLAY_REJECTED: Final = "oauth_state.replay_rejected"


# Attributes already present on a ``LogRecord``; ``extra=`` must not shadow them
# (the stdlib raises ``KeyError`` if it does), so ``record`` drops any collision
# defensively. ``message``/``asctime`` are added later by the formatter.
_RESERVED_LOGRECORD_KEYS: frozenset[str] = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


def record(
    event: str,
    *,
    outcome: str = Outcome.SUCCESS,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Emit a structured audit event on the ``jafaal.audit`` logger.

    Args:
        event: A stable dotted slug (see :class:`Event`).
        outcome: ``"success"`` / ``"failure"`` / ``"blocked"`` (see
            :class:`Outcome`).
        level: Logging level — ``INFO`` for normal outcomes, ``WARNING`` for
            failures and lockouts.
        **fields: Event-specific structured fields. ``None`` values and any key
            that would collide with a reserved ``LogRecord`` attribute are
            dropped, so a call site can pass optional fields unconditionally.
    """
    extra: dict[str, Any] = {"audit": True, "event": event, "outcome": outcome}
    for key, value in fields.items():
        if value is None or key in _RESERVED_LOGRECORD_KEYS:
            continue
        extra[key] = value
    logger.log(level, event, extra=extra)
