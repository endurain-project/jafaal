"""Standard-library logging shim for JAFAAL.

JAFAAL emits all log records into the ``jafaal`` logger namespace using only
the standard library. Host applications attach their own handlers and
formatters to the ``jafaal`` logger (or the root logger) to capture output —
the library never configures logging itself. This mirrors the convention used
by well-behaved Python libraries (e.g. the sibling ``safeuploads`` package).

The ``print_to_log`` / ``print_to_log_and_console`` call signatures are kept
identical to the former ``core.logger`` helpers so existing call sites need no
changes beyond their import.
"""

from __future__ import annotations

import logging
from typing import Any

# All library log records flow through this single named logger. The host
# configures handlers on "jafaal" (or an ancestor) to route the output.
logger = logging.getLogger("jafaal")

_LEVELS: dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


def print_to_log(
    message: str,
    log_level: str = "info",
    exc: Exception | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    """Log ``message`` at ``log_level`` on the ``jafaal`` logger.

    Args:
        message: The message to log.
        log_level: One of ``debug``, ``info``, ``warning``, ``error``,
            ``critical``. Unknown values fall back to ``info``.
        exc: Optional exception instance. Its traceback is attached when the
            effective level is ``error`` or ``critical``.
        context: Optional structured fields attached to the record via the
            standard-library ``extra`` mapping.
    """
    level = _LEVELS.get(log_level, logging.INFO)
    include_trace = exc is not None and level >= logging.ERROR
    logger.log(
        level,
        message,
        exc_info=exc if include_trace else None,
        extra=context,
        stacklevel=2,
    )


def print_to_log_and_console(
    message: str,
    log_level: str = "info",
    exc: Exception | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    """Alias of :func:`print_to_log`.

    In the standalone library, "console" output is simply whichever handler
    the host attaches to the ``jafaal`` logger, so this behaves identically to
    :func:`print_to_log`.
    """
    print_to_log(message, log_level, exc, context)
