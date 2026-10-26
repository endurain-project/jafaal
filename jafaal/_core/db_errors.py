"""Consistent SQLAlchemy error handling for CRUD functions.

Provides the ``handle_db_errors`` decorator applied across JAFAAL's CRUD
helpers. It converts an unexpected :class:`~sqlalchemy.exc.SQLAlchemyError` into
a 500 :class:`~jafaal.exceptions.InternalError`, logging only the error class
name (never the SQL text, to avoid leaking PII or credentials — OWASP A09).
``IntegrityError`` is re-raised for caller-specific handling; every other
exception, ``JafaalError`` included, propagates untouched.

**It does not roll back.** JAFAAL's CRUD layer runs inside the *caller's*
transaction (see :func:`jafaal.orm.unit_of_work`), so rolling back here would
silently discard the host's pending work as well as JAFAAL's — turning a
recoverable constraint violation into host data loss. Unwinding is the unit of
work's job: :func:`jafaal.orm.transactional` (JAFAAL's own endpoints) or the
host's own transaction scope.

A CRUD helper that means to *catch* an ``IntegrityError`` and carry on must
therefore contain the failed flush in a savepoint — see
:func:`jafaal.orm.savepoint` — because a failed flush leaves the surrounding
transaction in a pending-rollback state that no later statement can use.
"""

import inspect
import logging
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, NoReturn, cast

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

import jafaal.exceptions as jafaal_exceptions

logger = logging.getLogger(__name__)


def _handle_db_error(db_err: SQLAlchemyError, func_name: str) -> NoReturn:
    """Log a database error securely and raise :class:`InternalError`.

    Args:
        db_err: The database error that occurred.
        func_name: Name of the function where the error occurred.

    Raises:
        InternalError: Always raises 500 after logging.
    """
    # Log only the exception class name — SQLAlchemy error strings
    # frequently embed the offending SQL statement and parameter values,
    # which can leak PII / credentials into logs (OWASP A09).
    logger.error(f"Database error in {func_name}: {type(db_err).__name__}", exc_info=db_err)

    raise jafaal_exceptions.InternalError("Database error occurred") from db_err


def handle_db_errors[T, **P](func: Callable[P, T]) -> Callable[P, T]:
    """Decorator to handle SQLAlchemy database errors consistently.

    Catches ``SQLAlchemyError``, logs it, and converts it to a 500
    ``InternalError``. ``IntegrityError`` is re-raised for caller-specific handling;
    any non-SQLAlchemy exception, ``JafaalError`` included, propagates untouched.

    Does **not** roll back: the transaction belongs to the caller (see the module
    docstring).

    Supports both synchronous and asynchronous functions.

    Args:
        func: The CRUD function to wrap (can be sync or async).

    Returns:
        Wrapped function with error handling.
    """
    # One signature covers both kinds: for a coroutine function ``T`` is the
    # coroutine it returns. A separate async overload listed first would also
    # match a sync function whose return type is untyped (the ORM models are),
    # and so mistype its result as a coroutine.
    func_name = getattr(func, "__name__", repr(func))

    if inspect.iscoroutinefunction(func):
        async_func = cast("Callable[..., Awaitable[Any]]", func)

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await async_func(*args, **kwargs)
            except IntegrityError:
                raise
            except SQLAlchemyError as db_err:
                _handle_db_error(db_err, func_name)

        return cast("Callable[P, T]", async_wrapper)

    @wraps(func)
    def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return func(*args, **kwargs)
        except IntegrityError:
            raise
        except SQLAlchemyError as db_err:
            _handle_db_error(db_err, func_name)

    return sync_wrapper
