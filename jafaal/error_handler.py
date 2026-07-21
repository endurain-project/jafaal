"""FastAPI edge handler mapping :class:`~jafaal.exceptions.JafaalError` to HTTP.

This is the single place that imports FastAPI for error mapping. The host
registers it once at startup via :func:`register_exception_handlers` (Phase 5's
``create_auth_router`` does this automatically). Registration is a no-op until
the core raises a :class:`JafaalError`, so it can be installed up-front with no
behavior change (no broken window during the raise-site migration).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

import jafaal.utils as jafaal_utils
from jafaal.exceptions import JafaalError

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


async def jafaal_exception_handler(request: Request, exc: JafaalError) -> JSONResponse:
    """Translate a :class:`JafaalError` into a JSON HTTP response.

    Emits ``{"detail": ..., "code": ...}`` with the error's status code and
    header hints (e.g. ``WWW-Authenticate``, ``Retry-After``). When
    ``exc.clear_refresh_cookie`` is set (stale refresh token) the refresh-cookie
    deletion headers are added to the response.
    """
    response = JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "code": exc.code},
        headers=dict(exc.headers) if exc.headers else None,
    )
    if getattr(exc, "clear_refresh_cookie", False):
        jafaal_utils.clear_refresh_token_cookies(response)
    return response


def register_exception_handlers(app: FastAPI) -> None:
    """Install JAFAAL's edge exception handler on the host FastAPI app.

    Call once at startup, before serving requests. Safe to install up-front: it
    is a no-op until the core raises a :class:`JafaalError`.
    """
    # Starlette types handlers as ``Callable[[Request, Exception], ...]``; ours
    # narrows ``exc`` to ``JafaalError`` (safe — it is only dispatched for that
    # exception type), which Starlette's broad signature cannot express.
    app.add_exception_handler(JafaalError, jafaal_exception_handler)  # type: ignore[arg-type]
