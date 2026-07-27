"""FastAPI edge handler mapping :class:`~jafaal.exceptions.JafaalError` to HTTP.

This is the single place that imports FastAPI for error mapping. The host
registers it once at startup via :func:`register_exception_handlers`
(``create_auth_router`` does this automatically).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from jafaal.exceptions import JafaalError, OAuthError

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def _body(exc: JafaalError) -> dict[str, str]:
    """Return the response body for ``exc``, in the shape its audience expects.

    Two contracts, because two different consumers read them:

    * :class:`~jafaal.exceptions.OAuthError` renders the RFC 6749 §5.2 shape —
      ``{"error", "error_description"}`` — because that is the only thing a
      conformant OAuth client parses. An OAuth code smuggled inside a
      ``detail`` string is invisible to every client library.
    * everything else renders JAFAAL's ``{"detail", "code"}``, which is what an
      application front-end switches on.
    """
    if isinstance(exc, OAuthError):
        return {"error": exc.oauth_error, "error_description": exc.detail}
    return {"detail": exc.detail, "code": exc.code}


async def jafaal_exception_handler(request: Request, exc: JafaalError) -> JSONResponse:
    """Translate a :class:`JafaalError` into a JSON HTTP response.

    Emits JAFAAL's ``{"detail", "code"}`` shape, or the RFC 6749 §5.2
    ``{"error", "error_description"}`` shape for an
    :class:`~jafaal.exceptions.OAuthError` (see :func:`_body`), with the error's
    status code and header hints (e.g. ``WWW-Authenticate``, ``Retry-After``).
    When ``exc.clear_refresh_cookie`` is set (stale refresh token) the
    refresh-cookie deletion headers are added to the response.

    Token-endpoint errors also carry ``Cache-Control: no-store`` per RFC 6749
    §5.1, so an intermediary never caches an authorization failure.
    """
    headers = dict(exc.headers) if exc.headers else {}
    if isinstance(exc, OAuthError):
        headers.setdefault("Cache-Control", "no-store")
        headers.setdefault("Pragma", "no-cache")
    response = JSONResponse(
        status_code=exc.status_code,
        content=_body(exc),
        headers=headers or None,
    )
    if getattr(exc, "clear_refresh_cookie", False):
        # Imported lazily: jafaal.utils pulls in the ORM layer, which is not
        # mapped until jafaal.map_models() runs.
        import jafaal.utils as jafaal_utils

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
