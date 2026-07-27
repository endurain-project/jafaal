"""HTTP-surface security tests: refresh-cookie attributes, login lockout 429,
API-key authentication over the wire, and lazy rate-limiter binding.
"""

from __future__ import annotations

import functools

from conftest import WEB_CLIENT_ID, replace_settings
from fastapi import FastAPI, Response, Security
from fastapi.testclient import TestClient

import jafaal
import jafaal.api_keys.crud as api_keys_crud
import jafaal.api_keys.schema as api_keys_schema
import jafaal.rate_limit as rate_limit
import jafaal.utils as jafaal_utils


def _login(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password, "client_id": WEB_CLIENT_ID},
    )


def _set_cookie_headers(response) -> list[str]:
    """Return every ``Set-Cookie`` header value as a string."""
    return [value.decode() for key, value in response.headers.raw if key.lower() == b"set-cookie"]


# --------------------------------------------------------------------------- #
# Refresh-cookie security attributes
# --------------------------------------------------------------------------- #


def test_login_refresh_cookie_is_httponly_and_samesite_strict(client, make_user):
    make_user(username="alice")
    resp = _login(client)
    assert resp.status_code == 200

    # The value-bearing Set-Cookie (not the empty-value clears, which carry
    # max-age=0) is the one that fixes the cookie's security attributes.
    set_cookie = next(
        c for c in _set_cookie_headers(resp) if "jafaal_refresh_token=" in c and "max-age=0" not in c.lower()
    )
    lowered = set_cookie.lower()
    assert "httponly" in lowered
    assert "samesite=strict" in lowered
    assert "path=/api/v1/auth" in lowered


def test_refresh_cookie_is_secure_in_a_deployed_environment():
    original = jafaal.get_settings()
    # ``production`` is a deployed environment → the Secure flag must be set.
    jafaal.configure(replace_settings(original, environment="production"))
    try:
        response = Response()
        jafaal_utils.set_refresh_token_cookie(response, "tok-value")
        token_cookie = next(
            value.decode()
            for key, value in response.raw_headers
            if key.lower() == b"set-cookie" and b"jafaal_refresh_token=tok-value" in value
        )
        lowered = token_cookie.lower()
        assert "secure" in lowered
        assert "httponly" in lowered
        assert "samesite=strict" in lowered
    finally:
        jafaal.configure(original)


# --------------------------------------------------------------------------- #
# Progressive lockout surfaces as HTTP 429
# --------------------------------------------------------------------------- #


def test_login_returns_429_with_retry_after_when_account_locked(client, make_user):
    make_user(username="alice")
    # Five consecutive failures trip the first login-lockout tier.
    for _ in range(5):
        assert _login(client, password="Wr0ng!Pass").status_code == 401
    locked = _login(client, password="Wr0ng!Pass")
    assert locked.status_code == 429
    assert "retry-after" in {key.lower() for key in locked.headers}


# --------------------------------------------------------------------------- #
# API-key authentication over a real HTTP request
# --------------------------------------------------------------------------- #


def _protected_app() -> FastAPI:
    app = FastAPI()
    jafaal.register_exception_handlers(app)

    @app.get("/protected")
    def protected(_auth=Security(jafaal.check_auth_scopes, scopes=["reports:read"])):
        return {"ok": True}

    return app


def test_api_key_authenticates_over_http(make_user, db):
    jafaal.configure_api_key_scopes(["reports:read"])
    user = make_user(username="apiuser")
    _, raw = api_keys_crud.create_api_key(
        user.id, api_keys_schema.UsersApiKeyCreate(name="k", scopes=["reports:read"]), db
    )

    http = TestClient(_protected_app())

    # A valid key in the X-API-Key header authenticates and passes the scope check.
    assert http.get("/protected", headers={"X-API-Key": raw}).status_code == 200
    # No credential → 401.
    assert http.get("/protected").status_code == 401
    # An unknown key → 401.
    assert http.get("/protected", headers={"X-API-Key": "jafaal_bogus"}).status_code == 401


# --------------------------------------------------------------------------- #
# Lazy rate-limiter binding (configured after the routers are imported)
# --------------------------------------------------------------------------- #


class _BlockingLimiter:
    """A RateLimiter whose decorator rejects every request (HTTP 429)."""

    def limit(self, category):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                raise jafaal.RateLimitedError("blocked by test limiter", retry_after=1)

            return wrapper

        return decorator


def test_rate_limiter_configured_after_router_import_is_enforced(client, make_user):
    make_user(username="alice")
    # The router modules were imported when the client fixture built the app; the
    # default no-op limiter does not rate-limit.
    assert _login(client).status_code == 200

    rate_limit.configure_rate_limiter(_BlockingLimiter())
    try:
        # Lazy binding must pick up the limiter installed *after* import.
        assert _login(client).status_code == 429
    finally:
        rate_limit.reset_rate_limiter()
    # Reset re-binds the routes back to the no-op limiter on the next request.
    assert _login(client).status_code == 200
