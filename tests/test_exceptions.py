"""Contract tests for the JAFAAL exception hierarchy + edge handler (Phase 4b).

Asserts each domain error's stable ``code`` + HTTP ``status_code``/``headers``,
and that the edge handler maps them to the expected JSON responses. These pin the
framework-neutral contract that the raise-site migration must not break.
"""

import asyncio
import json

import pytest

from jafaal import exceptions as exc
from jafaal.error_handler import jafaal_exception_handler

# --------------------------------------------------------------------------- #
# Hierarchy contract
# --------------------------------------------------------------------------- #

_STATUS_AND_CODE = [
    (exc.AuthenticationError, 401, "authentication_error"),
    (exc.AuthorizationError, 403, "authorization_error"),
    (exc.InvalidRequestError, 400, "invalid_request"),
    (exc.UnprocessableError, 422, "unprocessable"),
    (exc.NotFoundError, 404, "not_found"),
    (exc.ConflictError, 409, "conflict"),
    (exc.PreconditionFailedError, 412, "precondition_failed"),
    (exc.RateLimitedError, 429, "rate_limited"),
    (exc.UpstreamError, 502, "upstream_error"),
    (exc.UpstreamTimeoutError, 504, "upstream_timeout"),
    (exc.ServiceUnavailableError, 503, "service_unavailable"),
    (exc.InternalError, 500, "internal_error"),
    (exc.InvalidCredentialsError, 401, "invalid_credentials"),
    (exc.TokenExpiredError, 401, "token_expired"),
    (exc.InvalidTokenError, 401, "invalid_token"),
    (exc.SessionExpiredError, 401, "session_expired"),
    (exc.InvalidApiKeyError, 401, "invalid_api_key"),
    (exc.StaleRefreshTokenError, 401, "stale_refresh_token"),
    (exc.MissingScopeError, 403, "missing_scope"),
    (exc.InvalidMFACodeError, 400, "invalid_mfa_code"),
    (exc.PasswordPolicyError, 422, "password_policy"),
    (exc.StoreUnavailableError, 503, "store_unavailable"),
    (exc.IdentityProviderError, 502, "identity_provider_error"),
    (exc.IdentityProviderTimeoutError, 504, "identity_provider_timeout"),
]


@pytest.mark.parametrize(("cls", "status", "code"), _STATUS_AND_CODE)
def test_status_code_and_slug(cls, status, code):
    e = cls()
    assert isinstance(e, exc.JafaalError)
    assert e.status_code == status
    assert e.code == code
    assert e.detail, "each error has a non-empty default detail"


def test_401s_without_a_presented_credential_send_a_bare_bearer_challenge():
    # RFC 6750 §3: the ``error`` parameter MUST NOT be sent when the request
    # carried no authentication information — there is nothing wrong with a
    # credential that was never presented.
    for cls in (exc.AuthenticationError, exc.InvalidCredentialsError):
        assert cls().headers == {"WWW-Authenticate": "Bearer"}


def test_401s_for_an_unusable_credential_advertise_invalid_token():
    # RFC 6750 §3.1: a token that is expired, malformed, or revoked is
    # ``invalid_token``, and §3 wants a description so a client can tell
    # "refresh and retry" from "log in again" without parsing prose.
    for cls in (
        exc.TokenExpiredError,
        exc.InvalidTokenError,
        exc.SessionExpiredError,
        exc.StaleRefreshTokenError,
        exc.InactiveAccountError,
    ):
        challenge = cls().headers["WWW-Authenticate"]
        assert challenge.startswith('Bearer error="invalid_token"')
        assert 'error_description="' in challenge


def test_challenge_description_cannot_break_the_header():
    # A detail carrying a quote or newline must not produce a malformed header.
    challenge = exc.InvalidTokenError('bad "token"\r\nInjected: x').headers["WWW-Authenticate"]
    assert "\r" not in challenge
    assert "\n" not in challenge
    assert challenge.count('"') % 2 == 0


def test_an_inactive_account_is_a_401_not_a_403_or_404():
    # A deactivated/deleted account is a credential-validation failure: 403
    # would tell a bearer its token is still good, and 404 would make account
    # state observable to whoever holds a stale token.
    assert exc.InactiveAccountError.status_code == 401
    assert issubclass(exc.InactiveAccountError, exc.AuthenticationError)


def test_invalid_api_key_advertises_apikey():
    assert exc.InvalidApiKeyError().headers == {"WWW-Authenticate": "ApiKey"}


def test_inheritance_shape():
    assert issubclass(exc.UnprocessableError, exc.InvalidRequestError)
    assert issubclass(exc.InvalidMFACodeError, exc.InvalidRequestError)
    assert issubclass(exc.PasswordPolicyError, exc.UnprocessableError)
    assert issubclass(exc.StoreUnavailableError, exc.ServiceUnavailableError)
    assert issubclass(exc.IdentityProviderTimeoutError, exc.UpstreamError)
    assert issubclass(exc.MissingScopeError, exc.AuthorizationError)


def test_custom_detail_overrides_default():
    assert exc.NotFoundError("no user").detail == "no user"
    assert exc.NotFoundError().detail == exc.NotFoundError.default_detail


def test_rate_limited_retry_after():
    e = exc.RateLimitedError(retry_after=30)
    assert e.retry_after == 30
    assert e.headers["Retry-After"] == "30"


def test_missing_scope_carries_missing():
    e = exc.MissingScopeError(missing={"users:write", "users:read"})
    assert e.missing == frozenset({"users:write", "users:read"})


def test_stale_refresh_token_flag():
    assert exc.StaleRefreshTokenError().clear_refresh_cookie is True


# --------------------------------------------------------------------------- #
# Edge handler mapping
# --------------------------------------------------------------------------- #


def _handle(e):
    return asyncio.run(jafaal_exception_handler(None, e))


def test_handler_status_and_body():
    r = _handle(exc.NotFoundError("nope"))
    assert r.status_code == 404
    assert json.loads(r.body) == {"detail": "nope", "code": "not_found"}


def test_handler_propagates_www_authenticate():
    r = _handle(exc.InvalidCredentialsError())
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_handler_propagates_retry_after():
    r = _handle(exc.RateLimitedError(retry_after=42))
    assert r.status_code == 429
    assert r.headers["retry-after"] == "42"


def test_handler_clears_refresh_cookie():
    r = _handle(exc.StaleRefreshTokenError())
    assert r.status_code == 401
    set_cookies = [v.decode() for k, v in r.raw_headers if k == b"set-cookie"]
    assert set_cookies, "stale refresh token must emit cookie-deletion headers"
    assert any("jafaal_refresh_token" in c for c in set_cookies)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
