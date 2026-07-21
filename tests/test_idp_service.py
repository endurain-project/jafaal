"""Tests for the identity-provider OAuth2/OIDC service.

External I/O is mocked: HTTP (discovery / JWKS / userinfo) via fake httpx clients,
and token exchange via a fake OAuth client. ID-token verification is exercised
with real RSA signing against an in-memory JWKS. The SSRF guard is stubbed for
the HTTP-mocking tests (it has its own dedicated tests) so they stay hermetic.
"""

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey
from starlette.requests import Request

import jafaal.exceptions as exc
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.schema as idp_schema
import jafaal.oauth_state.crud as oauth_state_crud
from jafaal._internal.password_hasher import password_hasher
from jafaal.identity_providers.service import IdentityProviderService

JWKS_URI = "https://idp.example.com/jwks"
ISSUER = "https://idp.example.com"
AUDIENCE = "client-abc"


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class _FakeResponse:
    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code
        self.text = "error-body"

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "err",
                request=httpx.Request("GET", "http://x"),
                response=httpx.Response(self.status_code),
            )

    def json(self):
        return self._data


class _FakeHttpClient:
    def __init__(self, response):
        self._response = response

    async def get(self, url, headers=None, **kwargs):
        return self._response


class _FakeOAuthClient:
    def __init__(self, token, userinfo=None):
        self._token = token
        self._userinfo = userinfo

    async def fetch_token(self, token_endpoint, **kwargs):
        return self._token

    async def get(self, url, headers=None, **kwargs):
        return _FakeResponse(self._userinfo)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _request():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "client": ("1.2.3.4", 1),
        "scheme": "https",
        "server": ("app.test", 443),
    }
    return Request(scope)


def _create_idp(db, *, slug="oidc", **overrides):
    fields = {
        "name": "OIDC IdP",
        "slug": slug,
        "client_id": AUDIENCE,
        "client_secret": "the-secret",
        "enabled": True,
    }
    fields.update(overrides)
    return idp_crud.create_identity_provider(idp_schema.IdentityProviderCreate(**fields), db)


def _id_token_claims(*, iss=ISSUER, aud=AUDIENCE, nonce=None, exp_delta=3600, sub="idp-subject"):
    now = int(datetime.now(UTC).timestamp())
    claims = {"iss": iss, "aud": aud, "sub": sub, "iat": now, "exp": now + exp_delta}
    if nonce is not None:
        claims["nonce"] = nonce
    return claims


def _rsa_jwks(kid="test-key-1"):
    key = RSAKey.generate_key(2048, {"kid": kid})
    return key, {"keys": [key.as_dict(private=False)]}


def _no_ssrf(monkeypatch):
    monkeypatch.setattr("jafaal._core.network.reject_private_url", lambda *a, **k: None)


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_get_redirect_uri(db):
    svc = IdentityProviderService()
    assert svc._get_redirect_uri("google") == "https://app.test/api/v1/public/idp/callback/google"


def test_decrypt_client_id_and_secret(db):
    idp = _create_idp(db)
    svc = IdentityProviderService()
    assert svc._decrypt_client_id(idp) == AUDIENCE
    assert svc._decrypt_client_secret(idp) == "the-secret"


def test_decrypt_client_secret_failure(db):
    idp = _create_idp(db)
    idp.client_secret = "not-a-valid-fernet-value"
    svc = IdentityProviderService()
    with pytest.raises(exc.InternalError):
        svc._decrypt_client_secret(idp)


def test_map_user_claims_default_and_custom(db):
    svc = IdentityProviderService()
    idp = _create_idp(db)
    mapped = svc._map_user_claims(idp, {"preferred_username": "alice", "email": "a@b.dev", "name": "Alice"})
    assert mapped == {"username": "alice", "email": "a@b.dev", "name": "Alice"}

    idp_custom = _create_idp(db, slug="custom", user_mapping={"username": ["login"]})
    mapped2 = svc._map_user_claims(idp_custom, {"login": "bob", "email": "b@b.dev"})
    assert mapped2["username"] == "bob"


def test_is_email_verified():
    svc = IdentityProviderService()
    assert svc._is_email_verified({"email_verified": True}) is True
    assert svc._is_email_verified({"email_verified": "true"}) is True
    assert svc._is_email_verified({"email_verified": False}) is False
    assert svc._is_email_verified({}) is False


def test_prune_expired_caches():
    svc = IdentityProviderService()
    past = datetime.now(UTC) - timedelta(hours=2)
    svc._discovery_cache[1] = {"x": 1}
    svc._cache_expiry[1] = past
    svc._jwks_cache[JWKS_URI] = {"jwks": {}, "cached_at": past}
    svc._prune_expired_caches()
    assert 1 not in svc._discovery_cache
    assert JWKS_URI not in svc._jwks_cache


# --------------------------------------------------------------------------- #
# ID token verification
# --------------------------------------------------------------------------- #


def test_verify_id_token_valid():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(nonce="n1"), key)

    claims = asyncio.run(svc._verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE, expected_nonce="n1"))
    assert claims["sub"] == "idp-subject"


def test_verify_id_token_rejects_symmetric_alg():
    svc = IdentityProviderService()
    oct_key = OctKey.import_key("x" * 32)
    token = jwt.encode({"alg": "HS256", "kid": "test-key-1"}, _id_token_claims(), oct_key)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc._verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_expired():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(exp_delta=-10), key)
    with pytest.raises(exc.TokenExpiredError):
        asyncio.run(svc._verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_wrong_issuer():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(iss="https://evil.example"), key)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc._verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_nonce_mismatch():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(nonce="real"), key)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc._verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE, expected_nonce="different"))


def test_verify_id_token_unknown_kid():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks(kid="real-kid")
    svc._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "unknown-kid"}, _id_token_claims(), key)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc._verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_missing_kid():
    svc = IdentityProviderService()
    key, _jwks = _rsa_jwks()
    token = jwt.encode({"alg": "RS256"}, _id_token_claims(), key)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc._verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


# --------------------------------------------------------------------------- #
# Discovery + JWKS (mocked HTTP)
# --------------------------------------------------------------------------- #


def test_get_oidc_configuration_returns_none_without_issuer(db):
    svc = IdentityProviderService()
    idp = _create_idp(db)  # no issuer_url
    assert asyncio.run(svc.get_oidc_configuration(idp)) is None


def test_get_oidc_configuration_fetches_and_caches(db, monkeypatch):
    _no_ssrf(monkeypatch)
    svc = IdentityProviderService()
    idp = _create_idp(db, issuer_url=ISSUER)
    config = {"issuer": ISSUER, "token_endpoint": f"{ISSUER}/token", "jwks_uri": JWKS_URI}
    svc._http_client = _FakeHttpClient(_FakeResponse(config))

    result = asyncio.run(svc.get_oidc_configuration(idp))
    assert result == config
    # Cached on the second call.
    assert idp.id in svc._discovery_cache


def test_fetch_jwks_success_and_invalid(db, monkeypatch):
    _no_ssrf(monkeypatch)
    svc = IdentityProviderService()
    _key, jwks = _rsa_jwks()
    svc._http_client = _FakeHttpClient(_FakeResponse(jwks))
    assert asyncio.run(svc._fetch_jwks(JWKS_URI)) == jwks

    svc2 = IdentityProviderService()
    svc2._http_client = _FakeHttpClient(_FakeResponse({"no_keys": True}))
    with pytest.raises(exc.IdentityProviderError):
        asyncio.run(svc2._fetch_jwks(JWKS_URI))


# --------------------------------------------------------------------------- #
# Authorization URL
# --------------------------------------------------------------------------- #


def test_initiate_login_builds_authorization_url(db):
    svc = IdentityProviderService()
    idp = _create_idp(db, authorization_endpoint=f"{ISSUER}/authorize", scopes="openid email")
    state_id, nonce = "state-123", "nonce-123"
    oauth_state_crud.create_oauth_state(
        db=db, state_id=state_id, nonce=nonce, client_type="web", ip_address=None, idp_id=idp.id
    )

    url = asyncio.run(svc.initiate_login(idp, _request(), db, oauth_state_id=state_id))
    assert url.startswith(f"{ISSUER}/authorize")
    assert f"client_id={AUDIENCE}" in url
    assert "state=state-123" in url
    assert "nonce=nonce-123" in url
    assert "redirect_uri=" in url


def test_initiate_login_requires_state(db):
    svc = IdentityProviderService()
    idp = _create_idp(db, authorization_endpoint=f"{ISSUER}/authorize")
    with pytest.raises(exc.InternalError):
        asyncio.run(svc.initiate_login(idp, _request(), db, oauth_state_id=None))


# --------------------------------------------------------------------------- #
# Callback (mocked token exchange + userinfo)
# --------------------------------------------------------------------------- #


def _prepare_callback_idp(db, monkeypatch, svc, *, userinfo, token=None):
    _no_ssrf(monkeypatch)
    token = token or {"access_token": "at", "refresh_token": "rt", "expires_in": 300, "token_type": "Bearer"}
    monkeypatch.setattr(svc, "_create_oauth_client", lambda **kw: _FakeOAuthClient(token, userinfo))
    return token


def test_handle_callback_login_creates_user(db, monkeypatch):
    svc = IdentityProviderService()
    idp = _create_idp(db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo")
    userinfo = {
        "sub": "idp-sub-1",
        "email": "sso@test.dev",
        "preferred_username": "ssouser",
        "name": "SSO User",
        "email_verified": True,
    }
    token = _prepare_callback_idp(db, monkeypatch, svc, userinfo=userinfo)

    state_id = "s-login"
    oauth_state_crud.create_oauth_state(
        db=db, state_id=state_id, nonce="n", client_type="web", ip_address=None, idp_id=idp.id
    )
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    result = asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))

    assert result["user"].username == "ssouser"
    assert result["token_data"] == token
    # Link recorded for the IdP subject.
    assert links_crud.get_user_identity_provider_by_subject_and_idp_id(idp.id, "idp-sub-1", db) is not None


def test_handle_callback_link_mode(db, make_user, monkeypatch):
    user = make_user(username="existing")
    svc = IdentityProviderService()
    idp = _create_idp(db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo")
    userinfo = {"sub": "idp-sub-2", "email": "existing@test.dev", "email_verified": True}
    _prepare_callback_idp(db, monkeypatch, svc, userinfo=userinfo)

    state_id = "s-link"
    oauth_state_crud.create_oauth_state(
        db=db,
        state_id=state_id,
        nonce="n",
        client_type="web",
        ip_address=None,
        idp_id=idp.id,
        user_id=user.id,
    )
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    result = asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))
    assert result["mode"] == "link"
    assert result["user"].id == user.id
    assert links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db) is not None


def test_handle_callback_missing_subject(db, monkeypatch):
    svc = IdentityProviderService()
    idp = _create_idp(db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo")
    _prepare_callback_idp(db, monkeypatch, svc, userinfo={"email": "x@test.dev"})  # no 'sub'

    state_id = "s-nosub"
    oauth_state_crud.create_oauth_state(
        db=db, state_id=state_id, nonce="n", client_type="web", ip_address=None, idp_id=idp.id
    )
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    with pytest.raises(exc.IdentityProviderError):
        asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))
