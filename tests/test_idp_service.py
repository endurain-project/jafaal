"""Tests for the identity-provider OAuth2/OIDC service.

External I/O is mocked: HTTP (discovery / JWKS / userinfo) via fake httpx clients,
and token exchange via a fake OAuth client. ID-token verification is exercised
with real RSA signing against an in-memory JWKS. The SSRF guard is stubbed for
the HTTP-mocking tests (it has its own dedicated tests) so they stay hermetic.
"""

import asyncio
import base64
import hashlib
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from conftest import replace_settings
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey
from starlette.requests import Request

import jafaal
import jafaal.exceptions as exc
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.schema as idp_schema
import jafaal.oauth_state.crud as oauth_state_crud
from jafaal._core import crypto
from jafaal._internal.password_hasher import password_hasher
from jafaal._internal.security_stores import consume_step_up_reauth_grant
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


class _CapturingOAuthClient:
    """OAuth client that records the kwargs passed to ``fetch_token``."""

    def __init__(self, captured, token, userinfo=None):
        self._captured = captured
        self._token = token
        self._userinfo = userinfo

    async def fetch_token(self, token_endpoint, **kwargs):
        self._captured.update(kwargs)
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


def _id_token_claims(
    *, iss=ISSUER, aud=AUDIENCE, nonce=None, exp_delta=3600, sub="idp-subject", azp=None, at_hash=None
):
    now = int(datetime.now(UTC).timestamp())
    claims = {"iss": iss, "aud": aud, "sub": sub, "iat": now, "exp": now + exp_delta}
    if nonce is not None:
        claims["nonce"] = nonce
    if azp is not None:
        claims["azp"] = azp
    if at_hash is not None:
        claims["at_hash"] = at_hash
    return claims


def _rsa_jwks(kid="test-key-1"):
    key = RSAKey.generate_key(2048, {"kid": kid})
    return key, {"keys": [key.as_dict(private=False)]}


def _no_ssrf(monkeypatch):
    monkeypatch.setattr("jafaal._core.network.reject_private_url", lambda *a, **k: None)


@contextmanager
def _settings(**overrides):
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, **overrides))
    try:
        yield
    finally:
        jafaal.configure(original)


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
    svc.discovery._discovery_cache[1] = {"x": 1}
    svc.discovery._cache_expiry[1] = past
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": {}, "cached_at": past}
    svc.discovery._prune_expired_caches()
    assert 1 not in svc.discovery._discovery_cache
    assert JWKS_URI not in svc.discovery._jwks_cache


# --------------------------------------------------------------------------- #
# ID token verification
# --------------------------------------------------------------------------- #


def test_verify_id_token_valid():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(nonce="n1"), key)

    claims = asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE, expected_nonce="n1"))
    assert claims["sub"] == "idp-subject"


def test_verify_id_token_rejects_symmetric_alg():
    svc = IdentityProviderService()
    oct_key = OctKey.import_key("x" * 32)
    token = jwt.encode({"alg": "HS256", "kid": "test-key-1"}, _id_token_claims(), oct_key)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_expired():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(exp_delta=-10), key)
    with pytest.raises(exc.TokenExpiredError):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_wrong_issuer():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(iss="https://evil.example"), key)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_nonce_mismatch():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(nonce="real"), key)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE, expected_nonce="different"))


def test_verify_id_token_unknown_kid_falls_back_to_every_published_key():
    # ``kid`` is a hint, not a requirement: a stale cached JWKS (or an IdP that
    # rotated keys without changing the set) would otherwise fail every login.
    # The signature still has to verify against a key the IdP published.
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks(kid="real-kid")
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "unknown-kid"}, _id_token_claims(), key)
    claims = asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))
    assert claims["sub"] == "idp-subject"


def test_verify_id_token_unknown_kid_still_rejects_foreign_signature():
    # The fallback must not become "accept anything": a token signed by a key the
    # IdP never published is still rejected.
    svc = IdentityProviderService()
    _published, jwks = _rsa_jwks(kid="real-kid")
    foreign, _ = _rsa_jwks(kid="attacker-kid")
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "unknown-kid"}, _id_token_claims(), foreign)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_azp_mismatch_rejected():
    # A present azp naming a different client must be rejected (OIDC §3.1.3.7).
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(azp="someone-else"), key)
    with pytest.raises(exc.InvalidTokenError, match="azp"):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_azp_match_accepted():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(azp=AUDIENCE), key)
    claims = asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))
    assert claims["azp"] == AUDIENCE


def test_verify_id_token_multiple_aud_requires_azp():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    # Multiple audiences without azp is rejected...
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(aud=[AUDIENCE, "other-client"]), key)
    with pytest.raises(exc.InvalidTokenError, match="azp"):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))
    # ...but accepted when azp names our client.
    token_ok = jwt.encode(
        {"alg": "RS256", "kid": "test-key-1"},
        _id_token_claims(aud=[AUDIENCE, "other-client"], azp=AUDIENCE),
        key,
    )
    claims = asyncio.run(svc.discovery.verify_id_token(token_ok, JWKS_URI, ISSUER, AUDIENCE))
    assert claims["sub"] == "idp-subject"


def test_verify_id_token_at_hash_valid_and_mismatch():
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    access_token = "the-access-token-value"
    # at_hash = base64url(left-most half of SHA-256(access_token)) for RS256.
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    at_hash = base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")
    token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(at_hash=at_hash), key)

    # Matching access token verifies.
    claims = asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE, access_token=access_token))
    assert claims["sub"] == "idp-subject"

    # A different access token fails the at_hash binding.
    with pytest.raises(exc.InvalidTokenError, match="at_hash"):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE, access_token="different-token"))


def test_get_userinfo_forwards_access_token_for_at_hash():
    # Confirms the wiring exercised by the SSO/mobile-PKCE callback: _get_userinfo
    # forwards the token response's access_token into ID-token verification, so
    # at_hash is validated end-to-end (not just in the unit above).
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    access_token = "exchanged-access-token"
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    at_hash = base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")
    id_token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, _id_token_claims(at_hash=at_hash), key)

    # No userinfo endpoint → verification runs against the id_token directly.
    ok = asyncio.run(
        svc._get_userinfo({"id_token": id_token, "access_token": access_token}, None, None, JWKS_URI, ISSUER, AUDIENCE)
    )
    assert ok["sub"] == "idp-subject"

    # A swapped access token breaks the at_hash binding through the same path.
    with pytest.raises(exc.InvalidTokenError, match="at_hash"):
        asyncio.run(
            svc._get_userinfo(
                {"id_token": id_token, "access_token": "swapped-token"}, None, None, JWKS_URI, ISSUER, AUDIENCE
            )
        )


def test_get_userinfo_oidc_refuses_userinfo_without_verified_id_token(monkeypatch):
    # An OIDC provider (require_verified_id_token=True) must NOT authenticate from
    # userinfo when there is no verifiable ID token; a plain OAuth2 provider
    # (False) legitimately uses userinfo as the identity source.
    _no_ssrf(monkeypatch)
    svc = IdentityProviderService()
    userinfo = {"sub": "u1", "email": "u1@test.dev"}
    client = _FakeOAuthClient({"access_token": "at"}, userinfo)

    got = asyncio.run(
        svc._get_userinfo(
            {"access_token": "at"},
            f"{ISSUER}/userinfo",
            client,
            None,
            None,
            AUDIENCE,
            require_verified_id_token=False,
        )
    )
    assert got["sub"] == "u1"

    with pytest.raises(exc.IdentityProviderError):
        asyncio.run(
            svc._get_userinfo(
                {"access_token": "at"},
                f"{ISSUER}/userinfo",
                client,
                None,
                None,
                AUDIENCE,
                require_verified_id_token=True,
            )
        )


def test_verify_id_token_without_kid_is_accepted():
    # OIDC Core does not require ``kid`` on an ID token, and single-key providers
    # routinely omit it — demanding one would refuse those IdPs outright.
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256"}, _id_token_claims(), key)
    claims = asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))
    assert claims["sub"] == "idp-subject"


def test_verify_id_token_without_kid_still_rejects_foreign_signature():
    svc = IdentityProviderService()
    _published, jwks = _rsa_jwks()
    foreign, _ = _rsa_jwks(kid="other")
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256"}, _id_token_claims(), foreign)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_skips_encryption_only_jwks_entries():
    # An entry marked use="enc" can never have produced a signature, so it must
    # not be offered as a verification candidate.
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    enc_entry = dict(jwks["keys"][0])
    enc_entry["use"] = "enc"
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": {"keys": [enc_entry]}, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256"}, _id_token_claims(), key)
    with pytest.raises(exc.InvalidTokenError):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


def test_verify_id_token_ignores_unusable_jwks_entries():
    # A malformed or unsupported entry alongside a good one must be skipped, not
    # abort the whole verification.
    svc = IdentityProviderService()
    key, jwks = _rsa_jwks()
    noisy = {"keys": [{"kty": "OKP", "crv": "X25519"}, {"kty": "RSA", "n": "!!"}, *jwks["keys"]]}
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": noisy, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256"}, _id_token_claims(), key)
    assert asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))["sub"] == "idp-subject"


def test_verify_id_token_empty_jwks_is_rejected():
    svc = IdentityProviderService()
    key, _jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": {"keys": []}, "cached_at": datetime.now(UTC)}
    token = jwt.encode({"alg": "RS256"}, _id_token_claims(), key)
    with pytest.raises(exc.InvalidTokenError, match="unknown key"):
        asyncio.run(svc.discovery.verify_id_token(token, JWKS_URI, ISSUER, AUDIENCE))


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
    svc.discovery._http_client = _FakeHttpClient(_FakeResponse(config))

    result = asyncio.run(svc.get_oidc_configuration(idp))
    assert result == config
    # Cached on the second call.
    assert idp.id in svc.discovery._discovery_cache


def test_fetch_jwks_success_and_invalid(db, monkeypatch):
    _no_ssrf(monkeypatch)
    svc = IdentityProviderService()
    _key, jwks = _rsa_jwks()
    svc.discovery._http_client = _FakeHttpClient(_FakeResponse(jwks))
    assert asyncio.run(svc.discovery.fetch_jwks(JWKS_URI)) == jwks

    svc2 = IdentityProviderService()
    svc2.discovery._http_client = _FakeHttpClient(_FakeResponse({"no_keys": True}))
    with pytest.raises(exc.IdentityProviderError):
        asyncio.run(svc2.discovery.fetch_jwks(JWKS_URI))


# --------------------------------------------------------------------------- #
# Authorization URL
# --------------------------------------------------------------------------- #


def test_initiate_login_builds_authorization_url(db):
    svc = IdentityProviderService()
    idp = _create_idp(db, authorization_endpoint=f"{ISSUER}/authorize", scopes="openid email")
    state_id, nonce = "state-123", "nonce-123"
    oauth_state_crud.create_oauth_state(db=db, state_id=state_id, nonce=nonce, ip_address=None, idp_id=idp.id)

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


def test_initiate_login_includes_pkce_challenge_and_stores_verifier(db):
    svc = IdentityProviderService()
    idp = _create_idp(db, authorization_endpoint=f"{ISSUER}/authorize")
    state_id = "pkce-state"
    oauth_state_crud.create_oauth_state(db=db, state_id=state_id, nonce="pkce-nonce", ip_address=None, idp_id=idp.id)

    url = asyncio.run(svc.initiate_login(idp, _request(), db, oauth_state_id=state_id))

    query = parse_qs(urlparse(url).query)
    assert query["code_challenge_method"] == ["S256"]
    # The verifier is stored (encrypted) against the state and matches the
    # S256 challenge advertised to the IdP (proves upstream PKCE is bound).
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)
    assert state_obj.upstream_code_verifier
    verifier = crypto.decrypt_token_fernet(state_obj.upstream_code_verifier)
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    assert query["code_challenge"] == [expected]


def test_initiate_login_rejects_http_authorization_endpoint_when_required(db):
    svc = IdentityProviderService()
    idp = _create_idp(db, authorization_endpoint="http://idp.example/authorize")
    oauth_state_crud.create_oauth_state(db=db, state_id="s-http", nonce="n", ip_address=None, idp_id=idp.id)
    with pytest.raises(exc.InvalidRequestError):
        asyncio.run(svc.initiate_login(idp, _request(), db, oauth_state_id="s-http"))


def test_initiate_login_allows_http_authorization_endpoint_when_disabled(db):
    svc = IdentityProviderService()
    idp = _create_idp(db, authorization_endpoint="http://idp.example/authorize")
    oauth_state_crud.create_oauth_state(db=db, state_id="s-httpok", nonce="n", ip_address=None, idp_id=idp.id)
    with _settings(idp_require_https=False):
        url = asyncio.run(svc.initiate_login(idp, _request(), db, oauth_state_id="s-httpok"))
    assert url.startswith("http://idp.example/authorize")


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
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    userinfo = {
        "sub": "idp-subject",
        "email": "sso@test.dev",
        "preferred_username": "ssouser",
        "name": "SSO User",
        "email_verified": True,
    }
    token = _prepare_callback_idp(db, monkeypatch, svc, userinfo=userinfo)

    state_id = "s-login"
    oauth_state_crud.create_oauth_state(db=db, state_id=state_id, nonce="n", ip_address=None, idp_id=idp.id)
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    result = asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))

    assert result["user"].username == "ssouser"
    assert result["token_data"] == token
    # Link recorded for the IdP subject.
    assert links_crud.get_user_identity_provider_by_subject_and_idp_id(idp.id, "idp-subject", db) is not None


# --------------------------------------------------------------------------- #
# Discovery must fail closed
#
# When the IdP declares an issuer the flow is OIDC and the ID token is meant to
# be verified against the discovered JWKS. Continuing after a discovery failure
# would silently skip signature, issuer and nonce validation and fall back to
# trusting the userinfo response alone — exactly the downgrade an attacker able
# to disrupt discovery would want.
# --------------------------------------------------------------------------- #


def _oidc_callback_state(db, idp, state_id):
    oauth_state_crud.create_oauth_state(db=db, state_id=state_id, nonce="n", ip_address=None, idp_id=idp.id)
    return oauth_state_crud.get_oauth_state_by_id(state_id, db)


def test_handle_callback_fails_closed_when_discovery_errors(db, monkeypatch):
    svc = IdentityProviderService()
    idp = _create_idp(db, issuer_url=ISSUER, token_endpoint=f"{ISSUER}/token")
    _prepare_callback_idp(db, monkeypatch, svc, userinfo={"sub": "idp-subject"})

    async def _boom(_idp):
        raise RuntimeError("discovery down")

    monkeypatch.setattr(svc, "get_oidc_configuration", _boom)
    state_obj = _oidc_callback_state(db, idp, "s-disc-err")

    with pytest.raises(exc.IdentityProviderError, match="discovery endpoint"):
        asyncio.run(svc.handle_callback(idp, "code", "s-disc-err", _request(), password_hasher, db, state_obj))


def test_handle_callback_fails_closed_when_discovery_publishes_no_jwks(db, monkeypatch):
    svc = IdentityProviderService()
    idp = _create_idp(db, issuer_url=ISSUER, token_endpoint=f"{ISSUER}/token")
    _prepare_callback_idp(db, monkeypatch, svc, userinfo={"sub": "idp-subject"})

    async def _no_jwks(_idp):
        return {"issuer": ISSUER, "userinfo_endpoint": f"{ISSUER}/userinfo"}

    monkeypatch.setattr(svc, "get_oidc_configuration", _no_jwks)
    state_obj = _oidc_callback_state(db, idp, "s-disc-nojwks")

    with pytest.raises(exc.IdentityProviderError, match="no JWKS"):
        asyncio.run(svc.handle_callback(idp, "code", "s-disc-nojwks", _request(), password_hasher, db, state_obj))


def test_handle_callback_without_issuer_url_skips_discovery(db, monkeypatch):
    # A plain OAuth2 provider declares no issuer, so there is no ID token to
    # verify and no discovery to fail: that path must keep working.
    svc = IdentityProviderService()
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    _prepare_callback_idp(
        db,
        monkeypatch,
        svc,
        userinfo={"sub": "plain-oauth", "email": "p@test.dev", "preferred_username": "plainuser"},
    )
    state_obj = _oidc_callback_state(db, idp, "s-no-issuer")

    result = asyncio.run(svc.handle_callback(idp, "code", "s-no-issuer", _request(), password_hasher, db, state_obj))
    assert result["user"].username == "plainuser"


def test_handle_callback_replays_pkce_verifier(db, monkeypatch):
    svc = IdentityProviderService()
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    userinfo = {"sub": "idp-pkce", "email": "pkce@test.dev", "email_verified": True}
    token = {"access_token": "at", "refresh_token": "rt", "expires_in": 300, "token_type": "Bearer"}
    captured: dict = {}
    _no_ssrf(monkeypatch)
    monkeypatch.setattr(svc, "_create_oauth_client", lambda **kw: _CapturingOAuthClient(captured, token, userinfo))

    state_id = "s-pkce"
    oauth_state_crud.create_oauth_state(db=db, state_id=state_id, nonce="n", ip_address=None, idp_id=idp.id)
    oauth_state_crud.set_upstream_code_verifier(state_id, crypto.encrypt_token_fernet("verifier-xyz"), db)
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))
    # The stored verifier is decrypted and replayed on the token exchange.
    assert captured["code_verifier"] == "verifier-xyz"


def test_handle_callback_without_pkce_verifier_omits_code_verifier(db, monkeypatch):
    svc = IdentityProviderService()
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    userinfo = {"sub": "idp-nopkce", "email": "nopkce@test.dev", "email_verified": True}
    token = {"access_token": "at", "refresh_token": "rt", "expires_in": 300, "token_type": "Bearer"}
    captured: dict = {}
    _no_ssrf(monkeypatch)
    monkeypatch.setattr(svc, "_create_oauth_client", lambda **kw: _CapturingOAuthClient(captured, token, userinfo))

    state_id = "s-nopkce"
    oauth_state_crud.create_oauth_state(db=db, state_id=state_id, nonce="n", ip_address=None, idp_id=idp.id)
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))
    # A state with no stored verifier (e.g. a legacy in-flight flow) does not
    # send code_verifier, staying compatible with the pre-PKCE token exchange.
    assert "code_verifier" not in captured


def test_handle_callback_link_mode(db, make_user, monkeypatch):
    user = make_user(username="existing")
    svc = IdentityProviderService()
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    userinfo = {"sub": "idp-sub-2", "email": "existing@test.dev", "email_verified": True}
    _prepare_callback_idp(db, monkeypatch, svc, userinfo=userinfo)

    state_id = "s-link"
    oauth_state_crud.create_oauth_state(
        db=db,
        state_id=state_id,
        nonce="n",
        ip_address=None,
        idp_id=idp.id,
        user_id=user.id,
    )
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    result = asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))
    assert result["mode"] == "link"
    assert result["user"].id == user.id
    assert links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db) is not None


def _stepup_state(db, idp, user, *, state_id):
    oauth_state_crud.create_oauth_state(
        db=db,
        state_id=state_id,
        nonce="n",
        ip_address=None,
        idp_id=idp.id,
        user_id=user.id,
        purpose="stepup",
    )
    return oauth_state_crud.get_oauth_state_by_id(state_id, db)


def test_handle_callback_step_up_success(db, make_user, monkeypatch):
    user = make_user(username="ssostepup", password=None)
    svc = IdentityProviderService()
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    links_crud.create_user_identity_provider(user.id, idp.id, "idp-sub-su", db)
    now = int(datetime.now(UTC).timestamp())
    userinfo = {"sub": "idp-sub-su", "email": "ssostepup@test.dev", "auth_time": now}
    _prepare_callback_idp(db, monkeypatch, svc, userinfo=userinfo)
    state_obj = _stepup_state(db, idp, user, state_id="s-su")

    result = asyncio.run(svc.handle_callback(idp, "auth-code", "s-su", _request(), password_hasher, db, state_obj))
    assert result["mode"] == "stepup"
    assert result["user"].id == user.id
    # A single-use step-up grant was minted for the user.
    assert consume_step_up_reauth_grant(user.id) is True


def test_handle_callback_step_up_stale_auth_time(db, make_user, monkeypatch):
    user = make_user(username="ssostale", password=None)
    svc = IdentityProviderService()
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    links_crud.create_user_identity_provider(user.id, idp.id, "idp-sub-stale", db)
    stale = int(datetime.now(UTC).timestamp()) - 4000  # older than the 300s freshness window
    userinfo = {"sub": "idp-sub-stale", "auth_time": stale}
    _prepare_callback_idp(db, monkeypatch, svc, userinfo=userinfo)
    state_obj = _stepup_state(db, idp, user, state_id="s-stale")

    with pytest.raises(exc.AuthenticationError):
        asyncio.run(svc.handle_callback(idp, "auth-code", "s-stale", _request(), password_hasher, db, state_obj))
    assert consume_step_up_reauth_grant(user.id) is False


def test_handle_callback_step_up_missing_auth_time(db, make_user, monkeypatch):
    user = make_user(username="ssonoat", password=None)
    svc = IdentityProviderService()
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    links_crud.create_user_identity_provider(user.id, idp.id, "idp-sub-noat", db)
    userinfo = {"sub": "idp-sub-noat"}  # provider did not assert auth_time
    _prepare_callback_idp(db, monkeypatch, svc, userinfo=userinfo)
    state_obj = _stepup_state(db, idp, user, state_id="s-noat")

    with pytest.raises(exc.AuthenticationError):
        asyncio.run(svc.handle_callback(idp, "auth-code", "s-noat", _request(), password_hasher, db, state_obj))
    assert consume_step_up_reauth_grant(user.id) is False


def test_handle_callback_step_up_identity_mismatch(db, make_user, monkeypatch):
    user = make_user(username="ssomm", password=None)
    svc = IdentityProviderService()
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    # The user is NOT linked to the subject the IdP returns.
    now = int(datetime.now(UTC).timestamp())
    userinfo = {"sub": "someone-elses-sub", "auth_time": now}
    _prepare_callback_idp(db, monkeypatch, svc, userinfo=userinfo)
    state_obj = _stepup_state(db, idp, user, state_id="s-mm")

    with pytest.raises(exc.AuthorizationError):
        asyncio.run(svc.handle_callback(idp, "auth-code", "s-mm", _request(), password_hasher, db, state_obj))
    assert consume_step_up_reauth_grant(user.id) is False


def test_initiate_link_forwards_extra_authorize_params(db, make_user):
    user = make_user(username="linkparams")
    svc = IdentityProviderService()
    idp = _create_idp(db, authorization_endpoint=f"{ISSUER}/authorize")
    oauth_state_crud.create_oauth_state(
        db=db,
        state_id="s-xtra",
        nonce="n",
        ip_address=None,
        idp_id=idp.id,
        user_id=user.id,
        purpose="stepup",
    )
    url = asyncio.run(
        svc.initiate_link(
            idp,
            _request(),
            user.id,
            db,
            oauth_state_id="s-xtra",
            authorize_extra_params={"prompt": "login", "max_age": "300"},
        )
    )
    assert "prompt=login" in url
    assert "max_age=300" in url


def test_handle_callback_missing_subject(db, monkeypatch):
    svc = IdentityProviderService()
    idp = _create_idp(
        db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo", provider_type="oauth2"
    )
    _prepare_callback_idp(db, monkeypatch, svc, userinfo={"email": "x@test.dev"})  # no 'sub'

    state_id = "s-nosub"
    oauth_state_crud.create_oauth_state(db=db, state_id=state_id, nonce="n", ip_address=None, idp_id=idp.id)
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    with pytest.raises(exc.IdentityProviderError):
        asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))


def test_handle_callback_oidc_refuses_unverified_userinfo(db, monkeypatch):
    # An OIDC provider that returns userinfo but no verifiable ID token (no
    # issuer_url/JWKS configured) must fail closed instead of authenticating from
    # unverified userinfo — the authorization-code-injection defense.
    svc = IdentityProviderService()
    idp = _create_idp(db, token_endpoint=f"{ISSUER}/token", userinfo_endpoint=f"{ISSUER}/userinfo")  # oidc default
    userinfo = {"sub": "idp-sub-noverify", "email": "x@test.dev", "preferred_username": "x", "email_verified": True}
    _prepare_callback_idp(db, monkeypatch, svc, userinfo=userinfo)  # token carries no id_token

    state_id = "s-oidc-noverify"
    oauth_state_crud.create_oauth_state(db=db, state_id=state_id, nonce="n", ip_address=None, idp_id=idp.id)
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    with pytest.raises(exc.IdentityProviderError):
        asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))
    # No account provisioned and no link recorded.
    assert links_crud.get_user_identity_provider_by_subject_and_idp_id(idp.id, "idp-sub-noverify", db) is None


def test_handle_callback_oidc_verified_id_token_succeeds(db, monkeypatch):
    # The OIDC happy path: a provider with a verifiable ID token authenticates
    # through the full callback with the fail-closed guard in place.
    _no_ssrf(monkeypatch)
    svc = IdentityProviderService()
    idp = _create_idp(db, issuer_url=ISSUER, token_endpoint=f"{ISSUER}/token")  # provider_type defaults to "oidc"
    key, jwks = _rsa_jwks()
    svc.discovery._jwks_cache[JWKS_URI] = {"jwks": jwks, "cached_at": datetime.now(UTC)}

    async def _fake_config(_idp):
        return {"jwks_uri": JWKS_URI, "issuer": ISSUER, "token_endpoint": f"{ISSUER}/token"}

    monkeypatch.setattr(svc, "get_oidc_configuration", _fake_config)

    claims = _id_token_claims(nonce="n", sub="idp-oidc-1")
    claims.update({"email": "oidc@test.dev", "preferred_username": "oidcuser", "email_verified": True})
    id_token = jwt.encode({"alg": "RS256", "kid": "test-key-1"}, claims, key)
    token = {"access_token": "at", "id_token": id_token, "expires_in": 300, "token_type": "Bearer"}
    monkeypatch.setattr(svc, "_create_oauth_client", lambda **kw: _FakeOAuthClient(token, None))

    state_id = "s-oidc-ok"
    oauth_state_crud.create_oauth_state(db=db, state_id=state_id, nonce="n", ip_address=None, idp_id=idp.id)
    state_obj = oauth_state_crud.get_oauth_state_by_id(state_id, db)

    result = asyncio.run(svc.handle_callback(idp, "auth-code", state_id, _request(), password_hasher, db, state_obj))
    assert result["user"].username == "oidcuser"
    assert links_crud.get_user_identity_provider_by_subject_and_idp_id(idp.id, "idp-oidc-1", db) is not None


# --------------------------------------------------------------------------- #
# SSRF guard enforced END-TO-END through the service (guard NOT stubbed)
#
# Every other test here stubs ``reject_private_url`` so it can use example.com
# hostnames offline. That leaves the wiring — service pre-flight -> real guard —
# unproven, so these tests run the genuine guard. They use IP literals
# (127.0.0.1 / 169.254.169.254), which ``getaddrinfo`` resolves locally, so no
# network access or DNS is required.
# --------------------------------------------------------------------------- #


def _link_with_refresh_token(db, user_id, idp_id, token="rt"):
    links_crud.create_user_identity_provider(user_id, idp_id, f"sub-{idp_id}", db)
    link = links_crud.get_user_identity_provider_by_user_id_and_idp_id(user_id, idp_id, db)
    link.idp_refresh_token = crypto.encrypt_token_fernet(token)
    db.commit()
    return link


@pytest.mark.parametrize(
    "token_endpoint",
    [
        "https://127.0.0.1/token",  # loopback
        "https://169.254.169.254/token",  # cloud instance metadata
        "https://10.0.0.5/token",  # private RFC1918
    ],
)
def test_service_refuses_private_token_endpoint_with_real_guard(db, make_user, token_endpoint):
    # The admin-configured token endpoint is SSRF-checked by the service before
    # any credential-bearing call is made.
    user = make_user()
    idp = _create_idp(db, token_endpoint=token_endpoint)
    _link_with_refresh_token(db, user.id, idp.id)

    with pytest.raises(exc.InvalidRequestError):
        asyncio.run(IdentityProviderService().refresh_idp_session(user.id, idp.id, db))


def test_service_refuses_private_discovery_url_with_real_guard(db, make_user):
    # Discovery is pre-flighted too, so a private issuer never resolves an
    # endpoint (the service reports an unresolvable provider rather than
    # dialling internal infrastructure).
    user = make_user()
    idp = _create_idp(db, issuer_url="https://127.0.0.1")
    _link_with_refresh_token(db, user.id, idp.id)

    with pytest.raises(exc.IdentityProviderError):
        asyncio.run(IdentityProviderService().refresh_idp_session(user.id, idp.id, db))


def test_service_honours_ssrf_allow_list_end_to_end(db, make_user, monkeypatch):
    # The opt-in escape hatch must work through the same un-stubbed path: with
    # the host allow-listed, the identical request proceeds past the guard.
    user = make_user()
    idp = _create_idp(db, token_endpoint="https://127.0.0.1/token")
    _link_with_refresh_token(db, user.id, idp.id)
    new_token = {"access_token": "at", "refresh_token": "rt2", "expires_in": 300}
    svc = IdentityProviderService()
    monkeypatch.setattr(svc, "_create_oauth_client", lambda **kw: _FakeOAuthClient(new_token, None))

    with _settings(ssrf_allowed_hosts=("127.0.0.1",)):
        assert asyncio.run(svc.refresh_idp_session(user.id, idp.id, db)) == new_token


def test_service_refuses_http_token_endpoint_with_real_guard(db, make_user):
    # idp_require_https is threaded into the same un-stubbed pre-flight, so a
    # cleartext endpoint is refused even when the host is allow-listed.
    user = make_user()
    idp = _create_idp(db, token_endpoint="http://127.0.0.1/token")
    _link_with_refresh_token(db, user.id, idp.id)

    with _settings(ssrf_allowed_hosts=("127.0.0.1",)), pytest.raises(exc.InvalidRequestError, match="HTTPS"):
        asyncio.run(IdentityProviderService().refresh_idp_session(user.id, idp.id, db))
