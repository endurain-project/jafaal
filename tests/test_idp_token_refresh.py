"""Tests for IdP token refresh/revoke and the refresh-policy decision logic.

Token exchange and the revocation HTTP call are mocked; the policy methods run
against real link rows (naive datetimes on SQLite) to exercise tz-normalization.
"""

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest

import jafaal.exceptions as exc
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.schema as idp_schema
from jafaal._core import crypto
from jafaal.identity_providers.service import IdentityProviderService, TokenAction

ISSUER = "https://idp.example.com"


class _FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data or {}
        self.text = ""

    @property
    def is_redirect(self):
        return self.status_code in (301, 302, 303, 307, 308)

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "e", request=httpx.Request("POST", "http://x"), response=httpx.Response(self.status_code)
            )


class _FakeHttpClient:
    def __init__(self, response):
        self._r = response
        self.post_kwargs = None

    async def get(self, url, **kwargs):
        return self._r

    async def post(self, url, **kwargs):
        self.post_kwargs = kwargs
        return self._r


class _FakeOAuthClient:
    def __init__(self, token=None, raise_exc=None):
        self._token = token
        self._raise = raise_exc

    async def fetch_token(self, endpoint, **kwargs):
        if self._raise:
            raise self._raise
        return self._token


def _no_ssrf(monkeypatch):
    monkeypatch.setattr("jafaal._core.network.reject_private_url", lambda *a, **k: None)


def _create_idp(db, *, slug="oidc", issuer_url=None, token_endpoint=None):
    return idp_crud.create_identity_provider(
        idp_schema.IdentityProviderCreate(
            name="IdP",
            slug=slug,
            client_id="cid",
            client_secret="secret",
            enabled=True,
            issuer_url=issuer_url,
            token_endpoint=token_endpoint,
        ),
        db,
    )


def _link_with_tokens(db, user_id, idp_id, *, refresh="rt", expires_at=None, updated_at=None):
    links_crud.create_user_identity_provider(user_id, idp_id, f"sub-{idp_id}", db)
    link = links_crud.get_user_identity_provider_by_user_id_and_idp_id(user_id, idp_id, db)
    link.idp_refresh_token = crypto.encrypt_token_fernet(refresh) if refresh else None
    link.idp_access_token_expires_at = expires_at
    link.idp_refresh_token_updated_at = updated_at
    db.commit()
    db.refresh(link)
    return link


# --------------------------------------------------------------------------- #
# Refresh-policy decision (_should_refresh_idp_token / _is_token_expired_by_age)
# --------------------------------------------------------------------------- #


def test_should_refresh_skip_without_token(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    link = _link_with_tokens(db, user.id, idp.id, refresh=None)
    assert IdentityProviderService()._should_refresh_idp_token(link) == TokenAction.SKIP


def test_should_refresh_when_close_to_expiry(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    now = datetime.now(UTC)
    link = _link_with_tokens(
        db, user.id, idp.id, expires_at=now + timedelta(minutes=2), updated_at=now - timedelta(minutes=10)
    )
    assert IdentityProviderService()._should_refresh_idp_token(link) == TokenAction.REFRESH


def test_should_skip_when_recently_refreshed(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    now = datetime.now(UTC)
    link = _link_with_tokens(
        db, user.id, idp.id, expires_at=now + timedelta(minutes=2), updated_at=now - timedelta(seconds=10)
    )
    assert IdentityProviderService()._should_refresh_idp_token(link) == TokenAction.SKIP


def test_should_skip_when_valid(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    now = datetime.now(UTC)
    link = _link_with_tokens(
        db, user.id, idp.id, expires_at=now + timedelta(hours=1), updated_at=now - timedelta(minutes=10)
    )
    assert IdentityProviderService()._should_refresh_idp_token(link) == TokenAction.SKIP


def test_should_clear_when_too_old(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    now = datetime.now(UTC)
    link = _link_with_tokens(
        db, user.id, idp.id, expires_at=now + timedelta(minutes=2), updated_at=now - timedelta(days=100)
    )
    assert IdentityProviderService()._should_refresh_idp_token(link) == TokenAction.CLEAR


def test_is_token_expired_by_age(db, make_user):
    user = make_user()
    now = datetime.now(UTC)
    svc = IdentityProviderService()
    old_idp = _create_idp(db, slug="old")
    old = _link_with_tokens(db, user.id, old_idp.id, updated_at=now - timedelta(days=100))
    assert svc._is_token_expired_by_age(old) is True
    fresh_idp = _create_idp(db, slug="fresh")
    fresh = _link_with_tokens(db, user.id, fresh_idp.id, updated_at=now - timedelta(days=1))
    assert svc._is_token_expired_by_age(fresh) is False


# --------------------------------------------------------------------------- #
# refresh_idp_session (mocked token exchange)
# --------------------------------------------------------------------------- #


def test_refresh_session_without_stored_token_returns_none(db, make_user):
    user = make_user()
    idp = _create_idp(db, token_endpoint=f"{ISSUER}/token")
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    assert asyncio.run(IdentityProviderService().refresh_idp_session(user.id, idp.id, db)) is None


def test_refresh_session_success(db, make_user, monkeypatch):
    _no_ssrf(monkeypatch)
    user = make_user()
    idp = _create_idp(db, token_endpoint=f"{ISSUER}/token")
    _link_with_tokens(db, user.id, idp.id, refresh="old-rt")
    new_token = {"access_token": "new-at", "refresh_token": "new-rt", "expires_in": 300}
    svc = IdentityProviderService()
    monkeypatch.setattr(svc, "_create_oauth_client", lambda **kw: _FakeOAuthClient(token=new_token))
    assert asyncio.run(svc.refresh_idp_session(user.id, idp.id, db)) == new_token


def test_refresh_session_invalid_token_is_cleared(db, make_user, monkeypatch):
    _no_ssrf(monkeypatch)
    user = make_user()
    idp = _create_idp(db, token_endpoint=f"{ISSUER}/token")
    _link_with_tokens(db, user.id, idp.id, refresh="old-rt")
    err = httpx.HTTPStatusError("bad", request=httpx.Request("POST", "http://x"), response=httpx.Response(400))
    svc = IdentityProviderService()
    monkeypatch.setattr(svc, "_create_oauth_client", lambda **kw: _FakeOAuthClient(raise_exc=err))

    assert asyncio.run(svc.refresh_idp_session(user.id, idp.id, db)) is None
    link = links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db)
    assert link.idp_refresh_token is None  # cleared


def test_clear_refresh_token_if_matches_guards_concurrent_rotation(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    _link_with_tokens(db, user.id, idp.id, refresh="rt")
    stored = links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db).idp_refresh_token

    # A concurrent refresh already rotated the token: the stale ciphertext the
    # race loser read no longer matches, so the clear must be a no-op.
    assert (
        links_crud.clear_user_identity_provider_refresh_token_if_matches(user.id, idp.id, "stale-ciphertext", db)
        is False
    )
    db.expire_all()
    link = links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db)
    assert link.idp_refresh_token == stored  # winner's freshly rotated token preserved

    # The exact stored ciphertext still clears (genuine revocation path).
    assert links_crud.clear_user_identity_provider_refresh_token_if_matches(user.id, idp.id, stored, db) is True
    db.expire_all()
    link = links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db)
    assert link.idp_refresh_token is None


def test_refresh_session_stale_400_does_not_clear_rotated_token(db, make_user, monkeypatch):
    _no_ssrf(monkeypatch)
    user = make_user()
    idp = _create_idp(db, token_endpoint=f"{ISSUER}/token")
    # The DB row holds the winner's freshly rotated token.
    _link_with_tokens(db, user.id, idp.id, refresh="winner-rt")
    winner_ct = links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db).idp_refresh_token
    # Simulate the race loser: it read the OLD ciphertext before the rotation,
    # so its now-stale token is rejected by the IdP with a 400.
    stale_ct = crypto.encrypt_token_fernet("loser-old-rt")
    monkeypatch.setattr(
        "jafaal.identity_providers.links.utils.get_user_identity_provider_refresh_token_by_user_id_and_idp_id",
        lambda *a, **k: stale_ct,
    )
    err = httpx.HTTPStatusError("bad", request=httpx.Request("POST", "http://x"), response=httpx.Response(400))
    svc = IdentityProviderService()
    monkeypatch.setattr(svc, "_create_oauth_client", lambda **kw: _FakeOAuthClient(raise_exc=err))

    assert asyncio.run(svc.refresh_idp_session(user.id, idp.id, db)) is None
    db.expire_all()
    link = links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db)
    assert link.idp_refresh_token == winner_ct  # winner's token preserved, not wiped by the loser


def test_refresh_session_idp_not_found(db):
    with pytest.raises(exc.NotFoundError):
        asyncio.run(IdentityProviderService().refresh_idp_session(1, 9999, db))


# --------------------------------------------------------------------------- #
# revoke_idp_token (RFC 7009, mocked HTTP)
# --------------------------------------------------------------------------- #


def test_revoke_no_token_is_success(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    assert asyncio.run(IdentityProviderService().revoke_idp_token(user.id, idp.id, db)) is True


def test_revoke_without_revocation_endpoint_returns_false(db, make_user):
    user = make_user()
    idp = _create_idp(db)  # no issuer_url → no discovery → no revocation endpoint
    _link_with_tokens(db, user.id, idp.id, refresh="rt")
    assert asyncio.run(IdentityProviderService().revoke_idp_token(user.id, idp.id, db)) is False


def test_revoke_success(db, make_user, monkeypatch):
    user = make_user()
    idp = _create_idp(db, issuer_url=ISSUER)
    _link_with_tokens(db, user.id, idp.id, refresh="rt")
    svc = IdentityProviderService()
    # The revocation POST carries the refresh token + client credentials, so it
    # runs the SSRF/HTTPS pre-flight; stub it (the guard has its own tests).
    _no_ssrf(monkeypatch)
    # Seed the discovery cache so the revocation endpoint resolves without HTTP.
    svc.discovery._discovery_cache[idp.id] = {"revocation_endpoint": f"{ISSUER}/revoke"}
    svc.discovery._cache_expiry[idp.id] = datetime.now(UTC) + timedelta(hours=1)
    svc.discovery._http_client = _FakeHttpClient(_FakeResponse(status_code=200))
    assert asyncio.run(svc.revoke_idp_token(user.id, idp.id, db)) is True


def test_revoke_never_follows_a_redirect(db, make_user, monkeypatch):
    """The revocation POST must not replay client credentials to a redirect target.

    The body carries ``client_secret`` and the IdP refresh token, and on a
    307/308 httpx preserves both the method and the body. The revocation
    endpoint comes from the provider's discovery document, so a redirect there
    would exfiltrate the credentials to whatever host it names — which the SSRF
    guard does not prevent, since it only rejects private addresses.
    """
    user = make_user()
    idp = _create_idp(db, issuer_url=ISSUER)
    _link_with_tokens(db, user.id, idp.id, refresh="rt")
    svc = IdentityProviderService()
    _no_ssrf(monkeypatch)
    svc.discovery._discovery_cache[idp.id] = {"revocation_endpoint": f"{ISSUER}/revoke"}
    svc.discovery._cache_expiry[idp.id] = datetime.now(UTC) + timedelta(hours=1)
    fake_client = _FakeHttpClient(_FakeResponse(status_code=307))
    svc.discovery._http_client = fake_client

    # A redirect is reported as a failed revocation, never chased.
    assert asyncio.run(svc.revoke_idp_token(user.id, idp.id, db)) is False
    # ...and redirect-following was explicitly disabled for the request.
    assert fake_client.post_kwargs["follow_redirects"] is False
