"""Tests for token introspection (RFC 7662) and revocation (RFC 7009)."""

from __future__ import annotations

from conftest import replace_settings

import jafaal
import jafaal.api_keys.crud as api_keys_crud
import jafaal.api_keys.schema as api_keys_schema

WEB = {"X-Client-Type": "web"}
MOBILE = {"X-Client-Type": "mobile"}
INTROSPECT = "/api/v1/auth/introspect"
REVOKE = "/api/v1/auth/revoke"


def _login_web(client, username="alice", password="Str0ng!Pass"):
    return client.post("/api/v1/auth/login", data={"username": username, "password": password}, headers=WEB)


def _login_mobile(client, username="alice", password="Str0ng!Pass"):
    return client.post("/api/v1/auth/login", data={"username": username, "password": password}, headers=MOBILE)


def _api_key(db, user_id, scopes):
    jafaal.configure_api_key_scopes(list(scopes))
    data = api_keys_schema.UsersApiKeyCreate(name="k", scopes=list(scopes))
    _row, raw = api_keys_crud.create_api_key(user_id, data, db)
    return raw


def _introspect_key(db, user_id):
    return _api_key(db, user_id, [jafaal.AUTH_INTROSPECT])


# --------------------------------------------------------------------------- #
# Introspection (RFC 7662)
# --------------------------------------------------------------------------- #


def test_introspect_active_access_token(client, make_user, db):
    user = make_user(username="alice")
    access = _login_web(client).json()["access_token"]
    key = _introspect_key(db, user.id)

    resp = client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key})
    assert resp.status_code == 200
    body = resp.json()
    assert body["active"] is True
    assert body["sub"] == str(user.id)
    assert body["typ"] == "access"
    assert body["token_type"] == "Bearer"
    assert "profile" in body["scope"]  # space-delimited per RFC 7662


def test_introspect_requires_the_introspect_scope(client, make_user, db):
    user = make_user(username="alice")
    access = _login_web(client).json()["access_token"]
    # An API key WITHOUT auth:introspect must be rejected.
    key = _api_key(db, user.id, ["profile"])
    resp = client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key})
    assert resp.status_code == 403


def test_introspect_unauthenticated_is_rejected(client, make_user):
    make_user(username="alice")
    access = _login_web(client).json()["access_token"]
    assert client.post(INTROSPECT, data={"token": access}).status_code == 401


def test_introspect_invalid_token_is_inactive(client, make_user, db):
    user = make_user(username="alice")
    key = _introspect_key(db, user.id)
    resp = client.post(INTROSPECT, data={"token": "not.a.jwt"}, headers={"X-API-Key": key})
    assert resp.status_code == 200
    assert resp.json()["active"] is False


def test_introspect_reflects_logout(client, make_user, db):
    user = make_user(username="alice")
    access = _login_web(client).json()["access_token"]
    key = _introspect_key(db, user.id)

    assert client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key}).json()["active"] is True
    client.post("/api/v1/auth/logout", headers=WEB)  # deletes the session
    # The access token's session is gone → introspection reports it inactive.
    assert client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key}).json()["active"] is False


# --------------------------------------------------------------------------- #
# Revocation (RFC 7009)
# --------------------------------------------------------------------------- #


def test_revoke_refresh_token_kills_the_session(client, make_user):
    make_user(username="alice")
    refresh = _login_mobile(client).json()["refresh_token"]

    assert client.post(REVOKE, data={"token": refresh}).status_code == 200
    # The refresh token no longer works (its session was deleted).
    retry = client.post(
        "/api/v1/auth/refresh",
        headers={**MOBILE, "Authorization": f"Bearer {refresh}"},
    )
    assert retry.status_code in (401, 404)


def test_revoke_unknown_token_returns_200(client):
    assert client.post(REVOKE, data={"token": "garbage"}).status_code == 200


def test_revoke_access_token_without_denylist_is_noop(client, make_user, db):
    user = make_user(username="alice")
    access = _login_web(client).json()["access_token"]
    key = _introspect_key(db, user.id)

    assert client.post(REVOKE, data={"token": access}).status_code == 200
    # Without the opt-in denylist, the access token stays valid until it lapses.
    assert client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key}).json()["active"] is True


def test_revoke_access_token_with_denylist_enabled(client, make_user, db):
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, denylist_enabled=True))
    try:
        user = make_user(username="alice")
        access = _login_web(client).json()["access_token"]
        key = _introspect_key(db, user.id)

        assert client.post(REVOKE, data={"token": access}).status_code == 200
        # The jti is denylisted → the token is now inactive and rejected.
        assert client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key}).json()["active"] is False
    finally:
        jafaal.configure(original)
        jafaal.reset_state_store()
