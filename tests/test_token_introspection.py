"""Tests for token introspection (RFC 7662) and revocation (RFC 7009)."""

from __future__ import annotations

from conftest import NATIVE_CLIENT_ID, WEB_CLIENT_ID, replace_settings

import jafaal
import jafaal.api_keys.crud as api_keys_crud
import jafaal.api_keys.schema as api_keys_schema

INTROSPECT = "/api/v1/auth/introspect"
REVOKE = "/api/v1/auth/revoke"


def _login_web(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login", data={"username": username, "password": password, "client_id": WEB_CLIENT_ID}
    )


def _login_mobile(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login", data={"username": username, "password": password, "client_id": NATIVE_CLIENT_ID}
    )


def _api_key(db, user_id, scopes):
    jafaal.configure_api_key_scopes(list(scopes))
    data = api_keys_schema.UsersApiKeyCreate(name="k", scopes=list(scopes))
    _row, raw = api_keys_crud.create_api_key(user_id, data, db)
    db.commit()
    return raw


def _revoke(client, token, *, client_id=WEB_CLIENT_ID):
    """POST /revoke naming the client the token was issued to (RFC 7009 §2.1)."""
    return client.post(REVOKE, data={"token": token, "client_id": client_id})


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
    assert body["token_use"] == "access"
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
    client.post("/api/v1/auth/logout")  # deletes the session
    # The access token's session is gone → introspection reports it inactive.
    assert client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key}).json()["active"] is False


# --------------------------------------------------------------------------- #
# Revocation (RFC 7009)
# --------------------------------------------------------------------------- #


def test_revoke_refresh_token_kills_the_session(client, make_user):
    make_user(username="alice")
    refresh = _login_mobile(client).json()["refresh_token"]

    assert _revoke(client, refresh, client_id=NATIVE_CLIENT_ID).status_code == 200
    # The refresh token no longer works (its session was deleted).
    retry = client.post(
        "/api/v1/auth/refresh",
        headers={"Authorization": f"Bearer {refresh}"},
    )
    assert retry.status_code == 400  # RFC 6749 §5.2 invalid_grant


def test_revoke_unknown_token_returns_200(client):
    assert _revoke(client, "garbage").status_code == 200


def test_revoke_requires_a_client_id(client, make_user):
    # RFC 7009 §2.1: a public client identifies itself. Without it the endpoint
    # cannot check §5's "was this token issued to you?".
    make_user(username="alice")
    refresh = _login_mobile(client).json()["refresh_token"]
    resp = client.post(REVOKE, data={"token": refresh})
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_revoke_rejects_an_unregistered_client(client):
    resp = client.post(REVOKE, data={"token": "garbage", "client_id": "ghost"})
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_another_clients_token_cannot_be_revoked(client, make_user):
    # Otherwise a leaked refresh token is a force-logout primitive: anyone who
    # observes one can kill its owner's session. The refusal is silent (200,
    # no-op) so the endpoint does not answer "whose token is this?".
    make_user(username="alice")
    refresh = _login_mobile(client).json()["refresh_token"]

    assert _revoke(client, refresh, client_id=WEB_CLIENT_ID).status_code == 200

    # Still live: the session was not touched.
    still_valid = client.post(
        "/api/v1/auth/refresh",
        headers={"Authorization": f"Bearer {refresh}"},
    )
    assert still_valid.status_code == 200


def test_revoke_access_token_without_denylist_is_noop(client, make_user, db):
    user = make_user(username="alice")
    access = _login_web(client).json()["access_token"]
    key = _introspect_key(db, user.id)

    assert _revoke(client, access).status_code == 200
    # Without the opt-in denylist, the access token stays valid until it lapses.
    assert client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key}).json()["active"] is True


def test_revoke_access_token_with_denylist_enabled(client, make_user, db):
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, denylist_enabled=True))
    try:
        user = make_user(username="alice")
        access = _login_web(client).json()["access_token"]
        key = _introspect_key(db, user.id)

        assert _revoke(client, access).status_code == 200
        # The jti is denylisted → the token is now inactive and rejected.
        assert client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key}).json()["active"] is False
    finally:
        jafaal.configure(original)
        jafaal.reset_state_store()


def test_revoking_a_refresh_token_kills_its_access_tokens(client, make_user):
    # RFC 7009 §2.1: revoking a refresh token SHOULD invalidate the access tokens
    # from the same grant. Deleting the session does not — access-token
    # validation is stateless — so the session id is denylisted too.
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, denylist_enabled=True))
    try:
        make_user(username="alice")
        body = _login_mobile(client).json()
        headers = {"Authorization": f"Bearer {body['access_token']}"}
        assert client.get("/api/v1/auth/sessions/user/1", headers=headers).status_code != 401

        assert _revoke(client, body["refresh_token"], client_id=NATIVE_CLIENT_ID).status_code == 200

        assert client.get("/api/v1/auth/sessions/user/1", headers=headers).status_code == 401
    finally:
        jafaal.configure(original)
        jafaal.reset_state_store()


# --------------------------------------------------------------------------- #
# Cacheability
# --------------------------------------------------------------------------- #


def test_introspection_responses_are_not_cacheable(client, make_user, db):
    # RFC 7662 §4: the body describes a live credential — its subject, scope and
    # remaining validity — so an intermediary must not retain it.
    user = make_user(username="alice")
    access = _login_web(client).json()["access_token"]
    key = _introspect_key(db, user.id)

    resp = client.post(INTROSPECT, data={"token": access}, headers={"X-API-Key": key})
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["pragma"] == "no-cache"


def test_revocation_responses_are_not_cacheable(client, make_user):
    # The request body carried a live credential; a response cached against it
    # is a cached credential (RFC 7009 §2.1, inheriting RFC 6749 §5.1).
    make_user(username="alice")
    access = _login_web(client).json()["access_token"]

    resp = _revoke(client, access)
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["pragma"] == "no-cache"
