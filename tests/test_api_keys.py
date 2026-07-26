"""Tests for API-key helpers and the host-configurable scope allow-list."""

import hashlib

import pytest

import jafaal
import jafaal.api_keys.utils as api_keys_utils
import jafaal.scopes as scopes
import jafaal.settings as settings_mod


def test_generate_api_key_format():
    key = api_keys_utils.generate_api_key()
    prefix = settings_mod.get_settings().api_key_prefix
    assert key.startswith(f"{prefix}_")
    # prefix + "_" + 43-char base64url token
    assert len(key.split("_", 1)[1]) >= 43


def test_hash_api_key_is_a_keyed_hmac():
    raw = "jafaal_abc"
    # Keyed under the API-key subkey: neither a bare SHA-256 (which anyone with
    # database read access could recompute offline) nor a digest any other
    # purpose could produce.
    assert api_keys_utils.hash_api_key(raw) != hashlib.sha256(raw.encode()).hexdigest()
    assert api_keys_utils.hash_api_key(raw) == api_keys_utils.token_hashing.hmac_sha256(
        raw, api_keys_utils.token_hashing.KeyPurpose.API_KEY
    )


def test_scope_allow_list_is_empty_by_default():
    assert api_keys_utils.get_api_key_scopes() == frozenset()
    # With no configured scopes, everything is rejected.
    with pytest.raises(ValueError):
        api_keys_utils.validate_api_key_scopes(["anything"], granted_scopes=["anything"])


def test_configure_and_validate_scopes():
    jafaal.configure_api_key_scopes(["reports:read", "reports:write"])
    assert api_keys_utils.get_api_key_scopes() == frozenset({"reports:read", "reports:write"})
    # Supported scopes the caller holds pass.
    api_keys_utils.validate_api_key_scopes(["reports:read"], granted_scopes=["reports:read"])
    # Unsupported scope rejected.
    with pytest.raises(ValueError, match="Unsupported API key scopes"):
        api_keys_utils.validate_api_key_scopes(["reports:delete"], granted_scopes=["reports:delete"])
    # Empty request rejected.
    with pytest.raises(ValueError):
        api_keys_utils.validate_api_key_scopes([], granted_scopes=["reports:read"])


# --------------------------------------------------------------------------- #
# Scope delegation
#
# A credential may never carry more authority than the account minting it: an
# allow-listed scope the caller does not hold must be refused, otherwise API-key
# creation is a privilege-escalation primitive.
# --------------------------------------------------------------------------- #


def test_caller_cannot_grant_a_scope_it_does_not_hold():
    jafaal.configure_api_key_scopes(["reports:read", "users:write"])
    with pytest.raises(ValueError, match="do not hold"):
        api_keys_utils.validate_api_key_scopes(["users:write"], granted_scopes=["reports:read"])


def test_partial_escalation_is_refused_entirely():
    jafaal.configure_api_key_scopes(["reports:read", "users:write"])
    with pytest.raises(ValueError, match="users:write"):
        api_keys_utils.validate_api_key_scopes(
            ["reports:read", "users:write"],
            granted_scopes=["reports:read"],
        )


def test_caller_may_grant_a_subset_of_its_own_scopes():
    jafaal.configure_api_key_scopes(["reports:read", "users:write"])
    api_keys_utils.validate_api_key_scopes(
        ["reports:read"],
        granted_scopes=["reports:read", "users:write"],
    )


def test_allow_list_still_caps_a_superuser():
    # Holding a scope is not enough: it must also be allow-listed for API keys.
    jafaal.configure_api_key_scopes(["reports:read"])
    with pytest.raises(ValueError, match="Unsupported API key scopes"):
        api_keys_utils.validate_api_key_scopes(["users:write"], granted_scopes=["reports:read", "users:write"])


def test_reset_scopes():
    jafaal.configure_api_key_scopes(["reports:read"])
    jafaal.reset_api_key_scopes()
    assert api_keys_utils.get_api_key_scopes() == frozenset()


def test_scopes_json_roundtrip():
    scopes = ["reports:read", "reports:write"]
    encoded = api_keys_utils.scopes_to_json(scopes)
    assert api_keys_utils.json_to_scopes(encoded) == scopes


# --------------------------------------------------------------------------- #
# Keyed-digest migration
#
# Keys issued before the move from an unkeyed SHA-256 to a keyed HMAC must keep
# authenticating, and be rewritten to the keyed form on first use so the
# fallback drains.
# --------------------------------------------------------------------------- #


def _fake_request():
    from types import SimpleNamespace

    return SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(path="/api/v1/whatever"),
        headers={},
    )


def _identity_service(db):
    from jafaal._internal.password_hasher import get_password_hasher
    from jafaal._internal.token_manager import get_token_manager
    from jafaal.identity_service import DefaultIdentityService

    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _create_key(user_id, db):
    import jafaal.api_keys.crud as api_keys_crud
    import jafaal.api_keys.schema as api_keys_schema

    jafaal.configure_api_key_scopes(["reports:read"])
    return api_keys_crud.create_api_key(
        user_id,
        api_keys_schema.UsersApiKeyCreate(name="k", scopes=["reports:read"]),
        db,
    )


def test_new_api_keys_are_stored_as_keyed_digests(db, make_user):
    user = make_user(username="keyowner")
    row, raw_key = _create_key(user.id, db)
    assert row.key_hash == api_keys_utils.hash_api_key(raw_key)
    assert row.key_hash != hashlib.sha256(raw_key.encode()).hexdigest()


def test_stored_api_key_authenticates(db, make_user):
    user = make_user(username="keyuser")
    _row, raw_key = _create_key(user.id, db)

    principal = _identity_service(db).resolve_from_api_key(raw_key, _fake_request())
    assert principal.user_id == user.id


def test_unknown_api_key_is_rejected(db, make_user):
    from jafaal.exceptions import InvalidApiKeyError

    make_user(username="someone")
    with pytest.raises(InvalidApiKeyError):
        _identity_service(db).resolve_from_api_key("jafaal_not-a-real-key", _fake_request())


# --------------------------------------------------------------------------- #
# End-to-end scope delegation over HTTP
# --------------------------------------------------------------------------- #

_WEB = {"X-Client-Type": "web"}
_PASSWORD = "Str0ng!Pass"


def _auth_headers(client, username):
    access = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": _PASSWORD},
        headers=_WEB,
    ).json()["access_token"]
    return {**_WEB, "Authorization": f"Bearer {access}"}


def _create_key_request(client, username, requested_scopes):
    return client.post(
        "/api/v1/auth/api-keys",
        json={
            "name": "k",
            "scopes": requested_scopes,
            "current_password": _PASSWORD,
        },
        headers=_auth_headers(client, username),
    )


def test_http_regular_user_cannot_mint_an_admin_scoped_key(client, make_user):
    # ``users:write`` is allow-listed for API keys but only minted into an
    # admin's token, so a regular user must not be able to delegate it.
    jafaal.configure_api_key_scopes([scopes.USERS_READ, scopes.USERS_WRITE])
    make_user(username="regular", password=_PASSWORD, is_superuser=False)

    response = _create_key_request(client, "regular", [scopes.USERS_WRITE])

    assert response.status_code == 400
    assert "do not hold" in response.json()["detail"]


def test_http_regular_user_may_mint_a_key_within_its_own_scopes(client, make_user):
    jafaal.configure_api_key_scopes([scopes.USERS_READ, scopes.USERS_WRITE])
    make_user(username="regular2", password=_PASSWORD, is_superuser=False)

    response = _create_key_request(client, "regular2", [scopes.USERS_READ])

    assert response.status_code == 201
    # ``scopes`` is returned in its stored JSON-encoded form.
    assert api_keys_utils.json_to_scopes(response.json()["scopes"]) == [scopes.USERS_READ]


def test_http_superuser_may_mint_an_admin_scoped_key(client, make_user):
    jafaal.configure_api_key_scopes([scopes.USERS_READ, scopes.USERS_WRITE])
    make_user(username="root", password=_PASSWORD, is_superuser=True)

    response = _create_key_request(client, "root", [scopes.USERS_WRITE])

    assert response.status_code == 201


def test_http_escalating_key_is_never_persisted(client, make_user, db):
    import jafaal.api_keys.crud as api_keys_crud

    jafaal.configure_api_key_scopes([scopes.USERS_READ, scopes.USERS_WRITE])
    user = make_user(username="regular3", password=_PASSWORD, is_superuser=False)

    _create_key_request(client, "regular3", [scopes.USERS_WRITE])

    assert api_keys_crud.get_api_keys_by_user_id(user.id, db) == []
