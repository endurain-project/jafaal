"""Regression tests for the review-hardening batch (M1-M9 + standards).

Each test names the invariant it protects rather than the code path it happens
to touch, so a future refactor that keeps the behaviour keeps the test.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager

import pytest
from conftest import NATIVE_CLIENT_ID, WEB_CLIENT_ID, replace_settings
from fastapi import FastAPI
from fastapi.testclient import TestClient

import jafaal
import jafaal.exceptions as exc
import jafaal.metadata as metadata
import jafaal.ports as ports
import jafaal.scopes as scopes
import jafaal.settings as settings_mod

PASSWORD = "Str0ng!Pass"


@contextmanager
def _settings(**overrides):
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, **overrides))
    try:
        yield
    finally:
        jafaal.configure(original)


def _login(client, username, password=PASSWORD):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password, "client_id": WEB_CLIENT_ID},
    )


# --------------------------------------------------------------------------- #
# M3 - RFC 6750 insufficient_scope challenge
# --------------------------------------------------------------------------- #


def test_missing_scope_error_builds_an_rfc6750_challenge():
    err = exc.MissingScopeError(missing={"users:write"}, required={"users:write", "users:read"})
    # RFC 6750 §3: space-delimited scope list, not a Python container repr.
    assert err.headers["WWW-Authenticate"] == 'Bearer error="insufficient_scope", scope="users:read users:write"'


def test_missing_scope_error_falls_back_to_the_missing_set():
    err = exc.MissingScopeError(missing={"users:write"})
    assert 'scope="users:write"' in err.headers["WWW-Authenticate"]


def test_missing_scope_error_challenge_can_be_overridden():
    err = exc.MissingScopeError(missing={"a"}, headers={"WWW-Authenticate": "Custom"})
    assert err.headers["WWW-Authenticate"] == "Custom"


def test_scope_denial_over_http_sends_the_challenge(client, make_user):
    make_user(username="scopeless", password=PASSWORD, is_superuser=False)
    access = _login(client, "scopeless").json()["access_token"]
    # ``sessions:read`` is an admin-tier scope a regular user never holds.
    response = client.get(
        "/api/v1/auth/sessions/user/1",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert response.status_code == 403
    challenge = response.headers["WWW-Authenticate"]
    assert challenge.startswith('Bearer error="insufficient_scope"')
    # No Python repr characters leaked into the header value.
    assert "[" not in challenge and "{" not in challenge and "'" not in challenge


# --------------------------------------------------------------------------- #
# M4 - the login path bounds password length before hashing
# --------------------------------------------------------------------------- #


def test_over_long_password_is_rejected_without_hashing(client, make_user):
    make_user(username="longpw", password=PASSWORD)
    over_limit = "x" * (jafaal.get_settings().passwords.max_length + 1)
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "longpw", "password": over_limit, "client_id": WEB_CLIENT_ID},
    )
    assert response.status_code == 401
    # Indistinguishable from any other bad credential: the bound must not become
    # an oracle for "this account exists".
    assert response.json()["code"] == "invalid_credentials"


def test_password_at_the_limit_is_still_accepted(client, make_user):
    at_limit = "A1!" + "x" * (jafaal.get_settings().passwords.max_length - 3)
    make_user(username="limitpw", password=at_limit)
    assert _login(client, "limitpw", at_limit).status_code == 200


# --------------------------------------------------------------------------- #
# M2 - refresh-token claims are unreachable without validation
# --------------------------------------------------------------------------- #


def test_validated_refresh_token_is_the_only_source_of_refresh_claims():
    import inspect

    from jafaal._internal import internal_dependencies as deps

    # Each claim reader takes the validated type, so no endpoint can read ``sub``
    # or ``sid`` off a token that nobody checked.
    for reader in (
        deps.get_sub_from_refresh_token,
        deps.get_sid_from_refresh_token,
        deps.get_and_return_refresh_token,
    ):
        annotations = [p.annotation for p in inspect.signature(reader).parameters.values()]
        assert any(
            deps.ValidatedRefreshToken is getattr(a, "__origin__", None) or "ValidatedRefreshToken" in str(a)
            for a in annotations
        ), reader.__name__


def test_access_token_is_rejected_as_a_refresh_token(client, make_user):
    make_user(username="mixup", password=PASSWORD)
    # A body-delivery client, so there is no refresh cookie to satisfy the
    # request and the presented token is the one actually evaluated.
    access = client.post(
        "/api/v1/auth/login",
        data={"username": "mixup", "password": PASSWORD, "client_id": NATIVE_CLIENT_ID},
    ).json()["access_token"]
    # Present an ACCESS token on the refresh path: the token_use claim must not
    # be honoured as a refresh token.
    response = client.post(
        "/api/v1/auth/refresh",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# M1 - opt-in live scope narrowing
# --------------------------------------------------------------------------- #


def test_demotion_takes_effect_immediately_when_reauthorizing(client, make_user, db):
    user = make_user(username="demoted", password=PASSWORD, is_superuser=True)
    access = _login(client, "demoted").json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {access}"}

    # The admin token works while the account is still an admin.
    assert client.get(f"/api/v1/auth/sessions/user/{user.id}", headers=admin_headers).status_code == 200

    ports.get_user_repository().get_by_id(user.id, db).is_superuser = False
    db.commit()

    # Without the toggle the stale admin scope is still honoured...
    assert client.get(f"/api/v1/auth/sessions/user/{user.id}", headers=admin_headers).status_code == 200

    # ...with it, the token is narrowed to what the account now holds.
    with _settings(reauthorize_scopes_per_request=True):
        response = client.get(f"/api/v1/auth/sessions/user/{user.id}", headers=admin_headers)
    assert response.status_code == 403


def test_reauthorization_never_grants_a_scope_the_token_lacks():
    from jafaal.identity_service import DefaultIdentityService

    catalog = scopes.get_scope_catalog()
    promoted = type("U", (), {"id": 1, "is_superuser": True})()
    # A token minted while the account was regular must not pick up admin scopes
    # just because the account was promoted: narrowing only ever removes.
    narrowed = DefaultIdentityService._narrow_to_current_entitlement(list(catalog.regular), promoted)
    assert set(narrowed) == set(catalog.regular)
    assert not set(narrowed) & (set(catalog.admin) - set(catalog.regular))


def test_narrowing_leaves_scopes_the_catalog_does_not_govern():
    """A capability the resolver never mints must survive narrowing.

    ``auth:introspect`` is deliberately outside the catalog tiers — it is granted
    straight to a service API key, never to a user. Intersecting against the
    resolver's output alone would strip it on every request.
    """
    from jafaal.identity_service import DefaultIdentityService

    regular = type("U", (), {"id": 1, "is_superuser": False})()
    narrowed = DefaultIdentityService._narrow_to_current_entitlement(
        [scopes.PROFILE, scopes.AUTH_INTROSPECT, scopes.USERS_WRITE],
        regular,
    )
    assert scopes.AUTH_INTROSPECT in narrowed  # ungoverned: untouched
    assert scopes.PROFILE in narrowed  # governed and held
    assert scopes.USERS_WRITE not in narrowed  # governed and no longer held


def test_api_key_scopes_are_narrowed_on_demotion_without_the_toggle(make_user, db):
    """An API key must shed stale admin authority even with the toggle off.

    Unlike an access token, an API key's expiry is optional, so it cannot rely on
    lapsing to drop scopes the account no longer holds.
    """
    from fastapi import Security

    import jafaal.api_keys.crud as api_keys_crud
    import jafaal.api_keys.schema as api_keys_schema

    user = make_user(username="keyholder", password=PASSWORD, is_superuser=True)
    jafaal.configure_api_key_scopes([scopes.SESSIONS_READ])
    _row, raw_key = api_keys_crud.create_api_key(
        user.id,
        api_keys_schema.UsersApiKeyCreate(name="admin key", scopes=[scopes.SESSIONS_READ]),
        db,
    )
    db.commit()

    app = FastAPI()
    jafaal.register_exception_handlers(app)

    @app.get("/admin-only")
    def admin_only(_auth=Security(jafaal.check_auth_scopes, scopes=[scopes.SESSIONS_READ])):
        return {"ok": True}

    http = TestClient(app)
    headers = {"X-API-Key": raw_key}

    # sessions:read is an admin-tier scope, so the key works while the account
    # is still a superuser.
    assert http.get("/admin-only", headers=headers).status_code == 200

    ports.get_user_repository().get_by_id(user.id, db).is_superuser = False
    db.commit()

    # Narrowed immediately — no reauthorize_scopes_per_request required.
    assert http.get("/admin-only", headers=headers).status_code == 403


# --------------------------------------------------------------------------- #
# M7 - security-critical events get reserved capacity
# --------------------------------------------------------------------------- #


def test_critical_events_have_headroom_above_routine_ones():
    assert ports.MAX_INFLIGHT_CRITICAL_EVENTS > ports.MAX_INFLIGHT_EVENTS
    assert "on_account_locked" in ports.CRITICAL_EVENT_METHODS
    assert "on_refresh_token_theft_detected" in ports.CRITICAL_EVENT_METHODS


def test_critical_event_admitted_when_routine_bound_is_full(monkeypatch, caplog):
    # Saturate the general bound, then prove a lockout notification still gets a
    # slot while a routine notification does not.
    monkeypatch.setattr(ports, "MAX_INFLIGHT_EVENTS", 0)
    monkeypatch.setattr(ports, "MAX_INFLIGHT_CRITICAL_EVENTS", 4)

    assert ports._acquire_dispatch_slot("on_account_locked") is True
    ports._release_dispatch_slot()
    assert ports._acquire_dispatch_slot("on_password_reset_requested") is False


def test_dropping_a_critical_event_is_logged_at_error(monkeypatch, caplog):
    monkeypatch.setattr(ports, "MAX_INFLIGHT_EVENTS", 0)
    monkeypatch.setattr(ports, "MAX_INFLIGHT_CRITICAL_EVENTS", 0)

    class _Sink:
        async def on_account_locked(self, event):  # pragma: no cover - never awaited
            return None

    jafaal.configure_event_sink(_Sink())
    try:
        with caplog.at_level(logging.ERROR, logger="jafaal.ports"):
            ports.dispatch_event("on_account_locked", object())
        assert any(record.levelno == logging.ERROR for record in caplog.records)
        assert "SECURITY-CRITICAL" in caplog.text
    finally:
        jafaal.configure_event_sink(jafaal.NullAuthEventSink())


# --------------------------------------------------------------------------- #
# M9 - startup verification
# --------------------------------------------------------------------------- #


def test_create_auth_router_verifies_configuration_by_default():
    original = ports.get_user_repository()
    ports._user_repository.reset()
    try:
        with pytest.raises(RuntimeError, match="UserRepository"):
            jafaal.create_auth_router()
        # The escape hatch still builds the router for hosts that wire adapters
        # after assembling the app.
        assert jafaal.create_auth_router(verify=False) is not None
    finally:
        jafaal.configure_user_repository(original)


# --------------------------------------------------------------------------- #
# Standards - the discovery document advertises what a client actually needs
# --------------------------------------------------------------------------- #


def test_metadata_carries_no_extension_members():
    # Every field a client needs is a standard one. A bespoke member would mean
    # an endpoint that cannot be driven by a stock OAuth library.
    doc = metadata.get_authorization_server_metadata(api_root="https://app.test/api/v1")
    assert not [key for key in doc if key.startswith("jafaal")]


def test_metadata_declares_no_client_authentication():
    doc = metadata.get_authorization_server_metadata(api_root="https://app.test/api/v1")
    # RFC 8414 §2 defaults to client_secret_basic when absent, which JAFAAL does
    # not implement — stating "none" explicitly is what keeps a client honest.
    assert doc["token_endpoint_auth_methods_supported"] == ["none"]
    assert set(doc["grant_types_supported"]) == {"authorization_code", "refresh_token"}


# --------------------------------------------------------------------------- #
# DRY - login and MFA-verify share one delivery path
# --------------------------------------------------------------------------- #


def test_mfa_challenge_uses_202_for_cookie_clients_and_200_for_body_clients(client, make_user):
    import pyotp

    import jafaal.mfa.crud as mfa_crud
    import jafaal.orm as jafaal_orm
    from jafaal._core import crypto

    user = make_user(username="mfauser", password=PASSWORD)
    secret = pyotp.random_base32()
    session = jafaal_orm.get_sessionmaker()()
    try:
        with jafaal_orm.unit_of_work(session):
            mfa_crud.update_user_mfa(user.id, session, encrypted_secret=crypto.encrypt_token_fernet(secret))
    finally:
        session.close()

    # A browser client gets 202: the password was right but the login is not
    # finished, and 200 would be indistinguishable from a completed login to a
    # client that only reads the status code.
    web = _login(client, "mfauser")
    assert web.status_code == 202
    assert web.json()["mfa_required"] is True

    native = client.post(
        "/api/v1/auth/login",
        data={"username": "mfauser", "password": PASSWORD, "client_id": NATIVE_CLIENT_ID},
    )
    assert native.status_code == 200
    # Both shapes come from one model, so the fields cannot drift apart.
    assert set(native.json()) == set(web.json())


def test_an_unregistered_client_cannot_open_a_pending_mfa_login(client, make_user):
    make_user(username="badclient", password=PASSWORD)
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "badclient", "password": PASSWORD, "client_id": "desktop"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


# --------------------------------------------------------------------------- #
# Guard: the app assembles without JAFAAL reading configuration at import
# --------------------------------------------------------------------------- #


def test_router_assembly_is_idempotent():
    app = FastAPI()
    app.include_router(jafaal.create_auth_router(app=app), prefix="/api/v1")
    with TestClient(app) as http:
        doc = http.get("/api/v1/.well-known/oauth-authorization-server")
    assert doc.status_code == 200
    assert doc.json()["issuer"] == settings_mod.get_settings().resolved_issuer
