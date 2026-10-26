"""Runtime auth policy read through the ``SettingsProvider`` port.

Token lifetimes, session timeouts and the allowed login methods are read per
call, so a host can change them without ``jafaal.configure()``. Covers the
resolvers (fallback, clamping, fail-closed), the places that consume them, and
the ``LoginMethods`` enforcement on each route.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from types import SimpleNamespace

import pytest
from conftest import NATIVE_CLIENT_ID, StaticSettingsProvider, replace_settings
from fastapi import Response

import jafaal
import jafaal.exceptions as exc
import jafaal.ports as ports
import jafaal.sessions.utils as session_utils
import jafaal.utils as jafaal_utils
from jafaal._internal import token_denylist
from jafaal._internal.services import token_admin_service
from jafaal._internal.token_manager import TokenManager, TokenType, get_token_manager
from jafaal.adapters import StaticSettingsProvider as AdapterStaticSettingsProvider


class RuntimeProvider(StaticSettingsProvider):
    """The test provider plus mutable runtime policy."""

    def __init__(self, **kwargs):
        super().__init__()
        self.lifetimes = kwargs.get("lifetimes", ports.TokenLifetimes(15, 7))
        self.sessions = kwargs.get("sessions", ports.SessionPolicy(False, 1, 720))
        self.methods = kwargs.get("methods", ports.LoginMethods())

    def get_token_lifetimes(self):
        return self.lifetimes

    def get_session_policy(self):
        return self.sessions

    def get_login_methods(self):
        return self.methods


@pytest.fixture
def install():
    """Install a provider for one test; the suite's static provider is restored after."""

    def _install(provider):
        jafaal.configure_settings_provider(provider)
        return provider

    yield _install
    jafaal.configure_settings_provider(StaticSettingsProvider())


@pytest.fixture
def settings_override():
    original = jafaal.get_settings()

    def _apply(**overrides):
        jafaal.configure(replace_settings(original, **overrides))

    yield _apply
    jafaal.configure(original)


def _user():
    return SimpleNamespace(id=1, username="alice", is_superuser=False)


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "3"])
def test_lifetimes_and_policy_reject_non_positive_integers(bad):
    with pytest.raises(ValueError, match="positive integer"):
        ports.TokenLifetimes(bad, 7)
    with pytest.raises(ValueError, match="positive integer"):
        ports.TokenLifetimes(15, bad)
    with pytest.raises(ValueError, match="positive integer"):
        ports.SessionPolicy(True, bad, 720)
    with pytest.raises(ValueError, match="positive integer"):
        ports.SessionPolicy(True, 1, bad)


def test_login_methods_default_to_everything_enabled():
    assert ports.LoginMethods() == ports.LoginMethods(password=True, identity_providers=True, passkeys=True)


def test_ceilings_may_not_undercut_the_deployment_defaults():
    with pytest.raises(ValueError, match="max_access_token_minutes"):
        jafaal.TokenSettings(access_token_expire_minutes=15, max_access_token_minutes=5)
    with pytest.raises(ValueError, match="max_refresh_token_days"):
        jafaal.TokenSettings(refresh_token_expire_days=7, max_refresh_token_days=1)
    with pytest.raises(ValueError, match="max_absolute_timeout_hours"):
        jafaal.SessionSettings(absolute_timeout_hours=720, max_absolute_timeout_hours=24)


# --------------------------------------------------------------------------- #
# Resolvers: fallback
# --------------------------------------------------------------------------- #


def test_a_provider_with_only_the_original_methods_behaves_as_before():
    settings = jafaal.get_settings()
    assert ports.resolve_token_lifetimes() == ports.TokenLifetimes(
        settings.tokens.access_token_expire_minutes, settings.tokens.refresh_token_expire_days
    )
    assert ports.resolve_session_policy() == ports.SessionPolicy(
        settings.sessions.idle_timeout_enabled,
        settings.sessions.idle_timeout_hours,
        settings.sessions.absolute_timeout_hours,
    )
    assert ports.resolve_login_methods() == ports.LoginMethods()


def test_with_no_provider_the_resolvers_fall_back_to_auth_settings():
    provider = ports.get_settings_provider()
    ports._settings_provider.reset()
    try:
        assert ports.resolve_token_lifetimes() == ports.TokenLifetimes(15, 7)
        assert ports.resolve_login_methods() == ports.LoginMethods()
    finally:
        jafaal.configure_settings_provider(provider)


def test_the_static_adapter_defers_to_auth_settings_until_overridden(install):
    install(AdapterStaticSettingsProvider())
    assert ports.resolve_token_lifetimes() == ports.TokenLifetimes(15, 7)
    assert ports.resolve_session_policy() == ports.SessionPolicy(False, 1, 720)
    assert ports.resolve_login_methods() == ports.LoginMethods()

    install(
        AdapterStaticSettingsProvider(
            token_lifetimes=ports.TokenLifetimes(5, 2),
            session_policy=ports.SessionPolicy(True, 3, 48),
            login_methods=ports.LoginMethods(password=False),
        )
    )
    assert ports.resolve_token_lifetimes() == ports.TokenLifetimes(5, 2)
    assert ports.resolve_session_policy() == ports.SessionPolicy(True, 3, 48)
    assert ports.resolve_login_methods().password is False


# --------------------------------------------------------------------------- #
# Resolvers: ceilings
# --------------------------------------------------------------------------- #


def test_provider_values_are_clamped_to_the_ceilings_with_a_warning(install, settings_override, caplog):
    settings_override(max_access_token_minutes=30, max_refresh_token_days=14, max_absolute_timeout_hours=800)
    install(RuntimeProvider(lifetimes=ports.TokenLifetimes(600, 90), sessions=ports.SessionPolicy(True, 2, 5000)))

    with caplog.at_level(logging.WARNING, logger="jafaal.ports"):
        assert ports.resolve_token_lifetimes() == ports.TokenLifetimes(30, 14)
        assert ports.resolve_session_policy() == ports.SessionPolicy(True, 2, 800)

    codes = {getattr(r, "warning_code", None) for r in caplog.records}
    assert {"token_lifetime_clamped", "session_timeout_clamped"} <= codes


def test_values_within_the_ceilings_are_untouched_and_silent(install, settings_override, caplog):
    settings_override(max_access_token_minutes=30)
    install(RuntimeProvider(lifetimes=ports.TokenLifetimes(20, 3)))
    with caplog.at_level(logging.WARNING, logger="jafaal.ports"):
        assert ports.resolve_token_lifetimes() == ports.TokenLifetimes(20, 3)
    assert not caplog.records


def test_without_ceilings_provider_values_pass_through(install):
    install(RuntimeProvider(lifetimes=ports.TokenLifetimes(100000, 3650)))
    assert ports.resolve_token_lifetimes() == ports.TokenLifetimes(100000, 3650)


# --------------------------------------------------------------------------- #
# Resolvers: fail closed
# --------------------------------------------------------------------------- #


class _Broken(RuntimeProvider):
    def get_token_lifetimes(self):
        raise ConnectionError("settings store down")

    def get_session_policy(self):
        raise ConnectionError("settings store down")

    def get_login_methods(self):
        raise ConnectionError("settings store down")


class _WrongType(RuntimeProvider):
    def get_login_methods(self):
        return {"password": False}


@pytest.mark.parametrize(
    "resolver", [ports.resolve_token_lifetimes, ports.resolve_session_policy, ports.resolve_login_methods]
)
def test_a_raising_provider_is_never_replaced_by_defaults(install, resolver):
    install(_Broken())
    with pytest.raises(exc.SettingsUnavailableError) as info:
        resolver()
    assert info.value.status_code == 503
    assert isinstance(info.value.__cause__, ConnectionError)


def test_a_provider_building_an_invalid_value_is_an_error_not_a_default(install):
    class _Invalid(RuntimeProvider):
        def get_token_lifetimes(self):
            return ports.TokenLifetimes(0, 7)

    install(_Invalid())
    with pytest.raises(exc.SettingsUnavailableError):
        ports.resolve_token_lifetimes()


def test_a_provider_returning_the_wrong_type_is_an_error(install):
    install(_WrongType())
    with pytest.raises(exc.SettingsUnavailableError):
        ports.resolve_login_methods()


def test_a_broken_provider_yields_503_at_the_edge_and_no_login(install, make_user, client):
    make_user(username="alice", password="Str0ng!Pass")
    install(_Broken())
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "Str0ng!Pass", "client_id": NATIVE_CLIENT_ID},
    )
    assert response.status_code == 503
    assert response.json()["code"] == "settings_unavailable"


# --------------------------------------------------------------------------- #
# Read at use time
# --------------------------------------------------------------------------- #


def _lifetime(issued: tuple[datetime, str], now: datetime) -> timedelta:
    return issued[0] - now


def test_new_tokens_follow_the_provider_without_reconfiguring(install):
    provider = install(RuntimeProvider(lifetimes=ports.TokenLifetimes(10, 3)))
    manager = get_token_manager()

    before = datetime.now(UTC)
    access, _ = manager.create_token("s1", _user(), TokenType.ACCESS)
    refresh, _ = manager.create_token("s1", _user(), TokenType.REFRESH)
    assert timedelta(minutes=9, seconds=50) < access - before <= timedelta(minutes=10, seconds=5)
    assert timedelta(days=2, hours=23) < refresh - before <= timedelta(days=3, seconds=5)

    provider.lifetimes = ports.TokenLifetimes(2, 1)
    before = datetime.now(UTC)
    access, _ = manager.create_token("s1", _user(), TokenType.ACCESS)
    refresh, _ = manager.create_token("s1", _user(), TokenType.REFRESH)
    assert access - before <= timedelta(minutes=2, seconds=5)
    assert refresh - before <= timedelta(days=1, seconds=5)


def test_a_directly_built_token_manager_keeps_its_constructor_lifetimes(install):
    install(RuntimeProvider(lifetimes=ports.TokenLifetimes(1, 1)))
    manager = TokenManager("k" * 32, "HS256", access_token_expire_minutes=40, refresh_token_expire_days=5)
    before = datetime.now(UTC)
    exp, _ = manager.create_token("s1", _user(), TokenType.ACCESS)
    assert exp - before > timedelta(minutes=39)


def test_the_refresh_cookie_follows_the_provider(install):
    provider = install(RuntimeProvider(lifetimes=ports.TokenLifetimes(10, 3)))

    def cookie_days() -> float:
        response = Response()
        jafaal_utils.set_refresh_token_cookie(response, "tok")
        header = next(v for k, v in response.raw_headers if k == b"set-cookie" and b"=tok;" in v).decode()
        expires = (
            header.split("expires=")[1].split(";")[0]
            if "expires=" in header
            else header.split("Expires=")[1].split(";")[0]
        )
        return (parsedate_to_datetime(expires) - datetime.now(UTC)).total_seconds() / 86400

    assert 2.9 < cookie_days() <= 3.0
    provider.lifetimes = ports.TokenLifetimes(10, 1)
    assert 0.9 < cookie_days() <= 1.0


def test_session_expiry_for_a_rotation_uses_the_current_refresh_lifetime(install):
    provider = install(RuntimeProvider(lifetimes=ports.TokenLifetimes(10, 3)))
    now = datetime.now(UTC)
    assert session_utils.session_expires_at(now, now) == now + timedelta(days=3)
    provider.lifetimes = ports.TokenLifetimes(10, 1)
    assert session_utils.session_expires_at(now, now) == now + timedelta(days=1)


def _row(created_at, last_activity_at):
    return SimpleNamespace(id="s", user_id=1, created_at=created_at, last_activity_at=last_activity_at)


def test_an_existing_session_honours_a_reduced_absolute_timeout(install):
    provider = install(RuntimeProvider(sessions=ports.SessionPolicy(False, 1, 720)))
    created = datetime.now(UTC) - timedelta(hours=30)
    row = _row(created, datetime.now(UTC))
    session_utils.validate_session_timeout(row)

    provider.sessions = ports.SessionPolicy(False, 1, 24)
    with pytest.raises(exc.SessionExpiredError):
        session_utils.validate_session_timeout(row)


def test_an_existing_session_honours_a_reduced_idle_timeout(install):
    provider = install(RuntimeProvider(sessions=ports.SessionPolicy(True, 5, 720)))
    now = datetime.now(UTC)
    row = _row(now - timedelta(hours=2), now - timedelta(hours=2))
    session_utils.validate_session_timeout(row)

    provider.sessions = ports.SessionPolicy(True, 1, 720)
    with pytest.raises(exc.SessionExpiredError, match="inactivity"):
        session_utils.validate_session_timeout(row)

    provider.sessions = ports.SessionPolicy(False, 1, 720)  # idle check switched off at runtime
    session_utils.validate_session_timeout(row)


def test_the_idle_sweep_follows_the_provider_and_skips_when_it_is_unavailable(install, monkeypatch, caplog):
    import jafaal.sessions.crud as sessions_crud

    seen = []

    def spy(cutoff, session):
        seen.append(cutoff)
        return 0

    monkeypatch.setattr(sessions_crud, "delete_idle_sessions", spy)
    provider = install(RuntimeProvider(sessions=ports.SessionPolicy(False, 1, 720)))
    session_utils.cleanup_idle_sessions()
    assert seen == []

    provider.sessions = ports.SessionPolicy(True, 4, 720)
    session_utils.cleanup_idle_sessions()
    assert len(seen) == 1
    assert timedelta(hours=3, minutes=59) < datetime.now(UTC) - seen[0] < timedelta(hours=4, minutes=1)

    install(_Broken())
    with caplog.at_level(logging.ERROR):
        session_utils.cleanup_idle_sessions()
    assert len(seen) == 1


# --------------------------------------------------------------------------- #
# Denylist TTL
# --------------------------------------------------------------------------- #


def test_the_session_denylist_outlives_tokens_issued_before_a_shortening(install, settings_override):
    settings_override(max_access_token_minutes=60)
    provider = install(RuntimeProvider(lifetimes=ports.TokenLifetimes(45, 7)))
    # Tokens were issued at 45 minutes; the operator then cut it to 5.
    provider.lifetimes = ports.TokenLifetimes(5, 7)
    ttl = token_admin_service._session_denylist_ttl()
    assert ttl >= 60 * 60  # the configured ceiling, not the new 5-minute lifetime


def test_the_session_denylist_never_undercuts_the_deployment_default(install):
    install(RuntimeProvider(lifetimes=ports.TokenLifetimes(1, 7)))
    assert token_admin_service._session_denylist_ttl() >= 15 * 60


def test_revoking_a_refresh_token_denies_the_session_for_the_safe_ttl(
    install, settings_override, make_user, client, monkeypatch
):
    settings_override(denylist_enabled=True, max_access_token_minutes=60)
    provider = install(RuntimeProvider(lifetimes=ports.TokenLifetimes(45, 7)))
    make_user(username="alice", password="Str0ng!Pass")
    body = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "Str0ng!Pass", "client_id": NATIVE_CLIENT_ID},
    ).json()
    provider.lifetimes = ports.TokenLifetimes(5, 7)

    denied = []
    monkeypatch.setattr(token_denylist, "deny_session", lambda sid, ttl: denied.append(ttl))
    response = client.post(
        "/api/v1/auth/revoke",
        data={"token": body["refresh_token"], "client_id": NATIVE_CLIENT_ID},
    )
    assert response.status_code == 200, response.text
    assert denied
    assert denied[0] >= 60 * 60


def test_an_access_token_denylist_entry_uses_the_tokens_own_exp(install, settings_override, monkeypatch):
    settings_override(denylist_enabled=True)
    provider = install(RuntimeProvider(lifetimes=ports.TokenLifetimes(45, 7)))
    exp, token = get_token_manager().create_token("s1", _user(), TokenType.ACCESS)
    provider.lifetimes = ports.TokenLifetimes(1, 7)  # shortened after issue

    denied = []
    monkeypatch.setattr(token_denylist, "deny_access_token", lambda jti, ttl: denied.append(ttl))
    claims = get_token_manager().decode_token(token).claims
    token_admin_service._revoke_access_token(claims)

    remaining = (exp - datetime.now(UTC)).total_seconds()
    assert denied
    assert remaining - 5 <= denied[0] <= remaining + 90  # the token's own exp + buffer, not 1 minute


# --------------------------------------------------------------------------- #
# LoginMethods enforcement
# --------------------------------------------------------------------------- #


def _login(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password, "client_id": NATIVE_CLIENT_ID},
    )


def test_disabling_passwords_refuses_login_before_any_credential_check(install, make_user, client):
    make_user(username="alice", password="Str0ng!Pass")
    install(RuntimeProvider(methods=ports.LoginMethods(password=False)))

    right = _login(client)
    wrong = _login(client, password="not-the-password")
    unknown = _login(client, username="nobody")
    for response in (right, wrong, unknown):
        assert response.status_code == 403
        assert response.json()["code"] == "login_method_disabled"
    # Identical for a real and an unknown account: nothing about the account leaks.
    assert right.json() == wrong.json() == unknown.json()


def test_the_password_flag_does_not_count_failed_attempts(install, make_user, client):
    make_user(username="alice", password="Str0ng!Pass")
    provider = install(RuntimeProvider(methods=ports.LoginMethods(password=False)))
    for _ in range(12):
        assert _login(client, password="wrong").status_code == 403
    provider.methods = ports.LoginMethods()
    assert _login(client).status_code == 200  # no lockout accrued while it was refused


def test_a_login_method_enabled_again_at_runtime_works_immediately(install, make_user, client):
    make_user(username="alice", password="Str0ng!Pass")
    provider = install(RuntimeProvider(methods=ports.LoginMethods(password=False)))
    assert _login(client).status_code == 403
    provider.methods = ports.LoginMethods()
    assert _login(client).status_code == 200


def test_disabling_identity_providers_does_not_block_password_login(install, make_user, client):
    make_user(username="alice", password="Str0ng!Pass")
    install(RuntimeProvider(methods=ports.LoginMethods(identity_providers=False, passkeys=False)))
    assert _login(client).status_code == 200


def test_disabling_identity_providers_empties_the_public_list(install, client):
    import jafaal.identity_providers.crud as idp_crud
    import jafaal.identity_providers.schema as idp_schema
    import jafaal.orm as jafaal_orm

    session = jafaal_orm.get_sessionmaker()()
    try:
        with jafaal_orm.unit_of_work(session):
            idp_crud.create_identity_provider(
                idp_schema.IdentityProviderCreate(
                    name="IdP", slug="oidc", client_id="cid", client_secret="secret", enabled=True
                ),
                session,
            )
    finally:
        session.close()

    assert [p["slug"] for p in client.get("/api/v1/public/idp").json()] == ["oidc"]
    install(RuntimeProvider(methods=ports.LoginMethods(identity_providers=False)))
    assert client.get("/api/v1/public/idp").json() == []


def test_disabling_passkeys_refuses_passwordless_authentication_only(install, make_user, client):
    make_user(username="alice", password="Str0ng!Pass")
    install(RuntimeProvider(methods=ports.LoginMethods(passkeys=False)))

    begin = client.post("/api/v1/public/webauthn/authenticate/begin", json={"username": "alice"})
    assert begin.status_code == 403
    assert begin.json()["code"] == "login_method_disabled"
    complete = client.post(
        "/api/v1/public/webauthn/authenticate/complete",
        json={"challenge_id": "x", "credential": {}, "client_id": NATIVE_CLIENT_ID},
    )
    assert complete.status_code == 403
    assert complete.json()["code"] == "login_method_disabled"

    # Password login and credential management are untouched.
    token = _login(client).json()["access_token"]
    listing = client.get("/api/v1/auth/webauthn/credentials", headers={"Authorization": f"Bearer {token}"})
    assert listing.status_code == 200


def test_passkeys_enabled_does_not_raise_the_policy_error(install, client):
    install(RuntimeProvider(methods=ports.LoginMethods(password=False)))
    response = client.post("/api/v1/public/webauthn/authenticate/begin", json={"username": "alice"})
    assert response.json().get("code") != "login_method_disabled"
