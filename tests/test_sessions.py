"""Tests for session utilities, session CRUD, refresh-token rotation, and OAuth state."""

import dataclasses
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from starlette.requests import Request

import jafaal
import jafaal.exceptions as exc
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.utils as oauth_state_utils
import jafaal.sessions.crud as sessions_crud
import jafaal.sessions.rotated_refresh_tokens.crud as rotated_crud
import jafaal.sessions.rotated_refresh_tokens.schema as rotated_schema
import jafaal.sessions.rotated_refresh_tokens.utils as rotated_utils
import jafaal.sessions.utils as session_utils
from jafaal._core import crypto
from jafaal._internal.password_hasher import password_hasher
from jafaal._internal.token_manager import TokenType, get_token_manager
from jafaal.identity_service import DefaultIdentityService


@contextmanager
def _settings(**overrides):
    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, **overrides))
    try:
        yield
    finally:
        jafaal.configure(original)


def _request(host="203.0.113.1", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [(b"user-agent", ua.encode())],
        "client": (host, 4321),
        "scheme": "http",
        "server": ("t", 80),
    }
    return Request(scope)


# --------------------------------------------------------------------------- #
# CSRF + timeout + user-agent parsing
# --------------------------------------------------------------------------- #


def test_verify_csrf_token_constant_time_match():
    token = "csrf-token-abc"
    stored = session_utils._hash_csrf_token(token)
    assert session_utils.verify_csrf_token(token, stored) is True
    assert session_utils.verify_csrf_token("wrong", stored) is False


def test_validate_session_timeout_noop_when_disabled():
    old = SimpleNamespace(
        last_activity_at=datetime.now(UTC) - timedelta(days=10),
        created_at=datetime.now(UTC) - timedelta(days=10),
    )
    session_utils.validate_session_timeout(old)  # disabled by default → no raise


def test_validate_session_timeout_idle_expiry():
    with _settings(session_idle_timeout_enabled=True, session_idle_timeout_hours=1):
        idle = SimpleNamespace(
            last_activity_at=datetime.now(UTC) - timedelta(hours=2),
            created_at=datetime.now(UTC) - timedelta(minutes=10),
        )
        with pytest.raises(exc.SessionExpiredError):
            session_utils.validate_session_timeout(idle)


def test_validate_session_timeout_absolute_expiry():
    with _settings(
        session_idle_timeout_enabled=True,
        session_idle_timeout_hours=100,
        session_absolute_timeout_hours=1,
    ):
        aged = SimpleNamespace(
            last_activity_at=datetime.now(UTC),
            created_at=datetime.now(UTC) - timedelta(hours=2),
        )
        with pytest.raises(exc.SessionExpiredError):
            session_utils.validate_session_timeout(aged)


def test_parse_user_agent():
    iphone_ua = (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
    )
    mobile = session_utils.parse_user_agent(iphone_ua)
    assert mobile.device_type == session_utils.DeviceType.MOBILE
    # An empty UA is not mobile/tablet → classified as PC.
    unknown = session_utils.parse_user_agent("")
    assert unknown.device_type == session_utils.DeviceType.PC


# --------------------------------------------------------------------------- #
# Strict session binding (access-token revocation)
# --------------------------------------------------------------------------- #


def _svc(db):
    return DefaultIdentityService(db, get_token_manager(), password_hasher)


def _access_token(user, sid):
    _, token = get_token_manager().create_token(sid, user, TokenType.ACCESS)
    return token


def test_access_token_resolves_without_session_when_binding_off(db, make_user):
    # Default (binding off): access tokens are validated statelessly, so a token
    # resolves even when its session no longer exists (e.g. after logout).
    user = make_user()
    token = _access_token(user, "sess-gone")
    assert _svc(db).resolve_from_access_token(token).user_id == user.id


def test_strict_binding_rejects_revoked_session(db, make_user):
    # With strict binding on, revoking the session (logout / single-session
    # revocation) makes the outstanding access token fail immediately.
    user = make_user()
    session_utils.create_session("sess-b", user, _request(), "rt", password_hasher, db)
    token = _access_token(user, "sess-b")
    with _settings(strict_session_binding=True):
        # Valid while the session exists...
        assert _svc(db).resolve_from_access_token(token).user_id == user.id
        # ...and rejected the moment the session is revoked.
        sessions_crud.delete_session("sess-b", user.id, db)
        with pytest.raises(exc.SessionExpiredError):
            _svc(db).resolve_from_access_token(token)


def test_strict_binding_rejects_missing_session(db, make_user):
    user = make_user()
    token = _access_token(user, "never-created")
    with _settings(strict_session_binding=True), pytest.raises(exc.SessionExpiredError):
        _svc(db).resolve_from_access_token(token)


def test_strict_binding_rejects_session_owned_by_other_user(db, make_user):
    owner = make_user(username="owner")
    other = make_user(username="other")
    # The session belongs to `other`, but the token claims `owner` with that sid.
    session_utils.create_session("sess-x", other, _request(), "rt", password_hasher, db)
    token = _access_token(owner, "sess-x")
    with _settings(strict_session_binding=True), pytest.raises(exc.InvalidTokenError):
        _svc(db).resolve_from_access_token(token)


def test_strict_binding_enforces_session_timeout(db, make_user):
    # An idle-timed-out session rejects the access token under strict binding.
    user = make_user()
    session_utils.create_session("sess-idle", user, _request(), "rt", password_hasher, db)
    token = _access_token(user, "sess-idle")
    row = sessions_crud.get_session_by_id("sess-idle", db)
    row.last_activity_at = datetime.now(UTC) - timedelta(hours=2)
    db.commit()
    with (
        _settings(
            strict_session_binding=True,
            session_idle_timeout_enabled=True,
            session_idle_timeout_hours=1,
        ),
        pytest.raises(exc.SessionExpiredError),
    ):
        _svc(db).resolve_from_access_token(token)


# --------------------------------------------------------------------------- #
# Session CRUD
# --------------------------------------------------------------------------- #


def test_session_create_get_delete(db, make_user):
    user = make_user()
    session_utils.create_session("sess-1", user, _request(), "refresh-value", password_hasher, db)

    row = sessions_crud.get_session_by_id("sess-1", db)
    assert row is not None
    assert row.user_id == user.id
    assert row.token_family_id == "sess-1"

    sessions_crud.delete_session("sess-1", user.id, db)
    assert sessions_crud.get_session_by_id("sess-1", db) is None


def test_get_user_sessions(db, make_user):
    user = make_user()
    session_utils.create_session("s-a", user, _request(), "rt-a", password_hasher, db)
    session_utils.create_session("s-b", user, _request(), "rt-b", password_hasher, db)
    sessions = sessions_crud.get_user_sessions(user.id, db)
    assert {s.id for s in sessions} == {"s-a", "s-b"}


def test_delete_sessions_by_user_with_exclude(db, make_user):
    user = make_user()
    session_utils.create_session("keep", user, _request(), "rt-keep", password_hasher, db)
    session_utils.create_session("drop", user, _request(), "rt-drop", password_hasher, db)
    sessions_crud.delete_sessions_by_user(user.id, db, exclude_session_id="keep")
    remaining = {s.id for s in sessions_crud.get_user_sessions(user.id, db)}
    assert remaining == {"keep"}


# --------------------------------------------------------------------------- #
# Refresh-token rotation / reuse detection
# --------------------------------------------------------------------------- #


def test_rotated_token_store_and_lookup(db, make_user):
    user = make_user()
    session_utils.create_session("fam-1", user, _request(), "initial-rt", password_hasher, db)
    exp = datetime.now(UTC) + timedelta(days=7)
    rotated_utils.store_rotated_token(
        "old-token",
        "fam-1",
        0,
        db,
        replacement_refresh_token="new-token",
        replacement_refresh_token_exp=exp,
    )

    # An unseen token is not reused (early return, no datetime comparison).
    assert rotated_utils.check_token_reuse("never-seen", db) == (False, False)

    # The rotated record is retrievable by its HMAC-SHA256 lookup hash.
    row = rotated_crud.get_rotated_token_by_hash(rotated_utils.hmac_hash_token("old-token"), db)
    assert row is not None
    assert row.token_family_id == "fam-1"
    assert row.rotation_count == 0


def test_invalidate_token_family_deletes_sessions(db, make_user):
    user = make_user()
    session_utils.create_session("fam-x", user, _request(), "rt", password_hasher, db)
    deleted = rotated_utils.invalidate_token_family("fam-x", db)
    assert deleted >= 1
    assert sessions_crud.get_session_by_id("fam-x", db) is None


def test_rotated_token_in_grace_replay(db, make_user):
    user = make_user()
    session_utils.create_session("fam-g", user, _request(), "initial-rt", password_hasher, db)
    exp = datetime.now(UTC) + timedelta(days=7)
    rotated_utils.store_rotated_token(
        "old-token",
        "fam-g",
        0,
        db,
        replacement_refresh_token="new-token",
        replacement_refresh_token_exp=exp,
    )

    # Reused, still inside the 60s grace window.
    assert rotated_utils.check_token_reuse("old-token", db) == (True, True)

    # Replay returns the stored replacement and a tz-aware expiry.
    replay = rotated_utils.get_grace_replay_token("old-token", db)
    assert replay is not None
    replacement, replacement_exp = replay
    assert replacement == "new-token"
    assert replacement_exp.tzinfo is not None  # normalized to UTC-aware


def test_rotated_token_reuse_after_grace_is_theft(db, make_user):
    user = make_user()
    session_utils.create_session("fam-t", user, _request(), "rt", password_hasher, db)
    past = datetime.now(UTC) - timedelta(seconds=120)
    rotated_crud.create_rotated_token(
        rotated_schema.RotatedRefreshTokenCreate(
            token_family_id="fam-t",
            hashed_token=rotated_utils.hmac_hash_token("stolen-token"),
            rotation_count=0,
            rotated_at=past,
            expires_at=past,
            replacement_refresh_token=crypto.encrypt_token_fernet("replacement"),
            replacement_refresh_token_exp=past,
        ),
        db,
    )

    # Reuse past the grace window is flagged as theft (reused, not in grace).
    assert rotated_utils.check_token_reuse("stolen-token", db) == (True, False)
    # No replay past grace.
    assert rotated_utils.get_grace_replay_token("stolen-token", db) is None


def test_validate_session_timeout_on_real_db_row(db, make_user):
    # A freshly created session stores naive datetimes on SQLite; the timeout
    # check must remain tz-safe and not raise for a live session.
    with _settings(session_idle_timeout_enabled=True, session_idle_timeout_hours=1):
        user = make_user()
        session_utils.create_session("s-live", user, _request(), "rt", password_hasher, db)
        row = sessions_crud.get_session_by_id("s-live", db)
        session_utils.validate_session_timeout(row)  # must not raise


# --------------------------------------------------------------------------- #
# OAuth state (PKCE / nonce)
# --------------------------------------------------------------------------- #


def test_oauth_state_create_and_lookup(db):
    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()
    assert state_id != nonce
    oauth_state_crud.create_oauth_state(
        db=db,
        state_id=state_id,
        nonce=nonce,
        client_type="web",
        ip_address="1.2.3.4",
    )
    row = oauth_state_crud.get_oauth_state_by_id_and_not_used(state_id, db)
    assert row is not None
    assert row.nonce == nonce
    # Unknown id → None.
    assert oauth_state_crud.get_oauth_state_by_id_and_not_used("does-not-exist", db) is None
