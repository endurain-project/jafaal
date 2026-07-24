"""Tests for the account-security service (password change, session revocation)."""

import dataclasses
from contextlib import contextmanager

import pytest
from starlette.requests import Request

import jafaal
import jafaal._internal.services.account_security_service as account_svc
import jafaal.exceptions as exc
import jafaal.sessions.crud as sessions_crud
import jafaal.sessions.utils as session_utils
from jafaal._internal.password_hasher import get_password_hasher
from jafaal._internal.security_stores import StepUpAttempts
from jafaal._internal.token_manager import get_token_manager
from jafaal.identity_service import DefaultIdentityService


def _svc(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _request():
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [(b"user-agent", b"Mozilla/5.0")],
        "client": ("1.2.3.4", 1),
        "scheme": "http",
        "server": ("t", 80),
    }
    return Request(scope)


@contextmanager
def _settings(**overrides):
    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, **overrides))
    try:
        yield
    finally:
        jafaal.configure(original)


def test_change_own_password_success(db, make_user):
    user = make_user(password="Old1!Pass")
    account_svc.change_own_password(user.id, "Old1!Pass", "New1!Passw", None, _svc(db), StepUpAttempts(), db)

    svc = _svc(db)
    stored = svc.get_password_hash(user.id)
    assert svc.verify_password("New1!Passw", stored) is True
    assert svc.verify_password("Old1!Pass", stored) is False


def test_change_own_password_wrong_current_password(db, make_user):
    user = make_user(password="Old1!Pass")
    with pytest.raises(exc.InvalidCredentialsError):
        account_svc.change_own_password(user.id, "WRONG!Pass", "New1!Passw", None, _svc(db), StepUpAttempts(), db)


def test_change_own_password_revokes_other_sessions(db, make_user):
    user = make_user(password="Old1!Pass")
    session_utils.create_session("keep", user, _request(), "rt-keep", db)
    session_utils.create_session("drop", user, _request(), "rt-drop", db)

    account_svc.change_own_password(
        user.id,
        "Old1!Pass",
        "New1!Passw",
        None,
        _svc(db),
        StepUpAttempts(),
        db,
        revoke_other_sessions=True,
        current_session_id="keep",
    )

    remaining = {s.id for s in sessions_crud.get_user_sessions(user.id, db)}
    assert remaining == {"keep"}


def test_change_managed_user_password_revokes_all_sessions(db, make_user):
    user = make_user(password="Old1!Pass")
    session_utils.create_session("s1", user, _request(), "rt", db)
    account_svc.change_managed_user_password(user.id, "New1!Passw", _svc(db), db)

    svc = _svc(db)
    assert svc.verify_password("New1!Passw", svc.get_password_hash(user.id)) is True
    assert sessions_crud.get_user_sessions(user.id, db) == []


def test_get_user_sessions(db, make_user):
    user = make_user()
    session_utils.create_session("s1", user, _request(), "rt", db)
    assert len(account_svc.get_user_sessions(user.id, db)) == 1


def test_get_user_sessions_empty_in_demo(db, make_user):
    user = make_user()
    session_utils.create_session("s1", user, _request(), "rt", db)
    with _settings(environment="demo"):
        assert account_svc.get_user_sessions(user.id, db) == []


def test_delete_user_session(db, make_user):
    user = make_user()
    session_utils.create_session("s1", user, _request(), "rt", db)
    account_svc.delete_user_session("s1", user.id, db)
    assert sessions_crud.get_session_by_id("s1", db) is None


def test_delete_other_user_sessions(db, make_user):
    user = make_user()
    session_utils.create_session("keep", user, _request(), "a", db)
    session_utils.create_session("drop", user, _request(), "b", db)
    revoked = account_svc.delete_other_user_sessions(user.id, "keep", db)
    assert revoked == 1
    assert {s.id for s in sessions_crud.get_user_sessions(user.id, db)} == {"keep"}


def test_identity_service_delete_other_sessions_returns_count(db, make_user):
    # The DefaultIdentityService wrapper surfaces the revoked-session count from
    # the underlying service (it previously dropped it).
    user = make_user()
    session_utils.create_session("keep", user, _request(), "a", db)
    session_utils.create_session("drop-1", user, _request(), "b", db)
    session_utils.create_session("drop-2", user, _request(), "c", db)
    revoked = _svc(db).delete_other_user_sessions(user.id, "keep")
    assert revoked == 2
    assert {s.id for s in sessions_crud.get_user_sessions(user.id, db)} == {"keep"}
