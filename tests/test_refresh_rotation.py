"""End-to-end HTTP tests for refresh-token rotation, reuse detection, and CSRF.

These drive the real ``/auth/refresh`` endpoint through the mounted router (the
security-critical path the unit tests in ``test_sessions.py`` only exercise at
the util level): silent rotation, idempotent in-grace replay, stolen-token theft
detection with whole-family invalidation, and the web CSRF bootstrap rules.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jafaal.orm as jafaal_orm
from jafaal._internal.token_manager import TokenType, get_token_manager
from jafaal.sessions.rotated_refresh_tokens.models import RotatedRefreshToken

WEB = {"X-Client-Type": "web"}
REFRESH = "/api/v1/auth/refresh"
COOKIE = "jafaal_refresh_token"
COOKIE_PATH = "/api/v1/auth"


def _login(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
        headers=WEB,
    )


def _refresh_cookie(client) -> str | None:
    return client.cookies.get(COOKIE)


def _set_refresh_cookie(client, value: str) -> None:
    # Re-present an old/forged token: reuse whatever domain/path httpx stored the
    # login cookie under, then swap in our value.
    domain, path = "testserver.local", COOKIE_PATH
    for cookie in client.cookies.jar:
        if cookie.name == COOKIE:
            domain, path = cookie.domain, cookie.path
            break
    client.cookies.clear()
    client.cookies.set(COOKIE, value, domain=domain, path=path)


def _force_rotated_tokens_past_grace() -> None:
    """Expire every stored rotated-token grace window (simulate elapsed time)."""
    session = jafaal_orm.get_sessionmaker()()
    try:
        for row in session.query(RotatedRefreshToken).all():
            row.expires_at = datetime.now(UTC) - timedelta(seconds=600)
        session.commit()
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# Rotation
# --------------------------------------------------------------------------- #


def test_refresh_rotates_the_refresh_cookie(client, make_user):
    make_user(username="alice")
    _login(client)
    original = _refresh_cookie(client)

    resp = client.post(REFRESH, headers=WEB)

    assert resp.status_code == 200
    rotated = _refresh_cookie(client)
    assert rotated is not None
    assert rotated != original  # the refresh token itself is rotated, not just the access token


def test_refresh_without_cookie_is_unauthorized(client):
    resp = client.post(REFRESH, headers=WEB)
    assert resp.status_code == 401


def test_refresh_after_logout_finds_no_session(client, make_user):
    make_user(username="alice")
    _login(client)
    valid_cookie = _refresh_cookie(client)
    assert client.post("/api/v1/auth/logout", headers=WEB).status_code == 200

    # Re-present the (now-deleted) session's refresh token.
    _set_refresh_cookie(client, valid_cookie)
    resp = client.post(REFRESH, headers=WEB)
    assert resp.status_code in (401, 404)


# --------------------------------------------------------------------------- #
# Reuse detection / theft
# --------------------------------------------------------------------------- #


def test_reuse_after_grace_is_theft_and_kills_the_family(client, make_user):
    make_user(username="alice")
    _login(client)
    stolen = _refresh_cookie(client)

    # Legitimate rotation → the presented token is now the *old* one.
    assert client.post(REFRESH, headers=WEB).status_code == 200
    current = _refresh_cookie(client)

    # Past the grace window, re-presenting the old token is treated as theft.
    _force_rotated_tokens_past_grace()
    _set_refresh_cookie(client, stolen)
    theft = client.post(REFRESH, headers=WEB)
    assert theft.status_code == 401
    assert "reuse" in theft.json()["detail"].lower()

    # Theft invalidates the whole family: even the legitimate current token dies.
    _set_refresh_cookie(client, current)
    assert client.post(REFRESH, headers=WEB).status_code in (401, 404)


def test_theft_emits_security_event(client, make_user, event_sink):
    from jafaal.ports import RefreshTokenTheftDetected

    make_user(username="alice")
    _login(client)
    stolen = _refresh_cookie(client)

    assert client.post(REFRESH, headers=WEB).status_code == 200  # legitimate rotation
    _force_rotated_tokens_past_grace()
    _set_refresh_cookie(client, stolen)
    assert client.post(REFRESH, headers=WEB).status_code == 401  # theft detected

    theft = [e for e in event_sink.events if isinstance(e, RefreshTokenTheftDetected)]
    assert len(theft) == 1
    assert theft[0].token_family_id


def test_in_grace_replay_is_idempotent(client, make_user):
    make_user(username="alice")
    _login(client)
    old = _refresh_cookie(client)

    assert client.post(REFRESH, headers=WEB).status_code == 200
    replacement = _refresh_cookie(client)
    assert replacement != old

    # Re-presenting the just-rotated token *within* grace replays the same
    # replacement (a lost response / racing retry converges, no new rotation).
    _set_refresh_cookie(client, old)
    replay = client.post(REFRESH, headers=WEB)
    assert replay.status_code == 200
    assert _refresh_cookie(client) == replacement


def test_refresh_rejects_session_owner_mismatch(client, make_user):
    make_user(username="alice")
    bob = make_user(username="bob")
    access = _login(client, "alice").json()["access_token"]

    # Forge a validly-signed refresh token that names bob's sub but alice's sid.
    token_manager = get_token_manager()
    alice_sid = token_manager.get_token_claim(access, "sid")
    _exp, forged = token_manager.create_token(alice_sid, bob, TokenType.REFRESH)

    _set_refresh_cookie(client, forged)
    resp = client.post(REFRESH, headers=WEB)
    assert resp.status_code == 401


def test_refresh_rejects_deactivated_user(client, make_user, db):
    make_user(username="alice")
    _login(client)

    # Deactivate the account after login; the still-valid refresh token must
    # not mint new tokens for a now-disabled user.
    users = jafaal_orm.get_user_model()
    row = db.query(users).filter(users.username == "alice").one()
    row.is_active = False
    db.commit()

    resp = client.post(REFRESH, headers=WEB)
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# CSRF bootstrap rules (web)
# --------------------------------------------------------------------------- #


def test_csrf_not_required_on_first_refresh_bootstrap(client, make_user):
    make_user(username="alice")
    _login(client)  # login does NOT bind a CSRF hash to the session
    # First refresh with no CSRF header must succeed (page-reload bootstrap).
    assert client.post(REFRESH, headers=WEB).status_code == 200


def test_wrong_csrf_header_is_rejected_once_bound(client, make_user):
    make_user(username="alice")
    _login(client)
    # First refresh binds a CSRF hash to the session.
    client.post(REFRESH, headers=WEB)

    resp = client.post(REFRESH, headers={**WEB, "X-CSRF-Token": "totally-wrong"})
    assert resp.status_code == 403
    assert "csrf" in resp.json()["detail"].lower()


def test_correct_csrf_header_is_accepted(client, make_user):
    make_user(username="alice")
    _login(client)
    bound = client.post(REFRESH, headers=WEB).json()
    csrf = bound["csrf_token"]

    resp = client.post(REFRESH, headers={**WEB, "X-CSRF-Token": csrf})
    assert resp.status_code == 200


def test_missing_csrf_header_still_allowed_after_binding(client, make_user):
    make_user(username="alice")
    _login(client)
    client.post(REFRESH, headers=WEB)  # binds CSRF

    # Omitting the header on a later reload must still bootstrap (no lockout).
    assert client.post(REFRESH, headers=WEB).status_code == 200
