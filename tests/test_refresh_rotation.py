"""End-to-end HTTP tests for refresh-token rotation, reuse detection, and CSRF.

These drive the real ``/auth/refresh`` endpoint through the mounted router (the
security-critical path the unit tests in ``test_sessions.py`` only exercise at
the util level): silent rotation, idempotent in-grace replay, stolen-token theft
detection with whole-family invalidation, and the web CSRF bootstrap rules.
"""

from __future__ import annotations

import dataclasses
import hashlib
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import jafaal.orm as jafaal_orm
import jafaal.sessions.utils as session_utils
import jafaal.settings as jafaal_settings
from jafaal._internal.password_hasher import password_hasher
from jafaal._internal.token_manager import TokenType, get_token_manager
from jafaal.sessions.models import UsersSessions
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


def _login_mobile(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
        headers={"X-Client-Type": "mobile"},
    )


@contextmanager
def _override_settings(**overrides):
    """Temporarily reconfigure JAFAAL, restoring the suite settings afterwards."""
    original = jafaal_settings.get_settings()
    jafaal_settings.configure(dataclasses.replace(original, **overrides))
    try:
        yield
    finally:
        jafaal_settings.configure(original)


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


# --------------------------------------------------------------------------- #
# Off-site rejection (what makes the header-less bootstrap safe)
#
# A cross-site attacker can simply omit the X-CSRF-Token header, so the token
# check alone never protected the bootstrap path. ``Origin`` and
# ``Sec-Fetch-Site`` are forbidden header names — page script cannot forge or
# strip them — so the browser's own classification is the load-bearing signal.
# --------------------------------------------------------------------------- #


def test_cross_site_refresh_is_rejected_even_without_a_csrf_header(client, make_user):
    make_user(username="alice")
    _login(client)

    resp = client.post(REFRESH, headers={**WEB, "Sec-Fetch-Site": "cross-site"})
    assert resp.status_code == 403
    assert "origin" in resp.json()["detail"].lower()


def test_cross_site_refresh_is_rejected_even_with_a_valid_csrf_token(client, make_user):
    make_user(username="alice")
    _login(client)
    csrf = client.post(REFRESH, headers=WEB).json()["csrf_token"]

    resp = client.post(
        REFRESH,
        headers={**WEB, "X-CSRF-Token": csrf, "Sec-Fetch-Site": "cross-site"},
    )
    assert resp.status_code == 403


def test_sibling_subdomain_refresh_is_rejected(client, make_user):
    # SameSite=Strict still sends the cookie for a same-*site* request, so a
    # sibling subdomain (or a subdomain takeover) must be rejected too.
    make_user(username="alice")
    _login(client)

    resp = client.post(REFRESH, headers={**WEB, "Sec-Fetch-Site": "same-site"})
    assert resp.status_code == 403


def test_same_origin_and_direct_navigation_are_allowed(client, make_user):
    make_user(username="alice")
    _login(client)

    for fetch_site in ("same-origin", "none"):
        assert client.post(REFRESH, headers={**WEB, "Sec-Fetch-Site": fetch_site}).status_code == 200


def test_mismatched_origin_header_is_rejected(client, make_user):
    make_user(username="alice")
    _login(client)

    resp = client.post(REFRESH, headers={**WEB, "Origin": "https://evil.test"})
    assert resp.status_code == 403


def test_trusted_origin_header_is_accepted(client, make_user):
    # The suite configures base_url=https://app.test, which is the default
    # trusted origin.
    make_user(username="alice")
    _login(client)

    assert client.post(REFRESH, headers={**WEB, "Origin": "https://app.test"}).status_code == 200


def test_explicit_csrf_trusted_origins_enable_a_split_origin_frontend(client, make_user):
    # Frontend and API on different hosts: the frontend origin must be listed,
    # and only that origin is accepted.
    make_user(username="alice")
    _login(client)

    with _override_settings(csrf_trusted_origins=("https://spa.test",)):
        assert client.post(REFRESH, headers={**WEB, "Origin": "https://spa.test"}).status_code == 200
        # base_url no longer implicitly trusted once an explicit list is set.
        assert client.post(REFRESH, headers={**WEB, "Origin": "https://app.test"}).status_code == 403


def test_mobile_clients_are_not_subject_to_the_origin_check(client, make_user):
    # Mobile clients send the refresh token in the Authorization header, not a
    # cookie, so they are not a CSRF target.
    make_user(username="alice")
    mobile = {"X-Client-Type": "mobile"}
    refresh_token = _login_mobile(client).json()["refresh_token"]

    resp = client.post(
        REFRESH,
        headers={**mobile, "Authorization": f"Bearer {refresh_token}", "Sec-Fetch-Site": "cross-site"},
    )
    assert resp.status_code == 200


# --------------------------------------------------------------------------- #
# Stored refresh-token digest format
#
# Refresh tokens are high-entropy signed JWTs, so the session stores a keyed
# HMAC-SHA256 digest (microseconds) rather than a password KDF (~50 ms, paid
# twice per /refresh). Legacy Argon2/bcrypt rows must keep verifying until they
# are rotated away.
# --------------------------------------------------------------------------- #


def _session_row(session_id):
    session = jafaal_orm.get_sessionmaker()()
    try:
        return session.get(UsersSessions, session_id)
    finally:
        session.close()


def _stored_hash(session_id) -> str:
    row = _session_row(session_id)
    assert row is not None
    return row.refresh_token


def test_login_stores_refresh_token_as_keyed_hmac(client, make_user):
    make_user()
    body = _login(client).json()

    stored = _stored_hash(body["session_id"])
    # 64 lowercase hex characters == HMAC-SHA256, not an Argon2/bcrypt PHC string.
    assert len(stored) == 64
    assert set(stored) <= set("0123456789abcdef")
    assert not stored.startswith("$")
    # It is the keyed digest of the issued token, and nothing else matches.
    assert stored == session_utils.hash_refresh_token(_refresh_cookie(client))
    assert stored != session_utils.hash_refresh_token("not-the-token")


def test_stored_digest_is_keyed_not_a_bare_sha256(client, make_user):
    # A bare SHA-256 would let anyone with database read access verify a stolen
    # token offline; the HMAC keys it to AuthSettings.secret_key.
    make_user()
    body = _login(client).json()
    token = _refresh_cookie(client)

    assert _stored_hash(body["session_id"]) != hashlib.sha256(token.encode()).hexdigest()


def test_refresh_accepts_a_legacy_argon2_session_and_rehashes_it(client, make_user):
    # Sessions written before the switch hold an Argon2 hash. They must keep
    # working, and rotating one must rewrite it in the HMAC format so the
    # fallback drains instead of persisting forever.
    make_user()
    body = _login(client).json()
    session_id = body["session_id"]
    token = _refresh_cookie(client)

    session = jafaal_orm.get_sessionmaker()()
    try:
        row = session.get(UsersSessions, session_id)
        row.refresh_token = password_hasher.hash_password(token)
        session.commit()
    finally:
        session.close()

    legacy = _stored_hash(session_id)
    assert legacy.startswith("$")  # sanity: we really wrote a PHC-format hash

    response = client.post(REFRESH, headers=WEB)
    assert response.status_code == 200

    # Rotation rewrote the digest in the new format, bound to the new token.
    rotated = _stored_hash(session_id)
    assert not rotated.startswith("$")
    assert rotated == session_utils.hash_refresh_token(_refresh_cookie(client))


def test_refresh_rejects_a_wrong_token_against_a_legacy_argon2_session(client, make_user):
    make_user()
    session_id = _login(client).json()["session_id"]

    session = jafaal_orm.get_sessionmaker()()
    try:
        row = session.get(UsersSessions, session_id)
        row.refresh_token = password_hasher.hash_password("a-different-token")
        session.commit()
    finally:
        session.close()

    assert client.post(REFRESH, headers=WEB).status_code == 401


def test_refresh_rejects_an_unverifiable_stored_hash_without_a_500(client, make_user):
    # A corrupt/unknown stored hash must fail the comparison (401), not blow up
    # the request with a 500 out of the password library.
    make_user()
    session_id = _login(client).json()["session_id"]

    session = jafaal_orm.get_sessionmaker()()
    try:
        row = session.get(UsersSessions, session_id)
        row.refresh_token = "$totally-not-a-real-hash$"
        session.commit()
    finally:
        session.close()

    assert client.post(REFRESH, headers=WEB).status_code == 401
