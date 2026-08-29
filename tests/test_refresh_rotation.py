"""End-to-end HTTP tests for refresh-token rotation, reuse detection, and CSRF.

These drive the real ``/auth/refresh`` endpoint through the mounted router (the
security-critical path the unit tests in ``test_sessions.py`` only exercise at
the util level): silent rotation, idempotent in-grace replay, stolen-token theft
detection with whole-family invalidation, and the web CSRF bootstrap rules.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from conftest import NATIVE_CLIENT_ID, WEB_CLIENT_ID, replace_settings

import jafaal.orm as jafaal_orm
import jafaal.sessions.utils as session_utils
import jafaal.settings as jafaal_settings
from jafaal._core import timeutils
from jafaal._internal.token_manager import TokenType, get_token_manager
from jafaal.sessions.models import UsersSessions
from jafaal.sessions.rotated_refresh_tokens.models import RotatedRefreshToken

REFRESH = "/api/v1/auth/refresh"
COOKIE = "jafaal_refresh_token"
COOKIE_PATH = "/api/v1/auth"


def _login(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password, "client_id": WEB_CLIENT_ID},
    )


def _login_mobile(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password, "client_id": NATIVE_CLIENT_ID},
    )


@contextmanager
def _override_settings(**overrides):
    """Temporarily reconfigure JAFAAL, restoring the suite settings afterwards."""
    original = jafaal_settings.get_settings()
    jafaal_settings.configure(replace_settings(original, **overrides))
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

    resp = client.post(REFRESH)

    assert resp.status_code == 200
    rotated = _refresh_cookie(client)
    assert rotated is not None
    assert rotated != original  # the refresh token itself is rotated, not just the access token


def test_rotation_does_not_extend_a_session_past_its_absolute_deadline(client, make_user, db):
    """Refreshing slides ``expires_at`` forward, but never past the hard ceiling.

    Without the cap a client refreshing once per token lifetime keeps a single
    login alive forever — the unbounded refresh-token lifetime RFC 9700 §4.14.2
    warns against.
    """
    make_user(username="alice")
    _login(client)

    row = db.query(UsersSessions).one()
    created_at = row.created_at
    session_id = row.id
    db.rollback()

    # A 1-hour ceiling with a 7-day refresh token: the ceiling has to win.
    with _override_settings(absolute_timeout_hours=1):
        assert client.post(REFRESH).status_code == 200
        db.expire_all()
        rotated = db.query(UsersSessions).filter(UsersSessions.id == session_id).one()
        deadline = timeutils.ensure_aware_utc(created_at) + timedelta(hours=1)
        assert timeutils.ensure_aware_utc(rotated.expires_at) == deadline


def test_concurrent_refresh_of_one_token_does_not_error(client, make_user):
    """A duplicated refresh must produce a defined response, never a 500.

    Two requests carrying the same refresh token used to both pass the verify
    step and race to INSERT the same rotated-token row; the loser tripped the
    unique index and surfaced as an unhandled IntegrityError.
    """
    make_user(username="alice")
    _login(client)
    token = _refresh_cookie(client)

    first = client.post(REFRESH)
    assert first.status_code == 200

    # Re-present the same token twice more: the grace replay serves one, and the
    # next is refused cleanly rather than blowing up.
    _set_refresh_cookie(client, token)
    assert client.post(REFRESH).status_code == 200

    _set_refresh_cookie(client, token)
    replayed_again = client.post(REFRESH)
    assert replayed_again.status_code == 401
    assert replayed_again.status_code != 500


def test_refresh_without_cookie_is_unauthorized(client):
    resp = client.post(REFRESH)
    assert resp.status_code == 401


def test_refresh_after_logout_finds_no_session(client, make_user):
    make_user(username="alice")
    _login(client)
    valid_cookie = _refresh_cookie(client)
    assert client.post("/api/v1/auth/logout").status_code == 200

    # Re-present the (now-deleted) session's refresh token.
    _set_refresh_cookie(client, valid_cookie)
    resp = client.post(REFRESH)
    assert resp.status_code == 400  # RFC 6749 §5.2 invalid_grant


# --------------------------------------------------------------------------- #
# Reuse detection / theft
# --------------------------------------------------------------------------- #


def test_reuse_after_grace_is_theft_and_kills_the_family(client, make_user):
    make_user(username="alice")
    _login(client)
    stolen = _refresh_cookie(client)

    # Legitimate rotation → the presented token is now the *old* one.
    assert client.post(REFRESH).status_code == 200
    current = _refresh_cookie(client)

    # Past the grace window, re-presenting the old token is treated as theft.
    _force_rotated_tokens_past_grace()
    _set_refresh_cookie(client, stolen)
    theft = client.post(REFRESH)
    assert theft.status_code == 401
    assert "reuse" in theft.json()["detail"].lower()

    # Theft invalidates the whole family: even the legitimate current token dies.
    _set_refresh_cookie(client, current)
    assert client.post(REFRESH).status_code == 400  # RFC 6749 §5.2 invalid_grant


def test_theft_emits_security_event(client, make_user, event_sink):
    from jafaal.ports import RefreshTokenTheftDetected

    make_user(username="alice")
    _login(client)
    stolen = _refresh_cookie(client)

    assert client.post(REFRESH).status_code == 200  # legitimate rotation
    _force_rotated_tokens_past_grace()
    _set_refresh_cookie(client, stolen)
    assert client.post(REFRESH).status_code == 401  # theft detected

    theft = [e for e in event_sink.events if isinstance(e, RefreshTokenTheftDetected)]
    assert len(theft) == 1
    assert theft[0].token_family_id


def test_in_grace_replay_is_idempotent(client, make_user):
    make_user(username="alice")
    _login(client)
    old = _refresh_cookie(client)

    assert client.post(REFRESH).status_code == 200
    replacement = _refresh_cookie(client)
    assert replacement != old

    # Re-presenting the just-rotated token *within* grace replays the same
    # replacement (a lost response / racing retry converges, no new rotation).
    _set_refresh_cookie(client, old)
    replay = client.post(REFRESH)
    assert replay.status_code == 200
    assert _refresh_cookie(client) == replacement


def test_in_grace_replay_is_single_use_then_treated_as_theft(client, make_user):
    """The grace window serves one retry, not an unlimited credential oracle.

    A lost rotation response produces exactly one retry. Serving the live
    replacement every time a rotated token is presented would let a thief keep
    harvesting it for the whole window, and would suppress the reuse signal
    RFC 9700 §4.14.2 relies on to detect the theft at all.
    """
    make_user(username="alice")
    _login(client)
    old = _refresh_cookie(client)

    assert client.post(REFRESH).status_code == 200

    # First re-presentation inside grace: the legitimate retry, served.
    _set_refresh_cookie(client, old)
    assert client.post(REFRESH).status_code == 200

    # Second: the replay is spent, so this is reuse of a superseded token —
    # rejected, and the whole family is invalidated even though we are still
    # well inside the 60-second window.
    _set_refresh_cookie(client, old)
    second = client.post(REFRESH)
    assert second.status_code == 401

    # The family is gone: the replacement no longer refreshes either. Its
    # session row was deleted, so the grant no longer resolves: invalid_grant.
    assert client.post(REFRESH).status_code == 400


def test_refresh_rejects_session_owner_mismatch(client, make_user):
    make_user(username="alice")
    bob = make_user(username="bob")
    access = _login(client, "alice").json()["access_token"]

    # Forge a validly-signed refresh token that names bob's sub but alice's sid.
    token_manager = get_token_manager()
    alice_sid = token_manager.get_token_claim(access, "sid")
    _exp, forged = token_manager.create_token(alice_sid, bob, TokenType.REFRESH)

    _set_refresh_cookie(client, forged)
    resp = client.post(REFRESH)
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

    resp = client.post(REFRESH)
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# CSRF bootstrap rules (web)
# --------------------------------------------------------------------------- #


def test_csrf_not_required_on_first_refresh_bootstrap(client, make_user):
    make_user(username="alice")
    _login(client)  # login does NOT bind a CSRF hash to the session
    # First refresh with no CSRF header must succeed (page-reload bootstrap).
    assert client.post(REFRESH).status_code == 200


def test_wrong_csrf_header_is_rejected_once_bound(client, make_user):
    make_user(username="alice")
    _login(client)
    # First refresh binds a CSRF hash to the session.
    client.post(REFRESH)

    resp = client.post(REFRESH, headers={"X-CSRF-Token": "totally-wrong"})
    assert resp.status_code == 403
    assert "csrf" in resp.json()["detail"].lower()


def test_correct_csrf_header_is_accepted(client, make_user):
    make_user(username="alice")
    _login(client)
    bound = client.post(REFRESH).json()
    csrf = bound["csrf_token"]

    resp = client.post(REFRESH, headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200


def test_missing_csrf_header_still_allowed_after_binding(client, make_user):
    make_user(username="alice")
    _login(client)
    client.post(REFRESH)  # binds CSRF

    # Omitting the header on a later reload must still bootstrap (no lockout).
    assert client.post(REFRESH).status_code == 200


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

    resp = client.post(REFRESH, headers={"Sec-Fetch-Site": "cross-site"})
    assert resp.status_code == 403
    assert "origin" in resp.json()["detail"].lower()


def test_cross_site_refresh_is_rejected_even_with_a_valid_csrf_token(client, make_user):
    make_user(username="alice")
    _login(client)
    csrf = client.post(REFRESH).json()["csrf_token"]

    resp = client.post(
        REFRESH,
        headers={"X-CSRF-Token": csrf, "Sec-Fetch-Site": "cross-site"},
    )
    assert resp.status_code == 403


def test_sibling_subdomain_refresh_is_rejected(client, make_user):
    # SameSite=Strict still sends the cookie for a same-*site* request, so a
    # sibling subdomain (or a subdomain takeover) must be rejected too.
    make_user(username="alice")
    _login(client)

    resp = client.post(REFRESH, headers={"Sec-Fetch-Site": "same-site"})
    assert resp.status_code == 403


def test_same_origin_and_direct_navigation_are_allowed(client, make_user):
    make_user(username="alice")
    _login(client)

    for fetch_site in ("same-origin", "none"):
        assert client.post(REFRESH, headers={"Sec-Fetch-Site": fetch_site}).status_code == 200


def test_mismatched_origin_header_is_rejected(client, make_user):
    make_user(username="alice")
    _login(client)

    resp = client.post(REFRESH, headers={"Origin": "https://evil.test"})
    assert resp.status_code == 403


def test_trusted_origin_header_is_accepted(client, make_user):
    # The suite configures base_url=https://app.test, which is the default
    # trusted origin.
    make_user(username="alice")
    _login(client)

    assert client.post(REFRESH, headers={"Origin": "https://app.test"}).status_code == 200


def test_explicit_csrf_trusted_origins_enable_a_split_origin_frontend(client, make_user):
    # Frontend and API on different hosts: the frontend origin must be listed,
    # and only that origin is accepted.
    make_user(username="alice")
    _login(client)

    with _override_settings(csrf_trusted_origins=("https://spa.test",)):
        assert client.post(REFRESH, headers={"Origin": "https://spa.test"}).status_code == 200
        # base_url no longer implicitly trusted once an explicit list is set.
        assert client.post(REFRESH, headers={"Origin": "https://app.test"}).status_code == 403


def test_body_delivery_clients_are_not_subject_to_the_origin_check(client, make_user):
    # A body-delivery client holds the refresh token itself instead of relying
    # on a cookie, so it is not a CSRF target.
    make_user(username="alice")
    refresh_token = _login_mobile(client).json()["refresh_token"]

    resp = client.post(
        REFRESH,
        headers={"Authorization": f"Bearer {refresh_token}", "Sec-Fetch-Site": "cross-site"},
    )
    assert resp.status_code == 200


# --------------------------------------------------------------------------- #
# Stored refresh-token digest format
#
# Refresh tokens are high-entropy signed JWTs, so the session stores a keyed
# HMAC-SHA256 digest (microseconds) rather than a password KDF (~50 ms, paid
# twice per /refresh). Legacy Argon2 rows must keep verifying until they
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
    # 64 lowercase hex characters == HMAC-SHA256, not an Argon2 PHC string.
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


def test_refresh_rejects_a_session_whose_digest_does_not_match(client, make_user):
    make_user()
    session_id = _login(client).json()["session_id"]

    session = jafaal_orm.get_sessionmaker()()
    try:
        row = session.get(UsersSessions, session_id)
        row.refresh_token = session_utils.hash_refresh_token("a-different-token")
        session.commit()
    finally:
        session.close()

    assert client.post(REFRESH).status_code == 401


def test_refresh_rejects_a_malformed_stored_digest_without_a_500(client, make_user):
    # A corrupt stored digest must fail the comparison (401), not blow up the
    # request with a 500.
    make_user()
    session_id = _login(client).json()["session_id"]

    session = jafaal_orm.get_sessionmaker()()
    try:
        row = session.get(UsersSessions, session_id)
        row.refresh_token = "not-a-digest"
        session.commit()
    finally:
        session.close()

    assert client.post(REFRESH).status_code == 401


# --------------------------------------------------------------------------- #
# RFC 6749 §6 token-endpoint request shape
#
# /auth/refresh accepts the standard request a stock OAuth client sends, with no
# JAFAAL-specific header of any kind. Delivery mode is read from the token's own
# ``client_id`` claim, so the caller has no say in it at rotation time.
# --------------------------------------------------------------------------- #


def test_standard_grant_request_returns_a_new_token_bundle(client, make_user):
    make_user()
    refresh_token = _login_mobile(client).json()["refresh_token"]

    response = client.post(
        REFRESH,
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
    )

    assert response.status_code == 200
    body = response.json()
    # RFC 6749 §5.1 shape, plus JAFAAL's extras (which the RFC permits).
    assert body["token_type"] == "Bearer"
    assert isinstance(body["expires_in"], int)
    assert body["access_token"]
    assert body["refresh_token"] != refresh_token  # rotated


def test_delivery_mode_follows_the_token_not_the_request(client, make_user):
    # A body-delivery client's refresh always returns the token in the body,
    # whichever carrier the request used. The client is fixed when the session is
    # created; a request cannot switch it and move where the next refresh token
    # lands.
    make_user()
    refresh_token = _login_mobile(client).json()["refresh_token"]

    via_form = client.post(REFRESH, data={"grant_type": "refresh_token", "refresh_token": refresh_token}).json()
    assert via_form["refresh_token"]
    assert "csrf_token" not in via_form

    via_header = client.post(REFRESH, headers={"Authorization": f"Bearer {via_form['refresh_token']}"}).json()
    assert via_header["refresh_token"]
    assert "csrf_token" not in via_header


def test_a_cookie_client_keeps_cookie_delivery_through_the_standard_grant(client, make_user):
    # The mirror image: a cookie client that sends its token in the RFC 6749 form
    # body still gets cookie delivery back, because the registration says so.
    make_user()
    _login(client)
    cookie_token = client.cookies.get(COOKIE)

    body = client.post(REFRESH, data={"grant_type": "refresh_token", "refresh_token": cookie_token}).json()

    assert "refresh_token" not in body
    assert body["csrf_token"]


def test_a_token_from_a_deregistered_client_stops_rotating(client, make_user):
    # If the host withdraws a client, its sessions must stop: continuing would
    # mean guessing a delivery mode and scope ceiling that no longer exist.
    make_user()
    refresh_token = _login_mobile(client).json()["refresh_token"]

    with _override_settings(oauth_clients=()):
        assert (
            client.post(REFRESH, data={"grant_type": "refresh_token", "refresh_token": refresh_token}).status_code
            == 401
        )


def test_unsupported_grant_type_is_rejected(client, make_user):
    make_user()
    refresh_token = _login_mobile(client).json()["refresh_token"]

    response = client.post(
        REFRESH,
        data={"grant_type": "authorization_code", "refresh_token": refresh_token},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


def test_standard_grant_without_a_token_is_a_malformed_request(client, make_user):
    make_user()
    _login_mobile(client)

    response = client.post(REFRESH, data={"grant_type": "refresh_token"})

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_request"


def test_standard_grant_rejects_a_forged_token(client, make_user):
    make_user()
    _login_mobile(client)

    response = client.post(
        REFRESH,
        data={"grant_type": "refresh_token", "refresh_token": "not-a-jwt"},
    )

    assert response.status_code == 401


def test_a_request_carrying_no_token_at_all_is_unauthenticated(client, make_user):
    # No cookie, no header, no form body: there is no credential to validate.
    make_user()

    assert client.post(REFRESH).status_code == 401


def test_standard_grant_rotates_the_token(client, make_user):
    make_user()
    first = _login_mobile(client).json()["refresh_token"]

    rotated = client.post(
        REFRESH,
        data={"grant_type": "refresh_token", "refresh_token": first},
    ).json()["refresh_token"]
    assert rotated != first

    # The replacement works in turn.
    assert (
        client.post(
            REFRESH,
            data={"grant_type": "refresh_token", "refresh_token": rotated},
        ).status_code
        == 200
    )
