"""Tests for session utilities, session CRUD, refresh-token rotation, and OAuth state."""

import dataclasses
import threading
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
    session_utils.create_session("sess-b", user, _request(), "rt", db)
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
    session_utils.create_session("sess-x", other, _request(), "rt", db)
    token = _access_token(owner, "sess-x")
    with _settings(strict_session_binding=True), pytest.raises(exc.InvalidTokenError):
        _svc(db).resolve_from_access_token(token)


def test_strict_binding_enforces_session_timeout(db, make_user):
    # An idle-timed-out session rejects the access token under strict binding.
    user = make_user()
    session_utils.create_session("sess-idle", user, _request(), "rt", db)
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
    session_utils.create_session("sess-1", user, _request(), "refresh-value", db)

    row = sessions_crud.get_session_by_id("sess-1", db)
    assert row is not None
    assert row.user_id == user.id
    assert row.token_family_id == "sess-1"

    sessions_crud.delete_session("sess-1", user.id, db)
    assert sessions_crud.get_session_by_id("sess-1", db) is None


def test_get_user_sessions(db, make_user):
    user = make_user()
    session_utils.create_session("s-a", user, _request(), "rt-a", db)
    session_utils.create_session("s-b", user, _request(), "rt-b", db)
    sessions = sessions_crud.get_user_sessions(user.id, db)
    assert {s.id for s in sessions} == {"s-a", "s-b"}


def test_delete_sessions_by_user_with_exclude(db, make_user):
    user = make_user()
    session_utils.create_session("keep", user, _request(), "rt-keep", db)
    session_utils.create_session("drop", user, _request(), "rt-drop", db)
    sessions_crud.delete_sessions_by_user(user.id, db, exclude_session_id="keep")
    remaining = {s.id for s in sessions_crud.get_user_sessions(user.id, db)}
    assert remaining == {"keep"}


# --------------------------------------------------------------------------- #
# Refresh-token rotation / reuse detection
# --------------------------------------------------------------------------- #


def test_rotated_token_store_and_lookup(db, make_user):
    user = make_user()
    session_utils.create_session("fam-1", user, _request(), "initial-rt", db)
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
    session_utils.create_session("fam-x", user, _request(), "rt", db)
    deleted = rotated_utils.invalidate_token_family("fam-x", db)
    assert deleted >= 1
    assert sessions_crud.get_session_by_id("fam-x", db) is None


def test_rotated_token_in_grace_replay(db, make_user):
    user = make_user()
    session_utils.create_session("fam-g", user, _request(), "initial-rt", db)
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


def test_grace_replay_is_idempotent_across_duplicate_reads(db, make_user):
    # Duplicate in-grace refresh retries (a lost rotation response, or a racing
    # background refresh) must converge on the single replacement minted by the
    # original rotation — never diverge, escalate to theft, or re-rotate.
    # (True thread-parallelism of the lockout primitive is covered in
    # test_state_store.py; the DB-level guarantee under genuine thread
    # concurrency is proven below via the ``concurrent_db`` fixture.)
    user = make_user()
    session_utils.create_session("fam-cc", user, _request(), "initial-rt", db)
    exp = datetime.now(UTC) + timedelta(days=7)
    rotated_utils.store_rotated_token(
        "old-cc",
        "fam-cc",
        0,
        db,
        replacement_refresh_token="new-cc",
        replacement_refresh_token_exp=exp,
    )

    # Many duplicate presentations of the same rotated token...
    results = [rotated_utils.get_grace_replay_token("old-cc", db) for _ in range(12)]
    assert all(r is not None for r in results)
    # ...all converge on the one stored replacement (idempotent, no divergence).
    assert {r[0] for r in results} == {"new-cc"}
    # It stays an in-grace reuse throughout: no theft escalation, no re-rotation.
    assert rotated_utils.check_token_reuse("old-cc", db) == (True, True)


# --------------------------------------------------------------------------- #
# DB-level atomicity under REAL thread concurrency
#
# These use the file-backed ``concurrent_db`` fixture so each thread gets its own
# connection and the database (not Python) arbitrates the race — the in-memory
# suite engine shares a single connection and cannot express write contention.
# --------------------------------------------------------------------------- #


def _run_concurrently(work, threads=8):
    """Run ``work(i)`` in ``threads`` threads released simultaneously.

    Returns the list of ``(result, exception)`` pairs in completion-agnostic
    order. A barrier maximises the overlap so the contention is genuine.
    """
    barrier = threading.Barrier(threads)
    outcomes: list[tuple[object, BaseException | None]] = []
    lock = threading.Lock()

    def _worker(index):
        barrier.wait()
        try:
            result, err = work(index), None
        except BaseException as exception:  # recorded, then asserted on below
            result, err = None, exception
        with lock:
            outcomes.append((result, err))

    workers = [threading.Thread(target=_worker, args=(i,)) for i in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=60)
    return outcomes


def test_token_exchange_claim_has_exactly_one_winner_under_real_concurrency(concurrent_db):
    # The one-shot PKCE exchange is guarded by a single conditional UPDATE
    # (claim_session_for_token_exchange). Under genuine parallelism exactly one
    # caller may claim it; any other outcome is a double-spend of the code.
    with concurrent_db.session() as setup:
        session_utils.create_session(
            "race-exchange",
            SimpleNamespace(id=concurrent_db.user_id),
            _request(),
            None,
            setup,
        )

    def _claim(index):
        with concurrent_db.session() as session:
            return sessions_crud.claim_session_for_token_exchange("race-exchange", f"hash-{index}", session)

    outcomes = _run_concurrently(_claim)
    assert [err for _, err in outcomes if err is not None] == []
    assert [result for result, _ in outcomes].count(True) == 1
    assert [result for result, _ in outcomes].count(False) == len(outcomes) - 1

    # Exactly one refresh-token hash was persisted — the winner's.
    with concurrent_db.session() as check:
        claimed = sessions_crud.get_session_by_id("race-exchange", check)
        assert claimed.tokens_exchanged is True
        assert claimed.refresh_token.startswith("hash-")


def test_concurrent_rotation_of_one_token_records_a_single_row(concurrent_db):
    # Two refreshes presenting the SAME refresh token must not both record a
    # rotation: the unique index on the token hash is what makes the rotation
    # single-use at the database level (no double-spend), so exactly one of the
    # racing writers may commit.
    with concurrent_db.session() as setup:
        session_utils.create_session(
            "race-family",
            SimpleNamespace(id=concurrent_db.user_id),
            _request(),
            "initial-rt",
            setup,
        )
    exp = datetime.now(UTC) + timedelta(days=7)

    def _rotate(index):
        with concurrent_db.session() as session:
            rotated_utils.store_rotated_token(
                "contended-token",
                "race-family",
                0,
                session,
                replacement_refresh_token=f"replacement-{index}",
                replacement_refresh_token_exp=exp,
            )
            return index

    outcomes = _run_concurrently(_rotate)
    winners = [result for result, err in outcomes if err is None]
    assert len(winners) == 1, "more than one rotation of the same token committed"

    # One row, and the replayable replacement is the winner's — the losers'
    # replacements were never persisted, so an in-grace retry cannot diverge.
    with concurrent_db.session() as check:
        row = rotated_crud.get_rotated_token_by_hash(rotated_utils.hmac_hash_token("contended-token"), check)
        assert row is not None
        assert crypto.decrypt_token_fernet(row.replacement_refresh_token) == f"replacement-{winners[0]}"


def test_rotated_token_reuse_after_grace_is_theft(db, make_user):
    user = make_user()
    session_utils.create_session("fam-t", user, _request(), "rt", db)
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
        session_utils.create_session("s-live", user, _request(), "rt", db)
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
