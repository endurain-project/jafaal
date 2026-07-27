"""Time-boundary tests: expiry, grace windows, skew, and TOTP timesteps.

Every one of these is an off-by-one waiting to happen, and none of them can be
proven by a test that just calls the function "now" — the interesting cases sit
one second either side of a boundary. So the clock is driven explicitly:
``freeze_time`` patches ``datetime.now`` in the module under test, and the TOTP
tests pin ``time.time``.

What is being pinned down:

* a session expires *after* its idle / absolute limit, not on it;
* a rotated refresh token is replayable for exactly the grace window and is
  treated as theft one second later;
* ``TokenSettings.leeway_seconds`` widens the accepted ``exp``/``nbf`` window by
  exactly that much, in both directions; and
* a TOTP code is accepted across its drift window and never twice.
"""

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from conftest import replace_settings
from starlette.requests import Request

import jafaal
import jafaal.exceptions as exc
import jafaal.mfa.service as mfa_service
import jafaal.sessions.rotated_refresh_tokens.utils as rotated_utils
import jafaal.sessions.utils as session_utils
from jafaal._internal.token_manager import TokenManager, TokenType


@contextmanager
def _settings(**overrides):
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, **overrides))
    try:
        yield
    finally:
        jafaal.configure(original)


@contextmanager
def freeze_time(module, moment: datetime):
    """Pin ``datetime.now`` inside ``module`` to ``moment``."""

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return moment if tz is None else moment.astimezone(tz)

    original = module.datetime
    module.datetime = _FrozenDatetime
    try:
        yield
    finally:
        module.datetime = original


def _request():
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [(b"user-agent", b"Mozilla/5.0")],
        "client": ("1.2.3.4", 1),
        "scheme": "https",
        "server": ("app.test", 443),
    }
    return Request(scope)


# --------------------------------------------------------------------------- #
# Session idle / absolute timeout boundaries
# --------------------------------------------------------------------------- #


def _session_row(*, created_at: datetime, last_activity_at: datetime):
    return SimpleNamespace(
        id="sess",
        user_id=1,
        created_at=created_at,
        last_activity_at=last_activity_at,
    )


@pytest.mark.parametrize(
    ("elapsed_seconds", "expires"),
    [
        (3600 - 1, False),  # one second inside the window
        (3600, False),  # exactly on the limit — not yet expired
        (3600 + 1, True),  # one second past
    ],
)
def test_idle_timeout_boundary_is_exclusive(elapsed_seconds, expires):
    start = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    row = _session_row(created_at=start, last_activity_at=start)

    with (
        _settings(idle_timeout_enabled=True, idle_timeout_hours=1, absolute_timeout_hours=999),
        freeze_time(session_utils, start + timedelta(seconds=elapsed_seconds)),
    ):
        if expires:
            with pytest.raises(exc.SessionExpiredError, match="inactivity"):
                session_utils.validate_session_timeout(row)
        else:
            session_utils.validate_session_timeout(row)


@pytest.mark.parametrize(
    ("elapsed_seconds", "expires"),
    [
        (86400, False),
        (86400 + 1, True),
    ],
)
def test_absolute_timeout_boundary_is_exclusive(elapsed_seconds, expires):
    start = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    now = start + timedelta(seconds=elapsed_seconds)
    # Recent activity keeps the idle window open, so only the absolute limit can fire.
    row = _session_row(created_at=start, last_activity_at=now)

    with (
        _settings(idle_timeout_enabled=True, idle_timeout_hours=999, absolute_timeout_hours=24),
        freeze_time(session_utils, now),
    ):
        if expires:
            with pytest.raises(exc.SessionExpiredError, match="Please login again"):
                session_utils.validate_session_timeout(row)
        else:
            session_utils.validate_session_timeout(row)


def test_timeouts_are_not_enforced_when_disabled():
    start = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    row = _session_row(created_at=start, last_activity_at=start)
    with (
        _settings(idle_timeout_enabled=False, idle_timeout_hours=1, absolute_timeout_hours=1),
        freeze_time(session_utils, start + timedelta(days=365)),
    ):
        session_utils.validate_session_timeout(row)


# --------------------------------------------------------------------------- #
# Refresh-token rotation grace window
# --------------------------------------------------------------------------- #


def _store_rotated(db, token: str, *, rotated_at: datetime):
    """Persist a rotated-token record whose rotation happened at ``rotated_at``."""
    import jafaal.sessions.rotated_refresh_tokens.crud as rotated_crud
    import jafaal.sessions.rotated_refresh_tokens.schema as rotated_schema
    from jafaal._core import crypto

    rotated_crud.create_rotated_token(
        rotated_schema.RotatedRefreshTokenCreate(
            token_family_id="fam-clock",
            hashed_token=rotated_utils.hmac_hash_token(token),
            rotation_count=0,
            rotated_at=rotated_at,
            expires_at=rotated_at + timedelta(seconds=rotated_utils.TOKEN_REUSE_GRACE_PERIOD_SECONDS),
            replacement_refresh_token=crypto.encrypt_token_fernet("replacement"),
            replacement_refresh_token_exp=rotated_at + timedelta(days=7),
        ),
        db,
    )


@pytest.mark.parametrize(
    ("age_seconds", "expected_in_grace"),
    [
        (0, True),
        (rotated_utils.TOKEN_REUSE_GRACE_PERIOD_SECONDS - 1, True),
        (rotated_utils.TOKEN_REUSE_GRACE_PERIOD_SECONDS + 1, False),
    ],
)
def test_reuse_grace_window_boundary(db, make_user, age_seconds, expected_in_grace):
    """Inside the window a replay is an idempotent retry; outside it is theft.

    The distinction decides whether a duplicate refresh gets its tokens replayed
    or the user's entire session family is destroyed, so the boundary matters.
    """
    make_user(username="clock-user")
    now = datetime.now(UTC)
    with jafaal.unit_of_work(db):
        _store_rotated(db, "graced-token", rotated_at=now - timedelta(seconds=age_seconds))

    is_reused, in_grace = rotated_utils.check_token_reuse("graced-token", db)

    assert is_reused is True
    assert in_grace is expected_in_grace


def test_an_unrotated_token_is_not_reuse(db, make_user):
    make_user(username="clock-user-2")
    is_reused, in_grace = rotated_utils.check_token_reuse("never-rotated", db)
    assert (is_reused, in_grace) == (False, False)


# --------------------------------------------------------------------------- #
# JWT clock skew (exp / nbf leeway)
# --------------------------------------------------------------------------- #


def _manager(**kwargs):
    return TokenManager(
        "k" * 32,
        "HS256",
        issuer="iss",
        audience="aud",
        access_token_expire_minutes=15,
        **kwargs,
    )


def _user():
    return SimpleNamespace(id=1, username="skewed", is_superuser=False)


def _token_issued_at(manager: TokenManager, moment: datetime) -> str:
    """Mint an access token as if the clock had read ``moment``.

    Only *issuance* is time-shifted. Validation deliberately runs against the
    real clock, because ``exp``/``nbf`` are checked by joserfc's claims
    registry using its own clock — freezing JAFAAL's ``datetime`` would not
    affect it, and a test that patched joserfc's internals would be asserting
    against a stub rather than the code path that actually runs in production.
    """
    import jafaal._internal.token_manager as tm

    with freeze_time(tm, moment):
        _, token = manager.create_token("sid", _user(), TokenType.ACCESS)
    return token


def test_expired_token_is_rejected_without_leeway():
    manager = _manager()
    # Issued 16 minutes ago with a 15-minute lifetime → expired a minute ago.
    token = _token_issued_at(manager, datetime.now(UTC) - timedelta(minutes=16))

    with pytest.raises(exc.TokenExpiredError):
        manager.validate_token_expiration(token, TokenType.ACCESS)


def test_leeway_widens_the_accepted_expiry_window():
    """A token just past ``exp`` is accepted only within the configured leeway."""
    manager = _manager(leeway_seconds=30)

    # Expired 20 seconds ago — inside the 30-second leeway.
    just_expired = _token_issued_at(manager, datetime.now(UTC) - timedelta(minutes=15, seconds=20))
    manager.validate_token_expiration(just_expired, TokenType.ACCESS)

    # Expired 45 seconds ago — outside it.
    long_expired = _token_issued_at(manager, datetime.now(UTC) - timedelta(minutes=15, seconds=45))
    with pytest.raises(exc.TokenExpiredError):
        manager.validate_token_expiration(long_expired, TokenType.ACCESS)


def test_zero_leeway_is_strict():
    """The default must not silently tolerate skew."""
    manager = _manager(leeway_seconds=0)
    token = _token_issued_at(manager, datetime.now(UTC) - timedelta(minutes=15, seconds=5))

    with pytest.raises(exc.TokenExpiredError):
        manager.validate_token_expiration(token, TokenType.ACCESS)


def test_a_token_from_a_slightly_fast_clock_is_accepted_within_leeway():
    """``nbf`` in the near future is the other half of the skew problem."""
    manager = _manager(leeway_seconds=30)
    # Issued by a node whose clock is 20 seconds ahead of ours.
    token = _token_issued_at(manager, datetime.now(UTC) + timedelta(seconds=20))

    manager.validate_token_expiration(token, TokenType.ACCESS)


def test_a_token_from_a_badly_fast_clock_is_rejected():
    manager = _manager(leeway_seconds=0)
    token = _token_issued_at(manager, datetime.now(UTC) + timedelta(minutes=5))

    with pytest.raises(exc.InvalidTokenError):
        manager.validate_token_expiration(token, TokenType.ACCESS)


# --------------------------------------------------------------------------- #
# TOTP timestep drift and single use
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("offset_steps", [-1, 0, 1])
def test_totp_accepts_codes_within_the_drift_window(monkeypatch, offset_steps):
    pyotp = pytest.importorskip("pyotp")
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    base = 1_900_000_000  # a fixed instant, so the timestep is deterministic
    monkeypatch.setattr(mfa_service.time, "time", lambda: base)

    code = totp.at(base + offset_steps * totp.interval)
    matched = mfa_service._matched_totp_timestep(secret, code)

    assert matched == (base // totp.interval) + offset_steps


def test_totp_rejects_a_code_outside_the_drift_window(monkeypatch):
    pyotp = pytest.importorskip("pyotp")
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    base = 1_900_000_000
    monkeypatch.setattr(mfa_service.time, "time", lambda: base)

    # Two steps away is outside the +/- 1 window.
    code = totp.at(base + 2 * totp.interval)
    assert mfa_service._matched_totp_timestep(secret, code) is None


def test_a_timestep_can_only_be_claimed_once(monkeypatch):
    """Replay protection is a claim, so the second attempt on one step loses."""
    base = 1_900_000_000
    monkeypatch.setattr(mfa_service.time, "time", lambda: base)

    timestep = base // 30
    assert mfa_service._claim_totp_timestep(1, timestep) is True
    assert mfa_service._claim_totp_timestep(1, timestep) is False
    # A different step, and a different user, are unaffected.
    assert mfa_service._claim_totp_timestep(1, timestep + 1) is True
    assert mfa_service._claim_totp_timestep(2, timestep) is True
