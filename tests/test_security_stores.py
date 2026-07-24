"""Tests for the progressive-lockout security stores (login, MFA, step-up)."""

import time

import jafaal.state_store as state_store_mod
from jafaal._internal.security_stores import (
    _LOGIN_LOCKOUT_THRESHOLDS,
    FailedLoginAttempts,
    PendingMFALogin,
    StepUpAttempts,
    consume_step_up_reauth_grant,
    grant_step_up_reauth,
    normalize_username_key,
    username_log_identifier,
)
from jafaal.state_store import InMemoryStateStore


def test_normalize_username_key():
    assert normalize_username_key("  Alice  ") == "alice"
    assert normalize_username_key("A+B") == "a b"  # '+' decodes to space
    assert normalize_username_key("Bob%20Smith") == "bob smith"  # url-decoded


def test_username_log_identifier_is_hashed():
    ident = username_log_identifier("alice")
    assert ident.startswith("username_hash=")
    assert "alice" not in ident  # non-reversible


def test_step_up_reauth_grant_is_single_use():
    grant_step_up_reauth(42, idp_id=7, ttl_seconds=120)
    assert consume_step_up_reauth_grant(42) is True
    # Consumed: a second read finds nothing.
    assert consume_step_up_reauth_grant(42) is False


def test_step_up_reauth_grant_absent_returns_false():
    assert consume_step_up_reauth_grant(999) is False


# --------------------------------------------------------------------------- #
# FailedLoginAttempts (5/10/20 → 5m/30m/24h)
# --------------------------------------------------------------------------- #


def test_failed_login_locks_after_threshold():
    store = FailedLoginAttempts()
    assert store.is_locked_out("alice") is False
    for _ in range(4):
        store.record_failed_attempt("alice")
    assert store.is_locked_out("alice") is False  # under the 5 threshold
    store.record_failed_attempt("alice")  # 5th → lock
    assert store.is_locked_out("alice") is True
    assert store.get_lockout_time("alice") is not None


def test_failed_login_reset_clears_lock():
    store = FailedLoginAttempts()
    for _ in range(5):
        store.record_failed_attempt("bob")
    assert store.is_locked_out("bob") is True
    store.reset_attempts("bob")
    assert store.is_locked_out("bob") is False
    assert store.get_lockout_time("bob") is None


def test_login_lockout_reaches_second_and_third_tier_durations():
    # Drive the atomic increment with the REAL login thresholds, pre-seeding the
    # counter so the higher tiers (which an active gate would otherwise block
    # from being reached in one burst) are exercised deterministically.
    tiers = tuple((count, seconds) for count, seconds, _label in _LOGIN_LOCKOUT_THRESHOLDS)
    # (seed, resulting count, expected lock seconds): tier 1 (5→5m), 2 (10→30m), 3 (20→24h).
    for seed, expected_seconds in ((4, 5 * 60), (9, 30 * 60), (19, 24 * 60 * 60)):
        store = InMemoryStateStore()
        store.set("counter", str(seed).encode(), ttl_seconds=3600)
        now = int(time.time())
        outcome = store.record_tiered_failure("counter", "gate", tiers, 3600)
        assert outcome.newly_locked is True
        assert outcome.locked_until_epoch is not None
        assert abs((outcome.locked_until_epoch - now) - expected_seconds) <= 2


def test_login_lock_releases_after_expiry(monkeypatch):
    store = InMemoryStateStore()
    attempts = FailedLoginAttempts(store)
    for _ in range(5):
        attempts.record_failed_attempt("alice")
    assert attempts.is_locked_out("alice") is True

    # Advance the monotonic clock past the tier-1 (5 min) lock: the gate entry
    # expires by TTL and the account unlocks without any manual reset.
    base = state_store_mod.time.monotonic()
    monkeypatch.setattr(state_store_mod.time, "monotonic", lambda: base + 6 * 60)
    assert attempts.is_locked_out("alice") is False


def test_failed_login_is_case_and_whitespace_insensitive():
    store = FailedLoginAttempts()
    for _ in range(5):
        store.record_failed_attempt("  Alice ")
    # Same account keyed by the normalized form.
    assert store.is_locked_out("alice") is True


def test_failed_login_clear_all():
    store = FailedLoginAttempts()
    store.record_failed_attempt("alice")
    store.clear_all()
    assert store.is_locked_out("alice") is False


# --------------------------------------------------------------------------- #
# Per-source-IP backoff (50/100/250 → 15m/1h/24h)
# --------------------------------------------------------------------------- #


def test_login_ip_locks_after_ip_threshold():
    store = FailedLoginAttempts()
    ip = "203.0.113.9"
    assert store.is_ip_locked_out(ip) is False
    for _ in range(49):
        store.record_ip_failure(ip)
    assert store.is_ip_locked_out(ip) is False  # under the 50 threshold
    store.record_ip_failure(ip)  # 50th → IP locked
    assert store.is_ip_locked_out(ip) is True
    assert store.get_ip_lockout_time(ip) is not None


def test_login_ip_reset_clears_lock():
    store = FailedLoginAttempts()
    ip = "203.0.113.9"
    for _ in range(50):
        store.record_ip_failure(ip)
    assert store.is_ip_locked_out(ip) is True
    store.reset_ip_attempts(ip)
    assert store.is_ip_locked_out(ip) is False


def test_login_ip_and_username_lockouts_are_independent():
    # Five failures for one username lock the account but not the IP (needs 50),
    # so normal targeted brute-force does not incidentally trip the IP backoff.
    store = FailedLoginAttempts()
    for _ in range(5):
        store.record_failed_attempt("alice")
        store.record_ip_failure("203.0.113.9")
    assert store.is_locked_out("alice") is True
    assert store.is_ip_locked_out("203.0.113.9") is False


def test_clear_all_clears_ip_lockout():
    store = FailedLoginAttempts()
    for _ in range(50):
        store.record_ip_failure("203.0.113.9")
    assert store.is_ip_locked_out("203.0.113.9") is True
    store.clear_all()
    assert store.is_ip_locked_out("203.0.113.9") is False


def test_login_ip_lockout_can_be_disabled():
    import dataclasses

    import jafaal

    store = FailedLoginAttempts()
    ip = "203.0.113.9"
    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, login_ip_lockout_enabled=False))
    try:
        for _ in range(60):
            assert store.record_ip_failure(ip) == 0  # no-op when disabled
        assert store.is_ip_locked_out(ip) is False
        assert store.get_ip_lockout_time(ip) is None
    finally:
        jafaal.configure(original)


# --------------------------------------------------------------------------- #
# PendingMFALogin (bookkeeping + 5/10/15 lockout)
# --------------------------------------------------------------------------- #


def test_pending_mfa_add_get_claim():
    store = PendingMFALogin()
    assert store.has_pending_login("alice") is False
    store.add_pending_login("alice", 42)
    assert store.has_pending_login("alice") is True
    assert store.get_pending_login("alice") == 42
    # Claim is atomic single-use.
    assert store.claim_pending_login("alice") == 42
    assert store.get_pending_login("alice") is None


def test_pending_mfa_coerces_to_host_pk_type():
    """The stored id round-trips as the host PK type (int here), not bytes/str.

    Regression guard: it used to be ``int()``-parsed unconditionally, which
    permanently broke MFA login for UUID-PK hosts (see the UUID e2e test for the
    UUID side).
    """
    store = PendingMFALogin()
    store.add_pending_login("alice", 42)
    got = store.get_pending_login("alice")
    assert got == 42
    assert isinstance(got, int)
    claimed = store.claim_pending_login("alice")
    assert claimed == 42
    assert isinstance(claimed, int)


def test_pending_mfa_evicts_corrupt_entry():
    """A stored value that cannot be coerced to the PK type is treated as absent."""
    from jafaal._internal.security_stores import _key_prefix, _username_digest
    from jafaal.state_store import get_state_store

    store = PendingMFALogin()
    key = f"{_key_prefix()}:mfa:pending:{_username_digest('mallory')}"
    get_state_store().set(key, b"not-a-valid-id", ttl_seconds=300)
    assert store.get_pending_login("mallory") is None
    # The corrupt entry was evicted on read.
    assert get_state_store().get(key) is None


def test_pending_mfa_clear_for_user():
    store = PendingMFALogin()
    store.add_pending_login("alice", 1)
    store.add_pending_login("bob", 1)
    store.add_pending_login("carol", 2)
    assert store.clear_for_user(1) == 2
    assert store.get_pending_login("carol") == 2


def test_pending_mfa_lockout():
    store = PendingMFALogin()
    for _ in range(5):
        store.record_failed_attempt("alice")
    assert store.is_locked_out("alice") is True
    store.reset_attempts("alice")
    assert store.is_locked_out("alice") is False


# --------------------------------------------------------------------------- #
# StepUpAttempts (keyed by stable user id)
# --------------------------------------------------------------------------- #


def test_step_up_lockout_and_reset():
    store = StepUpAttempts()
    key = "user:1"
    for _ in range(5):
        store.record_failed_attempt(key)
    assert store.is_locked_out(key) is True
    store.reset_attempts(key)
    assert store.is_locked_out(key) is False
