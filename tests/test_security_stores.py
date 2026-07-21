"""Tests for the progressive-lockout security stores (login, MFA, step-up)."""

from jafaal._internal.security_stores import (
    FailedLoginAttempts,
    PendingMFALogin,
    StepUpAttempts,
    normalize_username_key,
    username_log_identifier,
)


def test_normalize_username_key():
    assert normalize_username_key("  Alice  ") == "alice"
    assert normalize_username_key("A+B") == "a b"  # '+' decodes to space
    assert normalize_username_key("Bob%20Smith") == "bob smith"  # url-decoded


def test_username_log_identifier_is_hashed():
    ident = username_log_identifier("alice")
    assert ident.startswith("username_hash=")
    assert "alice" not in ident  # non-reversible


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
