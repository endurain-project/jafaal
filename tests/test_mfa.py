"""Tests for MFA: TOTP verification, replay protection, and backup codes."""

import dataclasses
import threading
import time

import pyotp
import pytest

import jafaal
import jafaal.mfa.crud as mfa_crud
import jafaal.mfa.service as mfa_service
from jafaal._core import crypto
from jafaal._internal.password_hasher import get_password_hasher
from jafaal._internal.token_manager import get_token_manager
from jafaal.exceptions import StoreUnavailableError
from jafaal.identity_service import DefaultIdentityService
from jafaal.state_store import StateStoreUnavailableError


class _FailingStateStore:
    """A ``StateStore`` whose reads/writes always raise (simulates an outage)."""

    def get(self, key):
        raise StateStoreUnavailableError("down")

    def set(self, key, value, ttl_seconds=None):
        raise StateStoreUnavailableError("down")

    def delete(self, key):
        raise StateStoreUnavailableError("down")

    def delete_prefix(self, prefix):
        raise StateStoreUnavailableError("down")

    def get_and_delete(self, key):
        raise StateStoreUnavailableError("down")

    def set_if_absent(self, key, value, ttl_seconds):
        raise StateStoreUnavailableError("down")

    def increment(self, key, ttl_seconds):
        raise StateStoreUnavailableError("down")

    def iter_keys(self, prefix):
        raise StateStoreUnavailableError("down")

    def record_tiered_failure(self, counter_key, gate_key, tiers, counter_ttl_seconds):
        raise StateStoreUnavailableError("down")


def _identity_service(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _enable_mfa(user_id, db, secret):
    mfa_crud.update_user_mfa(user_id, db, encrypted_secret=crypto.encrypt_token_fernet(secret))


def test_generate_totp_secret():
    secret = mfa_service.generate_totp_secret()
    assert isinstance(secret, str) and len(secret) >= 16


def test_verify_totp_accepts_current_rejects_old():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    assert mfa_service.verify_totp(secret, totp.now()) is True
    # A code from 10 steps ago is outside the ±1 window.
    old_code = totp.at(int(time.time()) - 300)
    assert mfa_service.verify_totp(secret, old_code) is False


def test_matched_timestep_returns_counter_or_none():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    ts = mfa_service._matched_totp_timestep(secret, totp.now())
    assert ts == int(time.time()) // totp.interval
    assert mfa_service._matched_totp_timestep(secret, totp.at(int(time.time()) - 300)) is None


def test_totp_replay_is_rejected(db, make_user):
    user = make_user()
    secret = pyotp.random_base32()
    _enable_mfa(user.id, db, secret)
    identity_service = _identity_service(db)

    code = pyotp.TOTP(secret).now()
    # First use of a valid code succeeds.
    assert mfa_service.verify_user_mfa(user.id, code, identity_service, db) is True
    # Replaying the same code within its window is rejected.
    assert mfa_service.verify_user_mfa(user.id, code, identity_service, db) is False


def test_totp_replay_fails_closed_on_store_outage(db, make_user):
    # Default policy: if the replay-protection store is down, a TOTP code cannot
    # be verified single-use, so the request fails closed (503) rather than
    # accepting a potentially-replayed code.
    user = make_user()
    secret = pyotp.random_base32()
    _enable_mfa(user.id, db, secret)
    identity_service = _identity_service(db)
    code = pyotp.TOTP(secret).now()

    jafaal.configure_state_store(_FailingStateStore())
    try:
        with pytest.raises(StoreUnavailableError):
            mfa_service.verify_user_mfa(user.id, code, identity_service, db)
    finally:
        jafaal.reset_state_store()


def test_concurrent_use_of_one_totp_code_has_exactly_one_winner(concurrent_db):
    # Single-use enforcement must be a *claim*, not a check followed by a write:
    # under genuine parallelism a get/set pair lets several callers all observe
    # "unused" and all succeed, which is exactly the replay the guard exists to
    # stop. The ``concurrent_db`` fixture gives each thread its own real
    # connection, so the verifications genuinely overlap.
    secret = pyotp.random_base32()
    with concurrent_db.session() as setup:
        _enable_mfa(concurrent_db.user_id, setup, secret)
    code = pyotp.TOTP(secret).now()

    workers = 16
    barrier = threading.Barrier(workers)
    results: list[bool] = []
    lock = threading.Lock()

    def attempt():
        with concurrent_db.session() as session:
            identity_service = _identity_service(session)
            barrier.wait()  # maximise contention: all threads verify at once
            outcome = mfa_service.verify_user_mfa(concurrent_db.user_id, code, identity_service, session)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == workers
    assert sum(1 for accepted in results if accepted) == 1


def test_totp_replay_fail_open_when_configured(db, make_user):
    # Opt-in policy: prefer availability — accept the code despite the outage.
    user = make_user()
    secret = pyotp.random_base32()
    _enable_mfa(user.id, db, secret)
    identity_service = _identity_service(db)
    code = pyotp.TOTP(secret).now()

    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, mfa_totp_replay_fail_open=True))
    jafaal.configure_state_store(_FailingStateStore())
    try:
        assert mfa_service.verify_user_mfa(user.id, code, identity_service, db) is True
    finally:
        jafaal.configure(original)
        jafaal.reset_state_store()


def test_verify_user_mfa_rejects_wrong_code(db, make_user):
    user = make_user()
    secret = pyotp.random_base32()
    _enable_mfa(user.id, db, secret)
    identity_service = _identity_service(db)
    old_code = pyotp.TOTP(secret).at(int(time.time()) - 300)
    assert mfa_service.verify_user_mfa(user.id, old_code, identity_service, db) is False


def test_verify_user_mfa_false_when_disabled(db, make_user):
    user = make_user()
    identity_service = _identity_service(db)
    assert mfa_service.is_mfa_enabled_for_user(user.id, db) is False
    assert mfa_service.verify_user_mfa(user.id, "123456", identity_service, db) is False


def test_setup_user_mfa_returns_secret_and_qr(db, make_user):
    user = make_user()
    resp = mfa_service.setup_user_mfa(user.id, db)
    assert resp.secret
    assert resp.qr_code.startswith("data:image/png;base64,")
    assert resp.app_name == "Test"


def test_enable_and_consume_backup_code(db, make_user):
    user = make_user()
    secret = pyotp.random_base32()
    identity_service = _identity_service(db)
    code = pyotp.TOTP(secret).now()

    backup_codes = mfa_service.enable_user_mfa(user.id, secret, code, identity_service, db)
    assert backup_codes and all("-" in c for c in backup_codes)
    assert mfa_service.is_mfa_enabled_for_user(user.id, db) is True

    # A backup code verifies once, then is consumed (single-use).
    one = backup_codes[0]
    assert mfa_service.verify_user_mfa(user.id, one, identity_service, db) is True
    assert mfa_service.verify_user_mfa(user.id, one, identity_service, db) is False


def test_enable_rejects_bad_setup_code(db, make_user):
    import jafaal.exceptions as exc

    user = make_user()
    secret = pyotp.random_base32()
    identity_service = _identity_service(db)
    bad = pyotp.TOTP(secret).at(int(time.time()) - 300)
    try:
        mfa_service.enable_user_mfa(user.id, secret, bad, identity_service, db)
        raised = False
    except exc.InvalidMFACodeError:
        raised = True
    assert raised
