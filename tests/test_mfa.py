"""Tests for MFA: TOTP verification, replay protection, and backup codes."""

import time

import pyotp

import jafaal.mfa.crud as mfa_crud
import jafaal.mfa.service as mfa_service
from jafaal._core import crypto
from jafaal._internal.password_hasher import get_password_hasher
from jafaal._internal.token_manager import get_token_manager
from jafaal.identity_service import DefaultIdentityService


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
