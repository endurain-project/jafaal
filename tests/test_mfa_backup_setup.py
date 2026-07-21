"""Tests for MFA backup codes, the MFA setup-secret store, and step-up verification."""

import pyotp
import pytest

import jafaal.exceptions as exc
import jafaal.mfa.backup_codes.crud as backup_codes_crud
import jafaal.mfa.crud as mfa_crud
from jafaal._core import crypto
from jafaal._internal.password_hasher import get_password_hasher, password_hasher
from jafaal._internal.security_stores import StepUpAttempts
from jafaal._internal.services.step_up_service import verify_step_up_credentials
from jafaal._internal.token_manager import get_token_manager
from jafaal.identity_service import DefaultIdentityService
from jafaal.mfa.backup_codes.utils import generate_backup_code, verify_and_consume_backup_code
from jafaal.mfa.setup_store import MFASecretStore


def _svc(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _enable_mfa(user_id, db, secret):
    mfa_crud.update_user_mfa(user_id, db, encrypted_secret=crypto.encrypt_token_fernet(secret))


# --------------------------------------------------------------------------- #
# Backup codes
# --------------------------------------------------------------------------- #


def test_generate_backup_code_format():
    code = generate_backup_code()
    assert len(code) == 9
    assert code[4] == "-"
    # No visually ambiguous characters.
    assert not set("01OI") & set(code.replace("-", ""))


def test_backup_code_verify_and_single_use(db, make_user):
    user = make_user()
    codes = backup_codes_crud.create_backup_codes(user.id, _svc(db), db)
    assert codes

    # A valid code verifies once...
    assert verify_and_consume_backup_code(user.id, codes[0], password_hasher, db) is True
    # ...and is then consumed (single-use).
    assert verify_and_consume_backup_code(user.id, codes[0], password_hasher, db) is False


def test_backup_code_rejects_unknown_code(db, make_user):
    user = make_user()
    backup_codes_crud.create_backup_codes(user.id, _svc(db), db)
    assert verify_and_consume_backup_code(user.id, "ZZZZ-ZZZZ", password_hasher, db) is False


# --------------------------------------------------------------------------- #
# MFA setup-secret store
# --------------------------------------------------------------------------- #


def test_mfa_setup_store_add_get_delete():
    store = MFASecretStore()
    assert store.has_secret(1) is False
    assert store.get_secret(1) is None

    store.add_secret(1, "JBSWY3DPEHPK3PXP")
    assert store.has_secret(1) is True
    assert store.get_secret(1) == "JBSWY3DPEHPK3PXP"

    store.delete_secret(1)
    assert store.has_secret(1) is False


def test_mfa_setup_store_clear_all():
    store = MFASecretStore()
    store.add_secret(1, "AAAA")
    store.add_secret(2, "BBBB")
    store.clear_all()
    assert store.has_secret(1) is False
    assert store.has_secret(2) is False


# --------------------------------------------------------------------------- #
# Step-up verification
# --------------------------------------------------------------------------- #


def test_step_up_success_password_only(db, make_user):
    user = make_user(password="Str0ng!Pass")
    # No MFA → password alone suffices; returns None on success.
    assert verify_step_up_credentials(user.id, "Str0ng!Pass", None, _svc(db), StepUpAttempts(), db) is None


def test_step_up_wrong_password(db, make_user):
    user = make_user(password="Str0ng!Pass")
    with pytest.raises(exc.InvalidCredentialsError):
        verify_step_up_credentials(user.id, "WRONG", None, _svc(db), StepUpAttempts(), db)


def test_step_up_missing_password_when_account_has_one(db, make_user):
    user = make_user(password="Str0ng!Pass")
    with pytest.raises(exc.InvalidCredentialsError):
        verify_step_up_credentials(user.id, None, None, _svc(db), StepUpAttempts(), db)


def test_step_up_requires_mfa_code_when_enabled(db, make_user):
    user = make_user(password="Str0ng!Pass")
    _enable_mfa(user.id, db, pyotp.random_base32())
    with pytest.raises(exc.AuthenticationError):
        verify_step_up_credentials(user.id, "Str0ng!Pass", None, _svc(db), StepUpAttempts(), db)


def test_step_up_accepts_valid_totp(db, make_user):
    user = make_user(password="Str0ng!Pass")
    secret = pyotp.random_base32()
    _enable_mfa(user.id, db, secret)
    code = pyotp.TOTP(secret).now()
    assert verify_step_up_credentials(user.id, "Str0ng!Pass", code, _svc(db), StepUpAttempts(), db) is None


def test_step_up_locks_out_after_repeated_failures(db, make_user):
    user = make_user(password="Str0ng!Pass")
    store = StepUpAttempts()
    svc = _svc(db)
    for _ in range(5):
        with pytest.raises(exc.InvalidCredentialsError):
            verify_step_up_credentials(user.id, "WRONG", None, svc, store, db)
    # Now locked out → 429 before any credential comparison.
    with pytest.raises(exc.RateLimitedError):
        verify_step_up_credentials(user.id, "Str0ng!Pass", None, svc, store, db)
