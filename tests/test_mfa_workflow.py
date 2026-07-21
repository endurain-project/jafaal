"""Tests for the route-facing MFA workflow orchestration."""

import time

import pyotp
import pytest

import jafaal._internal.services.mfa_workflow as mfa_workflow
import jafaal.exceptions as exc
import jafaal.mfa.crud as mfa_crud
import jafaal.mfa.schema as mfa_schema
import jafaal.mfa.service as mfa_service
import jafaal.schema as jafaal_schema
from jafaal._core import crypto
from jafaal._internal.password_hasher import get_password_hasher
from jafaal._internal.security_stores import StepUpAttempts
from jafaal._internal.token_manager import get_token_manager
from jafaal.identity_service import DefaultIdentityService
from jafaal.mfa.setup_store import MFASecretStore


def _svc(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _enable_mfa_direct(user_id, db, secret):
    mfa_crud.update_user_mfa(user_id, db, encrypted_secret=crypto.encrypt_token_fernet(secret))


def test_get_mfa_status(db, make_user):
    user = make_user()
    assert mfa_workflow.get_mfa_status(user.id, db).mfa_enabled is False
    _enable_mfa_direct(user.id, db, pyotp.random_base32())
    assert mfa_workflow.get_mfa_status(user.id, db).mfa_enabled is True


def test_backup_code_status_when_none(db, make_user):
    user = make_user()
    status = mfa_workflow.get_backup_code_status(user.id, db)
    assert status.has_codes is False
    assert status.total == 0


def test_setup_then_enable_mfa(db, make_user):
    user = make_user(password="Str0ng!Pass")
    store = MFASecretStore()

    resp = mfa_workflow.setup_mfa(user.id, db, store)
    assert resp.secret
    assert store.has_secret(user.id) is True

    code = pyotp.TOTP(resp.secret).now()
    result = mfa_workflow.enable_mfa(
        mfa_schema.MFASetupRequest(current_password="Str0ng!Pass", mfa_code=code),
        user.id,
        _svc(db),
        StepUpAttempts(),
        db,
        store,
    )
    assert result["backup_codes"]
    assert mfa_service.is_mfa_enabled_for_user(user.id, db) is True
    # Pending setup secret is consumed on success.
    assert store.has_secret(user.id) is False


def test_enable_mfa_wrong_code_keeps_pending_secret(db, make_user):
    user = make_user(password="Str0ng!Pass")
    store = MFASecretStore()
    resp = mfa_workflow.setup_mfa(user.id, db, store)
    wrong = pyotp.TOTP(resp.secret).at(int(time.time()) - 300)

    with pytest.raises(exc.InvalidMFACodeError):
        mfa_workflow.enable_mfa(
            mfa_schema.MFASetupRequest(current_password="Str0ng!Pass", mfa_code=wrong),
            user.id,
            _svc(db),
            StepUpAttempts(),
            db,
            store,
        )
    # Retained so the user can retry.
    assert store.has_secret(user.id) is True


def test_enable_mfa_without_setup_fails(db, make_user):
    user = make_user(password="Str0ng!Pass")
    store = MFASecretStore()
    code = pyotp.TOTP(pyotp.random_base32()).now()
    with pytest.raises(exc.InvalidRequestError):
        mfa_workflow.enable_mfa(
            mfa_schema.MFASetupRequest(current_password="Str0ng!Pass", mfa_code=code),
            user.id,
            _svc(db),
            StepUpAttempts(),
            db,
            store,
        )


def test_disable_mfa(db, make_user):
    user = make_user(password="Str0ng!Pass")
    secret = pyotp.random_base32()
    _enable_mfa_direct(user.id, db, secret)

    result = mfa_workflow.disable_mfa(
        mfa_schema.MFADisableRequest(current_password="Str0ng!Pass", mfa_code=pyotp.TOTP(secret).now()),
        user.id,
        _svc(db),
        StepUpAttempts(),
        db,
    )
    assert "disabled" in result["message"].lower()
    assert mfa_service.is_mfa_enabled_for_user(user.id, db) is False


def test_verify_mfa_valid(db, make_user):
    user = make_user()
    secret = pyotp.random_base32()
    _enable_mfa_direct(user.id, db, secret)
    result = mfa_workflow.verify_mfa(
        mfa_schema.MFARequest(mfa_code=pyotp.TOTP(secret).now()),
        user.id,
        _svc(db),
        db,
    )
    assert "verified" in result["message"].lower()


def test_verify_mfa_invalid(db, make_user):
    user = make_user()
    secret = pyotp.random_base32()
    _enable_mfa_direct(user.id, db, secret)
    wrong = pyotp.TOTP(secret).at(int(time.time()) - 300)
    with pytest.raises(exc.InvalidMFACodeError):
        mfa_workflow.verify_mfa(mfa_schema.MFARequest(mfa_code=wrong), user.id, _svc(db), db)


def test_generate_backup_codes_requires_mfa_enabled(db, make_user):
    user = make_user(password="Str0ng!Pass")
    with pytest.raises(exc.InvalidRequestError):
        mfa_workflow.generate_backup_codes(
            jafaal_schema.StepUpVerification(current_password="Str0ng!Pass", mfa_code=None),
            user.id,
            _svc(db),
            StepUpAttempts(),
            db,
        )


def test_generate_backup_codes_success(db, make_user):
    user = make_user(password="Str0ng!Pass")
    secret = pyotp.random_base32()
    _enable_mfa_direct(user.id, db, secret)
    result = mfa_workflow.generate_backup_codes(
        jafaal_schema.StepUpVerification(current_password="Str0ng!Pass", mfa_code=pyotp.TOTP(secret).now()),
        user.id,
        _svc(db),
        StepUpAttempts(),
        db,
    )
    assert len(result.codes) > 0
