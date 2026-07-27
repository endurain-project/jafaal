"""Tests for MFA backup codes, the MFA setup-secret store, and step-up verification."""

import pyotp
import pytest
from conftest import replace_settings

import jafaal.exceptions as exc
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.schema as idp_schema
import jafaal.mfa.backup_codes.crud as backup_codes_crud
import jafaal.mfa.crud as mfa_crud
from jafaal._core import crypto
from jafaal._internal.password_hasher import get_password_hasher, password_hasher
from jafaal._internal.security_stores import StepUpAttempts, grant_step_up_reauth
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


def test_step_up_denied_when_no_password_and_no_mfa(db, make_user):
    # Fail closed: an SSO-only account with no MFA has no factor to verify, so a
    # valid access token alone must NOT satisfy step-up. The denial is a
    # deterministic account-state check (403), so repeating it never trips the
    # progressive-lockout counter (which would otherwise surface as 429).
    user = make_user(password=None)
    store = StepUpAttempts()
    for _ in range(10):
        with pytest.raises(exc.AuthorizationError):
            verify_step_up_credentials(user.id, None, None, _svc(db), store, db)


def test_step_up_bootstrap_allows_sso_only_no_factor(db, make_user):
    # The MFA-enrolment bootstrap is the one permitted exception, so an SSO-only
    # user can establish their first factor (enable_mfa then proves the freshly
    # enrolled TOTP code itself).
    user = make_user(password=None)
    assert (
        verify_step_up_credentials(user.id, None, None, _svc(db), StepUpAttempts(), db, allow_sso_only_bootstrap=True)
        is None
    )


def test_step_up_bootstrap_still_verifies_existing_password(db, make_user):
    # The bootstrap flag must never weaken an account that DOES have a password:
    # enabling MFA on a password account still requires the current password.
    user = make_user(password="Str0ng!Pass")
    with pytest.raises(exc.InvalidCredentialsError):
        verify_step_up_credentials(
            user.id, "WRONG", None, _svc(db), StepUpAttempts(), db, allow_sso_only_bootstrap=True
        )


def test_step_up_sso_only_account_satisfies_via_mfa(db, make_user):
    # Post-bootstrap path: an SSO-only account that has enrolled MFA can step up
    # with its TOTP code alone (no password needed, MFA is the factor).
    user = make_user(password=None)
    secret = pyotp.random_base32()
    _enable_mfa(user.id, db, secret)
    code = pyotp.TOTP(secret).now()
    assert verify_step_up_credentials(user.id, None, code, _svc(db), StepUpAttempts(), db) is None


def _link_idp(db, user, *, slug="oidc"):
    idp = idp_crud.create_identity_provider(
        idp_schema.IdentityProviderCreate(
            name=f"IdP {slug}", slug=slug, client_id="cid", client_secret="secret", enabled=True
        ),
        db,
    )
    links_crud.create_user_identity_provider(user.id, idp.id, f"sub-{slug}", db)
    return idp


def test_step_up_satisfied_by_reauth_grant(db, make_user):
    # A fresh IdP re-auth grant satisfies step-up even for an SSO-only account
    # with no local password and no MFA (the second factor is delegated to, and
    # freshly asserted by, the identity provider).
    user = make_user(password=None)
    grant_step_up_reauth(user.id, idp_id=1, ttl_seconds=120)
    assert verify_step_up_credentials(user.id, None, None, _svc(db), StepUpAttempts(), db) is None


def test_step_up_reauth_grant_is_single_use(db, make_user):
    # Consuming the grant authorises exactly one operation; with no link, a
    # second attempt falls through to the fail-closed denial.
    user = make_user(password=None)
    grant_step_up_reauth(user.id, idp_id=1, ttl_seconds=120)
    assert verify_step_up_credentials(user.id, None, None, _svc(db), StepUpAttempts(), db) is None
    with pytest.raises(exc.AuthorizationError):
        verify_step_up_credentials(user.id, None, None, _svc(db), StepUpAttempts(), db)


def test_step_up_challenges_reauth_for_sso_only_with_link(db, make_user):
    # An SSO-only account with a usable IdP link is challenged to re-authenticate
    # (rather than failing closed) when it has no local factor.
    user = make_user(password=None)
    idp = _link_idp(db, user)
    with pytest.raises(exc.StepUpReauthRequiredError) as excinfo:
        verify_step_up_credentials(user.id, None, None, _svc(db), StepUpAttempts(), db)
    assert idp.id in excinfo.value.reauth_idp_ids


def test_step_up_reauth_grant_takes_precedence_over_challenge(db, make_user):
    # With a grant present, step-up passes without a challenge even when the
    # account also has an IdP link.
    user = make_user(password=None)
    _link_idp(db, user)
    grant_step_up_reauth(user.id, idp_id=1, ttl_seconds=120)
    assert verify_step_up_credentials(user.id, None, None, _svc(db), StepUpAttempts(), db) is None


def test_step_up_reauth_disabled_falls_back_to_fail_closed(db, make_user):
    # When IdP step-up re-auth is disabled, an SSO-only account with a link is
    # NOT challenged — it fails closed (403), the same as one with no link.

    import jafaal

    user = make_user(password=None)
    _link_idp(db, user)
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, step_up_idp_reauth_enabled=False))
    try:
        with pytest.raises(exc.AuthorizationError):
            verify_step_up_credentials(user.id, None, None, _svc(db), StepUpAttempts(), db)
    finally:
        jafaal.configure(original)
