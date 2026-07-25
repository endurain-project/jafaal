"""Tests for the password-reset and sign-up single-use token flows."""

import asyncio

import pytest

import jafaal
import jafaal.credentials.crud as credentials_crud
import jafaal.exceptions as exc
import jafaal.password_reset_tokens.crud as prt_crud
import jafaal.password_reset_tokens.utils as prt_utils
import jafaal.sign_up_tokens.crud as sut_crud
import jafaal.sign_up_tokens.utils as sut_utils
import jafaal.token_hashing as token_hashing
from jafaal._internal.password_hasher import get_password_hasher, password_hasher
from jafaal._internal.token_manager import get_token_manager
from jafaal.identity_service import DefaultIdentityService
from jafaal.schema import SignUpRequest


def _identity_service(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


# --------------------------------------------------------------------------- #
# Password reset
# --------------------------------------------------------------------------- #


def test_password_reset_claim_is_atomic_single_use(db, make_user):
    user = make_user()
    token, _ = prt_utils.create_password_reset_token(user.id, db)
    digests = token_hashing.legacy_lookup_digests(token, token_hashing.KeyPurpose.PASSWORD_RESET)
    assert prt_crud.claim_password_reset_token(digests, db) == user.id
    # A second claim of the same token finds nothing (already used).
    assert prt_crud.claim_password_reset_token(digests, db) is None


def test_use_password_reset_token_updates_credential(db, make_user):
    user = make_user(password="Old1!Pass")
    token, _ = prt_utils.create_password_reset_token(user.id, db)
    prt_utils.use_password_reset_token(token, "New1!Passw", _identity_service(db), db)

    cred = credentials_crud.get_credential(user.id, db)
    assert password_hasher.verify_password("New1!Passw", cred.password_hash)
    # Token is consumed.
    digests = token_hashing.legacy_lookup_digests(token, token_hashing.KeyPurpose.PASSWORD_RESET)
    assert prt_crud.claim_password_reset_token(digests, db) is None


def test_use_password_reset_token_rejects_invalid(db):
    with pytest.raises(exc.InvalidRequestError):
        prt_utils.use_password_reset_token("bogus", "New1!Passw", _identity_service(db), db)


def test_request_password_reset_emits_event_for_active_user(db, make_user, event_sink):
    user = make_user()
    asyncio.run(prt_utils.request_password_reset(user.email, db))
    assert len(event_sink.events) == 1
    assert event_sink.events[0].user_id == user.id
    assert event_sink.events[0].token  # plaintext token carried for delivery


def test_request_password_reset_is_enumeration_safe(db, event_sink):
    asyncio.run(prt_utils.request_password_reset("nobody@nowhere.test", db))
    assert event_sink.events == []


def test_request_password_reset_swallows_delivery_failure(db, make_user):
    class BoomSink:
        async def on_password_reset_requested(self, event):
            raise RuntimeError("delivery down")

        async def on_email_verification_requested(self, event): ...
        async def on_signup_pending_admin_approval(self, event): ...
        async def on_signup_approved(self, event): ...

    user = make_user()
    jafaal.configure_event_sink(BoomSink())
    try:
        # Must not raise despite the sink failing (enumeration-safe contract).
        asyncio.run(prt_utils.request_password_reset(user.email, db))
    finally:
        jafaal.configure_event_sink(jafaal.NullAuthEventSink())


# --------------------------------------------------------------------------- #
# Sign-up
# --------------------------------------------------------------------------- #


def test_sign_up_claim_is_atomic_single_use(db, make_user):
    user = make_user()
    token, _ = sut_utils.create_sign_up_token(user.id, db)
    digests = token_hashing.legacy_lookup_digests(token, token_hashing.KeyPurpose.SIGN_UP)
    assert sut_crud.claim_sign_up_token(digests, db) == user.id
    assert sut_crud.claim_sign_up_token(digests, db) is None


def test_use_sign_up_token_consumes_once(db, make_user):
    user = make_user()
    token, _ = sut_utils.create_sign_up_token(user.id, db)
    assert sut_utils.use_sign_up_token(token, db) == user.id
    with pytest.raises(exc.InvalidRequestError):
        sut_utils.use_sign_up_token(token, db)


def test_use_sign_up_token_rejects_invalid(db):
    with pytest.raises(exc.InvalidRequestError):
        sut_utils.use_sign_up_token("bogus", db)


def test_register_local_user_and_email_verification_event(db, event_sink):
    req = SignUpRequest(username="bob", email="bob@test.dev", password="Str0ng!Pass")
    signup = jafaal.SignupConfig(enabled=True, require_email_verification=True, require_admin_approval=False)
    user = sut_utils.register_local_user(req, signup, _identity_service(db), db)
    assert user.username == "bob"
    # Verification required → account not yet usable.
    assert user.is_active is False
    assert user.is_verified is False
    # Credential was persisted by JAFAAL.
    assert credentials_crud.get_credential(user.id, db) is not None

    asyncio.run(sut_utils.request_email_verification(user, db))
    assert len(event_sink.events) == 1
    assert event_sink.events[0].email == "bob@test.dev"
