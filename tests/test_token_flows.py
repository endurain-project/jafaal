"""Tests for the password-reset and sign-up single-use token flows."""

import asyncio
import threading

import pytest

import jafaal
import jafaal.credentials.crud as credentials_crud
import jafaal.exceptions as exc
import jafaal.orm as jafaal_orm
import jafaal.password_reset_tokens.crud as prt_crud
import jafaal.password_reset_tokens.utils as prt_utils
import jafaal.sign_up_tokens.crud as sut_crud
import jafaal.sign_up_tokens.status_store as sut_status_store
import jafaal.sign_up_tokens.utils as sut_utils
import jafaal.token_hashing as token_hashing
from jafaal._internal.password_hasher import get_password_hasher, password_hasher
from jafaal._internal.token_manager import get_token_manager
from jafaal.identity_service import DefaultIdentityService
from jafaal.schema import SignUpRequest


def _identity_service(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _run_claim_race(concurrent_db, claim, workers=8):
    barrier = threading.Barrier(workers)
    results: list[object] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def attempt():
        try:
            with concurrent_db.session() as session, jafaal_orm.unit_of_work(session):
                barrier.wait()
                result = claim(session)
        except BaseException as error:
            with lock:
                errors.append(error)
        else:
            with lock:
                results.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not [thread for thread in threads if thread.is_alive()]
    assert errors == []
    return results


# --------------------------------------------------------------------------- #
# Password reset
# --------------------------------------------------------------------------- #


def test_password_reset_claim_is_atomic_single_use(db, make_user):
    user = make_user()
    token, _ = prt_utils.create_password_reset_token(user.id, db)
    token_hash = token_hashing.hmac_sha256(token, token_hashing.KeyPurpose.PASSWORD_RESET)
    assert prt_crud.claim_password_reset_token(token_hash, db) == user.id
    # A second claim of the same token finds nothing (already used).
    assert prt_crud.claim_password_reset_token(token_hash, db) is None


def test_password_reset_claim_has_one_winner_under_real_concurrency(concurrent_db):
    with concurrent_db.session() as setup, jafaal_orm.unit_of_work(setup):
        token, _ = prt_utils.create_password_reset_token(concurrent_db.user_id, setup)
    token_hash = token_hashing.hmac_sha256(token, token_hashing.KeyPurpose.PASSWORD_RESET)

    results = _run_claim_race(
        concurrent_db,
        lambda session: prt_crud.claim_password_reset_token(token_hash, session),
    )

    assert results.count(concurrent_db.user_id) == 1
    assert results.count(None) == len(results) - 1


def test_use_password_reset_token_updates_credential(db, make_user):
    user = make_user(password="Old1!Pass")
    token, _ = prt_utils.create_password_reset_token(user.id, db)
    prt_utils.use_password_reset_token(token, "New1!Passw", _identity_service(db), db)

    cred = credentials_crud.get_credential(user.id, db)
    assert password_hasher.verify_password("New1!Passw", cred.password_hash)
    # Token is consumed.
    token_hash = token_hashing.hmac_sha256(token, token_hashing.KeyPurpose.PASSWORD_RESET)
    assert prt_crud.claim_password_reset_token(token_hash, db) is None


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
    token_hash = token_hashing.hmac_sha256(token, token_hashing.KeyPurpose.SIGN_UP)
    assert sut_crud.claim_sign_up_token(token_hash, db) == user.id
    assert sut_crud.claim_sign_up_token(token_hash, db) is None


def test_sign_up_claim_has_one_winner_under_real_concurrency(concurrent_db):
    with concurrent_db.session() as setup, jafaal_orm.unit_of_work(setup):
        token, _ = sut_utils.create_sign_up_token(concurrent_db.user_id, setup)
    token_hash = token_hashing.hmac_sha256(token, token_hashing.KeyPurpose.SIGN_UP)

    results = _run_claim_race(
        concurrent_db,
        lambda session: sut_crud.claim_sign_up_token(token_hash, session),
    )

    assert results.count(concurrent_db.user_id) == 1
    assert results.count(None) == len(results) - 1


def test_use_sign_up_token_consumes_once(db, make_user):
    user = make_user()
    token, _ = sut_utils.create_sign_up_token(user.id, db)
    assert sut_utils.use_sign_up_token(token, db) == user.id
    with pytest.raises(exc.InvalidRequestError):
        sut_utils.use_sign_up_token(token, db)


def test_use_sign_up_token_rejects_invalid(db):
    with pytest.raises(exc.InvalidRequestError):
        sut_utils.use_sign_up_token("bogus", db)


def test_sign_up_status_store_issues_opaque_real_and_decoy_handles():
    state = jafaal.InMemoryStateStore()
    store = sut_status_store.SignUpStatusStore(state)

    real_handle = store.create("token-row-id", ttl_seconds=60)
    decoy_handle = store.create(None, ttl_seconds=60)

    assert len(real_handle) >= 32
    assert len(decoy_handle) >= 32
    assert real_handle != decoy_handle
    assert store.resolve(real_handle) == (True, "token-row-id")
    assert store.resolve(decoy_handle) == (True, None)
    assert all(real_handle not in key and decoy_handle not in key for key in state.iter_keys(""))


def test_sign_up_status_store_expires_handles():
    store = sut_status_store.SignUpStatusStore(jafaal.InMemoryStateStore())
    handle = store.create("token-row-id", ttl_seconds=0)

    assert store.resolve(handle) == (False, None)


def test_sign_up_status_store_wraps_backend_outages():
    class UnavailableStateStore(jafaal.InMemoryStateStore):
        def set(self, key, value, ttl_seconds=None):
            raise jafaal.StateStoreUnavailableError("unavailable")

        def get(self, key):
            raise jafaal.StateStoreUnavailableError("unavailable")

    store = sut_status_store.SignUpStatusStore(UnavailableStateStore())

    with pytest.raises(sut_status_store.SignUpStatusStoreUnavailableError):
        store.create(None, ttl_seconds=60)
    with pytest.raises(sut_status_store.SignUpStatusStoreUnavailableError):
        store.resolve("unknown")


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
