"""Tests for transaction ownership: JAFAAL flushes, the caller commits.

The contract these pin down is the one a host has to be able to rely on:

* every JAFAAL function that takes a ``Session`` participates in the caller's
  transaction and never commits, so the host can compose JAFAAL's writes with
  its own into one atomic unit;
* JAFAAL's own endpoints commit exactly once per request, via the
  :class:`~jafaal.orm.TransactionalRoute` route class every router is built
  with — so a *new* endpoint cannot forget to;
* a failing request rolls everything back; and
* the few writes whose durability must not depend on the request succeeding
  (single-use claims, theft revocation) run in their own transaction.
"""

import threading

import pytest
from conftest import Users
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import jafaal
import jafaal.identity_providers.links.crud as links_crud
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.utils as oauth_state_utils
import jafaal.orm as jafaal_orm
import jafaal.sessions.crud as sessions_crud
import jafaal.sessions.rotated_refresh_tokens.utils as rotated_utils


def _session():
    return jafaal_orm.get_sessionmaker()()


# --------------------------------------------------------------------------- #
# CRUD never commits
# --------------------------------------------------------------------------- #


def test_crud_writes_are_invisible_until_the_caller_commits(concurrent_db):
    """A JAFAAL write must not be durable until the *caller* says so.

    This is the whole point of the contract: if CRUD committed on its own, a
    host could not roll back a JAFAAL write when its own later step failed.

    Uses ``concurrent_db`` because the suite's default engine is in-memory
    SQLite behind a ``StaticPool`` — one connection shared by every session, so
    an "observer" there would see uncommitted rows and the assertion would be
    vacuous.
    """
    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()

    writer = concurrent_db.session()
    try:
        oauth_state_crud.create_oauth_state(
            db=writer,
            state_id=state_id,
            nonce=nonce,
            ip_address=None,
            user_id=concurrent_db.user_id,
        )
        # Written and flushed, but not committed: another connection sees nothing.
        with concurrent_db.session() as observer:
            assert oauth_state_crud.get_oauth_state_by_id_and_not_used(state_id, observer) is None
        writer.commit()
    finally:
        writer.close()

    with concurrent_db.session() as observer:
        assert oauth_state_crud.get_oauth_state_by_id_and_not_used(state_id, observer) is not None


def test_host_can_roll_back_a_jafaal_write_with_its_own(make_user):
    """A host failure after a JAFAAL call must undo the JAFAAL write too."""
    user = make_user(username="dave")
    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()

    session = _session()
    try:
        with pytest.raises(RuntimeError), jafaal_orm.unit_of_work(session):
            oauth_state_crud.create_oauth_state(
                db=session,
                state_id=state_id,
                nonce=nonce,
                ip_address=None,
                user_id=user.id,
            )
            raise RuntimeError("host step failed")
    finally:
        session.close()

    with _session() as observer:
        assert oauth_state_crud.get_oauth_state_by_id_and_not_used(state_id, observer) is None


def test_unit_of_work_is_reentrant(make_user):
    """An inner scope joins the outer one; only the outermost decides."""
    user = make_user(username="erin")
    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()

    session = _session()
    try:
        with pytest.raises(RuntimeError), jafaal_orm.unit_of_work(session):
            with jafaal_orm.unit_of_work(session):
                oauth_state_crud.create_oauth_state(
                    db=session,
                    state_id=state_id,
                    nonce=nonce,
                    ip_address=None,
                    user_id=user.id,
                )
            # The inner block exiting cleanly must NOT have committed, so the
            # outer failure can still undo its write.
            raise RuntimeError("outer failed")
    finally:
        session.close()

    with _session() as observer:
        assert oauth_state_crud.get_oauth_state_by_id_and_not_used(state_id, observer) is None


# --------------------------------------------------------------------------- #
# Savepoints keep a caught IntegrityError recoverable
# --------------------------------------------------------------------------- #


def test_duplicate_idp_link_is_a_conflict_without_losing_the_hosts_work(make_user):
    """Catching a constraint violation must not discard the caller's writes.

    ``create_user_identity_provider`` translates a UNIQUE violation into a 409.
    It brackets the flush in a savepoint precisely so that the surrounding
    transaction — which may already hold host writes — survives.
    """
    user = make_user(username="frank")
    session = _session()
    try:
        with jafaal_orm.unit_of_work(session):
            links_crud.create_user_identity_provider(user.id, 1, "subject-1", session)

        with jafaal_orm.unit_of_work(session):
            # A host write that must survive the caught conflict below.
            session.add(Users(username="host-row", email="host-row@test.dev", is_active=True, is_verified=True))
            session.flush()

            with pytest.raises(jafaal.ConflictError):
                links_crud.create_user_identity_provider(user.id, 1, "subject-1", session)
    finally:
        session.close()

    with _session() as observer:
        assert observer.query(Users).filter(Users.username == "host-row").one_or_none() is not None


def test_savepoint_rolls_back_only_its_own_block(make_user):
    make_user(username="grace")
    session = _session()
    try:
        with jafaal_orm.unit_of_work(session):
            session.add(Users(username="keeper", email="keeper@test.dev", is_active=True, is_verified=True))
            session.flush()

            with pytest.raises(IntegrityError), jafaal_orm.savepoint(session):
                # Duplicate username violates the unique constraint.
                session.add(Users(username="keeper", email="dupe@test.dev", is_active=True, is_verified=True))
                session.flush()
    finally:
        session.close()

    with _session() as observer:
        assert observer.query(Users).filter(Users.username == "keeper").count() == 1


# --------------------------------------------------------------------------- #
# The route class commits once per request
# --------------------------------------------------------------------------- #


def _probe_app():
    """A tiny app using JAFAAL's transactional router, for boundary assertions."""
    app = FastAPI()
    router = jafaal_orm.auth_router()

    @router.post("/write/{username}")
    def write(username: str, db: Session = Depends(jafaal_orm.get_db)):
        db.add(Users(username=username, email=f"{username}@probe.test", is_active=True, is_verified=True))
        db.flush()
        return {"ok": True}

    @router.post("/write-then-fail/{username}")
    def write_then_fail(username: str, db: Session = Depends(jafaal_orm.get_db)):
        db.add(Users(username=username, email=f"{username}@probe.test", is_active=True, is_verified=True))
        db.flush()
        raise jafaal.InvalidRequestError("nope")

    app.include_router(router)
    jafaal.register_exception_handlers(app)
    return app


def test_route_class_commits_a_successful_request():
    client = TestClient(_probe_app())
    assert client.post("/write/committed").status_code == 200
    with _session() as observer:
        assert observer.query(Users).filter(Users.username == "committed").one_or_none() is not None


def test_route_class_rolls_back_a_failed_request():
    """A request that raises must leave nothing behind, even after a flush."""
    client = TestClient(_probe_app())
    assert client.post("/write-then-fail/discarded").status_code == 400
    with _session() as observer:
        assert observer.query(Users).filter(Users.username == "discarded").one_or_none() is None


def test_every_jafaal_router_uses_the_transactional_route_class():
    """Guards against a new router being added without the transaction policy."""
    from jafaal.api_keys.router import router as api_keys_router
    from jafaal.identity_providers.public_router import router as idp_public_router
    from jafaal.identity_providers.router import router as idp_router
    from jafaal.password_reset_tokens.router import router as password_reset_router
    from jafaal.router import router as auth_router
    from jafaal.sessions.router import router as sessions_router
    from jafaal.sign_up_tokens.router import router as sign_up_router
    from jafaal.webauthn.router import public_router as webauthn_public_router
    from jafaal.webauthn.router import router as webauthn_router

    for router in (
        auth_router,
        sessions_router,
        api_keys_router,
        idp_router,
        idp_public_router,
        password_reset_router,
        sign_up_router,
        webauthn_router,
        webauthn_public_router,
    ):
        assert router.route_class is jafaal_orm.TransactionalRoute


# --------------------------------------------------------------------------- #
# Autonomous writes: durable regardless of the request's outcome
# --------------------------------------------------------------------------- #


def test_token_family_revocation_survives_the_401_that_follows_it(concurrent_db, make_user):
    """Theft revocation must not be rolled back by the failing request.

    ``/auth/refresh`` detects reuse, revokes the family, and *then* raises a 401.
    If the revocation shared that request's unit of work it would be rolled
    straight back and the stolen token would keep working — so it runs in its own
    transaction. Asserted directly here: an outer scope that fails must not undo
    it.
    """
    user = make_user(username="heidi")
    session = _session()
    try:
        with jafaal_orm.unit_of_work(session):
            sessions_crud.create_session(
                _session_row(user.id, "fam-autonomous"),
                session,
            )
    finally:
        session.close()

    outer = _session()
    try:
        with pytest.raises(RuntimeError), jafaal_orm.unit_of_work(outer):
            rotated_utils.invalidate_token_family("fam-autonomous")
            raise RuntimeError("the request then failed, as it does on theft")
    finally:
        outer.close()

    with _session() as observer:
        assert sessions_crud.get_session_by_id("fam-autonomous", observer) is None


def _session_row(user_id, session_id):
    from datetime import UTC, datetime, timedelta

    import jafaal.sessions.schema as sessions_schema

    now = datetime.now(UTC)
    return sessions_schema.UsersSessionsInternal(
        id=session_id,
        user_id=user_id,
        refresh_token="digest",
        ip_address="1.2.3.4",
        device_type="PC",
        operating_system="Linux",
        operating_system_version="1",
        browser="Firefox",
        browser_version="1",
        created_at=now,
        last_activity_at=now,
        expires_at=now + timedelta(days=7),
        oauth_state_id=None,
        tokens_exchanged=True,
        token_family_id=session_id,
        rotation_count=0,
        last_rotation_at=None,
        csrf_token_hash=None,
    )


def test_autonomous_session_commits_independently(make_user):
    user = make_user(username="ivan")
    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()

    outer = _session()
    try:
        with pytest.raises(RuntimeError), jafaal_orm.unit_of_work(outer):
            with jafaal_orm.autonomous_session() as inner:
                oauth_state_crud.create_oauth_state(
                    db=inner,
                    state_id=state_id,
                    nonce=nonce,
                    ip_address=None,
                    user_id=user.id,
                )
            raise RuntimeError("outer failed")
    finally:
        outer.close()

    with _session() as observer:
        assert oauth_state_crud.get_oauth_state_by_id_and_not_used(state_id, observer) is not None


# --------------------------------------------------------------------------- #
# Concurrency: the single-use claims still have exactly one winner
# --------------------------------------------------------------------------- #


def test_oauth_state_claim_has_one_winner_under_real_concurrency(concurrent_db):
    """The state claim is what stops an authorization code being replayed.

    It now commits in its own transaction, so this proves the guarantee holds
    across genuine parallel connections rather than only within one session.
    """
    from jafaal.orm import get_sessionmaker

    state_id, nonce = oauth_state_utils.create_state_id_and_nonce()
    with concurrent_db.session() as setup, jafaal_orm.unit_of_work(setup):
        oauth_state_crud.create_oauth_state(
            db=setup,
            state_id=state_id,
            nonce=nonce,
            ip_address=None,
            user_id=concurrent_db.user_id,
        )

    workers = 12
    barrier = threading.Barrier(workers)
    results: list[bool] = []
    lock = threading.Lock()

    def attempt():
        with concurrent_db.session() as session, jafaal_orm.unit_of_work(session):
            barrier.wait()
            claimed = oauth_state_crud.mark_oauth_state_used(state_id, session)
        with lock:
            results.append(claimed)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert results.count(True) == 1, f"expected exactly one winner, got {results.count(True)}"
    assert results.count(False) == workers - 1
    assert get_sessionmaker() is not None  # sanity: the suite's factory is untouched
