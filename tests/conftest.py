"""Shared test setup and fixtures.

Provides a fully-wired, standalone JAFAAL for functional tests:

* an in-memory SQLite database shared across sessions/threads (``StaticPool``),
* a real host ``Users`` model built on :data:`jafaal.orm.Base`,
* in-memory ``UserRepository`` / static ``SettingsProvider`` / recording
  ``AuthEventSink`` adapters, and
* per-test schema + state-store isolation.

The library is configured once per session; each test gets a fresh schema and a
fresh in-memory state store so lockout counters and TOTP replay markers never
leak between tests.
"""

from __future__ import annotations

import os

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import String, create_engine
from sqlalchemy.orm import Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

import jafaal
import jafaal.credentials.crud as credentials_crud
import jafaal.orm as jafaal_orm
from jafaal import IntPKUserMixin
from jafaal._internal.password_hasher import password_hasher
from jafaal.orm import Base

# --------------------------------------------------------------------------- #
# Host user model (built on JAFAAL's single declarative registry)
# --------------------------------------------------------------------------- #


class Users(IntPKUserMixin, Base):
    """Minimal host user model used across the test suite."""

    __tablename__ = "users"

    display_name: Mapped[str | None] = mapped_column(String(250), nullable=True)


# --------------------------------------------------------------------------- #
# Port adapters
# --------------------------------------------------------------------------- #


class InMemoryUserRepository:
    """SQLAlchemy-backed ``UserRepository`` over the test ``Users`` table."""

    def get_by_id(self, user_id, db):
        return db.get(Users, user_id)

    def get_by_email(self, email, db):
        return db.query(Users).filter(Users.email == email).one_or_none()

    def get_by_username(self, username, db):
        return db.query(Users).filter(Users.username == username).one_or_none()

    def create_local_user(self, username, email, db, *, is_active, is_verified):
        user = Users(username=username, email=email, is_active=is_active, is_verified=is_verified)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def provision_from_idp(self, identity, db):
        user = Users(
            username=identity.suggested_username,
            email=identity.email or f"{identity.subject}@idp.test",
            is_active=True,
            is_verified=identity.email_verified,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def sync_from_idp(self, user_id, claims, db):
        return None

    def set_email_verified(self, user_id, db, *, activate):
        user = db.get(Users, user_id)
        user.is_verified = True
        if activate:
            user.is_active = True
        db.commit()


class StaticSettingsProvider:
    """Static ``SettingsProvider`` with overridable policy / sign-up config."""

    def __init__(self, policy=None, signup=None):
        self._policy = policy or jafaal.PasswordPolicy(
            min_length_regular=8, min_length_admin=12, password_type="strict"
        )
        self._signup = signup or jafaal.SignupConfig(
            enabled=True, require_email_verification=False, require_admin_approval=False
        )

    def get_password_policy(self):
        return self._policy

    def get_signup_config(self):
        return self._signup


class RecordingEventSink:
    """Captures emitted events so tests can assert on them."""

    def __init__(self):
        self.events: list[object] = []

    async def on_password_reset_requested(self, event):
        self.events.append(event)

    async def on_email_verification_requested(self, event):
        self.events.append(event)

    async def on_signup_pending_admin_approval(self, event):
        self.events.append(event)

    async def on_signup_approved(self, event):
        self.events.append(event)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def engine():
    """A single shared engine for the whole suite.

    Defaults to an in-memory SQLite database shared across threads
    (``StaticPool``). Set ``JAFAAL_TEST_DATABASE_URL`` (e.g. a Postgres or MySQL
    URL) to run the identical suite against another backend — the CI database
    matrix uses this to prove the ORM models and queries stay portable.
    """
    url = os.environ.get("JAFAAL_TEST_DATABASE_URL")
    if url:
        return create_engine(url)
    return create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


@pytest.fixture(scope="session", autouse=True)
def _configure_jafaal(engine):
    """Configure the library once for the whole test session."""
    jafaal.configure(
        jafaal.AuthSettings(
            secret_key="s" * 32,
            fernet_key=Fernet.generate_key().decode(),
            base_url="https://app.test",
            app_name="Test",
            # Not a deployed environment → refresh cookies are not ``Secure``,
            # so the http TestClient stores them.
            environment="test",
        )
    )
    jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False, expire_on_commit=False))
    jafaal.configure_user_repository(InMemoryUserRepository())
    jafaal.configure_settings_provider(StaticSettingsProvider())
    yield
    jafaal.reset()


@pytest.fixture(autouse=True)
def _isolate(engine):
    """Fresh schema + fresh state store for every test."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    jafaal.reset_state_store()
    jafaal.reset_scopes()
    jafaal.reset_api_key_scopes()
    jafaal.configure_event_sink(jafaal.NullAuthEventSink())
    yield
    jafaal.reset_state_store()


@pytest.fixture
def db():
    """A request-independent session for direct-CRUD assertions."""
    session = jafaal_orm.get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def event_sink():
    """Install a recording event sink and return it; reset afterwards."""
    sink = RecordingEventSink()
    jafaal.configure_event_sink(sink)
    yield sink
    jafaal.configure_event_sink(jafaal.NullAuthEventSink())


@pytest.fixture
def make_user():
    """Factory that creates a user (optionally with a local password)."""

    def _make(
        username="alice",
        email=None,
        password="Str0ng!Pass",
        *,
        user_id=None,
        is_active=True,
        is_superuser=False,
        is_verified=True,
    ):
        session = jafaal_orm.get_sessionmaker()()
        try:
            user = Users(
                username=username,
                email=email or f"{username}@test.dev",
                is_active=is_active,
                is_superuser=is_superuser,
                is_verified=is_verified,
            )
            if user_id is not None:
                user.id = user_id
            session.add(user)
            session.commit()
            session.refresh(user)
            if password is not None:
                credentials_crud.upsert_password_hash(user.id, password_hasher.hash_password(password), session)
            session.expunge(user)
            return user
        finally:
            session.close()

    return _make


@pytest.fixture
def client():
    """A FastAPI TestClient with the full JAFAAL router mounted under /api/v1."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(jafaal.create_auth_router(app=app), prefix="/api/v1")
    return TestClient(app)
