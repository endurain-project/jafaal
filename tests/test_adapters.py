"""Tests for the batteries-included reference adapters in ``jafaal.adapters``."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import pytest

import jafaal
import jafaal.ports as ports
from jafaal.adapters import (
    DEFAULT_PASSWORD_POLICY,
    DEFAULT_SIGNUP_CONFIG,
    CompositeAuthEventSink,
    LoggingAuthEventSink,
    SqlAlchemyUserRepository,
    StaticSettingsProvider,
)
from jafaal.exceptions import NotFoundError

try:
    import fakeredis
except ImportError:  # pragma: no cover
    fakeredis = None  # type: ignore[assignment]

from jafaal.adapters import RedisStateStore

requires_fakeredis = pytest.mark.skipif(fakeredis is None, reason="fakeredis not installed")

WEB = {"X-Client-Type": "web"}


# --------------------------------------------------------------------------- #
# SqlAlchemyUserRepository
# --------------------------------------------------------------------------- #


class TestSqlAlchemyUserRepository:
    def test_create_and_lookup(self, db):
        repo = SqlAlchemyUserRepository()
        user = repo.create_local_user("bob", "bob@test.dev", db, is_active=True, is_verified=False)

        assert user.id is not None
        assert user.is_active is True
        assert user.is_verified is False
        assert repo.get_by_id(user.id, db).username == "bob"
        assert repo.get_by_email("bob@test.dev", db).id == user.id
        assert repo.get_by_username("bob", db).id == user.id

    def test_lookup_misses_return_none(self, db):
        repo = SqlAlchemyUserRepository()
        assert repo.get_by_id(999_999, db) is None
        assert repo.get_by_email("ghost@absent.dev", db) is None
        assert repo.get_by_username("ghost", db) is None

    def test_provision_from_idp(self, db):
        repo = SqlAlchemyUserRepository()
        identity = ports.IdpIdentity(
            subject="sub-1",
            idp_id=1,
            email="idp@test.dev",
            email_verified=True,
            suggested_username="idpuser",
            display_name="IdP User",
            claims={},
        )
        user = repo.provision_from_idp(identity, db)

        assert user.username == "idpuser"
        assert user.email == "idp@test.dev"
        assert user.is_active is True
        assert user.is_verified is True

    def test_provision_from_idp_synthesizes_email_when_absent(self, db):
        repo = SqlAlchemyUserRepository()
        identity = ports.IdpIdentity(
            subject="sub-2",
            idp_id=1,
            email=None,
            email_verified=False,
            suggested_username="noemail",
            display_name=None,
            claims={},
        )
        user = repo.provision_from_idp(identity, db)

        assert user.email == "noemail@sso.invalid"
        assert user.is_verified is False

    def test_set_email_verified_activates(self, db):
        repo = SqlAlchemyUserRepository()
        user = repo.create_local_user("carol", "carol@test.dev", db, is_active=False, is_verified=False)

        repo.set_email_verified(user.id, db, activate=True)

        refreshed = repo.get_by_id(user.id, db)
        assert refreshed.is_verified is True
        assert refreshed.is_active is True

    def test_set_email_verified_without_activation(self, db):
        repo = SqlAlchemyUserRepository()
        user = repo.create_local_user("dave", "dave@test.dev", db, is_active=False, is_verified=False)

        repo.set_email_verified(user.id, db, activate=False)

        refreshed = repo.get_by_id(user.id, db)
        assert refreshed.is_verified is True
        assert refreshed.is_active is False

    def test_set_email_verified_missing_user_raises(self, db):
        repo = SqlAlchemyUserRepository()
        with pytest.raises(NotFoundError):
            repo.set_email_verified(999_999, db, activate=True)

    def test_sync_from_idp_is_a_noop(self, db):
        repo = SqlAlchemyUserRepository()
        assert repo.sync_from_idp(1, {"email": "x@test.dev"}, db) is None

    def test_end_to_end_signup_then_login(self, client):
        """The adapter satisfies the real HTTP sign-up + login flow."""
        original = ports.get_user_repository()
        jafaal.configure_user_repository(SqlAlchemyUserRepository())
        try:
            signup = client.post(
                "/api/v1/auth/sign-up/request",
                json={"username": "erin", "email": "erin@test.dev", "password": "Str0ng!Pass"},
            )
            assert signup.status_code == 201

            login = client.post(
                "/api/v1/auth/login",
                data={"username": "erin", "password": "Str0ng!Pass"},
                headers=WEB,
            )
            assert login.status_code == 200
        finally:
            jafaal.configure_user_repository(original)


# --------------------------------------------------------------------------- #
# StaticSettingsProvider
# --------------------------------------------------------------------------- #


class TestStaticSettingsProvider:
    def test_defaults(self):
        provider = StaticSettingsProvider()
        assert provider.get_password_policy() is DEFAULT_PASSWORD_POLICY
        assert provider.get_signup_config() is DEFAULT_SIGNUP_CONFIG
        assert provider.get_password_policy().min_length_for(is_superuser=True) == 12
        assert provider.get_password_policy().min_length_for(is_superuser=False) == 8

    def test_overrides(self):
        policy = jafaal.PasswordPolicy(min_length_regular=10, min_length_admin=20, password_type="length_only")
        signup = jafaal.SignupConfig(enabled=False, require_email_verification=True, require_admin_approval=True)

        provider = StaticSettingsProvider(password_policy=policy, signup_config=signup)

        assert provider.get_password_policy() is policy
        assert provider.get_signup_config() is signup

    def test_powers_real_signup_toggle(self, client):
        """A static provider drives the live sign-up gate."""
        original = ports.get_settings_provider()
        jafaal.configure_settings_provider(
            StaticSettingsProvider(signup_config=jafaal.SignupConfig(False, False, False))
        )
        try:
            r = client.post(
                "/api/v1/auth/sign-up/request",
                json={"username": "x", "email": "x@test.dev", "password": "Str0ng!Pass"},
            )
            assert r.status_code == 403
        finally:
            jafaal.configure_settings_provider(original)


# --------------------------------------------------------------------------- #
# Event sinks
# --------------------------------------------------------------------------- #


def _password_reset_event(token="SECRET-RESET-TOKEN"):
    return ports.PasswordResetRequested(
        user_id=1,
        email="alice@test.dev",
        display_name="Alice",
        token=token,
        expires_at=datetime.now(UTC),
        locale=None,
    )


def _verification_event(token="SECRET-VERIFY-TOKEN"):
    return ports.EmailVerificationRequested(
        user_id=2,
        email="bob@test.dev",
        display_name="Bob",
        token=token,
        expires_at=datetime.now(UTC),
        locale=None,
    )


class _RecordingSink:
    def __init__(self):
        self.received: list[object] = []

    async def on_password_reset_requested(self, event):
        self.received.append(event)

    async def on_email_verification_requested(self, event):
        self.received.append(event)

    async def on_signup_pending_admin_approval(self, event):
        self.received.append(event)

    async def on_signup_approved(self, event):
        self.received.append(event)


class TestLoggingAuthEventSink:
    async def test_logs_context_but_redacts_token(self, caplog):
        sink = LoggingAuthEventSink()
        with caplog.at_level(logging.INFO, logger="jafaal.adapters.events"):
            await sink.on_password_reset_requested(_password_reset_event())
            await sink.on_email_verification_requested(_verification_event())

        assert "SECRET-RESET-TOKEN" not in caplog.text
        assert "SECRET-VERIFY-TOKEN" not in caplog.text
        assert "alice@test.dev" in caplog.text
        assert "bob@test.dev" in caplog.text

    async def test_all_event_types_emit(self, caplog):
        sink = LoggingAuthEventSink()
        with caplog.at_level(logging.INFO, logger="jafaal.adapters.events"):
            await sink.on_password_reset_requested(_password_reset_event())
            await sink.on_email_verification_requested(_verification_event())
            await sink.on_signup_pending_admin_approval(
                ports.SignupPendingAdminApproval(user_id=3, username="carol", display_name="Carol")
            )
            await sink.on_signup_approved(
                ports.SignupApproved(user_id=3, email="carol@test.dev", display_name="Carol", locale=None)
            )
        assert caplog.text.count("\n") >= 4

    async def test_honours_custom_logger_and_level(self, caplog):
        custom = logging.getLogger("test.custom.sink")
        sink = LoggingAuthEventSink(custom, level=logging.WARNING)
        with caplog.at_level(logging.WARNING, logger="test.custom.sink"):
            await sink.on_signup_approved(
                ports.SignupApproved(user_id=9, email="z@test.dev", display_name=None, locale=None)
            )
        assert any(rec.levelno == logging.WARNING and rec.name == "test.custom.sink" for rec in caplog.records)


class TestCompositeAuthEventSink:
    async def test_fans_out_to_all_sinks(self):
        first, second = _RecordingSink(), _RecordingSink()
        composite = CompositeAuthEventSink([first, second])

        await composite.on_password_reset_requested(_password_reset_event())

        assert len(first.received) == 1
        assert len(second.received) == 1

    async def test_every_event_type_is_dispatched(self):
        sink = _RecordingSink()
        composite = CompositeAuthEventSink([sink])

        await composite.on_password_reset_requested(_password_reset_event())
        await composite.on_email_verification_requested(_verification_event())
        await composite.on_signup_pending_admin_approval(
            ports.SignupPendingAdminApproval(user_id=3, username="carol", display_name="Carol")
        )
        await composite.on_signup_approved(
            ports.SignupApproved(user_id=3, email="carol@test.dev", display_name="Carol", locale=None)
        )

        assert len(sink.received) == 4

    async def test_isolates_a_failing_sink(self, caplog):
        class _Boom(_RecordingSink):
            async def on_password_reset_requested(self, event):
                raise RuntimeError("delivery boom")

        before, boom, after = _RecordingSink(), _Boom(), _RecordingSink()
        composite = CompositeAuthEventSink([before, boom, after])

        # A failure in the middle sink must not stop the others or propagate.
        with caplog.at_level(logging.ERROR, logger="jafaal.adapters.events"):
            await composite.on_password_reset_requested(_password_reset_event())

        assert len(before.received) == 1
        assert len(after.received) == 1
        assert "delivery boom" in caplog.text


# --------------------------------------------------------------------------- #
# RedisStateStore
# --------------------------------------------------------------------------- #


@requires_fakeredis
class TestRedisStateStore:
    @pytest.fixture
    def store(self):
        return RedisStateStore(client=fakeredis.FakeStrictRedis())

    def test_get_set_delete(self, store):
        assert store.get("missing") is None
        store.set("k", b"v")
        assert store.get("k") == b"v"
        store.delete("k")
        assert store.get("k") is None

    def test_get_and_delete(self, store):
        store.set("k", b"v")
        assert store.get_and_delete("k") == b"v"
        assert store.get("k") is None
        assert store.get_and_delete("absent") is None

    def test_prefix_iteration_and_delete(self, store):
        store.set("p:a", b"1")
        store.set("p:b", b"2")
        store.set("q:c", b"3")

        assert sorted(store.iter_keys("p:")) == ["p:a", "p:b"]
        assert store.delete_prefix("p:") == 2
        assert list(store.iter_keys("p:")) == []
        assert store.get("q:c") == b"3"  # untouched

    def test_returns_bytes_not_str(self, store):
        store.set("k", b"value")
        assert isinstance(store.get("k"), bytes)

    def test_tiered_lockout_locks_and_stops_counting(self, store):
        tiers = ((3, 60),)
        outcomes = [store.record_tiered_failure("c", "g", tiers, 3600) for _ in range(4)]

        assert [o.count for o in outcomes] == [1, 2, 3, 3]
        assert outcomes[2].newly_locked is True
        assert outcomes[2].locked_until_epoch is not None
        # While locked, the counter neither increments nor re-locks.
        assert outcomes[3].newly_locked is False
        assert outcomes[3].count == 3

    def test_reset_via_delete_clears_lockout(self, store):
        tiers = ((2, 60),)
        store.record_tiered_failure("c", "g", tiers, 3600)
        store.record_tiered_failure("c", "g", tiers, 3600)  # now locked
        store.delete("c")
        store.delete("g")
        fresh = store.record_tiered_failure("c", "g", tiers, 3600)
        assert fresh.count == 1
        assert fresh.newly_locked is False

    def test_matches_in_memory_store_semantics(self, store):
        """The Redis adapter is behaviourally identical to the in-memory default."""
        tiers = ((3, 60), (5, 120))
        memory = jafaal.InMemoryStateStore()

        redis_counts = [store.record_tiered_failure("c", "g", tiers, 3600).count for _ in range(6)]
        memory_counts = [memory.record_tiered_failure("c", "g", tiers, 3600).count for _ in range(6)]

        assert redis_counts == memory_counts == [1, 2, 3, 3, 3, 3]

    def test_missing_dependency_guard(self, monkeypatch):
        import jafaal.adapters.redis_state_store as mod
        from jafaal._core.optional_deps import MissingDependencyError

        monkeypatch.setattr(mod, "_redis", None)
        with pytest.raises(MissingDependencyError):
            mod.RedisStateStore(url="redis://localhost:6379/0")

    def test_constructs_from_url_lazily(self):
        # redis-py connects lazily, so building from a URL must not require a
        # reachable server at construction time.
        store = RedisStateStore(url="redis://localhost:6379/0")
        assert store is not None

    def test_backend_outage_is_translated(self):
        import redis

        from jafaal.state_store import StateStoreUnavailableError

        class _BrokenClient:
            def get(self, *args, **kwargs):
                raise redis.exceptions.ConnectionError("backend down")

        store = RedisStateStore(client=_BrokenClient())
        with pytest.raises(StateStoreUnavailableError):
            store.get("k")
