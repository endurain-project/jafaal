"""Tests for the batteries-included reference adapters in ``jafaal.adapters``."""

from __future__ import annotations

import dataclasses
import hashlib
import logging
from datetime import UTC, datetime

import httpx
import pytest
from fastapi import Request

import jafaal
import jafaal.ports as ports
import jafaal.rate_limit as rate_limit
from jafaal.adapters import (
    DEFAULT_PASSWORD_POLICY,
    DEFAULT_SIGNUP_CONFIG,
    BlocklistBreachChecker,
    CompositeAuthEventSink,
    HibpBreachChecker,
    LoggingAuthEventSink,
    SqlAlchemyUserRepository,
    StateStoreRateLimiter,
    StaticSettingsProvider,
)
from jafaal.exceptions import NotFoundError
from jafaal.state_store import StateStoreUnavailableError

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

    def test_set_if_absent_claims_once(self, store):
        # SET .. NX EX is atomic server-side, so only the first caller wins and
        # the stored value is never overwritten by a loser.
        assert store.set_if_absent("claim", b"1", 60) is True
        assert store.set_if_absent("claim", b"2", 60) is False
        assert store.get("claim") == b"1"

    def test_set_if_absent_sets_a_ttl(self, store):
        store.set_if_absent("claim", b"1", 60)
        assert store._client.ttl("claim") > 0

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

    def test_increment_counts_and_sets_ttl(self):
        raw = fakeredis.FakeStrictRedis()
        store = RedisStateStore(client=raw)
        assert [store.increment("c", 60) for _ in range(3)] == [1, 2, 3]
        # The counter carries a TTL so fixed-window rate-limit buckets self-expire.
        assert 0 < raw.ttl("c") <= 60

    def test_increment_matches_in_memory_store(self):
        redis_store = RedisStateStore(client=fakeredis.FakeStrictRedis())
        memory = jafaal.InMemoryStateStore()
        redis_counts = [redis_store.increment("c", 60) for _ in range(4)]
        memory_counts = [memory.increment("c", 60) for _ in range(4)]
        assert redis_counts == memory_counts == [1, 2, 3, 4]


# --------------------------------------------------------------------------- #
# StateStoreRateLimiter
# --------------------------------------------------------------------------- #


def _login(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
        headers=WEB,
    )


def _make_request(host: str) -> Request:
    """A minimal Starlette/FastAPI ``Request`` whose client IP is ``host``."""
    return Request({"type": "http", "headers": [], "client": (host, 0)})


class TestParseBudget:
    def test_valid_budgets(self):
        from jafaal.adapters.rate_limiter import _parse_budget

        assert _parse_budget("10/minute") == (10, 60)
        assert _parse_budget("30/hour") == (30, 3600)
        assert _parse_budget(" 5 / second ") == (5, 1)
        assert _parse_budget("2/days") == (2, 86400)

    @pytest.mark.parametrize("bad", ["10", "abc/minute", "10/fortnight", ""])
    def test_invalid_budgets_raise(self, bad):
        from jafaal.adapters.rate_limiter import _parse_budget

        with pytest.raises(ValueError):
            _parse_budget(bad)


class TestStateStoreRateLimiter:
    def test_installing_it_flips_off_the_no_op_limiter(self):
        jafaal.configure_rate_limiter(StateStoreRateLimiter())
        try:
            assert rate_limit.is_enforcing() is True
        finally:
            jafaal.reset_rate_limiter()

    def test_blocks_requests_over_budget(self, client, make_user):
        make_user(username="alice")
        original = jafaal.get_settings()
        # A wide window keeps every request in one fixed-window bucket for the
        # duration of the test (no minute/hour-boundary flakiness).
        jafaal.configure(dataclasses.replace(original, rate_limit_sensitive="3/hour"))
        jafaal.configure_rate_limiter(StateStoreRateLimiter())
        try:
            for _ in range(3):
                assert _login(client).status_code == 200
            blocked = _login(client)
            assert blocked.status_code == 429
            assert int(blocked.headers["Retry-After"]) > 0
        finally:
            jafaal.configure(original)
            jafaal.reset_rate_limiter()

    def test_separate_ips_have_separate_counters(self):
        original = jafaal.get_settings()
        jafaal.configure(dataclasses.replace(original, rate_limit_sensitive="1/hour"))
        limiter = StateStoreRateLimiter()

        @limiter.limit(rate_limit.SENSITIVE)
        def endpoint(request):
            return "ok"

        try:
            # Each IP gets its own budget: the first hit per IP is allowed, and
            # only the second hit from the *same* IP trips the 1/hour limit.
            assert endpoint(request=_make_request("1.1.1.1")) == "ok"
            assert endpoint(request=_make_request("2.2.2.2")) == "ok"
            with pytest.raises(jafaal.RateLimitedError):
                endpoint(request=_make_request("1.1.1.1"))
        finally:
            jafaal.configure(original)

    async def test_wraps_async_endpoints(self):
        limiter = StateStoreRateLimiter()

        @limiter.limit(rate_limit.WRITE)
        async def endpoint(request):
            return "async-ok"

        assert await endpoint(request=_make_request("9.9.9.9")) == "async-ok"

    def test_fails_open_when_no_request_argument(self):
        limiter = StateStoreRateLimiter()

        @limiter.limit(rate_limit.SENSITIVE)
        def endpoint(x):
            return x * 2

        # No Request in args/kwargs → the limiter cannot identify a client, so it
        # passes the call through untouched instead of erroring.
        assert endpoint(21) == 42

    def test_fails_open_when_state_store_unavailable(self, client, make_user):
        make_user(username="alice")
        original = jafaal.get_settings()
        jafaal.configure(dataclasses.replace(original, rate_limit_sensitive="1/hour"))

        class _BrokenStore(jafaal.InMemoryStateStore):
            def increment(self, key, ttl_seconds):
                raise StateStoreUnavailableError("limiter backend down")

        jafaal.configure_state_store(_BrokenStore())
        jafaal.configure_rate_limiter(StateStoreRateLimiter())
        try:
            # Budget is 1/hour, so requests 2+ would 429 if the limiter counted;
            # a state-store outage must instead fail open so auth stays up.
            for _ in range(3):
                assert _login(client).status_code == 200
        finally:
            jafaal.configure(original)
            jafaal.reset_state_store()
            jafaal.reset_rate_limiter()

    def test_fails_open_on_malformed_budget(self):
        original = jafaal.get_settings()
        jafaal.configure(dataclasses.replace(original, rate_limit_sensitive="not-a-budget"))
        limiter = StateStoreRateLimiter()

        @limiter.limit(rate_limit.SENSITIVE)
        def endpoint(request):
            return "ok"

        try:
            # A misconfigured budget must not wedge the endpoint shut.
            for _ in range(5):
                assert endpoint(request=_make_request("1.1.1.1")) == "ok"
        finally:
            jafaal.configure(original)


# --------------------------------------------------------------------------- #
# Password breach checkers
# --------------------------------------------------------------------------- #


def _hibp_prefix_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return digest[:5], digest[5:]


class TestBlocklistBreachChecker:
    def test_blocks_listed_password_case_insensitively(self):
        checker = BlocklistBreachChecker(["Password123", "hunter2"])
        assert checker.is_breached("password123") is True  # casefold match
        assert checker.is_breached("HUNTER2") is True
        assert checker.is_breached("uniqueP@ss") is False

    def test_case_sensitive_mode(self):
        checker = BlocklistBreachChecker(["Password123"], case_insensitive=False)
        assert checker.is_breached("Password123") is True
        assert checker.is_breached("password123") is False


class TestHibpBreachChecker:
    def _checker(self, handler, **kwargs):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        return HibpBreachChecker(client=client, **kwargs)

    def test_detects_breached_password(self):
        password = "password123"
        prefix, suffix = _hibp_prefix_suffix(password)

        def handler(request):
            # k-anonymity: only the 5-char prefix is sent, plus the padding header.
            assert request.url.path == f"/range/{prefix}"
            assert request.headers["Add-Padding"] == "true"
            return httpx.Response(200, text=f"{suffix}:42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\r\n")

        assert self._checker(handler).is_breached(password) is True

    def test_password_not_in_range_is_allowed(self):
        def handler(request):
            return httpx.Response(200, text="0000000000000000000000000000000000000:5\r\n")

        assert self._checker(handler).is_breached("anything-unique") is False

    def test_min_count_filters_low_counts(self):
        password = "seen-a-few-times"
        _prefix, suffix = _hibp_prefix_suffix(password)

        def handler(request):
            return httpx.Response(200, text=f"{suffix}:3\r\n")

        assert self._checker(handler, min_count=5).is_breached(password) is False  # 3 < 5
        assert self._checker(handler).is_breached(password) is True  # default min_count=1

    def test_padding_rows_are_ignored(self):
        password = "padded"
        _prefix, suffix = _hibp_prefix_suffix(password)

        def handler(request):
            return httpx.Response(200, text=f"{suffix}:0\r\n")  # padding rows carry count 0

        assert self._checker(handler).is_breached(password) is False

    def test_fails_open_on_http_error(self):
        def handler(request):
            return httpx.Response(503)

        assert self._checker(handler).is_breached("whatever") is False

    def test_rejects_bad_min_count(self):
        with pytest.raises(ValueError, match="min_count"):
            HibpBreachChecker(min_count=0)


def test_blocklist_checker_wired_into_password_validation(db):
    # End-to-end: a blocklisted password is rejected by validate_and_hash_password.
    from jafaal._internal.password_hasher import get_password_hasher
    from jafaal._internal.token_manager import get_token_manager
    from jafaal.exceptions import PasswordPolicyError
    from jafaal.identity_service import DefaultIdentityService

    jafaal.configure_password_breach_checker(BlocklistBreachChecker(["Str0ng!Pass"]))
    svc = DefaultIdentityService(db, get_token_manager(), get_password_hasher())
    try:
        with pytest.raises(PasswordPolicyError, match="breach"):
            svc.validate_and_hash_password("Str0ng!Pass", 8, "strict")
    finally:
        jafaal.configure_password_breach_checker(jafaal.NullPasswordBreachChecker())
