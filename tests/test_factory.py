"""Tests for ``create_auth_router`` assembly and its startup safety warnings."""

from __future__ import annotations

import logging

from cryptography.fernet import Fernet
from fastapi import FastAPI

import jafaal
import jafaal.rate_limit as jafaal_rate_limit
from jafaal.exceptions import JafaalError
from jafaal.state_store import TieredFailureOutcome

FACTORY_LOGGER = "jafaal.factory"


class _DummyLimiter:
    """A non-no-op RateLimiter (identity decorator) — enough to count as configured."""

    def limit(self, category):
        def decorator(func):
            return func

        return decorator


class _FakeDistributedStore:
    """A minimal non-in-memory StateStore stand-in (a 'distributed' backend)."""

    def get(self, key):
        return None

    def set(self, key, value, ttl_seconds=None):
        return None

    def delete(self, key):
        return None

    def delete_prefix(self, prefix):
        return 0

    def get_and_delete(self, key):
        return None

    def iter_keys(self, prefix):
        return iter(())

    def record_tiered_failure(self, counter_key, gate_key, tiers, counter_ttl_seconds):
        return TieredFailureOutcome(0, None, False)


def _production_settings():
    return jafaal.AuthSettings(
        secret_key="s" * 32,
        fernet_key=Fernet.generate_key().decode(),
        base_url="https://app.test",
        app_name="Test",
        environment="production",
    )


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #


def test_create_auth_router_mounts_routes_and_registers_handler():
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(jafaal.create_auth_router(app=app), prefix="/api/v1")

    assert JafaalError in app.exception_handlers

    # The endpoints are reachable (present → not 404) once mounted.
    client = TestClient(app)
    assert client.post("/api/v1/auth/login").status_code != 404
    assert client.post("/api/v1/auth/refresh", headers={"X-Client-Type": "web"}).status_code != 404


def test_is_enforcing_reflects_configuration():
    jafaal_rate_limit.reset_rate_limiter()
    try:
        assert jafaal_rate_limit.is_enforcing() is False
        jafaal_rate_limit.configure_rate_limiter(_DummyLimiter())
        assert jafaal_rate_limit.is_enforcing() is True
    finally:
        jafaal_rate_limit.reset_rate_limiter()


# --------------------------------------------------------------------------- #
# Rate-limiter warning
# --------------------------------------------------------------------------- #


def test_warns_when_rate_limiter_unconfigured(caplog):
    jafaal_rate_limit.reset_rate_limiter()
    try:
        with caplog.at_level(logging.WARNING, logger=FACTORY_LOGGER):
            jafaal.create_auth_router()
        assert "rate limiting is not configured" in caplog.text.lower()
    finally:
        jafaal_rate_limit.reset_rate_limiter()


def test_no_rate_limit_warning_when_configured(caplog):
    jafaal_rate_limit.reset_rate_limiter()
    try:
        with caplog.at_level(logging.WARNING, logger=FACTORY_LOGGER):
            jafaal.create_auth_router(rate_limiter=_DummyLimiter())
        assert "rate limiting is not configured" not in caplog.text.lower()
    finally:
        jafaal_rate_limit.reset_rate_limiter()


# --------------------------------------------------------------------------- #
# In-memory state store warning (deployed environments)
# --------------------------------------------------------------------------- #


def test_warns_on_in_memory_state_store_when_deployed(caplog):
    original = jafaal.get_settings()
    jafaal.configure(_production_settings())
    jafaal.reset_state_store()  # in-memory default
    jafaal.configure_rate_limiter(_DummyLimiter())  # silence the unrelated warning
    try:
        with caplog.at_level(logging.WARNING, logger=FACTORY_LOGGER):
            jafaal.create_auth_router()
        text = caplog.text.lower()
        assert "in-memory" in text
        assert "deployed" in text
    finally:
        jafaal.configure(original)
        jafaal_rate_limit.reset_rate_limiter()
        jafaal.reset_state_store()


def test_no_state_store_warning_with_distributed_backend(caplog):
    original = jafaal.get_settings()
    jafaal.configure(_production_settings())
    jafaal.configure_state_store(_FakeDistributedStore())
    jafaal.configure_rate_limiter(_DummyLimiter())
    try:
        with caplog.at_level(logging.WARNING, logger=FACTORY_LOGGER):
            jafaal.create_auth_router()
        assert "in-memory" not in caplog.text.lower()
    finally:
        jafaal.configure(original)
        jafaal_rate_limit.reset_rate_limiter()
        jafaal.reset_state_store()


def test_no_state_store_warning_when_not_deployed(caplog):
    # The session fixture configures environment="test" (not deployed).
    jafaal.reset_state_store()  # in-memory default
    jafaal.configure_rate_limiter(_DummyLimiter())
    try:
        with caplog.at_level(logging.WARNING, logger=FACTORY_LOGGER):
            jafaal.create_auth_router()
        assert "in-memory" not in caplog.text.lower()
    finally:
        jafaal_rate_limit.reset_rate_limiter()
