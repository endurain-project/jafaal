"""Tests for AuthSettings validation and the settings accessor lifecycle."""

from dataclasses import FrozenInstanceError

import pytest
from cryptography.fernet import Fernet

import jafaal
from jafaal import settings as settings_mod


def _valid(**overrides):
    base = {
        "secret_key": "k" * 32,
        "fernet_key": Fernet.generate_key().decode(),
        "base_url": "https://app.test",
    }
    base.update(overrides)
    return jafaal.AuthSettings(**base)


def test_requires_secret_key():
    with pytest.raises(ValueError, match="secret_key"):
        _valid(secret_key="")


def test_requires_fernet_key():
    with pytest.raises(ValueError, match="fernet_key"):
        _valid(fernet_key="")


def test_rejects_short_secret_key():
    # A non-empty but too-short HS256 key is brute-forceable → rejected up front.
    with pytest.raises(ValueError, match="secret_key"):
        _valid(secret_key="tooshort")
    # Exactly the minimum length is accepted.
    assert _valid(secret_key="k" * settings_mod.MIN_SECRET_KEY_LENGTH) is not None


def test_rejects_invalid_fernet_key():
    # A malformed Fernet key fails at construction, not later at first encrypt.
    with pytest.raises(ValueError, match="fernet_key"):
        _valid(fernet_key="not-a-valid-fernet-key")


def test_algorithm_must_be_allow_listed():
    with pytest.raises(ValueError, match="algorithm"):
        _valid(algorithm="none")
    with pytest.raises(ValueError, match="algorithm"):
        _valid(algorithm="RS256")


def test_positive_expiries():
    with pytest.raises(ValueError, match="access_token_expire_minutes"):
        _valid(access_token_expire_minutes=0)
    with pytest.raises(ValueError, match="refresh_token_expire_days"):
        _valid(refresh_token_expire_days=-1)


def test_positive_argon2_cost():
    with pytest.raises(ValueError, match="argon2_time_cost"):
        _valid(argon2_time_cost=0)
    with pytest.raises(ValueError, match="argon2_memory_cost"):
        _valid(argon2_memory_cost=0)
    with pytest.raises(ValueError, match="argon2_parallelism"):
        _valid(argon2_parallelism=-1)


def test_secure_defaults():
    s = _valid()
    # trusted_proxies is empty by default: trust only the direct peer, so a
    # client cannot spoof its source IP via X-Forwarded-For / X-Real-IP.
    assert s.trusted_proxies == ()
    # The process-local in-memory state store is not permitted in a deployed
    # environment unless the host explicitly opts in.
    assert s.allow_in_memory_state_store_when_deployed is False
    # Argon2 cost defaults match pwdlib / argon2-cffi.
    assert (s.argon2_time_cost, s.argon2_memory_cost, s.argon2_parallelism) == (3, 65536, 4)


def test_issuer_audience_fall_back_to_base_url():
    s = _valid()
    assert s.resolved_issuer == "https://app.test"
    assert s.resolved_audience == "https://app.test"
    s2 = _valid(issuer="iss", audience="aud")
    assert s2.resolved_issuer == "iss"
    assert s2.resolved_audience == "aud"


def test_is_deployed():
    assert _valid(environment="production").is_deployed is True
    assert _valid(environment="demo").is_deployed is True
    assert _valid(environment="test").is_deployed is False


def test_settings_are_frozen():
    s = _valid()
    with pytest.raises(FrozenInstanceError):
        s.secret_key = "other"  # type: ignore[misc]


def test_configure_get_reset_and_generation():
    # Snapshot current (the session fixture configured one) and restore after.
    original = settings_mod.get_settings()
    gen_before = settings_mod.settings_generation()

    try:
        settings_mod.configure(_valid(app_name="Reconfigured"))
        assert settings_mod.is_configured() is True
        assert settings_mod.get_settings().app_name == "Reconfigured"
        assert settings_mod.settings_generation() > gen_before

        settings_mod.reset()
        assert settings_mod.is_configured() is False
        with pytest.raises(RuntimeError, match="not configured"):
            settings_mod.get_settings()
    finally:
        # Restore for the rest of the session no matter what.
        settings_mod.configure(original)


def test_configure_rejects_wrong_type():
    with pytest.raises(TypeError):
        settings_mod.configure({"secret_key": "x"})  # type: ignore[arg-type]
