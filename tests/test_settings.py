"""Tests for the grouped settings objects, their validation, and the accessor."""

import dataclasses
from dataclasses import FrozenInstanceError

import pytest
from cryptography.fernet import Fernet

import jafaal
from jafaal import settings as settings_mod


def _secrets(**overrides):
    base = {"secret_key": "k" * 32, "fernet_key": Fernet.generate_key().decode()}
    base.update(overrides)
    return jafaal.Secrets(**base)


def _valid(**overrides):
    """Build a valid AuthSettings, overriding top-level fields or whole groups."""
    base = {"secrets": _secrets(), "base_url": "https://app.test"}
    base.update(overrides)
    return jafaal.AuthSettings(**base)


def _rsa_pem():
    from joserfc.jwk import RSAKey

    return RSAKey.generate_key(2048).as_pem(private=True).decode()


def _ec_pem():
    from joserfc.jwk import ECKey

    return ECKey.generate_key("P-256").as_pem(private=True).decode()


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #


def test_requires_secret_key():
    with pytest.raises(ValueError, match="secret_key"):
        _secrets(secret_key="")


def test_requires_fernet_key():
    with pytest.raises(ValueError, match="fernet_key"):
        _secrets(fernet_key="")


def test_rejects_short_secret_key():
    # A non-empty but too-short HS256 key is brute-forceable → rejected up front.
    with pytest.raises(ValueError, match="secret_key"):
        _secrets(secret_key="tooshort")
    # Exactly the minimum length is accepted.
    assert _secrets(secret_key="k" * settings_mod.MIN_SECRET_KEY_LENGTH) is not None


def test_rejects_invalid_fernet_key():
    # A malformed Fernet key fails at construction, not later at first encrypt.
    with pytest.raises(ValueError, match="fernet_key"):
        _secrets(fernet_key="not-a-valid-fernet-key")


# --------------------------------------------------------------------------- #
# Tokens — including the cross-group algorithm/key-material rule
# --------------------------------------------------------------------------- #


def test_algorithm_must_be_allow_listed():
    with pytest.raises(ValueError, match="algorithm"):
        jafaal.TokenSettings(algorithm="none")
    with pytest.raises(ValueError, match="algorithm"):
        jafaal.TokenSettings(algorithm="HS512")  # symmetric, but not allow-listed


def test_asymmetric_requires_private_key():
    # The algorithm and the key material live in different groups, so this
    # consistency rule can only be enforced by the root object.
    with pytest.raises(ValueError, match="requires"):
        _valid(tokens=jafaal.TokenSettings(algorithm="RS256"))


def test_asymmetric_rejects_malformed_or_wrong_type_key():
    with pytest.raises(ValueError, match="private_key is invalid"):
        _valid(
            secrets=_secrets(private_key="-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"),
            tokens=jafaal.TokenSettings(algorithm="RS256"),
        )
    # An EC key cannot sign RS256.
    with pytest.raises(ValueError, match="private_key is invalid"):
        _valid(secrets=_secrets(private_key=_ec_pem()), tokens=jafaal.TokenSettings(algorithm="RS256"))


def test_private_key_with_symmetric_algorithm_rejected():
    with pytest.raises(ValueError, match="symmetric"):
        _valid(secrets=_secrets(private_key=_rsa_pem()))  # algorithm defaults to HS256


def test_asymmetric_valid_config_accepted():
    assert _valid(secrets=_secrets(private_key=_rsa_pem()), tokens=jafaal.TokenSettings(algorithm="RS256"))
    assert _valid(secrets=_secrets(private_key=_ec_pem()), tokens=jafaal.TokenSettings(algorithm="ES256"))


def test_asymmetric_public_only_fallback_accepted():
    from joserfc.jwk import RSAKey

    new = RSAKey.generate_key(2048)
    old_public = RSAKey.generate_key(2048).as_pem(private=False).decode()
    settings = _valid(
        secrets=_secrets(
            private_key=new.as_pem(private=True).decode(),
            private_key_fallbacks=(old_public,),  # verify-only public key is fine
        ),
        tokens=jafaal.TokenSettings(algorithm="RS256"),
    )
    assert settings is not None


def test_is_asymmetric_predicate():
    assert jafaal.TokenSettings(algorithm="HS256").is_asymmetric is False
    assert jafaal.TokenSettings(algorithm="RS256").is_asymmetric is True


def test_positive_expiries():
    with pytest.raises(ValueError, match="access_token_expire_minutes"):
        jafaal.TokenSettings(access_token_expire_minutes=0)
    with pytest.raises(ValueError, match="refresh_token_expire_days"):
        jafaal.TokenSettings(refresh_token_expire_days=-1)


def test_rejects_negative_jwt_leeway():
    with pytest.raises(ValueError, match="leeway_seconds"):
        jafaal.TokenSettings(leeway_seconds=-1)
    assert jafaal.TokenSettings(leeway_seconds=30).leeway_seconds == 30


# --------------------------------------------------------------------------- #
# Passwords / SSO / WebAuthn group validation
# --------------------------------------------------------------------------- #


def test_positive_argon2_cost():
    with pytest.raises(ValueError, match="argon2_time_cost"):
        jafaal.PasswordSettings(argon2_time_cost=0)
    with pytest.raises(ValueError, match="argon2_memory_cost"):
        jafaal.PasswordSettings(argon2_memory_cost=0)
    with pytest.raises(ValueError, match="argon2_parallelism"):
        jafaal.PasswordSettings(argon2_parallelism=-1)


def test_rejects_short_password_max_length():
    # NIST SP 800-63B: allow at least 64 characters for passphrases.
    with pytest.raises(ValueError, match="max_length"):
        jafaal.PasswordSettings(max_length=32)
    assert jafaal.PasswordSettings(max_length=64) is not None


def test_idp_require_https_defaults_true():
    assert _valid().sso.idp_require_https is True


def test_idp_require_https_can_be_disabled():
    assert _valid(sso=jafaal.SsoSettings(idp_require_https=False)).sso.idp_require_https is False


def test_step_up_windows_must_be_positive():
    with pytest.raises(ValueError, match="step_up_reauth_max_age_seconds"):
        jafaal.SsoSettings(step_up_reauth_max_age_seconds=0)
    with pytest.raises(ValueError, match="step_up_grant_ttl_seconds"):
        jafaal.SsoSettings(step_up_grant_ttl_seconds=0)


def test_webauthn_challenge_ttl_must_be_positive():
    with pytest.raises(ValueError, match="challenge_ttl_seconds"):
        jafaal.WebAuthnSettings(challenge_ttl_seconds=0)


# --------------------------------------------------------------------------- #
# Refresh cookie
# --------------------------------------------------------------------------- #


def test_rejects_invalid_refresh_cookie_prefix():
    with pytest.raises(ValueError, match="refresh_cookie_prefix"):
        jafaal.SessionSettings(refresh_cookie_prefix="__Bogus-")


def test_host_cookie_prefix_requires_root_path():
    # __Host- mandates Path=/, so it is rejected with the default scoped path...
    with pytest.raises(ValueError, match="__Host-"):
        jafaal.SessionSettings(refresh_cookie_prefix="__Host-")
    # ...and accepted once the path is "/".
    assert jafaal.SessionSettings(refresh_cookie_prefix="__Host-", refresh_cookie_path="/") is not None


def test_effective_refresh_cookie_name():
    # No prefix → plain name.
    assert _valid().effective_refresh_cookie_name == "jafaal_refresh_token"
    # Prefix only applies in a deployed environment (browsers require Secure).
    secure = jafaal.SessionSettings(refresh_cookie_prefix="__Secure-")
    assert _valid(sessions=secure, environment="test").effective_refresh_cookie_name == "jafaal_refresh_token"
    assert (
        _valid(sessions=secure, environment="production").effective_refresh_cookie_name
        == "__Secure-jafaal_refresh_token"
    )
    host = jafaal.SessionSettings(refresh_cookie_prefix="__Host-", refresh_cookie_path="/")
    assert (
        _valid(sessions=host, environment="production").effective_refresh_cookie_name == "__Host-jafaal_refresh_token"
    )


# --------------------------------------------------------------------------- #
# Defaults and derived values
# --------------------------------------------------------------------------- #


def test_secure_defaults():
    s = _valid()
    # trusted_proxies is empty by default: trust only the direct peer, so a
    # client cannot spoof its source IP via X-Forwarded-For / X-Real-IP.
    assert s.network.trusted_proxies == ()
    # The process-local in-memory state store and the no-op rate limiter are not
    # permitted in a deployed environment unless the host explicitly opts in.
    assert s.allow_in_memory_state_store_when_deployed is False
    assert s.allow_no_rate_limit_when_deployed is False
    # API keys are header-only by default (query strings land in access logs).
    assert s.api_keys.allow_query_param is False
    # Argon2 cost defaults match pwdlib / argon2-cffi.
    assert (
        s.passwords.argon2_time_cost,
        s.passwords.argon2_memory_cost,
        s.passwords.argon2_parallelism,
    ) == (3, 65536, 4)


def test_groups_default_to_independent_instances():
    """Mutable-looking defaults must not be shared between AuthSettings objects."""
    a, b = _valid(), _valid()
    assert a.tokens is not b.tokens
    assert a.webauthn is not b.webauthn


def test_issuer_audience_and_client_id_fall_back_to_base_url():
    s = _valid()
    assert s.resolved_issuer == "https://app.test"
    assert s.resolved_audience == "https://app.test"
    assert s.resolved_client_id == "https://app.test"
    s2 = _valid(tokens=jafaal.TokenSettings(issuer="iss", audience="aud", client_id="cid"))
    assert s2.resolved_issuer == "iss"
    assert s2.resolved_audience == "aud"
    assert s2.resolved_client_id == "cid"


def test_webauthn_identity_falls_back_to_base_url_and_app_name():
    s = _valid(app_name="Example")
    assert s.resolved_webauthn_rp_id == "app.test"
    assert s.resolved_webauthn_rp_name == "Example"
    assert s.resolved_webauthn_origins == ("https://app.test",)
    explicit = _valid(webauthn=jafaal.WebAuthnSettings(rp_id="example.com", origins=("https://a.example.com",)))
    assert explicit.resolved_webauthn_rp_id == "example.com"
    assert explicit.resolved_webauthn_origins == ("https://a.example.com",)


def test_csrf_trusted_origins_fall_back_to_base_url():
    assert _valid().resolved_csrf_trusted_origins == ("https://app.test",)
    explicit = _valid(sessions=jafaal.SessionSettings(csrf_trusted_origins=("https://ui.example",)))
    assert explicit.resolved_csrf_trusted_origins == ("https://ui.example",)


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #


def test_is_deployed():
    assert _valid(environment="production").is_deployed is True
    assert _valid(environment="demo").is_deployed is True
    assert _valid(environment="staging").is_deployed is True
    assert _valid(environment="test").is_deployed is False
    assert _valid(environment="development").is_deployed is False


def test_every_known_environment_is_accepted():
    for name in settings_mod.KNOWN_ENVIRONMENTS:
        assert _valid(environment=name).environment == name


def test_unknown_environment_is_rejected():
    # ``is_deployed`` gates the cookie Secure flag, the cookie name prefix, and
    # the two fail-closed startup guards, so a typo must never silently fall
    # through to "not deployed".
    for typo in ("prod", "Production", "PRODUCTION", "live", "prd", ""):
        with pytest.raises(ValueError, match="not a recognised environment"):
            _valid(environment=typo)


def test_deployed_and_local_environment_sets_are_disjoint():
    assert not (settings_mod.DEPLOYED_ENVIRONMENTS & settings_mod.LOCAL_ENVIRONMENTS)
    assert settings_mod.KNOWN_ENVIRONMENTS == (settings_mod.DEPLOYED_ENVIRONMENTS | settings_mod.LOCAL_ENVIRONMENTS)


def test_default_environment_is_the_safe_one():
    # Forgetting to set it must not weaken a deployment.
    assert _valid().is_deployed is True


# --------------------------------------------------------------------------- #
# Immutability and the accessor lifecycle
# --------------------------------------------------------------------------- #


def test_settings_are_frozen():
    s = _valid()
    with pytest.raises(FrozenInstanceError):
        s.secrets.secret_key = "other"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        s.tokens.algorithm = "RS256"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        s.app_name = "other"  # type: ignore[misc]


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


# --------------------------------------------------------------------------- #
# Secret redaction
#
# ``Secrets`` is a dataclass, so the generated ``__repr__`` would otherwise print
# the JWT signing key and the Fernet at-rest key verbatim into any traceback
# frame dump, error-tracker payload, or ``logger.debug(settings)``.
# --------------------------------------------------------------------------- #

_SECRET_FIELDS = (
    "secret_key",
    "fernet_key",
    "private_key",
    "secret_key_fallbacks",
    "fernet_key_fallbacks",
    "private_key_fallbacks",
)


def test_repr_and_str_never_expose_key_material():
    secret = "supersecret-signing-key-value-01"
    old_secret = "previous-signing-key-value-00000"
    fernet = Fernet.generate_key().decode()
    old_fernet = Fernet.generate_key().decode()
    private_pem = _rsa_pem()

    settings = _valid(
        secrets=jafaal.Secrets(
            secret_key=secret,
            secret_key_fallbacks=(old_secret,),
            fernet_key=fernet,
            fernet_key_fallbacks=(old_fernet,),
            private_key=private_pem,
        ),
        tokens=jafaal.TokenSettings(algorithm="RS256"),
    )

    # The root repr embeds the group reprs, so redaction must survive nesting.
    for rendered in (repr(settings), str(settings), f"{settings}", repr(settings.secrets)):
        for leaked in (secret, old_secret, fernet, old_fernet, private_pem):
            assert leaked not in rendered

    for rendered in (repr(settings), repr(settings.secrets)):
        # The fields are visibly redacted rather than silently dropped, so a
        # missing value is still distinguishable from a hidden one.
        for name in _SECRET_FIELDS:
            assert f"{name}=<redacted>" in rendered

    # Non-secret configuration is still rendered, so the repr stays useful.
    assert "app_name=" in repr(settings)
    assert "algorithm='RS256'" in repr(settings)


def test_every_key_bearing_field_is_declared_repr_false():
    # The ``repr=False`` flag on the field is the single source of truth the
    # custom __repr__ reads, so a newly added secret field must carry it.
    non_repr = {f.name for f in dataclasses.fields(jafaal.Secrets) if not f.repr}
    assert non_repr == set(_SECRET_FIELDS)


def test_no_secret_bearing_field_lives_outside_the_secrets_group():
    """Key material must be confined to ``Secrets``, which is the redacted group.

    Any other group renders its fields verbatim, so a key stored there would
    leak through the root repr.
    """
    key_ish = ("secret", "fernet", "private_key", "password", "token")
    for group in (
        jafaal.TokenSettings,
        jafaal.SessionSettings,
        jafaal.PasswordSettings,
        jafaal.MfaSettings,
        jafaal.WebAuthnSettings,
        jafaal.SsoSettings,
        jafaal.NetworkSettings,
        jafaal.RateLimitSettings,
        jafaal.ApiKeySettings,
        jafaal.AuditSettings,
    ):
        for spec in dataclasses.fields(group):
            assert not any(spec.name.startswith(word) for word in key_ish), (
                f"{group.__name__}.{spec.name} looks like key material; it belongs in Secrets"
            )


def test_secret_values_are_still_readable_as_attributes():
    # Redaction is presentational only; the library reads these normally.
    settings = _valid(secrets=_secrets(secret_key="z" * 32))
    assert settings.secrets.secret_key == "z" * 32
