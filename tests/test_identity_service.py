"""Tests for the IdentityService boundary and the unified JWT/API-key resolver."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from starlette.requests import Request

import jafaal
import jafaal.api_keys.crud as api_keys_crud
import jafaal.api_keys.schema as api_keys_schema
import jafaal.exceptions as exc
from jafaal._internal.internal_dependencies import validate_access_token_or_api_key
from jafaal._internal.password_hasher import get_password_hasher
from jafaal._internal.token_manager import TokenType, get_token_manager
from jafaal.identity_service import DefaultIdentityService, IdentityService, LocalCredentialStore


def _svc(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _request(path="/api/v1/x", client_host="203.0.113.1"):
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": b"",
        "headers": [],
        "client": (client_host, 1234),
        "scheme": "http",
        "server": ("test", 80),
    }
    return Request(scope)


def _make_api_key(db, user_id, scopes=("reports:read",), is_active=True):
    jafaal.configure_api_key_scopes(list(scopes))
    data = api_keys_schema.UsersApiKeyCreate(name="k", scopes=list(scopes))
    db_key, raw = api_keys_crud.create_api_key(user_id, data, db)
    if not is_active:
        db_key.is_active = False
        db.commit()
    return db_key, raw


# --------------------------------------------------------------------------- #
# Password auth
# --------------------------------------------------------------------------- #


def test_authenticate_password_success(db, make_user):
    user = make_user(username="alice", password="Str0ng!Pass")
    principal = _svc(db).authenticate_password("alice", "Str0ng!Pass")
    assert principal.user_id == user.id


def test_authenticate_password_wrong(db, make_user):
    make_user(username="alice", password="Str0ng!Pass")
    with pytest.raises(exc.InvalidCredentialsError):
        _svc(db).authenticate_password("alice", "WRONG")


def test_authenticate_password_unknown_user(db):
    with pytest.raises(exc.InvalidCredentialsError):
        _svc(db).authenticate_password("ghost", "whatever")


def test_authenticate_password_sso_only_account(db, make_user):
    # No local password → treated identically to a wrong password.
    make_user(username="ssoonly", password=None)
    with pytest.raises(exc.InvalidCredentialsError):
        _svc(db).authenticate_password("ssoonly", "anything")


def test_validate_and_hash_password_rejects_breached(db):
    # A policy-valid password is rejected when the configured breach checker
    # flags it (NIST SP 800-63B breach screening). Default null checker allows it.
    class _BreachAll:
        def is_breached(self, password: str) -> bool:
            return True

    svc = _svc(db)
    assert svc.validate_and_hash_password("Str0ng!Pass", 8, "strict")  # null checker → allowed
    jafaal.configure_password_breach_checker(_BreachAll())
    try:
        with pytest.raises(exc.PasswordPolicyError, match="breach"):
            svc.validate_and_hash_password("Str0ng!Pass", 8, "strict")
    finally:
        jafaal.configure_password_breach_checker(jafaal.NullPasswordBreachChecker())


# --------------------------------------------------------------------------- #
# Access token resolution
# --------------------------------------------------------------------------- #


def test_resolve_from_access_token(db, make_user):
    user = make_user(username="alice")
    _, token = get_token_manager().create_token("sid-1", user, TokenType.ACCESS)
    principal = _svc(db).resolve_from_access_token(token)
    assert principal.user_id == user.id
    assert principal.credential.session_id == "sid-1"


def test_resolve_from_access_token_inactive_user(db, make_user):
    user = make_user(username="inactive", is_active=False)
    _, token = get_token_manager().create_token("s", user, TokenType.ACCESS)
    # A deactivated account makes the credential unusable, so this is a 401
    # invalid_token — not a 403, which would confirm the token is otherwise good.
    with pytest.raises(exc.InactiveAccountError):
        _svc(db).resolve_from_access_token(token)


def test_resolve_from_access_token_invalid(db):
    with pytest.raises(exc.InvalidTokenError):
        _svc(db).resolve_from_access_token("not.a.valid.token")


# --------------------------------------------------------------------------- #
# API key resolution
# --------------------------------------------------------------------------- #


def test_resolve_from_api_key_success(db, make_user):
    user = make_user()
    _, raw = _make_api_key(db, user.id)
    principal = _svc(db).resolve_from_api_key(raw, _request())
    assert principal.user_id == user.id
    assert "reports:read" in principal.scopes


def test_resolve_from_api_key_wrong_key(db, make_user):
    user = make_user()
    _make_api_key(db, user.id)
    with pytest.raises(exc.InvalidApiKeyError):
        _svc(db).resolve_from_api_key("jafaal_totallyBogusKeyValue", _request())


def test_resolve_from_api_key_revoked(db, make_user):
    user = make_user()
    _, raw = _make_api_key(db, user.id, is_active=False)
    with pytest.raises(exc.InvalidApiKeyError):
        _svc(db).resolve_from_api_key(raw, _request())


def test_resolve_from_api_key_expired(db, make_user):
    user = make_user()
    db_key, raw = _make_api_key(db, user.id)
    # Expire the key; expiry is compared in Python, so this exercises the
    # tz-normalization that keeps the comparison safe on naive-datetime backends.
    db_key.expires_at = datetime.now(UTC) - timedelta(days=1)
    db.commit()
    with pytest.raises(exc.InvalidApiKeyError):
        _svc(db).resolve_from_api_key(raw, _request())


# --------------------------------------------------------------------------- #
# Session cookie + scope checks
# --------------------------------------------------------------------------- #


def test_resolve_from_session_cookie_missing(db):
    with pytest.raises(exc.SessionExpiredError):
        _svc(db).resolve_from_session_cookie("no-such-session")


def test_check_scope(db, make_user):
    user = make_user(username="alice")
    _, token = get_token_manager().create_token("s", user, TokenType.ACCESS)
    svc = _svc(db)
    principal = svc.resolve_from_access_token(token)
    svc.check_scope(principal, frozenset({"profile"}))  # regular scope: OK
    with pytest.raises(exc.MissingScopeError):
        svc.check_scope(principal, frozenset({"users:write"}))  # admin-only


# --------------------------------------------------------------------------- #
# Local-password helpers
# --------------------------------------------------------------------------- #


def test_local_password_helpers(db, make_user):
    user = make_user(username="alice", password="Str0ng!Pass")
    svc = _svc(db)
    assert svc.has_local_password(user.id) is True
    assert svc.get_password_hash(user.id) is not None

    svc.clear_local_password(user.id)
    assert svc.has_local_password(user.id) is False

    svc.set_local_password_hash(user.id, get_password_hasher().hash_password("New1!Pass"))
    assert svc.has_local_password(user.id) is True


# --------------------------------------------------------------------------- #
# Unified JWT / API-key dependency
# --------------------------------------------------------------------------- #


def test_unified_auth_accepts_jwt(db, make_user):
    user = make_user()
    _, token = get_token_manager().create_token("s", user, TokenType.ACCESS)
    ctx = asyncio.run(
        validate_access_token_or_api_key(
            _request(), _svc(db), access_token=token, api_key_header=None, api_key_query=None
        )
    )
    assert ctx.user_id == user.id
    assert ctx.auth_type == "jwt"


def test_unified_auth_accepts_api_key(db, make_user):
    user = make_user()
    _, raw = _make_api_key(db, user.id)
    ctx = asyncio.run(
        validate_access_token_or_api_key(
            _request(), _svc(db), access_token=None, api_key_header=raw, api_key_query=None
        )
    )
    assert ctx.user_id == user.id
    assert ctx.auth_type == "api_key"


def test_unified_auth_requires_a_credential(db):
    with pytest.raises(exc.AuthenticationError):
        asyncio.run(
            validate_access_token_or_api_key(
                _request(), _svc(db), access_token=None, api_key_header=None, api_key_query=None
            )
        )


# --------------------------------------------------------------------------- #
# The boundary is a boundary, not a table of contents
# --------------------------------------------------------------------------- #


def _protocol_methods(protocol: type) -> set[str]:
    """Return the method names a Protocol declares."""
    return {name for name in getattr(protocol, "__protocol_attrs__", set()) if not name.startswith("_")}


def test_identity_service_declares_only_the_credential_boundary():
    """Pin the boundary's shape so it cannot silently re-grow into a facade.

    It once carried 33 methods — MFA enrolment, session listing, password
    changes, identity-provider links — which meant a host wanting to swap
    *authentication* had to re-implement two dozen methods that were pure
    passthroughs to JAFAAL's own services. Anything added here should answer
    "how do I recognise this caller, and how do I start and stop their session?"
    """
    assert _protocol_methods(IdentityService) == {
        "authenticate_password",
        "resolve_from_access_token",
        "resolve_from_api_key",
        "resolve_from_session_cookie",
        "issue_token_pair",
        "revoke_session",
        "check_scope",
    }


def test_local_credential_store_declares_only_the_password_seam():
    assert _protocol_methods(LocalCredentialStore) == {
        "validate_and_hash_password",
        "hash_password",
        "verify_password",
        "get_password_hash",
        "has_local_password",
        "set_local_password_hash",
        "clear_local_password",
    }


def test_the_default_implementation_satisfies_both(db):
    # Both are runtime_checkable, so a host can assert its own replacement
    # conforms at startup rather than discovering a missing method on the login
    # path.
    svc = _svc(db)
    assert isinstance(svc, IdentityService)
    assert isinstance(svc, LocalCredentialStore)


def test_the_two_protocols_do_not_overlap():
    # Disjoint surfaces are what makes them independently swappable: a host can
    # replace password storage without touching credential resolution.
    assert not _protocol_methods(IdentityService) & _protocol_methods(LocalCredentialStore)


def test_workflow_services_are_reached_directly_not_through_the_boundary():
    """The application services take a session, not a bound facade.

    This is the shape that let the boundary shrink: a caller that wants to list
    sessions or enrol MFA imports the service and passes `db`, instead of the
    boundary carrying a method for it.
    """
    import inspect

    import jafaal._internal.services.account_security_service as account_security_service
    import jafaal._internal.services.mfa_workflow as mfa_workflow

    for fn in (account_security_service.get_user_sessions, mfa_workflow.get_mfa_status):
        assert "db" in inspect.signature(fn).parameters, fn.__name__
