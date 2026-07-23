"""Tests for the identity-link service, link tokens, and link CRUD/utils (DB-only)."""

from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from starlette.requests import Request

import jafaal._internal.services.identity_link_service as link_service
import jafaal.exceptions as exc
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.link_tokens.crud as link_token_crud
import jafaal.identity_providers.link_tokens.schema as link_token_schema
import jafaal.identity_providers.link_tokens.utils as link_token_utils
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.links.utils as links_utils
import jafaal.identity_providers.schema as idp_schema
import jafaal.mfa.crud as mfa_crud
import jafaal.schema as jafaal_schema
from jafaal._core import crypto
from jafaal._internal.password_hasher import get_password_hasher
from jafaal._internal.security_stores import StepUpAttempts
from jafaal._internal.token_manager import get_token_manager
from jafaal.identity_service import DefaultIdentityService


def _svc(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _request(host="1.2.3.4"):
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "client": (host, 1),
        "scheme": "https",
        "server": ("app.test", 443),
    }
    return Request(scope)


def _create_idp(db, *, slug="oidc", enabled=True):
    return idp_crud.create_identity_provider(
        idp_schema.IdentityProviderCreate(
            name=f"IdP {slug}", slug=slug, client_id="cid", client_secret="secret", enabled=enabled
        ),
        db,
    )


# --------------------------------------------------------------------------- #
# Link-token utils + CRUD
# --------------------------------------------------------------------------- #


def test_hash_idp_link_token_is_deterministic():
    assert link_token_utils.hash_idp_link_token("abc") == link_token_utils.hash_idp_link_token("abc")


def test_generate_and_lookup_link_token(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    resp = link_token_utils.generate_idp_link_token(user.id, idp.id, "1.2.3.4", db)
    assert resp.token
    row = link_token_crud.get_idp_link_token_by_hash(link_token_utils.hash_idp_link_token(resp.token), db)
    assert row is not None
    assert row.user_id == user.id


def test_mark_link_token_used_is_single_use(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    resp = link_token_utils.generate_idp_link_token(user.id, idp.id, None, db)
    token_hash = link_token_utils.hash_idp_link_token(resp.token)
    assert link_token_crud.mark_token_as_used(token_hash, db) is True
    assert link_token_crud.mark_token_as_used(token_hash, db) is False


# --------------------------------------------------------------------------- #
# generate_link_token (step-up gated)
# --------------------------------------------------------------------------- #


def test_generate_link_token_success(db, make_user):
    user = make_user(password="Str0ng!Pass")
    idp = _create_idp(db)
    req = link_token_schema.IdpLinkTokenRequest(current_password="Str0ng!Pass", mfa_code=None)
    resp = link_service.generate_link_token(idp.id, req, _request(), user.id, _svc(db), StepUpAttempts(), db)
    assert resp.token


def test_generate_link_token_idp_not_found(db, make_user):
    user = make_user(password="Str0ng!Pass")
    req = link_token_schema.IdpLinkTokenRequest(current_password="Str0ng!Pass", mfa_code=None)
    with pytest.raises(exc.NotFoundError):
        link_service.generate_link_token(9999, req, _request(), user.id, _svc(db), StepUpAttempts(), db)


def test_generate_link_token_already_linked(db, make_user):
    user = make_user(password="Str0ng!Pass")
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    req = link_token_schema.IdpLinkTokenRequest(current_password="Str0ng!Pass", mfa_code=None)
    with pytest.raises(exc.ConflictError):
        link_service.generate_link_token(idp.id, req, _request(), user.id, _svc(db), StepUpAttempts(), db)


def test_generate_link_token_step_up_fails(db, make_user):
    user = make_user(password="Str0ng!Pass")
    idp = _create_idp(db)
    req = link_token_schema.IdpLinkTokenRequest(current_password="WRONG!Pass", mfa_code=None)
    with pytest.raises(exc.InvalidCredentialsError):
        link_service.generate_link_token(idp.id, req, _request(), user.id, _svc(db), StepUpAttempts(), db)


# --------------------------------------------------------------------------- #
# delete_identity_provider_link (self-service) + admin unlink
# --------------------------------------------------------------------------- #


def test_delete_link_success_with_password(db, make_user):
    user = make_user(password="Str0ng!Pass")
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    step_up = jafaal_schema.StepUpVerification(current_password="Str0ng!Pass", mfa_code=None)
    link_service.delete_identity_provider_link(idp.id, step_up, user.id, _svc(db), StepUpAttempts(), db)
    assert links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db) is None


def test_delete_link_blocks_last_auth_method(db, make_user):
    # SSO-only account whose only login method is a single IdP link cannot
    # unlink it (anti-lockout guard). MFA is enrolled here so step-up is
    # satisfiable — proving the unlink is blocked by the last-auth-method guard,
    # not by the fail-closed step-up check (MFA is a second factor, not a
    # primary login method, so it does not count as a remaining auth method).
    secret = pyotp.random_base32()
    user = make_user(password=None)
    mfa_crud.update_user_mfa(user.id, db, encrypted_secret=crypto.encrypt_token_fernet(secret))
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    step_up = jafaal_schema.StepUpVerification(current_password=None, mfa_code=pyotp.TOTP(secret).now())
    with pytest.raises(exc.InvalidRequestError):
        link_service.delete_identity_provider_link(idp.id, step_up, user.id, _svc(db), StepUpAttempts(), db)


def test_delete_link_challenges_reauth_for_sso_only_without_local_factor(db, make_user):
    # An SSO-only account with no password and no MFA cannot satisfy step-up with
    # a bare access token. Because it has usable IdP links, step-up challenges
    # the caller to re-authenticate (rather than silently allowing the unlink).
    # A second link is present so the denial comes from step-up, not from the
    # anti-lockout last-auth-method guard.
    user = make_user(password=None)
    idp = _create_idp(db, slug="first")
    idp2 = _create_idp(db, slug="second")
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    links_crud.create_user_identity_provider(user.id, idp2.id, "sub2", db)
    step_up = jafaal_schema.StepUpVerification(current_password=None, mfa_code=None)
    with pytest.raises(exc.StepUpReauthRequiredError):
        link_service.delete_identity_provider_link(idp.id, step_up, user.id, _svc(db), StepUpAttempts(), db)


def test_delete_link_not_linked(db, make_user):
    user = make_user(password="Str0ng!Pass")
    idp = _create_idp(db)
    step_up = jafaal_schema.StepUpVerification(current_password="Str0ng!Pass", mfa_code=None)
    with pytest.raises(exc.NotFoundError):
        link_service.delete_identity_provider_link(idp.id, step_up, user.id, _svc(db), StepUpAttempts(), db)


def test_admin_delete_link(db, make_user):
    user = make_user(password="Str0ng!Pass")
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    link_service.admin_delete_identity_provider_link(user.id, idp.id, db)
    assert links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db) is None


def test_admin_delete_blocks_last_auth_method(db, make_user):
    user = make_user(password=None)
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    with pytest.raises(exc.InvalidRequestError):
        link_service.admin_delete_identity_provider_link(user.id, idp.id, db)


# --------------------------------------------------------------------------- #
# Link listing / enrichment / counts
# --------------------------------------------------------------------------- #


def test_get_user_identity_provider_links_enriched(db, make_user):
    user = make_user()
    idp = _create_idp(db, slug="goog")
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    links = link_service.get_user_identity_provider_links(user.id, db)
    assert len(links) == 1
    assert links[0].idp_slug == "goog"
    assert links[0].idp_name == "IdP goog"


def test_enrich_empty_returns_empty(db, make_user):
    user = make_user()
    assert links_utils.enrich_user_identity_providers([], user.id, db) == []


def test_get_identity_link_counts_for_users(db, make_user):
    u1 = make_user(username="u1")
    u2 = make_user(username="u2")
    idp = _create_idp(db, slug="a")
    idp2 = _create_idp(db, slug="b")
    links_crud.create_user_identity_provider(u1.id, idp.id, "s1", db)
    links_crud.create_user_identity_provider(u1.id, idp2.id, "s2", db)
    links_crud.create_user_identity_provider(u2.id, idp.id, "s3", db)
    counts = link_service.get_identity_link_counts_for_users([u1.id, u2.id], db)
    assert counts[u1.id] == 2
    assert counts[u2.id] == 1
    assert link_service.get_identity_link_counts_for_users([], db) == {}


# --------------------------------------------------------------------------- #
# validate_and_claim_browser_link_token
# --------------------------------------------------------------------------- #


def test_validate_and_claim_link_token(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    resp = link_token_utils.generate_idp_link_token(user.id, idp.id, "1.2.3.4", db)
    assert link_service.validate_and_claim_browser_link_token(resp.token, idp.id, "1.2.3.4", db) == user.id
    # Replay: the token was consumed, so it is no longer valid.
    with pytest.raises(exc.JafaalError):
        link_service.validate_and_claim_browser_link_token(resp.token, idp.id, "1.2.3.4", db)


def test_validate_claim_invalid_token(db):
    with pytest.raises(exc.InvalidTokenError):
        link_service.validate_and_claim_browser_link_token("bogus-token", 1, None, db)


def test_validate_claim_idp_mismatch(db, make_user):
    user = make_user()
    idp = _create_idp(db, slug="a")
    other = _create_idp(db, slug="b")
    resp = link_token_utils.generate_idp_link_token(user.id, idp.id, None, db)
    with pytest.raises(exc.InvalidTokenError):
        link_service.validate_and_claim_browser_link_token(resp.token, other.id, None, db)


def test_validate_claim_existing_link_conflict(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    resp = link_token_utils.generate_idp_link_token(user.id, idp.id, None, db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    with pytest.raises(exc.ConflictError):
        link_service.validate_and_claim_browser_link_token(resp.token, idp.id, None, db)


# --------------------------------------------------------------------------- #
# links CRUD: last-login, token store/clear, delete
# --------------------------------------------------------------------------- #


def test_update_last_login(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    updated = links_crud.update_user_identity_provider_last_login(user.id, idp.id, db)
    assert updated is not None
    assert updated.last_login is not None


def test_store_and_clear_idp_tokens(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)

    encrypted = crypto.encrypt_token_fernet("refresh-tok")
    links_crud.store_user_identity_provider_tokens(
        user.id, idp.id, encrypted, datetime.now(UTC) + timedelta(hours=1), db
    )
    stored = links_utils.get_user_identity_provider_refresh_token_by_user_id_and_idp_id(user.id, idp.id, db)
    assert crypto.decrypt_token_fernet(stored) == "refresh-tok"

    assert links_crud.clear_user_identity_provider_refresh_token_by_user_id_and_idp_id(user.id, idp.id, db) is True
    assert links_utils.get_user_identity_provider_refresh_token_by_user_id_and_idp_id(user.id, idp.id, db) is None


def test_delete_user_identity_provider_returns_bool(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "sub", db)
    assert links_crud.delete_user_identity_provider(user.id, idp.id, db) is True
    assert links_crud.delete_user_identity_provider(user.id, idp.id, db) is False
