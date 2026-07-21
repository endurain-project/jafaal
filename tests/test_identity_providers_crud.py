"""Tests for identity-provider and identity-link CRUD (DB-only, no OIDC calls)."""

import pytest

import jafaal.exceptions as exc
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.schema as idp_schema
from jafaal._core import crypto


def _create_idp(db, *, slug="test-idp", name="Test IdP", enabled=True):
    data = idp_schema.IdentityProviderCreate(
        name=name,
        slug=slug,
        client_id="client-123",
        client_secret="secret-456",
        enabled=enabled,
        issuer_url="https://idp.example",
    )
    return idp_crud.create_identity_provider(data, db)


# --------------------------------------------------------------------------- #
# Identity provider CRUD
# --------------------------------------------------------------------------- #


def test_create_and_fetch_identity_provider(db):
    idp = _create_idp(db)
    assert idp.id is not None
    assert idp_crud.get_identity_provider(idp.id, db).slug == "test-idp"
    assert idp_crud.get_identity_provider_by_slug("test-idp", db).id == idp.id
    assert idp_crud.get_identity_provider_by_slug("missing", db) is None


def test_client_secret_encrypted_at_rest(db):
    idp = _create_idp(db)
    assert idp.client_secret != "secret-456"  # stored encrypted
    assert crypto.decrypt_token_fernet(idp.client_secret) == "secret-456"
    assert crypto.decrypt_token_fernet(idp.client_id) == "client-123"


def test_list_and_filter_identity_providers(db):
    _create_idp(db, slug="idp-a", name="A IdP", enabled=True)
    _create_idp(db, slug="idp-b", name="B IdP", enabled=False)
    all_idps = idp_crud.get_all_identity_providers(db)
    assert {i.slug for i in all_idps} == {"idp-a", "idp-b"}
    enabled = idp_crud.get_enabled_identity_providers(db)
    assert {i.slug for i in enabled} == {"idp-a"}
    ids = [i.id for i in all_idps]
    assert len(idp_crud.get_identity_providers_by_ids(ids, db)) == 2
    assert idp_crud.get_identity_providers_by_ids([], db) == []


def test_create_duplicate_slug_conflicts(db):
    _create_idp(db, slug="dup")
    with pytest.raises(exc.ConflictError):
        _create_idp(db, slug="dup", name="Other")


def test_update_identity_provider(db):
    idp = _create_idp(db)
    updated = idp_crud.update_identity_provider(
        idp.id,
        idp_schema.IdentityProviderUpdate(name="Renamed", slug="test-idp", client_secret="new-secret"),
        db,
    )
    assert updated.name == "Renamed"
    assert crypto.decrypt_token_fernet(updated.client_secret) == "new-secret"


def test_update_missing_identity_provider(db):
    with pytest.raises(exc.NotFoundError):
        idp_crud.update_identity_provider(
            9999,
            idp_schema.IdentityProviderUpdate(name="X", slug="x"),
            db,
        )


def test_delete_identity_provider(db):
    idp = _create_idp(db)
    idp_crud.delete_identity_provider(idp.id, db)
    assert idp_crud.get_identity_provider(idp.id, db) is None


def test_delete_missing_identity_provider(db):
    with pytest.raises(exc.NotFoundError):
        idp_crud.delete_identity_provider(9999, db)


def test_delete_identity_provider_with_linked_user_conflicts(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "subject-1", db)
    with pytest.raises(exc.ConflictError):
        idp_crud.delete_identity_provider(idp.id, db)


# --------------------------------------------------------------------------- #
# Identity link CRUD
# --------------------------------------------------------------------------- #


def test_create_and_fetch_identity_link(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    link = links_crud.create_user_identity_provider(user.id, idp.id, "subject-1", db)
    assert link.user_id == user.id

    assert links_crud.check_user_identity_providers_by_idp_id(idp.id, db) is True
    by_user = links_crud.get_user_identity_providers_by_user_id(user.id, db)
    assert len(by_user) == 1
    assert links_crud.get_user_identity_provider_by_user_id_and_idp_id(user.id, idp.id, db) is not None
    assert links_crud.get_user_identity_provider_by_subject_and_idp_id(idp.id, "subject-1", db) is not None
    assert links_crud.get_user_identity_provider_by_subject_and_idp_id(idp.id, "nobody", db) is None


def test_duplicate_identity_link_conflicts(db, make_user):
    user = make_user()
    idp = _create_idp(db)
    links_crud.create_user_identity_provider(user.id, idp.id, "subject-1", db)
    with pytest.raises(exc.ConflictError):
        links_crud.create_user_identity_provider(user.id, idp.id, "subject-1", db)
