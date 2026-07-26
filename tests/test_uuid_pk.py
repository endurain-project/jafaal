"""UUID primary-key support.

JAFAAL supports either an integer or a UUID user primary key. Because all
JAFAAL models and the host ``Users`` model must share one declarative registry
(:data:`jafaal.orm.Base`), a process can only map ``users`` once — the suite's
``conftest`` already maps an *integer* ``Users``. The genuine end-to-end UUID
scenario is therefore exercised in an isolated subprocess (a fresh registry with
a ``UUIDPKUserMixin`` ``Users``), while the coercion/serialisation seams are
unit-tested in-process.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import uuid
from types import SimpleNamespace

import pytest

import jafaal.orm as jafaal_orm
from jafaal._internal.token_manager import TokenType, get_token_manager

# --------------------------------------------------------------------------- #
# In-process seams (integer registry from conftest)
# --------------------------------------------------------------------------- #


def test_coerce_user_id_on_integer_registry():
    """With an int PK, string/int subjects coerce to int and a UUID is rejected."""
    assert jafaal_orm.user_id_python_type() is int
    assert jafaal_orm.coerce_user_id(5) == 5
    assert jafaal_orm.coerce_user_id("5") == 5
    assert jafaal_orm.coerce_user_id(None) is None
    # A UUID string cannot be an integer PK — malformed subject.
    with pytest.raises(ValueError):
        jafaal_orm.coerce_user_id(str(uuid.uuid4()))


def test_create_token_serializes_uuid_subject():
    """A UUID ``user.id`` is minted into the JWT ``sub`` as its string form."""
    tm = get_token_manager()
    uid = uuid.uuid4()
    user = SimpleNamespace(id=uid, is_superuser=False)

    _, access = tm.create_token("session-1", user, TokenType.ACCESS)
    claims = tm.decode_token(access).claims

    assert claims["sub"] == str(uid)
    assert isinstance(claims["sub"], str)


def test_create_token_keeps_integer_subject_int():
    """An integer ``user.id`` is serialised as a string ``sub`` (RFC 7519 §4.1.2).

    ``sub`` is defined as StringOrURI, so the RFC 9068 profile always emits a
    string; ``coerce_user_id`` converts it back to the host PK type on the way
    in. The ``legacy`` profile keeps the historical int.
    """
    tm = get_token_manager()
    user = SimpleNamespace(id=123, is_superuser=False)

    _, access = tm.create_token("session-1", user, TokenType.ACCESS)
    claims = tm.decode_token(access).claims

    assert claims["sub"] == "123"
    assert isinstance(claims["sub"], str)


# --------------------------------------------------------------------------- #
# End-to-end UUID PK (isolated subprocess → fresh single registry)
# --------------------------------------------------------------------------- #

_UUID_E2E = textwrap.dedent(
    '''
    import uuid

    from cryptography.fernet import Fernet
    from sqlalchemy import String, create_engine
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

    import jafaal
    import jafaal.orm as jafaal_orm
    from jafaal import UUIDPKUserMixin


    class Base(DeclarativeBase):
        pass


    class Users(UUIDPKUserMixin, Base):
        __tablename__ = "users"
        display_name: Mapped[str | None] = mapped_column(String(250), nullable=True)


    # Host owns the base; map JAFAAL's tables into it before any model/CRUD import.
    jafaal.map_models(Base)

    import jafaal.credentials.crud as credentials_crud
    from jafaal._internal.password_hasher import password_hasher
    from jafaal._internal.token_manager import TokenType, get_token_manager
    from jafaal.identity_service import DefaultIdentityService


    class Repo:
        """Minimal UserRepository — only get_by_id is on the resolve path."""

        def get_by_id(self, user_id, db):
            return db.get(Users, user_id)

        def get_by_email(self, email, db):
            return db.query(Users).filter(Users.email == email).one_or_none()

        def get_by_username(self, username, db):
            return db.query(Users).filter(Users.username == username).one_or_none()

        def create_local_user(self, username, email, db, *, is_active, is_verified):
            raise NotImplementedError

        def provision_from_idp(self, identity, db):
            raise NotImplementedError

        def sync_from_idp(self, user_id, claims, db):
            return None

        def set_email_verified(self, user_id, db, *, activate):
            return None


    jafaal.configure(
        jafaal.AuthSettings(
            secret_key="s" * 32,
            fernet_key=Fernet.generate_key().decode(),
            base_url="https://app.test",
            environment="test",
        )
    )
    engine = create_engine("sqlite://")
    jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False, expire_on_commit=False))
    jafaal.configure_user_repository(Repo())
    Base.metadata.create_all(engine)

    # 1. Every companion FK follows the UUID primary key.
    fk_tables = [
        "users_sessions",
        "users_api_keys",
        "users_local_credentials",
        "idp_link_tokens",
        "users_identity_providers",
        "mfa_backup_codes",
        "users_mfa",
        "oauth_states",
        "password_reset_tokens",
        "sign_up_tokens",
    ]
    for name in fk_tables:
        col = Base.metadata.tables[name].c.user_id
        assert col.type.python_type is uuid.UUID, (name, col.type)

    assert jafaal_orm.user_id_python_type() is uuid.UUID

    # 2. Create a user + credential: companion FK + reverse relationship resolve.
    db = jafaal_orm.get_sessionmaker()()
    user = Users(username="alice", email="alice@test.dev", is_active=True, is_verified=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    uid = user.id
    assert isinstance(uid, uuid.UUID)

    credentials_crud.upsert_password_hash(uid, password_hasher.hash_password("Str0ng!Pass"), db)
    db.refresh(user)
    assert user.local_credential is not None
    assert user.local_credential.user_id == uid

    # 3. Token round-trip: sub is minted as a string and resolves back to the user.
    tm = get_token_manager()
    _, access = tm.create_token(str(uuid.uuid4()), user, TokenType.ACCESS)
    claims = tm.decode_token(access).claims
    assert claims["sub"] == str(uid)

    principal = DefaultIdentityService(db, tm, password_hasher).resolve_from_access_token(access)
    assert isinstance(principal.user_id, uuid.UUID)
    assert principal.user_id == uid
    assert principal.username == "alice"

    # 3b. Pending-MFA login round-trips the UUID id. Regression: get/claim used
    #     to int()-parse the stored value, which raised ValueError for a UUID and
    #     permanently broke MFA login for UUID-PK hosts (202 then "no pending
    #     login" forever).
    from jafaal._internal.security_stores import PendingMFALogin

    pending = PendingMFALogin()
    ticket = pending.add_pending_login("alice", uid)
    fetched = pending.get_pending_login(ticket)
    assert fetched is not None
    assert isinstance(fetched.user_id, uuid.UUID) and fetched.user_id == uid, (fetched, type(fetched.user_id))
    claimed = pending.claim_pending_login(ticket)
    assert claimed is not None
    assert isinstance(claimed.user_id, uuid.UUID) and claimed.user_id == uid, (claimed, type(claimed.user_id))
    assert pending.get_pending_login(ticket) is None

    # 4. Cascade delete through the UUID FK.
    db.delete(user)
    db.commit()
    from jafaal.credentials.models import LocalCredential

    assert db.query(LocalCredential).count() == 0

    print("UUID_PK_OK")
    '''
)


def test_uuid_pk_end_to_end():
    """A host mapping ``Users`` on ``UUIDPKUserMixin`` works end to end."""
    result = subprocess.run(
        [sys.executable, "-c", _UUID_E2E],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"subprocess failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    assert "UUID_PK_OK" in result.stdout, result.stdout
