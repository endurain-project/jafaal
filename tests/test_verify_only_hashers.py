"""Verify-only password hashers: the migration path into JAFAAL.

A host adopting JAFAAL may hold hashes from another scheme. They verify, are
upgraded to Argon2id on first successful login, and are never produced.
"""

from __future__ import annotations

import logging
import unicodedata

import pytest
from conftest import NATIVE_CLIENT_ID, replace_settings
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

import jafaal
import jafaal.credentials.crud as credentials_crud
import jafaal.maintenance as maintenance
from jafaal._internal.password_hasher import PasswordHasher, get_password_hasher

PASSWORD = "Str0ng!Pass-for-bcrypt"
BCRYPT = BcryptHasher(rounds=4)


@pytest.fixture
def configure_passwords():
    original = jafaal.get_settings()

    def _apply(**overrides):
        jafaal.configure(replace_settings(original, **overrides))

    yield _apply
    jafaal.configure(original)


def _store_hash(user, password_hash, db):
    credentials_crud.upsert_password_hash(user.id, password_hash, db)
    db.commit()


def _stored(user, db):
    db.expire_all()
    return credentials_crud.get_credential(user.id, db).password_hash


def _login(client, username, password):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password, "client_id": NATIVE_CLIENT_ID},
    )


# --------------------------------------------------------------------------- #
# Verify, upgrade, never produce
# --------------------------------------------------------------------------- #


def test_a_bcrypt_hash_verifies_and_is_upgraded_to_argon2id_on_first_login(
    configure_passwords, make_user, client, db, event_sink
):
    configure_passwords(verify_only_hashers=(BCRYPT,))
    user = make_user(username="alice", password=None)
    _store_hash(user, BCRYPT.hash(PASSWORD), db)
    assert _stored(user, db).startswith("$2")
    assert maintenance.count_non_argon2_password_hashes(db) == 1
    event_sink.events.clear()

    assert _login(client, "alice", PASSWORD).status_code == 200

    assert _stored(user, db).startswith("$argon2id$")
    assert maintenance.count_non_argon2_password_hashes(db) == 0
    # An upgrade is not a password change.
    assert not [e for e in event_sink.events if type(e).__name__ == "PasswordChanged"]
    # ...and the upgraded hash keeps working.
    assert _login(client, "alice", PASSWORD).status_code == 200


def test_a_wrong_password_against_a_bcrypt_hash_fails_and_leaves_it_alone(configure_passwords, make_user, client, db):
    configure_passwords(verify_only_hashers=(BCRYPT,))
    user = make_user(username="alice", password=None)
    original = BCRYPT.hash(PASSWORD)
    _store_hash(user, original, db)

    assert _login(client, "alice", "not-the-password-at-all").status_code == 401
    assert _stored(user, db) == original


def test_new_hashes_are_never_bcrypt(configure_passwords):
    configure_passwords(verify_only_hashers=(BCRYPT,))
    assert get_password_hasher().hash_password(PASSWORD).startswith("$argon2id$")


def test_without_verify_only_hashers_the_hasher_is_argon2_only(configure_passwords):
    configure_passwords()
    hasher = get_password_hasher()
    assert [type(h) for h in hasher._password_hash.hashers] == [Argon2Hasher]
    stored = hasher.hash_password(PASSWORD)
    assert hasher.verify_and_update(PASSWORD, stored) == (True, None)
    assert hasher.verify_and_update("wrong", stored) == (False, None)


def test_the_count_ignores_argon2id_hashes(make_user, db):
    make_user(username="alice")
    assert maintenance.count_non_argon2_password_hashes(db) == 0


# --------------------------------------------------------------------------- #
# Normalization compatibility
# --------------------------------------------------------------------------- #

NFC = unicodedata.normalize("NFC", "pässwörd-é-long-enough")
NFD = unicodedata.normalize("NFD", NFC)


def test_raw_input_is_not_retried_unless_enabled(configure_passwords, make_user, client, db):
    configure_passwords(verify_only_hashers=(BCRYPT,))
    user = make_user(username="alice", password=None)
    _store_hash(user, BCRYPT.hash(NFD), db)  # hashed by a system that did not normalize

    assert NFC != NFD
    assert _login(client, "alice", NFD).status_code == 401
    assert _stored(user, db).startswith("$2")


def test_raw_input_retry_succeeds_and_rehashes_from_the_nfc_form(configure_passwords, make_user, client, db):
    configure_passwords(verify_only_hashers=(BCRYPT,), verify_unnormalized_input=True)
    user = make_user(username="alice", password=None)
    _store_hash(user, BCRYPT.hash(NFD), db)

    assert _login(client, "alice", NFD).status_code == 200
    upgraded = _stored(user, db)
    assert upgraded.startswith("$argon2id$")
    # Re-hashed from NFC: either spelling now verifies, through JAFAAL's normalization.
    hasher = get_password_hasher()
    assert hasher.verify_password(NFC, upgraded)
    assert hasher.verify_password(NFD, upgraded)


def test_raw_input_retry_still_rejects_a_wrong_password(configure_passwords, make_user, client, db):
    configure_passwords(verify_only_hashers=(BCRYPT,), verify_unnormalized_input=True)
    user = make_user(username="alice", password=None)
    original = BCRYPT.hash(NFD)
    _store_hash(user, original, db)

    assert _login(client, "alice", NFC + "x").status_code == 401
    assert _stored(user, db) == original


def _count_verifications(hasher: PasswordHasher, monkeypatch) -> list[str]:
    calls: list[str] = []
    inner = hasher._password_hash
    real_verify, real_update = inner.verify, inner.verify_and_update

    def verify(*args, **kwargs):
        calls.append("verify")
        return real_verify(*args, **kwargs)

    def verify_and_update(*args, **kwargs):
        calls.append("verify")
        return real_verify_and_update(*args, **kwargs)

    real_verify_and_update = real_update
    monkeypatch.setattr(inner, "verify", verify)
    monkeypatch.setattr(inner, "verify_and_update", verify_and_update)
    return calls


@pytest.mark.parametrize("candidate", ["wrong-ascii-password", "wrong-pässwörd", NFD])
def test_the_failure_path_costs_the_same_verifications_for_every_input(candidate, monkeypatch):
    hasher = PasswordHasher(verify_unnormalized_input=True)
    stored = hasher.hash_password("some-other-password")
    calls = _count_verifications(hasher, monkeypatch)

    assert hasher.verify_and_update(candidate, stored) == (False, None)
    failed = len(calls)
    calls.clear()
    hasher.dummy_verify()

    assert failed == 2
    assert len(calls) == failed  # the unknown-user path is indistinguishable


def test_without_the_flag_failure_and_dummy_each_cost_one_verification(monkeypatch):
    hasher = PasswordHasher()
    stored = hasher.hash_password("some-other-password")
    calls = _count_verifications(hasher, monkeypatch)
    hasher.verify_and_update("nope", stored)
    failed = len(calls)
    calls.clear()
    hasher.dummy_verify()
    assert failed == len(calls) == 1


# --------------------------------------------------------------------------- #
# Settings validation and the startup diagnostic
# --------------------------------------------------------------------------- #


def test_verify_only_hashers_must_be_hashers():
    with pytest.raises(ValueError, match="pwdlib hasher"):
        jafaal.PasswordSettings(verify_only_hashers=(object(),))  # type: ignore[arg-type]


def test_an_argon2_hasher_is_not_a_verify_only_scheme():
    with pytest.raises(ValueError, match="Argon2"):
        jafaal.PasswordSettings(verify_only_hashers=(Argon2Hasher(),))


def test_startup_warns_while_verify_only_hashers_are_configured(configure_passwords, caplog):
    configure_passwords(verify_only_hashers=(BCRYPT,))
    with caplog.at_level(logging.WARNING, logger="jafaal.factory"):
        jafaal.create_auth_router()
    matching = [r for r in caplog.records if getattr(r, "warning_code", None) == "verify_only_hashers_configured"]
    assert len(matching) == 1
    assert "BcryptHasher" in matching[0].getMessage()


def test_no_startup_warning_without_verify_only_hashers(configure_passwords, caplog):
    configure_passwords()
    with caplog.at_level(logging.WARNING, logger="jafaal.factory"):
        jafaal.create_auth_router()
    assert all(getattr(r, "warning_code", None) != "verify_only_hashers_configured" for r in caplog.records)


# --------------------------------------------------------------------------- #
# Scheme-independent failure cost, and bcrypt's input cap
# --------------------------------------------------------------------------- #


def _multi_scheme_hasher(**kwargs) -> PasswordHasher:
    from pwdlib import PasswordHash

    return PasswordHasher(hasher=PasswordHash([Argon2Hasher(), BCRYPT]), **kwargs)


def _count_by_scheme(hasher: PasswordHasher, monkeypatch) -> dict[str, int]:
    counts = {"argon2": 0, "bcrypt": 0}
    for scheme, inner in zip(("argon2", "bcrypt"), hasher._password_hash.hashers, strict=True):
        real = inner.verify

        def counted(*args, _scheme=scheme, _real=real, **kwargs):
            counts[_scheme] += 1
            return _real(*args, **kwargs)

        monkeypatch.setattr(inner, "verify", counted)
    return counts


@pytest.mark.parametrize("flag", [False, True])
def test_a_failed_check_costs_the_same_whichever_scheme_holds_the_hash(flag, monkeypatch):
    hasher = _multi_scheme_hasher(verify_unnormalized_input=flag)
    stored = {"argon2": hasher.hash_password("right-password-1"), "bcrypt": BCRYPT.hash("right-password-1")}
    counts = _count_by_scheme(hasher, monkeypatch)

    observed = {}
    for scheme, hashed in stored.items():
        counts.update(argon2=0, bcrypt=0)
        assert hasher.verify_and_update("wrong-password", hashed) == (False, None)
        observed[scheme] = dict(counts)
    counts.update(argon2=0, bcrypt=0)
    hasher.dummy_verify()
    observed["unknown user"] = dict(counts)

    # An account's scheme, or its absence, cannot be read off the work done.
    assert observed["argon2"] == observed["bcrypt"] == observed["unknown user"]
    assert all(n >= 1 for n in observed["argon2"].values())


def test_a_password_over_bcrypts_limit_verifies_the_truncated_input_and_rehashes_in_full(
    configure_passwords, make_user, client, db
):
    configure_passwords(verify_only_hashers=(BCRYPT,))
    user = make_user(username="alice", password=None)
    long_password = "p" * 100
    # An older system silently hashed only the first 72 bytes.
    _store_hash(user, BCRYPT.hash(long_password[:72]), db)

    assert _login(client, "alice", long_password).status_code == 200
    upgraded = _stored(user, db)
    assert upgraded.startswith("$argon2id$")
    hasher = get_password_hasher()
    assert hasher.verify_password(long_password, upgraded)
    # The Argon2id replacement is the whole password, not its 72-byte prefix.
    assert not hasher.verify_password(long_password[:72], upgraded)


def test_a_wrong_long_password_against_a_bcrypt_hash_is_a_401_not_an_error(configure_passwords, make_user, client, db):
    configure_passwords(verify_only_hashers=(BCRYPT,))
    user = make_user(username="alice", password=None)
    original = BCRYPT.hash("q" * 72)
    _store_hash(user, original, db)

    assert _login(client, "alice", "r" * 100).status_code == 401
    assert _stored(user, db) == original
