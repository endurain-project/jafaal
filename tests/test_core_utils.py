"""Tests for vendored _core utilities: validation, crypto, and the db-error decorator."""

import asyncio

import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

import jafaal.exceptions as exc
from jafaal._core import crypto, db_errors, validation

# --------------------------------------------------------------------------- #
# validation.validate_id
# --------------------------------------------------------------------------- #


def test_validate_id_accepts_value_above_minimum():
    validation.validate_id(5, 0, "must be > 0")  # does not raise


def test_validate_id_rejects_value_at_or_below_minimum():
    with pytest.raises(exc.UnprocessableError):
        validation.validate_id(0, 0, "must be > 0")
    with pytest.raises(exc.UnprocessableError):
        validation.validate_id(3, 5, "must be > 5")


# --------------------------------------------------------------------------- #
# crypto (Fernet)
# --------------------------------------------------------------------------- #


def test_encrypt_decrypt_roundtrip():
    enc = crypto.encrypt_token_fernet("secret-value")
    assert enc != "secret-value"
    assert crypto.decrypt_token_fernet(enc) == "secret-value"


def test_crypto_none_passthrough():
    assert crypto.encrypt_token_fernet(None) is None
    assert crypto.decrypt_token_fernet(None) is None


def test_encrypt_coerces_non_str():
    enc = crypto.encrypt_token_fernet(12345)
    assert crypto.decrypt_token_fernet(enc) == "12345"


def test_decrypt_invalid_token_raises_internal_error():
    with pytest.raises(exc.InternalError):
        crypto.decrypt_token_fernet("not-a-valid-fernet-token")


# --------------------------------------------------------------------------- #
# db_errors.handle_db_errors
# --------------------------------------------------------------------------- #


def test_handle_db_errors_passes_jafaal_error_through(db):
    @db_errors.handle_db_errors
    def op(db):
        raise exc.NotFoundError("nope")

    with pytest.raises(exc.NotFoundError):
        op(db)


def test_handle_db_errors_converts_sqlalchemy_error(db):
    @db_errors.handle_db_errors
    def op(db):
        raise SQLAlchemyError("boom")

    with pytest.raises(exc.InternalError):
        op(db)


def test_handle_db_errors_reraises_integrity_error(db):
    @db_errors.handle_db_errors
    def op(db):
        raise IntegrityError("INSERT", {}, Exception("dup"))

    with pytest.raises(IntegrityError):
        op(db)


def test_handle_db_errors_returns_value_on_success(db):
    @db_errors.handle_db_errors
    def op(db):
        return 42

    assert op(db) == 42


def test_handle_db_errors_supports_async(db):
    @db_errors.handle_db_errors
    async def op(db):
        raise SQLAlchemyError("boom")

    with pytest.raises(exc.InternalError):
        asyncio.run(op(db))
