"""Property-based tests (hypothesis) for pure helpers and JWT round-trips.

These complement the example-based suites with breadth: random inputs exercise
the hashing, username-normalisation, user-id coercion, and JWT encode/decode
paths that security controls depend on.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from hypothesis import given, settings
from hypothesis import strategies as st

from jafaal._core import hashing
from jafaal._internal.security_stores import normalize_username_key
from jafaal._internal.token_manager import TokenType, get_token_manager
from jafaal.orm import coerce_user_id

# Keep runs fast and deterministic: JWT/argon2-free paths are cheap, but capping
# examples and disabling the timing deadline avoids flakiness on slower CI.
_PROP = settings(max_examples=75, deadline=None)

# Exclude lone surrogates, which cannot be UTF-8 encoded (str.encode would raise
# for both the helper and the reference implementation).
_TEXT = st.text(st.characters(blacklist_categories=("Cs",)))


@_PROP
@given(_TEXT)
def test_sha256_hex_matches_hashlib_and_is_hex(value):
    digest = hashing.sha256_hex(value)
    assert digest == hashlib.sha256(value.encode()).hexdigest()
    assert len(digest) == 64
    assert all(char in "0123456789abcdef" for char in digest)


@_PROP
@given(_TEXT)
def test_normalize_username_key_is_canonical(value):
    key = normalize_username_key(value)
    # Fully case-folded (casefold is idempotent), no surrounding whitespace, and
    # '+' has been normalised to a space — the invariants lockout keys rely on.
    assert key == key.casefold()
    assert key == key.strip()
    assert "+" not in key


@_PROP
@given(st.integers(min_value=0, max_value=2**63 - 1))
def test_coerce_user_id_int_roundtrip(user_id):
    # The test host user model has an integer primary key, so coercion targets
    # ``int``; the JSON (string) form of a sub claim must round-trip back.
    assert coerce_user_id(user_id) == user_id
    assert coerce_user_id(str(user_id)) == user_id


@_PROP
@given(
    st.integers(min_value=1, max_value=2**31 - 1),
    st.text(alphabet="abcdefABCDEF0123456789-_", min_size=1, max_size=40),
)
def test_jwt_sub_and_sid_roundtrip(user_id, session_id):
    tm = get_token_manager()
    _, token = tm.create_token(session_id, SimpleNamespace(id=user_id, is_superuser=False), TokenType.ACCESS)
    assert tm.get_token_claim(token, "sub") == user_id
    assert tm.get_token_claim(token, "sid") == session_id
