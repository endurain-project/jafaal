"""The credential-change revocation matrix, asserted as a matrix.

Every path that invalidates a password must revoke every *other* credential
derived from it. That list grows each time JAFAAL gains a credential type, and
per-flow tests do not catch a hole in it — each one asserts the entries its
author remembered. So the entries are enumerated here once and every path is run
against all of them.

Adding a credential type without adding it to
:func:`jafaal._internal.services.credential_sweep.revoke_derived_credentials`
should fail here, loudly, before it ships.

Deliberately *not* in the matrix (see the sweep module's docstring for why):
access tokens, registered passkeys, enrolled TOTP, identity-provider links.
"""

from __future__ import annotations

import pytest
from starlette.requests import Request

import jafaal
import jafaal._internal.security_stores as security_stores
import jafaal._internal.services.account_security_service as account_svc
import jafaal.api_keys.crud as api_keys_crud
import jafaal.api_keys.schema as api_keys_schema
import jafaal.password_reset_tokens.crud as reset_crud
import jafaal.password_reset_tokens.utils as reset_utils
import jafaal.sessions.crud as sessions_crud
import jafaal.sessions.utils as session_utils
import jafaal.token_hashing as token_hashing
import jafaal.webauthn.challenge_store as webauthn_challenge_store
from jafaal._internal.password_hasher import get_password_hasher
from jafaal._internal.security_stores import StepUpAttempts
from jafaal._internal.token_manager import get_token_manager
from jafaal.identity_service import DefaultIdentityService

#: Plaintext reset tokens planted per user, so the "is it still redeemable?"
#: check can go through the same digest lookup redemption uses.
_PLANTED_RESET_TOKENS: dict[object, str] = {}


def _svc(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _request():
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [(b"user-agent", b"Mozilla/5.0")],
        "client": ("1.2.3.4", 1),
        "scheme": "http",
        "server": ("t", 80),
    }
    return Request(scope)


# --------------------------------------------------------------------------- #
# The matrix rows: one credential each, with how to plant and how to observe it
# --------------------------------------------------------------------------- #


def _plant_session(user, db):
    session_utils.create_session("doomed", user, _request(), "rt-doomed", db)


def _session_survives(user, db) -> bool:
    return any(s.id == "doomed" for s in sessions_crud.get_user_sessions(user.id, db))


def _plant_api_key(user, db):
    jafaal.configure_api_key_scopes([jafaal.scopes.PROFILE])
    api_keys_crud.create_api_key(
        user.id,
        api_keys_schema.UsersApiKeyCreate(name="k", scopes=[jafaal.scopes.PROFILE]),
        db,
    )


def _api_key_survives(user, db) -> bool:
    return any(key.is_active for key in api_keys_crud.get_api_keys_by_user_id(user.id, db))


def _plant_reset_token(user, db):
    token, _expires = reset_utils.create_password_reset_token(user.id, db)
    _PLANTED_RESET_TOKENS[user.id] = token


def _reset_token_survives(user, db) -> bool:
    # Observed the way an attacker would use it: is the digest still redeemable?
    token = _PLANTED_RESET_TOKENS[user.id]
    digest = token_hashing.hmac_sha256(token, token_hashing.KeyPurpose.PASSWORD_RESET)
    row = reset_crud.get_password_reset_token_by_hash(digest, db)
    return row is not None and not row.used


def _plant_pending_mfa(user, db):
    security_stores.pending_mfa_store.add_pending_login(user.username, user.id, "test-web")


def _pending_mfa_survives(user, db) -> bool:
    prefix = f"{security_stores._key_prefix()}:mfa:pending:"
    from jafaal.state_store import get_state_store

    return any(get_state_store().get(key) is not None for key in list(get_state_store().iter_keys(prefix)))


def _plant_step_up_grant(user, db):
    security_stores.grant_step_up_reauth(user.id, idp_id=1, ttl_seconds=300)


def _step_up_grant_survives(user, db) -> bool:
    return security_stores.consume_step_up_reauth_grant(user.id)


def _plant_webauthn_challenge(user, db):
    webauthn_challenge_store.store_registration_challenge(user.id, b"challenge-bytes")


def _webauthn_challenge_survives(user, db) -> bool:
    return webauthn_challenge_store.pop_registration_challenge(user.id) is not None


#: ``(label, plant, survives)`` for every credential a password change must kill.
CREDENTIALS = [
    pytest.param(_plant_session, _session_survives, id="session"),
    pytest.param(_plant_api_key, _api_key_survives, id="api_key"),
    pytest.param(_plant_reset_token, _reset_token_survives, id="password_reset_token"),
    pytest.param(_plant_pending_mfa, _pending_mfa_survives, id="pending_mfa_ticket"),
    pytest.param(_plant_step_up_grant, _step_up_grant_survives, id="step_up_grant"),
    pytest.param(_plant_webauthn_challenge, _webauthn_challenge_survives, id="webauthn_reg_challenge"),
]


# --------------------------------------------------------------------------- #
# The matrix columns: every path that invalidates a password
# --------------------------------------------------------------------------- #


def _self_service_change(user, db):
    account_svc.change_own_password(user.id, "Old1!Pass", "New1!Passw", None, _svc(db), StepUpAttempts(), db)


def _admin_change(user, db):
    account_svc.change_managed_user_password(user.id, "New1!Passw", _svc(db), db)


def _reset_via_token(user, db):
    token, _expires = reset_utils.create_password_reset_token(user.id, db)
    reset_utils.use_password_reset_token(token, "New1!Passw", _svc(db), db)


PASSWORD_CHANGE_PATHS = [
    pytest.param(_self_service_change, id="self_service"),
    pytest.param(_admin_change, id="admin"),
    pytest.param(_reset_via_token, id="reset_token"),
]


@pytest.mark.parametrize("change_password", PASSWORD_CHANGE_PATHS)
@pytest.mark.parametrize(("plant", "survives"), CREDENTIALS)
def test_password_change_revokes_every_derived_credential(db, make_user, change_password, plant, survives):
    user = make_user(password="Old1!Pass")
    plant(user, db)
    assert survives(user, db), "the fixture did not actually plant the credential"

    change_password(user, db)

    assert not survives(user, db)
