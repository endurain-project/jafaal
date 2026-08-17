"""End-to-end HTTP tests for ``POST /auth/password/change``.

A password change grants persistent account access, so a valid access token
alone must never be enough — every test here is really about what the endpoint
*refuses*.
"""

from conftest import WEB_CLIENT_ID, login

import jafaal
import jafaal.api_keys.crud as api_keys_crud
import jafaal.api_keys.schema as api_keys_schema
import jafaal.credentials.crud as credentials_crud
import jafaal.sessions.crud as sessions_crud

CURRENT = "Str0ng!Pass"
REPLACEMENT = "Repl4ced!Passphrase"


def _tokens(client, username, password=CURRENT):
    response = login(client, username, password)
    assert response.status_code == 200, response.text
    return response.json()


def _change(client, access_token, **body):
    return client.post(
        "/api/v1/auth/password/change",
        json=body,
        headers={"Authorization": f"Bearer {access_token}"},
    )


def test_password_change_replaces_the_credential(client, make_user):
    make_user(username="changer", password=CURRENT)
    tokens = _tokens(client, "changer")

    response = _change(client, tokens["access_token"], current_password=CURRENT, new_password=REPLACEMENT)
    assert response.status_code == 200, response.text

    assert login(client, "changer", CURRENT).status_code == 401
    assert login(client, "changer", REPLACEMENT).status_code == 200


def test_password_change_requires_the_current_password(client, make_user):
    """A stolen access token alone must not be enough to seize the account."""
    make_user(username="nostepup", password=CURRENT)
    tokens = _tokens(client, "nostepup")

    response = _change(client, tokens["access_token"], new_password=REPLACEMENT)
    assert response.status_code == 401

    # The credential is untouched.
    assert login(client, "nostepup", CURRENT).status_code == 200


def test_password_change_rejects_a_wrong_current_password(client, make_user):
    make_user(username="wrongcurrent", password=CURRENT)
    tokens = _tokens(client, "wrongcurrent")

    response = _change(
        client,
        tokens["access_token"],
        current_password="N0tTheOne!",
        new_password=REPLACEMENT,
    )
    assert response.status_code == 401
    assert login(client, "wrongcurrent", CURRENT).status_code == 200


def test_password_change_requires_authentication(client, make_user):
    make_user(username="anon", password=CURRENT)
    response = client.post(
        "/api/v1/auth/password/change",
        json={"current_password": CURRENT, "new_password": REPLACEMENT},
    )
    assert response.status_code == 401


def test_password_change_enforces_the_password_policy(client, make_user):
    make_user(username="weaknew", password=CURRENT)
    tokens = _tokens(client, "weaknew")

    response = _change(client, tokens["access_token"], current_password=CURRENT, new_password="short")
    assert response.status_code == 422


def test_password_change_revokes_other_sessions_but_keeps_the_caller(client, make_user, db):
    user = make_user(username="multisession", password=CURRENT)
    other = _tokens(client, "multisession")
    caller = _tokens(client, "multisession")

    response = _change(client, caller["access_token"], current_password=CURRENT, new_password=REPLACEMENT)
    assert response.status_code == 200
    assert response.json()["revoked_sessions"] >= 1

    remaining = {s.id for s in sessions_crud.get_user_sessions(user.id, db)}
    assert caller["session_id"] in remaining
    assert other["session_id"] not in remaining


def test_password_change_can_keep_other_sessions(client, make_user, db):
    user = make_user(username="routine", password=CURRENT)
    other = _tokens(client, "routine")
    caller = _tokens(client, "routine")

    response = _change(
        client,
        caller["access_token"],
        current_password=CURRENT,
        new_password=REPLACEMENT,
        revoke_other_sessions=False,
    )
    assert response.status_code == 200
    assert response.json()["revoked_sessions"] == 0

    remaining = {s.id for s in sessions_crud.get_user_sessions(user.id, db)}
    assert {caller["session_id"], other["session_id"]} <= remaining


def test_password_change_revokes_api_keys(client, make_user, db):
    """An API key outlives every other credential, so it must not survive."""
    user = make_user(username="keyholder", password=CURRENT)
    jafaal.configure_api_key_scopes(["profile"])
    api_keys_crud.create_api_key(user.id, api_keys_schema.UsersApiKeyCreate(name="k", scopes=["profile"]), db)
    db.commit()

    tokens = _tokens(client, "keyholder")
    assert (
        _change(client, tokens["access_token"], current_password=CURRENT, new_password=REPLACEMENT).status_code == 200
    )

    assert [k for k in api_keys_crud.get_api_keys_by_user_id(user.id, db) if k.is_active] == []


def test_password_change_clears_a_forced_change_requirement(client, make_user, db):
    """The endpoint is the documented way out of ``password_change_required``.

    Without it a credential written with ``must_change=True`` would be a
    lockout: login refuses the password, and nothing else can replace it.
    """
    user = make_user(username="bootstrap", password=None)
    with jafaal.unit_of_work(db):
        jafaal.set_password(user.id, CURRENT, db, must_change=True)

    refused = login(client, "bootstrap", CURRENT)
    assert refused.status_code == 401
    assert refused.json()["code"] == "password_change_required"

    # The account owner replaces it out of band (the host's change screen calls
    # set_password), and the requirement lifts.
    with jafaal.unit_of_work(db):
        jafaal.set_password(user.id, REPLACEMENT, db)

    assert credentials_crud.get_credential(user.id, db).must_change_password is False
    assert login(client, "bootstrap", REPLACEMENT).status_code == 200


def test_password_change_rejects_unknown_fields(client, make_user):
    make_user(username="strict", password=CURRENT)
    tokens = _tokens(client, "strict")

    response = _change(
        client,
        tokens["access_token"],
        current_password=CURRENT,
        new_password=REPLACEMENT,
        client_id=WEB_CLIENT_ID,
    )
    assert response.status_code == 422
