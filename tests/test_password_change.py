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


# --------------------------------------------------------------------------- #
# Administrative reset — POST /auth/password/user/{user_id}
# --------------------------------------------------------------------------- #

ADMIN_PASSWORD = "Adm1n!Passphrase"


def _admin_reset(client, access_token, user_id, **body):
    return client.post(
        f"/api/v1/auth/password/user/{user_id}",
        json=body,
        headers={"Authorization": f"Bearer {access_token}"},
    )


def test_admin_can_reset_another_users_password(client, make_user, db):
    make_user(username="root", password=ADMIN_PASSWORD, is_superuser=True)
    target = make_user(username="target", password=CURRENT)
    admin = _tokens(client, "root", ADMIN_PASSWORD)

    response = _admin_reset(
        client,
        admin["access_token"],
        target.id,
        current_password=ADMIN_PASSWORD,
        new_password=REPLACEMENT,
    )
    assert response.status_code == 200, response.text

    # Defaults to must_change, so the target cannot simply use it.
    refused = login(client, "target", REPLACEMENT)
    assert refused.status_code == 401
    assert refused.json()["code"] == "password_change_required"
    assert credentials_crud.get_credential(target.id, db).must_change_password is True


def test_admin_reset_requires_the_admins_own_step_up(client, make_user):
    """A stolen admin access token must not be enough to seize an account."""
    make_user(username="root2", password=ADMIN_PASSWORD, is_superuser=True)
    target = make_user(username="target2", password=CURRENT)
    admin = _tokens(client, "root2", ADMIN_PASSWORD)

    response = _admin_reset(client, admin["access_token"], target.id, new_password=REPLACEMENT)
    assert response.status_code == 401

    # The target's credential is untouched.
    assert login(client, "target2", CURRENT).status_code == 200


def test_admin_reset_refuses_a_non_superuser_targeting_someone_else(client, make_user):
    """Object-level check: holding the scope is not permission to touch anyone."""
    make_user(username="regular", password=CURRENT)
    target = make_user(username="victim", password=CURRENT)
    caller = _tokens(client, "regular")

    response = _admin_reset(
        client,
        caller["access_token"],
        target.id,
        current_password=CURRENT,
        new_password=REPLACEMENT,
    )
    assert response.status_code in (401, 403)
    assert login(client, "victim", CURRENT).status_code == 200


def test_admin_reset_can_opt_out_of_the_forced_change(client, make_user):
    make_user(username="root3", password=ADMIN_PASSWORD, is_superuser=True)
    target = make_user(username="target3", password=CURRENT)
    admin = _tokens(client, "root3", ADMIN_PASSWORD)

    response = _admin_reset(
        client,
        admin["access_token"],
        target.id,
        current_password=ADMIN_PASSWORD,
        new_password=REPLACEMENT,
        must_change=False,
    )
    assert response.status_code == 200
    assert login(client, "target3", REPLACEMENT).status_code == 200


def test_admin_reset_revokes_the_targets_sessions(client, make_user, db):
    make_user(username="root4", password=ADMIN_PASSWORD, is_superuser=True)
    target = make_user(username="target4", password=CURRENT)
    _tokens(client, "target4")
    assert sessions_crud.get_user_sessions(target.id, db) != []
    db.rollback()

    admin = _tokens(client, "root4", ADMIN_PASSWORD)
    assert (
        _admin_reset(
            client,
            admin["access_token"],
            target.id,
            current_password=ADMIN_PASSWORD,
            new_password=REPLACEMENT,
        ).status_code
        == 200
    )

    assert sessions_crud.get_user_sessions(target.id, db) == []


# --------------------------------------------------------------------------- #
# Renewal — POST /auth/password/renew
# --------------------------------------------------------------------------- #


def test_renew_completes_an_admin_reset_end_to_end(client, make_user, db):
    """The loop that makes ``must_change`` usable rather than a lockout."""
    make_user(username="root5", password=ADMIN_PASSWORD, is_superuser=True)
    target = make_user(username="target5", password=CURRENT)
    admin = _tokens(client, "root5", ADMIN_PASSWORD)

    temporary = "Temp0rary!Passphrase"
    assert (
        _admin_reset(
            client,
            admin["access_token"],
            target.id,
            current_password=ADMIN_PASSWORD,
            new_password=temporary,
        ).status_code
        == 200
    )
    assert login(client, "target5", temporary).status_code == 401

    renewed = client.post(
        "/api/v1/auth/password/renew",
        json={"username": "target5", "current_password": temporary, "new_password": REPLACEMENT},
    )
    assert renewed.status_code == 200, renewed.text

    assert credentials_crud.get_credential(target.id, db).must_change_password is False
    assert login(client, "target5", REPLACEMENT).status_code == 200


def test_renew_refuses_an_account_that_is_not_flagged(client, make_user):
    """Otherwise it would be an unauthenticated step-up bypass for everyone."""
    make_user(username="unflagged", password=CURRENT)

    response = client.post(
        "/api/v1/auth/password/renew",
        json={"username": "unflagged", "current_password": CURRENT, "new_password": REPLACEMENT},
    )
    assert response.status_code == 401
    assert login(client, "unflagged", CURRENT).status_code == 200


def test_renew_refuses_an_unknown_account_identically(client):
    response = client.post(
        "/api/v1/auth/password/renew",
        json={"username": "ghost", "current_password": CURRENT, "new_password": REPLACEMENT},
    )
    assert response.status_code == 401


def test_renew_rejects_a_wrong_current_password(client, make_user, db):
    user = make_user(username="flaggedwrong", password=None)
    with jafaal.unit_of_work(db):
        jafaal.set_password(user.id, CURRENT, db, must_change=True)

    response = client.post(
        "/api/v1/auth/password/renew",
        json={"username": "flaggedwrong", "current_password": "N0tIt!", "new_password": REPLACEMENT},
    )
    assert response.status_code == 401
    assert credentials_crud.get_credential(user.id, db).must_change_password is True
