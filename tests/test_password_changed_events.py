"""Host-facing events for committed password replacements."""

import asyncio
import dataclasses
import logging

import pytest
from conftest import NATIVE_CLIENT_ID, login
from sqlalchemy.orm import Session

import jafaal
import jafaal._internal.services.account_security_service as account_security_service
import jafaal.ports as jafaal_ports

CURRENT = "Current1!Password"
REPLACEMENT = "Replacement2!Password"
ADMIN_PASSWORD = "Administrator3!Password"


def _password_events(sink):
    assert jafaal_ports.wait_for_pending_events()
    return [event for event in sink.events if isinstance(event, jafaal.PasswordChanged)]


def _change(client, access_token, **body):
    return client.post(
        "/api/v1/auth/password/change",
        json=body,
        headers={"Authorization": f"Bearer {access_token}"},
    )


def test_self_service_change_emits_once_with_revoked_sessions(client, make_user, event_sink):
    user = make_user(username="self-event", password=CURRENT)
    other = login(client, user.username, CURRENT)
    caller = login(client, user.username, CURRENT).json()
    event_sink.events.clear()

    response = _change(
        client,
        caller["access_token"],
        current_password=CURRENT,
        new_password=REPLACEMENT,
    )

    assert response.status_code == 200
    events = _password_events(event_sink)
    assert events == [
        jafaal.PasswordChanged(
            user_id=user.id,
            username=user.username,
            change_kind="self_service",
            revoked_sessions=response.json()["revoked_sessions"],
        )
    ]
    assert events[0].revoked_sessions >= 1
    assert other.status_code == 200


def test_forced_renewal_emits_once(client, make_user, db, event_sink):
    user = make_user(username="renew-event", password=None)
    with jafaal.unit_of_work(db):
        jafaal.set_password(user.id, CURRENT, db, must_change=True)
    event_sink.events.clear()

    response = client.post(
        "/api/v1/auth/password/renew",
        json={"username": user.username, "current_password": CURRENT, "new_password": REPLACEMENT},
    )

    assert response.status_code == 200
    assert _password_events(event_sink) == [
        jafaal.PasswordChanged(
            user_id=user.id,
            username=user.username,
            change_kind="forced_renewal",
            revoked_sessions=0,
        )
    ]


def test_reset_confirmation_emits_once_and_not_on_request(client, make_user, event_sink):
    user = make_user(username="reset-event", password=CURRENT)
    assert login(client, user.username, CURRENT).status_code == 200
    event_sink.events.clear()
    request = client.post("/api/v1/auth/password-reset/request", json={"email": user.email})
    assert request.status_code == 200
    assert _password_events(event_sink) == []
    token = next(event.token for event in event_sink.events if isinstance(event, jafaal.PasswordResetRequested))
    event_sink.events.clear()

    response = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": REPLACEMENT},
    )

    assert response.status_code == 200
    events = _password_events(event_sink)
    assert len(events) == 1
    assert dataclasses.asdict(events[0]) == {
        "user_id": user.id,
        "username": user.username,
        "change_kind": "password_reset",
        "revoked_sessions": 1,
        "initiating_administrator_user_id": None,
    }


def test_administrator_reset_emits_once_with_actor_and_count(client, make_user, event_sink):
    admin = make_user(username="admin-event", password=ADMIN_PASSWORD, is_superuser=True)
    target = make_user(username="admin-target", password=CURRENT)
    assert login(client, target.username, CURRENT).status_code == 200
    admin_tokens = login(client, admin.username, ADMIN_PASSWORD).json()
    event_sink.events.clear()

    response = client.post(
        f"/api/v1/auth/password/user/{target.id}",
        json={
            "current_password": ADMIN_PASSWORD,
            "new_password": REPLACEMENT,
            "must_change": False,
        },
        headers={"Authorization": f"Bearer {admin_tokens['access_token']}"},
    )

    assert response.status_code == 200
    assert response.json()["revoked_sessions"] == 1
    assert _password_events(event_sink) == [
        jafaal.PasswordChanged(
            user_id=target.id,
            username=target.username,
            change_kind="administrator_reset",
            revoked_sessions=1,
            initiating_administrator_user_id=admin.id,
        )
    ]


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/auth/password/renew", {"username": "absent", "current_password": CURRENT, "new_password": "short"}),
        ("/api/v1/auth/password-reset/confirm", {"token": "invalid-token", "new_password": REPLACEMENT}),
    ],
)
def test_rejected_unauthenticated_operations_emit_nothing(client, event_sink, path, body):
    assert client.post(path, json=body).status_code in (400, 401)
    assert _password_events(event_sink) == []


def test_validation_and_failed_step_up_emit_nothing(client, make_user, event_sink):
    user = make_user(username="failed-event", password=CURRENT)
    tokens = login(client, user.username, CURRENT).json()
    event_sink.events.clear()

    assert _change(client, tokens["access_token"], current_password=CURRENT, new_password="short").status_code == 422
    assert (
        _change(
            client,
            tokens["access_token"],
            current_password="Wrong4!Password",
            new_password=REPLACEMENT,
        ).status_code
        == 401
    )
    assert _password_events(event_sink) == []


def test_failed_persistence_emits_nothing(client, make_user, event_sink, monkeypatch):
    user = make_user(username="persist-event", password=CURRENT)
    tokens = login(client, user.username, CURRENT).json()
    event_sink.events.clear()

    def fail_change(*args, **kwargs):
        raise jafaal.InternalError("persistence failed")

    monkeypatch.setattr(account_security_service, "change_own_password", fail_change)
    assert (
        _change(
            client,
            tokens["access_token"],
            current_password=CURRENT,
            new_password=REPLACEMENT,
        ).status_code
        == 500
    )
    assert _password_events(event_sink) == []


def test_failed_commit_discards_the_event(client, make_user, event_sink, monkeypatch):
    user = make_user(username="commit-event", password=CURRENT)
    tokens = login(client, user.username, CURRENT).json()
    event_sink.events.clear()

    def fail_commit(self):
        raise RuntimeError("commit failed")

    monkeypatch.setattr(Session, "commit", fail_commit)
    with pytest.raises(RuntimeError, match="commit failed"):
        _change(
            client,
            tokens["access_token"],
            current_password=CURRENT,
            new_password=REPLACEMENT,
        )
    assert _password_events(event_sink) == []


def test_sink_failure_is_logged_without_exposing_credentials(client, make_user, caplog):
    class FailingSink:
        async def on_password_changed(self, event):
            raise RuntimeError("delivery refused")

    user = make_user(username="sink-event", password=CURRENT)
    login_response = login(client, user.username, CURRENT, client_id=NATIVE_CLIENT_ID)
    tokens = login_response.json()
    jafaal.configure_event_sink(FailingSink())
    caplog.set_level(logging.WARNING, logger="jafaal.ports")

    response = _change(
        client,
        tokens["access_token"],
        current_password=CURRENT,
        new_password=REPLACEMENT,
    )

    assert response.status_code == 200
    assert jafaal_ports.wait_for_pending_events()
    assert "AuthEventSink on_password_changed failed: RuntimeError" in caplog.text
    for secret in (CURRENT, REPLACEMENT, tokens["access_token"], tokens["refresh_token"]):
        assert secret not in caplog.text


def test_event_has_no_credential_fields_and_null_sink_accepts_it():
    event = jafaal.PasswordChanged(1, "safe-user", "self_service", 0)
    assert set(dataclasses.asdict(event)) == {
        "user_id",
        "username",
        "change_kind",
        "revoked_sessions",
        "initiating_administrator_user_id",
    }
    assert asyncio.run(jafaal.NullAuthEventSink().on_password_changed(event)) is None
