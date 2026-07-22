"""Tests for the structured ``jafaal.audit`` logging channel."""

from __future__ import annotations

import dataclasses
import logging

import jafaal
import jafaal.audit as audit
from jafaal._core import hashing


def _audit_records(caplog):
    """Return only the records emitted on the audit channel."""
    return [r for r in caplog.records if getattr(r, "audit", False)]


def test_record_emits_structured_fields(caplog):
    with caplog.at_level(logging.INFO, logger=audit.AUDIT_LOGGER_NAME):
        audit.record(audit.Event.LOGIN_SUCCESS, user_id=7, username="alice", ip="1.2.3.4")

    records = _audit_records(caplog)
    assert len(records) == 1
    rec = records[0]
    assert rec.event == "login.success"
    assert rec.outcome == "success"
    assert rec.user_id == 7
    assert rec.username == "alice"
    assert rec.ip == "1.2.3.4"
    # The log message is the event slug, so plain-text handlers stay readable.
    assert rec.getMessage() == "login.success"


def test_record_drops_none_and_reserved_fields(caplog):
    with caplog.at_level(logging.INFO, logger=audit.AUDIT_LOGGER_NAME):
        # ip=None is dropped; ``module`` is a reserved LogRecord attribute and
        # must not be overwritten (the stdlib would raise KeyError otherwise).
        audit.record(
            audit.Event.LOGIN_FAILURE,
            outcome=audit.Outcome.FAILURE,
            ip=None,
            module="attacker-controlled",
            reason="invalid_credentials",
        )

    rec = _audit_records(caplog)[0]
    assert not hasattr(rec, "ip")  # None value dropped
    assert rec.reason == "invalid_credentials"
    # The genuine LogRecord.module is preserved, not the reserved-key collision.
    assert rec.module != "attacker-controlled"


def test_audit_scrubs_pii_when_disabled(caplog):
    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, audit_include_pii=False))
    try:
        with caplog.at_level(logging.INFO, logger=audit.AUDIT_LOGGER_NAME):
            audit.record(
                audit.Event.LOGIN_FAILURE,
                outcome=audit.Outcome.FAILURE,
                username="Alice",
                ip="1.2.3.4",
                email="a@b.test",
            )
        rec = _audit_records(caplog)[0]
        # Direct identifiers are dropped; username survives only as a one-way hash.
        assert not hasattr(rec, "username")
        assert not hasattr(rec, "ip")
        assert not hasattr(rec, "email")
        assert rec.username_hash == hashing.sha256_hex("alice")
    finally:
        jafaal.configure(original)


def test_audit_includes_pii_by_default(caplog):
    with caplog.at_level(logging.INFO, logger=audit.AUDIT_LOGGER_NAME):
        audit.record(audit.Event.LOGIN_FAILURE, outcome=audit.Outcome.FAILURE, username="alice", ip="1.2.3.4")
    rec = _audit_records(caplog)[0]
    # Default keeps identifiers so a SIEM sees the brute-force signal.
    assert rec.username == "alice"
    assert rec.ip == "1.2.3.4"


def test_login_failure_emits_audit_event(client, make_user, caplog):
    make_user(username="bob", password="Str0ng!Pass")
    with caplog.at_level(logging.INFO, logger=audit.AUDIT_LOGGER_NAME):
        resp = client.post(
            "/api/v1/auth/login",
            data={"username": "bob", "password": "wrong-password"},
            headers={"X-Client-Type": "web"},
        )

    assert resp.status_code == 401
    failures = [r for r in _audit_records(caplog) if r.event == "login.failure"]
    assert failures, "expected a login.failure audit event"
    assert failures[0].username == "bob"
    assert failures[0].outcome == "failure"


def test_login_success_emits_audit_event(client, make_user, caplog):
    make_user(username="carol", password="Str0ng!Pass")
    with caplog.at_level(logging.INFO, logger=audit.AUDIT_LOGGER_NAME):
        resp = client.post(
            "/api/v1/auth/login",
            data={"username": "carol", "password": "Str0ng!Pass"},
            headers={"X-Client-Type": "web"},
        )

    assert resp.status_code == 200
    successes = [r for r in _audit_records(caplog) if r.event == "login.success"]
    assert successes, "expected a login.success audit event"
    assert successes[0].username == "carol"
    assert successes[0].outcome == "success"


def test_lockout_emits_audit_event(client, make_user, caplog):
    make_user(username="dave", password="Str0ng!Pass")
    with caplog.at_level(logging.WARNING, logger=audit.AUDIT_LOGGER_NAME):
        # Five failures trips the first login-lockout tier, which emits the event.
        for _ in range(5):
            client.post(
                "/api/v1/auth/login",
                data={"username": "dave", "password": "wrong-password"},
                headers={"X-Client-Type": "web"},
            )

    lockouts = [r for r in _audit_records(caplog) if r.event == "lockout.applied"]
    assert lockouts, "expected a lockout.applied audit event"
    assert lockouts[0].outcome == "blocked"
    assert lockouts[0].store == "Login"
    assert lockouts[0].failed_attempts >= 5
