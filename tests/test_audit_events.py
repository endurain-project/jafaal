"""End-to-end coverage of the security-audit event stream.

``tests/test_audit.py`` covers the ``record`` primitive. This module asserts that
the flows which *change security state* actually emit on the audit channel — the
gap ASVS V7 targets, and the reason an incident responder can answer "what did
this attacker accomplish?" rather than only "what did they fail at?".
"""

from __future__ import annotations

import logging

import pyotp
import pytest

import jafaal
import jafaal._internal.services.account_security_service as account_svc
import jafaal.api_keys.crud as api_keys_crud
import jafaal.api_keys.schema as api_keys_schema
import jafaal.audit as audit
import jafaal.mfa.crud as mfa_crud
import jafaal.orm as jafaal_orm
import jafaal.password_reset_tokens.utils as prt_utils
import jafaal.scopes as jafaal_scopes
import jafaal.sessions.utils as session_utils
import jafaal.sign_up_tokens.utils as sut_utils
from jafaal._core import crypto
from jafaal._internal.password_hasher import get_password_hasher
from jafaal._internal.security_stores import StepUpAttempts
from jafaal._internal.token_manager import get_token_manager
from jafaal.identity_service import DefaultIdentityService

WEB = {"X-Client-Type": "web"}


def _svc(db):
    return DefaultIdentityService(db, get_token_manager(), get_password_hasher())


def _request():
    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "query_string": b"",
            "headers": [(b"user-agent", b"Mozilla/5.0")],
            "client": ("1.2.3.4", 1),
            "scheme": "http",
            "server": ("t", 80),
        }
    )


@pytest.fixture
def audited(caplog):
    """Capture the audit channel and expose the emitted event slugs."""
    with caplog.at_level(logging.INFO, logger=audit.AUDIT_LOGGER_NAME):
        yield caplog


def _events(caplog):
    return [r for r in caplog.records if getattr(r, "audit", False)]


def _slugs(caplog):
    return [r.event for r in _events(caplog)]


def _find(caplog, slug):
    matches = [r for r in _events(caplog) if r.event == slug]
    assert matches, f"{slug} was never emitted; got {_slugs(caplog)}"
    return matches[0]


def _login(client, username="alice", password="Str0ng!Pass"):
    return client.post("/api/v1/auth/login", data={"username": username, "password": password}, headers=WEB)


# --------------------------------------------------------------------------- #
# Session lifecycle
# --------------------------------------------------------------------------- #


def test_logout_and_refresh_are_audited(client, make_user, audited):
    make_user()
    access = _login(client).json()["access_token"]
    headers = {**WEB, "Authorization": f"Bearer {access}"}

    client.post("/api/v1/auth/refresh", headers={**headers, "Origin": "https://app.test"})
    client.post("/api/v1/auth/logout", headers=headers)

    assert "token.refreshed" in _slugs(audited)
    assert "logout" in _slugs(audited)


def test_password_change_records_the_session_revocation(db, make_user, audited):
    user = make_user(password="Old1!Pass")
    session_utils.create_session("drop", user, _request(), "rt-drop", db)
    account_svc.change_own_password(
        user.id,
        "Old1!Pass",
        "New1!Passw",
        None,
        _svc(db),
        StepUpAttempts(),
        db,
        revoke_other_sessions=True,
    )

    changed = _find(audited, "password.changed")
    assert changed.user_id == user.id
    assert changed.actor == "self"
    # A password change kills the user's other sessions; that is a security-state
    # change an investigator needs to see, not an implementation detail.
    assert "session.revoked" in _slugs(audited)


# --------------------------------------------------------------------------- #
# MFA
# --------------------------------------------------------------------------- #


def test_mfa_success_is_audited_not_just_failure(client, make_user, audited):
    user = make_user()
    secret = pyotp.random_base32()
    session = jafaal_orm.get_sessionmaker()()
    try:
        mfa_crud.update_user_mfa(user.id, session, encrypted_secret=crypto.encrypt_token_fernet(secret))
    finally:
        session.close()

    mfa_token = _login(client).json()["mfa_token"]
    response = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": mfa_token, "mfa_code": pyotp.TOTP(secret).now()},
        headers=WEB,
    )

    assert response.status_code == 200
    success = _find(audited, "mfa.success")
    assert success.user_id == user.id


# --------------------------------------------------------------------------- #
# Credentials issued out-of-band
# --------------------------------------------------------------------------- #


def test_api_key_lifecycle_is_audited(db, make_user, audited):
    user = make_user()
    jafaal.configure_api_key_scopes(["reports:read"])
    created, _plaintext = api_keys_crud.create_api_key(
        user.id,
        api_keys_schema.UsersApiKeyCreate(name="ci", scopes=["reports:read"]),
        db,
    )
    api_keys_crud.delete_api_key(created.id, user.id, db)

    assert _find(audited, "api_key.created").user_id == user.id
    deleted = _find(audited, "api_key.deleted")
    # The prefix must survive the row deletion, or the trail loses the only
    # handle that ties the audit entry to the credential that was in the wild.
    assert deleted.key_prefix
    assert deleted.levelno == logging.WARNING


async def test_password_reset_is_audited_end_to_end(db, make_user, event_sink, audited):
    user = make_user()
    await prt_utils.request_password_reset(user.email, db)
    token = event_sink.events[0].token
    prt_utils.use_password_reset_token(token, "Rec0very!Pass", _svc(db), db)

    assert "password.reset_requested" in _slugs(audited)
    assert _find(audited, "password.reset_completed").user_id == user.id
    assert "session.revoked" in _slugs(audited)


def test_sign_up_confirmation_records_success_and_failure(db, make_user, audited):
    user = make_user()
    token, _ = sut_utils.create_sign_up_token(user.id, db)
    sut_utils.use_sign_up_token(token, db)
    with pytest.raises(jafaal.JafaalError):
        sut_utils.use_sign_up_token(token, db)

    confirmations = [r for r in _events(audited) if r.event == "signup.confirmed"]
    assert [r.outcome for r in confirmations] == ["success", "failure"]


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #


def test_scope_denial_is_audited(client, make_user, audited):
    make_user()
    jafaal.configure_scopes(
        jafaal_scopes.DEFAULT_SCOPE_CATALOG.extend(
            admin=("reports:read",),
            descriptions={"reports:read": "Read reports"},
        )
    )
    access = _login(client).json()["access_token"]
    # ``auth:introspect`` is admin-only, so a regular user's token is rejected.
    response = client.post(
        "/api/v1/auth/introspect",
        data={"token": access},
        headers={**WEB, "Authorization": f"Bearer {access}"},
    )

    assert response.status_code == 403
    denied = _find(audited, "scope.denied")
    assert denied.outcome == "blocked"
    assert denied.levelno == logging.WARNING


# --------------------------------------------------------------------------- #
# Catalog hygiene
# --------------------------------------------------------------------------- #


def test_every_catalogued_event_has_a_call_site():
    """A slug nobody emits is a promise the audit trail silently breaks.

    An operator builds SIEM rules from :class:`jafaal.audit.Event`; an entry with
    no producer means an alert that can never fire.
    """
    from pathlib import Path

    package = Path(jafaal.__file__).parent
    sources = "\n".join(path.read_text(encoding="utf-8") for path in package.rglob("*.py") if path.name != "audit.py")
    names = [name for name in vars(audit.Event) if name.isupper()]
    unused = [name for name in names if f"Event.{name}" not in sources]
    assert not unused, f"audit events declared but never emitted: {unused}"


def test_client_ip_is_never_read_raw():
    """``request.client.host`` must not be read outside the network helper.

    The direct TCP peer is the *proxy* address in any deployment behind one, so a
    raw read poisons audit records and IP bindings while the lockout and
    rate-limit keys use the real client. ``network.get_ip_address`` is the single
    resolver (it walks the forwarded chain right-to-left); this guard stops a new
    call site from quietly reintroducing the split.
    """
    from pathlib import Path

    package = Path(jafaal.__file__).parent
    offenders = [
        str(path.relative_to(package))
        for path in package.rglob("*.py")
        # network.py is the implementation: it is where the peer is read.
        if path.name != "network.py" and "request.client.host" in path.read_text(encoding="utf-8")
    ]
    assert not offenders, (
        f"read the client IP via jafaal._core.network.get_ip_address instead of request.client.host in: {offenders}"
    )
