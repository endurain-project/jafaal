"""WebAuthn / passkey support (optional ``jafaal[webauthn]`` extra).

Companion table ``webauthn_credentials`` plus the registration, passwordless
authentication, and second-factor ceremonies. The HTTP endpoints are mounted by
:func:`jafaal.create_auth_router`; the ceremony logic lives in
:mod:`jafaal.webauthn.service` (which wraps the optional ``py_webauthn``
dependency defensively).
"""
