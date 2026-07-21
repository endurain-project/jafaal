"""The optional-feature dependency guards fail fast with an actionable hint.

MFA (``pyotp`` / ``qrcode``) and SSO (``authlib``) are optional extras. The
feature modules import them defensively (falling back to ``None``); these tests
simulate the "extra not installed" case by patching the module reference to
``None`` and assert that using the feature raises a clear
:class:`~jafaal._core.optional_deps.MissingDependencyError` with an install hint
rather than a bare ``AttributeError``.
"""

from __future__ import annotations

import pytest

import jafaal.identity_providers.service as idp_service
import jafaal.mfa.service as mfa_service
from jafaal._core.optional_deps import MissingDependencyError, require


def test_require_returns_present_dependency():
    sentinel = object()
    assert require(sentinel, package="x", extra="y", feature="Z") is sentinel


def test_require_raises_with_install_hint():
    with pytest.raises(MissingDependencyError, match=r"pip install 'jafaal\[mfa\]'"):
        require(None, package="pyotp", extra="mfa", feature="Multi-factor authentication")


def test_mfa_totp_fails_fast_without_pyotp(monkeypatch):
    monkeypatch.setattr(mfa_service, "pyotp", None)
    with pytest.raises(MissingDependencyError, match="pyotp"):
        mfa_service.generate_totp_secret()


def test_mfa_qr_fails_fast_without_qrcode(monkeypatch):
    # pyotp stays available so the failure is specifically the qrcode guard.
    monkeypatch.setattr(mfa_service, "qrcode", None)
    with pytest.raises(MissingDependencyError, match="qrcode"):
        mfa_service.generate_qr_code("JBSWY3DPEHPK3PXP", "alice")


def test_sso_fails_fast_without_authlib(monkeypatch):
    monkeypatch.setattr(idp_service, "AsyncOAuth2Client", None)
    with pytest.raises(MissingDependencyError, match="authlib"):
        idp_service._oauth_client_cls()
