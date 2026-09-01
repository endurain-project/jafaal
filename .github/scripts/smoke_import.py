"""Smoke-test a JAFAAL install: bare import, model mapping, router assembly.

By default, run against an environment that has **only** the base runtime
dependencies (no feature extras or dev groups). It proves four things a
packaging mistake would break:

1. ``import jafaal`` works without any optional dependency - the feature modules
   really do import defensively.
2. The distribution carries its version metadata (i.e. it was installed, not
   merely found on ``sys.path``).
3. The full router assembles, which transitively imports every sub-router,
   model, and schema in the package.
4. Using each optional feature fails with its documented ``jafaal[extra]``
    installation hint.

With ``--extra``, run against a wheel installed with exactly that feature extra.
The named feature must work and every unrelated feature must remain guarded;
``--extra all`` checks that the convenience union activates every feature.

Step 3 needs a host ``Users`` model, because JAFAAL's companion tables carry
foreign keys and relationships to it - the library deliberately does not own the
user table. A minimal one is defined here.

Must be run from **outside** the repository root, otherwise the local ``jafaal/``
package directory shadows the installed distribution and this would silently
validate the working tree instead of the built artifact::

    cd /tmp && python /path/to/repo/.github/scripts/smoke_import.py
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, NoReturn

from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

import jafaal
from jafaal._core.optional_deps import MissingDependencyError
from jafaal.adapters.static_settings import StaticSettingsProvider


class Base(DeclarativeBase):
    """Host-owned declarative base (JAFAAL maps its tables into this registry)."""


class Users(jafaal.IntPKUserMixin, Base):
    """Minimal host user model - the FK/relationship target JAFAAL requires."""

    __tablename__ = "users"


class SmokeUserRepository:
    """Host repository stub; route assembly must not perform user I/O."""

    @staticmethod
    def _unexpected() -> NoReturn:
        raise AssertionError("router assembly unexpectedly accessed the user repository")

    def get_by_id(self, user_id: Any, db: Session) -> jafaal.UserProtocol | None:
        self._unexpected()

    def get_by_email(self, email: str, db: Session) -> jafaal.UserProtocol | None:
        self._unexpected()

    def get_by_username(self, username: str, db: Session) -> jafaal.UserProtocol | None:
        self._unexpected()

    def create_local_user(
        self,
        username: str,
        email: str,
        db: Session,
        *,
        is_active: bool,
        is_verified: bool,
    ) -> jafaal.UserProtocol:
        self._unexpected()

    def provision_from_idp(self, identity: jafaal.IdpIdentity, db: Session) -> jafaal.UserProtocol:
        self._unexpected()

    def sync_from_idp(self, user_id: Any, claims: Mapping[str, Any], db: Session) -> None:
        self._unexpected()

    def set_email_verified(self, user_id: Any, db: Session, *, activate: bool) -> None:
        self._unexpected()


# ``create_auth_router`` imports and includes every sub-router: auth, sessions,
# api-keys, identity providers (private + public), password reset, sign-up,
# profile MFA, WebAuthn (private + public), JWKS, and RFC 8414 metadata. Recent
# FastAPI records each as a lazily-flattened ``_IncludedRouter``, so this count
# is the number of sub-routers that imported cleanly - exactly what this smoke
# test checks.
EXPECTED_SUB_ROUTERS = 12
FEATURE_EXTRAS = ("mfa", "sso", "webauthn", "redis", "migrations")


def _optional_feature_probes() -> dict[str, tuple[tuple[str, Callable[[], object]], ...]]:
    import jafaal.identity_providers.service as idp_service
    import jafaal.mfa.service as mfa_service
    import jafaal.migrations as migrations
    import jafaal.webauthn.service as webauthn_service
    from jafaal.adapters import RedisStateStore

    return {
        "mfa": (("pyotp", mfa_service._pyotp), ("qrcode", mfa_service._qrcode)),
        "sso": (("authlib", idp_service._oauth_client_cls),),
        "webauthn": (("webauthn", webauthn_service._require_webauthn),),
        "redis": (("redis", RedisStateStore),),
        "migrations": (("alembic", migrations._require_alembic),),
    }


def _expect_missing(extra: str, package: str, probe: Callable[[], object]) -> None:
    try:
        probe()
    except MissingDependencyError as err:
        hint = f"pip install 'jafaal[{extra}]'"
        if package not in str(err) or hint not in str(err):
            raise AssertionError(f"{extra} guard did not include package and install hint: {err}") from err
    else:
        raise AssertionError(f"{extra} feature unexpectedly available in an isolated base install")


def _smoke_base_optional_guards() -> None:
    for extra, probes in _optional_feature_probes().items():
        for package, probe in probes:
            _expect_missing(extra, package, probe)


def _smoke_extra(extra: str) -> None:
    probes_by_extra = _optional_feature_probes()
    selected = FEATURE_EXTRAS if extra == "all" else (extra,)

    for selected_extra in selected:
        for _, probe in probes_by_extra[selected_extra]:
            probe()

    if extra == "all":
        return
    for other_extra in FEATURE_EXTRAS:
        if other_extra == extra:
            continue
        for package, probe in probes_by_extra[other_extra]:
            _expect_missing(other_extra, package, probe)


def main(extra: str | None = None) -> int:
    """Run the smoke checks, returning a process exit code."""
    if (Path.cwd() / "jafaal" / "__init__.py").exists():
        print("FAIL: run this from outside the repository root, or the source tree shadows the install")
        return 1

    if not jafaal.__version__:
        print("FAIL: version metadata missing from the installed distribution")
        return 1

    if "site-packages" not in jafaal.__file__:
        print(f"FAIL: imported from the source tree, not an install: {jafaal.__file__}")
        return 1

    jafaal.map_models(Base)
    if extra is not None:
        _smoke_extra(extra)
        print(f"extra smoke OK: jafaal {jafaal.__version__}[{extra}], from {jafaal.__file__}")
        return 0

    engine = create_engine("sqlite://")
    jafaal.configure(
        jafaal.AuthSettings(
            secrets=jafaal.Secrets(
                secret_key="s" * 32,
                fernet_key=Fernet.generate_key().decode(),
            ),
            base_url="https://app.test",
            app_name="Smoke test",
            environment="test",
        )
    )
    jafaal.configure_sessionmaker(sessionmaker(bind=engine))
    jafaal.configure_user_repository(SmokeUserRepository())
    jafaal.configure_settings_provider(StaticSettingsProvider())
    router = jafaal.create_auth_router()

    if len(router.routes) != EXPECTED_SUB_ROUTERS:
        print(f"FAIL: expected {EXPECTED_SUB_ROUTERS} sub-routers, got {len(router.routes)}")
        return 1

    _smoke_base_optional_guards()
    print(
        f"base smoke OK: jafaal {jafaal.__version__}, {len(router.routes)} sub-routers, "
        f"all optional guards, from {jafaal.__file__}"
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--extra", choices=(*FEATURE_EXTRAS, "all"))
    args = parser.parse_args()
    sys.exit(main(args.extra))
