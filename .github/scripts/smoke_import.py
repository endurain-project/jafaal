"""Smoke-test a JAFAAL install: bare import, model mapping, router assembly.

Run against an environment that has **only** the base runtime dependencies (no
``mfa`` / ``sso`` / ``redis`` / ``webauthn`` extras, no dev groups). It proves
three things a packaging mistake would break:

1. ``import jafaal`` works without any optional dependency - the feature modules
   really do import defensively.
2. The distribution carries its version metadata (i.e. it was installed, not
   merely found on ``sys.path``).
3. The full router assembles, which transitively imports every sub-router,
   model, and schema in the package.

Step 3 needs a host ``Users`` model, because JAFAAL's companion tables carry
foreign keys and relationships to it - the library deliberately does not own the
user table. A minimal one is defined here.

Must be run from **outside** the repository root, otherwise the local ``jafaal/``
package directory shadows the installed distribution and this would silently
validate the working tree instead of the built artifact::

    cd /tmp && python /path/to/repo/.github/scripts/smoke_import.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy.orm import DeclarativeBase

import jafaal


class Base(DeclarativeBase):
    """Host-owned declarative base (JAFAAL maps its tables into this registry)."""


class Users(jafaal.IntPKUserMixin, Base):
    """Minimal host user model - the FK/relationship target JAFAAL requires."""

    __tablename__ = "users"


# ``create_auth_router`` imports and includes every sub-router: auth, sessions,
# api-keys, identity providers (private + public), password reset, sign-up,
# WebAuthn (private + public), JWKS, and RFC 8414 metadata. Recent FastAPI
# records each as a lazily-flattened ``_IncludedRouter``, so this count is the
# number of sub-routers that imported cleanly - exactly what this smoke test
# checks.
EXPECTED_SUB_ROUTERS = 11


def main() -> int:
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
    router = jafaal.create_auth_router()

    if len(router.routes) != EXPECTED_SUB_ROUTERS:
        print(f"FAIL: expected {EXPECTED_SUB_ROUTERS} sub-routers, got {len(router.routes)}")
        return 1

    print(f"smoke OK: jafaal {jafaal.__version__}, {len(router.routes)} sub-routers, from {jafaal.__file__}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
