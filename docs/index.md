# JAFAAL

<div>
    <a href="https://codeberg.org/endurain-project/jafaal/src/branch/main/LICENSE.md">
      <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
    </a>
    <a href="https://codeberg.org/endurain-project/jafaal/releases">
      <img src="https://img.shields.io/badge/dynamic/json?url=https://codeberg.org/api/v1/repos/endurain-project/jafaal/releases/latest&query=$.tag_name&label=release&color=blue" alt="Release">
    </a>
    <a href="https://pypi.org/project/jafaal/">
      <img src="https://img.shields.io/pypi/v/jafaal" alt="PyPI version">
    </a>
    <a href="https://codeberg.org/endurain-project/jafaal">
      <img src="https://img.shields.io/badge/dynamic/json?url=https://codeberg.org/api/v1/repos/endurain-project/jafaal&query=$.stars_count&label=stars&logo=codeberg" alt="Stars">
    </a>
</div>

**Just Another FastAPI Authentication Library.** JAFAAL is a batteries-included,
framework-agnostic authentication library for FastAPI + SQLAlchemy applications.
It owns the security-critical parts of auth so your app doesn't have to.

## Features

- **Password login** (Argon2, bcrypt fallback) with progressive per-account lockout
- **JWT access/refresh tokens** (HS256) with refresh-token **rotation + reuse detection**
- **Sessions** with idle/absolute timeout, CSRF binding, and web/mobile (PKCE) flows
- **MFA** (TOTP + single-use backup codes) with replay protection
- **API keys** with a host-controlled scope allow-list
- **SSO / OIDC** identity providers with SSRF-guarded outbound calls
- **Password reset & sign-up** flows that emit events (you deliver the email)
- A **`JafaalError` → HTTP** edge handler, so the core never imports HTTP concerns

JAFAAL depends only on a small set of **ports** you implement (your user table,
your dynamic settings, and how you deliver notifications). Everything else —
tables, routers, token logic — ships with the library, and ready-made
[adapters](ports-and-adapters.md#batteries-included-adapters) cover the common cases.

## Installation

```bash
pip install jafaal
# or
uv add jafaal
```

Requires Python 3.12+.

### Optional features

A minimal "login + JWT + sessions" deployment needs no extras. Install only what
you use:

```bash
pip install 'jafaal[mfa]'     # TOTP MFA (pyotp) + QR provisioning (qrcode)
pip install 'jafaal[sso]'     # OpenID Connect identity providers (authlib)
pip install 'jafaal[redis]'   # distributed StateStore adapter (redis)
pip install 'jafaal[all]'     # everything
```

If a feature is used without its extra installed, JAFAAL fails fast with a clear
install hint (a `MissingDependencyError`) rather than an obscure error.

## Quickstart

```python
import jafaal
from cryptography.fernet import Fernet
from fastapi import FastAPI
from sqlalchemy import String, create_engine
from sqlalchemy.orm import Mapped, mapped_column, sessionmaker

from jafaal import IntPKUserMixin
from jafaal.adapters import SqlAlchemyUserRepository, StaticSettingsProvider
from jafaal.orm import Base

# 1. Configure the library (you build settings; JAFAAL reads no env itself).
jafaal.configure(
    jafaal.AuthSettings(
        secret_key="<32+ byte JWT signing secret>",
        fernet_key=Fernet.generate_key().decode(),
        base_url="https://app.example.com",
        app_name="Example",
        environment="production",
    )
)


# 2. Build your user model on JAFAAL's Base (must be named `Users`, table `users`).
class Users(IntPKUserMixin, Base):
    __tablename__ = "users"
    display_name: Mapped[str | None] = mapped_column(String(250))


engine = create_engine("postgresql+psycopg://...")
jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False))
Base.metadata.create_all(engine)  # or use Alembic migrations

# 3. Install the ports (here via the batteries-included adapters).
jafaal.configure_user_repository(SqlAlchemyUserRepository())
jafaal.configure_settings_provider(StaticSettingsProvider())

# 4. Mount the router — registers the JafaalError→HTTP handler and every sub-router.
app = FastAPI()
app.include_router(jafaal.create_auth_router(app=app), prefix="/api/v1")
```

That's it — you now have `/api/v1/auth/login`, `/refresh`, `/logout`, session
management, MFA, API keys, SSO, sign-up and password-reset endpoints.

## Where to next

- **[Configuration](configuration.md)** — `AuthSettings`, sessions, scopes, rate
  limiting, and the distributed state store.
- **[Ports & Adapters](ports-and-adapters.md)** — the host boundary you implement
  and the ready-made adapters that satisfy it.
- **[Security](security.md)** — the threat model, built-in protections, and
  deployment hardening.
- **[API Reference](api.md)** — the full public API.
