> [!NOTE]
> **GitHub Mirror** - If you are viewing this on GitHub, please be aware that this repository is a read-only mirror. Issues, pull requests, and all project activity are tracked on Codeberg: [https://codeberg.org/endurain-project/jafaal](https://codeberg.org/endurain-project/jafaal)

# Just Another FastAPI Authentication Library (JAFAAL)

[![License](https://img.shields.io/badge/license-MIT-green)](https://codeberg.org/endurain-project/jafaal/src/branch/main/LICENSE.md)
[![Release](https://img.shields.io/badge/dynamic/json?url=https://codeberg.org/api/v1/repos/endurain-project/jafaal/releases/latest&query=$.tag_name&label=release&color=blue)](https://codeberg.org/endurain-project/jafaal/releases)
[![PyPI version](https://img.shields.io/pypi/v/jafaal)](https://pypi.org/project/jafaal/)
[![PyPI downloads](https://img.shields.io/pypi/dm/jafaal)](https://pypi.org/project/jafaal/)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://pypi.org/project/jafaal/)
[![Docs](https://img.shields.io/badge/docs-endurain--project.codeberg.page-blue)](https://jafaal.endurain.com/)
[![Stars](https://img.shields.io/badge/dynamic/json?url=https://codeberg.org/api/v1/repos/endurain-project/jafaal&query=$.stars_count&label=stars&logo=codeberg)](https://codeberg.org/endurain-project/jafaal)

## What is JAFAAL?

JAFAAL is a batteries-included, framework-agnostic authentication library for
FastAPI + SQLAlchemy applications. It owns the security-critical parts of auth so
your app doesn't have to:

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
tables, routers, token logic — ships with the library.

## Installation

```bash
pip install jafaal
# or
uv add jafaal
```

Requires Python 3.12+.

### Optional features

A minimal "login + JWT + sessions" deployment needs no extras. Multi-factor
authentication and single sign-on pull in additional packages, so they ship as
optional extras. Install only what you use:

```bash
pip install 'jafaal[mfa]'   # TOTP MFA (pyotp) + QR provisioning (qrcode)
pip install 'jafaal[sso]'   # OpenID Connect identity providers (authlib)
pip install 'jafaal[all]'   # everything
```

If a feature is used without its extra installed, JAFAAL fails fast with a clear
install hint (a `MissingDependencyError`) rather than an obscure error.

## Quickstart

### 1. Configure the library

JAFAAL never reads environment variables itself — you build the settings and
inject them once at startup.

```python
import jafaal
from cryptography.fernet import Fernet

jafaal.configure(
    jafaal.AuthSettings(
        secret_key="<32+ byte JWT signing secret>",
        fernet_key=Fernet.generate_key().decode(),  # at-rest token encryption
        base_url="https://app.example.com",
        app_name="Example",                          # shown in authenticator apps
        environment="production",                    # drives the cookie Secure flag
    )
)
```

### 2. Build your user model on JAFAAL's `Base` and register a session factory

JAFAAL owns a single declarative registry so its companion tables and your user
table share one metadata. Your model **must** be named `Users`, mapped to the
`users` table.

```python
from sqlalchemy import String, create_engine
from sqlalchemy.orm import Mapped, mapped_column, sessionmaker

from jafaal.orm import Base
from jafaal import IntPKUserMixin


class Users(IntPKUserMixin, Base):
    __tablename__ = "users"
    # Add any app-specific profile columns — JAFAAL never touches them:
    display_name: Mapped[str | None] = mapped_column(String(250))


engine = create_engine("postgresql+psycopg://...")
jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False))
Base.metadata.create_all(engine)  # or use Alembic migrations
```

The reverse relationships (`users_sessions`, `local_credential`, `auth_mfa`, …)
and the `mfa_enabled` property are supplied by the mixin — you declare none of them.

### 3. Implement the ports

```python
from jafaal import (
    PasswordPolicy, SignupConfig, UserProtocol,
    configure_settings_provider, configure_user_repository,
)


class SqlUserRepository:
    def get_by_id(self, user_id, db) -> UserProtocol | None:
        return db.get(Users, user_id)

    def get_by_email(self, email, db):
        return db.query(Users).filter(Users.email == email).one_or_none()

    def get_by_username(self, username, db):
        return db.query(Users).filter(Users.username == username).one_or_none()

    def create_local_user(self, username, email, db, *, is_active, is_verified):
        user = Users(username=username, email=email,
                     is_active=is_active, is_verified=is_verified)
        db.add(user); db.commit(); db.refresh(user)
        return user

    def provision_from_idp(self, identity, db): ...      # SSO auto-provisioning
    def sync_from_idp(self, user_id, claims, db): ...     # optional profile sync
    def set_email_verified(self, user_id, db, *, activate):
        user = db.get(Users, user_id)
        user.is_verified = True
        if activate:
            user.is_active = True
        db.commit()


class StaticSettingsProvider:
    def get_password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(min_length_regular=8, min_length_admin=12, password_type="strict")

    def get_signup_config(self) -> SignupConfig:
        return SignupConfig(enabled=True, require_email_verification=False,
                            require_admin_approval=False)


configure_user_repository(SqlUserRepository())
configure_settings_provider(StaticSettingsProvider())
```

Notifications (password-reset / sign-up emails, admin pings) are optional — JAFAAL
emits events to an `AuthEventSink`; install one with `jafaal.configure_event_sink(...)`
to deliver them, or skip it and those flows simply mint tokens without sending mail.

### 4. Mount the router

```python
from fastapi import FastAPI
import jafaal

app = FastAPI()
# Registers the JafaalError→HTTP handler and aggregates every sub-router.
app.include_router(jafaal.create_auth_router(app=app), prefix="/api/v1")
```

That's it — you now have `/api/v1/auth/login`, `/refresh`, `/logout`, session
management, MFA, API keys, SSO, sign-up and password-reset endpoints.

### 5. Optional configuration

```python
from jafaal import DEFAULT_SCOPE_CATALOG, configure_scopes, configure_api_key_scopes

# Layer your application scopes on top of JAFAAL's auth/identity scopes:
configure_scopes(DEFAULT_SCOPE_CATALOG.extend(
    regular=("reports:read",),
    admin=("reports:read", "reports:write"),
    descriptions={"reports:read": "Read reports", "reports:write": "Manage reports"},
))

# Opt each scope an API key may carry in explicitly (empty by default):
configure_api_key_scopes(["reports:read"])

# jafaal.configure_rate_limiter(...)  # inject a real limiter (e.g. slowapi)
# jafaal.configure_state_store(...)   # inject Redis for multi-worker lockout state
```

By default JAFAAL runs in a single process with an in-memory state store and no
rate limiting. For multi-worker/replica deployments, inject a distributed
`StateStore` and a `RateLimiter`.

## Documentation

Full documentation lives at [jafaal.endurain.com](https://jafaal.endurain.com/).

## Sponsors

A huge thank you to the project sponsors! Your support helps keep this project going.

Support Endurain's development on:

- [Buy Me a Coffee](https://buymeacoffee.com/endurain)
- [liberapay](https://liberapay.com/endurain/)
- [Patreon](https://patreon.com/u84745218)
- [GitHub Sponsors using archived repo](https://github.com/endurain-project/endurain)

## Contributing

Contributions are welcomed! Please open an issue to discuss any changes or improvements before submitting a PR. Check out the [Contributing Guidelines](CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.

<div align="center">
  <sub>Built with ❤️ from Portugal | Part of the <a href="https://codeberg.org/endurain-project">Endurain</a> ecosystem</sub>
</div>