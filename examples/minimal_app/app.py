"""A complete, runnable JAFAAL deployment in one file.

Everything JAFAAL needs from a host is here and nothing else: a user model, the
three ports, and the router. Run it with::

    uv run --with 'jafaal[all]' --with uvicorn uvicorn app:app --reload

then open http://127.0.0.1:8000/docs. A demo account is created on first start:

    username: demo    password: correct-horse-battery-staple

The database is SQLite in this directory, so deleting ``example.db`` resets
everything. See ../web_client.md and ../mobile_client.md for the client-side
walkthroughs that drive these endpoints.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated, Any

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI
from sqlalchemy import String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

import jafaal
from jafaal.adapters import HibpBreachChecker, StateStoreRateLimiter

logging.basicConfig(level=logging.INFO)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "example.db")


# --------------------------------------------------------------------------- #
# 1. Configure the library
#
# JAFAAL never reads the environment itself: the host builds the settings and
# injects them once. Read the keys from your secret manager in a real
# deployment — generating them at import time, as this example does, would
# invalidate every issued token on restart.
# --------------------------------------------------------------------------- #

jafaal.configure(
    jafaal.AuthSettings(
        secrets=jafaal.Secrets(
            secret_key=os.environ.get("JAFAAL_SECRET_KEY", "dev-only-secret-key-at-least-32-bytes!!"),
            fernet_key=os.environ.get("JAFAAL_FERNET_KEY", Fernet.generate_key().decode()),
        ),
        base_url="http://127.0.0.1:8000",
        app_name="JAFAAL Example",
        # "development" keeps the refresh cookie non-Secure so it survives plain
        # HTTP on IP loopback. Use "production" anywhere real, and serve HTTPS.
        environment="development",
        # Where /auth/authorize sends a browser that still has to log in.
        login_ui_url="http://127.0.0.1:8000/login",
        oauth_clients=(
            # A browser SPA: the refresh token goes back as an HttpOnly cookie
            # so page script never touches it.
            jafaal.OAuthClient(
                client_id="example-web",
                redirect_uris=("http://127.0.0.1:8000/callback",),
                token_delivery="cookie",
                name="Example web app",
            ),
            # A native app: no cookie jar, so the refresh token comes back in
            # the response body and the app stores it in the platform keystore.
            jafaal.OAuthClient(
                client_id="example-mobile",
                redirect_uris=("com.example.app:/callback",),
                token_delivery="body",
                name="Example mobile app",
            ),
        ),
    )
)


# --------------------------------------------------------------------------- #
# 2. Own the declarative Base and map JAFAAL's companion tables into it
#
# One registry means JAFAAL's foreign keys to ``users.id`` resolve and its
# reverse relationships work. The mixin supplies every auth column and
# relationship; add whatever profile columns you like alongside them.
# --------------------------------------------------------------------------- #


class Base(DeclarativeBase):
    pass


class Users(jafaal.IntPKUserMixin, Base):
    __tablename__ = "users"

    display_name: Mapped[str | None] = mapped_column(String(250))


jafaal.map_models(Base)

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
jafaal.configure_sessionmaker(SessionLocal)


# --------------------------------------------------------------------------- #
# 3. Implement the ports
#
# These three are the whole contract. JAFAAL owns passwords, tokens, sessions,
# MFA and the routers; the host owns its user table, its dynamic settings, and
# how notifications are delivered.
# --------------------------------------------------------------------------- #


class SqlUserRepository:
    """Persistence for the host's user table."""

    def get_by_id(self, user_id: Any, db) -> Users | None:
        return db.get(Users, user_id)

    def get_by_email(self, email: str, db) -> Users | None:
        return db.execute(select(Users).where(Users.email == email)).scalar_one_or_none()

    def get_by_username(self, username: str, db) -> Users | None:
        return db.execute(select(Users).where(Users.username == username)).scalar_one_or_none()

    def create_local_user(self, username: str, email: str, db, *, is_active: bool, is_verified: bool) -> Users:
        user = Users(username=username, email=email, is_active=is_active, is_verified=is_verified)
        db.add(user)
        # Flush, never commit: JAFAAL writes the password credential in this same
        # transaction, so committing here could leave a credential-less account
        # squatting the username.
        db.flush()
        return user

    def provision_from_idp(self, identity: jafaal.IdpIdentity, db) -> Users:
        user = Users(
            username=identity.suggested_username,
            email=identity.email or f"{identity.subject}@sso.invalid",
            display_name=identity.display_name,
            is_active=True,
            is_verified=identity.email_verified,
        )
        db.add(user)
        db.flush()
        return user

    def sync_from_idp(self, user_id: Any, claims, db) -> None:
        user = db.get(Users, user_id)
        if user is None:
            return
        if name := claims.get("name"):
            user.display_name = name
        # ``email`` is present only when the provider asserted it verified.
        if email := claims.get("email"):
            user.email = email

    def set_email_verified(self, user_id: Any, db, *, activate: bool) -> None:
        user = db.get(Users, user_id)
        if user is None:
            return
        user.is_verified = True
        if activate:
            user.is_active = True


class StaticSettingsProvider:
    """Password policy and sign-up toggles.

    Static here; back it with a settings table if operators change these at
    runtime.
    """

    def get_password_policy(self) -> jafaal.PasswordPolicy:
        # NIST SP 800-63B-4 §3.1.1.2: length, not composition rules.
        return jafaal.PasswordPolicy(
            min_length_regular=15,
            min_length_admin=20,
            password_type="length_only",
        )

    def get_signup_config(self) -> jafaal.SignupConfig:
        return jafaal.SignupConfig(
            enabled=True,
            require_email_verification=False,
            require_admin_approval=False,
        )


class LoggingEventSink:
    """Delivers JAFAAL's outbound notifications.

    JAFAAL never sends email. It emits an event and the host delivers it; this
    one just logs, so you can watch the flows. Swap in your mailer.
    """

    async def on_password_reset_requested(self, event) -> None:
        logging.info("Send password reset to %s: token=%s", event.email, event.token)

    async def on_email_verification_requested(self, event) -> None:
        logging.info("Send verification to %s: token=%s", event.email, event.token)

    async def on_account_locked(self, event) -> None:
        logging.warning("Account locked: user_id=%s", event.user_id)

    async def on_refresh_token_theft_detected(self, event) -> None:
        logging.error("Refresh-token theft: user_id=%s family=%s", event.user_id, event.token_family_id)


jafaal.configure_user_repository(SqlUserRepository())
jafaal.configure_settings_provider(StaticSettingsProvider())
jafaal.configure_event_sink(LoggingEventSink())
# NIST pairs "no composition rules" with a breach blocklist. This one is free,
# unauthenticated, and k-anonymous: only a five-character SHA-1 prefix leaves
# the process.
jafaal.configure_password_breach_checker(HibpBreachChecker())


# --------------------------------------------------------------------------- #
# 4. Build the app
# --------------------------------------------------------------------------- #


def _seed_demo_account() -> None:
    """Create the demo login on first start.

    JAFAAL stores credentials in its own table, so the user row and the
    credential must land in one transaction — hence the single unit of work.
    """
    with SessionLocal() as db, jafaal.unit_of_work(db):
        if db.execute(select(Users).where(Users.username == "demo")).scalar_one_or_none():
            return
        user = Users(username="demo", email="demo@example.com", is_active=True, is_verified=True)
        db.add(user)
        db.flush()
        jafaal.set_password(user.id, "correct-horse-battery-staple", db)
        logging.info("Seeded demo account (demo / correct-horse-battery-staple)")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)  # Use jafaal.migrations (Alembic) in production.
    _seed_demo_account()
    yield


app = FastAPI(title="JAFAAL example", lifespan=lifespan)

# ``create_auth_router`` verifies the configuration up front, so a missing port
# fails here with one clear message instead of on the first request that needs it.
app.include_router(
    jafaal.create_auth_router(app=app, rate_limiter=StateStoreRateLimiter()),
    prefix="/api/v1",
)


@app.get("/api/v1/me")
def read_me(
    auth: Annotated[jafaal.AuthContext, Depends(jafaal.validate_access_token_or_api_key)],
) -> dict[str, Any]:
    """A protected endpoint, to show how you consume JAFAAL's identity.

    ``validate_access_token_or_api_key`` accepts either a Bearer access token or
    an API key and resolves both to the same ``AuthContext``, so an endpoint
    never has to care which credential the caller used.
    """
    return {"user_id": auth.user_id, "scopes": sorted(auth.scopes)}
