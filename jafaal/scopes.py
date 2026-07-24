"""Authentication scope catalog.

JAFAAL ships only its own auth/identity scopes (``profile``, ``users:*``,
``sessions:*``, ``identity_providers:*``). A host adds its application scopes by
configuring an extended :class:`ScopeCatalog`; the token minter reads the
configured catalog when stamping a token's ``scope`` claim, and the Swagger
``Authorize`` picker advertises the descriptions.

Config delivery mirrors :mod:`jafaal.settings` — a configured module accessor —
with a working default (JAFAAL's own scopes), so :func:`get_scope_catalog` never
raises. The catalog is validated (every minted scope is described; ``regular`` is
a subset of ``admin``) at import and whenever a host configures one.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from jafaal._core.registry import ConfigSlot

# --- JAFAAL's own auth/identity scopes ---
PROFILE = "profile"
USERS_READ = "users:read"
USERS_WRITE = "users:write"
SESSIONS_READ = "sessions:read"
SESSIONS_WRITE = "sessions:write"
IDENTITY_PROVIDERS_READ = "identity_providers:read"
IDENTITY_PROVIDERS_WRITE = "identity_providers:write"

# Scope required to call the token-introspection endpoint (RFC 7662). It is
# intentionally NOT part of the catalog tiers (never minted into a user's token):
# grant it to a resource-server API key via
# ``configure_api_key_scopes([..., AUTH_INTROSPECT])`` so introspection stays a
# service-to-service capability, as RFC 7662 intends.
AUTH_INTROSPECT = "auth:introspect"

# Scopes a non-superuser token carries.
_JAFAAL_REGULAR: tuple[str, ...] = (PROFILE, USERS_READ, IDENTITY_PROVIDERS_READ)
# Scopes a superuser token carries (a superset of the regular tier).
_JAFAAL_ADMIN: tuple[str, ...] = (
    *_JAFAAL_REGULAR,
    USERS_WRITE,
    SESSIONS_READ,
    SESSIONS_WRITE,
    IDENTITY_PROVIDERS_WRITE,
)
_JAFAAL_DESCRIPTIONS: dict[str, str] = {
    PROFILE: "Privileges over the user's own profile",
    USERS_READ: "Read privileges over users",
    USERS_WRITE: "Write privileges over users",
    SESSIONS_READ: "Read privileges over sessions",
    SESSIONS_WRITE: "Create/edit/delete privileges over sessions",
    IDENTITY_PROVIDERS_READ: "Read privileges over identity providers",
    IDENTITY_PROVIDERS_WRITE: "Write privileges over identity providers",
}


@dataclass(frozen=True)
class ScopeCatalog:
    """Scopes a token carries per access tier, plus Swagger descriptions.

    Attributes:
        regular: Scopes stamped into a non-superuser's token.
        admin: Scopes stamped into a superuser's token (a superset of
            ``regular``).
        descriptions: Scope -> human description, shown in the Swagger
            ``Authorize`` dialog. Every minted scope must be described.
    """

    regular: tuple[str, ...]
    admin: tuple[str, ...]
    descriptions: Mapping[str, str]

    def validate(self) -> None:
        """Assert the catalog is internally consistent.

        Every scope advertised in ``descriptions`` must be one the server
        actually mints, and every minted scope must be advertised — a drift
        means either the UI offers a scope that is never enforced or a token
        carries an undocumented scope. ``regular`` must also be a subset of
        ``admin``.

        Raises:
            ValueError: If the catalog is inconsistent.
        """
        minted = frozenset(self.admin)
        described = frozenset(self.descriptions)
        undescribed = minted - described
        unminted = described - minted
        if undescribed or unminted:
            raise ValueError(
                "ScopeCatalog descriptions are out of sync with the scope tuples: "
                f"minted-but-undeclared={sorted(undescribed)}, "
                f"declared-but-never-minted={sorted(unminted)}"
            )
        extra_regular = frozenset(self.regular) - minted
        if extra_regular:
            raise ValueError(f"ScopeCatalog regular scopes are not a subset of admin scopes: {sorted(extra_regular)}")

    def extend(
        self,
        *,
        regular: tuple[str, ...] = (),
        admin: tuple[str, ...] = (),
        descriptions: Mapping[str, str] | None = None,
    ) -> ScopeCatalog:
        """Return a new catalog with the host's application scopes added on top.

        Args:
            regular: Extra scopes for the regular (and, implicitly, admin) tier.
            admin: Extra scopes for the admin tier (include the ``regular`` ones
                too, plus any admin-only scopes).
            descriptions: Descriptions for the added scopes.

        Returns:
            A new :class:`ScopeCatalog` combining JAFAAL's scopes with the host's.
        """
        return ScopeCatalog(
            regular=self.regular + tuple(regular),
            admin=self.admin + tuple(admin),
            descriptions={**self.descriptions, **(descriptions or {})},
        )


#: JAFAAL's own catalog (auth/identity scopes only). A host extends this.
DEFAULT_SCOPE_CATALOG = ScopeCatalog(_JAFAAL_REGULAR, _JAFAAL_ADMIN, _JAFAAL_DESCRIPTIONS)
DEFAULT_SCOPE_CATALOG.validate()

_scope_catalog: ConfigSlot[ScopeCatalog] = ConfigSlot(default_factory=lambda: DEFAULT_SCOPE_CATALOG)


def configure_scopes(catalog: ScopeCatalog) -> None:
    """Install the host's scope catalog (JAFAAL's scopes extended with app scopes).

    Args:
        catalog: The full catalog, typically ``DEFAULT_SCOPE_CATALOG.extend(...)``.

    Raises:
        ValueError: If the catalog is inconsistent (see :meth:`ScopeCatalog.validate`).
    """
    catalog.validate()
    _scope_catalog.configure(catalog)


def get_scope_catalog() -> ScopeCatalog:
    """Return the configured scope catalog (JAFAAL's own until configured)."""
    return _scope_catalog.get()


def reset_scopes() -> None:
    """Reset to JAFAAL's own catalog. Intended for tests."""
    _scope_catalog.reset()
