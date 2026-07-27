"""Tests that JAFAAL imposes nothing on the host's domain model.

Two contracts were removed in the run-up to 1.0, and these pin them removed:

* the host user class no longer has to be *named* ``Users`` — it is handed to
  :func:`jafaal.map_models` explicitly;
* ``is_superuser`` is no longer part of the boundary protocol — it feeds only the
  default scope resolver and the admin password-length policy, both of which read
  it defensively.

The rest of the suite already proves the first one implicitly: ``conftest`` maps
a class called ``Account`` and 800-odd tests pass. What is asserted here is the
*intent*, so a future change that reintroduces a name lookup fails loudly rather
than quietly re-imposing the convention.
"""

from __future__ import annotations

import pytest
from conftest import Account

import jafaal
import jafaal.orm as jafaal_orm
import jafaal.ports as jafaal_ports
import jafaal.scopes as jafaal_scopes

# --------------------------------------------------------------------------- #
# The user class is registered, not discovered by name
# --------------------------------------------------------------------------- #


def test_the_host_user_class_need_not_be_named_users():
    # The suite's model is called Account. If any lookup still keyed on the name
    # "Users", nothing in this package would resolve.
    assert jafaal_orm.get_user_model() is Account
    assert Account.__name__ != "Users"


def test_jafaal_models_resolve_their_relationship_through_the_registration(db):
    # The relationship target is the registered class, not a string looked up in
    # SQLAlchemy's class registry.
    import jafaal.sessions.models as sessions_models

    assert sessions_models.UsersSessions.users.property.mapper.class_ is Account


def test_map_models_rejects_a_second_conflicting_user_model():
    class Other:
        pass

    with pytest.raises(RuntimeError, match="different user_model"):
        jafaal.map_models(jafaal_orm.get_active_base(), user_model=Other)


def test_map_models_is_idempotent_with_the_same_arguments():
    # Re-registering the same pair is a no-op, so a host that calls it from two
    # entry points (app factory and a worker) is not punished for it.
    jafaal.map_models(jafaal_orm.get_active_base(), user_model=Account)
    assert jafaal_orm.get_user_model() is Account


# --------------------------------------------------------------------------- #
# is_superuser is optional
# --------------------------------------------------------------------------- #


class _NoFlagUser:
    """A host user model with no ``is_superuser`` attribute at all."""

    id = 1
    username = "nobody"
    email = "nobody@test.dev"
    is_active = True
    is_verified = True

    @property
    def mfa_enabled(self) -> bool:
        return False


def test_a_user_model_without_the_flag_satisfies_the_boundary_protocol():
    assert isinstance(_NoFlagUser(), jafaal_ports.UserProtocol)


def test_the_default_resolver_treats_a_missing_flag_as_unprivileged():
    # Reading the attribute directly would raise; the whole point of routing it
    # through one helper is that a host without the column still works.
    scopes = jafaal_ports.TieredScopeResolver().scopes_for(_NoFlagUser())  # type: ignore[arg-type]
    assert scopes == jafaal_scopes.get_scope_catalog().regular


def test_is_superuser_reader_handles_present_and_absent(make_user):
    assert jafaal_ports.is_superuser(_NoFlagUser()) is False  # type: ignore[arg-type]
    assert jafaal_ports.is_superuser(make_user(username="admin", is_superuser=True)) is True
    assert jafaal_ports.is_superuser(make_user(username="plain")) is False


def test_a_custom_resolver_replaces_the_flag_entirely(make_user):
    """A host with roles instead of a boolean stamps whatever it wants."""

    class RoleResolver:
        def scopes_for(self, user):
            return ("profile", "billing:write") if user.username == "biller" else ("profile",)

    original = jafaal_ports.get_scope_resolver()
    jafaal.configure_scope_resolver(RoleResolver())
    try:
        biller = make_user(username="biller")
        plain = make_user(username="plain")
        assert jafaal_ports.get_scope_resolver().scopes_for(biller) == ("profile", "billing:write")
        assert jafaal_ports.get_scope_resolver().scopes_for(plain) == ("profile",)
    finally:
        jafaal.configure_scope_resolver(original)
