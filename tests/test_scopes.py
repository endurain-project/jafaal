"""Tests for the scope catalog: validation, extension, and configuration."""

import pytest

import jafaal
from jafaal import scopes as scopes_mod


def test_default_catalog_is_valid_and_regular_subset_of_admin():
    cat = scopes_mod.DEFAULT_SCOPE_CATALOG
    cat.validate()  # does not raise
    assert set(cat.regular).issubset(set(cat.admin))
    # Every minted scope is described.
    assert set(cat.admin) == set(cat.descriptions)


def test_validate_rejects_undescribed_scope():
    bad = scopes_mod.ScopeCatalog(
        regular=("profile",),
        admin=("profile", "secret:scope"),
        descriptions={"profile": "p", "secret:scope": "s"},
    )
    bad.validate()  # described → OK
    worse = scopes_mod.ScopeCatalog(
        regular=("profile",),
        admin=("profile", "secret:scope"),
        descriptions={"profile": "p"},
    )
    with pytest.raises(ValueError, match="out of sync"):
        worse.validate()


def test_validate_rejects_regular_not_subset_of_admin():
    # ``extra:only`` is in regular but neither minted (admin) nor described, so
    # the description-sync check passes and the subset check is what fires.
    bad = scopes_mod.ScopeCatalog(
        regular=("profile", "extra:only"),
        admin=("profile",),
        descriptions={"profile": "p"},
    )
    with pytest.raises(ValueError, match="not a subset"):
        bad.validate()


def test_extend_adds_app_scopes_and_revalidates():
    extended = scopes_mod.DEFAULT_SCOPE_CATALOG.extend(
        regular=("reports:read",),
        admin=("reports:read", "reports:write"),
        descriptions={"reports:read": "Read reports", "reports:write": "Manage reports"},
    )
    extended.validate()
    assert "reports:read" in extended.regular
    assert "reports:write" in extended.admin
    assert "reports:write" not in extended.regular


def test_configure_installs_and_validates():
    extended = scopes_mod.DEFAULT_SCOPE_CATALOG.extend(
        regular=("reports:read",),
        admin=("reports:read",),
        descriptions={"reports:read": "Read reports"},
    )
    jafaal.configure_scopes(extended)
    assert "reports:read" in jafaal.get_scope_catalog().regular

    jafaal.reset_scopes()
    assert jafaal.get_scope_catalog() is scopes_mod.DEFAULT_SCOPE_CATALOG


def test_configure_rejects_inconsistent_catalog():
    bad = scopes_mod.ScopeCatalog(
        regular=("nope",),
        admin=("nope",),
        descriptions={},
    )
    with pytest.raises(ValueError):
        jafaal.configure_scopes(bad)
