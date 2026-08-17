"""Package-level hygiene: version metadata and public-API (__all__) integrity."""

import re
from pathlib import Path

import jafaal

API_STABILITY_DOC = Path(__file__).resolve().parent.parent / "docs" / "api-stability.md"


def test_version_is_populated():
    assert isinstance(jafaal.__version__, str)
    assert jafaal.__version__
    assert "__version__" in jafaal.__all__


def test_all_exports_are_importable():
    """Every name advertised in ``__all__`` must actually be importable."""
    missing = [name for name in jafaal.__all__ if not hasattr(jafaal, name)]
    assert missing == []


def test_all_has_no_duplicates():
    assert len(jafaal.__all__) == len(set(jafaal.__all__))


def test_the_documented_extension_surface_still_exists():
    """Every name the stability policy weakens the promise for must be real.

    The extension-surface table in ``docs/api-stability.md`` is what lets these
    names change in a minor release. A stale entry silently widens the SemVer
    promise back over something the policy says is not covered.
    """
    section = API_STABILITY_DOC.read_text().split("#### Extension surface", 1)[1]
    section = section.split("Everything else in `__all__`", 1)[0]
    # Only the table rows name exports; the surrounding prose does not.
    rows = [line for line in section.splitlines() if line.startswith("|")]
    documented = set(re.findall(r"`([a-zA-Z_][a-zA-Z0-9_]*)`", "\n".join(rows)))
    documented.discard("configure_")  # the row label, not an export

    unknown = sorted(name for name in documented if name not in jafaal.__all__)
    assert unknown == [], f"documented as extension surface but not exported: {unknown}"
