"""Package-level hygiene: version metadata and public-API (__all__) integrity."""

import jafaal


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
