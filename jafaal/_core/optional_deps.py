"""Fail-fast guards for optional third-party dependencies.

JAFAAL's single sign-on (identity providers) and MFA features depend on
third-party packages that a minimal "login + JWT + sessions" deployment does not
need. Those packages are declared as optional extras in ``pyproject.toml``
(``jafaal[sso]`` / ``jafaal[mfa]``).

Because ``import jafaal`` transitively imports the feature service modules, those
modules import their optional dependency defensively (falling back to ``None``)
so the package still imports without the extra installed. Each entry point that
actually uses the dependency then calls :func:`require`, so a missing extra
fails loudly with an actionable install hint at call time — never as a bare
``AttributeError`` on ``None`` deep in the flow.
"""

from __future__ import annotations

__all__ = ["MissingDependencyError", "require"]


class MissingDependencyError(RuntimeError):
    """Raised when an optional JAFAAL feature is used without its dependency.

    A deployment/environment error (the operator did not install the extra),
    not a request-level auth error — hence a plain :class:`RuntimeError`, not a
    :class:`~jafaal.exceptions.JafaalError`. It should surface loudly rather than
    be mapped to an HTTP response.
    """


def require[T](module: T | None, *, package: str, extra: str, feature: str) -> T:
    """Return ``module``, or raise a clear install hint when it is ``None``.

    Args:
        module: The optionally-imported module/object (``None`` if the package
            is not installed).
        package: The distribution name to install (e.g. ``"pyotp"``).
        extra: The JAFAAL extra that provides it (e.g. ``"mfa"``).
        feature: Human-readable feature name for the error message.

    Returns:
        ``module``, guaranteed non-``None``.

    Raises:
        MissingDependencyError: If ``module`` is ``None``.
    """
    if module is None:
        raise MissingDependencyError(
            f"{feature} requires the optional '{package}' package, which is not installed. "
            f"Install it with: pip install 'jafaal[{extra}]'"
        )
    return module
