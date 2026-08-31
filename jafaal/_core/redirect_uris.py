"""OAuth redirect URI validation and request matching."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_REVERSE_DOMAIN_SCHEME = re.compile(
    r"[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)


@dataclass(frozen=True)
class _RedirectUri:
    raw: str
    parsed: SplitResult
    is_loopback: bool = False


def _parse(uri: str) -> _RedirectUri:
    if not uri:
        raise ValueError("must not be empty")
    if not uri.isascii():
        raise ValueError("must be an ASCII URI; percent-encode non-ASCII characters")
    if any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in uri):
        raise ValueError("must not contain whitespace or control characters")
    if "#" in uri:
        raise ValueError("must not contain a fragment")

    try:
        parsed = urlsplit(uri)
        _ = parsed.port
    except ValueError as err:
        raise ValueError(f"is malformed: {err}") from err

    if not parsed.scheme:
        raise ValueError("must be an absolute URI with a scheme")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("must not contain user credentials")
    if parsed.hostname == "localhost":
        raise ValueError("localhost is not allowed; use the loopback IP literal 127.0.0.1 or [::1]")

    scheme = parsed.scheme.lower()
    if scheme == "https":
        if not parsed.hostname:
            raise ValueError("an HTTPS redirect must include a host")
        return _RedirectUri(uri, parsed)

    if scheme == "http":
        if parsed.hostname not in _LOOPBACK_HOSTS:
            raise ValueError("plain HTTP is allowed only for 127.0.0.1 or [::1] native-app loopback redirects")
        return _RedirectUri(uri, parsed, is_loopback=True)

    if not _REVERSE_DOMAIN_SCHEME.fullmatch(parsed.scheme):
        raise ValueError("a private-use scheme must use reverse-domain syntax such as 'com.example.app'")
    if parsed.netloc or not parsed.path.startswith("/"):
        raise ValueError("a private-use redirect must use a single slash after its scheme")
    return _RedirectUri(uri, parsed)


def validate_redirect_uri(uri: str) -> None:
    """Raise ``ValueError`` unless ``uri`` is an allowed redirect URI."""
    _parse(uri)


def _without_loopback_port(uri: _RedirectUri) -> str:
    scheme_separator = uri.raw.find("://")
    authority_start = scheme_separator + 3
    authority_end = len(uri.raw)
    for delimiter in "/?":
        index = uri.raw.find(delimiter, authority_start)
        if index != -1:
            authority_end = min(authority_end, index)

    host = "[::1]" if uri.parsed.hostname == "::1" else "127.0.0.1"
    authority = uri.raw[authority_start:authority_end]
    if authority != host and not (authority.startswith(f"{host}:") and authority[len(host) + 1 :].isdigit()):
        raise ValueError("loopback authority is not an IP literal with an optional numeric port")
    return f"{uri.raw[:authority_start]}{host}{uri.raw[authority_end:]}"


def redirect_uri_matches(registered: str, requested: str) -> bool:
    """Match exactly, except for a native loopback redirect's port."""
    try:
        registered_uri = _parse(registered)
        requested_uri = _parse(requested)
        if registered_uri.is_loopback:
            if not requested_uri.is_loopback or registered_uri.parsed.hostname != requested_uri.parsed.hostname:
                return False
            return hmac.compare_digest(
                _without_loopback_port(registered_uri),
                _without_loopback_port(requested_uri),
            )
    except ValueError:
        return False
    return hmac.compare_digest(registered, requested)


def redirect_uri_matches_exactly(expected: str, presented: str) -> bool:
    """Validate both URIs and compare every character exactly."""
    try:
        _parse(expected)
        _parse(presented)
    except ValueError:
        return False
    return hmac.compare_digest(expected, presented)
