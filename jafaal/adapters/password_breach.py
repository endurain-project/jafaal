"""Reference :class:`~jafaal.ports.PasswordBreachChecker` implementations.

Installed via :func:`jafaal.configure_password_breach_checker`, these screen a
proposed password against known-breached passwords (NIST SP 800-63B), the
recommended companion to a length-only policy.

* :class:`HibpBreachChecker` — queries the *Have I Been Pwned* "Pwned Passwords"
  range API. That endpoint is **free and unauthenticated** (no API key) and uses
  **k-anonymity**: only the first five hex characters of the password's SHA-1
  hash ever leave the process, and the server returns every hash suffix sharing
  that prefix so the match is computed locally. The full password (and full
  hash) are never transmitted. It checks the *password alone* — not a
  username/email pair (that is a different, commercial, more privacy-sensitive
  control; server-side progressive lockout already mitigates credential
  stuffing).
* :class:`BlocklistBreachChecker` — in-memory membership against a host-supplied
  list (e.g. a bundled "top N breached passwords" file or a custom deny-list).
  No network, no dependencies.

Both fail **open** where relevant: :class:`HibpBreachChecker` returns ``False``
(password allowed) on any network/HTTP error, so a breach-service outage cannot
block every password change. ``httpx`` is already a JAFAAL dependency, so neither
adapter needs an extra install.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable

import httpx

__all__ = ["BlocklistBreachChecker", "HibpBreachChecker"]

logger = logging.getLogger("jafaal.adapters.password_breach")

#: Public, free, unauthenticated HIBP "Pwned Passwords" range endpoint.
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"


class HibpBreachChecker:
    """A ``PasswordBreachChecker`` backed by the HIBP Pwned Passwords range API.

    The lookup is k-anonymous: the password is SHA-1 hashed locally and only the
    first five hex characters of the (uppercase) digest are sent; the API returns
    all suffixes sharing that prefix and the match is decided in-process.
    """

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        timeout: float = 2.0,
        min_count: int = 1,
        add_padding: bool = True,
        user_agent: str = "jafaal-password-breach-checker",
        base_url: str = HIBP_RANGE_URL,
    ) -> None:
        """Create the checker.

        Args:
            client: An existing ``httpx.Client`` to reuse (recommended for
                connection pooling and required for testing). When omitted, a
                client is created and owned by this instance (close it via
                :meth:`close`).
            timeout: Request timeout in seconds (only used when ``client`` is
                created here).
            min_count: Minimum number of breach appearances required to treat a
                password as breached (HIBP returns a per-hash count). ``1`` (the
                default) rejects any password seen even once; raise it to only
                reject widely-seen passwords.
            add_padding: Send the ``Add-Padding: true`` header so the response
                size does not reveal how many real matches the queried prefix has
                (extra privacy). Padding rows carry a count of ``0`` and are
                filtered out by ``min_count``.
            user_agent: ``User-Agent`` sent with each request (HIBP asks for a
                descriptive one).
            base_url: Override the range endpoint (e.g. a self-hosted mirror).

        Raises:
            ValueError: If ``min_count`` is less than 1.
        """
        if min_count < 1:
            raise ValueError(f"min_count must be >= 1 (got {min_count})")
        self._client = client if client is not None else httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._min_count = min_count
        self._add_padding = add_padding
        self._user_agent = user_agent
        self._base_url = base_url if base_url.endswith("/") else base_url + "/"

    def is_breached(self, password: str) -> bool:
        """Return ``True`` if the password appears in the Pwned Passwords corpus.

        Fails open (returns ``False``) on any network or HTTP error so a
        breach-service outage never blocks a password change.
        """
        # SHA-1 is mandated by the HIBP protocol (the corpus is keyed by it); it
        # is not used here as a security primitive, hence usedforsecurity=False.
        digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]

        headers = {"User-Agent": self._user_agent}
        if self._add_padding:
            headers["Add-Padding"] = "true"

        try:
            response = self._client.get(f"{self._base_url}{prefix}", headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as err:
            logger.warning(
                "HIBP breach lookup failed; failing open (password allowed): %s",
                type(err).__name__,
                exc_info=err,
            )
            return False

        return self._suffix_is_breached(response.text, suffix)

    def _suffix_is_breached(self, body: str, suffix: str) -> bool:
        """Return whether ``suffix`` appears in an HIBP range response body."""
        for line in body.splitlines():
            candidate, _, count_text = line.partition(":")
            if candidate.strip().upper() != suffix:
                continue
            try:
                return int(count_text.strip()) >= self._min_count
            except ValueError:
                # A matching hash with an unparseable count is still a match.
                return True
        return False

    def close(self) -> None:
        """Close the underlying HTTP client if this instance created it."""
        if self._owns_client:
            self._client.close()


class BlocklistBreachChecker:
    """A ``PasswordBreachChecker`` backed by an in-memory blocklist.

    Suitable for a bundled "top N breached passwords" list or a custom deny-list.
    Performs no I/O.
    """

    def __init__(self, blocklist: Iterable[str], *, case_insensitive: bool = True) -> None:
        """Create the checker.

        Args:
            blocklist: The passwords to reject.
            case_insensitive: When ``True`` (default), comparison is
                case-insensitive (``casefold``).
        """
        self._case_insensitive = case_insensitive
        self._blocked = frozenset(self._normalize(entry) for entry in blocklist)

    def _normalize(self, password: str) -> str:
        return password.casefold() if self._case_insensitive else password

    def is_breached(self, password: str) -> bool:
        """Return ``True`` if the password is in the blocklist."""
        return self._normalize(password) in self._blocked
