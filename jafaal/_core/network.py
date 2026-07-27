"""Network helpers: proxy-aware client IP extraction and SSRF guards.

Provides:

* :func:`get_ip_address` — extract the real client IP, honouring
  ``X-Forwarded-For`` / ``X-Real-IP`` only when the direct peer is a trusted
  proxy (``AuthSettings.trusted_proxies``), and resolving the forwarded chain
  right-to-left so a client cannot spoof its own source address.
* :func:`reject_private_url` — refuse to dial URLs that resolve to
  private/internal addresses (SSRF guard), with an
  ``AuthSettings.ssrf_allowed_hosts`` escape hatch.
* :func:`refresh_trusted_proxy_hostnames` — resolve hostname entries in
  ``trusted_proxies`` to IPs; the host may call this at startup (and
  periodically). Unlike the original Endurain implementation the resolution
  cache lives in this module, not on the (immutable) settings object.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import Request

import jafaal.exceptions as jafaal_exceptions
import jafaal.settings as jafaal_settings

logger = logging.getLogger(__name__)

_TRUSTED_PROXY_HOSTNAME_REFRESH_SECONDS = 60.0
_trusted_proxy_hostname_refresh_lock = threading.Lock()
_trusted_proxy_hostname_last_refresh = float("-inf")
# Trusted-proxy hostnames resolved to IPs (populated by
# refresh_trusted_proxy_hostnames). Lives here rather than on the frozen
# settings object.
_resolved_trusted_proxy_ips: set[str] = set()


def _looks_like_ip(value: str) -> bool:
    """Best-effort check that ``value`` is an IP literal.

    Args:
        value: Candidate IP literal or hostname.

    Returns:
        True when ``value`` is an IPv4/IPv6 literal.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to a de-duplicated list of IP addresses.

    Args:
        hostname: The hostname to resolve.

    Returns:
        List of resolved IP addresses, or an empty list on failure
        (a warning is logged).
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = [str(info[4][0]) for info in infos]
        seen: set[str] = set()
        unique_ips = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
        return unique_ips
    except socket.gaierror as err:
        logger.warning(f"Failed to resolve trusted_proxies hostname '{hostname}': {err}")
        return []


def _trusted_proxy_hostname_entries() -> list[str]:
    """Return the configured ``trusted_proxies`` entries needing DNS resolution."""
    hostnames: list[str] = []
    for configured_entry in jafaal_settings.get_settings().network.trusted_proxies:
        entry = configured_entry.strip()
        if not entry:
            continue
        if entry == "*" or "/" in entry or _looks_like_ip(entry):
            continue
        hostnames.append(entry)
    return hostnames


def _trusted_proxy_hostname_cache_is_fresh(now: float) -> bool:
    """Return True when the refresh throttle window has not elapsed."""
    cache_age = now - _trusted_proxy_hostname_last_refresh
    return cache_age < _TRUSTED_PROXY_HOSTNAME_REFRESH_SECONDS


def refresh_trusted_proxy_hostnames(
    *,
    force: bool = False,
    log_success: bool = False,
) -> dict[str, list[str]]:
    """Refresh ``trusted_proxies`` hostname resolutions.

    Args:
        force: Refresh even when the cache is still fresh.
        log_success: Log successful hostname resolutions.

    Returns:
        Mapping of hostnames to resolved IP addresses.
    """
    global _trusted_proxy_hostname_last_refresh, _resolved_trusted_proxy_ips

    hostnames = _trusted_proxy_hostname_entries()
    if not hostnames:
        _resolved_trusted_proxy_ips = set()
        return {}

    now = time.monotonic()
    if not force and _trusted_proxy_hostname_cache_is_fresh(now):
        return {}

    with _trusted_proxy_hostname_refresh_lock:
        now = time.monotonic()
        if not force and _trusted_proxy_hostname_cache_is_fresh(now):
            return {}

        resolved_map: dict[str, list[str]] = {}
        all_resolved_ips: set[str] = set()
        for hostname in hostnames:
            ips = _resolve_hostname(hostname)
            if not ips:
                continue

            resolved_map[hostname] = ips
            all_resolved_ips.update(ips)
            if log_success:
                logger.info(f"Resolved trusted_proxies hostname '{hostname}' to {ips}")

        _resolved_trusted_proxy_ips = all_resolved_ips
        _trusted_proxy_hostname_last_refresh = now

    return resolved_map


def _is_trusted_peer(peer_ip: str) -> bool:
    """Check whether ``peer_ip`` is in the ``trusted_proxies`` allow-list.

    Supports exact IPs and CIDR notation. The special value ``"*"`` trusts
    every peer — but it is **not** the default; ``trusted_proxies`` defaults to
    empty, so only the direct TCP peer is trusted. Also supports resolved
    hostnames (cached by :func:`refresh_trusted_proxy_hostnames`).

    Args:
        peer_ip: The direct TCP-connection IP of the caller.

    Returns:
        True if the peer is trusted, False otherwise.
    """
    trusted = jafaal_settings.get_settings().network.trusted_proxies
    if list(trusted) == ["*"]:
        return True
    try:
        addr = ipaddress.ip_address(peer_ip)
        for entry in trusted:
            entry = entry.strip()
            if not entry:
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if addr in network:
                    return True
            except ValueError:
                # Entry is not a valid network — compare as plain string
                if peer_ip == entry:
                    return True
    except ValueError:
        pass

    hostnames = _trusted_proxy_hostname_entries()
    if not hostnames:
        return False

    return peer_ip in _resolved_trusted_proxy_ips


def _normalize_forwarded_hop(hop: str) -> str | None:
    """Return the bare IP literal in an ``X-Forwarded-For`` hop, or ``None``.

    Hops are written in several shapes in the wild: a bare address, an address
    with a port (``1.2.3.4:5678``), a bracketed IPv6 address with or without a
    port (``[2001:db8::1]:8080``), or the RFC 7239 placeholder ``unknown``.
    Anything that does not reduce to a valid IP literal returns ``None`` so the
    caller skips it rather than propagating a client-controlled string into a
    lockout key or an audit record.

    Args:
        hop: One comma-separated ``X-Forwarded-For`` element.

    Returns:
        The normalised IP literal, or ``None`` when the hop is unusable.
    """
    candidate = hop.strip()
    if not candidate:
        return None
    if candidate.startswith("["):
        # [2001:db8::1] or [2001:db8::1]:8080
        closing = candidate.find("]")
        if closing == -1:
            return None
        candidate = candidate[1:closing]
    elif candidate.count(":") == 1:
        # Exactly one colon means IPv4 + port; a bare IPv6 address has several.
        candidate = candidate.split(":", 1)[0]
    return candidate if _looks_like_ip(candidate) else None


def _client_ip_from_forwarded_for(forwarded_for: str) -> str | None:
    """Return the client IP from an ``X-Forwarded-For`` chain, or ``None``.

    Walks the chain **right to left**, discarding hops that are themselves
    trusted infrastructure (``trusted_proxies``), and returns the first hop that
    is not. That hop is the closest address the infrastructure actually
    observed, and therefore the last one an attacker could not have written.

    Taking the *leftmost* hop instead — the intuitive "original client" — is
    unsafe: a proxy configured the usual way (nginx's
    ``proxy_add_x_forwarded_for``) **appends** the peer it saw to whatever the
    client sent, so a request carrying ``X-Forwarded-For: 1.2.3.4`` arrives as
    ``1.2.3.4, <real client>``. The leftmost element is then entirely
    attacker-controlled, which would let a caller evade the per-IP login lockout
    and the rate limiter, and forge the source IP recorded in audit records, just
    by varying a header.

    When every hop is trusted infrastructure (or ``trusted_proxies`` is
    ``("*",)``, which trusts all of them) there is no untrusted hop to find, so
    the leftmost is returned: that configuration asserts that a trusted proxy
    always overwrites the header.

    Args:
        forwarded_for: The raw ``X-Forwarded-For`` header value.

    Returns:
        The resolved client IP, or ``None`` when no hop is usable.
    """
    hops = [normalized for raw in forwarded_for.split(",") if (normalized := _normalize_forwarded_hop(raw))]
    if not hops:
        return None
    for hop in reversed(hops):
        if not _is_trusted_peer(hop):
            return hop
    return hops[0]


def get_ip_address(request: Request) -> str:
    """Extract client IP address from request, respecting ``trusted_proxies``.

    Proxy headers (``X-Forwarded-For``, ``X-Real-IP``) are only trusted when the
    direct TCP peer matches an entry in ``trusted_proxies``. This prevents
    attackers from spoofing their IP by injecting those headers on direct
    connections. ``trusted_proxies`` defaults to empty — only the direct peer is
    trusted; set it to ``("*",)`` to trust every peer.

    ``X-Forwarded-For`` is resolved by walking the chain right to left and
    returning the first hop that is *not* trusted infrastructure (see
    :func:`_client_ip_from_forwarded_for`), so a client cannot choose its own
    apparent source IP by prepending one. Every hop your infrastructure adds —
    not just the direct peer — must therefore appear in ``trusted_proxies`` (for
    example both the CDN egress ranges and the reverse proxy) for the true client
    address to be recovered.

    Args:
        request: Request object with headers and client info.

    Returns:
        Client IP address or "unknown" if indeterminate.
    """
    peer_ip = request.client.host if request.client else None

    if peer_ip and _is_trusted_peer(peer_ip):
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = _client_ip_from_forwarded_for(forwarded_for)
            if client_ip:
                return client_ip

        # Single-value header written by the proxy itself; still validated so a
        # malformed value cannot reach a lockout key.
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            normalized_real_ip = _normalize_forwarded_hop(real_ip)
            if normalized_real_ip:
                return normalized_real_ip

    return peer_ip or "unknown"


# ``Sec-Fetch-Site`` values that denote a request the browser considers on-site.
# ``none`` covers a user-initiated navigation (typed URL, bookmark).
_ON_SITE_FETCH_SITES: frozenset[str] = frozenset({"same-origin", "none"})


def _normalize_origin(origin: str) -> str:
    """Normalise an origin for comparison (case-folded, no trailing slash)."""
    return origin.strip().rstrip("/").lower()


def is_off_site_request(request: Request, allowed_origins: tuple[str, ...]) -> bool:
    """Return ``True`` when the browser marks this request as coming from off-site.

    A CSRF defence for cookie-authenticated endpoints. Both signals it reads are
    **forbidden header names**: page script cannot set, alter, or strip
    ``Origin`` or ``Sec-Fetch-Site``, so a cross-site attacker cannot suppress
    them the way it can simply omit a custom ``X-CSRF-Token`` header.

    Order of evidence:

    1. ``Origin`` — browsers send it on every ``POST``. When ``allowed_origins``
       is configured, an origin outside it is off-site. This is also what makes a
       split-origin deployment work (frontend and API on different hosts): list
       the frontend origin in ``csrf_trusted_origins``.
    2. ``Sec-Fetch-Site`` — the browser's own classification, consulted when the
       ``Origin`` comparison could not be made. Anything other than
       ``same-origin`` / ``none`` (i.e. ``cross-site``, or ``same-site`` as a
       sibling subdomain would send) is off-site.

    With both headers absent the request is treated as on-site: that is a
    non-browser client, which carries no ambient cookie and so cannot be the
    victim of a CSRF attack in the first place.

    Args:
        request: The incoming HTTP request.
        allowed_origins: Origins permitted to make the call (scheme + host +
            port). Empty disables the ``Origin`` comparison.

    Returns:
        True when the request demonstrably originates off-site.
    """
    origin = request.headers.get("Origin")
    if origin and allowed_origins:
        return _normalize_origin(origin) not in {_normalize_origin(allowed) for allowed in allowed_origins}

    fetch_site = request.headers.get("Sec-Fetch-Site")
    if fetch_site:
        return fetch_site.strip().lower() not in _ON_SITE_FETCH_SITES

    return False


def reject_off_site_request(request: Request, *, operation: str) -> None:
    """Refuse a browser request that demonstrably originates off-site.

    The single enforcement point for :func:`is_off_site_request`, used by every
    endpoint that reads **or writes** the refresh cookie: ``/auth/login``,
    ``/auth/mfa/verify``, ``/auth/refresh``, and the SSO/PKCE token exchange.

    Applying it on the *write* side matters as much as on the read side. A
    cross-site attacker who can make the victim's browser complete a login
    against attacker-controlled credentials plants an ``HttpOnly`` session the
    victim then unknowingly uses (login CSRF / session fixation). JAFAAL's
    mandatory ``X-Client-Type`` header already forces a CORS preflight and so
    blocks the simple form-POST version of that attack, but relying on it makes
    a header's *ergonomics* load-bearing for a *security* property — one
    "make X-Client-Type optional" change away from silently regressing.

    Both signals read are forbidden header names, so page script cannot forge or
    strip them.

    Args:
        request: The incoming HTTP request.
        operation: Human-readable name of the flow, used in the log line and the
            error detail (e.g. ``"Login"``).

    Raises:
        AuthorizationError: 403 when the request is off-site.
    """
    trusted = jafaal_settings.get_settings().resolved_csrf_trusted_origins
    if not is_off_site_request(request, trusted):
        return
    logger.warning(f"Rejected off-site {operation.lower()} request")
    raise jafaal_exceptions.AuthorizationError(
        f"{operation} requests must originate from a trusted origin",
        headers={"WWW-Authenticate": "Bearer"},
    )


# Schemes JAFAAL is willing to dial. Anything else (file://, gopher://, ftp://,
# data://, javascript:) is rejected outright.
_ALLOWED_OUTBOUND_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def _is_private_or_reserved(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return True if ``addr`` belongs to any non-routable range.

    Combines every "do not dial" predicate ``ipaddress`` exposes: private,
    loopback, link-local, multicast, unspecified, and reserved. Any of these
    would let an attacker pivot to internal infrastructure or cloud metadata.

    IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are decomposed to the
    embedded IPv4 address before classifying: CPython only started applying the
    ``is_private`` / ``is_global`` predicates through the mapped address in
    3.12.4, so on 3.12.0-3.12.3 a literal such as ``::ffff:169.254.169.254``
    would otherwise be treated as a public IPv6 address and slip past the
    deny-list (while the OS still routes it to the embedded IPv4 target, e.g.
    the cloud metadata endpoint). Decomposing here makes the guard correct on
    every supported patch release.
    """
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def _load_ssrf_allowlist() -> tuple[
    frozenset[str],
    tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
]:
    """Split ``ssrf_allowed_hosts`` into hostnames and IP networks."""
    hosts: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in jafaal_settings.get_settings().network.ssrf_allowed_hosts:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            hosts.add(entry.lower())
    return frozenset(hosts), tuple(networks)


def _is_ssrf_allowlisted(
    hostname: str,
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return True if ``hostname`` or ``addr`` is allowlisted.

    Consulted only when the resolved address would otherwise be rejected by
    :func:`_is_private_or_reserved`.
    """
    hosts, networks = _load_ssrf_allowlist()
    if hostname.lower() in hosts:
        return True
    return any(addr in network for network in networks)


def _reject_if_private(
    hostname: str,
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    purpose: str | None,
) -> None:
    """Raise unless ``addr`` is public (or an allow-listed private address).

    The single place the public-address policy — and the allow-list audit log —
    is applied, shared by :func:`reject_private_url` (URL pre-flight check) and
    :func:`_resolve_and_validate_host` (the pinned-IP transport).

    Raises:
        InvalidRequestError: If ``addr`` is a private/reserved address that is
            not covered by ``ssrf_allowed_hosts``.
    """
    if not _is_private_or_reserved(addr):
        return
    if _is_ssrf_allowlisted(hostname, addr):
        # Audit trail: every allow-listed private destination is logged so
        # operators can review what the SSRF exception is used for.
        logger.info(
            f"SSRF allowlist hit: dialing private address {addr} for "
            f"host {hostname} (purpose={purpose or 'unspecified'})"
        )
        return
    raise jafaal_exceptions.InvalidRequestError("URL resolves to a non-public address")


# Shared by the HTTPS-transport guards so operators get a single, actionable
# hint (including the escape hatch for local/self-host setups).
_HTTPS_REQUIRED_MESSAGE = (
    "Identity provider endpoint must use HTTPS. Set idp_require_https=False to "
    "allow http:// for local or self-hosted development."
)


def _require_https_scheme(scheme: str) -> None:
    """Raise unless ``scheme`` is ``https`` (cleartext-transport guard)."""
    if scheme.lower() != "https":
        raise jafaal_exceptions.InvalidRequestError(_HTTPS_REQUIRED_MESSAGE)


def require_https_url(url: str) -> None:
    """Reject a URL whose scheme is not ``https``.

    Enforces encrypted transport for an identity-provider endpoint without the
    DNS resolution / private-address checks of :func:`reject_private_url`, so it
    is safe for the authorization endpoint the *browser* dials, which may
    legitimately be a private or self-hosted host. Used by the SSO service when
    ``idp_require_https`` is enabled.

    Raises:
        InvalidRequestError: If ``url`` is malformed or does not use ``https``.
    """
    try:
        parsed = urlparse(url)
    except ValueError as err:
        raise jafaal_exceptions.InvalidRequestError("Malformed URL") from err
    _require_https_scheme(parsed.scheme)


def reject_private_url(url: str, *, purpose: str | None = None, require_https: bool = False) -> None:
    """Refuse to dial URLs that resolve to private/internal hosts (SSRF guard).

    Enforces two checks before any outbound HTTP call:

    1. The scheme must be ``http`` or ``https`` (or ``https`` only when
       ``require_https`` is set).
    2. Every address the hostname resolves to (both A and AAAA records) must be
       a public unicast address. A single private/loopback/link-local answer
       aborts the request (DNS-rebinding defence).

    Args:
        url: The fully-qualified URL the caller intends to fetch.
        purpose: Optional short tag identifying the outbound call (audit only).
        require_https: When True, additionally refuse any scheme other than
            ``https`` (keeps credential-bearing IdP calls off cleartext
            transports when ``idp_require_https`` is enabled).

    Raises:
        InvalidRequestError: 400 if the URL is malformed, uses a forbidden
            scheme, has no hostname, or resolves to any non-public address not
            covered by ``ssrf_allowed_hosts``.
    """
    try:
        parsed = urlparse(url)
    except ValueError as err:
        raise jafaal_exceptions.InvalidRequestError("Malformed URL") from err

    if parsed.scheme.lower() not in _ALLOWED_OUTBOUND_SCHEMES:
        raise jafaal_exceptions.InvalidRequestError("URL scheme is not permitted")
    if require_https:
        _require_https_scheme(parsed.scheme)

    hostname = parsed.hostname
    if not hostname:
        raise jafaal_exceptions.InvalidRequestError("URL has no hostname")

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as err:
        raise jafaal_exceptions.InvalidRequestError("URL hostname could not be resolved") from err

    for info in infos:
        sockaddr = info[4]
        ip_text = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_text)
        except ValueError as err:
            # Defensive: if the resolver hands back something unparseable,
            # treat as unsafe.
            raise jafaal_exceptions.InvalidRequestError("URL resolves to an unparseable address") from err
        _reject_if_private(hostname, addr, purpose=purpose)


async def ssrf_request_hook(request: httpx.Request) -> None:
    """``httpx`` request event hook that applies the SSRF guard to every request.

    Attach this to an ``httpx.AsyncClient`` (``event_hooks={"request": [...]}``)
    so :func:`reject_private_url` runs not just on the initial URL but on **every
    request the client makes, including each redirect hop**. ``httpx`` invokes
    request hooks once per hop inside its redirect loop, so this closes the
    redirect-based SSRF bypass that ``follow_redirects=True`` would otherwise
    open: a public endpoint answering ``302 Location: http://169.254.169.254/``
    (cloud metadata) or any other private/internal target is rejected before the
    connection is made.

    Raises:
        InvalidRequestError: If the request URL (or a redirect target) uses a
            forbidden scheme or resolves to a non-public address not covered by
            ``ssrf_allowed_hosts``.
    """
    reject_private_url(str(request.url), purpose="outbound_http")


def _resolve_and_validate_host(host: str, *, purpose: str | None = None) -> str:
    """Resolve ``host`` to a validated public IP address and return it.

    Applies the same public-address policy as :func:`reject_private_url` to every
    resolved address (rejecting if any is private/reserved and not allow-listed),
    then returns one validated IP for the connection to be pinned to. An IP
    literal is validated in place and returned unchanged.

    This is the resolution the pinned-IP transport connects to, so the address
    that is validated is exactly the address dialed — closing the DNS-rebinding
    TOCTOU that a separate check-then-connect leaves open.

    Args:
        host: The URL host — a hostname or an IP literal.
        purpose: Optional short tag for the allow-list audit log.

    Returns:
        A validated IP address string to connect to.

    Raises:
        InvalidRequestError: If ``host`` cannot be resolved, or resolves to (or
            is) a non-public address not covered by ``ssrf_allowed_hosts``.
    """
    if _looks_like_ip(host):
        _reject_if_private(host, ipaddress.ip_address(host), purpose=purpose)
        return host

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as err:
        raise jafaal_exceptions.InvalidRequestError("URL hostname could not be resolved") from err

    pinned: str | None = None
    for info in infos:
        ip_text = info[4][0]
        try:
            addr = ipaddress.ip_address(ip_text)
        except ValueError as err:
            raise jafaal_exceptions.InvalidRequestError("URL resolves to an unparseable address") from err
        _reject_if_private(host, addr, purpose=purpose)
        if pinned is None:
            pinned = str(addr)
    if pinned is None:
        raise jafaal_exceptions.InvalidRequestError("URL hostname could not be resolved")
    return pinned


def _pin_request_to_validated_ip(request: httpx.Request) -> None:
    """Rewrite ``request`` to connect to a validated IP (the SSRF connection pin).

    Validates the scheme and resolves the target host through
    :func:`_resolve_and_validate_host`, then — for a hostname target — rewrites
    the request URL to the validated IP while setting ``sni_hostname`` and
    preserving the ``Host`` header, so TLS (SNI + certificate verification) and
    virtual-host routing still use the original hostname. An IP-literal target is
    validated in place and left unchanged.

    Raises:
        InvalidRequestError: On a forbidden scheme, a missing host, or a
            non-public resolved address.
    """
    url = request.url
    if url.scheme.lower() not in _ALLOWED_OUTBOUND_SCHEMES:
        raise jafaal_exceptions.InvalidRequestError("URL scheme is not permitted")
    host = url.host
    if not host:
        raise jafaal_exceptions.InvalidRequestError("URL has no hostname")

    pinned_ip = _resolve_and_validate_host(host, purpose="outbound_http")
    if pinned_ip == host:
        # Already an IP literal (validated in place) — nothing to rewrite.
        return

    # Preserve the Host header (httpx set it from the original hostname when the
    # request was built) and the TLS SNI/verification hostname, then point the
    # connection at the pre-validated IP literal so httpx performs no second,
    # rebindable DNS lookup.
    original_host_header = request.headers.get("Host") or url.netloc.decode("ascii")
    request.extensions = {**request.extensions, "sni_hostname": host}
    request.url = url.copy_with(host=pinned_ip)
    request.headers["Host"] = original_host_header


class SsrfGuardAsyncTransport(httpx.AsyncBaseTransport):
    """An ``httpx`` async transport that pins connections to a validated IP.

    Wraps an inner transport (an :class:`httpx.AsyncHTTPTransport` in
    production). Before delegating each request — including every redirect hop,
    which httpx routes through the transport afresh — it resolves the target
    host, applies the SSRF public-address policy to **all** resolved addresses,
    and (for a hostname) rewrites the request to dial one validated IP while
    keeping the TLS SNI/verification hostname and ``Host`` header. Because httpx
    then connects to that IP literal without a second DNS lookup, a DNS-rebinding
    answer cannot swap in a private address between the check and the connection
    — closing the TOCTOU that :func:`reject_private_url` alone leaves open.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        _pin_request_to_validated_ip(request)
        return await self._inner.handle_async_request(request)

    async def __aenter__(self) -> SsrfGuardAsyncTransport:
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._inner.__aexit__(*exc_info)  # type: ignore[arg-type]

    async def aclose(self) -> None:
        await self._inner.aclose()


def build_ssrf_guard_transport(**http_transport_kwargs: Any) -> httpx.AsyncBaseTransport:
    """Build an SSRF-guarding async transport that pins connections to validated IPs.

    Wire it into an ``httpx.AsyncClient`` (or an authlib client that subclasses
    it) via ``transport=build_ssrf_guard_transport(...)``. Extra keyword
    arguments are forwarded to the inner :class:`httpx.AsyncHTTPTransport`
    (e.g. ``limits``).
    """
    return SsrfGuardAsyncTransport(httpx.AsyncHTTPTransport(**http_transport_kwargs))
