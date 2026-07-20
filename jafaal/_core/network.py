"""Network helpers: proxy-aware client IP extraction and SSRF guards.

Provides:

* :func:`get_ip_address` — extract the real client IP, honouring
  ``X-Forwarded-For`` / ``X-Real-IP`` only when the direct peer is a trusted
  proxy (``AuthSettings.trusted_proxies``).
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
from urllib.parse import urlparse

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
    for configured_entry in jafaal_settings.get_settings().trusted_proxies:
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

    Supports exact IPs and CIDR notation. The special value ``"*"`` (the
    default) trusts every peer. Also supports resolved hostnames (cached by
    :func:`refresh_trusted_proxy_hostnames`).

    Args:
        peer_ip: The direct TCP-connection IP of the caller.

    Returns:
        True if the peer is trusted, False otherwise.
    """
    trusted = jafaal_settings.get_settings().trusted_proxies
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


def get_ip_address(request: Request) -> str:
    """Extract client IP address from request, respecting ``trusted_proxies``.

    Proxy headers (``X-Forwarded-For``, ``X-Real-IP``) are only trusted when the
    direct TCP peer matches an entry in ``trusted_proxies``. This prevents
    attackers from spoofing their IP by injecting those headers on direct
    connections. When ``trusted_proxies`` is ``("*",)`` (the default) all peers
    are trusted.

    Args:
        request: Request object with headers and client info.

    Returns:
        Client IP address or "unknown" if indeterminate.
    """
    peer_ip = request.client.host if request.client else None

    if peer_ip and _is_trusted_peer(peer_ip):
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the leftmost IP: the original client
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

    return peer_ip or "unknown"


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
    """
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
    for entry in jafaal_settings.get_settings().ssrf_allowed_hosts:
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


def reject_private_url(url: str, *, purpose: str | None = None) -> None:
    """Refuse to dial URLs that resolve to private/internal hosts (SSRF guard).

    Enforces two checks before any outbound HTTP call:

    1. The scheme must be ``http`` or ``https``.
    2. Every address the hostname resolves to (both A and AAAA records) must be
       a public unicast address. A single private/loopback/link-local answer
       aborts the request (DNS-rebinding defence).

    Args:
        url: The fully-qualified URL the caller intends to fetch.
        purpose: Optional short tag identifying the outbound call (audit only).

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
        if _is_private_or_reserved(addr):
            if _is_ssrf_allowlisted(hostname, addr):
                # Audit trail: every allowlisted private destination is logged
                # so operators can review what the SSRF exception is used for.
                logger.info(
                    f"SSRF allowlist hit: dialing private address {ip_text} for "
                    f"host {hostname} (purpose={purpose or 'unspecified'})"
                )
                continue
            raise jafaal_exceptions.InvalidRequestError("URL resolves to a non-public address")
