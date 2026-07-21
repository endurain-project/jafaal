"""Tests for the SSRF guard and proxy-aware client IP extraction."""

import pytest
from starlette.requests import Request

import jafaal._core.network as network
import jafaal.exceptions as exc


def _request(client_host, headers=None):
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": raw_headers,
        "client": (client_host, 12345),
        "server": ("test", 80),
        "scheme": "http",
    }
    return Request(scope)


def test_reject_forbidden_scheme():
    with pytest.raises(exc.InvalidRequestError, match="scheme"):
        network.reject_private_url("ftp://example.com")
    with pytest.raises(exc.InvalidRequestError, match="scheme"):
        network.reject_private_url("file:///etc/passwd")


def test_reject_missing_hostname():
    with pytest.raises(exc.InvalidRequestError, match="hostname"):
        network.reject_private_url("http://")


def test_reject_loopback():
    with pytest.raises(exc.InvalidRequestError, match="non-public"):
        network.reject_private_url("http://127.0.0.1/token")


def test_reject_private_range():
    with pytest.raises(exc.InvalidRequestError, match="non-public"):
        network.reject_private_url("http://10.0.0.5")
    with pytest.raises(exc.InvalidRequestError, match="non-public"):
        network.reject_private_url("http://169.254.169.254/latest/meta-data")


def test_get_ip_address_honours_xff_when_peer_trusted():
    # Default trusted_proxies=("*",) trusts all peers, so XFF is honoured.
    req = _request("203.0.113.1", {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
    assert network.get_ip_address(req) == "1.2.3.4"


def test_get_ip_address_uses_real_ip_header():
    req = _request("203.0.113.1", {"X-Real-IP": "9.9.9.9"})
    assert network.get_ip_address(req) == "9.9.9.9"


def test_get_ip_address_falls_back_to_peer():
    req = _request("203.0.113.9")
    assert network.get_ip_address(req) == "203.0.113.9"


def test_get_ip_address_unknown_when_no_client():
    scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": [], "scheme": "http"}
    assert network.get_ip_address(Request(scope)) == "unknown"
