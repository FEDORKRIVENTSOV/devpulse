"""Protection against SSRF (Server-Side Request Forgery).

Problem: users give us a URL and OUR server requests it. A malicious user could
enter http://127.0.0.1/admin, http://10.0.0.5/ or the cloud metadata address
http://169.254.169.254/ and make our server read internal resources.

Defence:
1. only http/https, no credentials inside the URL;
2. resolve the host name to IP addresses and allow only PUBLIC ones;
3. follow redirects manually and re-check EVERY hop (a public site may redirect
   to an internal address);
4. always use timeouts.

Known limitation (documented in README): between our DNS check and the actual
connection a hostile DNS server could change its answer (DNS rebinding).
Production-grade fix: connect to the already-validated IP or use an egress proxy.
"""
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests
from django.conf import settings

ALLOWED_SCHEMES = {"http", "https"}
REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 3
BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".lan")


class UnsafeURLError(ValueError):
    """The URL points somewhere we must not connect to."""


def _allow_private():
    return getattr(settings, "ALLOW_PRIVATE_URLS", False)


def _check_ip(ip_text):
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        raise UnsafeURLError("Invalid IP address")
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is really 127.0.0.1
    # is_global is False for loopback, private, link-local (cloud metadata),
    # carrier-grade NAT, reserved and multicast ranges.
    if not ip.is_global:
        raise UnsafeURLError("Address is not a public internet address")


def _parse(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError("Only http and https URLs are allowed")
    if not parsed.hostname:
        raise UnsafeURLError("URL has no host")
    if parsed.username or parsed.password:
        raise UnsafeURLError("Credentials inside URL are not allowed")
    try:
        parsed.port  # raises ValueError for a broken port
    except ValueError:
        raise UnsafeURLError("Invalid port")
    return parsed


def _is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate_url_syntax(url):
    """Cheap check without DNS. Used when a monitor is created or edited."""
    parsed = _parse(url)
    if _allow_private():
        return
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(BLOCKED_HOST_SUFFIXES):
        raise UnsafeURLError("Local host names are not allowed")
    if _is_ip_literal(host):
        _check_ip(host)


def validate_public_url(url):
    """Full check including DNS. Used right before every real request."""
    parsed = _parse(url)
    if _allow_private():
        return
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(BLOCKED_HOST_SUFFIXES):
        raise UnsafeURLError("Local host names are not allowed")
    if _is_ip_literal(host):
        _check_ip(host)
        return
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UnsafeURLError("Host name cannot be resolved")
    if not infos:
        raise UnsafeURLError("Host name cannot be resolved")
    for info in infos:
        # EVERY resolved address must be public, not just the first one.
        _check_ip(info[4][0])


def safe_get(url, timeout=10):
    """GET with SSRF protection. Redirects are followed manually and re-validated."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        validate_public_url(current)
        response = requests.get(
            current,
            timeout=timeout,
            allow_redirects=False,
            stream=True,  # do not download the body, we only need the status
            headers={"User-Agent": "DevPulse/1.0 (uptime monitor)"},
        )
        if response.status_code in REDIRECT_CODES:
            location = response.headers.get("Location")
            response.close()
            if not location:
                return response
            current = urljoin(current, location)
            continue
        response.close()
        return response
    raise requests.exceptions.TooManyRedirects("Too many redirects")
