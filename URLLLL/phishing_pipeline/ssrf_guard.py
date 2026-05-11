"""
ssrf_guard.py — Prevent Server-Side Request Forgery (SSRF).

Before the pipeline navigates to any URL, this module verifies that the
resolved IP address is not in a private, loopback, or link-local range.
"""

import ipaddress
import socket
from urllib.parse import urlparse

from .logger import get_logger

log = get_logger("ssrf_guard")

# Ranges that MUST be blocked
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),         # Private (Class A)
    ipaddress.ip_network("172.16.0.0/12"),      # Private (Class B)
    ipaddress.ip_network("192.168.0.0/16"),     # Private (Class C)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]


def is_safe_url(url: str) -> bool:
    """
    Return True if the URL's host resolves to a public (non-internal) IP.
    Returns False and logs a warning if the URL targets a private/internal host.
    """
    try:
        # Ensure URL has a scheme so urlparse can extract the hostname
        _url = url.strip()
        if not _url.startswith(("http://", "https://")):
            _url = "https://" + _url

        host = urlparse(_url).hostname
        if not host:
            log.warning("SSRF guard: no hostname in URL '%s'", url)
            return False

        # Resolve hostname to IP(s)
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            for net in _BLOCKED_NETWORKS:
                if ip in net:
                    log.warning(
                        "SSRF guard BLOCKED: '%s' resolves to internal IP %s (%s)",
                        url, ip_str, net,
                    )
                    return False

        return True

    except socket.gaierror:
        # DNS resolution failed — host doesn't exist, let downstream handle it
        log.debug("SSRF guard: DNS resolution failed for '%s'", url)
        return True
    except Exception as exc:
        log.warning("SSRF guard error for '%s': %s", url, exc)
        return False
