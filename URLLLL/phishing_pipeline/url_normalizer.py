"""
url_normalizer.py — Step 2: Normalize extracted URLs.

Normalization steps:
  1. Whitespace cleanup
  2. Defanged URL re-fanging (hxxp → http, [.] → .)
  3. URL-decode percent-encoded characters
  4. Lowercase scheme and host
  5. Punycode / IDN normalization
  6. Remove default ports (:80 for HTTP, :443 for HTTPS)
  7. Remove trailing dots from hostname
  8. Remove tracking / junk query parameters
  9. Strip URL fragment (#…)
  10. Collapse duplicate slashes in the path
  11. Reconstruct with urllib.parse.urlunparse
"""

import re
from urllib.parse import (
    urlparse, urlunparse, unquote, urlencode, parse_qsl,
)
from .config import JUNK_PARAM_PREFIXES
from .logger import get_logger

log = get_logger("url_normalizer")

# Matches runs of two or more forward slashes NOT at the start of the path
_DOUBLE_SLASH: re.Pattern = re.compile(r"(?<!:)//+")

# Default ports per scheme
_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _strip_junk_params(query: str) -> str:
    """
    Remove known tracking / junk query parameters from a query string.
    Keeps parameters whose names do not match any junk prefix.
    """
    params = parse_qsl(query, keep_blank_values=True)
    kept = [
        (k, v)
        for k, v in params
        if not any(k.lower().startswith(p) for p in JUNK_PARAM_PREFIXES)
    ]
    return urlencode(kept)


def _refang(url: str) -> str:
    """Convert defanged security notation back to real URLs."""
    url = url.replace("hxxp", "http")
    url = url.replace("[.]", ".")
    url = url.replace("[:]", ":")
    url = url.replace("[/]", "/")
    return url


def _normalize_punycode(netloc: str) -> str:
    """
    Normalize IDN/Punycode hostnames.
    If the hostname is already Punycode (xn--...), decode it for display.
    If it contains Unicode, encode to Punycode for consistent comparison.
    Returns the ASCII Punycode form for consistency.
    """
    try:
        # Split off port if present
        if ":" in netloc:
            host, port = netloc.rsplit(":", 1)
        else:
            host, port = netloc, None

        # Try to encode to IDNA (handles Unicode → Punycode)
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            pass

        return f"{host}:{port}" if port else host
    except Exception:
        return netloc


def normalize_url(url: str) -> str:
    """
    Normalize a URL through decoding, lowercasing, junk-param removal,
    fragment stripping, Punycode normalization, and path canonicalization.

    Args:
        url: Raw URL string.

    Returns:
        Cleaned, normalized URL string. Returns the original url on error.
    """
    try:
        # Step 1 — whitespace cleanup
        url = url.strip()

        # Step 2 — defang
        url = _refang(url)

        # Step 3 — percent-decode
        url = unquote(url)

        parsed = urlparse(url)

        # Step 4 — lowercase scheme + host
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Step 5 — Punycode / IDN normalization
        netloc = _normalize_punycode(netloc)

        # Step 6 — remove default ports
        if ":" in netloc:
            host_part, port_part = netloc.rsplit(":", 1)
            if _DEFAULT_PORTS.get(scheme) == port_part:
                netloc = host_part

        # Step 7 — remove trailing dots from hostname
        if netloc.endswith("."):
            netloc = netloc.rstrip(".")

        # Step 8 — strip junk query params
        clean_query = _strip_junk_params(parsed.query)

        # Step 9 — drop fragment
        fragment = ""

        # Step 10 — collapse duplicate slashes in path
        path = _DOUBLE_SLASH.sub("/", parsed.path)

        normalized = urlunparse((scheme, netloc, path, parsed.params, clean_query, fragment))
        log.debug("Normalized: %s  →  %s", url, normalized)
        return normalized

    except Exception as exc:
        log.warning("normalize_url failed for '%s': %s", url, exc)
        return url
