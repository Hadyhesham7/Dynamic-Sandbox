"""
url_extractor.py — Step 1: Extract all URLs from raw email text.

Handles multiple URL sources:
  1. Full URLs with scheme:    http://example.com/path
  2. Bare URLs without scheme: example.com/path  (auto-prepends https://)
  3. HTML content:             <a href="..."> tags, form actions
  4. Defanged URLs:            hxxp://evil[.]com → http://evil.com
  5. Base64-encoded URLs:      aHR0cDovL... → http://...

Bare URL detection uses a heuristic: the string must start with a known
domain-like pattern (word chars, optional subdomain dots) and contain at
least one dot, followed optionally by a path / query string.
"""

import re
import base64
from .logger import get_logger

log = get_logger("url_extractor")

# ── Pattern 1: Full URLs with http / https scheme ─────────────────────────────
_FULL_URL_RE: re.Pattern = re.compile(
    r"https?://"
    r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)

# ── Pattern 2: Bare URLs — no scheme, but look like domain[/path][?query] ────
_BARE_URL_RE: re.Pattern = re.compile(
    r"(?<![/@\w])"              # not preceded by @, / or alphanumeric (avoid emails)
    r"(?:www\.)?"               # optional www.
    r"[A-Za-z0-9]"             # starts with alphanumeric
    r"[A-Za-z0-9\-]*"          # remainder of the first label
    r"(?:\.[A-Za-z0-9\-]+)+"   # at least one more dot-separated label (forces TLD)
    r"(?::[0-9]+)?"             # optional port
    r"(?:/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?" # optional path/query
    r"""(?=[,\s\"'<>\)\]|]|$)""",  # must be followed by whitespace/punctuation or EOL
    re.IGNORECASE,
)

# ── Pattern 3: Defanged URLs (hxxp, [.], etc.) ──────────────────────────────
_DEFANG_RE = re.compile(
    r"hxxps?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%\[\]]+",
    re.IGNORECASE,
)

# ── Pattern 4: HTML href/src attributes ──────────────────────────────────────
_HTML_ATTR_RE = re.compile(
    r"""(?:href|src|action|data)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# ── Pattern 5: Base64 encoded URLs ───────────────────────────────────────────
_BASE64_CANDIDATE_RE = re.compile(
    r"[A-Za-z0-9+/]{20,}={0,2}",
)

# Known single-word TLDs to validate bare URLs (avoids matching plain words)
_VALID_TLDS: frozenset[str] = frozenset([
    "com", "net", "org", "edu", "gov", "io", "co", "uk", "de", "fr",
    "ru", "cn", "jp", "au", "ca", "it", "es", "br", "in", "nl", "pl",
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "cc", "info",
    "biz", "tv", "me", "us", "eu", "online", "site", "web", "store",
    "shop", "app", "dev", "tech", "news", "media", "live", "click",
    "link", "win", "racing", "stream", "review", "loan", "work",
    "php", "html", "htm",
])

_STRIP_TRAILING: str = """.,;:!?)>"'"""


def _has_valid_tld(url_fragment: str) -> bool:
    """
    Return True if the first component of the URL fragment (the hostname part)
    ends with a known TLD, or if the fragment contains a path (/ present after
    the first dot), which is a strong signal of a URL.
    """
    host = url_fragment.split("/")[0].split("?")[0].split("#")[0]
    if ":" in host:
        host = host.split(":")[0]
    parts = host.rsplit(".", 1)
    if len(parts) < 2:
        return False
    tld = parts[-1].lower()
    return tld in _VALID_TLDS or "/" in url_fragment


def _refang_url(url: str) -> str:
    """Convert defanged URL back to real URL."""
    url = url.replace("hxxp", "http")
    url = url.replace("[.]", ".")
    url = url.replace("[:]", ":")
    url = url.replace("[/]", "/")
    return url


def _try_decode_base64_url(candidate: str) -> str | None:
    """Try to decode a base64 string and return it if it looks like a URL."""
    try:
        decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
        if decoded.startswith(("http://", "https://")):
            return decoded.strip()
    except Exception:
        pass
    return None


def extract_urls(text: str) -> list[str]:
    """
    Extract all HTTP/HTTPS and bare URLs from the given text.

    Supports:
    - Full URLs (with scheme) returned as-is
    - Bare URLs (without scheme) have 'https://' prepended
    - HTML <a href="...">, <form action="...">, <img src="..."> tags
    - Defanged URLs (hxxp://evil[.]com)
    - Base64-encoded URLs

    Args:
        text: Raw email body, HTML content, CSV cell, or any string.

    Returns:
        Ordered list of URL strings (duplicates removed).
    """
    if not text:
        log.warning("extract_urls received empty text.")
        return []

    collected: list[str] = []
    seen: set[str] = set()

    def _add(u: str) -> None:
        u = u.rstrip(_STRIP_TRAILING)
        if u and u not in seen:
            seen.add(u)
            collected.append(u)

    # ── Pass 1: Full URLs with scheme ─────────────────────────────────────────
    full_matches: list[tuple[int, int]] = []
    for m in _FULL_URL_RE.finditer(text):
        _add(m.group())
        full_matches.append((m.start(), m.end()))

    # ── Pass 2: HTML href/src/action attributes ──────────────────────────────
    for m in _HTML_ATTR_RE.finditer(text):
        attr_url = m.group(1).strip()
        if attr_url.startswith(("http://", "https://")):
            _add(attr_url)
        elif attr_url.startswith("//"):
            _add("https:" + attr_url)
        elif attr_url.startswith("/") or attr_url.startswith("#") or attr_url.startswith("mailto:"):
            continue  # relative or fragment or email — skip
        elif "." in attr_url and " " not in attr_url:
            _add("https://" + attr_url)

    # ── Pass 3: Defanged URLs ────────────────────────────────────────────────
    for m in _DEFANG_RE.finditer(text):
        refanged = _refang_url(m.group())
        _add(refanged)

    # ── Pass 4: Base64-encoded URLs ──────────────────────────────────────────
    for m in _BASE64_CANDIDATE_RE.finditer(text):
        decoded = _try_decode_base64_url(m.group())
        if decoded:
            _add(decoded)
            log.info("Decoded base64 URL: %s", decoded)

    # ── Pass 5: Bare URLs (skip spans already captured) ──────────────────────
    for m in _BARE_URL_RE.finditer(text):
        start, end = m.start(), m.end()
        if any(fs <= start < fe or fs < end <= fe for fs, fe in full_matches):
            continue

        fragment = m.group().rstrip(_STRIP_TRAILING)
        if not fragment:
            continue

        if not _has_valid_tld(fragment):
            continue

        full_url = "https://" + fragment
        _add(full_url)

    log.info("Extracted %d URL(s) from input text.", len(collected))
    return collected
