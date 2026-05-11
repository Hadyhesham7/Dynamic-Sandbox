"""
href_mismatch.py — Display text vs actual href mismatch detection.

Detects the classic phishing technique where anchor text shows a legitimate
URL (e.g., "https://paypal.com") but the actual href points to a malicious
domain (e.g., "http://evil.com/steal").

Example:
    <a href="http://evil.com">https://paypal.com</a>
    → display_url = "https://paypal.com"
    → actual_url  = "http://evil.com"
    → MISMATCH DETECTED (different domains)
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .logger import get_logger

log = get_logger("href_mismatch")

# Pattern to detect if anchor text looks like a URL
_TEXT_URL_RE = re.compile(
    r"^https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$",
    re.IGNORECASE,
)


def _extract_domain(url: str) -> str:
    """Extract the registered domain from a URL, lowercased."""
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def detect_href_mismatches(html: str) -> dict:
    """
    Scan HTML for <a> tags where the displayed text looks like a URL
    but points to a different domain than the actual href.

    Args:
        html: Raw HTML content string.

    Returns:
        Dict with:
            href_mismatch_count:    number of mismatched links found
            href_mismatch_details:  list of {display, actual, display_domain, actual_domain}
    """
    result = {
        "href_mismatch_count": 0,
        "href_mismatch_details": [],
    }

    if not html:
        return result

    try:
        soup = BeautifulSoup(html, "html.parser")

        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            display_text = anchor.get_text(strip=True)

            # Only check if the display text looks like a URL
            if not display_text or not _TEXT_URL_RE.match(display_text):
                continue

            display_domain = _extract_domain(display_text)
            actual_domain = _extract_domain(href)

            if not display_domain or not actual_domain:
                continue

            # Compare domains — mismatch means phishing
            if display_domain != actual_domain:
                result["href_mismatch_count"] += 1
                result["href_mismatch_details"].append({
                    "display": display_text[:200],
                    "actual": href[:200],
                    "display_domain": display_domain,
                    "actual_domain": actual_domain,
                })
                log.warning(
                    "HREF MISMATCH: displays '%s' but links to '%s'",
                    display_domain, actual_domain,
                )

    except Exception as exc:
        log.warning("href mismatch detection error: %s", exc)

    return result
