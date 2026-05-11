"""
threat_intel.py — Tranco Whitelist + URLhaus Blacklist integration.

Downloads and caches:
  1. Tranco Top 1M — legitimate domain whitelist (reduces false positives)
  2. URLhaus — known malware distribution URLs (immediate flagging)

Cache files are stored in phishing_pipeline/data/ and auto-refresh every 24h.

Usage:
    from phishing_pipeline.threat_intel import is_whitelisted, check_urlhaus
"""

from __future__ import annotations

import csv
import io
import os
import time
import zipfile
from urllib.parse import urlparse

import requests

from .logger import get_logger

log = get_logger("threat_intel")

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(_DATA_DIR, exist_ok=True)

_TRANCO_PATH = os.path.join(_DATA_DIR, "tranco_top1m.csv")
_URLHAUS_PATH = os.path.join(_DATA_DIR, "urlhaus_online.csv")

# Cache expiry: 24 hours
_CACHE_TTL = 86400

# ─── In-memory caches ────────────────────────────────────────────────────────
_tranco_domains: set[str] | None = None
_urlhaus_urls: set[str] | None = None
_urlhaus_domains: set[str] | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Tranco Whitelist
# ─────────────────────────────────────────────────────────────────────────────

def _download_tranco():
    """Download Tranco Top 1M list (CSV inside ZIP)."""
    url = "https://tranco-list.eu/top-1m.csv.zip"
    log.info("Downloading Tranco Top 1M from %s ...", url)
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            # The ZIP contains a single CSV file
            csv_name = zf.namelist()[0]
            with zf.open(csv_name) as f:
                data = f.read()
        with open(_TRANCO_PATH, "wb") as f:
            f.write(data)
        log.info("Tranco list saved: %s (%d bytes)", _TRANCO_PATH, len(data))
    except Exception as e:
        log.warning("Failed to download Tranco list: %s", e)


def _load_tranco() -> set[str]:
    """Load Tranco domains into memory."""
    global _tranco_domains
    if _tranco_domains is not None:
        return _tranco_domains

    # Check if cache needs refresh
    if not os.path.isfile(_TRANCO_PATH) or \
       (time.time() - os.path.getmtime(_TRANCO_PATH)) > _CACHE_TTL:
        _download_tranco()

    _tranco_domains = set()
    if os.path.isfile(_TRANCO_PATH):
        try:
            with open(_TRANCO_PATH, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        _tranco_domains.add(row[1].strip().lower())
            log.info("Tranco whitelist loaded: %d domains", len(_tranco_domains))
        except Exception as e:
            log.warning("Failed to load Tranco list: %s", e)

    return _tranco_domains


def is_whitelisted(domain: str) -> bool:
    """
    Check if a domain is in the Tranco Top 1M whitelist.

    Also checks parent domains:
      'login.microsoft.com' → checks 'microsoft.com' ✓

    Args:
        domain: Domain name to check.

    Returns:
        True if the domain is in the Tranco Top 1M.
    """
    tranco = _load_tranco()
    if not tranco:
        return False

    domain = domain.lower().strip()

    # Direct match
    if domain in tranco:
        return True

    # Check parent domain (e.g., 'sub.example.com' → 'example.com')
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in tranco:
            return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# URLhaus Blacklist
# ─────────────────────────────────────────────────────────────────────────────

def _download_urlhaus():
    """Download URLhaus active threat list."""
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    log.info("Downloading URLhaus feed from %s ...", url)
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        with open(_URLHAUS_PATH, "wb") as f:
            f.write(resp.content)
        log.info("URLhaus feed saved: %s (%d bytes)", _URLHAUS_PATH, len(resp.content))
    except Exception as e:
        log.warning("Failed to download URLhaus feed: %s", e)


def _load_urlhaus() -> tuple[set[str], set[str]]:
    """Load URLhaus URLs and domains into memory."""
    global _urlhaus_urls, _urlhaus_domains
    if _urlhaus_urls is not None:
        return _urlhaus_urls, _urlhaus_domains

    # Check if cache needs refresh
    if not os.path.isfile(_URLHAUS_PATH) or \
       (time.time() - os.path.getmtime(_URLHAUS_PATH)) > _CACHE_TTL:
        _download_urlhaus()

    _urlhaus_urls = set()
    _urlhaus_domains = set()

    if os.path.isfile(_URLHAUS_PATH):
        try:
            with open(_URLHAUS_PATH, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    # Skip comments
                    if line.startswith("#") or not line:
                        continue
                    # CSV format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                    parts = line.split('","')
                    if len(parts) >= 3:
                        raw_url = parts[2].strip('"').strip()
                        if raw_url.startswith(("http://", "https://")):
                            _urlhaus_urls.add(raw_url.lower())
                            try:
                                host = urlparse(raw_url).hostname
                                if host:
                                    _urlhaus_domains.add(host.lower())
                            except Exception:
                                pass
            log.info("URLhaus loaded: %d URLs, %d domains",
                     len(_urlhaus_urls), len(_urlhaus_domains))
        except Exception as e:
            log.warning("Failed to load URLhaus feed: %s", e)

    return _urlhaus_urls, _urlhaus_domains


def check_urlhaus(url: str) -> dict:
    """
    Check if a URL or its domain appears in URLhaus malware DB.

    Args:
        url: URL to check.

    Returns:
        Dict with:
            urlhaus_hit:     bool — True if URL/domain found in URLhaus
            urlhaus_match:   str — 'exact_url', 'domain', or ''
    """
    urls, domains = _load_urlhaus()

    result = {
        "urlhaus_hit": False,
        "urlhaus_match": "",
    }

    if not urls and not domains:
        return result

    url_lower = url.lower().strip()

    # Exact URL match
    if url_lower in urls:
        result["urlhaus_hit"] = True
        result["urlhaus_match"] = "exact_url"
        log.warning("URLhaus EXACT MATCH: %s", url[:80])
        return result

    # Domain match
    try:
        _u = url_lower
        if not _u.startswith(("http://", "https://")):
            _u = "https://" + _u
        host = urlparse(_u).hostname
        if host and host in domains:
            result["urlhaus_hit"] = True
            result["urlhaus_match"] = "domain"
            log.warning("URLhaus DOMAIN MATCH: %s (host=%s)", url[:80], host)
    except Exception:
        pass

    return result
