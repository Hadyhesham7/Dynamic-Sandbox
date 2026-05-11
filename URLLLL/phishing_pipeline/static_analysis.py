"""
static_analysis.py — Step 5: Lexical / static URL feature extraction.

All features are computed locally from the URL string itself —
no network requests are made here.

Features:
  - Character counts and ratios (including #, %, +, $, !, *, comma, //)
  - IP address detection
  - URL shortener detection
  - Abnormal URL structure
  - Shannon entropy
  - Suspicious keywords, urgency words, security words
  - Brand mentions and hijacking
  - Path depth & query complexity
  - Encoded non-ASCII detection
  - Path hacking terms, suspicious extensions
"""

import math
import re
from urllib.parse import urlparse, parse_qsl

import tldextract

from .config import SHORTENER_DOMAINS
from .logger import get_logger

log = get_logger("static_analysis")

# IPv4 in host (e.g. http://192.168.1.1/login)
_IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
)
# IPv6 in host (e.g. http://[::1]/path)
_IPV6_RE = re.compile(r"^\[.*\]$")

# One or more consecutive digit runs in the hostname
_DIGIT_BLOCK_RE = re.compile(r"\d+")

# Percent-encoded non-ASCII bytes (e.g. %E5%8D%8A = Chinese char)
# Three consecutive %XX sequences where X is A-F / 8-9 (multi-byte UTF-8)
_ENCODED_NONASCII_RE = re.compile(r"(?:%[89A-Fa-f][0-9A-Fa-f]){2,}")

# ── Suspicious keywords commonly found in phishing URLs ──────────────────────
_SUSPICIOUS_KEYWORDS: list[str] = [
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "validate", "confirm",
    "secure", "security", "account", "update",
    "banking", "password", "credential", "auth",
    "suspend", "locked", "restrict", "unusual",
    "paypal", "apple", "amazon", "microsoft",
    "wallet", "invoice", "payment", "billing",
    "recover", "restore", "reactivate",
    "webscr", "cmd=", "dispatch",
    "urgent", "immediately", "expire",
]

# ── Urgency words (dataset feature: phish_urgency_words) ─────────────────────
_URGENCY_WORDS: list[str] = [
    "urgent", "immediately", "expire", "suspended", "locked",
    "alert", "warning", "critical", "action", "required",
    "important", "deadline", "limited", "hurry", "now",
]

# ── Security words (dataset feature: phish_security_words) ───────────────────
_SECURITY_WORDS: list[str] = [
    "secure", "security", "verify", "verification", "authenticate",
    "confirm", "validate", "protect", "safety", "ssl",
    "encryption", "privacy", "trust", "certificate",
]

# ── Brand names for brand mention/hijack detection ───────────────────────────
_BRANDS: list[str] = [
    "paypal", "facebook", "google", "apple", "amazon", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "icloud",
    "chase", "wellsfargo", "bankofamerica", "citibank",
    "outlook", "yahoo", "gmail", "hotmail",
    "dhl", "fedex", "ups", "usps",
    "steam", "coinbase", "binance", "whatsapp", "telegram",
]

# ── Hacked terms in path ─────────────────────────────────────────────────────
_HACKED_TERMS: list[str] = [
    "hacked", "pwned", "defaced", "owned", "r00t", "sh3ll",
    "backdoor", "webshell", "c99", "r57", "FilesMan",
]

# ── Suspicious file extensions ───────────────────────────────────────────────
_SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".js",
    ".wsf", ".msi", ".ps1", ".jar", ".apk", ".dll", ".cpl",
}


def _shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy (> 4.0) may indicate randomly generated or obfuscated URLs.
    """
    if not s:
        return 0.0
    length = len(s)
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def analyze_static(url: str) -> dict:
    """
    Compute lexical / static features from the raw URL string.

    Produces ALL features required by both the ML model and the risk scorer.

    Args:
        url: URL string (raw or normalized).

    Returns:
        Dict of static analysis features.
    """
    defaults = {
        # ── Core character counts ─────────────────────────────────────────
        "url_len": 0,
        "at_sign": 0,
        "question_mark": 0,
        "hyphen": 0,
        "equals": 0,
        "dots": 0,
        "hash_sign": 0,
        "percent": 0,
        "plus_sign": 0,
        "dollar": 0,
        "exclamation": 0,
        "asterisk": 0,
        "comma": 0,
        "double_slash": 0,
        "digits": 0,
        "letters": 0,
        # ── Structural flags ──────────────────────────────────────────────
        "https": 0,
        "having_ip_address": 0,
        "shortening_service": 0,
        "abnormal_url": 0,
        # ── Hostname-level features ───────────────────────────────────────
        "phish_adv_hyphen_count": 0,
        "phish_adv_number_count": 0,
        # ── Encoding ──────────────────────────────────────────────────────
        "phish_encoded_non_ascii": 0,
        "phish_adv_encoded_chars": 0,
        # ── Statistical ───────────────────────────────────────────────────
        "url_entropy": 0.0,
        # ── Keyword detection ─────────────────────────────────────────────
        "suspicious_keyword_count": 0,
        "phish_urgency_words": 0,
        "phish_security_words": 0,
        # ── Brand detection ───────────────────────────────────────────────
        "phish_brand_mentions": 0,
        "phish_brand_hijack": 0,
        "is_brand_own_domain": 0,
        # ── Path/query complexity ─────────────────────────────────────────
        "path_depth": 0,
        "query_param_count": 0,
        "query_length": 0,
        "num_subdomains": 0,
        "phish_long_path": 0,
        "phish_many_params": 0,
        # ── Advanced structural ───────────────────────────────────────────
        "phish_adv_exact_brand_match": 0,
        "phish_adv_brand_in_subdomain": 0,
        "phish_adv_brand_in_path": 0,
        "phish_adv_suspicious_tld": 0,
        "phish_adv_long_domain": 0,
        "phish_adv_many_subdomains": 0,
        "phish_adv_path_keywords": 0,
        "phish_adv_has_redirect": 0,
        "phish_adv_many_params": 0,
        # ── Path indicators ───────────────────────────────────────────────
        "path_has_hacked_terms": 0,
        "suspicious_extension": 0,
        "path_underscore_count": 0,
        "is_gov_edu": 0,
    }

    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        # Strip port if present
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]

        ext = tldextract.extract(url)
        registered = ext.registered_domain.lower() if ext.registered_domain else ""
        domain_label = ext.domain.lower() if ext.domain else ""

        url_lower = url.lower()
        path_lower = parsed.path.lower()

        # Strip scheme for ML feature parity with dataset.
        # Dataset URLs are mostly scheme-less (e.g., "mp3raid.com/music/...")
        # so character counts must match that format.
        url_for_counts = url.split("://", 1)[1] if "://" in url else url

        # ── Whole-URL character counts (on scheme-stripped URL) ────────────────
        defaults["url_len"]       = len(url_for_counts)
        defaults["at_sign"]       = url_for_counts.count("@")
        defaults["question_mark"] = url_for_counts.count("?")
        defaults["hyphen"]        = url_for_counts.count("-")
        defaults["equals"]        = url_for_counts.count("=")
        defaults["dots"]          = url_for_counts.count(".")
        defaults["hash_sign"]     = url_for_counts.count("#")
        defaults["percent"]       = url_for_counts.count("%")
        defaults["plus_sign"]     = url_for_counts.count("+")
        defaults["dollar"]        = url_for_counts.count("$")
        defaults["exclamation"]   = url_for_counts.count("!")
        defaults["asterisk"]      = url_for_counts.count("*")
        defaults["comma"]         = url_for_counts.count(",")
        defaults["double_slash"]  = url_for_counts.count("//")
        defaults["digits"]        = sum(c.isdigit() for c in url_for_counts)
        defaults["letters"]       = sum(c.isalpha() for c in url_for_counts)

        # ── HTTPS flag ───────────────────────────────────────────────────────
        defaults["https"] = 1 if parsed.scheme.lower() == "https" else 0

        # ── IP address in host ────────────────────────────────────────────────
        if _IPV4_RE.match(host) or _IPV6_RE.match(host):
            defaults["having_ip_address"] = 1

        # ── Known URL shortener ───────────────────────────────────────────────
        if registered in SHORTENER_DOMAINS or host in SHORTENER_DOMAINS:
            defaults["shortening_service"] = 1

        # ── Abnormal URL: registered domain missing from netloc ───────────────
        # A mismatch can indicate IDN homograph or embedded credentials.
        if registered and registered not in host:
            defaults["abnormal_url"] = 1

        # ── Hostname-specific hyphen & digit counts ───────────────────────────
        defaults["phish_adv_hyphen_count"] = host.count("-")
        defaults["phish_adv_number_count"] = len(_DIGIT_BLOCK_RE.findall(host))

        # ── Percent-encoded non-ASCII in URL path ────────────────────────
        has_encoded = bool(_ENCODED_NONASCII_RE.search(parsed.path + parsed.query))
        defaults["phish_encoded_non_ascii"] = 1 if has_encoded else 0
        defaults["phish_adv_encoded_chars"] = 1 if has_encoded else 0

        # ── Shannon Entropy ──────────────────────────────────────────────
        defaults["url_entropy"] = _shannon_entropy(url)

        # ── Suspicious Keywords ──────────────────────────────────────────
        keyword_hits = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in url_lower)
        defaults["suspicious_keyword_count"] = keyword_hits

        # ── Urgency Words ────────────────────────────────────────────────
        defaults["phish_urgency_words"] = sum(1 for w in _URGENCY_WORDS if w in url_lower)

        # ── Security Words ───────────────────────────────────────────────
        defaults["phish_security_words"] = sum(1 for w in _SECURITY_WORDS if w in url_lower)

        # ── Brand Mentions ───────────────────────────────────────────────
        brand_count = sum(1 for b in _BRANDS if b in url_lower)

        # Is the domain the brand itself? (e.g., facebook.com IS facebook)
        brand_is_own_domain = any(b == domain_label for b in _BRANDS)
        defaults["is_brand_own_domain"] = 1 if brand_is_own_domain else 0

        if brand_is_own_domain:
            # Domain IS the brand — this is a legitimate brand URL.
            # Zero out brand-related phishing signals to prevent ML false positives.
            defaults["phish_brand_mentions"] = 0
            defaults["phish_brand_hijack"] = 0
            defaults["phish_adv_exact_brand_match"] = 0
            defaults["phish_adv_brand_in_subdomain"] = 0
            defaults["phish_adv_brand_in_path"] = 0
            log.debug("Domain '%s' IS the brand — suppressing brand phishing signals.", domain_label)
        else:
            defaults["phish_brand_mentions"] = brand_count
            # Brand hijack: brand name in URL but NOT in the registered domain
            if brand_count > 0:
                defaults["phish_brand_hijack"] = 1

        # ── Gov/Edu domain flag ───────────────────────────────────────────
        suffix_lower = ext.suffix.lower().lstrip(".")
        defaults["is_gov_edu"] = 1 if any(
            suffix_lower.endswith(s) for s in (".gov", ".edu", ".ac", ".mil",
                                                "gov", "edu", "ac.uk", "edu.au")
        ) else 0

        # ── Path Depth ───────────────────────────────────────────────────
        path_segments = [s for s in parsed.path.split("/") if s]
        defaults["path_depth"] = len(path_segments)
        defaults["phish_long_path"] = 1 if len(path_segments) > 4 else 0

        # ── Query Complexity ─────────────────────────────────────────────
        params = parse_qsl(parsed.query, keep_blank_values=True)
        defaults["query_param_count"] = len(params)
        defaults["query_length"] = len(parsed.query)
        defaults["phish_many_params"] = 1 if len(params) > 3 else 0
        defaults["phish_adv_many_params"] = 1 if len(params) > 5 else 0

        # ── Subdomain Count ──────────────────────────────────────────────
        subdomain_parts = [p for p in ext.subdomain.split(".") if p]
        defaults["num_subdomains"] = len(subdomain_parts)
        defaults["phish_adv_many_subdomains"] = 1 if len(subdomain_parts) >= 3 else 0

        # ── Advanced: brand in subdomain / path ──────────────────────────
        # Only set these if the domain is NOT the brand itself
        # (already suppressed above for brand_is_own_domain)
        if not brand_is_own_domain:
            subdomain_str = ext.subdomain.lower()
            defaults["phish_adv_exact_brand_match"] = 1 if domain_label in _BRANDS else 0
            defaults["phish_adv_brand_in_subdomain"] = 1 if any(
                b in subdomain_str for b in _BRANDS if b != domain_label
            ) else 0
            defaults["phish_adv_brand_in_path"] = 1 if any(
                b in path_lower for b in _BRANDS
            ) else 0

        # ── Advanced: suspicious TLD (duplicate of domain_intel, kept for ML) ─
        from .config import SUSPICIOUS_TLDS
        suffix = ext.suffix.lower().lstrip(".")
        defaults["phish_adv_suspicious_tld"] = 1 if suffix in SUSPICIOUS_TLDS else 0

        # ── Advanced: long domain ────────────────────────────────────────
        defaults["phish_adv_long_domain"] = 1 if len(registered) > 30 else 0

        # ── Advanced: path keywords ──────────────────────────────────────
        path_keywords = ["login", "signin", "verify", "account", "update",
                         "secure", "confirm", "password", "auth", "banking"]
        defaults["phish_adv_path_keywords"] = 1 if any(
            kw in path_lower for kw in path_keywords
        ) else 0

        # ── Advanced: redirect indicators in URL ─────────────────────────
        defaults["phish_adv_has_redirect"] = 1 if any(
            r in url_lower for r in ["redirect", "redir", "return=", "url=", "next=", "goto="]
        ) else 0

        # ── Path: hacked terms ───────────────────────────────────────────
        defaults["path_has_hacked_terms"] = 1 if any(
            t.lower() in path_lower for t in _HACKED_TERMS
        ) else 0

        # ── Suspicious extension ─────────────────────────────────────────
        for seg in path_segments:
            for sx in _SUSPICIOUS_EXTENSIONS:
                if seg.lower().endswith(sx):
                    defaults["suspicious_extension"] = 1
                    break

        # ── Path underscore count ────────────────────────────────────────
        defaults["path_underscore_count"] = parsed.path.count("_")

        log.debug("Static analysis for '%s': %s", url, defaults)
        return defaults

    except Exception as exc:
        log.warning("analyze_static failed for '%s': %s", url, exc)
        return defaults

