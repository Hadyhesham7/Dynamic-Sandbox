"""
domain_intel.py — Step 4: Domain intelligence features.

Uses tldextract for domain parsing, python-whois for WHOIS data,
dnspython for DNS analysis, and Levenshtein distance for typosquatting.

Features produced:
  - Basic:   domain, subdomain flags, TLD checks
  - WHOIS:   domain_age_days, whois_creation_date, whois_registrar,
             whois_privacy, newly_registered_domain
  - DNS:     dns_ip_count, dns_ttl_min, dns_has_mx, fast_flux_detected
  - Typosquat: typosquat_score, typosquat_target_brand
"""

from __future__ import annotations

import datetime
from urllib.parse import urlparse

import tldextract

from .config import SUSPICIOUS_TLDS
from .logger import get_logger

log = get_logger("domain_intel")

# ── Top brands checked for typosquatting ──────────────────────────────────────
_TOP_BRANDS: list[str] = [
    "paypal", "facebook", "google", "apple", "amazon", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "icloud",
    "chase", "wellsfargo", "bankofamerica", "citibank", "usbank",
    "outlook", "yahoo", "aol", "hotmail", "gmail",
    "dhl", "fedex", "ups", "usps",
    "steam", "epicgames", "roblox", "twitch",
    "whatsapp", "telegram", "signal", "discord",
    "coinbase", "binance", "blockchain", "metamask",
]

# ── Homoglyph substitution map (attacker-style replacements) ─────────────────
_HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g",
    "7": "t", "8": "b", "9": "g",
    "!": "i", "|": "l",
    "rn": "m", "vv": "w", "cl": "d", "nn": "m",
}


# ─────────────────────────────────────────────────────────────────────────────
# Levenshtein distance (pure-Python, no external dependency)
# ─────────────────────────────────────────────────────────────────────────────

def _levenshtein(s1: str, s2: str) -> int:
    """Compute edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,        # deletion
                curr[j] + 1,            # insertion
                prev[j] + (c1 != c2),   # substitution
            ))
        prev = curr
    return prev[-1]


def _normalize_homoglyphs(s: str) -> str:
    """Replace common homoglyphs with their latin equivalents."""
    result = s.lower()
    # Multi-char substitutions first
    for fake, real in sorted(_HOMOGLYPHS.items(), key=lambda x: -len(x[0])):
        result = result.replace(fake, real)
    return result


def _check_typosquatting(domain_name: str) -> dict:
    """
    Check if a domain name is suspiciously close to a known brand.

    Returns:
        typosquat_score:         edit distance to closest brand (0 = exact match)
        typosquat_target_brand:  the brand being impersonated (or "")
    """
    if not domain_name:
        return {"typosquat_score": 99, "typosquat_target_brand": ""}

    # Strip TLD to get just the domain label
    name = domain_name.lower()

    best_dist = 99
    best_brand = ""

    normalized_name = _normalize_homoglyphs(name)

    for brand in _TOP_BRANDS:
        # Short domain names (≤4 chars like "sol", "go") produce spurious
        # edit-distance matches against short brands ("aol", "ups", "dhl").
        # Only allow brand-substring matching for these; skip Levenshtein.
        if len(name) <= 4 and brand not in name:
            continue

        # For all domains, skip if length ratio is too different
        # e.g. "community" (9 chars) vs "ups" (3 chars) = ratio 3.0 → skip
        longer = max(len(name), len(brand))
        shorter = min(len(name), len(brand))
        if longer > 0 and shorter / longer < 0.5:
            continue

        # Direct Levenshtein on original name
        dist = _levenshtein(name, brand)
        if dist < best_dist:
            best_dist = dist
            best_brand = brand

        # Also check after homoglyph normalization
        norm_dist = _levenshtein(normalized_name, brand)
        if norm_dist < best_dist:
            # If normalized version is exact match but original is not,
            # this is a homoglyph attack (paypa1→paypal) — flag with dist=1
            if norm_dist == 0 and name != brand:
                if 1 < best_dist:
                    best_dist = 1
                    best_brand = brand
            else:
                best_dist = norm_dist
                best_brand = brand

        # Check if brand is substring (e.g., "paypal-verify-account.com")
        if brand in name and name != brand:
            dist = 1  # Very suspicious
            if dist < best_dist:
                best_dist = dist
                best_brand = brand

    # Exact match on ORIGINAL name means this IS the brand, not a typosquat
    if best_dist == 0 and name in _TOP_BRANDS:
        return {"typosquat_score": 0, "typosquat_target_brand": ""}

    return {
        "typosquat_score": best_dist,
        "typosquat_target_brand": best_brand if best_dist <= 3 else "",
    }


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS Lookup
# ─────────────────────────────────────────────────────────────────────────────

def _whois_lookup(domain: str) -> dict:
    """
    Query WHOIS for domain registration intelligence.
    Returns safe defaults if python-whois is not installed or lookup fails.
    """
    defaults = {
        "domain_age_days": -1,
        "whois_creation_date": "",
        "whois_registrar": "",
        "whois_privacy": 0,
        "newly_registered_domain": 0,
    }

    try:
        import whois
    except ImportError:
        log.warning("python-whois not installed — skipping WHOIS lookup. "
                     "Install with: pip install python-whois")
        return defaults

    try:
        w = whois.whois(domain)

        # ── Creation date ──────────────────────────────────────────────────
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if isinstance(creation, datetime.datetime):
            defaults["whois_creation_date"] = creation.isoformat()
            # Normalize timezone: make both naive for safe subtraction
            now = datetime.datetime.now(datetime.timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=datetime.timezone.utc)
            age = (now - creation).days
            defaults["domain_age_days"] = age
            defaults["newly_registered_domain"] = 1 if age < 30 else 0

        # ── Registrar ──────────────────────────────────────────────────────
        registrar = w.registrar or ""
        defaults["whois_registrar"] = str(registrar)[:120]

        # ── Privacy / proxy registration ───────────────────────────────────
        privacy_keywords = [
            "privacy", "proxy", "redacted", "withheld",
            "data protected", "whoisguard", "domains by proxy",
            "contact privacy", "identity protect",
        ]
        all_text = str(w).lower()
        if any(kw in all_text for kw in privacy_keywords):
            defaults["whois_privacy"] = 1

        log.info("WHOIS for '%s': age=%d days, registrar=%s",
                 domain, defaults["domain_age_days"], defaults["whois_registrar"][:40])

    except Exception as exc:
        log.warning("WHOIS lookup failed for '%s': %s", domain, exc)

    return defaults


# ─────────────────────────────────────────────────────────────────────────────
# DNS Intelligence
# ─────────────────────────────────────────────────────────────────────────────

def _dns_analysis(domain: str) -> dict:
    """
    Query DNS records for infrastructure intelligence.
    Returns safe defaults if dnspython is not installed or query fails.
    """
    defaults = {
        "dns_ip_count": 0,
        "dns_ttl_min": -1,
        "dns_has_mx": 0,
        "fast_flux_detected": 0,
    }

    try:
        import dns.resolver
    except ImportError:
        log.warning("dnspython not installed — skipping DNS analysis. "
                     "Install with: pip install dnspython")
        return defaults

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        # ── A records ─────────────────────────────────────────────────────
        try:
            a_answers = resolver.resolve(domain, "A")
            ips = [str(rr) for rr in a_answers]
            defaults["dns_ip_count"] = len(ips)

            # TTL — low TTL is a fast-flux indicator
            ttl = a_answers.rrset.ttl if a_answers.rrset else -1
            defaults["dns_ttl_min"] = ttl

            # Fast flux heuristic: many IPs + low TTL
            if len(ips) >= 5 and ttl < 300:
                defaults["fast_flux_detected"] = 1
                log.warning("Fast flux suspected for '%s': %d IPs, TTL=%d",
                            domain, len(ips), ttl)

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass

        # ── MX records ────────────────────────────────────────────────────
        try:
            mx_answers = resolver.resolve(domain, "MX")
            defaults["dns_has_mx"] = 1 if len(mx_answers) > 0 else 0
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass

        log.info("DNS for '%s': %d A records, TTL=%d, MX=%d",
                 domain, defaults["dns_ip_count"],
                 defaults["dns_ttl_min"], defaults["dns_has_mx"])

    except Exception as exc:
        log.warning("DNS analysis failed for '%s': %s", domain, exc)

    return defaults


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_domain(url: str) -> dict:
    """
    Extract comprehensive domain intelligence features from a URL.

    Performs:
      1. Domain parsing (tldextract)
      2. Subdomain / TLD / length flags
      3. WHOIS registration intelligence
      4. DNS infrastructure analysis
      5. Typosquatting / brand impersonation detection

    Args:
        url: Normalized URL string.

    Returns:
        Dict of domain intelligence features.
    """
    defaults = {
        # Basic domain features
        "domain": "",
        "phish_multiple_subdomains": 0,
        "phish_adv_long_domain": 0,
        "phish_suspicious_tld": 0,
        "is_gov_edu": 0,
        # WHOIS
        "domain_age_days": -1,
        "whois_creation_date": "",
        "whois_registrar": "",
        "whois_privacy": 0,
        "newly_registered_domain": 0,
        # DNS
        "dns_ip_count": 0,
        "dns_ttl_min": -1,
        "dns_has_mx": 0,
        "fast_flux_detected": 0,
        # Typosquatting
        "typosquat_score": 99,
        "typosquat_target_brand": "",
    }

    try:
        ext = tldextract.extract(url)

        # Registered domain (domain + suffix)
        registered = ext.registered_domain or ""
        defaults["domain"] = registered

        # ── phish_multiple_subdomains ─────────────────────────────────────────
        # Counts how many dot-separated parts exist in the subdomain string.
        # e.g. "secure.login.evil" → 3 parts → flag = 1
        subdomain_parts = [p for p in ext.subdomain.split(".") if p]
        defaults["phish_multiple_subdomains"] = 1 if len(subdomain_parts) >= 2 else 0

        # ── phish_adv_long_domain ─────────────────────────────────────────────
        # Long domain names are a common evasion tactic; threshold is 30 chars.
        defaults["phish_adv_long_domain"] = 1 if len(registered) > 30 else 0

        # ── phish_suspicious_tld ──────────────────────────────────────────────
        suffix = ext.suffix.lower().lstrip(".")
        defaults["phish_suspicious_tld"] = 1 if suffix in SUSPICIOUS_TLDS else 0

        # ── is_gov_edu ────────────────────────────────────────────────────────
        defaults["is_gov_edu"] = 1 if suffix in ("gov", "edu") else 0

        # ── WHOIS Intelligence ────────────────────────────────────────────────
        if registered:
            whois_data = _whois_lookup(registered)
            defaults.update(whois_data)

        # ── DNS Intelligence ──────────────────────────────────────────────────
        domain_for_dns = registered or ext.domain
        if domain_for_dns:
            dns_data = _dns_analysis(domain_for_dns)
            defaults.update(dns_data)

        # ── Typosquatting Detection ───────────────────────────────────────────
        # Check the registered domain label AND each subdomain label.
        # e.g., "paypa1.evil.tk" → check "evil" and "paypa1"
        domain_label = ext.domain or ""
        best_typo = {"typosquat_score": 99, "typosquat_target_brand": ""}

        if domain_label:
            best_typo = _check_typosquatting(domain_label)

        # Also check each subdomain label (e.g., "paypa1" in "paypa1.evil.tk")
        for sub_label in subdomain_parts:
            if len(sub_label) >= 3:  # Skip very short labels like "www"
                sub_typo = _check_typosquatting(sub_label)
                if sub_typo["typosquat_score"] < best_typo["typosquat_score"]:
                    best_typo = sub_typo

        defaults.update(best_typo)

        log.debug("Domain intel for '%s': %s", url, defaults)
        return defaults

    except Exception as exc:
        log.warning("analyze_domain failed for '%s': %s", url, exc)
        return defaults
