"""
risk_scorer.py — Composite risk scoring engine.

Computes a weighted risk score (0–100) from all pipeline features.
This replaces the naive "vt_malicious count as badge" approach with
a proper multi-signal scoring engine.
"""

from __future__ import annotations

from .logger import get_logger

log = get_logger("risk_scorer")

# ─────────────────────────────────────────────────────────────────────────────
# Scoring rules — each returns (points, reason) or (0, "")
# ─────────────────────────────────────────────────────────────────────────────

def _score_reputation(r: dict) -> list[tuple[int, str]]:
    """Score based on VirusTotal and other reputation signals."""
    signals = []
    vt_mal = r.get("vt_malicious", 0) or 0
    vt_sus = r.get("vt_suspicious", 0) or 0

    if vt_mal >= 5:
        signals.append((30, f"VirusTotal: {vt_mal} engines flagged MALICIOUS"))
    elif vt_mal >= 1:
        signals.append((20, f"VirusTotal: {vt_mal} engine(s) flagged malicious"))

    if vt_sus >= 3:
        signals.append((10, f"VirusTotal: {vt_sus} engines flagged suspicious"))
    elif vt_sus >= 1:
        signals.append((5, f"VirusTotal: {vt_sus} engine(s) flagged suspicious"))

    return signals


def _score_domain(r: dict) -> list[tuple[int, str]]:
    """Score based on domain intelligence."""
    signals = []

    age = r.get("domain_age_days", -1)
    if age != -1:
        if age < 7:
            signals.append((20, f"Domain is only {age} days old (< 7 days)"))
        elif age < 30:
            signals.append((12, f"Domain is only {age} days old (< 30 days)"))
        elif age < 90:
            signals.append((5, f"Domain is only {age} days old (< 90 days)"))

    if r.get("phish_suspicious_tld"):
        signals.append((8, "Suspicious/abused TLD detected"))

    if r.get("phish_multiple_subdomains"):
        signals.append((5, "Multiple subdomain levels"))

    if r.get("phish_adv_long_domain"):
        signals.append((4, "Unusually long domain name"))

    # NOTE: WHOIS privacy is common on legitimate sites — not scored
    # It's still captured in the report for manual review

    # No DNS A-records = domain doesn't resolve = suspicious
    dns_ips = r.get("dns_ip_count", -1)
    if dns_ips == 0:
        signals.append((10, "Domain has no DNS A-records (does not resolve)"))

    if r.get("fast_flux_detected"):
        signals.append((15, "Fast flux DNS detected (many IPs, low TTL)"))

    typo_score = r.get("typosquat_score", 99)
    typo_brand = r.get("typosquat_target_brand", "")
    if typo_brand and typo_score <= 1:
        signals.append((18, f"Typosquatting detected: impersonating '{typo_brand}' (dist={typo_score})"))
    elif typo_brand and typo_score == 2:
        signals.append((10, f"Possible typosquatting of '{typo_brand}' (dist={typo_score})"))
    # NOTE: dist=3 removed — too many false matches (go→aol, sheknows→ups)

    return signals


def _score_static(r: dict) -> list[tuple[int, str]]:
    """Score based on static URL features."""
    signals = []

    if r.get("having_ip_address"):
        signals.append((12, "IP address used as hostname"))

    if r.get("shortening_service"):
        signals.append((8, "URL shortener detected"))

    # NOTE: abnormal_url excluded from scoring — too many benign sites trigger it
    # (91.7% of dataset benign URLs have it due to how it's computed)

    if r.get("at_sign", 0) > 0:
        signals.append((10, "'@' in URL — may hide real destination"))

    kw_count = r.get("suspicious_keyword_count", 0)
    if kw_count >= 4:
        signals.append((10, f"{kw_count} suspicious keywords in URL"))
    elif kw_count >= 2:
        signals.append((4, f"{kw_count} suspicious keyword(s) in URL"))
    # NOTE: kw_count=1 is too common on benign sites (e.g. 'account' in URLs)

    entropy = r.get("url_entropy", 0)
    if isinstance(entropy, (int, float)) and entropy > 4.8:
        signals.append((6, f"High URL entropy ({entropy:.2f}) — possibly randomized"))
    # NOTE: 4.5 was too low — long benign URLs regularly hit 4.5-4.6

    url_len = r.get("url_len", 0)
    if isinstance(url_len, int) and url_len > 150:
        signals.append((5, f"Very long URL ({url_len} chars)"))

    if r.get("phish_encoded_non_ascii"):
        signals.append((8, "Encoded non-ASCII characters in URL"))

    return signals


def _score_redirects(r: dict) -> list[tuple[int, str]]:
    """Score based on redirect behavior."""
    signals = []

    count = r.get("phish_redirect_count", 0)
    if isinstance(count, int):
        if count >= 5:
            signals.append((15, f"Long redirect chain ({count} hops)"))
        elif count >= 3:
            signals.append((8, f"Multi-step redirect chain ({count} hops)"))

    cross = r.get("phish_cross_domain_redirects", 0)
    if isinstance(cross, int) and cross >= 2:
        signals.append((10, f"{cross} cross-domain redirects (domain hopping)"))

    if r.get("phish_open_redirect_abuse"):
        signals.append((15, "Open redirect abuse detected"))

    if r.get("phish_redirect_loop"):
        signals.append((12, "Redirect loop detected"))

    if r.get("phish_js_redirect_detected"):
        signals.append((8, "JavaScript redirect detected"))

    if r.get("phish_meta_refresh_detected"):
        signals.append((6, "Meta refresh redirect detected"))

    return signals


def _score_dynamic(r: dict) -> list[tuple[int, str]]:
    """Score based on dynamic analysis / DOM features."""
    signals = []

    pw_fields = r.get("web_password_fields", 0)
    has_login = r.get("web_has_login", 0)
    ssl_valid = r.get("web_ssl_valid", 0)

    if pw_fields and not ssl_valid:
        signals.append((18, "Password field on page WITHOUT valid SSL"))
    elif pw_fields and r.get("phish_suspicious_tld"):
        signals.append((12, "Password field on suspicious-TLD site"))

    if has_login and r.get("vt_malicious", 0) > 0:
        signals.append((15, "Login form + VT malicious flag = credential harvester"))

    hidden = r.get("web_hidden_inputs", 0)
    if isinstance(hidden, int) and hidden >= 5:
        signals.append((6, f"{hidden} hidden form inputs (possible exfiltration)"))

    ext_ratio = r.get("web_ext_ratio", 0)
    if isinstance(ext_ratio, float) and ext_ratio > 0.85:
        signals.append((8, f"{ext_ratio:.0%} external request ratio (cloned page?)"))
    # NOTE: 0.7 was too low — CDN-heavy news sites easily exceed it

    if r.get("web_defacement_detected"):
        signals.append((20, "Website defacement detected"))

    if r.get("file_download_detected"):
        signals.append((6, "Executable download link detected"))

    js_api_count = r.get("web_suspicious_js_apis", 0)
    if isinstance(js_api_count, int) and js_api_count >= 3:
        signals.append((8, f"{js_api_count} suspicious JavaScript APIs detected"))
    # NOTE: 1-2 hits is normal — analytics/tracking use localStorage, XMLHttpRequest

    return signals


def _score_anomaly(r: dict) -> list[tuple[int, str]]:
    """Score based on Isolation Forest anomaly detection.

    Only fires for high-confidence anomalies (80th+ percentile) to prevent
    false positives on benign sites with slightly unusual URL structures.
    """
    signals = []
    if r.get("is_anomaly"):
        percentile = r.get("anomaly_percentile", 0)
        if percentile >= 90:
            signals.append((8, f"Anomaly detector: highly anomalous (percentile={percentile:.0f}%)"))
        elif percentile >= 80:
            signals.append((4, f"Anomaly detector: flagged as unusual (percentile={percentile:.0f}%)"))
        # Below 80th percentile: log but don't score — too many benign sites trigger
    return signals


def _score_href_mismatch(r: dict) -> list[tuple[int, str]]:
    """Score based on display text vs href URL mismatch."""
    signals = []
    mismatch_count = r.get("href_mismatch_count", 0)
    if isinstance(mismatch_count, int) and mismatch_count >= 1:
        signals.append((20, f"{mismatch_count} display-vs-href mismatch(es) — classic phishing indicator"))
    return signals


def _score_ml(r: dict) -> list[tuple[int, str]]:
    """
    Score based on ML classifier prediction (XGBoost).

    Three tiers:
      - With corroboration: full weight (20/12/6 pts)
      - Without corroboration, 95%+ confidence: moderate weight (8 pts)
      - Without corroboration, <95%: suppressed entirely
    """
    signals = []
    prediction = r.get("ml_prediction", "unknown")
    confidence = r.get("ml_confidence", 0.0)

    if prediction in ("phishing", "malware", "defacement"):
        # Check for rule-based corroboration
        has_rule_signals = (
            r.get("phish_suspicious_tld", 0) or
            0 < r.get("typosquat_score", 0) <= 2 or
            r.get("newly_registered_domain", 0) or
            r.get("vt_malicious", 0) > 0 or
            r.get("having_ip_address", 0) or
            r.get("web_password_fields", 0) or
            r.get("suspicious_keyword_count", 0) >= 3 or
            r.get("href_mismatch_count", 0) >= 1 or
            r.get("phish_brand_hijack", 0) or
            r.get("phish_adv_many_subdomains", 0) or
            r.get("dns_ip_count", -1) == 0 or      # No DNS = dead/parked domain
            (r.get("whois_privacy", 0) and r.get("dns_has_mx", 1) == 0)  # Privacy + no MX
        )

        if has_rule_signals:
            # Corroborated — full weight
            if confidence >= 0.90:
                signals.append((20, f"ML classifier: {prediction} ({confidence:.0%} confidence)"))
            elif confidence >= 0.70:
                signals.append((12, f"ML classifier: {prediction} ({confidence:.0%} confidence)"))
            elif confidence >= 0.55:
                signals.append((6, f"ML classifier: {prediction} ({confidence:.0%} confidence)"))
        elif confidence >= 0.75:
            # High confidence but no rule corroboration — still score modestly
            signals.append((8, f"ML classifier: {prediction} ({confidence:.0%} confidence, uncorroborated)"))
        else:
            log.debug("ML says %s (%.0f%%) but no corroborating signals — suppressed.",
                       prediction, confidence * 100)
    return signals


def _score_api_behavior(r: dict) -> list[tuple[int, str]]:
    """Score based on API call sequence monitoring."""
    signals = []

    if r.get("api_credential_exfil_risk"):
        signals.append((25, "Credential data detected in POST body — exfiltration risk"))

    ext_posts = r.get("api_external_post_count", 0)
    if isinstance(ext_posts, int) and ext_posts >= 3:
        signals.append((10, f"{ext_posts} POST requests to external domain(s)"))
    # NOTE: 1-2 external POSTs are normal (analytics, consent, tracking pixels)

    suspicious_count = r.get("api_suspicious_pattern_count", 0)
    if isinstance(suspicious_count, int) and suspicious_count >= 2:
        signals.append((8, f"{suspicious_count} suspicious API patterns detected"))

    if r.get("api_websocket_count", 0) and r.get("api_unique_domains", 0) > 3:
        signals.append((6, "WebSocket + multiple target domains — hidden communication"))

    return signals


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def compute_risk_score(report: dict) -> dict:
    """
    Compute a composite risk score from all pipeline features.

    Args:
        report: Merged dict from all pipeline stages.

    Returns:
        Dict with:
            risk_score:    int 0–100 (capped)
            risk_level:    'clean' / 'low' / 'medium' / 'high' / 'critical'
            risk_signals:  list of (points, reason) tuples
    """
    all_signals: list[tuple[int, str]] = []

    all_signals.extend(_score_reputation(report))
    all_signals.extend(_score_domain(report))
    all_signals.extend(_score_static(report))
    all_signals.extend(_score_redirects(report))
    all_signals.extend(_score_dynamic(report))
    all_signals.extend(_score_anomaly(report))
    all_signals.extend(_score_href_mismatch(report))
    all_signals.extend(_score_ml(report))
    all_signals.extend(_score_api_behavior(report))

    # ── URLhaus Blacklist ─────────────────────────────────────────────────
    if report.get("urlhaus_hit"):
        match_type = report.get("urlhaus_match", "domain")
        if match_type == "exact_url":
            all_signals.append((40, "URLhaus: EXACT URL match in abuse.ch malware database"))
        else:
            all_signals.append((25, "URLhaus: Domain found in abuse.ch malware database"))

    raw_score = sum(pts for pts, _ in all_signals)

    # ── Tranco Whitelist Dampener ─────────────────────────────────────────
    # If the domain is in the Tranco Top 1M, it's a well-known legitimate site.
    # Halve the risk score to prevent false positives on popular domains.
    # (Exception: URLhaus hit overrides whitelist — even legit domains can be compromised)
    if report.get("tranco_whitelisted") and not report.get("urlhaus_hit"):
        raw_score = raw_score // 2
        if raw_score > 0:
            log.info("Tranco whitelist dampener applied: score halved (%d → %d)",
                     raw_score * 2, raw_score)

    capped_score = min(100, raw_score)

    if capped_score >= 60:
        level = "critical"
    elif capped_score >= 35:
        level = "high"
    elif capped_score >= 15:
        level = "medium"
    elif capped_score >= 5:
        level = "low"
    else:
        level = "clean"

    log.info("Risk score: %d/100 (%s) — %d signal(s) tranco=%s urlhaus=%s",
             capped_score, level, len(all_signals),
             "WL" if report.get("tranco_whitelisted") else "no",
             "HIT" if report.get("urlhaus_hit") else "no")

    return {
        "risk_score": capped_score,
        "risk_level": level,
        "risk_signals": all_signals,
    }

