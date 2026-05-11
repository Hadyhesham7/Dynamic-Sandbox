"""
pipeline.py — Orchestrator that chains all analysis stages together.

Call analyze_url(url) to get the full feature report dict for one URL.
Each stage is called independently; errors in one stage do not abort others.

Stages:
    1. SSRF guard
    2. URL normalization
    3. VirusTotal reputation check
    4. Domain intelligence (WHOIS + DNS + typosquatting)
    5. Static / lexical URL analysis
    6. Redirect graph analysis
    7–10. Dynamic analysis + API monitoring (Playwright headless browser)
    11. Anomaly detection (Isolation Forest)
    12. ML classifier (XGBoost)
    13. Composite risk scoring
"""

from __future__ import annotations

from .logger import get_logger
from .ssrf_guard import is_safe_url
from .url_normalizer import normalize_url
from .reputation import check_virustotal
from .domain_intel import analyze_domain
from .static_analysis import analyze_static
from .redirect_graph import analyze_redirects
from .dynamic_analysis import analyze_dynamic
from .anomaly_detector import score_anomaly
from .ml_model import predict as ml_predict
from .risk_scorer import compute_risk_score
from .threat_intel import is_whitelisted, check_urlhaus

log = get_logger("pipeline")


def analyze_url(url: str, skip_dynamic: bool = False) -> dict:
    """
    Run the full phishing analysis pipeline on a single URL.

    Stages:
        1. SSRF safety check
        2. URL normalization
        3. VirusTotal reputation check
        4. Domain intelligence (WHOIS, DNS, typosquatting)
        5. Static / lexical URL analysis
        6. Redirect graph analysis
        7–10. Dynamic analysis (Playwright headless browser)
        11. Anomaly detection (unsupervised Isolation Forest)
        12. Composite risk scoring

    Args:
        url:          Raw URL extracted from email.
        skip_dynamic: Set True to skip the Playwright stage (e.g. for batch
                      analysis where browser is unavailable).

    Returns:
        Flat dict merging all feature outputs plus the original URL,
        anomaly assessment, and composite risk score.
    """
    log.info("=" * 60)
    log.info("Starting analysis pipeline for: %s", url)

    report: dict = {"url": url}

    # ── Stage 1: SSRF Guard ─────────────────────────────────────────────────
    if not is_safe_url(url):
        log.warning("BLOCKED by SSRF guard: %s", url)
        report["ssrf_blocked"] = True
        report["risk_score"] = 0
        report["risk_level"] = "blocked"
        report["risk_signals"] = []
        report["normalized_url"] = url
        return report

    report["ssrf_blocked"] = False

    # ── Stage 2: Normalize ──────────────────────────────────────────────────
    try:
        log.info("[1/13] URL normalization…")
        norm_url = normalize_url(url)
        report["normalized_url"] = norm_url
    except Exception as exc:
        log.error("Normalization failed: %s", exc)
        norm_url = url
        report["normalized_url"] = url

    # ── Stage 2b: Tranco Whitelist Check ─────────────────────────────────────
    try:
        domain_for_check = report.get("normalized_url", url)
        # Extract domain from URL
        from urllib.parse import urlparse as _urlparse
        _tmp = domain_for_check
        if not _tmp.startswith(("http://", "https://")):
            _tmp = "https://" + _tmp
        _host = _urlparse(_tmp).hostname or domain_for_check
        report["tranco_whitelisted"] = is_whitelisted(_host)
        if report["tranco_whitelisted"]:
            log.info("[TRANCO] Domain '%s' is in Top 1M whitelist — low risk.", _host)
    except Exception as exc:
        log.debug("Tranco check failed: %s", exc)
        report["tranco_whitelisted"] = False

    # ── Stage 3: VirusTotal Reputation ─────────────────────────────────────
    try:
        log.info("[2/13] VirusTotal reputation check…")
        report.update(check_virustotal(norm_url))
    except Exception as exc:
        log.error("Reputation stage failed: %s", exc)
        report.update({"vt_malicious": 0, "vt_suspicious": 0,
                        "vt_harmless": 0, "vt_undetected": 0})

    # ── Stage 4: Domain Intelligence ────────────────────────────────────────
    try:
        log.info("[3/13] Domain intelligence (WHOIS + DNS + typosquatting)…")
        report.update(analyze_domain(norm_url))
    except Exception as exc:
        log.error("Domain intel stage failed: %s", exc)

    # ── Stage 4b: URLhaus Blacklist ─────────────────────────────────────────
    try:
        urlhaus_result = check_urlhaus(norm_url)
        report.update(urlhaus_result)
        if urlhaus_result.get("urlhaus_hit"):
            log.warning("[URLHAUS] URL/domain found in abuse.ch malware DB!")
    except Exception as exc:
        log.debug("URLhaus check failed: %s", exc)
        report["urlhaus_hit"] = False
        report["urlhaus_match"] = ""

    # ── Stage 5: Static Analysis ────────────────────────────────────────────
    try:
        log.info("[4/13] Static URL analysis…")
        report.update(analyze_static(norm_url))
    except Exception as exc:
        log.error("Static analysis stage failed: %s", exc)

    # ── Stage 6: Redirect Graph ─────────────────────────────────────────────
    try:
        log.info("[5/13] Redirect chain analysis…")
        report.update(analyze_redirects(norm_url))
    except Exception as exc:
        log.error("Redirect stage failed: %s", exc)
        report.update({"phish_redirect_count": 0, "final_url": norm_url})

    # ── Stage 7–10: Dynamic Analysis (Playwright) ───────────────────────────
    if skip_dynamic:
        log.info("[6/13] Dynamic analysis skipped (skip_dynamic=True).")
    else:
        try:
            log.info("[6/13] Dynamic analysis + API monitoring (headless browser)…")
            report.update(analyze_dynamic(norm_url))
        except Exception as exc:
            log.error("Dynamic analysis stage failed: %s", exc)

    # ── Stage 11: Anomaly Detection (Isolation Forest) ──────────────────────
    try:
        log.info("[7/13] Anomaly detection…")
        anomaly = score_anomaly(report)
        report.update(anomaly)
    except Exception as exc:
        log.error("Anomaly detection failed: %s", exc)
        report.update({"anomaly_score": 0.0, "is_anomaly": 0, "anomaly_percentile": 0.0})

    # ── Stage 12: ML Classifier (XGBoost) ──────────────────────────────
    try:
        log.info("[8/13] ML classifier (XGBoost)…")
        ml_result = ml_predict(report)
        report.update(ml_result)
    except Exception as exc:
        log.error("ML classification failed: %s", exc)
        report.update({"ml_prediction": "unknown", "ml_confidence": 0.0, "ml_probabilities": {}})

    # ── Stage 13: Composite Risk Scoring ───────────────────────────────
    try:
        log.info("[9/13] Computing composite risk score…")
        risk = compute_risk_score(report)
        report.update(risk)
    except Exception as exc:
        log.error("Risk scoring failed: %s", exc)
        report.update({"risk_score": 0, "risk_level": "unknown", "risk_signals": []})

    log.info("[13/13] Pipeline complete for: %s  → score=%s level=%s ml=%s anomaly=%s tranco=%s urlhaus=%s",
             url, report.get("risk_score"), report.get("risk_level"),
             report.get("ml_prediction", "n/a"),
             "YES" if report.get("is_anomaly") else "no",
             "WL" if report.get("tranco_whitelisted") else "no",
             "HIT" if report.get("urlhaus_hit") else "no")
    return report
