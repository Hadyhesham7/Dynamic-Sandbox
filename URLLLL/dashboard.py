"""
dashboard.py — Interactive terminal dashboard for the Phishing URL Analysis Pipeline.

Usage modes:
    1. python dashboard.py
       → prompts for email text (or a single URL), then analyses all found URLs

    2. python dashboard.py "https://example.com"
       → analyses the URL passed as first cli argument directly

    3. Import and call programmatically:
       from dashboard import run_analysis
       results = run_analysis(email_text)
"""

from __future__ import annotations

import sys
import json
import os
from typing import Any

# Force UTF-8 output on Windows consoles (cp1252 can't render box-drawing / emoji)
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from phishing_pipeline.url_extractor import extract_urls
from phishing_pipeline.pipeline import analyze_url


# ─────────────────────────────────────────────────────────────────────────────
# Terminal formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

WIDTH = 72

def _line(char: str = "─") -> str:
    return char * WIDTH

def _header(title: str, char: str = "═") -> None:
    pad = (WIDTH - len(title) - 2) // 2
    print(f"\n{char * pad} {title} {char * (WIDTH - pad - len(title) - 2)}")

def _section(title: str) -> None:
    print(f"\n  ┌─ {title} {'─' * (WIDTH - len(title) - 5)}┐")

def _row(label: str, value: Any, indent: int = 4) -> None:
    label_str = f"{' ' * indent}{label}"
    val_str = str(value)
    dots = "." * max(1, WIDTH - len(label_str) - len(val_str) - 4)
    print(f"{label_str} {dots} {val_str}")

def _risk_badge(score: int, level: str) -> str:
    badges = {
        "clean":    f"✅  CLEAN ({score}/100)",
        "low":      f"⚠️   LOW RISK ({score}/100)",
        "medium":   f"🔶  MEDIUM RISK ({score}/100)",
        "high":     f"🔴  HIGH RISK ({score}/100)",
        "critical": f"🚨  CRITICAL ({score}/100) ← LIKELY PHISHING",
        "blocked":  f"🛑  BLOCKED (internal IP / SSRF)",
    }
    return badges.get(level, f"❓  UNKNOWN ({score}/100)")

def _yn(val: int | float) -> str:
    return "YES" if val else "NO"


# ─────────────────────────────────────────────────────────────────────────────
# Report printer
# ─────────────────────────────────────────────────────────────────────────────

def print_report(report: dict) -> None:
    """Pretty-print a single URL analysis report to the terminal."""

    risk_score = report.get("risk_score", 0)
    risk_level = report.get("risk_level", "unknown")

    _header("PHISHING URL ANALYSIS REPORT", "═")
    print(f"  {'URL analyzed':30s}: {report.get('url', 'N/A')}")
    print(f"  {'Normalized URL':30s}: {report.get('normalized_url', 'N/A')}")
    print(f"\n  {'RISK ASSESSMENT':30s}: {_risk_badge(risk_score, risk_level)}")
    print(_line())

    if report.get("ssrf_blocked"):
        print("\n  🛑  URL was BLOCKED by SSRF guard (resolves to internal IP).")
        print(_line("═"))
        return

    # ── Reputation ────────────────────────────────────────────────────────────
    _section("🛡  VirusTotal Reputation")
    _row("Malicious engines",  report.get("vt_malicious",  "N/A"))
    _row("Suspicious engines", report.get("vt_suspicious", "N/A"))
    _row("Harmless engines",   report.get("vt_harmless",   "N/A"))
    _row("Undetected engines", report.get("vt_undetected", "N/A"))

    # ── Domain Intelligence ───────────────────────────────────────────────────
    _section("🌐  Domain Intelligence")
    _row("Registered domain",       report.get("domain", "N/A"))
    _row("Multiple subdomains",     _yn(report.get("phish_multiple_subdomains", 0)))
    _row("Long domain (>30 chars)", _yn(report.get("phish_adv_long_domain", 0)))
    _row("Suspicious TLD",          _yn(report.get("phish_suspicious_tld", 0)))
    _row("Government / Education",  _yn(report.get("is_gov_edu", 0)))

    # WHOIS
    age = report.get("domain_age_days", -1)
    _row("Domain age (days)",       age if age >= 0 else "Unknown")
    _row("WHOIS registrar",         report.get("whois_registrar", "N/A")[:50] or "N/A")
    _row("Newly registered (<30d)", _yn(report.get("newly_registered_domain", 0)))
    _row("WHOIS privacy/proxy",    _yn(report.get("whois_privacy", 0)))

    # DNS
    _row("DNS A record count",      report.get("dns_ip_count", "N/A"))
    _row("DNS min TTL",             report.get("dns_ttl_min", "N/A"))
    _row("Has MX record",           _yn(report.get("dns_has_mx", 0)))
    _row("Fast flux suspected",     "⚠️ YES" if report.get("fast_flux_detected") else "NO")

    # Typosquatting
    typo_brand = report.get("typosquat_target_brand", "")
    typo_score = report.get("typosquat_score", 99)
    if typo_brand:
        _row("Typosquatting target",    f"⚠️ {typo_brand} (distance={typo_score})")
    else:
        _row("Typosquatting target",    "None detected")

    # ── Static / Lexical Analysis ─────────────────────────────────────────────
    _section("🔬  Static URL Analysis")
    _row("URL length",              report.get("url_len", "N/A"))
    _row("'@' characters",          report.get("at_sign", "N/A"))
    _row("'?' characters",          report.get("question_mark", "N/A"))
    _row("'-' characters",          report.get("hyphen", "N/A"))
    _row("'=' characters",          report.get("equals", "N/A"))
    _row("'.' characters",          report.get("dots", "N/A"))
    _row("Digit count",             report.get("digits", "N/A"))
    _row("Letter count",            report.get("letters", "N/A"))
    _row("IP address in host",      _yn(report.get("having_ip_address", 0)))
    _row("URL shortener",           _yn(report.get("shortening_service", 0)))
    _row("Abnormal URL",            _yn(report.get("abnormal_url", 0)))
    _row("Hyphens in hostname",     report.get("phish_adv_hyphen_count", "N/A"))
    _row("Digit blocks in hostname",report.get("phish_adv_number_count", "N/A"))
    _row("URL entropy",             report.get("url_entropy", "N/A"))
    _row("Suspicious keywords",     report.get("suspicious_keyword_count", "N/A"))
    _row("Path depth",              report.get("path_depth", "N/A"))
    _row("Query param count",       report.get("query_param_count", "N/A"))
    _row("Subdomain count",         report.get("num_subdomains", "N/A"))

    # ── Redirect Chain ────────────────────────────────────────────────────────
    _section("🔀  Redirect Chain Analysis")
    _row("Redirect hops",          report.get("phish_redirect_count", "N/A"))
    _row("Final URL",              report.get("final_url", "N/A"))
    _row("Domains involved",       report.get("phish_redirect_domains", "N/A"))
    _row("Cross-domain redirects", report.get("phish_cross_domain_redirects", "N/A"))
    _row("Open redirect abuse",    "⚠️ YES" if report.get("phish_open_redirect_abuse") else "NO")
    _row("Total redirect time",    f"{report.get('phish_redirect_time', 0)}s")
    _row("Redirect loop",          "⚠️ YES" if report.get("phish_redirect_loop") else "NO")
    _row("JS redirect detected",   "⚠️ YES" if report.get("phish_js_redirect_detected") else "NO")
    _row("Meta refresh detected",  "⚠️ YES" if report.get("phish_meta_refresh_detected") else "NO")

    if report.get("visual_graph"):
        _section("🕸  Redirect Graph")
        print(f"\n{report.get('visual_graph')}")

    # ── Dynamic Analysis ──────────────────────────────────────────────────────
    _section("🤖  Dynamic Analysis (Headless Browser)")
    _row("HTTP status code",    report.get("web_http_status",     "N/A"))
    _row("Page is live",        _yn(report.get("web_is_live",     0)))
    _row("SSL certificate OK",  _yn(report.get("web_ssl_valid",   0)))
    _row("Forms found",         report.get("web_forms_count",     "N/A"))
    _row("Password fields",     report.get("web_password_fields", "N/A"))
    _row("Hidden inputs",       report.get("web_hidden_inputs",   "N/A"))
    _row("Login page detected", _yn(report.get("web_has_login",   0)))
    _row("Hidden iframes",      report.get("web_hidden_iframes",  "N/A"))
    _row("Suspicious JS APIs",  report.get("web_suspicious_js_apis", "N/A"))
    _row("External form action",_yn(report.get("web_external_form_action", 0)))

    js_details = report.get("web_suspicious_js_details", [])
    if js_details:
        _row("JS APIs found",   ", ".join(js_details))

    # ── Defacement ────────────────────────────────────────────────────────────
    _section("☠️  Defacement Check")
    is_defaced = report.get("web_defacement_detected")
    _row("Defacement detected", "⚠️ YES" if is_defaced else "NO")
    if is_defaced:
        _row("Confidence",      str(report.get("web_defacement_confidence", "N/A")).upper())
        _row("Reason",          report.get("web_defacement_reason", ""))

    # ── Network & External Resources ──────────────────────────────────────────
    _section("📡  Network Behaviour Analysis")
    ext_ratio = report.get("web_ext_ratio", 0)
    _row("Unique external domains", report.get("web_unique_domains",  "N/A"))
    _row("External request ratio",  f"{ext_ratio:.1%}" if isinstance(ext_ratio, float) else ext_ratio)
    _row("POST requests captured",  report.get("web_post_requests", "N/A"))
    _row("XHR/fetch requests",      report.get("web_xhr_fetch_count", "N/A"))

    # ── Download Detection ────────────────────────────────────────────────────
    _section("⬇️   Download Detection")
    _row("Suspicious download link",
         "⚠️  YES — potential dropper!" if report.get("file_download_detected") else "NO")

    # ── Screenshot ────────────────────────────────────────────────────────────
    screenshot_path = report.get("web_screenshot_path")
    if screenshot_path:
        _section("📸  Screenshot Captured")
        _row("Saved to", screenshot_path)

    # ── Anomaly Detection ─────────────────────────────────────────────────────
    _section("🔮  Anomaly Detection (Isolation Forest)")
    anomaly_score = report.get("anomaly_score", 0.0)
    is_anomaly = report.get("is_anomaly", 0)
    anomaly_pct = report.get("anomaly_percentile", 0.0)
    _row("Anomaly score",      f"{anomaly_score:.4f}")
    _row("Anomaly percentile", f"{anomaly_pct:.1f}%")
    _row("Verdict",            "⚠️  ANOMALOUS — deviates from normal URL patterns" if is_anomaly
                                else "✅  Normal — within expected patterns")

    # ── ML Classifier ─────────────────────────────────────────────────────────
    _section("🤖  ML Classifier (XGBoost)")
    ml_pred = report.get("ml_prediction", "unknown")
    ml_conf = report.get("ml_confidence", 0.0)
    ml_probs = report.get("ml_probabilities", {})
    _row("Prediction",  ml_pred.upper())
    _row("Confidence",  f"{ml_conf:.1%}")
    if ml_probs:
        for cls_name, prob in ml_probs.items():
            _row(f"  P({cls_name})", f"{prob:.3f}")

    # ── API Sequence Monitor ──────────────────────────────────────────────────
    if report.get("api_total_requests", 0) > 0:
        _section("📡  API Call Sequence Monitor")
        _row("Total API requests",    report.get("api_total_requests", 0))
        _row("XHR/fetch calls",       report.get("api_xhr_fetch_count", 0))
        _row("POST requests",         report.get("api_post_count", 0))
        _row("External POSTs",        report.get("api_external_post_count", 0))
        _row("WebSocket connections",  report.get("api_websocket_count", 0))
        _row("Beacon calls",          report.get("api_beacon_count", 0))
        _row("Unique target domains",  report.get("api_unique_domains", 0))
        _row("Credential exfil risk",
             "⚠️  YES" if report.get("api_credential_exfil_risk") else "NO")
        suspicious = report.get("api_suspicious_patterns", [])
        if suspicious:
            _row("Suspicious patterns", len(suspicious))
            for i, pattern in enumerate(suspicious[:5], 1):
                _row(f"  [{i}]", pattern)

    # ── ⚠️  COMPOSITE RISK ANALYSIS ──────────────────────────────────────────
    risk_signals = report.get("risk_signals", [])
    print(f"\n  {'═' * (WIDTH - 2)}")
    print(f"  🎯  COMPOSITE RISK SCORE: {risk_score}/100  ({risk_level.upper()})")
    print(f"  {'─' * (WIDTH - 2)}")

    if risk_signals:
        print(f"  Risk signals that contributed to the score:")
        print(f"  {'─' * (WIDTH - 2)}")
        for i, (points, reason) in enumerate(risk_signals, start=1):
            # Word-wrap each reason to fit within WIDTH
            prefix = f"  [{i}] +{points:2d} pts │ "
            wrapped = [reason[j:j+WIDTH-len(prefix)] for j in range(0, len(reason), WIDTH-len(prefix))]
            print(f"{prefix}{wrapped[0]}")
            for continuation in wrapped[1:]:
                print(f"  {'':>9}│ {continuation}")
        print()
    else:
        print(f"  ✅  NO RISK SIGNALS DETECTED — URL appears clean based on all checks.")
    print(f"  {'═' * (WIDTH - 2)}")

    # ── JSON raw dump ─────────────────────────────────────────────────────────
    # Remove non-serializable items for clean JSON output
    json_report = {k: v for k, v in report.items()
                   if not isinstance(v, (list,)) or all(isinstance(i, (str, int, float)) for i in v)}
    json_report["risk_signals"] = [
        {"points": p, "reason": r} for p, r in report.get("risk_signals", [])
    ]

    print(f"\n  {'─' * (WIDTH - 2)}")
    print("  Raw JSON report:")
    print(json.dumps(json_report, indent=4, default=str))
    print(_line("═"))


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis(
    email_text: str,
    skip_dynamic: bool = False,
) -> list[dict]:
    """
    Extract URLs from email_text, analyse each one, and return the list
    of result dicts (one per URL).

    Args:
        email_text:    Raw email body or a plain URL string.
        skip_dynamic:  If True, skip the Playwright dynamic analysis stage.

    Returns:
        List of analysis report dicts.
    """
    urls = extract_urls(email_text)

    # Fallback 1: starts with http/https but regex didn't match
    if not urls:
        stripped = email_text.strip()
        if stripped.startswith(("http://", "https://")):
            urls = [stripped]

    # Fallback 2: bare URL with no scheme at all (e.g., just pasted from CSV)
    if not urls:
        stripped = email_text.strip().rstrip("/")
        # Looks like a domain if it has a dot and no spaces
        if "." in stripped and " " not in stripped and len(stripped) < 2048:
            candidate = "https://" + stripped
            urls = [candidate]

    if not urls:
        print("\n  ⚠️  No URLs found in the provided text.")
        print("  Tip: paste a full URL (with or without http://) or an email containing URLs.")
        return []

    print(f"\n  Found {len(urls)} URL(s) to analyse.\n")

    results: list[dict] = []
    for i, url in enumerate(urls, start=1):
        print(_line("─"))
        print(f"  Analysing URL {i}/{len(urls)}: {url}")
        print(_line("─"))
        report = analyze_url(url, skip_dynamic=skip_dynamic)
        print_report(report)
        results.append(report)

    # ── Auto-generate HTML dashboard ──
    try:
        _this_dir = os.path.dirname(os.path.abspath(__file__))
        _html_mod_path = os.path.join(_this_dir, "url_html_report.py")
        if os.path.isfile(_html_mod_path):
            import importlib.util
            import webbrowser
            spec = importlib.util.spec_from_file_location("url_html_report", _html_mod_path)
            _mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(_mod)
            html_path = os.path.join(_this_dir, "url_report.html")
            _mod.generate_url_html_report(results, html_path)
            abs_html = os.path.abspath(html_path)
            webbrowser.open(f"file:///{abs_html.replace(os.sep, '/')}")
    except Exception as html_err:
        print(f"\n  ⚠️  HTML dashboard generation failed: {html_err}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Interactive CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    WIDTH = 60

    print("=" * WIDTH)

    print(" ██   ██ ███████ ███    ██ ██████  ██    ██ ")
    print(" ██   ██ ██      ████   ██ ██   ██  ██  ██  ")
    print(" ███████ █████   ██ ██  ██ ██   ██   ████   ")
    print(" ██   ██ ██      ██  ██ ██ ██   ██    ██    ")
    print(" ██   ██ ███████ ██   ████ ██████     ██    ")

    print("\n  URL Analysis Engine v2.0 — Full Pipeline")

    print("=" * WIDTH)


if __name__ == "__main__":
    main()

    # CLI argument: python dashboard.py "https://..."
    if len(sys.argv) > 1:
        input_text = " ".join(sys.argv[1:])
        print(f"\n  Input from CLI args: {input_text[:80]}…" if len(input_text) > 80 else f"\n  Input: {input_text}")
    else:
        print("\n  Paste your email text below and press Enter twice")
        print("  (or type a single URL and press Enter):\n")
        lines: list[str] = []
        try:
            while True:
                line = input()
                if line == "" and lines and lines[-1] == "":
                    break
                lines.append(line)
        except EOFError:
            pass
        input_text = "\n".join(lines)

    if not input_text.strip():
        print("\n  ⚠️  No input provided. Exiting.")
        sys.exit(0)

    # Ask about dynamic analysis
    print("\n  Run dynamic analysis (Playwright headless browser)? [Y/n]: ", end="")
    try:
        dyn_choice = input().strip().lower()
    except EOFError:
        dyn_choice = "y"
    skip_dyn = dyn_choice in ("n", "no")

    run_analysis(input_text, skip_dynamic=skip_dyn)
