"""
dynamic_analysis.py — Steps 7–10: Headless browser analysis with Playwright.
Now includes API call sequence monitoring (Step 9b).

Stages covered:
    Step 7  — Dynamic page loading, SSL check, HTTP status, live check
    Step 8  — DOM & form analysis (BeautifulSoup over page HTML)
    Step 8b — Defacement detection (DOM content scanner)
    Step 8c — Hidden iframe detection, suspicious JS API scanning
    Step 9  — Network request interception (method, type, external domain tracking)
    Step 10 — Download link detection in page HTML
    JS/Meta — JavaScript and meta-refresh redirect detection
    Screenshot — saved as PNG to screenshots/
"""

from __future__ import annotations

import re
import hashlib
import datetime
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .config import DOWNLOAD_EXTENSIONS, PLAYWRIGHT_TIMEOUT, SCREENSHOTS_DIR
from .defacement_detector import detect_defacement
from .logger import get_logger

log = get_logger("dynamic_analysis")

# ── Regex helpers ─────────────────────────────────────────────────────────────
_DOWNLOAD_RE = re.compile(
    "|".join(re.escape(ext) for ext in DOWNLOAD_EXTENSIONS),
    re.IGNORECASE,
)

# Words that suggest a login form even without a password field
_LOGIN_WORDS_RE = re.compile(
    r"\b(login|log in|sign in|signin|username|email address)\b",
    re.IGNORECASE,
)

# ── JavaScript redirect patterns ─────────────────────────────────────────────
_JS_REDIRECT_RE = re.compile(
    r"""(?:window\.location|document\.location|location\.href|location\.replace)\s*[=\(]\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# ── Meta refresh pattern ─────────────────────────────────────────────────────
_META_REFRESH_RE = re.compile(
    r"""<meta\s+http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']\d+\s*;\s*url\s*=\s*([^"'>]+)""",
    re.IGNORECASE,
)

# ── Suspicious JS API patterns ───────────────────────────────────────────────
# ONLY truly suspicious APIs — NOT common ones like localStorage, XMLHttpRequest,
# atob, or FormData which are used on virtually every modern website.
_SUSPICIOUS_JS_APIS = [
    (r"\beval\s*\(", "eval()"),
    (r"\bunescape\s*\(", "unescape()"),
    (r"\bdocument\.cookie\b", "document.cookie"),
    (r"\bnavigator\.sendBeacon\b", "navigator.sendBeacon"),
    (r"\bdocument\.execCommand\b", "document.execCommand"),
    (r"\bpostMessage\s*\(", "postMessage()"),
    (r"\bwindow\.opener\b", "window.opener"),
]

# Default safe result returned when the browser cannot load the page
_DEFAULT = {
    "web_http_status":          0,
    "web_is_live":              0,
    "web_ssl_valid":            0,
    "web_forms_count":          0,
    "web_password_fields":      0,
    "web_hidden_inputs":        0,
    "web_has_login":            0,
    "web_unique_domains":       0,
    "web_ext_ratio":            0.0,
    "file_download_detected":   0,
    # Defacement
    "web_defacement_detected":  0,
    "web_defacement_confidence":"none",
    "web_defacement_reason":    "",
    # Screenshot
    "web_screenshot_path":      "",
    # JS/Meta redirects
    "phish_js_redirect_detected": 0,
    "phish_meta_refresh_detected": 0,
    "phish_js_redirect_urls":   [],
    # Hidden iframes
    "web_hidden_iframes":       0,
    # Suspicious JS
    "web_suspicious_js_apis":   0,
    "web_suspicious_js_details": [],
    # Network enrichment
    "web_post_requests":        0,
    "web_xhr_fetch_count":      0,
    # Form action analysis
    "web_external_form_action": 0,
}


# ─────────────────────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_base_domain(url: str) -> str:
    """Return the netloc (host:port) of a URL, lowercased."""
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def _screenshot_path(url: str) -> str:
    """
    Build a safe filesystem path for a screenshot PNG.
    Pattern: screenshots/<host>_<url_hash8>_<timestamp>.png
    """
    host = _get_base_domain(url) or "unknown"
    # Sanitize host for use as filename
    host_safe = re.sub(r"[^A-Za-z0-9.\-]", "_", host)[:40]
    url_hash = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{host_safe}_{url_hash}_{ts}.png"
    return str(SCREENSHOTS_DIR / filename)


def _analyze_dom(html: str, page_url: str) -> dict:
    """
    Parse the page HTML with BeautifulSoup and extract DOM features.
    Now includes: hidden iframe detection, suspicious JS APIs,
    form action analysis, and JS/meta redirect detection.
    """
    result = {
        "web_forms_count":            0,
        "web_password_fields":        0,
        "web_hidden_inputs":          0,
        "web_has_login":              0,
        "file_download_detected":     0,
        "web_hidden_iframes":         0,
        "web_suspicious_js_apis":     0,
        "web_suspicious_js_details":  [],
        "web_external_form_action":   0,
        "phish_js_redirect_detected": 0,
        "phish_meta_refresh_detected":0,
        "phish_js_redirect_urls":     [],
    }

    try:
        soup = BeautifulSoup(html, "html.parser")
        page_domain = _get_base_domain(page_url)

        # ── Form analysis ─────────────────────────────────────────────────────
        forms = soup.find_all("form")
        result["web_forms_count"] = len(forms)

        password_inputs = soup.find_all("input", {"type": re.compile(r"^password$", re.I)})
        result["web_password_fields"] = len(password_inputs)

        hidden_inputs = soup.find_all("input", {"type": re.compile(r"^hidden$", re.I)})
        result["web_hidden_inputs"] = len(hidden_inputs)

        # Login indicator: password field OR login-related text on page
        page_text = soup.get_text(" ", strip=True)
        has_password = len(password_inputs) > 0
        has_login_text = bool(_LOGIN_WORDS_RE.search(page_text))
        result["web_has_login"] = 1 if (has_password or has_login_text) else 0

        # ── Form action analysis ─────────────────────────────────────────
        for form in forms:
            action = form.get("action", "")
            if action:
                action_domain = _get_base_domain(action)
                if action_domain and action_domain != page_domain:
                    result["web_external_form_action"] = 1
                    log.warning("Form POSTs to external domain: %s", action)
                    break

        # ── Hidden iframe detection ──────────────────────────────────────
        iframes = soup.find_all("iframe")
        hidden_count = 0
        for iframe in iframes:
            style = (iframe.get("style") or "").lower()
            width = iframe.get("width", "")
            height = iframe.get("height", "")
            if ("display:none" in style or "display: none" in style or
                "visibility:hidden" in style or "visibility: hidden" in style or
                width in ("0", "1") or height in ("0", "1") or
                "opacity:0" in style or "opacity: 0" in style):
                hidden_count += 1
        result["web_hidden_iframes"] = hidden_count

        # ── Suspicious JavaScript API detection ──────────────────────────
        scripts = soup.find_all("script")
        all_script_text = " ".join(
            s.string or "" for s in scripts
        )
        js_hits: list[str] = []
        for pattern, name in _SUSPICIOUS_JS_APIS:
            if re.search(pattern, all_script_text):
                js_hits.append(name)
        result["web_suspicious_js_apis"] = len(js_hits)
        result["web_suspicious_js_details"] = js_hits

        # ── JavaScript redirect detection ────────────────────────────────
        js_redirect_urls: list[str] = []
        for m in _JS_REDIRECT_RE.finditer(all_script_text):
            js_redirect_urls.append(m.group(1))
        if js_redirect_urls:
            result["phish_js_redirect_detected"] = 1
            result["phish_js_redirect_urls"] = js_redirect_urls
            log.info("JS redirects found: %s", js_redirect_urls)

        # ── Meta refresh redirect detection ──────────────────────────────
        meta_matches = _META_REFRESH_RE.findall(html)
        if meta_matches:
            result["phish_meta_refresh_detected"] = 1
            result["phish_js_redirect_urls"].extend(meta_matches)
            log.info("Meta refresh redirects found: %s", meta_matches)

        # ── Download link detection ───────────────────────────────────────────
        for tag in soup.find_all(["a", "script", "iframe", "embed", "object"]):
            attr_val = tag.get("href") or tag.get("src") or tag.get("data") or ""
            if _DOWNLOAD_RE.search(attr_val):
                result["file_download_detected"] = 1
                log.debug("Download link found: %s", attr_val)
                break

    except Exception as exc:
        log.warning("_analyze_dom error: %s", exc)

    return result


def _analyze_network(intercepted: list[dict], base_domain: str) -> dict:
    """
    Compute external-domain metrics from intercepted network requests.
    Now captures request methods and resource types.
    """
    if not intercepted:
        return {
            "web_unique_domains": 0,
            "web_ext_ratio": 0.0,
            "web_post_requests": 0,
            "web_xhr_fetch_count": 0,
        }

    external_domains: list[str] = []
    post_count = 0
    xhr_fetch_count = 0

    for req in intercepted:
        url = req.get("url", "")
        method = req.get("method", "GET")
        res_type = req.get("resource_type", "")

        domain = _get_base_domain(url)
        if domain and domain != base_domain:
            external_domains.append(domain)

        if method.upper() == "POST":
            post_count += 1

        if res_type in ("xhr", "fetch"):
            xhr_fetch_count += 1

    unique_ext = len(set(external_domains))
    ext_ratio = round(len(external_domains) / len(intercepted), 4) if intercepted else 0.0

    return {
        "web_unique_domains": unique_ext,
        "web_ext_ratio": ext_ratio,
        "web_post_requests": post_count,
        "web_xhr_fetch_count": xhr_fetch_count,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_dynamic(url: str) -> dict:
    """
    Load the URL in a headless Chromium browser and extract all dynamic
    features: DOM structure, defacement signals, network behaviour,
    download detection, JS/meta redirects, hidden iframes, suspicious
    JS APIs, and a full-page screenshot.

    Args:
        url: URL to analyse (normalized URL recommended).

    Returns:
        Dict with all dynamic analysis features.
        Falls back to all-zero defaults on any error.
    """
    result = dict(_DEFAULT)

    # Lazy Playwright import — graceful degradation if not installed
    try:
        from playwright.sync_api import sync_playwright, Error as PlaywrightError
    except ImportError:
        log.error(
            "Playwright is not installed. "
            "Run: pip install playwright && playwright install chromium"
        )
        return result

    base_domain = _get_base_domain(url)
    intercepted_requests: list[dict] = []
    screenshot_dest = _screenshot_path(url)

    # API call sequence monitor — hooks into the same browser session
    from .api_monitor import APIMonitor
    api_monitor = APIMonitor(page_domain=base_domain)

    try:
        with sync_playwright() as pw:

            # ── Launch headless Chromium ──────────────────────────────────────
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--ignore-certificate-errors",
                ],
            )

            # Isolated browser context with realistic user-agent
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                # Give the browser a realistic viewport so screenshots look normal
                viewport={"width": 1280, "height": 800},
            )

            page = context.new_page()

            # ── Network interception (Step 9) — register BEFORE navigating ────
            def _on_request(request):
                try:
                    intercepted_requests.append({
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                    })
                except Exception:
                    pass

            page.on("request", _on_request)

            # Hook API monitor into the same page events
            page.on("request", api_monitor.on_request)
            page.on("response", api_monitor.on_response)

            # ── Navigate and capture HTTP status (Step 7) ─────────────────────
            http_status = 0
            ssl_valid = 0
            is_live = 0

            try:
                response = page.goto(
                    url,
                    timeout=PLAYWRIGHT_TIMEOUT,
                    wait_until="domcontentloaded",
                )

                if response:
                    http_status = response.status
                    is_live = 1 if 200 <= http_status < 400 else 0

                    # SSL check: only meaningful for HTTPS URLs
                    if url.lower().startswith("https://"):
                        try:
                            sec = response.security_details()
                            ssl_valid = 1 if sec else 0
                        except Exception:
                            ssl_valid = 0

                log.info(
                    "Page loaded: status=%d  ssl=%d  live=%d",
                    http_status, ssl_valid, is_live,
                )

            except PlaywrightError as nav_err:
                log.warning("Navigation error for '%s': %s", url, nav_err)
                is_live = 0

            # ── Wait for JS to settle (2s) ──────────────────────────────────
            try:
                page.wait_for_timeout(2000)
            except Exception:
                pass

            # ── Screenshot (BEFORE closing page) ─────────────────────────────
            screenshot_saved = ""
            try:
                page.screenshot(
                    path=screenshot_dest,
                    full_page=True,         # capture entire scrollable page
                    timeout=10_000,         # 10 s max
                )
                screenshot_saved = screenshot_dest
                log.info("Screenshot saved: %s", screenshot_saved)
            except Exception as sc_err:
                log.warning("Screenshot failed: %s", sc_err)

            # ── DOM analysis (Step 8) ─────────────────────────────────────────
            html_content = ""
            try:
                html_content = page.content()
                dom_features = _analyze_dom(html_content, url)
            except Exception as dom_err:
                log.warning("DOM extraction failed: %s", dom_err)
                dom_features = {}

            # ── Defacement detection (Step 8b) ────────────────────────────────
            defacement_features = {}
            try:
                defacement_features = detect_defacement(html_content)
            except Exception as def_err:
                log.warning("Defacement detection failed: %s", def_err)

            # ── Clean up browser ──────────────────────────────────────────────
            try:
                context.close()
                browser.close()
            except Exception:
                pass

            # ── Network analysis (Step 9) ─────────────────────────────────────
            net_features = _analyze_network(intercepted_requests, base_domain)

            # ── API sequence analysis (Step 9b) ───────────────────────────────
            api_results = api_monitor.get_results()

            # ── Assemble result ───────────────────────────────────────────────
            result.update({
                "web_http_status":    http_status,
                "web_is_live":        is_live,
                "web_ssl_valid":      ssl_valid,
                "web_screenshot_path": screenshot_saved,
            })
            result.update(dom_features)
            result.update(defacement_features)
            result.update(net_features)
            result.update(api_results)

            log.info("Dynamic analysis complete for '%s'.", url)

    except Exception as exc:
        log.error("analyze_dynamic unexpected error for '%s': %s", url, exc)

    return result
