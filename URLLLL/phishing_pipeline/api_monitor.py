"""
api_monitor.py — API call sequence extraction via Playwright CDP.

Monitors all network-level API activity during dynamic page analysis:
  - XHR / fetch() requests
  - navigator.sendBeacon() calls
  - WebSocket connections
  - POST request bodies and destinations
  - Ordered request timeline with timestamps

Design:
  - Runs INSIDE the existing Playwright browser session
  - Uses page.on("request") / page.on("response") event hooks
  - Suspicious pattern detection is RULE-BASED (not ML)
  - Outputs both structured features and forensic timeline

Where it fits: Stage 9 (Network Behavior Analysis), runs during
the same Playwright session as dynamic_analysis.py.

What goes where:
  - api_total_requests, api_post_count, api_unique_domains → ML (numeric)
  - api_credential_exfil_risk, api_suspicious_patterns     → Risk scorer
  - api_timeline                                            → Forensic report only
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from .logger import get_logger

log = get_logger("api_monitor")

# ── Suspicious patterns (rule-based detection) ───────────────────────────────

# Credential-related parameter names in POST bodies or query strings
_CREDENTIAL_PARAMS = re.compile(
    r"\b(password|passwd|pwd|pass|secret|token|session|auth|"
    r"credit.?card|cvv|ssn|pin|otp|mfa)\b",
    re.IGNORECASE,
)

# Token/session in URL query string
_TOKEN_IN_URL = re.compile(
    r"[?&](token|session|auth|api.?key|access.?token|bearer)=",
    re.IGNORECASE,
)

# GraphQL endpoint indicators
_GRAPHQL_RE = re.compile(r"/graphql\b", re.IGNORECASE)


class APIMonitor:
    """
    Monitors API call sequences during a Playwright page load.

    Usage:
        monitor = APIMonitor(page_domain="example.com")
        page.on("request", monitor.on_request)
        page.on("response", monitor.on_response)
        # ... load the page ...
        results = monitor.get_results()
    """

    def __init__(self, page_domain: str):
        self.page_domain = page_domain.lower()
        self._start_time = time.time()

        # Collected data
        self._timeline: list[dict] = []
        self._post_requests: list[dict] = []
        self._xhr_fetch: list[dict] = []
        self._websockets: list[str] = []
        self._beacons: list[str] = []
        self._domains: set[str] = set()
        self._suspicious: list[str] = []

    def on_request(self, request) -> None:
        """Hook for page.on('request', ...)"""
        try:
            url = request.url
            method = request.method
            resource_type = request.resource_type
            timestamp = round(time.time() - self._start_time, 3)

            parsed = urlparse(url)
            domain = parsed.netloc.lower().split(":")[0]
            self._domains.add(domain)

            entry = {
                "time": timestamp,
                "method": method,
                "url": url[:500],
                "type": resource_type,
                "domain": domain,
                "is_external": domain != self.page_domain,
            }
            self._timeline.append(entry)

            # ── Track XHR/fetch ──────────────────────────────────────────
            if resource_type in ("xhr", "fetch"):
                self._xhr_fetch.append(entry)

            # ── Track POST requests ──────────────────────────────────────
            if method == "POST":
                post_entry = {**entry}
                try:
                    post_data = request.post_data or ""
                    post_entry["body_preview"] = post_data[:200]

                    # Check for credential data in POST body
                    if _CREDENTIAL_PARAMS.search(post_data):
                        self._suspicious.append(
                            f"CREDENTIAL data in POST to {domain}: "
                            f"body contains sensitive parameter"
                        )
                        post_entry["credential_risk"] = True
                except Exception:
                    post_entry["body_preview"] = ""

                self._post_requests.append(post_entry)

                # External POST = potential exfiltration
                if domain != self.page_domain and domain:
                    self._suspicious.append(
                        f"POST to external domain: {domain}"
                    )

            # ── Track WebSocket ──────────────────────────────────────────
            if url.startswith(("ws://", "wss://")):
                self._websockets.append(url)
                if domain != self.page_domain:
                    self._suspicious.append(
                        f"WebSocket to external domain: {domain}"
                    )

            # ── Token in URL ─────────────────────────────────────────────
            if _TOKEN_IN_URL.search(url):
                self._suspicious.append(
                    f"Token/session in URL: {url[:100]}"
                )

            # ── GraphQL detection ────────────────────────────────────────
            if _GRAPHQL_RE.search(url):
                self._suspicious.append(
                    f"GraphQL endpoint: {url[:100]}"
                )

        except Exception as exc:
            log.debug("Request hook error: %s", exc)

    def on_response(self, response) -> None:
        """Hook for page.on('response', ...) — captures beacon-like patterns."""
        try:
            url = response.url
            status = response.status

            # Beacon detection: 204 No Content responses (typical for sendBeacon)
            if status == 204:
                parsed = urlparse(url)
                domain = parsed.netloc.lower().split(":")[0]
                self._beacons.append(url)
                if domain != self.page_domain:
                    self._suspicious.append(
                        f"Beacon-like 204 response from external: {domain}"
                    )

        except Exception as exc:
            log.debug("Response hook error: %s", exc)

    def get_results(self) -> dict:
        """
        Compile all monitored data into a structured result dict.

        Returns features for both ML and rule engine.
        """
        total_time = round(time.time() - self._start_time, 3)

        # ── Detect rapid-fire requests ───────────────────────────────────
        if len(self._xhr_fetch) > 20 and total_time < 5:
            self._suspicious.append(
                f"Rapid-fire: {len(self._xhr_fetch)} XHR/fetch in {total_time}s"
            )

        # ── Count external POST ──────────────────────────────────────────
        external_posts = [p for p in self._post_requests if p.get("is_external")]
        credential_posts = [p for p in self._post_requests if p.get("credential_risk")]

        # ── Unique XHR domains ───────────────────────────────────────────
        xhr_domains = set(r["domain"] for r in self._xhr_fetch)
        if len(xhr_domains) > 3:
            self._suspicious.append(
                f"Multiple XHR target domains: {len(xhr_domains)} unique"
            )

        # De-duplicate suspicious patterns
        unique_suspicious = list(dict.fromkeys(self._suspicious))

        result = {
            # Numeric features (can feed into ML if retrained)
            "api_total_requests": len(self._timeline),
            "api_post_count": len(self._post_requests),
            "api_external_post_count": len(external_posts),
            "api_xhr_fetch_count": len(self._xhr_fetch),
            "api_unique_domains": len(self._domains),
            "api_websocket_count": len(self._websockets),
            "api_beacon_count": len(self._beacons),

            # Rule-based risk signals
            "api_credential_exfil_risk": 1 if credential_posts else 0,
            "api_suspicious_pattern_count": len(unique_suspicious),
            "api_suspicious_patterns": unique_suspicious,

            # Forensic timeline (not ML, not scoring — evidence only)
            "api_timeline": self._timeline[:100],  # Cap at 100 entries
            "api_monitoring_duration": total_time,
        }

        log.info(
            "API monitor: %d requests, %d XHR/fetch, %d POST (%d external), "
            "%d suspicious patterns in %.1fs",
            result["api_total_requests"],
            result["api_xhr_fetch_count"],
            result["api_post_count"],
            result["api_external_post_count"],
            result["api_suspicious_pattern_count"],
            total_time,
        )

        return result
