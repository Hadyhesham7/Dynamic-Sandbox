"""
master_orchestrator.py — KNOWHOW Unified Analysis Platform
===========================================================
Single entry point that routes inputs to the correct subsystem
and handles cross-subsystem handover logic.

Architecture:
    Input → Dispatcher → Subsystem A (File) or Subsystem B (URL) or Email
                        → Convergence 1: Download Handover
                        → Convergence 2: Overwatch Hooking
                        → Unified Report + HTML Dashboards

Usage:
    orchestrator = MasterOrchestrator()
    report = orchestrator.analyze("https://evil-site.com")
    report = orchestrator.analyze("C:/samples/malware.exe")
    report = orchestrator.analyze("C:/inbox/phish.eml")

CLI:
    python sandbox/master_orchestrator.py "https://evil-site.com"
    python sandbox/master_orchestrator.py malware.exe
    python sandbox/master_orchestrator.py phish.eml
"""

import os
import sys
import re
import time
import json
import subprocess

# Force UTF-8 on Windows console
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ─── Path setup ──────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

# Subsystem A: File Sandbox (same repo)
sys.path.insert(0, SCRIPT_DIR)

# Subsystem B: URL Pipeline
URL_PIPELINE_DIR = os.path.join(PROJECT_ROOT, "URLLLL")
if not os.path.isdir(URL_PIPELINE_DIR):
    print(f"[MASTER] WARNING: URLLLL directory not found at: {URL_PIPELINE_DIR}")
    print(f"[MASTER] Expected layout: <project_root>/URLLLL/phishing_pipeline/")
sys.path.insert(0, URL_PIPELINE_DIR)


# ─────────────────────────────────────────────────────────────────────────────
# MasterOrchestrator
# ─────────────────────────────────────────────────────────────────────────────

class MasterOrchestrator:
    """
    Unified analysis entry point for the KNOWHOW Sandbox.

    Routes inputs to Subsystem A (File Sandbox) or Subsystem B (URL Pipeline),
    handles cross-subsystem convergence, and produces a unified report.
    """

    # TLD pattern for bare URL detection
    _URL_PATTERN = re.compile(
        r"^https?://|"
        r"^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,}",
        re.IGNORECASE
    )

    def __init__(self, overwatch=False, timeout=60, mode="local",
                 skip_dynamic=False):
        """
        Args:
            overwatch: Enable Convergence Point 2 — hook the browser process.
            timeout:   Max execution time for file sandbox (seconds).
            mode:      "local" (mock network) or "vm" (FakeNet-NG).
            skip_dynamic: Skip Playwright dynamic analysis for URLs.
        """
        self.overwatch = overwatch
        self.timeout = timeout
        self.mode = mode
        self.skip_dynamic = skip_dynamic
        self.report = {}

    # ─────────────────────────────────────────────────────────────────────
    # STEP 1: Global Dispatcher (Router)
    # ─────────────────────────────────────────────────────────────────────

    def analyze(self, input_data: str) -> dict:
        """
        Primary entry point. Detects input type and routes accordingly.

        Supported inputs:
          - URL string → Subsystem B (URL Pipeline)
          - File path (.exe, .dll, etc.) → Subsystem A (File Sandbox)
          - Email file (.eml) → Extract → Route attachments + URLs

        Returns:
            Unified report dict containing findings from all subsystems.
        """
        self.report = {
            "input": input_data,
            "input_type": None,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "subsystem_a": None,      # File Sandbox results
            "subsystem_b": None,      # URL Pipeline results (list)
            "email_extraction": None,  # Email metadata
            "handover": [],            # Convergence 1: download/email attachment → sandbox (list)
            "overwatch": None,         # Convergence 2: browser hooking
            "unified_verdict": {},
        }

        # ─── EMAIL Input ───
        if input_data.lower().endswith(".eml") and os.path.isfile(input_data):
            self.report["input_type"] = "EMAIL"
            print(f"[MASTER] Input classified as EMAIL → extracting & routing")
            self._process_email(input_data)

        # ─── URL Input ───
        elif self._is_url(input_data):
            self.report["input_type"] = "URL"
            print(f"[MASTER] Input classified as URL → routing to Subsystem B")
            self._run_url_pipeline([input_data])

        # ─── FILE Input ───
        elif os.path.isfile(input_data):
            self.report["input_type"] = "FILE"
            print(f"[MASTER] Input classified as FILE → routing to Subsystem A")
            self._run_file_sandbox(input_data)

        else:
            print(f"[MASTER] ERROR: Input is neither a valid URL, file, nor .eml")
            self.report["error"] = "Unrecognized input type"
            return self.report

        # Generate unified verdict
        self._compute_unified_verdict()

        # Save unified report
        self._save_report()

        return self.report

    def _is_url(self, input_data: str) -> bool:
        """Determine if input is a URL (vs a local file path)."""
        if os.path.isfile(input_data):
            return False
        return bool(self._URL_PATTERN.match(input_data.strip()))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 2: Email Processing
    # ─────────────────────────────────────────────────────────────────────

    def _process_email(self, eml_path: str):
        """
        Parse .eml file, extract attachments and URLs,
        route each to the appropriate subsystem.
        """
        print(f"[MASTER] ── Email Extraction ──")

        try:
            from email_extractor import EmailExtractor
        except ImportError:
            _ext_path = os.path.join(SCRIPT_DIR, "email_extractor.py")
            import importlib.util
            spec = importlib.util.spec_from_file_location("email_extractor", _ext_path)
            _mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(_mod)
            EmailExtractor = _mod.EmailExtractor

        output_dir = os.path.join(SCRIPT_DIR, "reports", "artifacts", "email_extracted")
        extractor = EmailExtractor(eml_path, output_dir)
        extraction = extractor.extract()
        extractor.print_summary(extraction)

        self.report["email_extraction"] = extraction

        # ── Route extracted URLs to Subsystem B ──
        urls = [u["url"] for u in extraction.get("urls", [])]
        if urls:
            print(f"[MASTER] Routing {len(urls)} URL(s) to Subsystem B")
            self._run_url_pipeline(urls)

        # ── Route extracted attachments to Subsystem A ──
        # Route by extension OR by detected binary magic bytes (PE/OLE/ZIP)
        attachments = extraction.get("attachments", [])
        sandboxable_atts = [
            a for a in attachments
            if a.get("is_dangerous")
            or a.get("detected_type") in ("PE_EXECUTABLE", "OLE_DOCUMENT", "ZIP_ARCHIVE")
        ]

        if sandboxable_atts:
            print(f"[MASTER] Found {len(sandboxable_atts)} sandboxable attachment(s)")
            for att in sandboxable_atts:
                save_path = att.get("save_path", "")
                if save_path and os.path.isfile(save_path):
                    reason = att.get('detected_type', att.get('extension', 'unknown'))
                    print(f"[MASTER] Routing attachment to Subsystem A: {att['filename']} ({reason})")
                    self._run_file_sandbox(save_path, is_handover=True,
                                          handover_source="email_attachment")
                else:
                    print(f"[MASTER] WARNING: Attachment not saved: {att['filename']}")

    # ─────────────────────────────────────────────────────────────────────
    # STEP 3: Subsystem B — URL Pipeline
    # ─────────────────────────────────────────────────────────────────────

    def _run_url_pipeline(self, urls: list):
        """
        Execute the 13-stage URL phishing pipeline for each URL.
        After completion, check for download handover.
        """
        print(f"[MASTER] ── Subsystem B: URL Pipeline ({len(urls)} URLs) ──")

        try:
            from phishing_pipeline.pipeline import analyze_url
        except ImportError:
            print("[MASTER] ERROR: Cannot import phishing_pipeline. Check URLLLL path.")
            self.report["subsystem_b"] = {"error": "phishing_pipeline not found"}
            return

        all_results = []
        for i, url in enumerate(urls, 1):
            print(f"\n[MASTER] ── URL {i}/{len(urls)}: {url[:80]} ──")
            try:
                url_report = analyze_url(url, skip_dynamic=self.skip_dynamic)
                all_results.append(url_report)

                risk = url_report.get("risk_score", "?")
                level = url_report.get("risk_level", "?")
                ml = url_report.get("ml_prediction", "?")
                print(f"[MASTER]   Score: {risk}/100 | Level: {level} | ML: {ml}")

                # Check download handover for each URL
                self._check_download_handover(url_report)

            except Exception as e:
                print(f"[MASTER] ERROR analyzing URL: {e}")
                all_results.append({"url": url, "error": str(e)})

        self.report["subsystem_b"] = all_results

        # Generate URL HTML dashboard
        self._generate_url_dashboard(all_results)

        # Print terminal dashboard for each URL
        try:
            from dashboard import print_report
            for r in all_results:
                if "error" not in r:
                    print_report(r)
        except Exception as e:
            print(f"[MASTER] Terminal dashboard skipped: {e}")

    def _generate_url_dashboard(self, url_results):
        """Generate the URL HTML dashboard."""
        try:
            _html_path = os.path.join(URL_PIPELINE_DIR, "url_html_report.py")
            if os.path.isfile(_html_path):
                import importlib.util
                spec = importlib.util.spec_from_file_location("url_html_report", _html_path)
                _mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(_mod)

                output_path = os.path.join(SCRIPT_DIR, "reports", "url_report.html")
                email_meta = None
                if self.report.get("email_extraction"):
                    email_meta = self.report["email_extraction"].get("metadata")

                _mod.generate_url_html_report(url_results, output_path, email_meta)

                # Auto-open in browser
                import webbrowser
                abs_path = os.path.abspath(output_path)
                webbrowser.open(f"file:///{abs_path.replace(os.sep, '/')}")
                print(f"[MASTER] URL dashboard opened: {output_path}")
            else:
                print(f"[MASTER] URL HTML report module not found at {_html_path}")
        except Exception as e:
            print(f"[MASTER] WARNING: URL dashboard generation failed: {e}")

    # ─────────────────────────────────────────────────────────────────────
    # STEP 4: Convergence Point 1 — Download Handover
    # ─────────────────────────────────────────────────────────────────────

    def _check_download_handover(self, url_report: dict):
        """
        If the URL pipeline detected an executable payload download,
        hand it over to Subsystem A for deep OS-level analysis.
        """
        download_detected = url_report.get("file_download_detected", 0)
        is_executable = url_report.get("dl_is_executable", 0)
        double_ext = url_report.get("dl_double_extension", 0)
        dl_sha256 = url_report.get("dl_sha256", "")
        dl_filename = url_report.get("dl_filename", "")

        should_handover = (
            (download_detected and is_executable) or
            double_ext or
            (dl_sha256 and "malicious" in url_report.get("dl_vt_result", "").lower())
        )

        if not should_handover:
            return

        print(f"[MASTER] ══════════════════════════════════════════════")
        print(f"[MASTER] DOWNLOAD HANDOVER TRIGGERED")
        print(f"[MASTER]   File: {dl_filename}")
        print(f"[MASTER]   SHA256: {dl_sha256[:32]}...")
        print(f"[MASTER] ══════════════════════════════════════════════")

        payload_path = self._locate_downloaded_payload(dl_filename, dl_sha256)

        if payload_path:
            print(f"[MASTER] Handing payload to Subsystem A: {payload_path}")
            self._run_file_sandbox(payload_path, is_handover=True,
                                  handover_source=url_report.get("url", ""))
        else:
            print(f"[MASTER] WARNING: Downloaded payload not found on disk.")
            self.report["handover"] = {
                "triggered": True,
                "reason": "executable_download",
                "filename": dl_filename,
                "status": "payload_not_found",
            }

    def _locate_downloaded_payload(self, filename: str, sha256: str):
        """Search for the downloaded payload in known locations."""
        import hashlib
        import tempfile

        search_dirs = [
            tempfile.gettempdir(),
            os.path.expandvars(r"%USERPROFILE%\Downloads"),
            os.path.join(SCRIPT_DIR, "reports", "artifacts", "downloads"),
            os.path.join(SCRIPT_DIR, "reports", "artifacts", "email_extracted"),
        ]

        for directory in search_dirs:
            if not os.path.isdir(directory):
                continue
            for root, _, files in os.walk(directory):
                for f in files:
                    if f == filename:
                        full_path = os.path.join(root, f)
                        if sha256:
                            try:
                                h = hashlib.sha256()
                                with open(full_path, "rb") as fh:
                                    for chunk in iter(lambda: fh.read(8192), b""):
                                        h.update(chunk)
                                if h.hexdigest() == sha256:
                                    return full_path
                            except (PermissionError, OSError):
                                continue
                        else:
                            return full_path
        return None

    # ─────────────────────────────────────────────────────────────────────
    # STEP 5: Subsystem A — File Sandbox
    # ─────────────────────────────────────────────────────────────────────

    def _run_file_sandbox(self, filepath: str, is_handover=False,
                          handover_source=""):
        """
        Execute the full file sandbox pipeline via analyze.py subprocess.
        """
        import ctypes

        label = "HANDOVER" if is_handover else "FILE SANDBOX"
        print(f"[MASTER] ── Subsystem A: {label} ──")
        print(f"[MASTER]   Target: {os.path.basename(filepath)}")

        # Admin check
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False

        if not is_admin:
            print(f"[MASTER] WARNING: Not running as Administrator!")
            print(f"[MASTER]   DLL injection will fail without elevation.")
            result = {
                "error": "Elevation required for DLL injection",
                "file": os.path.basename(filepath),
            }
            if is_handover:
                if not isinstance(self.report["handover"], list):
                    self.report["handover"] = []
                self.report["handover"].append({
                    "triggered": True,
                    "status": "skipped_no_admin",
                    "source": handover_source,
                    "reason": "Elevation required",
                })
            else:
                self.report["subsystem_a"] = result
            return

        # Run analyze.py as subprocess (it handles the full pipeline)
        analyze_py = os.path.join(SCRIPT_DIR, "analyze.py")
        cmd = [
            sys.executable, analyze_py,
            filepath,
            "--timeout", str(self.timeout),
        ]

        print(f"[MASTER]   Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd, cwd=SCRIPT_DIR,
                capture_output=True, text=True,
                timeout=self.timeout + 30,
            )
            print(proc.stdout[-2000:] if len(proc.stdout) > 2000 else proc.stdout)
            if proc.stderr:
                print(f"[MASTER]   STDERR: {proc.stderr[-500:]}")

            # Load the generated report
            final_report_path = os.path.join(SCRIPT_DIR, "reports", "final_report.json")
            if os.path.isfile(final_report_path):
                with open(final_report_path) as f:
                    sandbox_result = json.load(f)
            else:
                sandbox_result = {
                    "status": "completed",
                    "output": proc.stdout[-1000:],
                }

        except subprocess.TimeoutExpired:
            print(f"[MASTER] Sandbox timed out after {self.timeout + 30}s")
            sandbox_result = {"error": "timeout"}
        except Exception as e:
            print(f"[MASTER] Sandbox error: {e}")
            sandbox_result = {"error": str(e)}

        # Store results
        if is_handover:
            if not isinstance(self.report["handover"], list):
                self.report["handover"] = []
            self.report["handover"].append({
                "triggered": True,
                "status": "completed",
                "source": handover_source,
                "payload_file": os.path.basename(filepath),
                "sandbox_result": sandbox_result,
            })
        else:
            self.report["subsystem_a"] = sandbox_result

    # ─────────────────────────────────────────────────────────────────────
    # STEP 6: Convergence Point 2 — Overwatch Hooking
    # ─────────────────────────────────────────────────────────────────────

    def _run_overwatch(self, url_report: dict):
        """
        EXPERIMENTAL: Hook into Playwright's Chromium to detect browser exploits.
        """
        print(f"[MASTER] ── Convergence 2: Overwatch Hooking ──")
        chrome_pid = self._find_chromium_pid()

        if not chrome_pid:
            self.report["overwatch"] = {
                "enabled": True,
                "status": "no_browser_pid",
            }
            return

        print(f"[MASTER]   Chromium PID: {chrome_pid}")
        self.report["overwatch"] = {
            "enabled": True,
            "chrome_pid": chrome_pid,
            "status": "monitoring",
            "note": "Requires DLL injection into chrome.exe",
        }

    def _find_chromium_pid(self):
        """Locate the Playwright-launched Chromium process."""
        try:
            result = subprocess.run(
                ["wmic", "process", "where",
                 "name='chrome.exe' and commandline like '%headless%'",
                 "get", "processid"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line.isdigit():
                    return int(line)
        except Exception:
            pass
        return None

    # ─────────────────────────────────────────────────────────────────────
    # STEP 7: Unified Verdict
    # ─────────────────────────────────────────────────────────────────────

    def _compute_unified_verdict(self):
        """Merge findings from all subsystems into a single threat assessment."""
        url_score = 0
        sandbox_score = 0
        email_risk = "NONE"
        verdict_signals = []

        # ── Email extraction indicators ──
        email_ext = self.report.get("email_extraction") or {}
        if email_ext:
            email_summary = email_ext.get("summary", {})
            email_risk = email_summary.get("risk_level", "LOW")
            indicators = email_ext.get("indicators", [])
            dangerous = email_summary.get("dangerous_attachments", 0)
            susp_urls = email_summary.get("suspicious_urls", 0)
            if indicators:
                verdict_signals.append(
                    f"Email: {len(indicators)} indicator(s), "
                    f"{dangerous} dangerous attachment(s), "
                    f"{susp_urls} suspicious URL(s)"
                )

        # ── URL Pipeline scores ──
        sub_b = self.report.get("subsystem_b") or []
        if isinstance(sub_b, list) and sub_b:
            scores = [r.get("risk_score", 0) for r in sub_b if isinstance(r, dict)]
            if scores:
                url_score = max(scores)
                worst = [r for r in sub_b if r.get("risk_score") == url_score]
                if worst:
                    w = worst[0]
                    verdict_signals.append(
                        f"URL risk: {url_score}/100 ({w.get('risk_level', '?')}) "
                        f"ML={w.get('ml_prediction', 'N/A')}"
                    )
        elif isinstance(sub_b, dict) and "risk_score" in sub_b:
            url_score = sub_b["risk_score"]
            verdict_signals.append(f"URL risk: {url_score}/100")

        # ── Sandbox score ──
        sub_a = self.report.get("subsystem_a") or {}
        if isinstance(sub_a, dict):
            # Try to get verdict from sandbox report
            ai_verdict = sub_a.get("ai_verdict", {})
            if ai_verdict:
                confidence = ai_verdict.get("combined_confidence", 0)
                verdict_label = ai_verdict.get("verdict", "N/A")
                # combined_confidence = how confident we are in the verdict.
                # If BENIGN with 100% confidence → risk = 0
                # If MALICIOUS with 100% confidence → risk = 100
                if verdict_label.upper() in ("BENIGN", "CLEAN"):
                    sandbox_score = max(0, 100 - confidence)
                else:
                    sandbox_score = confidence
                verdict_signals.append(
                    f"Sandbox: {verdict_label} "
                    f"(confidence: {confidence}%, risk: {sandbox_score})"
                )
            elif sub_a.get("summary", {}).get("risk_indicators"):
                risk_count = len(sub_a["summary"]["risk_indicators"])
                sandbox_score = min(risk_count * 15, 100)
                verdict_signals.append(
                    f"Sandbox: {risk_count} risk indicator(s)"
                )

        # ── Handover escalation ──
        handover = self.report.get("handover") or {}
        handover_score = 0
        if handover.get("status") == "completed":
            h_result = handover.get("sandbox_result", {})
            h_verdict = h_result.get("ai_verdict", {})
            if h_verdict:
                h_confidence = h_verdict.get("combined_confidence", 0)
                h_label = h_verdict.get("verdict", "N/A")
                if h_label.upper() in ("BENIGN", "CLEAN"):
                    handover_score = max(0, 100 - h_confidence)
                else:
                    handover_score = h_confidence
                verdict_signals.append(
                    f"Downloaded payload: {h_label} "
                    f"(confidence: {h_confidence}%, risk: {handover_score})"
                )

        # ── Combined score ──
        if self.report["input_type"] == "URL":
            combined = url_score + (handover_score * 0.5)
        elif self.report["input_type"] == "FILE":
            combined = sandbox_score
        elif self.report["input_type"] == "EMAIL":
            combined = max(url_score, sandbox_score, handover_score)
            # Elevate if email itself is suspicious
            if email_risk in ("HIGH", "CRITICAL"):
                combined = max(combined, 60)
        else:
            combined = max(url_score, sandbox_score)

        combined = min(int(combined), 100)

        # Determine level
        if combined >= 70:
            level = "CRITICAL"
        elif combined >= 50:
            level = "HIGH"
        elif combined >= 30:
            level = "MEDIUM"
        elif combined >= 10:
            level = "LOW"
        else:
            level = "CLEAN"

        self.report["unified_verdict"] = {
            "combined_score": combined,
            "level": level,
            "url_score": url_score,
            "sandbox_score": sandbox_score,
            "handover_score": handover_score,
            "email_risk": email_risk,
            "signals": verdict_signals,
        }

        print(f"\n[MASTER] {'=' * 56}")
        print(f"[MASTER]   UNIFIED VERDICT")
        print(f"[MASTER]   Combined Score: {combined}/100")
        print(f"[MASTER]   Level: {level}")
        for s in verdict_signals:
            print(f"[MASTER]   -> {s}")
        print(f"[MASTER] {'=' * 56}\n")

    # ─────────────────────────────────────────────────────────────────────
    # STEP 8: Save Unified Report
    # ─────────────────────────────────────────────────────────────────────

    def _save_report(self):
        """Save the unified report as JSON."""
        reports_dir = os.path.join(SCRIPT_DIR, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        output_path = os.path.join(reports_dir, "unified_report.json")

        with open(output_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)

        print(f"[MASTER] Unified report saved: {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="KNOWHOW Unified Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sandbox/master_orchestrator.py "https://evil-site.com"
  python sandbox/master_orchestrator.py malware.exe
  python sandbox/master_orchestrator.py phish.eml
  python sandbox/master_orchestrator.py "https://evil.com" --overwatch
  python sandbox/master_orchestrator.py malware.exe --timeout 120
  python sandbox/master_orchestrator.py phish.eml --skip-dynamic
        """
    )
    parser.add_argument("input", help="URL, file path, or .eml email to analyze")
    parser.add_argument("--overwatch", action="store_true",
                        help="Enable browser process hooking (experimental)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="File sandbox timeout in seconds (default: 60)")
    parser.add_argument("--mode", choices=["local", "vm"], default="local",
                        help="Network mode: local=mock, vm=FakeNet-NG")
    parser.add_argument("--skip-dynamic", action="store_true",
                        help="Skip Playwright headless browser analysis")

    args = parser.parse_args()

    orchestrator = MasterOrchestrator(
        overwatch=args.overwatch,
        timeout=args.timeout,
        mode=args.mode,
        skip_dynamic=args.skip_dynamic,
    )

    report = orchestrator.analyze(args.input)
