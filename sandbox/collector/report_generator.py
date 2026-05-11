"""
report_generator.py - Unified Report Generator
================================================
Merges all component reports into a single final_report.json.
Also generates the clean API call sequence.

Usage:
    generator = ReportGenerator(raw_dir="sandbox/reports/raw")
    report = generator.generate("sandbox/reports/final_report.json")
"""

import os
import json
import time

try:
    from .api_decoder import decode_api_args, format_decoded_args
except ImportError:
    from collector.api_decoder import decode_api_args, format_decoded_args


class ReportGenerator:
    """Merges component reports into a unified behavioral report."""

    COMPONENT_FILES = {
        "api_behavior": "api_calls.json",
        "file_activity": "file_activity.json",
        "registry_activity": "registry_activity.json",
        "network_activity": "network_activity.json",
        "memory_activity": "memory_activity.json",
    }

    def __init__(self, raw_dir="sandbox/reports/raw"):
        self.raw_dir = raw_dir

    def _load_component(self, filename):
        """Load a single component report."""
        path = os.path.join(self.raw_dir, filename)
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[REPORT] WARNING: Failed to load {filename}: {e}")
            return None

    def _generate_api_section(self, api_report_path):
        """Generate the API behavior section from collector output."""
        if not os.path.exists(api_report_path):
            return {"error": "API report not found"}

        with open(api_report_path) as f:
            raw = json.load(f)

        # Extract all calls
        calls = []
        for proc in raw.get("behavior", {}).get("processes", []):
            for c in proc.get("calls", []):
                calls.append(c)
        calls.sort(key=lambda x: x.get("time", 0))

        # Filter MinHook noise
        if calls:
            init_cutoff = calls[0].get("time", 0) + 0.1
            clean = [c for c in calls if c.get("time", 0) > init_cutoff
                     or c.get("api") not in ("VirtualProtect", "FlushInstructionCache")]
        else:
            clean = calls

        # Cut at ExitProcess
        for i, c in enumerate(clean):
            if c.get("api") == "ExitProcess":
                clean = clean[:i + 1]
                break

        # Build sequence
        raw_sequence = [c.get("api", "?") for c in clean]

        # Deduplicated
        deduped = []
        prev = None
        for api in raw_sequence:
            if api != prev:
                deduped.append(api)
                prev = api

        # Category flow
        cat_flow = []
        prev_cat = None
        for c in clean:
            cat = c.get("category", "?")
            if cat != prev_cat:
                cat_flow.append(cat)
                prev_cat = cat

        # API frequency
        api_counts = {}
        cat_counts = {}
        for c in clean:
            api = c.get("api", "?")
            cat = c.get("category", "?")
            api_counts[api] = api_counts.get(api, 0) + 1
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        return {
            "total_calls": len(clean),
            "unique_apis": len(set(raw_sequence)),
            "sequence_length": len(deduped),
            "raw_sequence": raw_sequence,
            "deduped_sequence": deduped,
            "category_flow": cat_flow,
            "api_frequency": dict(sorted(api_counts.items(),
                                         key=lambda x: -x[1])),
            "category_counts": dict(sorted(cat_counts.items(),
                                           key=lambda x: -x[1])),
            "detailed_calls": self._enrich_calls(clean),
        }

    def _enrich_calls(self, calls):
        """Enrich API calls with decoded human-readable arguments."""
        enriched = []
        for c in calls:
            entry = {
                "api": c.get("api"),
                "category": c.get("category"),
                "arguments": c.get("arguments", {}),
                "return": c.get("return", ""),
                "time": c.get("time", 0),
                "tid": c.get("tid", 0),
            }
            decoded = decode_api_args(entry["api"], entry["arguments"])
            if decoded:
                entry["decoded_args"] = decoded
            enriched.append(entry)
        return enriched

    def _build_timeline(self, report):
        """Build a unified chronological timeline from all events."""
        events = []

        # API calls
        api = report.get("api_behavior", {})
        for c in api.get("detailed_calls", []):
            api_name = c.get("api", "?")
            cat = c.get("category", "?")
            t = c.get("time", 0)
            decoded = c.get("decoded_args", {})
            detail = format_decoded_args(decoded) if decoded else ""

            # Add meaningful context from arguments
            args = c.get("arguments", {})
            if api_name in ("CreateFileA", "CreateFileW"):
                detail = args.get("lpFileName", detail)
            elif api_name == "connect":
                detail = args.get("address", detail)
            elif api_name == "gethostbyname":
                detail = args.get("name", detail)
            elif api_name in ("RegCreateKeyExA", "RegCreateKeyExW"):
                detail = args.get("lpSubKey", detail)
            elif api_name in ("RegSetValueExA", "RegSetValueExW"):
                detail = f"{args.get('lpValueName', '?')} = {args.get('data', '?')}"
            elif api_name == "VirtualAlloc":
                prot = decoded.get("flProtect", args.get("flProtect", ""))
                detail = f"size={args.get('dwSize', '?')} prot={prot}"

            events.append({
                "time": t,
                "category": cat,
                "event": api_name,
                "detail": detail,
                "source": "API",
            })

        events.sort(key=lambda x: x["time"])
        return events

    def generate(self, output_path, api_report_path=None, sample_info=None):
        """Generate the final merged report."""
        print("[REPORT] Generating final report...")

        # API behavior (from collector output)
        api_path = api_report_path or os.path.join(
            self.raw_dir, "..", "test_report.json")
        api_section = self._generate_api_section(api_path)

        # Load component reports
        file_report = self._load_component("file_activity.json")
        reg_report = self._load_component("registry_activity.json")
        net_report = self._load_component("network_activity.json")
        mem_report = self._load_component("memory_activity.json")
        screenshots_report = self._load_component("screenshots.json")

        # Build final report
        # Try to extract the sample name from the API report
        effective_sample_info = sample_info or {}
        if not effective_sample_info.get("name"):
            # Look inside the raw API report for target info
            try:
                with open(api_path) as f:
                    raw = json.load(f)
                target = raw.get("target", {})
                if target.get("file", {}).get("name"):
                    effective_sample_info["name"] = target["file"]["name"]
                elif raw.get("info", {}).get("sample"):
                    effective_sample_info["name"] = raw["info"]["sample"]
            except Exception:
                pass

        report = {
            "info": {
                "version": "sandbox-2.1",
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "timestamp": time.time(),
                "sample": effective_sample_info,
            },
            "api_behavior": api_section,
            "file_activity": file_report.get("data", {}) if file_report else
                             {"note": "File monitor not run"},
            "registry_activity": reg_report.get("data", {}) if reg_report else
                                 {"note": "Registry monitor not run"},
            "network_activity": net_report.get("data", {}) if net_report else
                                {"note": "Network monitor not run"},
            "memory_activity": mem_report.get("data", {}) if mem_report else
                               {"note": "Memory monitor not run"},
            "screenshots": screenshots_report if screenshots_report else
                           {"note": "Screenshot monitor not run", "count": 0, "files": []},
        }

        # ── Phase 8B: Process Tree Analysis ──
        try:
            from sandbox.monitors.process_tree import ProcessTreeAnalyzer
        except ImportError:
            try:
                _monitors_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "monitors")
                import importlib.util
                spec = importlib.util.spec_from_file_location("process_tree",
                    os.path.join(_monitors_dir, "process_tree.py"))
                _ptmod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(_ptmod)
                ProcessTreeAnalyzer = _ptmod.ProcessTreeAnalyzer
            except Exception:
                ProcessTreeAnalyzer = None

        if ProcessTreeAnalyzer:
            try:
                # Load raw API report for PID data
                raw_api = None
                if api_report_path and os.path.exists(api_report_path):
                    with open(api_report_path) as f:
                        raw_api = json.load(f)
                pt_analyzer = ProcessTreeAnalyzer(api_report=raw_api, final_report=report)
                report["process_tree"] = pt_analyzer.analyze()
                print("[REPORT] Process tree analysis complete.")
            except Exception as e:
                report["process_tree"] = {"error": str(e)}
                print(f"[REPORT] WARNING: Process tree failed: {e}")
        else:
            report["process_tree"] = {"note": "Process tree module not available"}

        # ── Phase 8C: WriteFile Content Analysis ──
        try:
            from sandbox.monitors.writefile_capture import WriteFileCaptureAnalyzer
        except ImportError:
            try:
                spec2 = importlib.util.spec_from_file_location("writefile_capture",
                    os.path.join(_monitors_dir, "writefile_capture.py"))
                _wfmod = importlib.util.module_from_spec(spec2)
                spec2.loader.exec_module(_wfmod)
                WriteFileCaptureAnalyzer = _wfmod.WriteFileCaptureAnalyzer
            except Exception:
                WriteFileCaptureAnalyzer = None

        if WriteFileCaptureAnalyzer:
            try:
                wf_analyzer = WriteFileCaptureAnalyzer(final_report=report)
                report["writefile_analysis"] = wf_analyzer.analyze()
                print("[REPORT] WriteFile content analysis complete.")
            except Exception as e:
                report["writefile_analysis"] = {"error": str(e)}
                print(f"[REPORT] WARNING: WriteFile analysis failed: {e}")
        else:
            report["writefile_analysis"] = {"note": "WriteFile capture module not available"}

        # Generate overall summary
        report["summary"] = self._generate_summary(report)

        # Generate execution timeline
        report["timeline"] = self._build_timeline(report)

        # Save JSON
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        self._print_summary(report, output_path)

        # Auto-generate HTML dashboard and open it
        try:
            import importlib.util
            import webbrowser
            # Find html_report.py in the same directory as this file
            _this_dir = os.path.dirname(os.path.abspath(__file__))
            _html_mod_path = os.path.join(_this_dir, "html_report.py")
            spec = importlib.util.spec_from_file_location("html_report", _html_mod_path)
            html_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(html_mod)
            html_path = output_path.replace(".json", ".html")
            html_mod.generate_html_report(output_path, html_path)
            # Auto-open in default browser
            abs_html = os.path.abspath(html_path)
            webbrowser.open(f"file:///{abs_html.replace(os.sep, '/')}")
            print(f"[HTML] Report opened in browser.")
        except Exception as e:
            print(f"[REPORT] Warning: HTML generation failed: {e}")

        return report

    def _generate_summary(self, report):
        """Generate a high-level behavioral summary."""
        summary = {
            "components_available": [],
            "risk_indicators": [],
        }

        # API
        api = report.get("api_behavior", {})
        if api and "total_calls" in api:
            summary["components_available"].append("api_behavior")
            summary["api_calls"] = api.get("total_calls", 0)
            summary["unique_apis"] = api.get("unique_apis", 0)

        # Files
        files = report.get("file_activity", {})
        file_summary = files.get("summary", {})
        if file_summary:
            summary["components_available"].append("file_activity")
            summary["files_created"] = file_summary.get("total_created", 0)
            summary["files_modified"] = file_summary.get("total_modified", 0)
            summary["files_deleted"] = file_summary.get("total_deleted", 0)
            if file_summary.get("suspicious_files"):
                summary["risk_indicators"].append(
                    f"Suspicious files dropped: {file_summary['suspicious_files']}")

        # Registry
        reg = report.get("registry_activity", {})
        reg_summary = reg.get("summary", {})
        if reg_summary:
            summary["components_available"].append("registry_activity")
            summary["registry_changes"] = (
                reg_summary.get("total_values_set", 0) +
                reg_summary.get("total_values_modified", 0)
            )
            if reg_summary.get("persistence_detected"):
                summary["risk_indicators"].append("Registry persistence detected")

        # Network
        net = report.get("network_activity", {})
        net_summary = net.get("summary", {})
        if net_summary:
            summary["components_available"].append("network_activity")
            summary["connections"] = net_summary.get("total_connections", 0)
            summary["dns_queries"] = net_summary.get("total_dns_queries", 0)
            if net_summary.get("connections_without_dns"):
                summary["risk_indicators"].append(
                    f"Connections without DNS: {net_summary['connections_without_dns']}")
            if net_summary.get("suspicious_ports_used"):
                summary["risk_indicators"].append(
                    f"Suspicious ports: {net_summary['suspicious_ports_used']}")
            if net_summary.get("c2_risk") in ("HIGH", "MEDIUM"):
                summary["risk_indicators"].append(
                    f"C2 risk: {net_summary['c2_risk']}")

        # Memory
        mem = report.get("memory_activity", {})
        mem_summary = mem.get("summary", {})
        if mem_summary:
            summary["components_available"].append("memory_activity")
            summary["rwx_count"] = mem_summary.get("rwx_count", 0)
            if mem_summary.get("rwx_detected"):
                summary["risk_indicators"].append(
                    f"RWX memory allocations: {mem_summary.get('rwx_count', 0)} detected")
            if mem_summary.get("injection_detected"):
                summary["risk_indicators"].append("Process injection indicators")
            if mem_summary.get("pe_in_memory"):
                summary["risk_indicators"].append("PE header found in memory dump")

        summary["total_risk_indicators"] = len(summary["risk_indicators"])

        # ── Threat Score (0-100) ──
        score = 0
        # File indicators
        susp_files = files.get("summary", {}).get("suspicious_files", [])
        score += min(len(susp_files) * 15, 30)   # +15 per suspicious file, max 30
        non_susp_created = file_summary.get("total_created", 0) - len(susp_files)
        score += min(non_susp_created * 3, 9)     # +3 per non-suspicious file, max 9

        # Registry indicators
        if reg_summary.get("persistence_detected"):
            score += 25  # Persistence is a strong signal
        score += min(reg_summary.get("total_values_set", 0) * 2, 6)  # +2 per value, max 6

        # Network indicators
        connections = net_summary.get("total_connections", 0)
        score += min(connections * 5, 15)          # +5 per connection, max 15
        if net_summary.get("connections_without_dns"):
            score += 10  # Hardcoded IPs
        if net_summary.get("c2_risk") == "HIGH":
            score += 15
        elif net_summary.get("c2_risk") == "MEDIUM":
            score += 8

        # Memory indicators
        rwx = mem_summary.get("rwx_count", 0)
        score += min(rwx * 10, 20)                 # +10 per RWX, max 20
        if mem_summary.get("injection_detected"):
            score += 20  # Process injection
        if mem_summary.get("pe_in_memory"):
            score += 10  # PE in memory

        summary["threat_score"] = min(score, 100)
        if score >= 70:
            summary["threat_level"] = "CRITICAL"
        elif score >= 50:
            summary["threat_level"] = "HIGH"
        elif score >= 30:
            summary["threat_level"] = "MEDIUM"
        elif score >= 10:
            summary["threat_level"] = "LOW"
        else:
            summary["threat_level"] = "CLEAN"

        return summary

    def _print_summary(self, report, output_path):
        """Print a rich, evidence-based CLI summary with threat context."""
        s = report.get("summary", {})
        W = 70  # column width

        def header(text):
            print(f"\n  {'-' * (W - 4)}")
            print(f"  {text}")
            print(f"  {'-' * (W - 4)}")

        def evidence(icon, msg, context=None):
            print(f"    {icon} {msg}")
            if context:
                print(f"       +-- Context: {context}")

        print()
        print("=" * W)
        print("  _  ___   _  _____      ___  _  _____      __")
        print(" | |/ / \\ | |/ _ \\ \\    / / || |/ _ \\ \\    / /")
        print(" | ' /|  \\| | | | \\ \\/\\/ /| || | | | \\ \\/\\/ / ")
        print(" | . \\| .  | | |_| |\\  /\\  /|  _ | |_| |\\  /\\  / ")
        print(" |_|\\_\\_|\\_|\\___/  \\/  \\/ |_| |_|\\___/  \\/  \\/ ")
        print()
        print("  SANDBOX BEHAVIORAL ANALYSIS REPORT")
        print("=" * W)

        # ── Overview ──
        comps = s.get("components_available", [])
        print(f"  Components:    {len(comps)}/5 active")
        print(f"  API calls:     {s.get('api_calls', '?')}")
        print(f"  Unique APIs:   {s.get('unique_apis', '?')}")

        # Threat Score
        threat_score = s.get("threat_score", 0)
        threat_level = s.get("threat_level", "UNKNOWN")
        risk_count = s.get("total_risk_indicators", 0)
        score_bar = "#" * (threat_score // 5) + "-" * (20 - threat_score // 5)
        print(f"  Threat Score:  {threat_score}/100  [{score_bar}]")
        print(f"  Threat Level:  {threat_level} ({risk_count} indicators)")

        # ── FILE ACTIVITY — with evidence ──
        files = report.get("file_activity", {})
        f_summary = files.get("summary", {})
        if f_summary:
            header("FILE ACTIVITY")
            created = f_summary.get("total_created", 0)
            modified = f_summary.get("total_modified", 0)
            deleted = f_summary.get("total_deleted", 0)
            print(f"    Created: {created}  |  Modified: {modified}  |  Deleted: {deleted}")

            # Show ALL created files with full forensic detail
            for f_item in files.get("files_created", []):
                fp = f_item.get("path", "?")
                fname = os.path.basename(fp)
                ext = os.path.splitext(fname)[1].lower()
                ftype = f_item.get("file_type", "Unknown")
                size = f_item.get("size", "?")
                is_suspicious = f_item.get("suspicious", False)

                if is_suspicious:
                    if ext in (".exe", ".dll", ".scr"):
                        ctx = "Executable dropped to disk - possible payload delivery"
                    elif ext in (".bat", ".cmd", ".ps1", ".vbs"):
                        ctx = "Script dropped - possible second-stage execution"
                    else:
                        ctx = "Suspicious file type dropped"
                    tag = "[!!]"
                else:
                    ctx = None
                    tag = "[--]"

                evidence(tag, f"DROPPED: {fname}", ctx)
                print(f"       Path: {fp}")
                print(f"       Size: {size} bytes  |  Type: {ftype}")
                sha = f_item.get("hash_sha256") or f_item.get("hash")
                md5 = f_item.get("hash_md5")
                if sha:
                    print(f"       SHA256: {sha}")
                if md5:
                    print(f"       MD5:    {md5}")

            # Show modified files
            for f_item in files.get("files_modified", []):
                fname = os.path.basename(f_item.get("path", "?"))
                old_s = f_item.get("old_size", "?")
                new_s = f_item.get("new_size", "?")
                evidence("[MOD]", f"MODIFIED: {fname}",
                         f"Size: {old_s} -> {new_s} bytes")

        # ── REGISTRY ACTIVITY — with evidence ──
        reg = report.get("registry_activity", {})
        reg_summary = reg.get("summary", {})
        if reg_summary:
            header("REGISTRY ACTIVITY")
            total_changes = (reg_summary.get("total_values_set", 0) +
                             reg_summary.get("total_values_modified", 0))
            print(f"    Changes: {total_changes}  |  "
                  f"Keys created: {reg_summary.get('total_keys_created', 0)}  |  "
                  f"Values deleted: {reg_summary.get('total_values_deleted', 0)}")

            # Show keys created
            for kc in reg.get("keys_created", [])[:5]:
                evidence("[KEY]", f"CREATED: {kc}",
                         "New registry key created by sample")

            # Show ALL values set (new values)
            for val in reg.get("values_set", []):
                key = val.get("key", "")
                name = val.get("name", "")
                data = val.get("data", "")
                vtype = val.get("type", "")
                type_map = {"REG_SZ": "Text", "REG_DWORD": "Integer",
                            "REG_BINARY": "Binary", "REG_EXPAND_SZ": "Text",
                            "REG_QWORD": "Integer64", "REG_MULTI_SZ": "MultiText"}
                friendly = type_map.get(vtype, vtype)
                evidence("[SET]", f"{key}\\{name} = {data}",
                         f"Type: {friendly} ({vtype})" if vtype else None)

            # Show ALL values modified (existing values changed)
            for val in reg.get("values_modified", []):
                key = val.get("key", "")
                name = val.get("name", "")
                old_val = val.get("old_value", "?")
                new_val = val.get("new_value", "?")
                evidence("[MOD]", f"{key}\\{name}",
                         f"Changed: {old_val} -> {new_val}")

            # Show deleted values
            for val in reg.get("values_deleted", []):
                key = val.get("key", "") if isinstance(val, dict) else val
                evidence("[DEL]", f"{key}")

            # Show persistence indicators with context
            persistence = reg.get("persistence_indicators", [])
            for ind in persistence[:5]:
                if "\\Run" in ind:
                    ctx = "Ensures automatic execution on every startup (Persistence)"
                elif "\\Services" in ind:
                    ctx = "Registers as Windows Service (Persistence + Privilege)"
                elif "\\Winlogon" in ind:
                    ctx = "Hijacks Windows login process (Advanced Persistence)"
                elif "\\TaskCache" in ind:
                    ctx = "Creates scheduled task (Persistence)"
                else:
                    ctx = "Registry modification in sensitive location"
                evidence("[PERSIST]", ind, ctx)

        # ── NETWORK ACTIVITY — with evidence ──
        net = report.get("network_activity", {})
        net_summary = net.get("summary", {})
        if net_summary:
            header("NETWORK ACTIVITY")
            print(f"    Connections: {net_summary.get('total_connections', 0)}  |  "
                  f"DNS: {net_summary.get('total_dns_queries', 0)}  |  "
                  f"C2 Risk: {net_summary.get('c2_risk', 'LOW')}")

            # Show actual connections with IPs
            for conn in net.get("connections", [])[:3]:
                ip = conn.get("ip", "?")
                port = conn.get("port", "?")
                susp = conn.get("suspicious", "")
                if susp:
                    evidence("[!!]", f"Connected to {ip}:{port}",
                             f"Suspicious port - {susp}")
                elif ip not in ("127.0.0.1", "0.0.0.0", "unknown", None):
                    evidence("[**]", f"Connected to {ip}:{port}",
                             "Outbound connection to external host")
                else:
                    evidence("[--]", f"Connected to {ip}:{port}")

            # Show DNS queries
            for dns in net.get("dns_queries", [])[:3]:
                hostname = dns.get("hostname", "?")
                evidence("[**]", f"DNS lookup: {hostname}",
                         "Domain resolution - possible C2 communication")

            # Show connections without DNS
            no_dns = net_summary.get("connections_without_dns", [])
            for ip in no_dns[:2]:
                evidence("[!!]", f"Direct IP connection (no DNS): {ip}",
                         "Hardcoded IP - evades DNS-based detection")

        # ── MEMORY ACTIVITY — with evidence ──
        mem = report.get("memory_activity", {})
        mem_summary = mem.get("summary", {})
        if mem_summary:
            header("MEMORY ACTIVITY")
            print(f"    Operations: {mem_summary.get('total_memory_ops', 0)}  |  "
                  f"RWX: {mem_summary.get('rwx_count', 0)}  |  "
                  f"Injection: {'YES' if mem_summary.get('injection_detected') else 'NO'}")

            # Show actual RWX allocations
            for rwx in mem.get("rwx_allocations", [])[:3]:
                addr = rwx.get("address", "?")
                size = rwx.get("size", "?")
                api = rwx.get("api", "?")
                if api in ("VirtualAllocEx",):
                    ctx = ("Remote RWX allocation - classic process injection "
                           "(allocate > write > execute in another process)")
                elif api == "VirtualProtect":
                    ctx = ("Memory re-protected to RWX - possible unpacking or "
                           "self-modifying code")
                else:
                    ctx = ("RWX memory allocated - could contain shellcode or "
                           "decrypted payload")
                evidence("[!!]", f"{api} @ {addr} (size: {size})", ctx)

            if mem_summary.get("injection_detected"):
                for inj in mem.get("injection_indicators", [])[:2]:
                    evidence("[!!]", f"Injection API: {inj.get('api', '?')}",
                             "Code injection into another process detected")

        # ── RISK SUMMARY ──
        header("RISK INDICATORS SUMMARY")
        if s.get("risk_indicators"):
            for i, r in enumerate(s["risk_indicators"], 1):
                print(f"    [{i}] {r}")
        else:
            print("    [OK] No risk indicators detected.")

        # ── EXECUTION TIMELINE (top 20 events) ──
        timeline = report.get("timeline", [])
        if timeline:
            header("EXECUTION TIMELINE")
            # Show category color codes
            cat_icons = {"FILE": "[F]", "REG": "[R]", "NET": "[N]",
                         "MEM": "[M]", "PROC": "[P]", "DLL": "[D]",
                         "CRYPT": "[C]", "SYS": "[S]", "SYNC": "[~]"}
            shown = 0
            for ev in timeline:
                if shown >= 20:
                    remaining = len(timeline) - 20
                    print(f"    ... and {remaining} more events (see JSON report)")
                    break
                t = ev.get("time", 0)
                cat = ev.get("category", "?")
                event = ev.get("event", "?")
                detail = ev.get("detail", "")
                icon = cat_icons.get(cat, "[?]")
                detail_str = f" -> {detail}" if detail else ""
                print(f"    [{t:8.3f}s] {icon} {cat:5s} {event}{detail_str}")
                shown += 1

        # -- Footer --
        print()
        print(f"  [>] JSON Report: {output_path}")
        print("=" * W)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Report Generator")
    parser.add_argument("--raw-dir", default="sandbox/reports/raw")
    parser.add_argument("--api-report", default="sandbox/reports/test_report.json")
    parser.add_argument("--output", default="sandbox/reports/final_report.json")
    args = parser.parse_args()

    gen = ReportGenerator(raw_dir=args.raw_dir)
    gen.generate(args.output, api_report_path=args.api_report)
