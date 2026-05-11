"""
writefile_capture.py - WriteFile Content Analyzer (Phase 8C)
==============================================================
Analyzes WriteFile buffer contents captured by the hook DLL.
Detects dropped scripts, batch files, config files, and encoded payloads.

The hook DLL captures the first 256 bytes of each WriteFile call as
a base64-encoded 'buffer_preview' field in the API arguments.

Usage:
    from monitors.writefile_capture import WriteFileCaptureAnalyzer
    analyzer = WriteFileCaptureAnalyzer(final_report)
    result = analyzer.analyze()
"""

import os
import json
import base64
import re


class WriteFileCaptureAnalyzer:
    """Analyze WriteFile buffer contents for forensic intelligence."""

    # File signatures (magic bytes)
    MAGIC_BYTES = {
        b"MZ": "PE_EXECUTABLE",
        b"\x7fELF": "ELF_BINARY",
        b"PK\x03\x04": "ZIP_ARCHIVE",
        b"\x1f\x8b": "GZIP_ARCHIVE",
        b"Rar!": "RAR_ARCHIVE",
        b"\xd0\xcf\x11\xe0": "OLE_DOCUMENT",     # DOC, XLS, etc.
        b"%PDF": "PDF_DOCUMENT",
        b"\xff\xd8\xff": "JPEG_IMAGE",
        b"\x89PNG": "PNG_IMAGE",
    }

    # Script content patterns
    SCRIPT_PATTERNS = [
        (re.compile(r'@echo\s+off', re.I), "BATCH_SCRIPT"),
        (re.compile(r'powershell', re.I), "POWERSHELL_COMMAND"),
        (re.compile(r'cmd\.exe\s*/c', re.I), "CMD_EXEC"),
        (re.compile(r'<script', re.I), "HTML_SCRIPT"),
        (re.compile(r'WScript\.Shell', re.I), "VBSCRIPT"),
        (re.compile(r'CreateObject\s*\(', re.I), "VBS_COM_OBJECT"),
        (re.compile(r'import\s+os|import\s+subprocess', re.I), "PYTHON_SCRIPT"),
        (re.compile(r'#!/bin/(ba)?sh', re.I), "SHELL_SCRIPT"),
        (re.compile(r'reg\s+add\s+', re.I), "REGISTRY_COMMAND"),
        (re.compile(r'schtasks\s+/create', re.I), "SCHEDULED_TASK"),
        (re.compile(r'net\s+user\s+', re.I), "USER_MANIPULATION"),
        (re.compile(r'netsh\s+', re.I), "FIREWALL_MANIPULATION"),
        (re.compile(r'certutil\s+-decode', re.I), "CERTUTIL_DECODE"),
        (re.compile(r'bitsadmin\s+/transfer', re.I), "BITSADMIN_DOWNLOAD"),
        (re.compile(r'base64', re.I), "BASE64_REFERENCE"),
        (re.compile(r'http[s]?://\S+', re.I), "EMBEDDED_URL"),
        (re.compile(r'HKEY_|HKCU\\|HKLM\\', re.I), "REGISTRY_PATH"),
    ]

    # Suspicious file extensions in written paths
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".wsf", ".scr", ".pif", ".com", ".hta", ".cpl",
    }

    def __init__(self, final_report=None, api_report=None):
        """
        Args:
            final_report: final_report.json dict
            api_report: Raw api_raw_report.json dict
        """
        self.final_report = final_report
        self.api_report = api_report
        self.captures = []

    def analyze(self):
        """Run the full WriteFile content analysis."""
        self._extract_writes()
        findings = self._analyze_contents()
        return self._build_result(findings)

    def _extract_writes(self):
        """Extract all WriteFile calls with their arguments."""
        calls = []

        # From final_report
        if self.final_report:
            for c in self.final_report.get("api_behavior", {}).get("detailed_calls", []):
                if c.get("api") == "WriteFile":
                    calls.append(c)

        # From raw API report
        elif self.api_report:
            for proc in self.api_report.get("behavior", {}).get("processes", []):
                for c in proc.get("calls", []):
                    if c.get("api") == "WriteFile":
                        calls.append(c)

        self.captures = calls

    def _resolve_handle_to_path(self, handle):
        """Try to resolve a file handle to a file path from CreateFile calls."""
        if not self.final_report:
            return None

        for c in self.final_report.get("api_behavior", {}).get("detailed_calls", []):
            if c.get("api") in ("CreateFileA", "CreateFileW"):
                ret = c.get("return", "")
                if ret == handle:
                    args = c.get("arguments", {})
                    return args.get("lpFileName", "")
        return None

    def _analyze_contents(self):
        """Analyze each WriteFile capture for suspicious content."""
        findings = []

        # Build handle -> path map
        handle_map = {}
        if self.final_report:
            for c in self.final_report.get("api_behavior", {}).get("detailed_calls", []):
                if c.get("api") in ("CreateFileA", "CreateFileW"):
                    ret = c.get("return", "")
                    args = c.get("arguments", {})
                    path = args.get("lpFileName", "")
                    if ret and path:
                        handle_map[ret] = path

        for i, capture in enumerate(self.captures):
            args = capture.get("arguments", {})
            handle = args.get("hFile", "")
            size = args.get("nNumberOfBytesToWrite", 0)
            buffer_b64 = args.get("buffer_preview", "")
            t = capture.get("time", 0)

            # Resolve handle to path
            file_path = handle_map.get(handle, "")
            file_ext = os.path.splitext(file_path)[1].lower() if file_path else ""

            finding = {
                "index": i,
                "time": t,
                "handle": handle,
                "file_path": file_path,
                "file_extension": file_ext,
                "bytes_written": size,
                "has_buffer": bool(buffer_b64),
                "detections": [],
                "content_type": "UNKNOWN",
                "content_preview": "",
            }

            # Check if writing to suspicious extension
            if file_ext in self.SUSPICIOUS_EXTENSIONS:
                finding["detections"].append({
                    "type": "SUSPICIOUS_FILE_WRITE",
                    "severity": "HIGH",
                    "detail": f"Writing to suspicious file type: {file_ext}",
                })

            # Analyze buffer content if available
            if buffer_b64:
                try:
                    raw_bytes = base64.b64decode(buffer_b64)
                    finding["content_preview"] = self._safe_preview(raw_bytes)

                    # Check magic bytes
                    for magic, file_type in self.MAGIC_BYTES.items():
                        if raw_bytes.startswith(magic):
                            finding["content_type"] = file_type
                            severity = "CRITICAL" if file_type == "PE_EXECUTABLE" else "HIGH"
                            finding["detections"].append({
                                "type": f"DROPPED_{file_type}",
                                "severity": severity,
                                "detail": f"WriteFile contains {file_type} header",
                            })
                            break

                    # Check for text/script content
                    try:
                        text = raw_bytes.decode("utf-8", errors="replace")
                        for pattern, script_type in self.SCRIPT_PATTERNS:
                            if pattern.search(text):
                                finding["detections"].append({
                                    "type": f"SCRIPT_CONTENT_{script_type}",
                                    "severity": "HIGH",
                                    "detail": f"WriteFile contains {script_type} content",
                                })
                                if finding["content_type"] == "UNKNOWN":
                                    finding["content_type"] = script_type
                    except Exception:
                        pass

                except Exception:
                    pass
            else:
                # No buffer captured — use heuristic from size + path
                if size > 0 and file_ext in self.SUSPICIOUS_EXTENSIONS:
                    finding["detections"].append({
                        "type": "BLIND_SUSPICIOUS_WRITE",
                        "severity": "MEDIUM",
                        "detail": f"Writing {size} bytes to {file_ext} (no buffer preview available)",
                    })

            findings.append(finding)

        return findings

    def _safe_preview(self, raw_bytes, max_len=128):
        """Generate a safe text preview of bytes."""
        try:
            text = raw_bytes[:max_len].decode("utf-8", errors="replace")
            # Remove non-printable characters
            text = "".join(c if c.isprintable() or c in "\n\r\t" else "." for c in text)
            return text.strip()
        except Exception:
            return raw_bytes[:max_len].hex()

    def _build_result(self, findings):
        """Build the final analysis result."""
        total_writes = len(self.captures)
        writes_with_buffer = sum(1 for f in findings if f["has_buffer"])
        suspicious_writes = [f for f in findings if f["detections"]]

        # Aggregate detections
        all_detections = []
        for f in findings:
            for d in f["detections"]:
                all_detections.append({
                    **d,
                    "file_path": f["file_path"],
                    "time": f["time"],
                    "bytes": f["bytes_written"],
                })

        # Unique written file paths
        written_files = list(set(
            f["file_path"] for f in findings if f["file_path"]
        ))

        return {
            "summary": {
                "total_write_calls": total_writes,
                "writes_with_buffer": writes_with_buffer,
                "suspicious_writes": len(suspicious_writes),
                "total_detections": len(all_detections),
                "unique_files_written": len(written_files),
                "buffer_capture_enabled": writes_with_buffer > 0,
            },
            "written_files": written_files,
            "detections": all_detections,
            "findings": [
                {
                    "file_path": f["file_path"],
                    "bytes_written": f["bytes_written"],
                    "content_type": f["content_type"],
                    "content_preview": f["content_preview"][:200],
                    "detections": f["detections"],
                    "time": f["time"],
                }
                for f in suspicious_writes
            ],
        }

    def print_summary(self):
        """Print analysis summary to console."""
        result = self.analyze()
        s = result["summary"]
        print("\n" + "=" * 60)
        print("  WRITEFILE CONTENT ANALYSIS")
        print("=" * 60)
        print(f"  Total WriteFile calls:    {s['total_write_calls']}")
        print(f"  With buffer captured:     {s['writes_with_buffer']}")
        print(f"  Suspicious writes:        {s['suspicious_writes']}")
        print(f"  Buffer capture enabled:   {s['buffer_capture_enabled']}")

        if result["written_files"]:
            print(f"\n  Files written to:")
            for f in result["written_files"][:10]:
                print(f"    -> {f}")

        if result["detections"]:
            print(f"\n  Detections:")
            for d in result["detections"]:
                print(f"    [{d['severity']}] {d['type']}: {d['detail']}")

        print("=" * 60)
        return result
