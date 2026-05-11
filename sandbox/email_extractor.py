"""
email_extractor.py - Email Attachment & URL Extraction (Phase 10)
=================================================================
Parses .eml files from email gateways and extracts:
  - File attachments (routed to File Sandbox)
  - URLs from body/HTML (routed to URL Pipeline)
  - Email metadata (sender, subject, headers)
  - Suspicious indicators (spoofing, unusual headers)

Usage:
    python email_extractor.py path/to/email.eml
    python email_extractor.py path/to/mailbox/ --batch

Or as a module:
    from email_extractor import EmailExtractor
    ex = EmailExtractor("email.eml")
    result = ex.extract()
"""

import os
import sys
import json
import email
import email.policy
import email.utils
import re
import base64
import hashlib
import quopri
import time
import argparse
from pathlib import Path


class EmailExtractor:
    """Parse .eml files and extract attachments + URLs for sandbox analysis."""

    # Dangerous attachment types
    DANGEROUS_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".pif", ".com", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".wsf", ".hta", ".cpl", ".msi",
        ".jar", ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        ".pdf", ".rtf", ".iso", ".img", ".vhd", ".zip", ".rar",
        ".7z", ".tar", ".gz", ".cab", ".lnk", ".reg",
    }

    # URL patterns
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )

    # Defanged URL patterns (hxxp, [.], etc.)
    DEFANGED_PATTERN = re.compile(
        r'hxxps?://[^\s<>"\')\]]+|'
        r'https?://[^\s]*\[\.\][^\s]*',
        re.IGNORECASE
    )

    # Suspicious header indicators
    SPOOF_HEADERS = [
        "X-Mailer", "X-Originating-IP", "Received-SPF",
        "Authentication-Results", "DKIM-Signature",
    ]

    def __init__(self, eml_path, output_dir=None):
        """
        Args:
            eml_path: Path to .eml file
            output_dir: Directory to save extracted attachments
        """
        self.eml_path = eml_path
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(eml_path), "extracted"
        )
        self.msg = None
        self.metadata = {}
        self.attachments = []
        self.urls = []
        self.indicators = []

    def extract(self):
        """Run full extraction pipeline."""
        self._parse_email()
        self._extract_metadata()
        self._extract_attachments()
        self._extract_urls()
        self._analyze_headers()
        return self._build_result()

    def _parse_email(self):
        """Parse the .eml file."""
        with open(self.eml_path, "r", encoding="utf-8", errors="replace") as f:
            self.msg = email.message_from_file(f, policy=email.policy.default)

    def _extract_metadata(self):
        """Extract email header metadata."""
        self.metadata = {
            "from": str(self.msg.get("From", "")),
            "to": str(self.msg.get("To", "")),
            "cc": str(self.msg.get("Cc", "")),
            "subject": str(self.msg.get("Subject", "")),
            "date": str(self.msg.get("Date", "")),
            "message_id": str(self.msg.get("Message-ID", "")),
            "reply_to": str(self.msg.get("Reply-To", "")),
            "return_path": str(self.msg.get("Return-Path", "")),
            "x_mailer": str(self.msg.get("X-Mailer", "")),
            "content_type": str(self.msg.get_content_type()),
            "has_attachments": False,
        }

        # Extract sender email and display name
        from_header = self.metadata["from"]
        parsed = email.utils.parseaddr(from_header)
        self.metadata["sender_name"] = parsed[0]
        self.metadata["sender_email"] = parsed[1]

        # Check for reply-to mismatch (phishing indicator)
        reply_to = self.metadata["reply_to"]
        if reply_to:
            reply_parsed = email.utils.parseaddr(reply_to)
            if reply_parsed[1] and reply_parsed[1] != parsed[1]:
                self.indicators.append({
                    "type": "REPLY_TO_MISMATCH",
                    "severity": "HIGH",
                    "detail": f"From: {parsed[1]} vs Reply-To: {reply_parsed[1]}",
                })

    def _extract_attachments(self):
        """Extract all file attachments."""
        os.makedirs(self.output_dir, exist_ok=True)

        for part in self.msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))

            # Skip non-attachment parts
            if "attachment" not in content_disposition and "inline" not in content_disposition:
                # Check for embedded files without explicit disposition
                filename = part.get_filename()
                if not filename:
                    continue

            filename = part.get_filename()
            if not filename:
                continue

            # Decode filename if encoded
            if isinstance(filename, bytes):
                filename = filename.decode("utf-8", errors="replace")

            # Get the payload
            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            # Calculate hashes
            md5 = hashlib.md5(payload).hexdigest()
            sha256 = hashlib.sha256(payload).hexdigest()

            # Determine file extension
            ext = os.path.splitext(filename)[1].lower()
            is_dangerous = ext in self.DANGEROUS_EXTENSIONS

            # Save to disk
            safe_name = re.sub(r'[^\w\-_\.]', '_', filename)
            save_path = os.path.join(self.output_dir, safe_name)
            with open(save_path, "wb") as f:
                f.write(payload)

            attachment_info = {
                "filename": filename,
                "safe_filename": safe_name,
                "save_path": save_path,
                "size": len(payload),
                "extension": ext,
                "content_type": part.get_content_type(),
                "md5": md5,
                "sha256": sha256,
                "is_dangerous": is_dangerous,
                "magic_header": payload[:4].hex() if len(payload) >= 4 else "",
            }

            # Check for PE header
            if payload[:2] == b"MZ":
                attachment_info["detected_type"] = "PE_EXECUTABLE"
                self.indicators.append({
                    "type": "PE_ATTACHMENT",
                    "severity": "CRITICAL",
                    "detail": f"Executable attachment: {filename}",
                })
            # Check for Office macros
            elif payload[:4] == b"\xd0\xcf\x11\xe0":
                attachment_info["detected_type"] = "OLE_DOCUMENT"
                self.indicators.append({
                    "type": "OLE_ATTACHMENT",
                    "severity": "HIGH",
                    "detail": f"OLE document (may contain macros): {filename}",
                })
            # Check for ZIP (could be Office XML or archive)
            elif payload[:2] == b"PK":
                attachment_info["detected_type"] = "ZIP_ARCHIVE"
            else:
                attachment_info["detected_type"] = "UNKNOWN"

            if is_dangerous:
                self.indicators.append({
                    "type": "DANGEROUS_EXTENSION",
                    "severity": "HIGH",
                    "detail": f"Dangerous file type: {filename} ({ext})",
                })

            self.attachments.append(attachment_info)

        self.metadata["has_attachments"] = len(self.attachments) > 0

    def _extract_urls(self):
        """Extract all URLs from email body and HTML parts."""
        seen_urls = set()

        for part in self.msg.walk():
            content_type = part.get_content_type()

            if content_type in ("text/plain", "text/html"):
                body = part.get_payload(decode=True)
                if body is None:
                    continue

                # Try to decode
                charset = part.get_content_charset() or "utf-8"
                try:
                    text = body.decode(charset, errors="replace")
                except (UnicodeDecodeError, LookupError):
                    text = body.decode("utf-8", errors="replace")

                # Extract URLs
                for match in self.URL_PATTERN.finditer(text):
                    url = match.group(0).rstrip(".,;:!?)>]")
                    if url not in seen_urls:
                        seen_urls.add(url)
                        url_info = {
                            "url": url,
                            "source": content_type,
                            "is_suspicious": self._is_suspicious_url(url),
                        }
                        self.urls.append(url_info)

                # Check for defanged URLs
                for match in self.DEFANGED_PATTERN.finditer(text):
                    defanged = match.group(0)
                    # Re-fang
                    refanged = defanged.replace("hxxp", "http").replace("[.]", ".")
                    if refanged not in seen_urls:
                        seen_urls.add(refanged)
                        self.urls.append({
                            "url": refanged,
                            "source": f"{content_type} (defanged)",
                            "is_suspicious": True,
                            "original": defanged,
                        })

    def _is_suspicious_url(self, url):
        """Check if a URL has suspicious characteristics."""
        suspicious = False
        url_lower = url.lower()

        # IP address in URL
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
            suspicious = True

        # Uncommon TLDs
        shady_tlds = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf",
                      ".work", ".click", ".link", ".info", ".buzz"]
        for tld in shady_tlds:
            if tld in url_lower:
                suspicious = True

        # Data URIs
        if url_lower.startswith("data:"):
            suspicious = True

        # Very long URLs (potential obfuscation)
        if len(url) > 200:
            suspicious = True

        # URL shorteners
        shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly",
                       "is.gd", "buff.ly", "rebrand.ly"]
        for s in shorteners:
            if s in url_lower:
                suspicious = True

        return suspicious

    def _analyze_headers(self):
        """Analyze email headers for suspicious patterns."""
        # SPF check
        spf = str(self.msg.get("Received-SPF", ""))
        if spf and "fail" in spf.lower():
            self.indicators.append({
                "type": "SPF_FAIL",
                "severity": "HIGH",
                "detail": f"SPF check failed: {spf[:200]}",
            })

        # DKIM check
        auth_results = str(self.msg.get("Authentication-Results", ""))
        if auth_results:
            if "dkim=fail" in auth_results.lower():
                self.indicators.append({
                    "type": "DKIM_FAIL",
                    "severity": "HIGH",
                    "detail": "DKIM signature validation failed",
                })
            if "dmarc=fail" in auth_results.lower():
                self.indicators.append({
                    "type": "DMARC_FAIL",
                    "severity": "HIGH",
                    "detail": "DMARC validation failed",
                })

        # Originating IP
        orig_ip = str(self.msg.get("X-Originating-IP", ""))
        if orig_ip:
            self.indicators.append({
                "type": "ORIGINATING_IP",
                "severity": "INFO",
                "detail": f"X-Originating-IP: {orig_ip}",
            })

        # Suspicious subject keywords
        subject = self.metadata.get("subject", "").lower()
        phishing_keywords = [
            "urgent", "verify your account", "suspended",
            "click here", "confirm your", "unusual activity",
            "security alert", "update your payment",
            "invoice", "wire transfer", "password expired",
        ]
        for kw in phishing_keywords:
            if kw in subject:
                self.indicators.append({
                    "type": "PHISHING_KEYWORD",
                    "severity": "MEDIUM",
                    "detail": f"Subject contains phishing keyword: '{kw}'",
                })
                break

    def _build_result(self):
        """Build the final extraction result."""
        # Determine routing recommendations
        routes = []

        for att in self.attachments:
            routes.append({
                "type": "FILE_SANDBOX",
                "target": att["save_path"],
                "filename": att["filename"],
                "reason": f"Attachment ({att['extension']}, {att['size']} bytes)",
                "priority": "HIGH" if att["is_dangerous"] else "MEDIUM",
            })

        for url_info in self.urls:
            if url_info["is_suspicious"]:
                routes.append({
                    "type": "URL_PIPELINE",
                    "target": url_info["url"],
                    "reason": "Suspicious URL in email body",
                    "priority": "HIGH",
                })
            else:
                routes.append({
                    "type": "URL_PIPELINE",
                    "target": url_info["url"],
                    "reason": "URL in email body",
                    "priority": "LOW",
                })

        # Overall risk
        critical_count = sum(1 for i in self.indicators if i["severity"] == "CRITICAL")
        high_count = sum(1 for i in self.indicators if i["severity"] == "HIGH")

        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count >= 2:
            risk_level = "HIGH"
        elif high_count >= 1 or len(self.attachments) > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "source_file": self.eml_path,
            "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "metadata": self.metadata,
            "attachments": self.attachments,
            "urls": self.urls,
            "indicators": self.indicators,
            "routing": routes,
            "summary": {
                "total_attachments": len(self.attachments),
                "dangerous_attachments": sum(1 for a in self.attachments if a["is_dangerous"]),
                "total_urls": len(self.urls),
                "suspicious_urls": sum(1 for u in self.urls if u["is_suspicious"]),
                "total_indicators": len(self.indicators),
                "risk_level": risk_level,
                "routes_to_sandbox": sum(1 for r in routes if r["type"] == "FILE_SANDBOX"),
                "routes_to_url_pipeline": sum(1 for r in routes if r["type"] == "URL_PIPELINE"),
            },
        }

    def print_summary(self, result=None):
        """Print extraction summary to console."""
        if result is None:
            result = self.extract()

        s = result["summary"]
        m = result["metadata"]

        print("\n" + "=" * 60)
        print("  EMAIL EXTRACTION REPORT")
        print("=" * 60)
        print(f"  From:    {m['from']}")
        print(f"  To:      {m['to']}")
        print(f"  Subject: {m['subject']}")
        print(f"  Date:    {m['date']}")
        print(f"  Risk:    {s['risk_level']}")
        print()
        print(f"  Attachments: {s['total_attachments']} ({s['dangerous_attachments']} dangerous)")
        for att in result["attachments"]:
            flag = " [DANGEROUS]" if att["is_dangerous"] else ""
            print(f"    -> {att['filename']} ({att['size']} bytes, {att['extension']}){flag}")
            print(f"       SHA256: {att['sha256']}")

        print(f"\n  URLs: {s['total_urls']} ({s['suspicious_urls']} suspicious)")
        for url_info in result["urls"][:10]:
            flag = " [SUSPICIOUS]" if url_info["is_suspicious"] else ""
            print(f"    -> {url_info['url'][:80]}{flag}")

        if result["indicators"]:
            print(f"\n  Indicators ({s['total_indicators']}):")
            for ind in result["indicators"]:
                print(f"    [{ind['severity']}] {ind['type']}: {ind['detail']}")

        print(f"\n  Routing Recommendations:")
        for route in result["routing"]:
            print(f"    [{route['priority']}] {route['type']}: {route['target'][:60]}")

        print("=" * 60)
        return result


def process_batch(directory, output_dir=None):
    """Process all .eml files in a directory."""
    eml_files = list(Path(directory).glob("*.eml"))
    print(f"Found {len(eml_files)} .eml files in {directory}")

    results = []
    for eml_path in eml_files:
        try:
            out_dir = output_dir or os.path.join(directory, "extracted", eml_path.stem)
            extractor = EmailExtractor(str(eml_path), out_dir)
            result = extractor.extract()
            results.append(result)
            risk = result["summary"]["risk_level"]
            atts = result["summary"]["total_attachments"]
            urls = result["summary"]["total_urls"]
            print(f"  [{risk:8s}] {eml_path.name}: {atts} attachments, {urls} URLs")
        except Exception as e:
            print(f"  [ERROR]  {eml_path.name}: {e}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Email Attachment & URL Extractor")
    parser.add_argument("input", help="Path to .eml file or directory")
    parser.add_argument("--batch", action="store_true",
                        help="Process all .eml files in directory")
    parser.add_argument("--output", "-o", default=None,
                        help="Output directory for extracted files")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    args = parser.parse_args()

    if args.batch or os.path.isdir(args.input):
        results = process_batch(args.input, args.output)
        if args.json:
            print(json.dumps(results, indent=2))
    else:
        extractor = EmailExtractor(args.input, args.output)
        result = extractor.extract()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            extractor.print_summary(result)

        # Save JSON report
        report_path = args.input.replace(".eml", "_extraction.json")
        with open(report_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[SAVED] {report_path}")


if __name__ == "__main__":
    main()
