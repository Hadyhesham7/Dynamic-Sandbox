"""
main.py — Interactive CLI for the Phishing URL Analysis Pipeline.

Input is auto-detected:
  - If it looks like a file path ending in .eml → parsed as email file
  - If it contains HTML tags → parsed as HTML email
  - If it starts with http/https → treated as a single URL
  - Otherwise → treated as plain text / email body

Usage:
    python main.py                              # interactive
    python main.py "https://example.com"        # CLI argument
"""

from __future__ import annotations

import sys
import os
import re
import email
from email import policy

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from phishing_pipeline.url_extractor import extract_urls
from dashboard import run_analysis

W = 60

_HTML_TAG_RE = re.compile(r"<\s*(a|form|iframe|img|script|div|html|body)\b", re.IGNORECASE)


def _banner():
    print()
    print("=" * W)
    print(" ██   ██ ███████ ███    ██ ██████  ██    ██ ")
    print(" ██   ██ ██      ████   ██ ██   ██  ██  ██  ")
    print(" ███████ █████   ██ ██  ██ ██   ██   ████   ")
    print(" ██   ██ ██      ██  ██ ██ ██   ██    ██    ")
    print(" ██   ██ ███████ ██   ████ ██████     ██    ")
    print()
    print("  URL Analysis Engine v3.0 — Hybrid ML Pipeline")
    print("=" * W)


def _ask_analysis_mode() -> bool:
    """Returns True to skip dynamic analysis (fast mode)."""
    print()
    print("  ┌─ Analysis Mode ─────────────────────────────────┐")
    print("  │  [1] ⚡ Fast   (static + ML — seconds)          │")
    print("  │  [2] 🔬 Full   (browser + screenshots + API)    │")
    print("  └──────────────────────────────────────────────────┘")
    try:
        choice = input("  Select [1/2] (default=1): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "1"
    if choice == "2":
        print("  → Full analysis selected")
        return False
    print("  → Fast analysis selected")
    return True


def _detect_and_read(raw: str) -> tuple[str, str]:
    """
    Auto-detect input type and return (content, detected_type).

    detected_type is one of: 'url', 'eml_file', 'html', 'text'
    """
    stripped = raw.strip().strip('"').strip("'")

    # 1) .eml file path
    if stripped.endswith(".eml") and os.path.isfile(stripped):
        try:
            with open(stripped, "r", encoding="utf-8", errors="replace") as f:
                msg = email.message_from_file(f, policy=policy.default)
            parts = []
            for pref in ("html", "plain"):
                body = msg.get_body(preferencelist=(pref,))
                if body:
                    c = body.get_content()
                    if c:
                        parts.append(c)
            if not parts:
                for part in msg.walk():
                    if part.get_content_type() in ("text/html", "text/plain"):
                        c = part.get_content()
                        if c:
                            parts.append(c)
            content = "\n".join(parts)
            return (content, "eml_file") if content else (raw, "text")
        except Exception:
            return raw, "text"

    # 2) Single URL (one line, starts with http)
    lines = [l for l in raw.strip().splitlines() if l.strip()]
    if len(lines) == 1 and lines[0].strip().startswith(("http://", "https://")):
        return raw.strip(), "url"

    # 3) HTML content (contains tags like <a, <form, <html, etc.)
    if _HTML_TAG_RE.search(raw):
        return raw, "html"

    # 4) Plain text / email body
    return raw, "text"


def main():
    _banner()

    # ── CLI argument mode ─────────────────────────────────────────────
    if len(sys.argv) > 1:
        raw_input = " ".join(sys.argv[1:])
    else:
        # ── Interactive mode ──────────────────────────────────────────
        print()
        print("  Paste a URL, email text, HTML, or .eml file path.")
        print("  Press Enter twice when done.")
        print("  " + "─" * 50)
        lines: list[str] = []
        try:
            while True:
                line = input()
                if line == "" and lines and lines[-1] == "":
                    break
                lines.append(line)
        except (EOFError, KeyboardInterrupt):
            pass
        raw_input = "\n".join(lines)

    if not raw_input.strip():
        print("\n  ⚠️  No input provided. Exiting.")
        sys.exit(0)

    # ── Auto-detect input type ────────────────────────────────────────
    content, input_type = _detect_and_read(raw_input)

    type_labels = {
        "url": "🔗 Single URL",
        "eml_file": "📎 .eml file",
        "html": "🌐 HTML email content",
        "text": "📧 Plain text / email body",
    }
    print(f"\n  Detected: {type_labels.get(input_type, input_type)}")

    # ── Extract URLs ──────────────────────────────────────────────────
    urls = extract_urls(content)
    if not urls:
        print("  ⚠️  No URLs found in input. Exiting.")
        sys.exit(0)

    print(f"  Found {len(urls)} URL(s):")
    for i, u in enumerate(urls[:10], 1):
        display = u[:62] + "…" if len(u) > 62 else u
        print(f"    [{i}] {display}")
    if len(urls) > 10:
        print(f"    ... and {len(urls) - 10} more")

    # ── Ask analysis mode ─────────────────────────────────────────────
    skip_dynamic = _ask_analysis_mode()

    # ── Run ───────────────────────────────────────────────────────────
    print()
    print("═" * W)
    print("  🚀 Starting analysis...")
    print("═" * W)

    run_analysis(content, skip_dynamic=skip_dynamic)

    print()
    print("═" * W)
    print("  ✅ Analysis complete.")
    print("═" * W)


if __name__ == "__main__":
    main()
