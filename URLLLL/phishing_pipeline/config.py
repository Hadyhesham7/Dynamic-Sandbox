"""
config.py — Central configuration for the Phishing URL Analysis Pipeline.
All API keys, constants, and shared lists live here.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from the project root if it exists
load_dotenv(Path(__file__).parent.parent.parent / ".env")

# ──────────────────────────────────────────────────────────
# VirusTotal API Key
# Set via environment variable VT_API_KEY before running.
# ──────────────────────────────────────────────────────────
VT_API_KEY: str = os.environ.get("VT_API_KEY", "8a1568ab7ad3337d4ba1b0e3adf4c71313613a7092c28777ac8c2f91b5753a02")

# ──────────────────────────────────────────────────────────
# HTTP Request Settings
# ──────────────────────────────────────────────────────────
REQUEST_TIMEOUT: int = 10        # seconds for general requests
VT_POLL_WAIT: int = 15           # seconds to wait for VT scan to complete

# ──────────────────────────────────────────────────────────
# Playwright headless browser settings
# ──────────────────────────────────────────────────────────
PLAYWRIGHT_TIMEOUT: int = 20_000  # ms — page navigation timeout

# ──────────────────────────────────────────────────────────
# Screenshots directory (Step 7 — dynamic analysis)
# ──────────────────────────────────────────────────────────
import pathlib as _pathlib
# Resolve relative to URLLLL/ directory (parent of phishing_pipeline/)
_PIPELINE_DIR = _pathlib.Path(__file__).parent.resolve()
_URLLLL_DIR = _PIPELINE_DIR.parent
SCREENSHOTS_DIR: _pathlib.Path = _URLLLL_DIR / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)

# ──────────────────────────────────────────────────────────
# File download extension list (Step 10)
# ──────────────────────────────────────────────────────────
DOWNLOAD_EXTENSIONS: list[str] = [
    # Executables / installers — genuinely suspicious on a web page
    ".exe", ".msi", ".apk", ".dmg", ".pkg",
    ".scr", ".bat", ".cmd", ".vbs", ".ps1",
    ".deb", ".run",
    # Archives are suspicious only when served as direct downloads
    # NOT flagged here: .zip, .rar, .7z, .tar, .gz — too common on legit sites
    # NOT flagged: .pdf, .doc, .js — exist on virtually every website
]

# ──────────────────────────────────────────────────────────
# Suspicious Free / Abused TLDs (Step 4)
# ──────────────────────────────────────────────────────────
SUSPICIOUS_TLDS: set[str] = {
    # Free / abused gTLDs
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "pw", "cc",
    "buzz", "click", "link", "work", "rest",
    "loan", "win", "racing", "stream", "review",
    # Commonly abused info / biz TLDs
    "info", "biz", "mobi", "name",
    # Country codes historically abused for spam/malware
    "su",    # Soviet Union — no content policy enforcement
    "ru",    # Used in many spam campaigns  (note: many legit RU sites too)
    # New gTLDs abused for phishing/defacement
    "gdn", "men", "date", "faith", "trade", "webcam",
    "accountant", "science", "download", "party",
}

# ──────────────────────────────────────────────────────────
# Known URL shortener domains (Step 5)
# ──────────────────────────────────────────────────────────
SHORTENER_DOMAINS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.link",
    "rb.gy", "shorturl.at", "cutt.ly", "tiny.cc",
    "lnkd.in", "youtu.be", "amzn.to",
}

# ──────────────────────────────────────────────────────────
# Query parameters to strip during normalization (Step 2)
# ──────────────────────────────────────────────────────────
JUNK_PARAM_PREFIXES: tuple[str, ...] = (
    "utm_", "fbclid", "gclid", "msclkid",
    "tracking", "sessionid", "sid", "ref",
    "affiliate", "campaign",
)
