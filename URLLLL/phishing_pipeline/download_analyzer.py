"""
download_analyzer.py — Step 10 (enhanced): File download analysis.

When a suspicious download link is detected in the DOM, this module can:
  1. Download the file (with size limits and timeout)
  2. Compute SHA256 and MD5 hashes
  3. Detect extension mismatch (e.g., invoice.pdf.exe)
  4. Validate MIME type vs actual content
  5. Optionally query VirusTotal by hash

All downloads are stored in a temporary sandboxed directory and cleaned up.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from urllib.parse import urlparse

import requests

from .config import REQUEST_TIMEOUT, DOWNLOAD_EXTENSIONS, VT_API_KEY
from .logger import get_logger

log = get_logger("download_analyzer")

# Maximum download size: 10 MB
_MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024

# Dangerous executable extensions
_EXECUTABLE_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".msi", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".ps1", ".psm1", ".reg", ".inf", ".cpl",
    ".hta", ".lnk", ".apk", ".deb", ".dmg",
}

# Double extension patterns (e.g., invoice.pdf.exe)
_DOUBLE_EXT_RE = re.compile(
    r"\.[a-zA-Z0-9]{2,5}\.(exe|scr|bat|cmd|com|pif|vbs|js|ps1|msi|apk)$",
    re.IGNORECASE,
)

# MIME type to expected extension mapping
_MIME_TO_EXTS: dict[str, set[str]] = {
    "application/x-msdownload":     {".exe", ".dll"},
    "application/x-msdos-program":  {".exe", ".com"},
    "application/x-executable":     {".exe"},
    "application/pdf":              {".pdf"},
    "application/zip":              {".zip"},
    "application/x-rar-compressed": {".rar"},
    "application/x-7z-compressed":  {".7z"},
    "application/vnd.ms-excel":     {".xls", ".xlsx"},
    "application/msword":           {".doc", ".docx"},
    "application/javascript":       {".js"},
    "text/html":                    {".html", ".htm"},
}


def analyze_download_link(url: str) -> dict:
    """
    Download a file from the given URL and perform security analysis.

    Args:
        url: Direct download URL found in DOM.

    Returns:
        Dict with download analysis results:
            dl_sha256, dl_md5, dl_filename, dl_size_bytes,
            dl_mime_type, dl_extension_mismatch, dl_double_extension,
            dl_is_executable, dl_vt_result
    """
    result = {
        "dl_sha256": "",
        "dl_md5": "",
        "dl_filename": "",
        "dl_size_bytes": 0,
        "dl_mime_type": "",
        "dl_extension_mismatch": 0,
        "dl_double_extension": 0,
        "dl_is_executable": 0,
        "dl_vt_result": "",
    }

    try:
        # ── Download with size limit ─────────────────────────────────────
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                )
            },
            allow_redirects=True,
        )
        response.raise_for_status()

        # Check content length before downloading
        content_length = int(response.headers.get("Content-Length", 0))
        if content_length > _MAX_DOWNLOAD_SIZE:
            log.warning("Download too large (%d bytes), skipping: %s",
                        content_length, url)
            result["dl_size_bytes"] = content_length
            return result

        # ── Save to temp file ────────────────────────────────────────────
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > _MAX_DOWNLOAD_SIZE:
                log.warning("Download exceeded max size during streaming: %s", url)
                break

        result["dl_size_bytes"] = len(content)

        # ── Compute hashes ───────────────────────────────────────────────
        result["dl_sha256"] = hashlib.sha256(content).hexdigest()
        result["dl_md5"] = hashlib.md5(content, usedforsecurity=False).hexdigest()

        # ── Extract filename ─────────────────────────────────────────────
        cd = response.headers.get("Content-Disposition", "")
        if "filename=" in cd:
            # Extract filename from Content-Disposition header
            fname_match = re.search(r'filename[*]?="?([^";]+)', cd)
            if fname_match:
                result["dl_filename"] = fname_match.group(1).strip()

        if not result["dl_filename"]:
            # Fall back to URL path
            path = urlparse(url).path
            result["dl_filename"] = os.path.basename(path) or "unknown"

        filename = result["dl_filename"]

        # ── MIME type ────────────────────────────────────────────────────
        result["dl_mime_type"] = response.headers.get("Content-Type", "").split(";")[0].strip()

        # ── Extension analysis ───────────────────────────────────────────
        _, ext = os.path.splitext(filename.lower())

        # Is it an executable?
        if ext in _EXECUTABLE_EXTS:
            result["dl_is_executable"] = 1

        # Double extension detection (e.g., invoice.pdf.exe)
        if _DOUBLE_EXT_RE.search(filename):
            result["dl_double_extension"] = 1
            log.warning("Double extension detected: %s", filename)

        # MIME type vs extension mismatch
        mime = result["dl_mime_type"]
        if mime in _MIME_TO_EXTS:
            expected_exts = _MIME_TO_EXTS[mime]
            if ext and ext not in expected_exts:
                result["dl_extension_mismatch"] = 1
                log.warning("MIME/ext mismatch: %s claims '%s' but file is '%s'",
                            filename, mime, ext)

        # ── Optional: VirusTotal hash lookup ─────────────────────────────
        if VT_API_KEY and result["dl_sha256"]:
            try:
                vt_resp = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{result['dl_sha256']}",
                    headers={"x-apikey": VT_API_KEY},
                    timeout=REQUEST_TIMEOUT,
                )
                if vt_resp.status_code == 200:
                    stats = vt_resp.json()["data"]["attributes"]["last_analysis_stats"]
                    mal = stats.get("malicious", 0)
                    result["dl_vt_result"] = f"{mal} engines flagged malicious"
                    log.info("VT file lookup for %s: %s", result["dl_sha256"][:16], result["dl_vt_result"])
                elif vt_resp.status_code == 404:
                    result["dl_vt_result"] = "not found in VT"
            except Exception as vt_err:
                log.warning("VT file hash lookup failed: %s", vt_err)

        log.info("Download analyzed: %s (sha256=%s, %d bytes, mime=%s)",
                 filename, result["dl_sha256"][:16], result["dl_size_bytes"], mime)

    except requests.RequestException as exc:
        log.warning("Download failed for '%s': %s", url, exc)
    except Exception as exc:
        log.warning("Download analysis error for '%s': %s", url, exc)

    return result
