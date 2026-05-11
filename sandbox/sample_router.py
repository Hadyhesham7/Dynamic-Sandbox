"""
sample_router.py - Sample Type Detection & Routing Engine
===========================================================
Detects file types from magic bytes and routes samples to the
correct analysis strategy.

Supported file types:
  - PE Executable (.exe, .dll, .scr) → Direct sandbox
  - Office OLE (.doc, .xls, .ppt)   → Macro extraction + Word execution
  - Office OOXML (.docx, .xlsm)     → Macro extraction + Word execution
  - ZIP Archive (.zip)               → Extract contents + route each
  - OLE Embedded Objects             → Extract embedded PEs

Usage:
    from sample_router import SampleRouter
    router = SampleRouter()
    result = router.analyze(filepath)
"""

import os
import sys
import shutil
import tempfile
import hashlib
import zipfile

# oletools imports
try:
    from oletools.olevba import VBA_Parser, VBA_Scanner
    from oletools import oleobj
    import olefile
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False
    print("[ROUTER] WARNING: oletools not installed. Run: pip install oletools")


# ── Magic Byte Signatures ──
MAGIC_SIGNATURES = {
    b"MZ":             "PE_EXECUTABLE",
    b"\xd0\xcf\x11\xe0": "OFFICE_OLE",      # OLE2 Compound (DOC/XLS/PPT)
    b"PK":             "ZIP_BASED",          # Could be OOXML or plain ZIP
    b"Rar!":           "RAR_ARCHIVE",
    b"\x1f\x8b":       "GZIP_ARCHIVE",
}

# Office OOXML extensions
OOXML_EXTENSIONS = {
    ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm",
    ".dotx", ".dotm", ".xltx", ".xltm",
}

# Macro-capable extensions
MACRO_EXTENSIONS = {
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".dot", ".dotm", ".xlt", ".xltm",
}

# PE extensions
PE_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx"}

# Common malware archive passwords
ARCHIVE_PASSWORDS = [None, b"infected", b"malware", b"virus", b"123456", b"password"]

# Suspicious VBA keywords
SUSPICIOUS_VBA_KEYWORDS = [
    "shell", "createobject", "wscript.shell", "powershell",
    "cmd.exe", "urldownloadtofile", "auto_open", "document_open",
    "workbook_open", "autoexec", "autoopen", "documentopen",
    "environ", "kill", "filesystemobject", "adodb.stream",
    "xmlhttp", "winhttp", "inet", "shellexecute",
    "regwrite", "regread", "createprocess",
]


class SampleRouter:
    """Detects file type and routes samples for analysis."""

    def __init__(self, extract_dir=None):
        """
        Args:
            extract_dir: Directory for extracted files. If None, uses a temp dir.
        """
        self.extract_dir = extract_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "reports", "artifacts", "extracted"
        )
        os.makedirs(self.extract_dir, exist_ok=True)

    # ══════════════════════════════════════════════════════════
    #  FILE TYPE DETECTION
    # ══════════════════════════════════════════════════════════

    def detect_type(self, filepath):
        """
        Detect file type from magic bytes and extension.

        Returns:
            dict with:
                type: str — PE_EXECUTABLE, OFFICE_OLE, OFFICE_OOXML,
                             ZIP_ARCHIVE, RAR_ARCHIVE, UNKNOWN
                ext: str — file extension
                description: str — human-readable description
                has_macros: bool — for Office files
        """
        if not os.path.exists(filepath):
            return {"type": "NOT_FOUND", "ext": "", "description": "File not found"}

        ext = os.path.splitext(filepath)[1].lower()

        # Read magic bytes
        try:
            with open(filepath, "rb") as f:
                header = f.read(8)
        except (PermissionError, OSError):
            return {"type": "UNREADABLE", "ext": ext, "description": "Cannot read file"}

        # Match magic bytes
        magic_type = None
        for sig, ftype in MAGIC_SIGNATURES.items():
            if header[:len(sig)] == sig:
                magic_type = ftype
                break

        # Determine final type
        result = {"ext": ext, "has_macros": False}

        if magic_type == "PE_EXECUTABLE":
            result["type"] = "PE_EXECUTABLE"
            result["description"] = f"PE Executable ({ext or '.exe'})"

        elif magic_type == "OFFICE_OLE":
            result["type"] = "OFFICE_OLE"
            result["description"] = f"Office OLE Document ({ext})"
            # Check for macros
            if OLETOOLS_AVAILABLE:
                result["has_macros"] = self._check_macros(filepath)

        elif magic_type == "ZIP_BASED":
            if ext in OOXML_EXTENSIONS:
                result["type"] = "OFFICE_OOXML"
                result["description"] = f"Office OOXML Document ({ext})"
                if OLETOOLS_AVAILABLE:
                    result["has_macros"] = self._check_macros(filepath)
            else:
                result["type"] = "ZIP_ARCHIVE"
                result["description"] = f"ZIP Archive ({ext})"

        elif magic_type == "RAR_ARCHIVE":
            result["type"] = "RAR_ARCHIVE"
            result["description"] = f"RAR Archive ({ext})"

        elif magic_type == "GZIP_ARCHIVE":
            result["type"] = "GZIP_ARCHIVE"
            result["description"] = f"GZIP Archive ({ext})"

        else:
            result["type"] = "UNKNOWN"
            result["description"] = f"Unknown file type ({ext})"

        # File metadata
        result["size"] = os.path.getsize(filepath)
        result["sha256"] = self._hash_file(filepath)
        result["filename"] = os.path.basename(filepath)

        return result

    def _check_macros(self, filepath):
        """Check if an Office file contains VBA macros."""
        try:
            parser = VBA_Parser(filepath)
            has = parser.detect_vba_macros()
            parser.close()
            return has
        except Exception:
            return False

    def _hash_file(self, filepath):
        """Compute SHA-256 hash."""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    # ══════════════════════════════════════════════════════════
    #  MACRO EXTRACTION (Office Documents)
    # ══════════════════════════════════════════════════════════

    def extract_macros(self, filepath):
        """
        Extract VBA macros from an Office document.

        Returns:
            dict with:
                has_macros: bool
                macro_count: int
                macros: list of {name, code, suspicious, suspicious_keywords}
                auto_exec: list of auto-execution triggers found
        """
        if not OLETOOLS_AVAILABLE:
            return {"has_macros": False, "error": "oletools not installed"}

        result = {
            "has_macros": False,
            "macro_count": 0,
            "macros": [],
            "auto_exec": [],
            "suspicious_count": 0,
        }

        try:
            parser = VBA_Parser(filepath)
            if not parser.detect_vba_macros():
                parser.close()
                return result

            result["has_macros"] = True

            # Extract each macro
            for (filename, stream, vba_name, vba_code) in parser.extract_macros():
                code_lower = vba_code.lower()

                # Find suspicious keywords
                found_keywords = [
                    kw for kw in SUSPICIOUS_VBA_KEYWORDS
                    if kw in code_lower
                ]
                is_suspicious = len(found_keywords) > 0

                macro_entry = {
                    "name": vba_name,
                    "stream": stream,
                    "code": vba_code,
                    "code_length": len(vba_code),
                    "suspicious": is_suspicious,
                    "suspicious_keywords": found_keywords,
                }
                result["macros"].append(macro_entry)

                if is_suspicious:
                    result["suspicious_count"] += 1

                # Check for auto-execution triggers
                auto_triggers = [
                    "auto_open", "autoopen", "document_open", "documentopen",
                    "workbook_open", "auto_close", "autoexec", "autoclose",
                ]
                for trigger in auto_triggers:
                    if trigger in code_lower:
                        result["auto_exec"].append(trigger)

            result["macro_count"] = len(result["macros"])

            # Also run VBA_Scanner for IOCs
            try:
                scanner = VBA_Scanner(parser.get_vba_code_all_modules())
                scan_results = scanner.scan()
                result["scan_summary"] = [
                    {"type": r[0], "keyword": r[1], "description": r[2]}
                    for r in scan_results
                ]
            except Exception:
                pass

            parser.close()

        except Exception as e:
            result["error"] = str(e)

        return result

    # ══════════════════════════════════════════════════════════
    #  OLE EMBEDDED OBJECT EXTRACTION
    # ══════════════════════════════════════════════════════════

    def extract_ole_objects(self, filepath):
        """
        Extract OLE embedded objects (e.g., embedded EXE in Word doc).

        Returns:
            list of dicts with: filename, path, size, type, is_pe
        """
        if not OLETOOLS_AVAILABLE:
            return []

        extracted = []
        ole_dir = os.path.join(self.extract_dir, "ole_objects")
        os.makedirs(ole_dir, exist_ok=True)

        try:
            # Method 1: oleobj — extracts embedded OLE objects
            for index, ole_entry in enumerate(oleobj.find_ole(filepath)):
                try:
                    if hasattr(ole_entry, 'filename') and ole_entry.filename:
                        out_name = ole_entry.filename
                    else:
                        out_name = f"embedded_object_{index}"

                    out_path = os.path.join(ole_dir, out_name)

                    if hasattr(ole_entry, 'oledata') and ole_entry.oledata:
                        with open(out_path, "wb") as f:
                            f.write(ole_entry.oledata)

                        is_pe = self._is_pe(out_path)
                        extracted.append({
                            "filename": out_name,
                            "path": out_path,
                            "size": os.path.getsize(out_path),
                            "is_pe": is_pe,
                            "type": "PE Executable" if is_pe else "Data",
                        })
                except Exception:
                    continue

        except Exception:
            pass

        # Method 2: If it's OLE2, also check internal streams
        try:
            if olefile.isOleFile(filepath):
                ole = olefile.OleFileIO(filepath)
                for stream in ole.listdir():
                    stream_path = "/".join(stream)
                    if any(s.lower() in ("package", "ole10native",
                                         "contents") for s in stream):
                        try:
                            data = ole.openstream(stream).read()
                            out_name = f"stream_{stream[-1]}"
                            out_path = os.path.join(ole_dir, out_name)
                            with open(out_path, "wb") as f:
                                f.write(data)

                            is_pe = data[:2] == b"MZ"
                            if is_pe or len(data) > 1024:
                                extracted.append({
                                    "filename": out_name,
                                    "path": out_path,
                                    "size": len(data),
                                    "is_pe": is_pe,
                                    "type": "PE Executable" if is_pe else "Embedded Data",
                                    "stream": stream_path,
                                })
                        except Exception:
                            continue
                ole.close()
        except Exception:
            pass

        return extracted

    def _is_pe(self, filepath):
        """Check if file starts with MZ header."""
        try:
            with open(filepath, "rb") as f:
                return f.read(2) == b"MZ"
        except Exception:
            return False

    # ══════════════════════════════════════════════════════════
    #  ARCHIVE EXTRACTION (ZIP)
    # ══════════════════════════════════════════════════════════

    def extract_archive(self, filepath):
        """
        Extract ZIP archive contents.

        Returns:
            list of dicts with: filename, path, size, type
        """
        archive_dir = os.path.join(self.extract_dir, "archive_contents")
        os.makedirs(archive_dir, exist_ok=True)

        extracted = []
        ext = os.path.splitext(filepath)[1].lower()

        if ext == ".zip" or self._is_zip(filepath):
            extracted = self._extract_zip(filepath, archive_dir)
        else:
            print(f"[ROUTER] Unsupported archive format: {ext}")

        return extracted

    def _is_zip(self, filepath):
        """Check if file is a ZIP."""
        try:
            with open(filepath, "rb") as f:
                return f.read(2) == b"PK"
        except Exception:
            return False

    def _extract_zip(self, filepath, dest_dir):
        """Extract ZIP with common malware password attempts."""
        extracted = []

        try:
            zf = zipfile.ZipFile(filepath, "r")
        except zipfile.BadZipFile:
            print("[ROUTER] ERROR: Invalid ZIP file")
            return []

        # Check if encrypted
        is_encrypted = any(zi.flag_bits & 0x1 for zi in zf.infolist())

        if is_encrypted:
            print("[ROUTER] ZIP is password-protected, trying common passwords...")
            success = False
            for pwd in ARCHIVE_PASSWORDS:
                if pwd is None:
                    continue
                try:
                    zf.extractall(dest_dir, pwd=pwd)
                    print(f"[ROUTER]   Password found: {pwd.decode()}")
                    success = True
                    break
                except (RuntimeError, zipfile.BadZipFile):
                    continue

            if not success:
                print("[ROUTER] ERROR: Could not crack ZIP password")
                zf.close()
                return []
        else:
            zf.extractall(dest_dir)

        zf.close()

        # Enumerate extracted files
        for root, dirs, files in os.walk(dest_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                file_type = self.detect_type(fpath)
                extracted.append({
                    "filename": fname,
                    "path": fpath,
                    "size": os.path.getsize(fpath),
                    "type": file_type["type"],
                    "description": file_type["description"],
                })

        return extracted

    # ══════════════════════════════════════════════════════════
    #  ROUTING DECISION
    # ══════════════════════════════════════════════════════════

    def route(self, filepath):
        """
        Analyze file type and determine the analysis strategy.

        Returns:
            dict with:
                file_info: file type detection results
                strategy: str — "DIRECT_PE", "OFFICE_DYNAMIC", "EXTRACT_AND_ROUTE"
                target_exe: str — path to the executable to sandbox
                target_args: list — arguments for the target process
                macros: dict — macro extraction results (if Office)
                ole_objects: list — extracted OLE objects (if Office)
                extracted_files: list — files from archive (if archive)
                pe_targets: list — PE files found for analysis
        """
        print(f"\n[ROUTER] Analyzing: {os.path.basename(filepath)}")

        file_info = self.detect_type(filepath)
        ftype = file_info["type"]

        print(f"[ROUTER] Detected: {file_info['description']}")
        print(f"[ROUTER] Size: {file_info.get('size', '?')} bytes")
        print(f"[ROUTER] SHA256: {file_info.get('sha256', '?')}")

        result = {
            "file_info": file_info,
            "strategy": None,
            "target_exe": None,
            "target_args": [],
            "macros": None,
            "ole_objects": [],
            "extracted_files": [],
            "pe_targets": [],
        }

        # ── PE EXECUTABLE → direct sandbox ──
        if ftype == "PE_EXECUTABLE":
            print("[ROUTER] Strategy: DIRECT PE EXECUTION")
            result["strategy"] = "DIRECT_PE"
            result["target_exe"] = filepath
            result["pe_targets"] = [filepath]

        # ── OFFICE DOCUMENT → extract macros + open in Word/Excel ──
        elif ftype in ("OFFICE_OLE", "OFFICE_OOXML"):
            print("[ROUTER] Extracting VBA macros...")
            macros = self.extract_macros(filepath)
            result["macros"] = macros

            if macros["has_macros"]:
                print(f"[ROUTER]   Found {macros['macro_count']} macro(s) "
                      f"({macros['suspicious_count']} suspicious)")
                for m in macros["macros"]:
                    tag = "[!!]" if m["suspicious"] else "[--]"
                    print(f"[ROUTER]   {tag} {m['name']} "
                          f"({m['code_length']} chars)")
                    if m["suspicious_keywords"]:
                        print(f"[ROUTER]       Keywords: "
                              f"{', '.join(m['suspicious_keywords'])}")

                if macros["auto_exec"]:
                    print(f"[ROUTER]   Auto-execution triggers: "
                          f"{', '.join(set(macros['auto_exec']))}")
            else:
                print("[ROUTER]   No VBA macros found")

            # Extract OLE embedded objects
            print("[ROUTER] Checking for OLE embedded objects...")
            ole_objects = self.extract_ole_objects(filepath)
            result["ole_objects"] = ole_objects

            if ole_objects:
                print(f"[ROUTER]   Found {len(ole_objects)} embedded object(s)")
                for obj in ole_objects:
                    tag = "[!!]" if obj["is_pe"] else "[--]"
                    print(f"[ROUTER]   {tag} {obj['filename']} "
                          f"({obj['size']} bytes, {obj['type']})")

                # Collect PE targets from embedded objects
                pe_from_ole = [o["path"] for o in ole_objects if o["is_pe"]]
                result["pe_targets"].extend(pe_from_ole)
            else:
                print("[ROUTER]   No embedded objects found")

            # Strategy: Open in Word for dynamic analysis
            ext = file_info["ext"]
            if ext in (".doc", ".docx", ".docm", ".dot", ".dotm", ".dotx"):
                app = self._find_word()
            elif ext in (".xls", ".xlsx", ".xlsm", ".xlt", ".xltm"):
                app = self._find_excel()
            else:
                app = self._find_word()  # Default to Word

            if app:
                print(f"[ROUTER] Strategy: OFFICE DYNAMIC ANALYSIS")
                print(f"[ROUTER]   Application: {os.path.basename(app)}")
                result["strategy"] = "OFFICE_DYNAMIC"
                result["target_exe"] = app
                result["target_args"] = [filepath]
            else:
                print("[ROUTER] WARNING: Office not found!")
                if result["pe_targets"]:
                    print("[ROUTER] Falling back to embedded PE analysis")
                    result["strategy"] = "DIRECT_PE"
                    result["target_exe"] = result["pe_targets"][0]
                else:
                    result["strategy"] = "STATIC_ONLY"
                    print("[ROUTER] Using static macro analysis only")

        # ── ZIP ARCHIVE → extract and route each file ──
        elif ftype == "ZIP_ARCHIVE":
            print("[ROUTER] Extracting archive contents...")
            extracted = self.extract_archive(filepath)
            result["extracted_files"] = extracted

            if extracted:
                print(f"[ROUTER]   Extracted {len(extracted)} file(s):")
                for ef in extracted:
                    tag = "[!!]" if ef["type"] == "PE_EXECUTABLE" else "[--]"
                    print(f"[ROUTER]   {tag} {ef['filename']} "
                          f"({ef['size']} bytes, {ef['description']})")

                # Collect PE targets
                pe_from_archive = [
                    ef["path"] for ef in extracted
                    if ef["type"] == "PE_EXECUTABLE"
                ]
                result["pe_targets"].extend(pe_from_archive)

                # Collect Office files for further routing
                office_from_archive = [
                    ef for ef in extracted
                    if ef["type"] in ("OFFICE_OLE", "OFFICE_OOXML")
                ]

                if pe_from_archive:
                    print(f"[ROUTER] Strategy: EXTRACT AND SANDBOX "
                          f"({len(pe_from_archive)} PE file(s))")
                    result["strategy"] = "EXTRACT_AND_ROUTE"
                    result["target_exe"] = pe_from_archive[0]
                elif office_from_archive:
                    # Re-route the first Office file
                    print("[ROUTER] Found Office document in archive, re-routing...")
                    sub = self.route(office_from_archive[0]["path"])
                    result["strategy"] = sub["strategy"]
                    result["target_exe"] = sub["target_exe"]
                    result["target_args"] = sub["target_args"]
                    result["macros"] = sub["macros"]
                    result["ole_objects"] = sub["ole_objects"]
                    result["pe_targets"].extend(sub["pe_targets"])
                else:
                    result["strategy"] = "NO_EXECUTABLE"
                    print("[ROUTER] No executable content found in archive")
            else:
                result["strategy"] = "EXTRACT_FAILED"
                print("[ROUTER] Failed to extract archive")

        else:
            result["strategy"] = "UNSUPPORTED"
            print(f"[ROUTER] Unsupported file type: {ftype}")

        return result

    # ── Office Application Locators ──

    def _find_word(self):
        """Find WINWORD.EXE on the system."""
        common_paths = [
            os.path.expandvars(r"%ProgramFiles%\Microsoft Office\root\Office16\WINWORD.EXE"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft Office\root\Office16\WINWORD.EXE"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft Office\Office16\WINWORD.EXE"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft Office\Office16\WINWORD.EXE"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft Office\root\Office15\WINWORD.EXE"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft Office\root\Office15\WINWORD.EXE"),
        ]
        for p in common_paths:
            if os.path.exists(p):
                return p

        # Try registry or PATH
        import shutil
        found = shutil.which("WINWORD.EXE") or shutil.which("WINWORD")
        return found

    def _find_excel(self):
        """Find EXCEL.EXE on the system."""
        common_paths = [
            os.path.expandvars(r"%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft Office\root\Office16\EXCEL.EXE"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft Office\Office16\EXCEL.EXE"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft Office\Office16\EXCEL.EXE"),
        ]
        for p in common_paths:
            if os.path.exists(p):
                return p

        import shutil
        found = shutil.which("EXCEL.EXE") or shutil.which("EXCEL")
        return found

    # ══════════════════════════════════════════════════════════
    #  CLI DISPLAY
    # ══════════════════════════════════════════════════════════

    def print_routing_summary(self, route_result):
        """Print a formatted summary of the routing decision."""
        W = 60
        print()
        print("=" * W)
        print("  SAMPLE ROUTING SUMMARY")
        print("=" * W)

        fi = route_result["file_info"]
        print(f"  File:      {fi.get('filename', '?')}")
        print(f"  Type:      {fi.get('description', '?')}")
        print(f"  Size:      {fi.get('size', '?')} bytes")
        print(f"  SHA256:    {fi.get('sha256', '?')}")
        print(f"  Strategy:  {route_result['strategy']}")

        if route_result["target_exe"]:
            print(f"  Target:    {os.path.basename(route_result['target_exe'])}")
        if route_result["target_args"]:
            print(f"  Args:      {' '.join(str(a) for a in route_result['target_args'])}")

        # Macros summary
        macros = route_result.get("macros")
        if macros and macros.get("has_macros"):
            print(f"\n  Macros:    {macros['macro_count']} found "
                  f"({macros['suspicious_count']} suspicious)")
            if macros.get("auto_exec"):
                print(f"  AutoExec:  {', '.join(set(macros['auto_exec']))}")

        # PE targets
        pe = route_result.get("pe_targets", [])
        if pe:
            print(f"\n  PE Targets: {len(pe)}")
            for p in pe:
                print(f"    -> {os.path.basename(p)}")

        print("=" * W)


# ── Standalone Usage ──
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Sample Router")
    parser.add_argument("file", help="File to analyze")
    args = parser.parse_args()

    router = SampleRouter()
    result = router.route(args.file)
    router.print_routing_summary(result)
