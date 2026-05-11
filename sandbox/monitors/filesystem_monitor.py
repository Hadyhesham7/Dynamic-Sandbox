"""
filesystem_monitor.py - File System Snapshot & Diff Monitor
============================================================
Takes before/after snapshots of monitored directories and reports:
  - Files created (dropped files)
  - Files modified
  - Files deleted
  - Directories created/removed

Usage:
    monitor = FileSystemMonitor()
    monitor.take_pre_snapshot()
    # ... run malware ...
    monitor.take_post_snapshot()
    report = monitor.generate_report()
    monitor.save_report("reports/raw/file_activity.json")
"""

import os
import json
import hashlib
import shutil
import time


class FileSystemMonitor:
    """Monitors file system changes by comparing before/after snapshots."""

    # Directories to monitor (expandable)
    DEFAULT_WATCH_DIRS = [
        os.path.expandvars(r"%TEMP%"),
        os.path.expandvars(r"%APPDATA%"),
        os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
        os.path.expandvars(r"%USERPROFILE%\Desktop"),
        os.path.expandvars(r"%USERPROFILE%\Documents"),
        os.path.expandvars(r"%USERPROFILE%\Downloads"),
    ]

    # File extensions to always track (even if in noisy directories)
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".scr", ".pif", ".com", ".hta", ".wsf", ".lnk",
        ".sys", ".drv", ".cpl", ".ocx", ".msi",
    }

    # Directories to SKIP (reduce noise on host)
    SKIP_PATTERNS = [
        "\\Google\\Chrome\\", "\\Mozilla\\Firefox\\",
        "\\Microsoft\\Edge\\", "\\Code\\",
        "\\__pycache__", "\\.git\\",
        "\\Windows\\Temp\\", "\\Logs\\",
    ]

    def __init__(self, watch_dirs=None, target_dir=None):
        """
        Args:
            watch_dirs: List of directories to monitor (default: standard locations)
            target_dir: Directory of the target executable (always monitored)
        """
        self.watch_dirs = list(watch_dirs or self.DEFAULT_WATCH_DIRS)
        if target_dir and target_dir not in self.watch_dirs:
            self.watch_dirs.append(target_dir)

        # Remove duplicates and non-existent paths
        self.watch_dirs = list(set(
            os.path.normpath(d) for d in self.watch_dirs if os.path.isdir(d)
        ))

        self.pre_snapshot = {}
        self.post_snapshot = {}
        self.pre_time = None
        self.post_time = None

    def _should_skip(self, filepath):
        """Check if a file path should be skipped (noise reduction)."""
        for pattern in self.SKIP_PATTERNS:
            if pattern.lower() in filepath.lower():
                return True
        return False

    def _hash_file(self, filepath):
        """Compute SHA-256 and MD5 hashes of a file."""
        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
                    md5.update(chunk)
            return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}
        except (PermissionError, OSError, FileNotFoundError):
            return {"sha256": None, "md5": None}

    def _detect_file_type(self, filepath):
        """Detect real file type from magic bytes (header signature)."""
        SIGNATURES = {
            b"MZ": "PE Executable (EXE/DLL/SYS)",
            b"PK": "ZIP Archive (or DOCX/XLSX/JAR)",
            b"\x7fELF": "ELF Binary (Linux)",
            b"\x89PNG": "PNG Image",
            b"\xff\xd8\xff": "JPEG Image",
            b"GIF8": "GIF Image",
            b"%PDF": "PDF Document",
            b"Rar!": "RAR Archive",
            b"\x1f\x8b": "GZIP Archive",
        }
        try:
            with open(filepath, "rb") as f:
                header = f.read(4)
            for sig, desc in SIGNATURES.items():
                if header[:len(sig)] == sig:
                    return desc
            return "Unknown / Data"
        except (PermissionError, OSError, FileNotFoundError):
            return "Unreadable"

    def _scan_directory(self, directory, max_depth=3):
        """
        Scan a directory and return file metadata.
        
        Returns:
            dict: {filepath: {"size": int, "mtime": float, "hash": str}}
        """
        files = {}
        try:
            for root, dirs, filenames in os.walk(directory):
                # Limit depth
                depth = root.replace(directory, "").count(os.sep)
                if depth >= max_depth:
                    dirs.clear()
                    continue

                for fname in filenames:
                    filepath = os.path.join(root, fname)

                    if self._should_skip(filepath):
                        continue

                    try:
                        stat = os.stat(filepath)
                        hashes = self._hash_file(filepath)
                        files[filepath] = {
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "hash": hashes["sha256"],
                            "md5": hashes["md5"],
                        }
                    except (PermissionError, OSError, FileNotFoundError):
                        continue
        except (PermissionError, OSError):
            pass

        return files

    def take_pre_snapshot(self):
        """Take a snapshot of monitored directories BEFORE execution."""
        print("[FILE_MON] Taking pre-execution snapshot...")
        self.pre_time = time.time()
        self.pre_snapshot = {}

        for directory in self.watch_dirs:
            print(f"[FILE_MON]   Scanning: {directory}")
            self.pre_snapshot.update(self._scan_directory(directory))

        print(f"[FILE_MON]   Indexed {len(self.pre_snapshot)} files")
        return self.pre_snapshot

    def take_post_snapshot(self):
        """Take a snapshot of monitored directories AFTER execution."""
        print("[FILE_MON] Taking post-execution snapshot...")
        self.post_time = time.time()
        self.post_snapshot = {}

        for directory in self.watch_dirs:
            self.post_snapshot.update(self._scan_directory(directory))

        print(f"[FILE_MON]   Indexed {len(self.post_snapshot)} files")
        return self.post_snapshot

    def compare(self):
        """Compare pre and post snapshots to find changes."""
        if not self.pre_snapshot or not self.post_snapshot:
            print("[FILE_MON] ERROR: Must take both snapshots first")
            return None

        pre_paths = set(self.pre_snapshot.keys())
        post_paths = set(self.post_snapshot.keys())

        # New files (created/dropped)
        created_paths = post_paths - pre_paths
        created = []
        for p in sorted(created_paths):
            info = self.post_snapshot[p]
            ext = os.path.splitext(p)[1].lower()
            created.append({
                "path": p,
                "size": info["size"],
                "hash_sha256": info["hash"],
                "hash_md5": info.get("md5"),
                "file_type": self._detect_file_type(p),
                "extension": ext,
                "suspicious": ext in self.SUSPICIOUS_EXTENSIONS,
            })

        # Deleted files
        deleted_paths = pre_paths - post_paths
        deleted = []
        for p in sorted(deleted_paths):
            info = self.pre_snapshot[p]
            deleted.append({
                "path": p,
                "size": info["size"],
                "hash_sha256": info["hash"],
                "hash_md5": info.get("md5"),
            })

        # Modified files (same path, different hash or size)
        common_paths = pre_paths & post_paths
        modified = []
        for p in sorted(common_paths):
            pre_info = self.pre_snapshot[p]
            post_info = self.post_snapshot[p]

            if (pre_info["hash"] != post_info["hash"] or
                    pre_info["size"] != post_info["size"]):
                modified.append({
                    "path": p,
                    "old_size": pre_info["size"],
                    "new_size": post_info["size"],
                    "old_hash_sha256": pre_info["hash"],
                    "new_hash_sha256": post_info["hash"],
                    "old_hash_md5": pre_info.get("md5"),
                    "new_hash_md5": post_info.get("md5"),
                })

        return {
            "files_created": created,
            "files_modified": modified,
            "files_deleted": deleted,
        }

    def copy_dropped_files(self, dest_dir, diff=None):
        """Copy newly created files to an artifacts directory."""
        if diff is None:
            diff = self.compare()
        if not diff:
            return []

        os.makedirs(dest_dir, exist_ok=True)
        copied = []

        for entry in diff["files_created"]:
            src = entry["path"]
            if not os.path.exists(src):
                continue
            try:
                # Sanitize filename for artifacts
                safe_name = os.path.basename(src)
                dest = os.path.join(dest_dir, safe_name)

                # Avoid overwriting
                counter = 1
                while os.path.exists(dest):
                    name, ext = os.path.splitext(safe_name)
                    dest = os.path.join(dest_dir, f"{name}_{counter}{ext}")
                    counter += 1

                shutil.copy2(src, dest)
                entry["artifact_copy"] = dest
                copied.append(dest)
            except (PermissionError, OSError) as e:
                entry["copy_error"] = str(e)

        return copied

    def generate_report(self, artifacts_dir=None):
        """Generate the file activity report."""
        diff = self.compare()
        if not diff:
            return {"component": "file_activity", "data": {}}

        # Copy dropped files if artifacts directory provided
        if artifacts_dir:
            self.copy_dropped_files(artifacts_dir, diff)

        report = {
            "component": "file_activity",
            "version": "1.0",
            "timestamp": time.time(),
            "monitored_directories": self.watch_dirs,
            "pre_snapshot_files": len(self.pre_snapshot),
            "post_snapshot_files": len(self.post_snapshot),
            "data": {
                "files_created": diff["files_created"],
                "files_modified": diff["files_modified"],
                "files_deleted": diff["files_deleted"],
                "summary": {
                    "total_created": len(diff["files_created"]),
                    "total_modified": len(diff["files_modified"]),
                    "total_deleted": len(diff["files_deleted"]),
                    "suspicious_files": [
                        f["path"] for f in diff["files_created"]
                        if f.get("suspicious")
                    ],
                }
            }
        }

        return report

    def save_report(self, output_path, artifacts_dir=None):
        """Generate and save the report to a JSON file."""
        report = self.generate_report(artifacts_dir)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        data = report["data"]
        s = data["summary"]
        print(f"[FILE_MON] Report saved: {output_path}")
        print(f"[FILE_MON]   Created:  {s['total_created']} files")
        print(f"[FILE_MON]   Modified: {s['total_modified']} files")
        print(f"[FILE_MON]   Deleted:  {s['total_deleted']} files")

        # Show detailed info for each created file
        for f in data.get("files_created", []):
            path = f["path"]
            fname = os.path.basename(path)
            ftype = f.get("file_type", "Unknown")
            size = f["size"]
            tag = "[!!]" if f.get("suspicious") else "[--]"
            print(f"[FILE_MON]     {tag} {fname}")
            print(f"[FILE_MON]         Path: {path}")
            print(f"[FILE_MON]         Size: {size} bytes  |  Type: {ftype}")
            if f.get("hash_sha256"):
                print(f"[FILE_MON]         SHA256: {f['hash_sha256']}")
            if f.get("hash_md5"):
                print(f"[FILE_MON]         MD5:    {f['hash_md5']}")

        for f in data.get("files_modified", []):
            fname = os.path.basename(f["path"])
            old_hash = f.get('old_hash_sha256') or '?'
            new_hash = f.get('new_hash_sha256') or '?'
            print(f"[FILE_MON]     [MOD] {fname}")
            print(f"[FILE_MON]         Size: {f['old_size']} -> {f['new_size']} bytes")
            print(f"[FILE_MON]         SHA256: {old_hash[:16]}... -> {new_hash[:16]}...")

        return report


# --- Standalone usage ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="File System Monitor")
    parser.add_argument("--action", choices=["pre", "post", "demo"],
                        required=True, help="Action to perform")
    parser.add_argument("--snapshot-file", default="sandbox/reports/raw/fs_snapshot.json",
                        help="Path to save/load snapshot")
    parser.add_argument("--output", default="sandbox/reports/raw/file_activity.json",
                        help="Output report path")
    parser.add_argument("--watch", nargs="+", help="Extra directories to watch")
    args = parser.parse_args()

    monitor = FileSystemMonitor(watch_dirs=args.watch)

    if args.action == "pre":
        snap = monitor.take_pre_snapshot()
        os.makedirs(os.path.dirname(args.snapshot_file), exist_ok=True)
        with open(args.snapshot_file, "w") as f:
            json.dump(snap, f, indent=2)
        print(f"[FILE_MON] Pre-snapshot saved: {args.snapshot_file}")

    elif args.action == "post":
        if not os.path.exists(args.snapshot_file):
            print("[FILE_MON] ERROR: No pre-snapshot found. Run --action pre first.")
        else:
            with open(args.snapshot_file) as f:
                monitor.pre_snapshot = json.load(f)
            monitor.take_post_snapshot()
            artifacts = os.path.join(os.path.dirname(args.output),
                                     "..", "artifacts", "dropped_files")
            monitor.save_report(args.output, artifacts_dir=artifacts)

    elif args.action == "demo":
        print("[FILE_MON] === DEMO MODE ===")
        monitor.take_pre_snapshot()

        # Create test changes
        test_dir = os.path.expandvars(r"%TEMP%\sandbox_test")
        os.makedirs(test_dir, exist_ok=True)
        test_file = os.path.join(test_dir, "test_dropped.txt")
        with open(test_file, "w") as f:
            f.write("This is a test dropped file")

        monitor.take_post_snapshot()
        monitor.save_report(args.output)

        # Cleanup
        os.remove(test_file)
        os.rmdir(test_dir)
