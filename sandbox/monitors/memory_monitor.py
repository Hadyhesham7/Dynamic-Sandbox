"""
memory_monitor.py - Memory Behavior Monitor
=============================================
Analyzes memory-related behavior from API hook logs and memory dump files.
Detects:
  - RWX memory allocations (potential unpacking/injection)
  - Process injection indicators
  - Suspicious memory patterns

Usage:
    monitor = MemoryMonitor()
    report = monitor.analyze(api_report_path, dumps_dir)
    monitor.save_report("reports/raw/memory_activity.json")
"""

import os
import json
import time
import math


class MemoryMonitor:
    """Analyzes memory behavior from API hook data and memory dumps."""

    # APIs that indicate suspicious memory behavior
    INJECTION_APIS = {
        "VirtualAllocEx", "WriteProcessMemory", "NtWriteVirtualMemory",
        "CreateRemoteThread", "NtCreateThreadEx",
        "QueueUserAPC", "SetThreadContext",
    }

    RWX_INDICATORS = {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    }

    UNPACK_INDICATORS = {
        "VirtualProtect",  # Changing page protection (common in unpackers)
        "FlushInstructionCache",  # Required after code modification
    }

    def __init__(self):
        self.api_calls = []
        self.dumps = []
        self.report_data = {}

    def _load_api_calls(self, api_report_path):
        """Load API calls from the collector report."""
        if not os.path.exists(api_report_path):
            print(f"[MEM_MON] WARNING: API report not found: {api_report_path}")
            return []

        with open(api_report_path) as f:
            report = json.load(f)

        calls = []
        for proc in report.get("behavior", {}).get("processes", []):
            for c in proc.get("calls", []):
                calls.append(c)

        return calls

    def _find_memory_dumps(self, dumps_dir):
        """Find memory dump files in the artifacts directory."""
        dumps = []
        if not os.path.isdir(dumps_dir):
            return dumps

        for fname in sorted(os.listdir(dumps_dir)):
            fpath = os.path.join(dumps_dir, fname)
            if os.path.isfile(fpath):
                size = os.path.getsize(fpath)
                dumps.append({
                    "filename": fname,
                    "path": fpath,
                    "size": size,
                    "entropy": self._calculate_entropy(fpath),
                    "has_pe_header": self._check_pe_header(fpath),
                    "printable_strings": self._extract_strings(fpath, min_len=6),
                })
        return dumps

    def _calculate_entropy(self, filepath, block_size=8192):
        """Calculate Shannon entropy of a file (high = encrypted/compressed)."""
        try:
            with open(filepath, "rb") as f:
                data = f.read(block_size)

            if not data:
                return 0.0

            freq = [0] * 256
            for byte in data:
                freq[byte] += 1

            entropy = 0.0
            length = len(data)
            for count in freq:
                if count > 0:
                    prob = count / length
                    entropy -= prob * math.log2(prob)

            return round(entropy, 2)
        except (OSError, PermissionError):
            return -1.0

    def _check_pe_header(self, filepath):
        """Check if a file starts with a PE header (MZ magic)."""
        try:
            with open(filepath, "rb") as f:
                magic = f.read(2)
                return magic == b"MZ"
        except (OSError, PermissionError):
            return False

    def _extract_strings(self, filepath, min_len=6, max_strings=50):
        """Extract printable ASCII strings from a binary file."""
        strings = []
        try:
            with open(filepath, "rb") as f:
                data = f.read(65536)  # First 64KB only

            current = []
            for byte in data:
                if 32 <= byte < 127:  # Printable ASCII
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        strings.append("".join(current))
                        if len(strings) >= max_strings:
                            break
                    current = []

            if len(current) >= min_len and len(strings) < max_strings:
                strings.append("".join(current))
        except (OSError, PermissionError):
            pass

        return strings

    def _analyze_memory_apis(self, calls):
        """Analyze memory-related API calls for suspicious patterns."""
        rwx_allocations = []
        injection_indicators = []
        unpack_indicators = []
        memory_ops = []

        for c in calls:
            api = c.get("api", "")
            cat = c.get("category", "")
            args = c.get("arguments", {})

            if cat != "MEM":
                # Check for injection APIs in PROC category too
                if api in self.INJECTION_APIS:
                    injection_indicators.append({
                        "api": api,
                        "args": args,
                        "time": c.get("time", 0),
                    })
                continue

            memory_ops.append({
                "api": api,
                "time": c.get("time", 0),
            })

            # Check for RWX allocations
            if api in self.RWX_INDICATORS:
                # Our hooks log as hex: "0x00000040" = PAGE_EXECUTE_READWRITE
                protection = str(args.get("flProtect", ""))
                new_protect = str(args.get("flNewProtect", ""))
                check_val = protection or new_protect

                # PAGE_EXECUTE_READWRITE = 0x40
                # PAGE_EXECUTE_WRITECOPY = 0x80
                is_rwx = ("0x00000040" in check_val or
                          "0x00000080" in check_val or
                          "0x40" == check_val or
                          "0x80" == check_val)

                if is_rwx:
                    event_time = c.get("time", 0)
                    dw_size = args.get("dwSize", 0)
                    # Convert string size to int if needed
                    if isinstance(dw_size, str):
                        try:
                            dw_size = int(dw_size)
                        except ValueError:
                            dw_size = 0

                    # Filter MinHook noise:
                    # 1. VirtualProtect with dwSize=5 is MinHook's
                    #    trampoline patching (5 bytes = JMP instruction)
                    # 2. Events in first 0.5 seconds are hook installation
                    is_minhook_noise = (
                        api == "VirtualProtect" and dw_size == 5
                    )
                    is_init_noise = (event_time < 0.5)

                    if not is_minhook_noise and not is_init_noise:
                        # Get address from lpAddress or return value
                        address = args.get("lpAddress", "")
                        if not address and api == "VirtualAlloc":
                            address = c.get("return", "")

                        rwx_allocations.append({
                            "api": api,
                            "address": address,
                            "size": dw_size,
                            "protection": check_val,
                            "time": event_time,
                        })

            # Check for unpack patterns
            if api in self.UNPACK_INDICATORS:
                unpack_indicators.append({
                    "api": api,
                    "time": c.get("time", 0),
                })

        return {
            "rwx_allocations": rwx_allocations,
            "injection_indicators": injection_indicators,
            "unpack_indicators": unpack_indicators,
            "total_memory_operations": len(memory_ops),
        }

    def analyze(self, api_report_path, dumps_dir=None):
        """Run full memory analysis."""
        print("[MEM_MON] Analyzing memory behavior...")

        # Load API calls
        self.api_calls = self._load_api_calls(api_report_path)
        mem_analysis = self._analyze_memory_apis(self.api_calls)

        # Analyze memory dumps
        if dumps_dir:
            self.dumps = self._find_memory_dumps(dumps_dir)
        else:
            self.dumps = []

        self.report_data = {
            "memory_operations": mem_analysis["total_memory_operations"],
            "rwx_allocations": mem_analysis["rwx_allocations"],
            "injection_indicators": mem_analysis["injection_indicators"],
            "unpack_indicators_count": len(mem_analysis["unpack_indicators"]),
            "memory_dumps": self.dumps,
            "summary": {
                "total_memory_ops": mem_analysis["total_memory_operations"],
                "rwx_detected": len(mem_analysis["rwx_allocations"]) > 0,
                "rwx_count": len(mem_analysis["rwx_allocations"]),
                "injection_detected": len(mem_analysis["injection_indicators"]) > 0,
                "injection_api_count": len(mem_analysis["injection_indicators"]),
                "unpacking_suspected": len(mem_analysis["unpack_indicators"]) > 10,
                "dumps_collected": len(self.dumps),
                "pe_in_memory": any(d.get("has_pe_header") for d in self.dumps),
                "high_entropy_dumps": [
                    d["filename"] for d in self.dumps
                    if d.get("entropy", 0) > 7.0
                ],
            }
        }

        return self.report_data

    def generate_report(self):
        """Generate the memory activity report."""
        return {
            "component": "memory_activity",
            "version": "1.0",
            "timestamp": time.time(),
            "data": self.report_data,
        }

    def save_report(self, output_path):
        """Save the report to a JSON file."""
        report = self.generate_report()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        s = self.report_data.get("summary", {})
        print(f"[MEM_MON] Report saved: {output_path}")
        print(f"[MEM_MON]   Memory operations: {s.get('total_memory_ops', 0)}")
        print(f"[MEM_MON]   RWX allocations:   {s.get('rwx_count', 0)}")
        print(f"[MEM_MON]   Injection APIs:     {s.get('injection_api_count', 0)}")
        print(f"[MEM_MON]   Memory dumps:       {s.get('dumps_collected', 0)}")

        if s.get("rwx_detected"):
            print("[MEM_MON]   WARNING: RWX memory detected!")
        if s.get("injection_detected"):
            print("[MEM_MON]   WARNING: Process injection indicators!")

        return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Memory Monitor")
    parser.add_argument("--api-report",
                        default="sandbox/reports/test_report.json",
                        help="Path to API call report")
    parser.add_argument("--dumps-dir",
                        default="sandbox/reports/artifacts/memory_dumps",
                        help="Path to memory dumps directory")
    parser.add_argument("--output",
                        default="sandbox/reports/raw/memory_activity.json")
    args = parser.parse_args()

    monitor = MemoryMonitor()
    monitor.analyze(args.api_report, args.dumps_dir)
    monitor.save_report(args.output)
