"""
collector.py — Named Pipe Log Collector
========================================
Creates a named pipe server that receives JSON log lines
from the hook_monitor.dll running inside the target process.

Usage:
    python collector.py                     # Start listening
    python collector.py --output report.json  # Save to file

The collector runs FIRST, then the injector sends the DLL.
"""

import json
import time
import sys
import os
import argparse
import threading
import win32pipe
import win32file
import pywintypes

PIPE_NAME = r"\\.\pipe\sandbox_monitor"
PIPE_BUFFER_SIZE = 65536


class PipeCollector:
    """Named pipe server that collects API call logs from the hook DLL."""

    def __init__(self):
        self.calls = []           # All captured API calls
        self.running = False
        self.pipe_handle = None
        self.start_time = time.time()

    def start(self):
        """Create the named pipe and wait for the DLL to connect."""
        print(f"[COLLECTOR] Creating named pipe: {PIPE_NAME}")

        try:
            self.pipe_handle = win32pipe.CreateNamedPipe(
                PIPE_NAME,
                win32pipe.PIPE_ACCESS_INBOUND,           # Read only
                (win32pipe.PIPE_TYPE_BYTE |                # Byte mode
                 win32pipe.PIPE_READMODE_BYTE |
                 win32pipe.PIPE_WAIT),                     # Blocking
                1,                                         # Max instances
                PIPE_BUFFER_SIZE,                          # Out buffer
                PIPE_BUFFER_SIZE,                          # In buffer
                0,                                         # Default timeout
                None                                       # Default security
            )
        except pywintypes.error as e:
            print(f"[COLLECTOR] ERROR creating pipe: {e}")
            return False

        print("[COLLECTOR] Waiting for hook DLL to connect...")
        print("[COLLECTOR] (Run the injector now)")

        try:
            win32pipe.ConnectNamedPipe(self.pipe_handle, None)
        except pywintypes.error as e:
            print(f"[COLLECTOR] Connection error: {e}")
            return False

        print("[COLLECTOR] DLL connected! Receiving logs...")
        self.running = True
        return True

    def collect(self):
        """Read JSON lines from the pipe until disconnection."""
        buffer = ""

        while self.running:
            try:
                # Read data from pipe
                result, data = win32file.ReadFile(
                    self.pipe_handle,
                    PIPE_BUFFER_SIZE
                )

                if result == 0:  # Success
                    buffer += data.decode("utf-8", errors="replace")

                    # Process complete lines
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            entry = json.loads(line)
                            self._process_entry(entry)
                        except json.JSONDecodeError:
                            print(f"[COLLECTOR] Bad JSON: {line[:100]}")

            except pywintypes.error as e:
                error_code = e.args[0]
                if error_code == 109:  # ERROR_BROKEN_PIPE — DLL disconnected
                    print("\n[COLLECTOR] Pipe disconnected (target process ended)")
                    self.running = False
                elif error_code == 233:  # ERROR_PIPE_NOT_CONNECTED
                    print("\n[COLLECTOR] Pipe not connected")
                    self.running = False
                else:
                    print(f"\n[COLLECTOR] Pipe error: {e}")
                    self.running = False

        return self.calls

    def _process_entry(self, entry):
        """Process a single API call entry."""
        api = entry.get("api", "?")
        cat = entry.get("cat", "?")

        # Skip internal markers
        if api.startswith("__sandbox_"):
            if api == "__sandbox_init__":
                print("[COLLECTOR] === Monitor initialized ===")
                self.start_time = time.time()
            elif api == "__sandbox_shutdown__":
                print("[COLLECTOR] === Monitor shutting down ===")
            return

        # Store the call
        self.calls.append(entry)
        count = len(self.calls)

        # Print live feed
        args_str = ""
        if entry.get("args"):
            # Show first argument value for context
            args = entry["args"]
            if isinstance(args, dict):
                first_key = next(iter(args), None)
                if first_key:
                    val = str(args[first_key])
                    if len(val) > 60:
                        val = val[:57] + "..."
                    args_str = f" | {first_key}={val}"

        ret = entry.get("ret", "")
        print(f"  [{count:4d}] [{cat:5s}] {api}{args_str} -> {ret}")

    def shutdown(self):
        """Close the pipe."""
        self.running = False
        if self.pipe_handle:
            try:
                win32file.CloseHandle(self.pipe_handle)
            except Exception:
                pass
            self.pipe_handle = None

    def get_summary(self):
        """Return a summary of collected calls."""
        if not self.calls:
            return "No API calls captured."

        # Count by category
        categories = {}
        api_counts = {}
        for call in self.calls:
            cat = call.get("cat", "?")
            api = call.get("api", "?")
            categories[cat] = categories.get(cat, 0) + 1
            api_counts[api] = api_counts.get(api, 0) + 1

        lines = []
        lines.append(f"\n{'='*60}")
        lines.append(f"  COLLECTION SUMMARY")
        lines.append(f"{'='*60}")
        lines.append(f"  Total API calls captured: {len(self.calls)}")
        lines.append(f"  Unique APIs seen:         {len(api_counts)}")
        lines.append(f"  Duration:                 {time.time()-self.start_time:.1f}s")

        # Identify MinHook noise: VirtualProtect + FlushInstructionCache
        # Phase 1: Hook INSTALLATION in the first 0.1s
        # Phase 2: Hook REMOVAL after ExitProcess (process shutdown)
        minhook_noise_apis = {"VirtualProtect", "FlushInstructionCache"}
        start_noise = 0
        end_noise = 0
        exit_index = None

        if self.calls:
            # Phase 1: First 0.1s = hook installation
            first_time = self.calls[0].get("time", 0)
            init_cutoff = first_time + 0.1
            for i, c in enumerate(self.calls):
                if c.get("api") == "ExitProcess":
                    exit_index = i
                if (c.get("time", 0) <= init_cutoff and
                        c.get("api") in minhook_noise_apis):
                    start_noise += 1

            # Phase 2: After ExitProcess = hook cleanup/removal
            if exit_index is not None:
                for c in self.calls[exit_index + 1:]:
                    if c.get("api") in minhook_noise_apis:
                        end_noise += 1

        noise_count = start_noise + end_noise
        real_count = len(self.calls) - noise_count
        lines.append(f"  MinHook noise (install):   {start_noise}")
        lines.append(f"  MinHook noise (cleanup):   {end_noise}")
        lines.append(f"  MinHook noise (total):     {noise_count}")
        lines.append(f"  Real sample API calls:     {real_count}")

        lines.append(f"")
        lines.append(f"  By Category:")
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            lines.append(f"    {cat:8s}: {count:5d} calls")
        lines.append(f"")
        lines.append(f"  Top 10 APIs:")
        for api, count in sorted(api_counts.items(), key=lambda x: -x[1])[:10]:
            if api in minhook_noise_apis:
                lines.append(f"    {api:35s}: {count:5d} calls  [MINHOOK NOISE]")
            else:
                lines.append(f"    {api:35s}: {count:5d} calls")
        lines.append(f"{'='*60}")

        return "\n".join(lines)

    def save_report(self, output_path):
        """Save collected calls as a JSON report."""
        # Group calls by PID
        processes = {}
        for call in self.calls:
            pid = call.get("pid", 0)
            if pid not in processes:
                processes[pid] = {
                    "pid": pid,
                    "calls": []
                }
            processes[pid]["calls"].append({
                "api": call.get("api"),
                "category": call.get("cat"),
                "arguments": call.get("args", {}),
                "return": call.get("ret", ""),
                "time": call.get("time", 0),
                "tid": call.get("tid", 0)
            })

        # Count unique APIs
        api_names = set()
        for call in self.calls:
            api_names.add(call.get("api", "?"))

        report = {
            "info": {
                "version": "sandbox-1.0",
                "timestamp": time.time(),
                "total_calls": len(self.calls),
                "unique_apis": len(api_names),
                "duration_seconds": round(time.time() - self.start_time, 1)
            },
            "behavior": {
                "processes": list(processes.values())
            }
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[COLLECTOR] Report saved to: {output_path}")
        return report


def main():
    parser = argparse.ArgumentParser(description="Sandbox API Call Collector")
    parser.add_argument("--output", "-o", default=None,
                        help="Output report file path (default: reports/report_<timestamp>.json)")
    args = parser.parse_args()

    collector = PipeCollector()

    try:
        if not collector.start():
            print("[COLLECTOR] Failed to start. Exiting.")
            sys.exit(1)

        calls = collector.collect()
    except KeyboardInterrupt:
        print("\n[COLLECTOR] Interrupted by user.")
    finally:
        collector.shutdown()

    # Print summary
    print(collector.get_summary())

    # Save report
    if calls:
        if args.output:
            output_path = args.output
        else:
            # Default path
            reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
            os.makedirs(reports_dir, exist_ok=True)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(reports_dir, f"report_{timestamp}.json")

        collector.save_report(output_path)
    else:
        print("[COLLECTOR] No calls captured — no report generated.")


if __name__ == "__main__":
    main()
