"""
test_injection.py — End-to-End Test
=====================================
Tests the full pipeline:
1. Starts the collector (named pipe server)
2. Launches api_exerciser.exe (or notepad.exe fallback)
3. Injects hook_monitor.dll into it
4. Waits for the test to complete
5. Prints results

MUST BE RUN AS ADMINISTRATOR for DLL injection to work.
"""

import subprocess
import threading
import time
import sys
import os
import ctypes

def is_admin():
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def stream_output(proc, label):
    """Read and print subprocess output in real-time."""
    for line in proc.stdout:
        print(f"[{label}] {line}", end="")

def main():
    if not is_admin():
        print("=" * 60)
        print("  ERROR: This script must be run as Administrator!")
        print("=" * 60)
        print()
        print("How to fix:")
        print("  1. Open PowerShell as Administrator")
        print("  2. cd to the project directory")
        print("  3. Run: python sandbox\\tests\\test_injection.py")
        print()
        print("Or right-click PowerShell -> Run as Administrator")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.join(script_dir, "..")
    project_dir = os.path.normpath(project_dir)

    collector_script = os.path.join(project_dir, "collector", "collector.py")
    injector_script = os.path.join(project_dir, "injector", "injector.py")
    report_path = os.path.join(project_dir, "reports", "test_report.json")

    # Delete old report
    if os.path.exists(report_path):
        os.remove(report_path)

    # Cleanup any leftover processes from previous runs
    os.system("taskkill /f /im api_exerciser.exe >nul 2>&1")
    os.system("taskkill /f /im api_exerciser3.exe >nul 2>&1")
    # Kill python processes that have "collector" in their command line
    os.system('wmic process where "name=\'python.exe\' and commandline like \'%%collector%%\'" call terminate >nul 2>&1')
    time.sleep(2)

    print("=" * 60)
    print("  SANDBOX END-TO-END TEST")
    print("=" * 60)
    print()

    # Step 1: Start collector in background (stream its output)
    print("[TEST] Starting collector...")
    collector_proc = subprocess.Popen(
        [sys.executable, collector_script, "--output", report_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    collector_thread = threading.Thread(target=stream_output, args=(collector_proc, "COLLECTOR"), daemon=True)
    collector_thread.start()
    time.sleep(1)  # Let pipe get created

    # Step 2: Find the target executable
    exerciser_path = None
    for name in ["api_exerciser.exe", "api_exerciser3.exe", "api_exerciser2.exe"]:
        p = os.path.join(script_dir, name)
        if os.path.exists(p):
            exerciser_path = p
            break

    if not exerciser_path:
        exerciser_path = r"C:\Windows\System32\notepad.exe"
        print("[TEST] No exerciser found, falling back to notepad")
        use_exerciser = False
    else:
        use_exerciser = True

    # Step 3: Launch the target
    print(f"[TEST] Launching {os.path.basename(exerciser_path)}...")
    target_proc = subprocess.Popen(
        exerciser_path,
        creationflags=subprocess.CREATE_NEW_CONSOLE  # Separate console so pipes don't interfere
    )
    target_pid = target_proc.pid
    print(f"[TEST] Target started (PID: {target_pid})")

    # Small delay for process initialization
    time.sleep(1)

    # Step 4: Inject the DLL using the injector with --pid
    print(f"[TEST] Injecting DLL into PID {target_pid}...")
    injector_proc = subprocess.Popen(
        [sys.executable, injector_script, "--pid", str(target_pid)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    # Read injector output (this finishes quickly since it's just inject_dll)
    injector_output = injector_proc.communicate(timeout=15)[0]
    print(injector_output)

    if injector_proc.returncode != 0:
        print("[TEST] Injection failed! See output above.")
        target_proc.kill()
        collector_proc.terminate()
        sys.exit(1)

    # Step 5: Wait for the exerciser to run all its tests
    if use_exerciser:
        print("[TEST] Hooks active! Waiting for api_exerciser to complete...")
        target_proc.wait(timeout=60)  # Wait for exerciser to finish naturally
        print("[TEST] api_exerciser finished.")
    else:
        print("[TEST] Hooks active! Waiting 10 seconds for API calls...")
        time.sleep(10)
        os.system("taskkill /f /im notepad.exe >nul 2>&1")

    time.sleep(3)  # Let collector flush remaining logs

    # Step 6: Stop collector
    collector_proc.terminate()
    time.sleep(1)

    # Step 7: Check results
    print()
    if os.path.exists(report_path):
        import json
        with open(report_path) as f:
            report = json.load(f)
        info = report.get("info", {})
        total = info.get("total_calls", 0)
        unique = info.get("unique_apis", "?")
        duration = info.get("duration_seconds", "?")

        print("=" * 60)
        print(f"  TEST PASSED! Captured {total} API calls.")
        print(f"  Unique APIs seen:   {unique}")
        print(f"  Duration:           {duration}s")

        # Collect all calls from behavior.processes[].calls[]
        all_calls = []
        for proc in report.get("behavior", {}).get("processes", []):
            all_calls.extend(proc.get("calls", []))

        # Show category breakdown
        categories = {}
        api_counts = {}
        for call in all_calls:
            cat = call.get("category", "UNKNOWN")
            api = call.get("api", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
            api_counts[api] = api_counts.get(api, 0) + 1

        if categories:
            print()
            print("  By Category:")
            for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
                print(f"    {cat:8s} : {count:5d} calls")

        if api_counts:
            print()
            print("  Top 15 APIs:")
            for api, count in sorted(api_counts.items(), key=lambda x: -x[1])[:15]:
                print(f"    {api:35s} : {count:5d} calls")

        print()
        print(f"  Report saved to: {report_path}")
        print("=" * 60)
    else:
        print("=" * 60)
        print("  TEST FAILED: No report generated.")
        print("  Check the output above for errors.")
        print("=" * 60)


if __name__ == "__main__":
    main()
