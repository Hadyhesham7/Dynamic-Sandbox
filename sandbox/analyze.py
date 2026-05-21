"""
analyze.py - Sandbox Pipeline Orchestrator
============================================
Single command to run the entire analysis pipeline.

Usage:
    python sandbox/analyze.py                       # Interactive mode
    python sandbox/analyze.py <sample.exe>           # Direct PE analysis
    python sandbox/analyze.py <sample.exe> --timeout 60

Interactive mode lets you choose:
  [1] Run built-in test sample
  [2] Analyze an attachment / file (auto-detects type)

Supported file types:
  - PE Executables (.exe, .dll, .scr)
  - Office Documents (.doc, .docx, .xls, .xlsm) — macro extraction + Word
  - ZIP Archives (.zip) — extract + route contents
  - OLE Embedded Objects — extract embedded PEs

Pipeline steps:
    1. Route sample (detect type, extract macros/archives)
    2. Pre-snapshots (file system + registry)
    3. Start collector (named pipe)
    4. Launch target process
    5. Inject hook DLL
    6. Wait for timeout or exit
    7. Post-snapshots + diff
    8. Analyze memory behavior
    9. Analyze network behavior
    10. Generate per-component reports
    11. Merge into final report

Requirements:
    - Must run as Administrator (for DLL injection)
    - hook_monitor.dll must be built
    - pywin32 package installed
    - oletools package (for Office analysis)
"""

import os
import sys
import time
import json
import ctypes
import argparse
import subprocess
import threading

# Add project root to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR) if os.path.basename(SCRIPT_DIR) == "sandbox" else SCRIPT_DIR
sys.path.insert(0, os.path.join(SCRIPT_DIR))

from monitors.filesystem_monitor import FileSystemMonitor
from monitors.registry_monitor import RegistryMonitor
from monitors.memory_monitor import MemoryMonitor
from monitors.network_monitor import NetworkMonitor
from monitors.screenshot_monitor import ScreenshotMonitor
from collector.report_generator import ReportGenerator
from sample_router import SampleRouter
from verdict_engine import calculate_final_verdict


def is_admin():
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def stream_output(proc, label):
    """Read subprocess output in a background thread."""
    try:
        for line in proc.stdout:
            print(f"  [{label}] {line}", end="")
    except Exception:
        pass


def find_dll():
    """Find hook_monitor.dll."""
    import struct
    is_64bit = struct.calcsize("P") * 8 == 64

    base = os.path.join(SCRIPT_DIR, "hook_dll")
    paths = []
    if is_64bit:
        paths.append(os.path.join(base, "build64", "Release", "hook_monitor.dll"))
        paths.append(os.path.join(base, "build64", "Debug", "hook_monitor.dll"))
    paths.append(os.path.join(base, "build", "Release", "hook_monitor.dll"))
    paths.append(os.path.join(base, "build", "Debug", "hook_monitor.dll"))

    for p in paths:
        if os.path.exists(p):
            return os.path.normpath(p)
    return None


def interactive_menu():
    """Show interactive mode selection menu."""
    W = 60
    test_sample = os.path.join(SCRIPT_DIR, "tests", "api_exerciser3.exe")
    has_test = os.path.exists(test_sample)

    print()
    print("=" * W)
    print("  KNOWHOW SANDBOX -- ANALYSIS MODE")
    print("=" * W)
    if has_test:
        print("  [1] Run built-in test sample (api_exerciser3.exe)")
    else:
        print("  [1] Run built-in test sample (NOT FOUND)")
    print("  [2] Analyze an attachment / file")
    print("=" * W)

    while True:
        choice = input("  Select mode (1/2): ").strip()
        if choice == "1":
            if not has_test:
                print("  ERROR: Test sample not found!")
                continue
            return {
                "mode": "test",
                "sample_path": test_sample,
                "route_result": {
                    "strategy": "DIRECT_PE",
                    "target_exe": test_sample,
                    "target_args": [],
                    "file_info": {
                        "type": "PE_EXECUTABLE",
                        "filename": "api_exerciser3.exe",
                        "description": "Built-in Test Sample",
                    },
                    "macros": None,
                    "ole_objects": [],
                    "pe_targets": [test_sample],
                },
            }
        elif choice == "2":
            filepath = input("  Enter file path: ").strip().strip('"')
            if not os.path.exists(filepath):
                print(f"  ERROR: File not found: {filepath}")
                continue

            filepath = os.path.abspath(filepath)
            router = SampleRouter()
            route_result = router.route(filepath)
            router.print_routing_summary(route_result)

            if route_result["strategy"] in ("UNSUPPORTED", "EXTRACT_FAILED",
                                            "NO_EXECUTABLE"):
                print("\n  Cannot analyze this file type.")
                retry = input("  Try another file? (y/n): ").strip().lower()
                if retry == "y":
                    continue
                sys.exit(0)

            return {
                "mode": "attachment",
                "sample_path": filepath,
                "route_result": route_result,
            }
        else:
            print("  Invalid choice. Enter 1 or 2.")


def main():
    parser = argparse.ArgumentParser(
        description="Sandbox Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sandbox/analyze.py                                  # Interactive mode
  python sandbox/analyze.py sample.exe                       # Direct PE analysis
  python sandbox/analyze.py sample.exe --timeout 60
  python sandbox/analyze.py malicious.docx                   # Office analysis
  python sandbox/analyze.py archive.zip                      # Extract + analyze
        """
    )
    parser.add_argument("sample", nargs="?", default=None,
                        help="Path to file to analyze (or omit for interactive)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Max execution time in seconds (default: 60)")
    parser.add_argument("--output", default=None,
                        help="Output report path")
    parser.add_argument("--mode", choices=["local", "vm"], default="local",
                        help="local = mock network, vm = FakeNet-NG")
    parser.add_argument("--no-network", action="store_true",
                        help="Skip network analysis")
    parser.add_argument("--no-memory", action="store_true",
                        help="Skip memory analysis")
    parser.add_argument("--no-files", action="store_true",
                        help="Skip file system monitoring")
    parser.add_argument("--no-registry", action="store_true",
                        help="Skip registry monitoring")
    args = parser.parse_args()

    # ── Determine what to analyze ──
    if args.sample:
        # Direct mode — route the provided file
        sample_path = os.path.abspath(args.sample)
        if not os.path.exists(sample_path):
            print(f"[PIPELINE] ERROR: File not found: {sample_path}")
            sys.exit(1)

        router = SampleRouter()
        route_result = router.route(sample_path)
        router.print_routing_summary(route_result)
        analysis_info = {
            "mode": "direct",
            "sample_path": sample_path,
            "route_result": route_result,
        }
    else:
        # Interactive mode
        analysis_info = interactive_menu()
        sample_path = analysis_info["sample_path"]

    route_result = analysis_info["route_result"]
    strategy = route_result["strategy"]
    target_exe = route_result["target_exe"]
    target_args = route_result.get("target_args", [])

    if strategy == "STATIC_ONLY":
        # Macro-only analysis — save macro report and exit
        print("[PIPELINE] Static macro analysis only (no Office application found)")
        macros = route_result.get("macros", {})
        macro_path = os.path.join(
            SCRIPT_DIR, "reports", "raw", "macro_analysis.json")
        os.makedirs(os.path.dirname(macro_path), exist_ok=True)
        with open(macro_path, "w") as f:
            # Strip actual code from macros (can be large)
            safe_macros = dict(macros)
            for m in safe_macros.get("macros", []):
                m["code"] = m["code"][:500] + "..." if len(m.get("code", "")) > 500 else m.get("code", "")
            json.dump(safe_macros, f, indent=2)
        print(f"[PIPELINE] Macro report saved: {macro_path}")
        sys.exit(0)

    if not target_exe:
        print("[PIPELINE] ERROR: No executable target determined.")
        sys.exit(1)

    if not is_admin():
        print("=" * 60)
        print("  ERROR: Must run as Administrator!")
        print("=" * 60)
        print("  Right-click PowerShell -> Run as Administrator")
        sys.exit(1)

    dll_path = find_dll()
    if not dll_path:
        print("[PIPELINE] ERROR: hook_monitor.dll not found! Build it first.")
        sys.exit(1)

    # Setup paths
    reports_dir = os.path.join(SCRIPT_DIR, "reports")
    raw_dir = os.path.join(reports_dir, "raw")
    artifacts_dir = os.path.join(reports_dir, "artifacts")
    dropped_dir = os.path.join(artifacts_dir, "dropped_files")
    dumps_dir = os.path.join(artifacts_dir, "memory_dumps")
    screenshots_dir = os.path.join(artifacts_dir, "screenshots")
    api_report_path = os.path.join(reports_dir, "api_raw_report.json")
    final_report_path = args.output or os.path.join(reports_dir, "final_report.json")

    for d in [reports_dir, raw_dir, artifacts_dir, dropped_dir, dumps_dir, screenshots_dir]:
        os.makedirs(d, exist_ok=True)

    # Clean old reports
    for fname in os.listdir(raw_dir):
        os.remove(os.path.join(raw_dir, fname))

    # Save macro analysis if available
    macros = route_result.get("macros")
    if macros and macros.get("has_macros"):
        macro_path = os.path.join(raw_dir, "macro_analysis.json")
        safe_macros = dict(macros)
        for m in safe_macros.get("macros", []):
            if len(m.get("code", "")) > 2000:
                m["code"] = m["code"][:2000] + "\n... (truncated)"
        with open(macro_path, "w") as f:
            json.dump(safe_macros, f, indent=2)
        print(f"[PIPELINE] Macro analysis saved: {macro_path}")

    print("=" * 60)
    print("  SANDBOX ANALYSIS PIPELINE")
    print("=" * 60)
    print(f"  Sample:    {os.path.basename(sample_path)}")
    print(f"  Type:      {route_result['file_info'].get('description', '?')}")
    print(f"  Strategy:  {strategy}")
    print(f"  Target:    {os.path.basename(target_exe)}")
    if target_args:
        print(f"  Args:      {os.path.basename(str(target_args[-1]))}")
    print(f"  Timeout:   {args.timeout}s")
    print(f"  Mode:      {args.mode}")
    print(f"  DLL:       {dll_path}")
    print()

    pipeline_start = time.time()
    collector_proc = None
    target_proc = None

    try:
        # ── STEP 1: Pre-Snapshots ──
        fs_monitor = None
        reg_monitor = None

        if not args.no_files:
            print("[PIPELINE] Step 1a: File system pre-snapshot...")
            target_dir = os.path.dirname(sample_path)
            fs_monitor = FileSystemMonitor(target_dir=target_dir)
            fs_monitor.take_pre_snapshot()

        if not args.no_registry:
            print("[PIPELINE] Step 1b: Registry pre-snapshot...")
            reg_monitor = RegistryMonitor()
            reg_monitor.take_pre_snapshot()

        # ── STEP 2: Start Collector ──
        print("[PIPELINE] Step 2: Starting collector...")
        collector_script = os.path.join(SCRIPT_DIR, "collector", "collector.py")

        # Kill old collectors
        os.system('wmic process where "name=\'python.exe\' and '
                  'commandline like \'%%collector%%\'" call terminate >nul 2>&1')
        time.sleep(1)

        collector_proc = subprocess.Popen(
            [sys.executable, collector_script, "--output", api_report_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        collector_thread = threading.Thread(
            target=stream_output, args=(collector_proc, "COLLECTOR"), daemon=True)
        collector_thread.start()
        time.sleep(1)

        # ── STEP 3: Launch Target ──
        if target_args:
            # Office mode: launch app with document as argument
            print(f"[PIPELINE] Step 3: Launching {os.path.basename(target_exe)} "
                  f"with {os.path.basename(str(target_args[-1]))}...")

            # ── STEP 3.0: Disable Office Protected View & Enable Macros ──
            # Without this, Word/Excel will block macro execution silently.
            if strategy == "OFFICE_DYNAMIC":
                try:
                    import winreg
                    # Detect Office version from target_exe path
                    office_version = "16.0"  # Default (Office 2016/2019/365)
                    for ver in ["16.0", "15.0", "14.0"]:
                        if f"Office{ver.split('.')[0]}" in target_exe or ver in target_exe:
                            office_version = ver
                            break

                    app_name = "Word" if "WINWORD" in target_exe.upper() else "Excel"

                    # 1. Disable Protected View (3 settings)
                    pv_key_path = rf"Software\Microsoft\Office\{office_version}\{app_name}\Security\ProtectedView"
                    pv_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, pv_key_path)
                    winreg.SetValueEx(pv_key, "DisableInternetFilesInPV", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(pv_key, "DisableAttachementsInPV", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(pv_key, "DisableUnsafeLocationsInPV", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(pv_key)

                    # 2. Enable all macros (VBAWarnings = 1 means "Enable All Macros")
                    sec_key_path = rf"Software\Microsoft\Office\{office_version}\{app_name}\Security"
                    sec_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, sec_key_path)
                    winreg.SetValueEx(sec_key, "VBAWarnings", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(sec_key)

                    # 3. Disable Trust Center first-run dialogs
                    resiliency_path = rf"Software\Microsoft\Office\{office_version}\{app_name}\Resiliency"
                    res_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, resiliency_path)
                    winreg.SetValueEx(res_key, "StartupItems", 0, winreg.REG_DWORD, 0)
                    winreg.CloseKey(res_key)

                    print(f"[PIPELINE]   Office macro security DISABLED for {app_name} {office_version}")
                    print(f"[PIPELINE]   Protected View: OFF | VBA Macros: ENABLED")
                except Exception as e:
                    print(f"[PIPELINE]   WARNING: Could not configure Office security: {e}")

            launch_cmd = [target_exe] + target_args
            target_proc = subprocess.Popen(
                launch_cmd,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        else:
            # Direct PE mode
            print(f"[PIPELINE] Step 3: Launching {os.path.basename(target_exe)}...")
            target_proc = subprocess.Popen(
                target_exe,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        target_pid = target_proc.pid
        print(f"[PIPELINE]   PID: {target_pid}")

        # Wait for the target to initialize
        # Office apps need more time than standalone PEs to fully load
        if strategy == "OFFICE_DYNAMIC":
            init_wait = 10
            print(f"[PIPELINE]   Waiting {init_wait}s for Office to fully initialize...")
        else:
            init_wait = 5
        time.sleep(init_wait)

        # ── STEP 3.5: Find real process to inject ──
        inject_pid = target_pid
        try:
            import ctypes as _ct
            from ctypes import wintypes as _wt
            _k32 = _ct.windll.kernel32

            class _PE32(_ct.Structure):
                _fields_ = [('dwSize', _wt.DWORD), ('cntUsage', _wt.DWORD),
                            ('th32ProcessID', _wt.DWORD),
                            ('th32DefaultHeapID', _ct.c_void_p),
                            ('th32ModuleID', _wt.DWORD),
                            ('cntThreads', _wt.DWORD),
                            ('th32ParentProcessID', _wt.DWORD),
                            ('pcPriClassBase', _ct.c_long),
                            ('dwFlags', _wt.DWORD),
                            ('szExeFile', _ct.c_char * 260)]

            _k32.CreateToolhelp32Snapshot.restype = _ct.c_void_p
            snap = _k32.CreateToolhelp32Snapshot(0x00000002, 0)
            pe = _PE32()
            pe.dwSize = _ct.sizeof(_PE32)
            children = []
            office_procs = []  # Track all WINWORD/EXCEL processes

            if _k32.Process32First(snap, _ct.byref(pe)):
                while True:
                    proc_name = pe.szExeFile.decode('utf-8', errors='replace').lower()
                    proc_pid = pe.th32ProcessID

                    # For OFFICE_DYNAMIC: find the real Office process by name
                    if strategy == "OFFICE_DYNAMIC":
                        if proc_name in ('winword.exe', 'excel.exe', 'powerpnt.exe'):
                            office_procs.append((proc_pid, proc_name))

                    # For PE: find child processes (PyInstaller detection)
                    if pe.th32ParentProcessID == target_pid:
                        if proc_name != 'conhost.exe':
                            children.append((proc_pid, proc_name))

                    if not _k32.Process32Next(snap, _ct.byref(pe)):
                        break
            _k32.CloseHandle(snap)

            if strategy == "OFFICE_DYNAMIC" and office_procs:
                # For Office: use the Office process (may differ from Popen PID)
                # Prefer the process that matches our Popen PID, else use the latest one
                matching = [p for p in office_procs if p[0] == target_pid]
                if matching:
                    inject_pid = matching[0][0]
                    print(f"[PIPELINE]   Office process confirmed: PID {inject_pid} ({matching[0][1]})")
                else:
                    # Popen PID was a launcher — use the real Office process
                    inject_pid = office_procs[-1][0]
                    print(f"[PIPELINE]   Office broker detected! Real process: PID {inject_pid} ({office_procs[-1][1]})")
                    print(f"[PIPELINE]   (Popen gave broker PID {target_pid}, actual Office PID {inject_pid})")
            elif children:
                inject_pid = children[0][0]
                print(f"[PIPELINE]   PyInstaller child detected: PID {inject_pid} ({children[0][1]})")
                print(f"[PIPELINE]   Injecting into CHILD process (not bootloader PID {target_pid})")
                # Give the child a moment to initialize
                time.sleep(2)
            else:
                print(f"[PIPELINE]   No child process found — injecting into PID {target_pid}")
        except Exception as e:
            print(f"[PIPELINE]   Child detection failed ({e}) — using PID {target_pid}")

        # ── STEP 4: Inject DLL ──
        print(f"[PIPELINE] Step 4: Injecting DLL into PID {inject_pid}...")
        injector_script = os.path.join(SCRIPT_DIR, "injector", "injector.py")

        inject_proc = subprocess.Popen(
            [sys.executable, injector_script, "--pid", str(inject_pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        inject_output = inject_proc.communicate(timeout=15)[0]

        if inject_proc.returncode != 0:
            print(f"[PIPELINE] ERROR: Injection failed!")
            print(inject_output)
            sys.exit(1)

        # Show injection result
        for line in inject_output.strip().split("\n"):
            if "SUCCESS" in line.upper() or "ERROR" in line.upper() or "injected" in line.lower():
                print(f"  [INJECTOR] {line.strip()}")

        # ── STEP 4.5: Start Screenshots ──
        print("[PIPELINE] Step 4.5: Starting screenshot monitor...")
        screenshot_monitor = ScreenshotMonitor(screenshots_dir, interval=3.0)
        screenshot_monitor.start()

        # ── STEP 5: Wait for Execution ──
        # Office apps never exit on their own — use a shorter window.
        # Macros execute within seconds; 30s captures all dynamic behavior.
        if strategy == "OFFICE_DYNAMIC":
            exec_timeout = min(30, args.timeout)
            print(f"[PIPELINE] Step 5: Office dynamic monitoring ({exec_timeout}s window)...")
            print(f"[PIPELINE]   (Macros execute immediately; "
                  f"Word will be terminated after {exec_timeout}s)")
        else:
            exec_timeout = args.timeout
            print(f"[PIPELINE] Step 5: Monitoring execution ({exec_timeout}s timeout)...")

        try:
            target_proc.wait(timeout=exec_timeout)
            print(f"[PIPELINE]   Process exited (code: {target_proc.returncode})")
        except subprocess.TimeoutExpired:
            print(f"[PIPELINE]   Execution window reached ({exec_timeout}s) — terminating")
            target_proc.kill()
            target_proc.wait(timeout=5)

        time.sleep(2)  # Let collector flush

        # ── STEP 6: Stop Collector & Monitors ──
        print("[PIPELINE] Step 6: Stopping collector and monitors...")
        if screenshot_monitor:
            screenshot_monitor.stop()
            with open(os.path.join(raw_dir, "screenshots.json"), "w") as f:
                json.dump(screenshot_monitor.get_summary(), f, indent=2)

        if collector_proc:
            collector_proc.terminate()
            try:
                collector_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                collector_proc.kill()
        time.sleep(1)

        # ── STEP 6.5: Sanitize API Report ──
        # The hook DLL can produce truncated JSON when the pipe disconnects
        # mid-write (especially for large Office captures). Fix it now before
        # any downstream monitor tries to parse it.
        if os.path.exists(api_report_path):
            try:
                with open(api_report_path, 'r', encoding='utf-8', errors='replace') as f:
                    raw = f.read()
                try:
                    report = json.loads(raw)
                    # JSON is valid — check for corrupted entries in processes
                    sanitized = False
                    for proc in report.get("behavior", {}).get("processes", []):
                        clean_calls = []
                        for call in proc.get("calls", []):
                            if isinstance(call, dict) and "api" in call:
                                clean_calls.append(call)
                            else:
                                sanitized = True
                        proc["calls"] = clean_calls
                    if sanitized:
                        with open(api_report_path, 'w') as f:
                            json.dump(report, f, indent=2)
                        print("[PIPELINE] Step 6.5: Sanitized corrupted API entries")
                except json.JSONDecodeError as e:
                    print(f"[PIPELINE] Step 6.5: API report has corrupted JSON — repairing...")
                    print(f"[PIPELINE]   Error: {e}")
                    # Try to salvage: find the last valid JSON closure
                    # The report structure is {"info":{...},"behavior":{"processes":[...]}}
                    # Try truncating at the last complete call entry
                    last_good = raw.rfind('"time":')
                    if last_good > 0:
                        # Find the end of that entry (next "}")
                        end_brace = raw.find('}', last_good)
                        if end_brace > 0:
                            truncated = raw[:end_brace + 1]
                            # Close all open brackets
                            truncated += ']}]}}'
                            try:
                                repaired = json.loads(truncated)
                                with open(api_report_path, 'w') as f:
                                    json.dump(repaired, f, indent=2)
                                total_calls = sum(
                                    len(p.get("calls", []))
                                    for p in repaired.get("behavior", {}).get("processes", [])
                                )
                                print(f"[PIPELINE]   Repaired! Salvaged {total_calls} API calls")
                            except json.JSONDecodeError:
                                # Last resort: create empty valid report
                                empty_report = {
                                    "info": {"version": "sandbox-1.0", "total_calls": 0,
                                             "note": "API report was corrupted and could not be repaired"},
                                    "behavior": {"processes": []}
                                }
                                with open(api_report_path, 'w') as f:
                                    json.dump(empty_report, f, indent=2)
                                print("[PIPELINE]   Could not repair — saved empty report")
                    else:
                        empty_report = {
                            "info": {"version": "sandbox-1.0", "total_calls": 0,
                                     "note": "API report was corrupted"},
                            "behavior": {"processes": []}
                        }
                        with open(api_report_path, 'w') as f:
                            json.dump(empty_report, f, indent=2)
                        print("[PIPELINE]   Could not repair — saved empty report")
            except Exception as e:
                print(f"[PIPELINE] Step 6.5: Sanitization error: {e}")

        # ── STEP 7: Post-Snapshots ──
        if fs_monitor:
            print("[PIPELINE] Step 7a: File system post-snapshot + diff...")
            fs_monitor.take_post_snapshot()
            fs_monitor.save_report(
                os.path.join(raw_dir, "file_activity.json"),
                artifacts_dir=dropped_dir,
            )

        if reg_monitor:
            print("[PIPELINE] Step 7b: Registry post-snapshot + diff...")
            reg_monitor.take_post_snapshot()
            reg_monitor.save_report(
                os.path.join(raw_dir, "registry_activity.json")
            )

        # ── STEP 8: Memory Analysis ──
        if not args.no_memory:
            print("[PIPELINE] Step 8: Memory behavior analysis...")
            mem_monitor = MemoryMonitor()
            mem_monitor.analyze(api_report_path, dumps_dir)
            mem_monitor.save_report(
                os.path.join(raw_dir, "memory_activity.json")
            )

        # ── STEP 9: Network Analysis ──
        if not args.no_network:
            print("[PIPELINE] Step 9: Network activity analysis...")
            net_mode = "mock" if args.mode == "local" else "vm"
            net_monitor = NetworkMonitor(mode=net_mode)
            net_monitor.analyze(api_report_path)
            net_monitor.save_report(
                os.path.join(raw_dir, "network_activity.json")
            )

        # ── STEP 10: Generate Final Report ──
        print("[PIPELINE] Step 10: Generating final report...")
        sample_info = {
            "name": os.path.basename(sample_path),
            "filename": os.path.basename(sample_path),
            "path": sample_path,
            "size": os.path.getsize(sample_path) if os.path.isfile(sample_path) else 0,
            "sha256": route_result["file_info"].get("sha256", ""),
            "file_type": route_result["file_info"].get("description", ""),
            "strategy": strategy,
            "pid": target_pid,
            "timeout": args.timeout,
            "mode": args.mode,
        }

        generator = ReportGenerator(raw_dir=raw_dir)
        generator.generate(
            final_report_path,
            api_report_path=api_report_path,
            sample_info=sample_info,
        )

        # ── STEP 11: AI Verdict (LSTM Behavioral Analysis) ──
        print("[PIPELINE] Step 11: Running AI verdict engine...")
        try:
            with open(final_report_path) as f:
                full_report = json.load(f)

            verdict_result = calculate_final_verdict(full_report)

            # Merge verdict into the final report JSON
            full_report["ai_verdict"] = verdict_result
            with open(final_report_path, "w") as f:
                json.dump(full_report, f, indent=2)
            print(f"[PIPELINE] AI verdict saved to {final_report_path}")

            # Regenerate HTML with verdict included
            try:
                import importlib.util
                import webbrowser
                _this_dir = os.path.join(SCRIPT_DIR, "collector")
                _html_mod_path = os.path.join(_this_dir, "html_report.py")
                spec = importlib.util.spec_from_file_location("html_report", _html_mod_path)
                html_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(html_mod)
                html_path = final_report_path.replace(".json", ".html")
                html_mod.generate_html_report(final_report_path, html_path)
                abs_html = os.path.abspath(html_path)
                webbrowser.open(f"file:///{abs_html.replace(os.sep, '/')}")
                print(f"[HTML] Dashboard regenerated with AI verdict.")
            except Exception as e2:
                print(f"[PIPELINE] WARNING: HTML regeneration failed: {e2}")
        except Exception as e:
            print(f"[PIPELINE] WARNING: AI verdict failed: {e}")

        elapsed = time.time() - pipeline_start
        print(f"\n[PIPELINE] Pipeline completed in {elapsed:.1f}s")

    except KeyboardInterrupt:
        print("\n[PIPELINE] Interrupted by user")
    except Exception as e:
        print(f"\n[PIPELINE] ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        if target_proc and target_proc.poll() is None:
            target_proc.kill()
        if collector_proc and collector_proc.poll() is None:
            collector_proc.terminate()


if __name__ == "__main__":
    main()
