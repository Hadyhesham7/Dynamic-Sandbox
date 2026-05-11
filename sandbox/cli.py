"""
cli.py - Sandbox Interactive CLI Helper
==========================================
Interactive menu for all sandbox operations: run, test, clean, view, verify.

Usage:
    python sandbox/cli.py
    python sandbox/cli.py --help
"""

import os
import sys
import subprocess
import shutil
import json
import glob

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

# ══════════════════════════════════════════════════════════
#  MENU DEFINITIONS
# ══════════════════════════════════════════════════════════

CATEGORIES = [
    ("Running the Sandbox",          "run"),
    ("Testing Individual Components", "test"),
    ("Creating Test Files",           "create"),
    ("Cleaning",                      "clean"),
    ("Viewing Results",               "view"),
    ("Verifying Installation",        "verify"),
]


def cls():
    """Clear screen."""
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    """Wait for user to press Enter."""
    print()
    input("  Press Enter to continue...")


def run_cmd(cmd, cwd=None, shell=True):
    """Run a command and show output."""
    print(f"\n  > {cmd}\n")
    print("-" * 60)
    try:
        subprocess.run(cmd, cwd=cwd or PROJECT_ROOT, shell=shell)
    except KeyboardInterrupt:
        print("\n  [Interrupted]")
    except Exception as e:
        print(f"  ERROR: {e}")
    print("-" * 60)


def print_header():
    """Print the main header."""
    W = 60
    print()
    print("=" * W)
    print("  KNOWHOW SANDBOX -- CLI HELPER")
    print("=" * W)


def print_menu(title, options):
    """Print a sub-menu and return user choice."""
    W = 60
    print()
    print("=" * W)
    print(f"  {title}")
    print("=" * W)
    for i, (label, _) in enumerate(options, 1):
        print(f"  [{i}] {label}")
    print(f"  [0] Back")
    print("=" * W)

    while True:
        choice = input("  Select: ").strip()
        if choice == "0":
            return None
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return options[idx]
        except ValueError:
            pass
        print("  Invalid choice. Try again.")


# ══════════════════════════════════════════════════════════
#  CATEGORY 1: RUNNING THE SANDBOX
# ══════════════════════════════════════════════════════════

def menu_run():
    options = [
        ("Interactive mode (choose test or attachment)", "interactive"),
        ("Run built-in test sample (api_exerciser3.exe)", "test_exe"),
        ("Run test macro document (test_macro_doc.doc)", "test_doc"),
        ("Run test archive (test_archive.zip)", "test_zip"),
        ("Run custom file (enter path)", "custom"),
        ("Run with custom timeout", "timeout"),
        ("Run with skipped components", "skip"),
    ]
    choice = print_menu("RUNNING THE SANDBOX", options)
    if not choice:
        return

    _, action = choice

    if action == "interactive":
        run_cmd(f'python sandbox/analyze.py')

    elif action == "test_exe":
        run_cmd(f'python sandbox/analyze.py sandbox/tests/api_exerciser3.exe')

    elif action == "test_doc":
        doc = os.path.join("sandbox", "tests", "test_macro_doc.doc")
        if not os.path.exists(os.path.join(PROJECT_ROOT, doc)):
            print(f"  File not found: {doc}")
            print(f"  Run 'Create Test Files' first.")
            pause()
            return
        run_cmd(f'python sandbox/analyze.py {doc}')

    elif action == "test_zip":
        zipf = os.path.join("sandbox", "tests", "test_archive.zip")
        if not os.path.exists(os.path.join(PROJECT_ROOT, zipf)):
            print(f"  File not found: {zipf}")
            print(f"  Run 'Create Test Files' first.")
            pause()
            return
        run_cmd(f'python sandbox/analyze.py {zipf}')

    elif action == "custom":
        filepath = input("  Enter file path: ").strip().strip('"')
        if not os.path.exists(filepath):
            print(f"  ERROR: File not found: {filepath}")
            pause()
            return
        run_cmd(f'python sandbox/analyze.py "{filepath}"')

    elif action == "timeout":
        filepath = input("  Enter file path: ").strip().strip('"')
        timeout = input("  Timeout (seconds): ").strip()
        if not timeout.isdigit():
            print("  Invalid timeout")
            pause()
            return
        run_cmd(f'python sandbox/analyze.py "{filepath}" --timeout {timeout}')

    elif action == "skip":
        filepath = input("  Enter file path: ").strip().strip('"')
        print("  Skip components (y/n):")
        skip_net = input("    Skip network? (y/n): ").strip().lower() == "y"
        skip_mem = input("    Skip memory? (y/n): ").strip().lower() == "y"
        skip_file = input("    Skip files? (y/n): ").strip().lower() == "y"
        skip_reg = input("    Skip registry? (y/n): ").strip().lower() == "y"
        flags = ""
        if skip_net:
            flags += " --no-network"
        if skip_mem:
            flags += " --no-memory"
        if skip_file:
            flags += " --no-files"
        if skip_reg:
            flags += " --no-registry"
        run_cmd(f'python sandbox/analyze.py "{filepath}"{flags}')

    pause()


# ══════════════════════════════════════════════════════════
#  CATEGORY 2: TESTING INDIVIDUAL COMPONENTS
# ══════════════════════════════════════════════════════════

def menu_test():
    options = [
        ("Test Sample Router with EXE", "router_exe"),
        ("Test Sample Router with DOC", "router_doc"),
        ("Test Sample Router with ZIP", "router_zip"),
        ("Test Sample Router with custom file", "router_custom"),
        ("Test Report Generator (re-generate from raw)", "report"),
        ("Test API Decoder", "decoder"),
        ("Test Threat Score", "score"),
    ]
    choice = print_menu("TESTING INDIVIDUAL COMPONENTS", options)
    if not choice:
        return

    _, action = choice

    if action == "router_exe":
        run_cmd('python sandbox/sample_router.py sandbox/tests/api_exerciser3.exe')

    elif action == "router_doc":
        doc = os.path.join("sandbox", "tests", "test_macro_doc.doc")
        if not os.path.exists(os.path.join(PROJECT_ROOT, doc)):
            print(f"  File not found. Run 'Create Test Files' first.")
            pause()
            return
        run_cmd(f'python sandbox/sample_router.py {doc}')

    elif action == "router_zip":
        zipf = os.path.join("sandbox", "tests", "test_archive.zip")
        if not os.path.exists(os.path.join(PROJECT_ROOT, zipf)):
            print(f"  File not found. Run 'Create Test Files' first.")
            pause()
            return
        run_cmd(f'python sandbox/sample_router.py {zipf}')

    elif action == "router_custom":
        filepath = input("  Enter file path: ").strip().strip('"')
        if not os.path.exists(filepath):
            print(f"  ERROR: File not found")
            pause()
            return
        run_cmd(f'python sandbox/sample_router.py "{filepath}"')

    elif action == "report":
        raw_dir = os.path.join(SCRIPT_DIR, "reports", "raw")
        if not os.path.exists(raw_dir) or not os.listdir(raw_dir):
            print("  No raw reports found. Run analysis first.")
            pause()
            return
        cmd = (
            'python -c "'
            'import sys; sys.path.insert(0, \\"sandbox\\"); '
            'from collector.report_generator import ReportGenerator; '
            'gen = ReportGenerator(raw_dir=\\"sandbox/reports/raw\\"); '
            'gen.generate(\\"sandbox/reports/final_report.json\\", '
            'api_report_path=\\"sandbox/reports/api_raw_report.json\\")'
            '"'
        )
        run_cmd(cmd)

    elif action == "decoder":
        cmd = (
            'python -c "'
            'import sys; sys.path.insert(0, \\"sandbox\\"); '
            'from collector.api_decoder import decode_api_args, format_decoded_args; '
            "args = decode_api_args(\\'CreateFileA\\', {\\'dwDesiredAccess\\': \\'0x40000000\\', \\'dwCreationDisposition\\': \\'0x2\\'}); "
            "print(\\'CreateFileA:\\', format_decoded_args(args)); "
            "args2 = decode_api_args(\\'VirtualAlloc\\', {\\'flProtect\\': \\'0x40\\', \\'flAllocationType\\': \\'0x3000\\'}); "
            "print(\\'VirtualAlloc:\\', format_decoded_args(args2)); "
            "args3 = decode_api_args(\\'socket\\', {\\'af\\': \\'0x2\\', \\'type\\': \\'0x1\\', \\'protocol\\': \\'0x6\\'}); "
            "print(\\'socket:\\', format_decoded_args(args3))"
            '"'
        )
        run_cmd(cmd)

    elif action == "score":
        report_path = os.path.join(SCRIPT_DIR, "reports", "final_report.json")
        if not os.path.exists(report_path):
            print("  No final report found. Run analysis first.")
            pause()
            return
        try:
            with open(report_path) as f:
                r = json.load(f)
            s = r.get("summary", {})
            score = s.get("threat_score", 0)
            level = s.get("threat_level", "UNKNOWN")
            indicators = s.get("total_risk_indicators", 0)
            bar_len = 20
            filled = int(score / 100 * bar_len)
            bar = "#" * filled + "-" * (bar_len - filled)
            print(f"\n  Threat Score: {score}/100  [{bar}]")
            print(f"  Threat Level: {level}")
            print(f"  Risk Indicators: {indicators}")
            for ri in s.get("risk_indicators", []):
                print(f"    -> {ri}")
        except Exception as e:
            print(f"  ERROR: {e}")

    pause()


# ══════════════════════════════════════════════════════════
#  CATEGORY 3: CREATING TEST FILES
# ══════════════════════════════════════════════════════════

def menu_create():
    options = [
        ("Create test Word doc with VBA macro (needs Word)", "macro_doc"),
        ("Create minimal OLE test file (no Word needed)", "ole_doc"),
        ("Create test ZIP archive (contains test EXE)", "zip"),
        ("Create all test files", "all"),
    ]
    choice = print_menu("CREATING TEST FILES", options)
    if not choice:
        return

    _, action = choice

    if action == "macro_doc":
        run_cmd('python sandbox/tests/create_test_doc.py')

    elif action == "ole_doc":
        run_cmd('python sandbox/tests/create_test_ole.py')

    elif action == "zip":
        # Create inline
        exe_path = os.path.join(SCRIPT_DIR, "tests", "api_exerciser3.exe")
        zip_path = os.path.join(SCRIPT_DIR, "tests", "test_archive.zip")
        if not os.path.exists(exe_path):
            print(f"  ERROR: Test EXE not found: {exe_path}")
            pause()
            return
        import zipfile
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(exe_path, "malware_sample.exe")
            zf.writestr("readme.txt", "Test archive for sandbox routing")
        print(f"  Created: {zip_path} ({os.path.getsize(zip_path)} bytes)")

    elif action == "all":
        print("\n  Creating all test files...\n")
        # OLE file
        print("  [1/3] Minimal OLE document...")
        run_cmd('python sandbox/tests/create_test_ole.py')
        # Macro doc
        print("  [2/3] Word document with VBA macro...")
        run_cmd('python sandbox/tests/create_test_doc.py')
        # ZIP
        print("  [3/3] ZIP archive...")
        exe_path = os.path.join(SCRIPT_DIR, "tests", "api_exerciser3.exe")
        zip_path = os.path.join(SCRIPT_DIR, "tests", "test_archive.zip")
        if os.path.exists(exe_path):
            import zipfile
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.write(exe_path, "malware_sample.exe")
                zf.writestr("readme.txt", "Test archive for sandbox routing")
            print(f"  Created: {zip_path} ({os.path.getsize(zip_path)} bytes)")

    pause()


# ══════════════════════════════════════════════════════════
#  CATEGORY 4: CLEANING
# ══════════════════════════════════════════════════════════

def menu_clean():
    options = [
        ("Clean raw component reports", "raw"),
        ("Clean final report (JSON + HTML)", "final"),
        ("Clean extracted files (router artifacts)", "extracted"),
        ("Clean dropped file artifacts", "dropped"),
        ("Clean memory dumps", "dumps"),
        ("Clean EVERYTHING in reports/", "all"),
        ("Kill stuck Word processes", "kill_word"),
        ("Kill stuck Python processes", "kill_python"),
    ]
    choice = print_menu("CLEANING", options)
    if not choice:
        return

    _, action = choice

    reports = os.path.join(SCRIPT_DIR, "reports")
    raw = os.path.join(reports, "raw")
    artifacts = os.path.join(reports, "artifacts")

    if action == "raw":
        count = 0
        if os.path.exists(raw):
            for f in os.listdir(raw):
                os.remove(os.path.join(raw, f))
                count += 1
        print(f"  Cleaned {count} raw report(s)")

    elif action == "final":
        for f in ["final_report.json", "final_report.html"]:
            fp = os.path.join(reports, f)
            if os.path.exists(fp):
                os.remove(fp)
                print(f"  Deleted: {f}")
            else:
                print(f"  Not found: {f}")

    elif action == "extracted":
        ext_dir = os.path.join(artifacts, "extracted")
        if os.path.exists(ext_dir):
            shutil.rmtree(ext_dir)
            print(f"  Cleaned: {ext_dir}")
        else:
            print("  No extracted files found")

    elif action == "dropped":
        drop_dir = os.path.join(artifacts, "dropped_files")
        if os.path.exists(drop_dir):
            count = 0
            for f in os.listdir(drop_dir):
                os.remove(os.path.join(drop_dir, f))
                count += 1
            print(f"  Cleaned {count} dropped file(s)")
        else:
            print("  No dropped files found")

    elif action == "dumps":
        dump_dir = os.path.join(artifacts, "memory_dumps")
        if os.path.exists(dump_dir):
            count = 0
            for f in os.listdir(dump_dir):
                os.remove(os.path.join(dump_dir, f))
                count += 1
            print(f"  Cleaned {count} memory dump(s)")
        else:
            print("  No memory dumps found")

    elif action == "all":
        confirm = input("  Are you sure? This deletes ALL reports (y/n): ").strip().lower()
        if confirm == "y":
            if os.path.exists(reports):
                shutil.rmtree(reports)
                print("  Cleaned ALL reports")
            else:
                print("  Reports directory not found")
        else:
            print("  Cancelled")

    elif action == "kill_word":
        run_cmd('taskkill /IM WINWORD.EXE /F')

    elif action == "kill_python":
        confirm = input("  This will kill ALL Python processes. Sure? (y/n): ").strip().lower()
        if confirm == "y":
            run_cmd('taskkill /IM python.exe /F')
        else:
            print("  Cancelled")

    pause()


# ══════════════════════════════════════════════════════════
#  CATEGORY 5: VIEWING RESULTS
# ══════════════════════════════════════════════════════════

def menu_view():
    options = [
        ("Open HTML report in browser", "html"),
        ("View threat score summary", "score"),
        ("View execution timeline (last 20)", "timeline"),
        ("View top 10 API calls", "top_apis"),
        ("View macro analysis report", "macros"),
        ("View full JSON report (raw)", "json"),
        ("List all raw component reports", "list_raw"),
    ]
    choice = print_menu("VIEWING RESULTS", options)
    if not choice:
        return

    _, action = choice
    report_path = os.path.join(SCRIPT_DIR, "reports", "final_report.json")

    if action == "html":
        html_path = os.path.join(SCRIPT_DIR, "reports", "final_report.html")
        if os.path.exists(html_path):
            os.startfile(html_path)
            print("  Opened in browser")
        else:
            print("  HTML report not found. Run analysis first.")

    elif action in ("score", "timeline", "top_apis"):
        if not os.path.exists(report_path):
            print("  No final report found. Run analysis first.")
            pause()
            return
        try:
            with open(report_path) as f:
                r = json.load(f)
        except Exception as e:
            print(f"  ERROR reading report: {e}")
            pause()
            return

        if action == "score":
            s = r.get("summary", {})
            score = s.get("threat_score", 0)
            level = s.get("threat_level", "UNKNOWN")
            bar_len = 20
            filled = int(score / 100 * bar_len)
            bar = "#" * filled + "-" * (bar_len - filled)
            print(f"\n  Threat Score:  {score}/100  [{bar}]")
            print(f"  Threat Level:  {level}")
            print(f"  Sample:        {r.get('info', {}).get('sample', {}).get('name', '?')}")
            print(f"  API Calls:     {s.get('total_api_calls', '?')}")
            print(f"  Files Dropped: {s.get('files_created', '?')}")
            print(f"  Connections:   {s.get('connections', '?')}")
            print(f"  RWX Allocs:    {s.get('rwx_count', '?')}")
            print(f"\n  Risk Indicators ({s.get('total_risk_indicators', 0)}):")
            for ri in s.get("risk_indicators", []):
                print(f"    [!] {ri}")

        elif action == "timeline":
            timeline = r.get("timeline", [])
            if not timeline:
                print("  No timeline data found.")
            else:
                cat_icons = {
                    "API": "[A]", "FILE": "[F]", "REG": "[R]",
                    "NET": "[N]", "MEM": "[M]", "PROC": "[P]", "SYNC": "[~]",
                }
                print(f"\n  EXECUTION TIMELINE (showing {min(20, len(timeline))}/{len(timeline)} events)")
                print("  " + "-" * 56)
                for ev in timeline[:20]:
                    t = ev.get("timestamp", 0)
                    cat = ev.get("category", "?")
                    event = ev.get("event", "?")
                    detail = ev.get("detail", "")
                    icon = cat_icons.get(cat, "[?]")
                    d = f" -> {detail}" if detail else ""
                    print(f"    [{t:8.3f}s] {icon} {cat:5s} {event}{d}")

        elif action == "top_apis":
            api = r.get("api_behavior", {})
            freq = api.get("api_frequency", {})
            if not freq:
                print("  No API frequency data found.")
            else:
                sorted_apis = sorted(freq.items(), key=lambda x: x[1], reverse=True)
                print(f"\n  TOP 10 API CALLS (total: {api.get('total_calls', '?')})")
                print("  " + "-" * 40)
                for name, count in sorted_apis[:10]:
                    bar = "#" * min(count, 30)
                    print(f"    {name:30s} {count:4d}  {bar}")

    elif action == "macros":
        macro_path = os.path.join(SCRIPT_DIR, "reports", "raw", "macro_analysis.json")
        if not os.path.exists(macro_path):
            print("  No macro analysis found.")
            pause()
            return
        with open(macro_path) as f:
            m = json.load(f)
        print(f"\n  VBA MACRO ANALYSIS")
        print(f"  Has Macros:  {m.get('has_macros', False)}")
        print(f"  Total:       {m.get('macro_count', 0)}")
        print(f"  Suspicious:  {m.get('suspicious_count', 0)}")
        if m.get("auto_exec"):
            print(f"  AutoExec:    {', '.join(set(m['auto_exec']))}")
        for macro in m.get("macros", []):
            tag = "[!!]" if macro.get("suspicious") else "[--]"
            print(f"\n  {tag} {macro.get('name', '?')} ({macro.get('code_length', '?')} chars)")
            if macro.get("suspicious_keywords"):
                print(f"      Keywords: {', '.join(macro['suspicious_keywords'])}")
            code = macro.get("code", "")
            if code:
                print("      Code preview:")
                for line in code.split("\n")[:10]:
                    print(f"        {line}")
                if code.count("\n") > 10:
                    print("        ...")

    elif action == "json":
        if os.path.exists(report_path):
            run_cmd(f'python -m json.tool "{report_path}" | more')
        else:
            print("  No final report found. Run analysis first.")

    elif action == "list_raw":
        raw_dir = os.path.join(SCRIPT_DIR, "reports", "raw")
        if os.path.exists(raw_dir) and os.listdir(raw_dir):
            print(f"\n  Raw reports in {raw_dir}:")
            for f in sorted(os.listdir(raw_dir)):
                fp = os.path.join(raw_dir, f)
                size = os.path.getsize(fp)
                print(f"    {f:40s} {size:>8,} bytes")
        else:
            print("  No raw reports found.")

    pause()


# ══════════════════════════════════════════════════════════
#  CATEGORY 6: VERIFYING INSTALLATION
# ══════════════════════════════════════════════════════════

def menu_verify():
    options = [
        ("Check all dependencies", "all"),
        ("Check oletools", "oletools"),
        ("Check Word / Excel location", "office"),
        ("Check hook DLL", "dll"),
        ("Check test files exist", "tests"),
        ("Check report directory structure", "dirs"),
    ]
    choice = print_menu("VERIFYING INSTALLATION", options)
    if not choice:
        return

    _, action = choice

    if action == "all" or action == "oletools":
        print("\n  [oletools]")
        try:
            from oletools.olevba import VBA_Parser
            import oletools
            ver = getattr(oletools, "__version__", "unknown")
            print(f"    Status:  OK (version {ver})")
        except ImportError:
            print("    Status:  NOT INSTALLED")
            print("    Fix:     pip install oletools")

    if action == "all" or action == "office":
        print("\n  [Microsoft Office]")
        sys.path.insert(0, SCRIPT_DIR)
        from sample_router import SampleRouter
        router = SampleRouter()
        word = router._find_word()
        excel = router._find_excel()
        print(f"    Word:    {word or 'NOT FOUND'}")
        print(f"    Excel:   {excel or 'NOT FOUND'}")

    if action == "all" or action == "dll":
        print("\n  [Hook DLL]")
        dll_patterns = [
            os.path.join(SCRIPT_DIR, "hook_dll", "build64", "Release", "hook_monitor.dll"),
            os.path.join(SCRIPT_DIR, "hook_dll", "build64", "Debug", "hook_monitor.dll"),
            os.path.join(SCRIPT_DIR, "hook_dll", "build", "Release", "hook_monitor.dll"),
            os.path.join(SCRIPT_DIR, "hook_dll", "build", "Debug", "hook_monitor.dll"),
        ]
        found = False
        for p in dll_patterns:
            if os.path.exists(p):
                print(f"    Found:   {p}")
                print(f"    Size:    {os.path.getsize(p):,} bytes")
                found = True
                break
        if not found:
            print("    Status:  NOT FOUND - build the DLL first!")

    if action == "all" or action == "tests":
        print("\n  [Test Files]")
        test_files = {
            "api_exerciser3.exe": os.path.join(SCRIPT_DIR, "tests", "api_exerciser3.exe"),
            "test_macro_doc.doc": os.path.join(SCRIPT_DIR, "tests", "test_macro_doc.doc"),
            "test_archive.zip": os.path.join(SCRIPT_DIR, "tests", "test_archive.zip"),
        }
        for name, path in test_files.items():
            if os.path.exists(path):
                size = os.path.getsize(path)
                print(f"    {name:30s} OK  ({size:,} bytes)")
            else:
                print(f"    {name:30s} MISSING")

    if action == "all" or action == "dirs":
        print("\n  [Directory Structure]")
        dirs = {
            "reports/": os.path.join(SCRIPT_DIR, "reports"),
            "reports/raw/": os.path.join(SCRIPT_DIR, "reports", "raw"),
            "reports/artifacts/": os.path.join(SCRIPT_DIR, "reports", "artifacts"),
            "reports/artifacts/dropped_files/": os.path.join(SCRIPT_DIR, "reports", "artifacts", "dropped_files"),
            "reports/artifacts/memory_dumps/": os.path.join(SCRIPT_DIR, "reports", "artifacts", "memory_dumps"),
            "reports/artifacts/extracted/": os.path.join(SCRIPT_DIR, "reports", "artifacts", "extracted"),
        }
        for name, path in dirs.items():
            status = "OK" if os.path.exists(path) else "MISSING"
            if os.path.exists(path):
                count = len(os.listdir(path))
                print(f"    {name:40s} {status}  ({count} items)")
            else:
                print(f"    {name:40s} {status}")

    pause()


# ══════════════════════════════════════════════════════════
#  MAIN LOOP
# ══════════════════════════════════════════════════════════

MENU_HANDLERS = {
    "run":    menu_run,
    "test":   menu_test,
    "create": menu_create,
    "clean":  menu_clean,
    "view":   menu_view,
    "verify": menu_verify,
}


def main():
    while True:
        cls()
        print_header()
        for i, (label, _) in enumerate(CATEGORIES, 1):
            print(f"  [{i}] {label}")
        print(f"  [0] Exit")
        print("=" * 60)

        choice = input("  Select category: ").strip()

        if choice == "0":
            print("\n  Goodbye!")
            break

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(CATEGORIES):
                _, key = CATEGORIES[idx]
                MENU_HANDLERS[key]()
            else:
                print("  Invalid choice.")
                pause()
        except ValueError:
            print("  Invalid choice.")
            pause()
        except KeyboardInterrupt:
            print("\n\n  Goodbye!")
            break


if __name__ == "__main__":
    main()
