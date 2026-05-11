"""
process_tree.py - Process Tree Tracker (Phase 8B)
===================================================
Builds parent->child PID chains from CreateProcess/ShellExecuteExW calls
captured by the hook DLL. Detects multi-stage payload execution.

Usage:
    from monitors.process_tree import ProcessTreeAnalyzer
    analyzer = ProcessTreeAnalyzer(api_raw_report)
    result = analyzer.analyze()
"""

import os
import json


class ProcessTreeAnalyzer:
    """Analyze API call logs to reconstruct the process execution tree."""

    # APIs that create child processes
    SPAWN_APIS = {
        "CreateProcessW", "CreateProcessA",
        "ShellExecuteExW", "ShellExecuteExA",
        "CreateProcessInternalW",
    }

    # Injection-related APIs (cross-process operations)
    INJECTION_APIS = {
        "CreateRemoteThread", "QueueUserAPC",
        "SetThreadContext", "WriteProcessMemory",
        "NtMapViewOfSection",
    }

    # Suspicious creation flags
    SUSPICIOUS_FLAGS = {
        0x00000004: "CREATE_SUSPENDED",
        0x08000000: "CREATE_NO_WINDOW",
        0x00000010: "CREATE_NEW_CONSOLE",
    }

    def __init__(self, api_report=None, final_report=None):
        """
        Args:
            api_report: Raw api_raw_report.json dict (has behavior.processes)
            final_report: final_report.json dict (has api_behavior.detailed_calls)
        """
        self.api_report = api_report
        self.final_report = final_report
        self.processes = {}   # pid -> process info
        self.tree = {}        # pid -> list of child pids
        self.root_pid = None

    def analyze(self):
        """Run the full process tree analysis."""
        calls = self._extract_calls()
        if not calls:
            return self._empty_result()

        self._build_tree(calls)
        self._detect_multi_stage()
        self._detect_injection(calls)

        return self._build_result()

    def _extract_calls(self):
        """Extract all API calls from whichever report is available."""
        calls = []

        # Prefer raw API report (has PID grouping)
        if self.api_report:
            for proc in self.api_report.get("behavior", {}).get("processes", []):
                pid = proc.get("pid", 0)
                if self.root_pid is None:
                    self.root_pid = pid
                for c in proc.get("calls", []):
                    c["_pid"] = pid
                    calls.append(c)

        # Fall back to final_report
        elif self.final_report:
            for c in self.final_report.get("api_behavior", {}).get("detailed_calls", []):
                calls.append(c)

        calls.sort(key=lambda x: x.get("time", 0))
        return calls

    def _build_tree(self, calls):
        """Build the process tree from CreateProcess calls."""
        # Track the root process
        if self.root_pid:
            self.processes[self.root_pid] = {
                "pid": self.root_pid,
                "name": "target.exe",
                "parent_pid": None,
                "spawn_time": 0,
                "spawn_api": "ROOT",
                "command_line": "",
                "creation_flags": "",
                "suspicious_flags": [],
                "depth": 0,
                "children": [],
            }
            self.tree[self.root_pid] = []

        child_counter = 90000  # synthetic PIDs for children we can't track

        for c in calls:
            api = c.get("api", "")
            if api not in self.SPAWN_APIS:
                continue

            args = c.get("arguments", c.get("args", {}))
            parent_pid = c.get("_pid", self.root_pid or 0)
            t = c.get("time", 0)

            # Extract process info
            app_name = args.get("lpApplicationName", args.get("lpFile", ""))
            cmd_line = args.get("lpCommandLine", args.get("lpParameters", ""))
            flags_raw = args.get("dwCreationFlags", "0x00000000")

            # Parse creation flags
            try:
                if isinstance(flags_raw, str):
                    flags_int = int(flags_raw, 16)
                else:
                    flags_int = int(flags_raw)
            except (ValueError, TypeError):
                flags_int = 0

            susp_flags = []
            for mask, name in self.SUSPICIOUS_FLAGS.items():
                if flags_int & mask:
                    susp_flags.append(name)

            # Assign synthetic child PID
            child_counter += 1
            child_pid = child_counter

            child_info = {
                "pid": child_pid,
                "name": os.path.basename(app_name) if app_name else cmd_line.split()[0] if cmd_line.strip() else "unknown",
                "parent_pid": parent_pid,
                "spawn_time": t,
                "spawn_api": api,
                "command_line": cmd_line,
                "application": app_name,
                "creation_flags": flags_raw,
                "suspicious_flags": susp_flags,
                "depth": self.processes.get(parent_pid, {}).get("depth", 0) + 1,
                "children": [],
            }

            self.processes[child_pid] = child_info
            self.tree.setdefault(parent_pid, []).append(child_pid)
            self.tree.setdefault(child_pid, [])

            # Update parent's children list
            if parent_pid in self.processes:
                self.processes[parent_pid]["children"].append(child_pid)

    def _detect_multi_stage(self):
        """Detect multi-stage payload execution patterns."""
        self.multi_stage = False
        self.max_depth = 0
        self.total_children = len(self.processes) - 1  # exclude root

        for pid, info in self.processes.items():
            if info["depth"] > self.max_depth:
                self.max_depth = info["depth"]

        # Multi-stage if depth >= 2 (grandchild processes)
        if self.max_depth >= 2:
            self.multi_stage = True

    def _detect_injection(self, calls):
        """Detect cross-process injection patterns."""
        self.injection_indicators = []

        for c in calls:
            api = c.get("api", "")
            if api in self.INJECTION_APIS:
                args = c.get("arguments", c.get("args", {}))
                self.injection_indicators.append({
                    "api": api,
                    "time": c.get("time", 0),
                    "target_handle": args.get("hProcess", args.get("hThread", "")),
                    "detail": args,
                })

        # Check for process hollowing pattern:
        # CreateProcess(SUSPENDED) -> WriteProcessMemory -> SetThreadContext -> ResumeThread
        self.hollowing_detected = False
        suspended_spawns = [
            p for p in self.processes.values()
            if "CREATE_SUSPENDED" in p.get("suspicious_flags", [])
        ]
        has_write_mem = any(i["api"] == "WriteProcessMemory" for i in self.injection_indicators)
        has_set_ctx = any(i["api"] == "SetThreadContext" for i in self.injection_indicators)

        if suspended_spawns and has_write_mem and has_set_ctx:
            self.hollowing_detected = True

    def _build_result(self):
        """Build the final analysis result dict."""
        # Build visual tree
        tree_lines = []
        if self.root_pid and self.root_pid in self.processes:
            self._render_tree(self.root_pid, "", True, tree_lines)

        risk_indicators = []
        if self.multi_stage:
            risk_indicators.append({
                "indicator": "MULTI_STAGE_EXECUTION",
                "severity": "HIGH",
                "detail": f"Process tree depth: {self.max_depth} (grandchild processes detected)",
            })
        if self.hollowing_detected:
            risk_indicators.append({
                "indicator": "PROCESS_HOLLOWING",
                "severity": "CRITICAL",
                "detail": "CreateProcess(SUSPENDED) + WriteProcessMemory + SetThreadContext pattern",
            })
        if self.injection_indicators:
            risk_indicators.append({
                "indicator": "CROSS_PROCESS_INJECTION",
                "severity": "CRITICAL",
                "detail": f"{len(self.injection_indicators)} injection API(s): "
                          f"{[i['api'] for i in self.injection_indicators[:5]]}",
            })

        # Suspicious child processes
        susp_children = []
        for pid, info in self.processes.items():
            if info.get("suspicious_flags"):
                susp_children.append({
                    "pid": pid,
                    "name": info["name"],
                    "flags": info["suspicious_flags"],
                    "api": info["spawn_api"],
                })

        return {
            "process_count": len(self.processes),
            "child_processes": self.total_children,
            "max_depth": self.max_depth,
            "multi_stage_detected": self.multi_stage,
            "hollowing_detected": self.hollowing_detected,
            "injection_indicators": self.injection_indicators,
            "suspicious_children": susp_children,
            "risk_indicators": risk_indicators,
            "tree_visual": "\n".join(tree_lines),
            "processes": {
                str(pid): {
                    "name": info["name"],
                    "parent_pid": info["parent_pid"],
                    "depth": info["depth"],
                    "spawn_api": info["spawn_api"],
                    "command_line": info.get("command_line", ""),
                    "suspicious_flags": info.get("suspicious_flags", []),
                    "children_count": len(info.get("children", [])),
                }
                for pid, info in self.processes.items()
            },
        }

    def _render_tree(self, pid, prefix, is_last, lines):
        """Render a tree branch for CLI/HTML display."""
        info = self.processes.get(pid, {})
        connector = "`-- " if is_last else "|-- "
        name = info.get("name", f"PID:{pid}")
        api = info.get("spawn_api", "")
        flags = info.get("suspicious_flags", [])

        label = f"[{pid}] {name}"
        if api and api != "ROOT":
            label += f" (via {api})"
        if flags:
            label += f" [{'|'.join(flags)}]"

        if prefix:
            lines.append(f"{prefix}{connector}{label}")
        else:
            lines.append(label)

        children = self.tree.get(pid, [])
        for i, child_pid in enumerate(children):
            is_child_last = (i == len(children) - 1)
            child_prefix = prefix + ("    " if is_last else "|   ")
            self._render_tree(child_pid, child_prefix, is_child_last, lines)

    def _empty_result(self):
        return {
            "process_count": 0,
            "child_processes": 0,
            "max_depth": 0,
            "multi_stage_detected": False,
            "hollowing_detected": False,
            "injection_indicators": [],
            "suspicious_children": [],
            "risk_indicators": [],
            "tree_visual": "(no process data available)",
            "processes": {},
        }

    def print_tree(self):
        """Print the process tree to console."""
        result = self.analyze()
        print("\n" + "=" * 60)
        print("  PROCESS TREE")
        print("=" * 60)
        print(result["tree_visual"])
        print(f"\n  Processes: {result['process_count']}")
        print(f"  Children:  {result['child_processes']}")
        print(f"  Max depth: {result['max_depth']}")
        if result["multi_stage_detected"]:
            print("  [!!!] MULTI-STAGE EXECUTION DETECTED")
        if result["hollowing_detected"]:
            print("  [!!!] PROCESS HOLLOWING DETECTED")
        for ind in result["risk_indicators"]:
            print(f"  [{ind['severity']}] {ind['indicator']}: {ind['detail']}")
        print("=" * 60)
        return result
