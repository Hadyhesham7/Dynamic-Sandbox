"""
registry_monitor.py - Registry Snapshot & Diff Monitor
=======================================================
Takes before/after snapshots of critical registry keys and reports:
  - Keys created
  - Values set/modified
  - Keys/values deleted
  - Persistence indicators (Run keys, services, etc.)

Usage:
    monitor = RegistryMonitor()
    monitor.take_pre_snapshot()
    # ... run malware ...
    monitor.take_post_snapshot()
    report = monitor.generate_report()
    monitor.save_report("reports/raw/registry_activity.json")
"""

import os
import json
import time
import winreg


class RegistryMonitor:
    """Monitors registry changes by comparing before/after snapshots."""

    # Critical registry keys to monitor
    WATCH_KEYS = [
        # Persistence - Auto-run
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Run",
         "HKCU\\...\\Run"),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKCU\\...\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "HKLM\\...\\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKLM\\...\\RunOnce"),

        # Persistence - Services
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Services",
         "HKLM\\...\\Services"),

        # Persistence - Shell extensions
        (winreg.HKEY_CURRENT_USER,
         r"Software\Classes\*\shell",
         "HKCU\\Classes\\*\\shell"),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Classes\Directory\shell",
         "HKCU\\Classes\\Directory\\shell"),

        # Persistence - Winlogon
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
         "HKLM\\...\\Winlogon"),

        # Persistence - Startup Approved
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
         "HKCU\\...\\StartupApproved\\Run"),

        # Browser/COM hijacking
        (winreg.HKEY_CURRENT_USER,
         r"Software\Classes\CLSID",
         "HKCU\\Classes\\CLSID"),

        # Scheduled Tasks (via registry)
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
         "HKLM\\...\\TaskCache\\Tasks"),

        # Custom test key (for testing with api_exerciser)
        (winreg.HKEY_CURRENT_USER,
         r"Software\SandboxTest",
         "HKCU\\Software\\SandboxTest"),

        # Macro malware config key (for macro test docs)
        (winreg.HKEY_CURRENT_USER,
         r"Software\MacroMalwareConfig",
         "HKCU\\Software\\MacroMalwareConfig"),
    ]

    # Keys that indicate persistence behavior
    PERSISTENCE_KEY_PATTERNS = [
        "\\Run", "\\RunOnce", "\\Services",
        "\\Winlogon", "\\StartupApproved",
        "\\shell\\open\\command", "\\TaskCache",
    ]

    def __init__(self, extra_keys=None):
        """
        Args:
            extra_keys: Additional (hive, subkey, label) tuples to monitor
        """
        self.watch_keys = list(self.WATCH_KEYS)
        if extra_keys:
            self.watch_keys.extend(extra_keys)

        self.pre_snapshot = {}
        self.post_snapshot = {}

    def _read_key_values(self, hive, subkey):
        """Read all values from a registry key."""
        values = {}
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            try:
                i = 0
                while True:
                    name, data, reg_type = winreg.EnumValue(key, i)
                    type_name = self._type_name(reg_type)
                    # Convert bytes to hex string for JSON serialization
                    if isinstance(data, bytes):
                        data = data.hex()
                    values[name] = {
                        "data": str(data),
                        "type": type_name,
                    }
                    i += 1
            except OSError:
                pass  # No more values
            winreg.CloseKey(key)
        except FileNotFoundError:
            pass  # Key doesn't exist
        except PermissionError:
            pass  # Access denied

        return values

    def _read_subkeys(self, hive, subkey):
        """List all subkeys of a registry key."""
        subkeys = []
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            try:
                i = 0
                while True:
                    name = winreg.EnumKey(key, i)
                    subkeys.append(name)
                    i += 1
            except OSError:
                pass
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError):
            pass

        return subkeys

    def _type_name(self, reg_type):
        """Convert registry type constant to string."""
        types = {
            winreg.REG_SZ: "REG_SZ",
            winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
            winreg.REG_BINARY: "REG_BINARY",
            winreg.REG_DWORD: "REG_DWORD",
            winreg.REG_QWORD: "REG_QWORD",
            winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
        }
        return types.get(reg_type, f"TYPE_{reg_type}")

    def _take_snapshot(self):
        """Take a snapshot of all watched keys."""
        snapshot = {}

        for hive, subkey, label in self.watch_keys:
            key_id = label
            values = self._read_key_values(hive, subkey)
            subkeys = self._read_subkeys(hive, subkey)

            # Read one level of subkey values (catches Config/C2Server etc.)
            subkey_values = {}
            for sk_name in subkeys:
                full_sk = f"{subkey}\\{sk_name}"
                sk_vals = self._read_key_values(hive, full_sk)
                if sk_vals:
                    subkey_values[sk_name] = sk_vals

            snapshot[key_id] = {
                "values": values,
                "subkeys": subkeys,
                "subkey_values": subkey_values,
                "exists": bool(values or subkeys),
            }

        return snapshot

    def take_pre_snapshot(self):
        """Take snapshot BEFORE execution."""
        print("[REG_MON] Taking pre-execution registry snapshot...")
        self.pre_snapshot = self._take_snapshot()
        count = sum(1 for k in self.pre_snapshot.values() if k["exists"])
        print(f"[REG_MON]   Monitored {len(self.pre_snapshot)} keys ({count} exist)")
        return self.pre_snapshot

    def take_post_snapshot(self):
        """Take snapshot AFTER execution."""
        print("[REG_MON] Taking post-execution registry snapshot...")
        self.post_snapshot = self._take_snapshot()
        return self.post_snapshot

    def compare(self):
        """Compare snapshots and return differences."""
        if not self.pre_snapshot or not self.post_snapshot:
            return None

        keys_created = []
        keys_deleted = []
        values_set = []
        values_modified = []
        values_deleted = []

        all_keys = set(self.pre_snapshot.keys()) | set(self.post_snapshot.keys())

        for key_id in sorted(all_keys):
            pre = self.pre_snapshot.get(key_id, {
                "values": {}, "subkeys": [], "subkey_values": {},
                "exists": False
            })
            post = self.post_snapshot.get(key_id, {
                "values": {}, "subkeys": [], "subkey_values": {},
                "exists": False
            })

            # Check for new subkeys
            pre_subs = set(pre["subkeys"])
            post_subs = set(post["subkeys"])
            for new_sub in post_subs - pre_subs:
                keys_created.append(f"{key_id}\\{new_sub}")
            for del_sub in pre_subs - post_subs:
                keys_deleted.append(f"{key_id}\\{del_sub}")

            # Check for value changes (direct values)
            pre_vals = pre["values"]
            post_vals = post["values"]

            # New values
            for name in set(post_vals.keys()) - set(pre_vals.keys()):
                v = post_vals[name]
                values_set.append({
                    "key": key_id,
                    "name": name,
                    "data": v["data"],
                    "type": v["type"],
                })

            # Deleted values
            for name in set(pre_vals.keys()) - set(post_vals.keys()):
                v = pre_vals[name]
                values_deleted.append({
                    "key": key_id,
                    "name": name,
                    "old_data": v["data"],
                })

            # Modified values
            for name in set(pre_vals.keys()) & set(post_vals.keys()):
                if pre_vals[name] != post_vals[name]:
                    values_modified.append({
                        "key": key_id,
                        "name": name,
                        "old_data": pre_vals[name]["data"],
                        "new_data": post_vals[name]["data"],
                        "type": post_vals[name]["type"],
                    })

            # Check subkey values (one level deep)
            pre_sk_vals = pre.get("subkey_values", {})
            post_sk_vals = post.get("subkey_values", {})

            for sk_name in post_sk_vals:
                old_vals = pre_sk_vals.get(sk_name, {})
                new_vals = post_sk_vals[sk_name]
                subkey_label = f"{key_id}\\{sk_name}"

                # New subkey values
                for vname in set(new_vals.keys()) - set(old_vals.keys()):
                    v = new_vals[vname]
                    values_set.append({
                        "key": subkey_label,
                        "name": vname,
                        "data": v["data"],
                        "type": v["type"],
                    })

                # Modified subkey values
                for vname in set(old_vals.keys()) & set(new_vals.keys()):
                    if old_vals[vname] != new_vals[vname]:
                        values_modified.append({
                            "key": subkey_label,
                            "name": vname,
                            "old_data": old_vals[vname]["data"],
                            "new_data": new_vals[vname]["data"],
                            "type": new_vals[vname]["type"],
                        })

        return {
            "keys_created": keys_created,
            "keys_deleted": keys_deleted,
            "values_set": values_set,
            "values_modified": values_modified,
            "values_deleted": values_deleted,
        }

    def _detect_persistence(self, diff):
        """Check if any changes indicate persistence behavior."""
        indicators = []

        for pattern in self.PERSISTENCE_KEY_PATTERNS:
            for key in diff["keys_created"]:
                if pattern.lower() in key.lower():
                    indicators.append(f"New key in persistence location: {key}")
            for val in diff["values_set"]:
                if pattern.lower() in val["key"].lower():
                    indicators.append(
                        f"New value in {val['key']}: {val['name']}={val['data']}"
                    )
            for val in diff["values_modified"]:
                if pattern.lower() in val["key"].lower():
                    indicators.append(
                        f"Modified persistence value: {val['key']}\\{val['name']}"
                    )

        return indicators

    def generate_report(self):
        """Generate the registry activity report."""
        diff = self.compare()
        if not diff:
            return {"component": "registry_activity", "data": {}}

        persistence = self._detect_persistence(diff)

        report = {
            "component": "registry_activity",
            "version": "1.0",
            "timestamp": time.time(),
            "monitored_keys": [label for _, _, label in self.watch_keys],
            "data": {
                "keys_created": diff["keys_created"],
                "keys_deleted": diff["keys_deleted"],
                "values_set": diff["values_set"],
                "values_modified": diff["values_modified"],
                "values_deleted": diff["values_deleted"],
                "persistence_indicators": persistence,
                "summary": {
                    "total_keys_created": len(diff["keys_created"]),
                    "total_keys_deleted": len(diff["keys_deleted"]),
                    "total_values_set": len(diff["values_set"]),
                    "total_values_modified": len(diff["values_modified"]),
                    "total_values_deleted": len(diff["values_deleted"]),
                    "persistence_detected": len(persistence) > 0,
                }
            }
        }

        return report

    def save_report(self, output_path):
        """Generate and save the report."""
        report = self.generate_report()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        s = report["data"]["summary"]
        data = report["data"]
        type_map = {"REG_SZ": "Text String", "REG_DWORD": "Integer (32-bit)",
                    "REG_BINARY": "Binary Data", "REG_EXPAND_SZ": "Expandable Text",
                    "REG_QWORD": "Integer (64-bit)", "REG_MULTI_SZ": "Multiple Strings"}

        print(f"[REG_MON] Report saved: {output_path}")
        print(f"[REG_MON]   Keys created:   {s['total_keys_created']}")
        print(f"[REG_MON]   Values set:     {s['total_values_set']}")
        print(f"[REG_MON]   Values modified: {s['total_values_modified']}")
        print(f"[REG_MON]   Values deleted:  {s['total_values_deleted']}")

        # Show each key created
        for kc in data.get("keys_created", []):
            print(f"[REG_MON]     [KEY] Created: {kc}")

        # Show each value set with data and type
        for val in data.get("values_set", []):
            key = val.get("key", "")
            name = val.get("name", "")
            value = val.get("data", "")
            vtype = val.get("type", "")
            friendly = type_map.get(vtype, vtype)
            print(f"[REG_MON]     [SET] {key}\\{name}")
            print(f"[REG_MON]           Value: {value}  |  Type: {friendly} ({vtype})")

        # Show each value modified with old -> new
        for val in data.get("values_modified", []):
            key = val.get("key", "")
            name = val.get("name", "")
            old_v = val.get("old_value", "?")
            new_v = val.get("new_value", "?")
            print(f"[REG_MON]     [MOD] {key}\\{name}")
            print(f"[REG_MON]           Old: {old_v}  ->  New: {new_v}")

        # Show each value deleted
        for val in data.get("values_deleted", []):
            key = val.get("key", "") if isinstance(val, dict) else val
            print(f"[REG_MON]     [DEL] {key}")

        # Show persistence indicators
        if s["persistence_detected"]:
            print("[REG_MON]   WARNING: Persistence indicators found!")
            for ind in data["persistence_indicators"]:
                print(f"[REG_MON]     -> {ind}")

        return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Registry Monitor")
    parser.add_argument("--action", choices=["pre", "post", "demo"],
                        required=True)
    parser.add_argument("--snapshot-file",
                        default="sandbox/reports/raw/reg_snapshot.json")
    parser.add_argument("--output",
                        default="sandbox/reports/raw/registry_activity.json")
    args = parser.parse_args()

    monitor = RegistryMonitor()

    if args.action == "pre":
        snap = monitor.take_pre_snapshot()
        os.makedirs(os.path.dirname(args.snapshot_file), exist_ok=True)
        with open(args.snapshot_file, "w") as f:
            json.dump(snap, f, indent=2)
        print(f"[REG_MON] Pre-snapshot saved: {args.snapshot_file}")

    elif args.action == "post":
        if not os.path.exists(args.snapshot_file):
            print("[REG_MON] ERROR: No pre-snapshot. Run --action pre first.")
        else:
            with open(args.snapshot_file) as f:
                monitor.pre_snapshot = json.load(f)
            monitor.take_post_snapshot()
            monitor.save_report(args.output)

    elif args.action == "demo":
        print("[REG_MON] === DEMO MODE ===")
        monitor.take_pre_snapshot()

        # Create test registry changes
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\SandboxTest")
            winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ,
                             "malware_demo_value")
            winreg.CloseKey(key)
        except Exception as e:
            print(f"[REG_MON] Demo write failed: {e}")

        monitor.take_post_snapshot()
        monitor.save_report(args.output)

        # Cleanup
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                           r"Software\SandboxTest")
        except Exception:
            pass
