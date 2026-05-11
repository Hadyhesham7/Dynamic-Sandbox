"""
azure_revert.py — Azure VM Snapshot Revert Script
===================================================
Triggered by the Gateway after receiving the analysis report.
Reverts the Sandbox VM to a clean state by swapping its OS disk
back to a pre-configured snapshot.

Flow:
    1. Deallocate the Sandbox VM
    2. Create a new managed disk from the clean snapshot
    3. Swap the VM's OS disk to the new clean disk
    4. Delete the old (dirty) disk
    5. Start the VM again

Environment Variables (REQUIRED):
    AZURE_SUBSCRIPTION_ID   — Your Azure subscription ID
    AZURE_RESOURCE_GROUP    — Resource group containing the VM
    AZURE_VM_NAME           — Name of the sandbox VM
    AZURE_SNAPSHOT_NAME     — Name of the clean OS disk snapshot
    AZURE_LOCATION          — Azure region (e.g., "eastus")

Authentication:
    Uses DefaultAzureCredential which supports:
    - Environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)
    - Managed Identity (when running on Azure VM)
    - Azure CLI login (for local development)

Usage:
    python azure_revert.py                    # Uses env vars
    python azure_revert.py --vm sandbox-vm-1  # Override VM name
"""

from __future__ import annotations

import os
import sys
import time
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("azure_revert")

# ─── Configuration from environment ────────────────────────────────────────
SUBSCRIPTION_ID:  str = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
RESOURCE_GROUP:   str = os.environ.get("AZURE_RESOURCE_GROUP", "")
VM_NAME:          str = os.environ.get("AZURE_VM_NAME", "")
SNAPSHOT_NAME:    str = os.environ.get("AZURE_SNAPSHOT_NAME", "")
LOCATION:         str = os.environ.get("AZURE_LOCATION", "eastus")


def validate_config(vm_name: str = None):
    """Ensure all required Azure configuration is present."""
    vm = vm_name or VM_NAME
    missing = []
    if not SUBSCRIPTION_ID: missing.append("AZURE_SUBSCRIPTION_ID")
    if not RESOURCE_GROUP:  missing.append("AZURE_RESOURCE_GROUP")
    if not vm:              missing.append("AZURE_VM_NAME")
    if not SNAPSHOT_NAME:   missing.append("AZURE_SNAPSHOT_NAME")
    if missing:
        log.error("Missing required environment variables: %s", ", ".join(missing))
        log.error("Set these before running the revert script.")
        sys.exit(1)
    return vm


def revert_vm_to_snapshot(vm_name: str = None, wait: bool = True) -> dict:
    """
    Full VM revert cycle: deallocate → swap disk → start.

    Args:
        vm_name:  Override for AZURE_VM_NAME env var.
        wait:     If True, block until each operation completes.

    Returns:
        Dict with status, timings, and any errors.
    """
    # ── Lazy import Azure SDKs (only needed when this function runs) ──
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.compute.models import (
            DiskCreateOption,
            CreationData,
            Disk,
        )
    except ImportError:
        log.error(
            "Azure SDKs not installed. Run:\n"
            "  pip install azure-identity azure-mgmt-compute"
        )
        return {"status": "error", "error": "Azure SDKs not installed"}

    vm = validate_config(vm_name)
    result = {"vm_name": vm, "status": "started", "steps": {}}
    t0 = time.time()

    # ── Authenticate ──────────────────────────────────────────────────────
    log.info("Authenticating with Azure (DefaultAzureCredential)...")
    credential = DefaultAzureCredential()
    compute = ComputeManagementClient(credential, SUBSCRIPTION_ID)

    # ── Step 1: Get current VM info ──────────────────────────────────────
    log.info("[1/5] Fetching VM '%s' info...", vm)
    try:
        vm_info = compute.virtual_machines.get(RESOURCE_GROUP, vm)
        old_disk_name = vm_info.storage_profile.os_disk.name
        old_disk_id = vm_info.storage_profile.os_disk.managed_disk.id
        log.info("  Current OS disk: %s", old_disk_name)
        result["steps"]["get_vm"] = "ok"
    except Exception as exc:
        log.error("Failed to get VM info: %s", exc)
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    # ── Step 2: Deallocate VM ────────────────────────────────────────────
    log.info("[2/5] Deallocating VM '%s'...", vm)
    t1 = time.time()
    try:
        poller = compute.virtual_machines.begin_deallocate(RESOURCE_GROUP, vm)
        if wait:
            poller.result()
        elapsed = round(time.time() - t1, 1)
        log.info("  VM deallocated in %.1fs", elapsed)
        result["steps"]["deallocate"] = {"status": "ok", "seconds": elapsed}
    except Exception as exc:
        log.error("Failed to deallocate VM: %s", exc)
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    # ── Step 3: Create new clean disk from snapshot ──────────────────────
    log.info("[3/5] Creating new disk from snapshot '%s'...", SNAPSHOT_NAME)
    t2 = time.time()
    new_disk_name = f"{vm}-clean-{int(time.time())}"
    try:
        snapshot = compute.snapshots.get(RESOURCE_GROUP, SNAPSHOT_NAME)
        snapshot_id = snapshot.id

        disk_params = Disk(
            location=LOCATION,
            creation_data=CreationData(
                create_option=DiskCreateOption.COPY,
                source_resource_id=snapshot_id,
            ),
            sku=vm_info.storage_profile.os_disk.managed_disk.storage_account_type
            if hasattr(vm_info.storage_profile.os_disk.managed_disk, "storage_account_type")
            else None,
        )
        poller = compute.disks.begin_create_or_update(
            RESOURCE_GROUP, new_disk_name, disk_params
        )
        if wait:
            new_disk = poller.result()
            new_disk_id = new_disk.id
        elapsed = round(time.time() - t2, 1)
        log.info("  New disk '%s' created in %.1fs", new_disk_name, elapsed)
        result["steps"]["create_disk"] = {"status": "ok", "disk": new_disk_name, "seconds": elapsed}
    except Exception as exc:
        log.error("Failed to create disk from snapshot: %s", exc)
        # Try to restart the VM even if disk creation failed
        log.info("Attempting to restart VM to avoid leaving it deallocated...")
        try:
            compute.virtual_machines.begin_start(RESOURCE_GROUP, vm).result()
        except Exception:
            pass
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    # ── Step 4: Swap OS disk ─────────────────────────────────────────────
    log.info("[4/5] Swapping OS disk to '%s'...", new_disk_name)
    t3 = time.time()
    try:
        vm_info.storage_profile.os_disk.managed_disk.id = new_disk_id
        vm_info.storage_profile.os_disk.name = new_disk_name
        poller = compute.virtual_machines.begin_create_or_update(
            RESOURCE_GROUP, vm, vm_info
        )
        if wait:
            poller.result()
        elapsed = round(time.time() - t3, 1)
        log.info("  OS disk swapped in %.1fs", elapsed)
        result["steps"]["swap_disk"] = {"status": "ok", "seconds": elapsed}
    except Exception as exc:
        log.error("Failed to swap OS disk: %s", exc)
        result["status"] = "error"
        result["error"] = str(exc)
        # Still try to start VM
        try:
            compute.virtual_machines.begin_start(RESOURCE_GROUP, vm).result()
        except Exception:
            pass
        return result

    # ── Step 5: Start VM ─────────────────────────────────────────────────
    log.info("[5/5] Starting VM '%s'...", vm)
    t4 = time.time()
    try:
        poller = compute.virtual_machines.begin_start(RESOURCE_GROUP, vm)
        if wait:
            poller.result()
        elapsed = round(time.time() - t4, 1)
        log.info("  VM started in %.1fs", elapsed)
        result["steps"]["start_vm"] = {"status": "ok", "seconds": elapsed}
    except Exception as exc:
        log.error("Failed to start VM: %s", exc)
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    # ── Cleanup: delete the old (dirty) disk ─────────────────────────────
    log.info("[+] Cleaning up old disk '%s'...", old_disk_name)
    try:
        compute.disks.begin_delete(RESOURCE_GROUP, old_disk_name).result()
        log.info("  Old disk deleted.")
        result["steps"]["cleanup"] = "ok"
    except Exception as exc:
        log.warning("Failed to delete old disk (non-fatal): %s", exc)
        result["steps"]["cleanup"] = f"warning: {exc}"

    total = round(time.time() - t0, 1)
    result["status"] = "completed"
    result["total_seconds"] = total
    log.info("=" * 50)
    log.info("VM revert completed in %.1fs", total)
    log.info("=" * 50)
    return result


# ─── CLI Entry Point ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Revert Azure Sandbox VM to a clean snapshot."
    )
    parser.add_argument(
        "--vm", default=VM_NAME,
        help="Azure VM name (overrides AZURE_VM_NAME env var)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate config without making changes"
    )
    args = parser.parse_args()

    if args.dry_run:
        vm = validate_config(args.vm)
        log.info("DRY RUN — Configuration valid:")
        log.info("  Subscription: %s", SUBSCRIPTION_ID[:8] + "...")
        log.info("  Resource Group: %s", RESOURCE_GROUP)
        log.info("  VM: %s", vm)
        log.info("  Snapshot: %s", SNAPSHOT_NAME)
        log.info("  Location: %s", LOCATION)
        return

    result = revert_vm_to_snapshot(args.vm)
    if result["status"] != "completed":
        log.error("Revert FAILED: %s", result.get("error"))
        sys.exit(1)


if __name__ == "__main__":
    main()
