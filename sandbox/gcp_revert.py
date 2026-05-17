"""
gcp_revert.py — GCP Sandbox VM Snapshot Revert (Production)
============================================================
THIS SCRIPT RUNS ON THE GATEWAY SERVER, NOT ON THE SANDBOX.

After the Gateway receives the analysis report via webhook, it calls
this script to revert the Sandbox VM back to a clean snapshot.

Architecture:
    ┌──────────┐    webhook     ┌──────────────┐
    │ Sandbox  │───────────────►│   Gateway    │
    │   VM     │                │   Server     │
    └──────────┘                └──────┬───────┘
         ▲                             │
         │     gcp_revert.py           │
         └─────────────────────────────┘
         (stop → swap disk → start)

How it works:
    1. Stop the Sandbox VM
    2. Detach the dirty boot disk
    3. Create a fresh disk from the clean snapshot
    4. Attach the fresh disk as boot
    5. Start the VM
    6. Delete the old dirty disk
    7. Wait for the API server to come back online

Environment Variables (set on the GATEWAY machine):
    GCP_PROJECT         — Google Cloud Project ID
    GCP_ZONE            — Zone (e.g. "us-central1-a")
    GCP_INSTANCE_NAME   — Sandbox VM name
    GCP_SNAPSHOT_NAME   — Clean snapshot name
    GCP_DISK_TYPE       — Disk type (default: "pd-ssd")
    SANDBOX_URL         — Sandbox health URL (default: http://<vm-ip>:8000)

Authentication:
    Option A: gcloud auth application-default login
    Option B: GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

Usage:
    python gcp_revert.py                    # Full revert
    python gcp_revert.py --dry-run          # Validate config only
    python gcp_revert.py --wait-ready       # Revert + wait for API health
"""

import os
import sys
import time
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [GCP-REVERT] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("gcp_revert")

# ─── Configuration ─────────────────────────────────────────────────────────
GCP_PROJECT: str = os.environ.get("GCP_PROJECT", "")
GCP_ZONE: str = os.environ.get("GCP_ZONE", "")
GCP_INSTANCE_NAME: str = os.environ.get("GCP_INSTANCE_NAME", "")
GCP_SNAPSHOT_NAME: str = os.environ.get("GCP_SNAPSHOT_NAME", "")
GCP_DISK_TYPE: str = os.environ.get("GCP_DISK_TYPE", "pd-ssd")
SANDBOX_URL: str = os.environ.get("SANDBOX_URL", "")


def _validate_config(vm_override: str = None) -> str:
    """Validate all required environment variables are set."""
    vm = vm_override or GCP_INSTANCE_NAME
    missing = []
    if not GCP_PROJECT:
        missing.append("GCP_PROJECT")
    if not GCP_ZONE:
        missing.append("GCP_ZONE")
    if not vm:
        missing.append("GCP_INSTANCE_NAME")
    if not GCP_SNAPSHOT_NAME:
        missing.append("GCP_SNAPSHOT_NAME")

    if missing:
        log.error(f"Missing required env vars: {', '.join(missing)}")
        log.error("Set them in your .env file or system environment.")
        sys.exit(1)

    return vm


def revert_to_snapshot(vm_name: str = None, wait_ready: bool = False) -> dict:
    """
    Full revert cycle: stop → swap disk → start → (optional) wait for health.

    Returns a dict with status, timing, and details.
    """
    try:
        from google.cloud import compute_v1
    except ImportError:
        log.error("google-cloud-compute not installed!")
        log.error("Run: pip install google-cloud-compute")
        return {"status": "error", "error": "SDK not installed"}

    vm = _validate_config(vm_name)
    t0 = time.time()
    result = {"vm": vm, "snapshot": GCP_SNAPSHOT_NAME, "status": "started"}

    instances = compute_v1.InstancesClient()
    disks = compute_v1.DisksClient()
    snapshots = compute_v1.SnapshotsClient()

    try:
        # ── Step 1: Get current boot disk info ──────────────────────────
        log.info(f"[1/6] Reading VM '{vm}' in {GCP_ZONE}...")
        instance = instances.get(
            project=GCP_PROJECT, zone=GCP_ZONE, instance=vm
        )

        boot_disk = None
        for d in instance.disks:
            if d.boot:
                boot_disk = d
                break

        if not boot_disk:
            raise RuntimeError("No boot disk found on the VM!")

        old_disk_name = boot_disk.source.split("/")[-1]
        device_name = boot_disk.device_name
        log.info(f"  Boot disk: {old_disk_name} (device: {device_name})")

        # ── Step 2: Stop the VM ─────────────────────────────────────────
        log.info(f"[2/6] Stopping VM...")
        t1 = time.time()
        op = instances.stop(
            project=GCP_PROJECT, zone=GCP_ZONE, instance=vm
        )
        op.result()  # Wait for completion
        log.info(f"  Stopped in {time.time() - t1:.1f}s")

        # ── Step 3: Detach dirty boot disk ──────────────────────────────
        log.info(f"[3/6] Detaching disk '{device_name}'...")
        t1 = time.time()
        op = instances.detach_disk(
            project=GCP_PROJECT, zone=GCP_ZONE,
            instance=vm, device_name=device_name
        )
        op.result()
        log.info(f"  Detached in {time.time() - t1:.1f}s")

        # ── Step 4: Create fresh disk from snapshot ─────────────────────
        new_disk_name = f"{vm}-clean-{int(time.time())}"
        log.info(f"[4/6] Creating disk '{new_disk_name}' from snapshot...")
        t1 = time.time()

        snapshot = snapshots.get(
            project=GCP_PROJECT, snapshot=GCP_SNAPSHOT_NAME
        )

        disk_body = compute_v1.Disk(
            name=new_disk_name,
            source_snapshot=snapshot.self_link,
            type_=f"zones/{GCP_ZONE}/diskTypes/{GCP_DISK_TYPE}",
        )
        op = disks.insert(
            project=GCP_PROJECT, zone=GCP_ZONE, disk_resource=disk_body
        )
        op.result()

        new_disk = disks.get(
            project=GCP_PROJECT, zone=GCP_ZONE, disk=new_disk_name
        )
        log.info(f"  Created in {time.time() - t1:.1f}s")

        # ── Step 5: Attach fresh disk as boot ───────────────────────────
        log.info(f"[5/6] Attaching fresh disk as boot...")
        t1 = time.time()
        attach_body = compute_v1.AttachedDisk(
            auto_delete=True,
            boot=True,
            device_name=device_name,
            source=new_disk.self_link,
            mode="READ_WRITE",
            type_="PERSISTENT",
        )
        op = instances.attach_disk(
            project=GCP_PROJECT, zone=GCP_ZONE,
            instance=vm, attached_disk_resource=attach_body,
        )
        op.result()
        log.info(f"  Attached in {time.time() - t1:.1f}s")

        # ── Step 6: Start the VM ────────────────────────────────────────
        log.info(f"[6/6] Starting VM...")
        t1 = time.time()
        op = instances.start(
            project=GCP_PROJECT, zone=GCP_ZONE, instance=vm
        )
        op.result()
        log.info(f"  Started in {time.time() - t1:.1f}s")

        # ── Cleanup: Delete old dirty disk ──────────────────────────────
        log.info(f"[+] Deleting old disk '{old_disk_name}'...")
        try:
            op = disks.delete(
                project=GCP_PROJECT, zone=GCP_ZONE, disk=old_disk_name
            )
            op.result()
            log.info("  Old disk deleted.")
        except Exception as e:
            log.warning(f"  Could not delete old disk (non-fatal): {e}")

        total = time.time() - t0
        result["status"] = "completed"
        result["total_seconds"] = round(total, 1)
        result["new_disk"] = new_disk_name
        log.info("=" * 50)
        log.info(f"REVERT COMPLETE in {total:.1f}s")
        log.info("=" * 50)

        # ── Optional: Wait for API to come back online ──────────────────
        if wait_ready and SANDBOX_URL:
            _wait_for_health(SANDBOX_URL)

        return result

    except Exception as exc:
        log.error(f"REVERT FAILED: {exc}")
        result["status"] = "error"
        result["error"] = str(exc)
        return result


def _wait_for_health(base_url: str, timeout: int = 180):
    """Poll the sandbox /health endpoint until it responds."""
    import requests

    health_url = f"{base_url.rstrip('/')}/api/v1/health"
    log.info(f"Waiting for sandbox to come online: {health_url}")

    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(health_url, timeout=5)
            if r.status_code == 200:
                log.info(f"Sandbox is ONLINE! (took {time.time() - start:.0f}s)")
                return True
        except Exception:
            pass
        time.sleep(5)

    log.warning(f"Sandbox did not respond within {timeout}s")
    return False


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Revert GCP Sandbox VM to clean snapshot"
    )
    parser.add_argument("--vm", default=None, help="Override VM name")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate config only, don't revert")
    parser.add_argument("--wait-ready", action="store_true",
                        help="After revert, wait for API /health to respond")
    args = parser.parse_args()

    if args.dry_run:
        vm = _validate_config(args.vm)
        log.info("DRY RUN — Config is valid:")
        log.info(f"  Project:  {GCP_PROJECT}")
        log.info(f"  Zone:     {GCP_ZONE}")
        log.info(f"  VM:       {vm}")
        log.info(f"  Snapshot: {GCP_SNAPSHOT_NAME}")
        log.info(f"  Disk:     {GCP_DISK_TYPE}")
        return

    result = revert_to_snapshot(args.vm, wait_ready=args.wait_ready)
    if result["status"] != "completed":
        sys.exit(1)


if __name__ == "__main__":
    main()
