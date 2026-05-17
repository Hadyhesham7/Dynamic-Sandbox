"""
api_server.py — FastAPI REST Gateway for the KNOWHOW Sandbox (v2.0)
====================================================================
Enterprise-grade HTTP bridge between the Email Gateway and the
MasterOrchestrator analysis engine.

Architecture:
    - Webhook-first (fire-and-forget) with polling fallback
    - Dual report generation (JSON + HTML)
    - Automated environment reset via /cleanup endpoint
    - Per-job isolated report storage

Endpoints:
    POST /api/v1/analyze         — Submit .eml, file, or URL for analysis
    GET  /api/v1/status/{id}     — Poll job status (fallback)
    GET  /api/v1/report/{id}     — Fetch JSON report
    GET  /api/v1/report/{id}/html — Serve HTML dashboard in browser
    POST /api/v1/cleanup         — Wipe artifacts & reset sandbox
    GET  /api/v1/health          — Liveness probe

Environment Variables:
    KNOWHOW_API_KEY      — Required. Gateway authentication key.
    KNOWHOW_UPLOAD_DIR   — Temp dir for uploads (default: <project>/uploads)
    KNOWHOW_REPORT_DIR   — Dir for reports (default: <sandbox>/reports)
    KNOWHOW_TIMEOUT      — Max analysis seconds (default: 300)
    KNOWHOW_MAX_CONCURRENT — Max parallel jobs (default: 3)

Usage:
    uvicorn sandbox.api_server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
import json
import shutil
import traceback
import logging
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("knowhow.api")

# ─── Configuration ──────────────────────────────────────────────────────────
from dotenv import load_dotenv

# All paths resolve relative to THIS file's location, NOT the CWD.
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent

load_dotenv(PROJECT_ROOT / ".env")

API_KEY: str = os.environ.get("KNOWHOW_API_KEY", "knowhow-default-dev-key-change-me")
ANALYSIS_TIMEOUT: int = int(os.environ.get("KNOWHOW_TIMEOUT", "300"))
MAX_CONCURRENT: int = int(os.environ.get("KNOWHOW_MAX_CONCURRENT", "3"))

sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(PROJECT_ROOT / "URLLLL"))

# ─── Runtime directories ───────────────────────────────────────────────────
UPLOAD_DIR: Path = Path(os.environ.get("KNOWHOW_UPLOAD_DIR", str(PROJECT_ROOT / "uploads")))
REPORT_DIR: Path = Path(os.environ.get("KNOWHOW_REPORT_DIR", str(SCRIPT_DIR / "reports")))

# Per-job reports are stored in REPORT_DIR/<job_id>/
# This isolates artifacts so cleanup is trivial.

def _init_runtime_dirs():
    """Create all runtime directories excluded by .gitignore."""
    dirs = [
        UPLOAD_DIR, REPORT_DIR,
        SCRIPT_DIR / "reports",
        SCRIPT_DIR / "reports" / "raw",
        SCRIPT_DIR / "reports" / "artifacts",
        SCRIPT_DIR / "reports" / "artifacts" / "dropped_files",
        SCRIPT_DIR / "reports" / "artifacts" / "memory_dumps",
        SCRIPT_DIR / "reports" / "artifacts" / "network_capture",
        SCRIPT_DIR / "reports" / "artifacts" / "screenshots",
        SCRIPT_DIR / "reports" / "artifacts" / "extracted",
        SCRIPT_DIR / "reports" / "artifacts" / "extracted" / "archive_contents",
        SCRIPT_DIR / "reports" / "artifacts" / "extracted" / "ole_objects",
        SCRIPT_DIR / "reports" / "artifacts" / "email_extracted",
        SCRIPT_DIR / "reports" / "artifacts" / "downloads",
        PROJECT_ROOT / "URLLLL" / "screenshots",
        PROJECT_ROOT / "URLLLL" / "phishing_pipeline" / "data",
        PROJECT_ROOT / "URLLLL" / "phishing_pipeline" / "models",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

_init_runtime_dirs()

# ─── Job Store ──────────────────────────────────────────────────────────────
_jobs: dict[str, dict] = {}
_executor = ProcessPoolExecutor(max_workers=MAX_CONCURRENT)

# ─── FastAPI App ────────────────────────────────────────────────────────────
app = FastAPI(
    title="KNOWHOW Sandbox API",
    version="2.0.0",
    description="Email Gateway ↔ Dynamic Malware Sandbox REST interface (Webhook + Polling)",
    docs_url="/docs",
)


# ─── Auth ───────────────────────────────────────────────────────────────────

def _verify_api_key(x_api_key: str = Header(None)):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(401, "Invalid or missing API key.")


# ─── Response Models ────────────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    job_id: str
    status: str
    message: str

class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    input: str | None = None
    input_type: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    is_malware: bool | None = None
    is_phishing: bool | None = None
    verdict_summary: str | None = None
    elapsed_seconds: float | None = None
    error: str | None = None
    report_json_url: str | None = None
    report_html_url: str | None = None
    report: dict | None = None

class CleanupResponse(BaseModel):
    status: str
    cleaned_dirs: list[str]
    message: str


# ─── Worker Function (child process) ───────────────────────────────────────

def _run_analysis(input_path: str, skip_dynamic: bool = False) -> dict:
    """Invoked in a child process via ProcessPoolExecutor."""
    import sys as _sys
    script_dir = str(Path(__file__).parent.resolve())
    project_root = str(Path(__file__).parent.parent.resolve())
    _sys.path.insert(0, script_dir)
    _sys.path.insert(0, str(Path(project_root) / "URLLLL"))

    from master_orchestrator import MasterOrchestrator
    orch = MasterOrchestrator(skip_dynamic=skip_dynamic)
    return orch.analyze(input_path)


# ─── Dual Report Generator ─────────────────────────────────────────────────

def _save_job_reports(job_id: str, result: dict) -> tuple[Path, Path | None]:
    """
    Save both JSON and HTML reports for a completed job.
    Returns (json_path, html_path_or_None).
    """
    job_report_dir = REPORT_DIR / job_id
    job_report_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. JSON Report ──
    json_path = job_report_dir / "report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    log.info(f"[REPORT] JSON saved: {json_path}")

    # ── 2. HTML Report ──
    html_path = None
    try:
        input_type = result.get("input_type", "")

        if input_type == "FILE" or input_type == "EMAIL":
            # Use the sandbox HTML report generator
            from collector.html_report import generate_html_report
            # The generator reads from a JSON file
            html_out = str(job_report_dir / "report.html")
            generate_html_report(str(json_path), html_out)
            html_path = Path(html_out)

        elif input_type == "URL":
            # Use the URL pipeline HTML report generator
            sys.path.insert(0, str(PROJECT_ROOT / "URLLLL"))
            from url_html_report import generate_url_html_report
            html_out = str(job_report_dir / "report.html")
            url_results = result.get("subsystem_b", [])
            if isinstance(url_results, dict):
                url_results = [url_results]
            if url_results:
                generate_url_html_report(url_results, html_out)
                html_path = Path(html_out)

        # Fallback: also check if the pipeline already generated one
        if html_path is None or not html_path.exists():
            for candidate in [
                SCRIPT_DIR / "reports" / "final_report.html",
                SCRIPT_DIR / "reports" / "unified_report.html",
            ]:
                if candidate.exists():
                    dest = job_report_dir / "report.html"
                    shutil.copy2(candidate, dest)
                    html_path = dest
                    break

        if html_path and html_path.exists():
            log.info(f"[REPORT] HTML saved: {html_path}")
        else:
            log.warning(f"[REPORT] HTML generation skipped for job {job_id}")

    except Exception as e:
        log.warning(f"[REPORT] HTML generation failed: {e}")

    return json_path, html_path


# ─── Webhook Delivery ──────────────────────────────────────────────────────

async def _deliver_webhook(job_id: str, callback_url: str, result: dict):
    """POST the final results to the Gateway's callback URL."""
    import aiohttp

    verdict = result.get("unified_verdict", {})
    payload = {
        "job_id": job_id,
        "status": "completed",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input": result.get("input"),
        "input_type": result.get("input_type"),
        "risk_score": verdict.get("combined_score"),
        "risk_level": verdict.get("level"),
        "verdict_signals": verdict.get("signals", []),
        "report_json_url": f"/api/v1/report/{job_id}",
        "report_html_url": f"/api/v1/report/{job_id}/html",
        "report": result,
    }

    headers = {"Content-Type": "application/json"}
    retries = 3

    for attempt in range(1, retries + 1):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    callback_url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    log.info(
                        f"[WEBHOOK] Delivered to {callback_url} "
                        f"(attempt {attempt}, status {resp.status})"
                    )
                    if resp.status < 400:
                        _jobs[job_id]["webhook_delivered"] = True
                        return
        except Exception as e:
            log.warning(f"[WEBHOOK] Attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                await asyncio.sleep(2 ** attempt)

    log.error(f"[WEBHOOK] All {retries} attempts failed for job {job_id}")
    _jobs[job_id]["webhook_delivered"] = False


# ─── Analysis Executor ──────────────────────────────────────────────────────

async def _execute_analysis(
    job_id: str, input_path: str, skip_dynamic: bool, callback_url: str | None
):
    """Run orchestrator in process pool, save reports, fire webhook."""
    job = _jobs[job_id]
    job["status"] = "running"
    loop = asyncio.get_event_loop()

    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(_executor, _run_analysis, input_path, skip_dynamic),
            timeout=ANALYSIS_TIMEOUT,
        )
        job["status"] = "completed"
        job["result"] = result

    except asyncio.TimeoutError:
        job["status"] = "timeout"
        job["error"] = f"Analysis exceeded {ANALYSIS_TIMEOUT}s timeout."
        job["result"] = {
            "input": input_path,
            "input_type": job.get("input_type"),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "error": "TIMEOUT",
            "unified_verdict": {
                "combined_score": -1, "level": "ERROR",
                "signals": [f"Analysis timed out after {ANALYSIS_TIMEOUT}s"],
            },
            "partial": True,
        }

    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)
        job["result"] = {
            "input": input_path,
            "input_type": job.get("input_type"),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "unified_verdict": {
                "combined_score": -1, "level": "ERROR",
                "signals": [f"Analysis failed: {exc}"],
            },
            "partial": True,
        }

    finally:
        job["elapsed_seconds"] = round(time.time() - job["started_at"], 2)

    # ── Save dual reports (JSON + HTML) ──
    result = job.get("result", {})
    json_path, html_path = _save_job_reports(job_id, result)
    job["json_path"] = str(json_path)
    job["html_path"] = str(html_path) if html_path else None

    # ── Fire webhook if callback_url was provided ──
    if callback_url:
        log.info(f"[WEBHOOK] Firing callback to {callback_url}")
        await _deliver_webhook(job_id, callback_url, result)


# ─── Endpoints ──────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health_check():
    """Liveness probe."""
    active = sum(1 for j in _jobs.values() if j["status"] == "running")
    completed = sum(1 for j in _jobs.values() if j["status"] == "completed")
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "active_jobs": active,
        "completed_jobs": completed,
        "max_concurrent": MAX_CONCURRENT,
    }


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze(
    file: Optional[UploadFile] = File(None),
    url: Optional[str] = Form(None),
    callback_url: Optional[str] = Form(None),
    skip_dynamic: bool = Form(False),
    x_api_key: str = Header(None),
):
    """
    Submit .eml, binary file, or URL for analysis.

    - **file**: Upload a file (.eml, .exe, .doc, etc.)
    - **url**: A URL string to analyze
    - **callback_url**: (Optional) Webhook URL. If provided, results are
      POSTed here when done (fire-and-forget mode).
    - **skip_dynamic**: Skip Playwright browser analysis for URLs.

    Returns a job_id. Use polling (/status) OR provide callback_url for webhook.
    """
    _verify_api_key(x_api_key)

    if not file and not url:
        raise HTTPException(400, "Must provide 'file' or 'url'.")

    active = sum(1 for j in _jobs.values() if j["status"] == "running")
    if active >= MAX_CONCURRENT:
        raise HTTPException(429, f"Server busy — {active}/{MAX_CONCURRENT} slots.")

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "status": "queued",
        "input": None,
        "input_type": None,
        "started_at": time.time(),
        "result": None,
        "error": None,
        "callback_url": callback_url,
        "webhook_delivered": None,
        "json_path": None,
        "html_path": None,
    }
    _jobs[job_id] = job

    if file:
        job_dir = UPLOAD_DIR / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        save_path = job_dir / file.filename
        with open(save_path, "wb") as f:
            content = await file.read()
            f.write(content)
        input_path = str(save_path)
        job["input"] = file.filename
        job["input_type"] = "EMAIL" if file.filename.lower().endswith(".eml") else "FILE"
    else:
        input_path = url.strip()
        job["input"] = input_path
        job["input_type"] = "URL"

    asyncio.create_task(
        _execute_analysis(job_id, input_path, skip_dynamic, callback_url)
    )

    mode = "Webhook → " + callback_url if callback_url else "Polling → GET /api/v1/status/" + job_id
    return AnalyzeResponse(
        job_id=job_id,
        status="queued",
        message=f"Analysis queued. Mode: {mode}",
    )


@app.get("/api/v1/status/{job_id}", response_model=JobStatusResponse)
async def get_status(job_id: str, x_api_key: str = Header(None)):
    """Poll job status (fallback if not using webhooks)."""
    _verify_api_key(x_api_key)

    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Job '{job_id}' not found.")

    result = job.get("result") or {}
    verdict = result.get("unified_verdict", {})
    done = job["status"] in ("completed", "timeout", "error")

    return JobStatusResponse(
        job_id=job_id,
        status=job["status"],
        input=job.get("input"),
        input_type=job.get("input_type") or result.get("input_type"),
        risk_score=verdict.get("combined_score"),
        risk_level=verdict.get("level"),
        is_malware=(
            verdict.get("level") in ("CRITICAL", "HIGH")
            and "malware" in str(verdict.get("signals", "")).lower()
        ) if verdict else None,
        is_phishing=(
            verdict.get("level") in ("CRITICAL", "HIGH")
            and "phishing" in str(verdict.get("signals", "")).lower()
        ) if verdict else None,
        verdict_summary="; ".join(verdict.get("signals", [])) if verdict.get("signals") else None,
        elapsed_seconds=job.get("elapsed_seconds"),
        error=job.get("error"),
        report_json_url=f"/api/v1/report/{job_id}" if done else None,
        report_html_url=f"/api/v1/report/{job_id}/html" if done and job.get("html_path") else None,
        report=result if done else None,
    )


@app.get("/api/v1/report/{job_id}")
async def get_report_json(job_id: str, x_api_key: str = Header(None)):
    """Retrieve the full JSON analysis report."""
    _verify_api_key(x_api_key)

    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Job '{job_id}' not found.")
    if job["status"] not in ("completed", "timeout", "error"):
        raise HTTPException(202, f"Job still {job['status']}.")

    # Serve from saved file if available
    json_path = job.get("json_path")
    if json_path and Path(json_path).exists():
        with open(json_path, "r", encoding="utf-8") as f:
            return JSONResponse(content=json.load(f))

    return JSONResponse(content=job.get("result", {}))


@app.get("/api/v1/report/{job_id}/html")
async def get_report_html(job_id: str, x_api_key: str = Header(None)):
    """Serve the HTML analysis dashboard directly in the browser."""
    _verify_api_key(x_api_key)

    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Job '{job_id}' not found.")
    if job["status"] not in ("completed", "timeout", "error"):
        raise HTTPException(202, f"Job still {job['status']}.")

    html_path = job.get("html_path")
    if html_path and Path(html_path).exists():
        return FileResponse(html_path, media_type="text/html")

    raise HTTPException(404, "HTML report not available for this job.")


# ─── Cleanup / Environment Reset ───────────────────────────────────────────

@app.post("/api/v1/cleanup", response_model=CleanupResponse)
async def cleanup_sandbox(x_api_key: str = Header(None)):
    """
    SOFT RESET — Wipe all analysis artifacts (files only, no VM revert).

    Use this for quick resets between analyses when a full snapshot
    revert is not needed.
    """
    _verify_api_key(x_api_key)
    cleaned = []

    # 1. Wipe uploads
    if UPLOAD_DIR.exists():
        shutil.rmtree(UPLOAD_DIR, ignore_errors=True)
        cleaned.append(str(UPLOAD_DIR))
        log.info(f"[CLEANUP] Wiped: {UPLOAD_DIR}")

    # 2. Wipe reports
    if REPORT_DIR.exists():
        shutil.rmtree(REPORT_DIR, ignore_errors=True)
        cleaned.append(str(REPORT_DIR))
        log.info(f"[CLEANUP] Wiped: {REPORT_DIR}")

    # 3. Wipe URL pipeline screenshots
    screenshots_dir = PROJECT_ROOT / "URLLLL" / "screenshots"
    if screenshots_dir.exists():
        shutil.rmtree(screenshots_dir, ignore_errors=True)
        cleaned.append(str(screenshots_dir))
        log.info(f"[CLEANUP] Wiped: {screenshots_dir}")

    # 4. Wipe VT cache
    vt_cache = PROJECT_ROOT / "URLLLL" / "phishing_pipeline" / "data" / "vt_cache.db"
    if vt_cache.exists():
        vt_cache.unlink()
        cleaned.append(str(vt_cache))
        log.info(f"[CLEANUP] Deleted: {vt_cache}")

    # 5. Clear in-memory job store
    completed_jobs = len(_jobs)
    _jobs.clear()
    log.info(f"[CLEANUP] Cleared {completed_jobs} jobs from memory")

    # 6. Re-create clean directory structure
    _init_runtime_dirs()
    log.info("[CLEANUP] Directory structure re-initialized")

    return CleanupResponse(
        status="clean",
        cleaned_dirs=cleaned,
        message=f"Sandbox reset complete. {completed_jobs} job(s) purged, "
                f"{len(cleaned)} director(ies) wiped.",
    )


# ─── GCP Snapshot Revert (HARD RESET) ──────────────────────────────────────

@app.post("/api/v1/revert")
async def revert_snapshot(x_api_key: str = Header(None)):
    """
    HARD RESET — Revert the Sandbox VM to a clean GCP snapshot.

    ⚠️ WARNING: This will STOP this VM, swap the disk, and restart it.
    The API server will go offline for ~60-120 seconds during the revert.

    This endpoint triggers gcp_revert.py which:
      1. Stops this VM
      2. Detaches the current (dirty) boot disk
      3. Creates a fresh disk from the clean snapshot
      4. Attaches it and starts the VM
      5. The API auto-starts via the scheduled task

    Required .env variables on this server:
      GCP_PROJECT, GCP_ZONE, GCP_INSTANCE_NAME, GCP_SNAPSHOT_NAME

    The Gateway should call this AFTER receiving the analysis report.
    After calling this, poll GET /health until the sandbox comes back.
    """
    _verify_api_key(x_api_key)

    # Validate GCP config before attempting
    gcp_project = os.environ.get("GCP_PROJECT", "")
    gcp_zone = os.environ.get("GCP_ZONE", "")
    gcp_instance = os.environ.get("GCP_INSTANCE_NAME", "")
    gcp_snapshot = os.environ.get("GCP_SNAPSHOT_NAME", "")

    missing = []
    if not gcp_project: missing.append("GCP_PROJECT")
    if not gcp_zone: missing.append("GCP_ZONE")
    if not gcp_instance: missing.append("GCP_INSTANCE_NAME")
    if not gcp_snapshot: missing.append("GCP_SNAPSHOT_NAME")

    if missing:
        raise HTTPException(
            500,
            f"GCP revert not configured. Missing env vars: {', '.join(missing)}. "
            f"Add them to your .env file."
        )

    # First do a soft cleanup
    _jobs.clear()

    # Launch the revert in background — this will kill this server process
    # so we respond first and THEN trigger the revert
    log.info("[REVERT] ⚠️ GCP snapshot revert triggered!")
    log.info(f"[REVERT] Project={gcp_project}, Zone={gcp_zone}, "
             f"VM={gcp_instance}, Snapshot={gcp_snapshot}")
    log.info("[REVERT] Server will go offline in ~5 seconds...")

    asyncio.create_task(_trigger_revert_delayed())

    return JSONResponse(
        status_code=200,
        content={
            "status": "revert_initiated",
            "message": "GCP snapshot revert triggered. This server will go offline "
                       "in ~5 seconds and come back with a clean disk in ~60-120s. "
                       "Poll GET /api/v1/health to detect when it's back.",
            "gcp_project": gcp_project,
            "gcp_zone": gcp_zone,
            "gcp_instance": gcp_instance,
            "gcp_snapshot": gcp_snapshot,
        }
    )


async def _trigger_revert_delayed():
    """
    Wait 5 seconds (so the HTTP response can be sent),
    then trigger the GCP revert which will kill this process.
    """
    await asyncio.sleep(5)
    log.info("[REVERT] Executing gcp_revert.py NOW...")

    try:
        import subprocess
        # Run gcp_revert.py as a detached subprocess
        # This script will stop this VM, so it must be fire-and-forget
        revert_script = str(SCRIPT_DIR / "gcp_revert.py")
        subprocess.Popen(
            [sys.executable, revert_script],
            cwd=str(SCRIPT_DIR),
            # Detach from this process so it survives briefly
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            if sys.platform == "win32" else 0,
        )
    except Exception as e:
        log.error(f"[REVERT] Failed to launch gcp_revert.py: {e}")


# ─── Startup / Shutdown ────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    _init_runtime_dirs()
    log.info("KNOWHOW Sandbox API v2.0 starting...")
    log.info(f"  Project root:   {PROJECT_ROOT}")
    log.info(f"  Upload dir:     {UPLOAD_DIR.resolve()}")
    log.info(f"  Report dir:     {REPORT_DIR.resolve()}")
    log.info(f"  Timeout:        {ANALYSIS_TIMEOUT}s")
    log.info(f"  Max concurrent: {MAX_CONCURRENT}")
    log.info(f"  API Key set:    {'YES' if API_KEY != 'knowhow-default-dev-key-change-me' else 'NO (default dev key)'}")
    log.info(f"  Webhook:        ENABLED")
    log.info(f"  GCP Revert:     {'CONFIGURED' if os.environ.get('GCP_SNAPSHOT_NAME') else 'NOT CONFIGURED'}")


@app.on_event("shutdown")
async def shutdown():
    _executor.shutdown(wait=False)
    log.info("Sandbox API shutting down.")


# ─── CLI Entry Point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=1,
    )
