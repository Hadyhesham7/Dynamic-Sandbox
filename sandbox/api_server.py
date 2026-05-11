"""
api_server.py — FastAPI REST Gateway for the KNOWHOW Sandbox
=============================================================
Serves as the HTTP bridge between the Email Gateway and the
MasterOrchestrator analysis engine.

Endpoints:
    POST /api/v1/analyze    — Submit .eml, file, or URL for analysis
    GET  /api/v1/status/{id} — Poll job status
    GET  /api/v1/report/{id} — Fetch completed report (JSON or HTML)
    GET  /api/v1/health      — Liveness probe

Environment Variables:
    KNOWHOW_API_KEY     — Required. Secret key the gateway must send
                          in the X-API-Key header.
    KNOWHOW_UPLOAD_DIR  — Temp directory for uploaded files (default: ./uploads)
    KNOWHOW_REPORT_DIR  — Directory for generated reports (default: ./reports)
    KNOWHOW_TIMEOUT     — Max analysis time in seconds (default: 300 = 5 min)

Usage:
    uvicorn sandbox.api_server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
import shutil
import traceback
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

# ─── Configuration ──────────────────────────────────────────────────────────
API_KEY: str = os.environ.get("KNOWHOW_API_KEY", "knowhow-default-dev-key-change-me")
UPLOAD_DIR: Path = Path(os.environ.get("KNOWHOW_UPLOAD_DIR", "./uploads"))
REPORT_DIR: Path = Path(os.environ.get("KNOWHOW_REPORT_DIR", "./reports"))
ANALYSIS_TIMEOUT: int = int(os.environ.get("KNOWHOW_TIMEOUT", "300"))  # 5 min
MAX_CONCURRENT: int = int(os.environ.get("KNOWHOW_MAX_CONCURRENT", "3"))

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# ─── Path setup for orchestrator import ─────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(PROJECT_ROOT / "URLLLL"))

# ─── Job Store (in-memory for single-server; swap to Redis for HA) ──────────
_jobs: dict[str, dict] = {}

# ─── Process pool for CPU-bound analysis ────────────────────────────────────
_executor = ProcessPoolExecutor(max_workers=MAX_CONCURRENT)

# ─── FastAPI App ────────────────────────────────────────────────────────────
app = FastAPI(
    title="KNOWHOW Sandbox API",
    version="1.0.0",
    description="Email Gateway ↔ Dynamic Malware Sandbox REST interface",
    docs_url="/docs",
)


# ─── Auth Dependency ────────────────────────────────────────────────────────

def _verify_api_key(x_api_key: str = Header(None)):
    """
    Reject requests missing or carrying an invalid API key.
    The gateway must send: X-API-Key: <KNOWHOW_API_KEY>
    """
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Set the X-API-Key header.",
        )


# ─── Response Models ───────────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    job_id: str
    status: str  # "queued", "running", "completed", "error", "timeout"
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
    report: dict | None = None


# ─── Worker Function (runs in separate process) ────────────────────────────

def _run_analysis(input_path: str, skip_dynamic: bool = False) -> dict:
    """
    Invoked in a child process via ProcessPoolExecutor.
    Imports the orchestrator here to avoid pickle issues.
    """
    # Re-import inside the child process
    import sys as _sys
    script_dir = str(Path(__file__).parent.resolve())
    project_root = str(Path(__file__).parent.parent.resolve())
    _sys.path.insert(0, script_dir)
    _sys.path.insert(0, str(Path(project_root) / "URLLLL"))

    from master_orchestrator import MasterOrchestrator

    orch = MasterOrchestrator(skip_dynamic=skip_dynamic)
    return orch.analyze(input_path)


# ─── Endpoints ──────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health_check():
    """Liveness probe — returns 200 if the service is running."""
    active_jobs = sum(1 for j in _jobs.values() if j["status"] == "running")
    return {
        "status": "healthy",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "active_jobs": active_jobs,
        "max_concurrent": MAX_CONCURRENT,
    }


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze(
    file: Optional[UploadFile] = File(None),
    url: Optional[str] = Form(None),
    skip_dynamic: bool = Form(False),
    x_api_key: str = Header(None),
):
    """
    Submit an .eml file, binary file, or URL for analysis.

    Accepts multipart/form-data with either:
      - file: An uploaded .eml or binary file
      - url:  A URL string to analyze

    Returns a job_id for polling via /api/v1/status/{job_id}.
    """
    # ── Auth ──
    _verify_api_key(x_api_key)

    # ── Validate input ──
    if not file and not url:
        raise HTTPException(400, "Must provide either 'file' (upload) or 'url' (form field).")

    # ── Rate limit (simple concurrent job cap) ──
    active = sum(1 for j in _jobs.values() if j["status"] == "running")
    if active >= MAX_CONCURRENT:
        raise HTTPException(
            429, f"Server busy — {active}/{MAX_CONCURRENT} slots in use. Retry later."
        )

    # ── Create job ──
    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "status": "queued",
        "input": None,
        "input_type": None,
        "started_at": time.time(),
        "result": None,
        "error": None,
    }
    _jobs[job_id] = job

    # ── Determine input path ──
    if file:
        # Save uploaded file to temp dir
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

    # ── Launch async analysis with timeout ──
    asyncio.create_task(_execute_analysis(job_id, input_path, skip_dynamic))

    return AnalyzeResponse(
        job_id=job_id,
        status="queued",
        message=f"Analysis queued. Poll GET /api/v1/status/{job_id} for results.",
    )


async def _execute_analysis(job_id: str, input_path: str, skip_dynamic: bool):
    """
    Run the orchestrator in a process pool with a strict timeout.
    On timeout, stores a partial error-recovery report.
    """
    job = _jobs[job_id]
    job["status"] = "running"
    loop = asyncio.get_event_loop()

    try:
        # Run CPU-bound analysis in a separate process, with timeout
        result = await asyncio.wait_for(
            loop.run_in_executor(_executor, _run_analysis, input_path, skip_dynamic),
            timeout=ANALYSIS_TIMEOUT,
        )
        job["status"] = "completed"
        job["result"] = result

    except asyncio.TimeoutError:
        # ── Error Recovery: analysis exceeded 5-minute limit ──
        job["status"] = "timeout"
        job["error"] = f"Analysis exceeded {ANALYSIS_TIMEOUT}s timeout limit."
        job["result"] = {
            "input": input_path,
            "input_type": job.get("input_type"),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "error": "TIMEOUT",
            "unified_verdict": {
                "combined_score": -1,
                "level": "ERROR",
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
                "combined_score": -1,
                "level": "ERROR",
                "signals": [f"Analysis failed: {exc}"],
            },
            "partial": True,
        }

    finally:
        job["elapsed_seconds"] = round(time.time() - job["started_at"], 2)


@app.get("/api/v1/status/{job_id}", response_model=JobStatusResponse)
async def get_status(job_id: str, x_api_key: str = Header(None)):
    """Poll job status and retrieve results when complete."""
    _verify_api_key(x_api_key)

    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Job '{job_id}' not found.")

    result = job.get("result") or {}
    verdict = result.get("unified_verdict", {})

    return JobStatusResponse(
        job_id=job_id,
        status=job["status"],
        input=job.get("input"),
        input_type=job.get("input_type") or result.get("input_type"),
        risk_score=verdict.get("combined_score"),
        risk_level=verdict.get("level"),
        is_malware=verdict.get("level") in ("CRITICAL", "HIGH") and "malware" in str(verdict.get("signals", "")),
        is_phishing=verdict.get("level") in ("CRITICAL", "HIGH") and "phishing" in str(verdict.get("signals", "")),
        verdict_summary="; ".join(verdict.get("signals", [])) if verdict.get("signals") else None,
        elapsed_seconds=job.get("elapsed_seconds"),
        error=job.get("error"),
        report=result if job["status"] in ("completed", "timeout", "error") else None,
    )


@app.get("/api/v1/report/{job_id}")
async def get_report(job_id: str, format: str = "json", x_api_key: str = Header(None)):
    """
    Retrieve the full analysis report.
    ?format=json  → JSON report (default)
    ?format=html  → HTML dashboard file
    """
    _verify_api_key(x_api_key)

    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Job '{job_id}' not found.")
    if job["status"] not in ("completed", "timeout", "error"):
        raise HTTPException(202, f"Job still {job['status']}. Poll /status/{job_id}.")

    if format == "html":
        # Look for the HTML report generated by the orchestrator
        html_path = REPORT_DIR / f"unified_report_{job_id}.html"
        if not html_path.exists():
            # Try generating it from the JSON result
            html_path = REPORT_DIR / "unified_report.html"
        if html_path.exists():
            return FileResponse(html_path, media_type="text/html")
        raise HTTPException(404, "HTML report not generated for this job.")

    return JSONResponse(content=job.get("result", {}))


# ─── Startup / Shutdown Events ─────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    print(f"[API] KNOWHOW Sandbox API starting...")
    print(f"[API] Upload dir:    {UPLOAD_DIR.resolve()}")
    print(f"[API] Report dir:    {REPORT_DIR.resolve()}")
    print(f"[API] Timeout:       {ANALYSIS_TIMEOUT}s")
    print(f"[API] Max concurrent: {MAX_CONCURRENT}")
    print(f"[API] API Key set:   {'YES' if API_KEY != 'knowhow-default-dev-key-change-me' else 'NO (using default dev key)'}")


@app.on_event("shutdown")
async def shutdown():
    _executor.shutdown(wait=False)
    print("[API] Sandbox API shutting down.")


# ─── CLI Entry Point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=1,  # Single worker; concurrency via ProcessPoolExecutor
    )
#test changes
