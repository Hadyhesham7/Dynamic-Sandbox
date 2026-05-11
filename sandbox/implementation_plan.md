# MasterOrchestrator — Unified Platform Integration Plan

> **Objective:** Merge the File Sandbox (Subsystem A) and URL Pipeline (Subsystem B) into a single entry point with cross-subsystem handover logic.

---

## Architecture Diagram

```
                    ┌──────────────────────────────┐
                    │     MasterOrchestrator        │
                    │     analyze_sample(input)      │
                    └──────────────┬───────────────┘
                                   │
                        ┌──────────┴──────────┐
                        ▼                     ▼
                   IS A FILE?             IS A URL?
                        │                     │
                        ▼                     ▼
               ┌────────────────┐    ┌────────────────────┐
               │  Subsystem A   │    │   Subsystem B      │
               │  File Sandbox  │    │   URL Pipeline     │
               │                │    │                    │
               │ • SampleRouter │    │ • 13-Stage Chain   │
               │ • DLL Inject   │    │ • Playwright       │
               │ • API Hooks    │    │ • XGBoost ML       │
               │ • Monitors×5   │    │ • Risk Scorer      │
               │ • LSTM Model   │    │                    │
               └────────────────┘    └───────┬────────────┘
                        ▲                     │
                        │          ┌──────────┴──────────┐
                        │          ▼                     ▼
                        │   Download Handover      Overwatch Hook
                        │   (Convergence 1)       (Convergence 2)
                        │          │                     │
                        │          │  "URL dropped a     │  "Hook chrome.exe
                        │          │   .exe payload"     │   for zero-day
                        │          │                     │   exploit detection"
                        └──────────┴─────────────────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │   Unified Report     │
                        │   (JSON + HTML)      │
                        │                      │
                        │ • Web Threats        │
                        │ • OS Threats         │
                        │ • Combined Verdict   │
                        └──────────────────────┘
```

---

## Skeleton Code

See [master_orchestrator.py](file:///C:/Users/hadyh/Desktop/Dynamic%20Sandbox%28Hendy%29/sandbox/master_orchestrator.py) for the full skeleton.

---

## Integration Points Summary

### 1. Global Dispatcher (Router)
- Detects input type: URL (starts with `http://`, `https://`, or contains `.` + TLD pattern) vs File (local path that exists on disk).
- Routes to the appropriate subsystem.

### 2. Convergence Point 1 — Download Handover
- After URL Pipeline's dynamic analysis completes, check if `file_download_detected == 1` and `dl_is_executable == 1`.
- If yes: the downloaded payload (already saved by `download_analyzer.py`) is handed to Subsystem A's full pipeline.
- The file sandbox results are merged into the final report under `"file_sandbox_handover"`.

### 3. Convergence Point 2 — Overwatch Hooking
- **Optional** (enabled via `--overwatch` flag).
- While Playwright's Chromium is running, locate the `chrome.exe` PID and inject `hook_monitor.dll` into it.
- The API collector captures any abnormal behavior (RWX allocations, shellcode injection) that would indicate a browser exploit.
- Results merged under `"overwatch"` in the final report.

### 4. Unified Report
- Single JSON + HTML report aggregating:
  - Web threat signals (redirects, DOM, reputation, ML verdict)
  - OS threat signals (API calls, registry, memory, files)
  - Combined threat score

> [!IMPORTANT]
> **Overwatch Hooking is experimental.** Hooking Chromium's own process will generate significant noise from legitimate browser internals. We will need a dedicated noise filter for browser-specific API patterns (similar to the MinHook filter we already have).

> [!WARNING]  
> **Download Handover requires Admin privileges.** If the URL pipeline detects a dropped executable, the user will be prompted to elevate if not already running as admin, since DLL injection requires it.
