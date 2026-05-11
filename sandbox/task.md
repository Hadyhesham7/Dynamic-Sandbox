# Layer 1 Pipeline — Task Tracker

## Phase 1-4: Core Infrastructure ✅
- [x] Hook DLL with MinHook (100+ APIs across 10 categories)
- [x] Named pipe collector (collector.py)
- [x] DLL injector
- [x] API call sequence extraction

## Phase 5A: File System Monitor ✅
- [x] `filesystem_monitor.py` — snapshot + diff + copy dropped files
- [x] SHA-256 hashing for created/modified files
- [x] Suspicious extension detection
- [x] Artifact copying (dropped files → reports/artifacts/)
- [x] Tested: 3 files detected (exe, dat, dll)

## Phase 5B: Registry Monitor ✅
- [x] `registry_monitor.py` — snapshot + diff persistence keys
- [x] 12 persistence key categories monitored
- [x] **FIX:** Added one-level subkey value reading (BUG-5)
- [x] Now captures: C2Server, BeaconInterval from SandboxTest\Config
- [x] [SET]/[MOD] flags for created vs modified keys
- [x] Tested: Persistence detection working

## Phase 5C: Memory Monitor ✅
- [x] `memory_monitor.py` — RWX + injection + dump analysis
- [x] **FIX:** Correct flProtect/flNewProtect parsing
- [x] **FIX:** MinHook noise filtering — exclude dwSize=5 & t<0.5s (BUG-3)
- [x] MinHook noise flagged in top 10 API display
- [x] Entropy + PE header + string extraction for memory dumps

## Phase 5D: Network Monitor ✅
- [x] `network_monitor.py` — mock mode API hook parsing
- [x] **FIX:** Combined "IP:PORT" parsing from address field
- [x] **FIX:** Added WSASend/WSARecv data transfer tracking (BUG-2)
- [x] **FIX:** Added bind/listen/accept server behavior tracking (BUG-4)
- [x] Suspicious port detection (4444=Metasploit, 8080=C2 HTTP)

## Phase 5E: Report Generator ✅
- [x] `report_generator.py` — merges all raw reports
- [x] HTML dashboard (`html_report.py`)
- [x] Suspicious ports in risk indicators
- [x] RWX count in summary output
- [x] All 5 component sections in final_report.json

## DLL-Level Fixes (Audit) ✅
- [x] **FIX:** Added `socket()` hook — missing entirely (BUG-1)
- [x] **FIX:** Added `gethostbyname()` hook — missing entirely (BUG-1)
- [x] **FIX:** Added `getaddrinfo()` hook — missing entirely (BUG-1)
- [x] DLL recompiled: 14 network hooks (was 11)

## Code Quality Fixes ✅
- [x] **FIX:** Bare except → except Exception in collector.py (BUG-7)

---

## Phase 6: Forensic Enhancements ✅
- [x] API Argument Decoder (`api_decoder.py`) — hex → readable names
- [x] Threat Score (0-100 weighted) — CLI + HTML + JSON
- [x] Execution Timeline — chronological merged event log
- [x] SHA256/MD5 file hashing in reports
- [x] Magic-byte file type detection

## Phase 7: Interactive Attachment Analysis ✅
- [x] Sample Router (`sample_router.py`) — PE/Office/ZIP/OLE detection
- [x] oletools integration — VBA macro extraction + keyword scanning
- [x] OLE embedded object extraction
- [x] ZIP archive extraction (with password cracking)
- [x] Office dynamic analysis — WINWORD.EXE + DLL injection
- [x] Interactive menu in `analyze.py` (test sample vs attachment)
- [x] CLI helper tool (`cli.py`) — nested menus for all operations

## Verification (Checkpoint Items) ✅
- [x] Phase 6 Orchestrator — `analyze.py` IS the orchestrator with interactive menu
- [x] DLL compiled with socket + gethostbyname + getaddrinfo hooks
- [x] Sample Router tested: PE ✅, Office ✅, ZIP ✅
- [x] Macro detection tested: 2 macros found (1 suspicious) with auto_exec triggers
- [x] Word found: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`

---

## ─── NEXT: Phase 8 — Sandbox Depth ───

### 8A: Screenshot Capture (Easy, ~2h) ✅
- [x] Background thread captures desktop every 3s during execution
- [x] Save to `reports/artifacts/screenshots/`
- [x] Include in HTML report

### 8B: Process Tree Tracking (Medium, ~3h) ✅
- [x] Track parent->child PID chains from CreateProcess calls
- [x] Visualize process tree in CLI + HTML report
- [x] Detect multi-stage payload execution
- [x] Detect process hollowing + injection patterns
- [x] Integrated into report_generator.py

### 8C: WriteFile Content Capture (Medium, ~4h) ✅
- [x] Hook `WriteFile` to capture buffer content for small writes (<256 bytes)
- [x] C-level change in `hooks_file.c` (base64 encoder + buffer capture)
- [x] Python analyzer: PE header, script, URL, encoded payload detection
- [x] Show written data in report (scripts, configs, batch files)
- [x] NOTE: DLL rebuild required for buffer capture to activate

---

## Phases 9-13 Status

### Phase 9: VM Snapshot Restore - SKIPPED
- [x] Skipped (sandbox server VM not applicable)

### Phase 10: Email Attachment Extraction (.eml -> router) ✅
- [x] `email_extractor.py` — Full .eml parser
- [x] Extract file attachments (PE/OLE/ZIP detection + SHA256 hashing)
- [x] Extract URLs from body/HTML (including defanged hxxp)
- [x] Email metadata (From, To, Subject, SPF/DKIM/DMARC)
- [x] Phishing indicators (reply-to mismatch, suspicious keywords)
- [x] Routing recommendations (FILE_SANDBOX / URL_PIPELINE)
- [x] Batch mode for processing mailbox directories
- [x] JSON report output

### Phase 11: Anti-evasion (sleep detection, timer fast-forward) ✅
- [x] Sleep/SleepEx capped at 1000ms (was already done)
- [x] NtDelayExecution fast-forward (kernel-level Sleep bypass, cap 1s)
- [x] QueryPerformanceCounter 10x acceleration (timing check evasion)
- [x] WaitForSingleObject/WaitForMultipleObjects cap at 3s
- [x] IsDebuggerPresent/CheckRemoteDebuggerPresent always FALSE
- [x] ExitWindowsEx blocked (prevents shutdown)
- [x] DLL rebuilt with all anti-evasion hooks

### Phase 12: Sandbox -> ML Pipeline integration ✅
- [x] Already built: `verdict_engine.py` feeds API sequences to LSTM
- [x] UNK reliability scoring + corroborated fusion
- [x] Integrated into `analyze.py` orchestration

### Phase 13: End-to-end verdict (email -> sandbox -> ML -> verdict) ✅
- [x] File path: analyze.py -> monitors -> verdict_engine -> final_report
- [x] Email path: email_extractor.py -> routes to FILE_SANDBOX or URL_PIPELINE
- [x] URL path: master_orchestrator.py -> URL pipeline -> verdict

---

## Phase 8D: Hybrid Verdict Engine ✅
- [x] `verdict_engine.py` — Heuristic + LSTM fusion
- [x] Layer 1: Heuristic flag extraction from all 4 monitors
- [x] Layer 2: LSTM BiLSTM model integration (509 API vocab)
- [x] Corroboration-gated fusion logic (5 decision rules)
- [x] UNK reliability tiers (HIGH/MEDIUM/LOW/VERY_LOW)
- [x] API name normalization (suffix/prefix/case matching)
- [x] CLI-formatted verdict printout
- [x] **INTEGRATED** into `analyze.py` (Step 11 — after report generation)
- [x] **INTEGRATED** verdict merged into `final_report.json` as `ai_verdict`
- [x] **INTEGRATED** HTML dashboard verdict banner (between stats and risk indicators)

## Phase 9: Master Orchestrator ✅ (FULLY INTEGRATED)
- [x] `master_orchestrator.py` — Unified File + URL + Email platform
- [x] Global Dispatcher (URL vs File vs Email routing)
- [x] EMAIL input: .eml → email_extractor → route attachments + URLs
- [x] Convergence Point 1: Download Handover (URL→Sandbox via subprocess)
- [x] Convergence Point 2: Overwatch Hooking (browser exploit detection)
- [x] Unified verdict scoring (combined 0-100, email-aware)
- [x] Real sandbox pipeline integration (via subprocess to analyze.py)
- [x] Fixed URLLLL path reference (Dynamic Sandbox folder)
- [x] CLI: `--skip-dynamic`, `--overwatch`, `--timeout`, `--mode`

## URL HTML Dashboard ✅
- [x] `URLLLL/url_html_report.py` — Self-contained HTML dashboard
- [x] Dark theme matching sandbox dashboard
- [x] All 13 pipeline stages rendered (reputation, domain, static, redirect, dynamic, ML, anomaly)
- [x] Risk signals breakdown with points
- [x] Screenshot embed (base64 inline)
- [x] Email metadata banner (when routed from .eml)
- [x] Auto-opens in browser after analysis
- [x] Integrated into `dashboard.py` run_analysis()
- [x] Integrated into master_orchestrator.py URL pipeline

