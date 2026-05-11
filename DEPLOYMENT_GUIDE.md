# KNOWHOW Sandbox — Azure Deployment Guide

> **Target**: Windows Server 2022 on Azure (Students subscription)  
> **Architecture**: Email Gateway → REST API → Sandbox VM → Report → Snapshot Revert

---

## Table of Contents

1. [Workflow Overview](#1-workflow-overview)
2. [Local Machine Setup (Pre-Deployment)](#2-local-machine-setup)
3. [Azure VM Provisioning](#3-azure-vm-provisioning)
4. [Server Initialization (RDP Session)](#4-server-initialization)
5. [ML Model Deployment](#5-ml-model-deployment)
6. [Environment Configuration](#6-environment-configuration)
7. [End-to-End Testing](#7-end-to-end-testing)
8. [Taking the Clean Snapshot](#8-taking-the-clean-snapshot)
9. [Post-Snapshot: Updating Code](#9-post-snapshot-updating-code)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Workflow Overview

```
┌──────────────────────────────────────────────────────────────┐
│  LOCAL MACHINE (Development)                                 │
│  ┌─────────────┐     git push     ┌───────────────────────┐ │
│  │ Edit Code   │ ──────────────── │ Private GitHub Repo   │ │
│  └─────────────┘                  └───────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                                            │
                                       git pull
                                            │
┌──────────────────────────────────────────────────────────────┐
│  AZURE VM (Sandbox Server)                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  C:\Sandbox\                                         │   │
│  │  ├── sandbox\          (File sandbox + API server)   │   │
│  │  ├── URLLLL\           (URL analysis pipeline)       │   │
│  │  └── requirements.txt                                │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ML Models: Downloaded from Google Drive / Azure Blob        │
│  (NOT in Git — too large)                                    │
└──────────────────────────────────────────────────────────────┘
```

**Golden Rule**: All code changes happen **locally**, pushed to GitHub, and pulled on the server. The server is NEVER edited directly (it will be reverted via snapshot after each analysis).

---

## 2. Local Machine Setup

### 2.1 Initialize Git Repository

Open PowerShell in your project folder:

```powershell
cd "C:\Users\hadyh\Desktop\Dynamic Sandbox(Hendy)"

# Initialize git repo
git init

# The .gitignore is already created — verify it
cat .gitignore

# Stage all trackable files
git add .

# Verify what will be committed (should NOT include .pkl, .csv, .venv, etc.)
git status

# Commit
git commit -m "Initial commit: KNOWHOW Sandbox v1.0"
```

### 2.2 Create Private GitHub Repository

1. Go to https://github.com/new
2. **Repository name**: `knowhow-sandbox` (or your preferred name)
3. **Visibility**: ⚠️ **Private** (contains API keys references and security code)
4. **Do NOT** initialize with README (we already have code)
5. Click **Create repository**

### 2.3 Push to GitHub

```powershell
# Add remote (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/knowhow-sandbox.git

# Push
git branch -M main
git push -u origin main
```

### 2.4 Upload ML Models to Google Drive

Upload these files to a Google Drive folder (or Azure Blob Storage):

| File | Size | Path on Server |
|------|------|----------------|
| `xgb_classifier.pkl` | 10.9 MB | `URLLLL\phishing_pipeline\models\` |
| `isolation_forest.pkl` | 1.5 MB | `URLLLL\phishing_pipeline\models\` |
| `final_dataset_with_all_features_v3.1.csv` | 144.4 MB | `URLLLL\Full Dataset\` |
| `hook_monitor.dll` | 0.1 MB | `sandbox\` |

> **Tip**: Create a Google Drive folder named "KNOWHOW-Models" and share it with yourself for easy access via RDP browser.

### 2.5 Verify .gitignore Works

```powershell
# This should show ZERO .pkl, .csv, .h5, .eml files
git status

# If any large files appear, they need to be added to .gitignore
```

---

## 3. Azure VM Provisioning

### 3.1 Create the VM

1. Go to **Azure Portal** → **Virtual Machines** → **Create**
2. **Configuration**:

| Setting | Value |
|---------|-------|
| Subscription | Azure for Students |
| Resource Group | `knowhow-sandbox-rg` (create new) |
| VM Name | `knowhow-sandbox-vm` |
| Region | Choose closest to you |
| Image | **Windows Server 2022 Datacenter** |
| Size | **D4s_v5** (4 vCPU, 16 GB RAM) |
| Admin username | Your choice |
| Admin password | Strong password |
| Public inbound ports | RDP (3389) + Custom (8000 for API) |

3. **Disks**: Premium SSD, 256 GB
4. **Networking**: Create new VNet, allow ports 3389, 8000

### 3.2 Network Security Group (NSG) Rules

After VM creation, go to **Networking** → **Add inbound rule**:

| Priority | Port | Protocol | Source | Name |
|----------|------|----------|--------|------|
| 300 | 3389 | TCP | Your IP only | Allow-RDP |
| 310 | 8000 | TCP | Gateway IP only | Allow-API |
| 400 | * | * | * | Deny-All-Other |

> ⚠️ **Security**: Restrict port 8000 to ONLY the Gateway server's IP address.

---

## 4. Server Initialization (RDP Session)

### 4.1 Connect via RDP

```
mstsc /v:YOUR_VM_PUBLIC_IP
```

### 4.2 Install Git

1. Open browser on the server
2. Download Git from: https://git-scm.com/download/win
3. Install with **default settings**
4. Verify:

```cmd
git --version
```

### 4.3 Install Python 3.12+

1. Download from: https://www.python.org/downloads/
2. ⚠️ **CHECK**: "Add Python to PATH" during installation
3. Verify:

```cmd
python --version
pip --version
```

### 4.4 Clone the Repository

```cmd
cd C:\
git clone https://github.com/YOUR_USERNAME/knowhow-sandbox.git Sandbox
cd C:\Sandbox
```

> **Fallback**: If Git clone fails due to auth issues, you can copy-paste the folder via RDP drag-and-drop.

### 4.5 Install Python Dependencies

```cmd
cd C:\Sandbox
pip install -r requirements.txt
```

Wait for all packages to install. This may take 5-10 minutes.

### 4.6 Install Playwright Browsers

```cmd
playwright install chromium
```

This downloads the Chromium browser binary (~150 MB) for dynamic URL analysis.

---

## 5. ML Model Deployment

### 5.1 Download Models from Google Drive

1. Open browser on the server (inside RDP session)
2. Go to your Google Drive "KNOWHOW-Models" folder
3. Download each file and place in the correct directory:

```
C:\Sandbox\
├── URLLLL\
│   ├── Full Dataset\
│   │   └── final_dataset_with_all_features_v3.1.csv    ← 144 MB
│   └── phishing_pipeline\
│       └── models\
│           ├── xgb_classifier.pkl                       ← 11 MB
│           └── isolation_forest.pkl                     ← 1.5 MB
└── sandbox\
    └── hook_monitor.dll                                 ← 0.1 MB
```

### 5.2 Verify Models Are In Place

```cmd
cd C:\Sandbox
dir URLLLL\phishing_pipeline\models\*.pkl
dir URLLLL\Full Dataset\*.csv
dir sandbox\hook_monitor.dll
```

All three commands should show the files with correct sizes.

---

## 6. Environment Configuration

### 6.1 Set Environment Variables

Open PowerShell **as Administrator** on the server:

```powershell
# ─── API Security ───
[System.Environment]::SetEnvironmentVariable("KNOWHOW_API_KEY", "YOUR-SECRET-API-KEY-HERE", "Machine")

# ─── VirusTotal ───
[System.Environment]::SetEnvironmentVariable("VT_API_KEY", "8a1568ab7ad3337d4ba1b0e3adf4c71313613a7092c28777ac8c2f91b5753a02", "Machine")

# ─── Timeouts ───
[System.Environment]::SetEnvironmentVariable("KNOWHOW_TIMEOUT", "300", "Machine")
[System.Environment]::SetEnvironmentVariable("KNOWHOW_MAX_CONCURRENT", "3", "Machine")
```

> ⚠️ Replace `YOUR-SECRET-API-KEY-HERE` with a real secret key. Generate one with:
> ```powershell
> python -c "import secrets; print(secrets.token_urlsafe(32))"
> ```

### 6.2 Configure Windows Firewall

```powershell
# Allow inbound on port 8000 for the API
New-NetFirewallRule -DisplayName "KNOWHOW API" -Direction Inbound -Port 8000 -Protocol TCP -Action Allow
```

### 6.3 Set Up Auto-Start (Optional)

Create a scheduled task to start the API server on boot:

```powershell
$action = New-ScheduledTaskAction -Execute "python" -Argument "-m uvicorn sandbox.api_server:app --host 0.0.0.0 --port 8000" -WorkingDirectory "C:\Sandbox"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "KNOWHOW-API" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest
```

---

## 7. End-to-End Testing

### 7.1 Start the API Server

```cmd
cd C:\Sandbox
python -m uvicorn sandbox.api_server:app --host 0.0.0.0 --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
[API] KNOWHOW Sandbox API starting...
[API] API Key set:   YES
```

### 7.2 Test Health Endpoint

Open a **new** CMD window:

```cmd
curl http://localhost:8000/api/v1/health
```

Expected: `{"status":"healthy", ...}`

### 7.3 Test URL Analysis

```cmd
curl -X POST http://localhost:8000/api/v1/analyze ^
  -H "X-API-Key: YOUR-SECRET-API-KEY-HERE" ^
  -F "url=https://google.com" ^
  -F "skip_dynamic=true"
```

Expected: `{"job_id":"...","status":"queued","message":"..."}`

Then poll:
```cmd
curl http://localhost:8000/api/v1/status/JOB_ID_HERE -H "X-API-Key: YOUR-SECRET-API-KEY-HERE"
```

### 7.4 Test from Gateway (Remote)

From the Gateway server, test the API using the VM's public IP:

```bash
curl -X POST http://VM_PUBLIC_IP:8000/api/v1/analyze \
  -H "X-API-Key: YOUR-SECRET-API-KEY-HERE" \
  -F "file=@/path/to/suspicious_email.eml"
```

### 7.5 Verify All Subsystems

Run a quick check:

```cmd
cd C:\Sandbox
python -c "from sandbox.master_orchestrator import MasterOrchestrator; print('Orchestrator OK')"
python -c "from URLLLL.phishing_pipeline.pipeline import analyze_url; print('URL Pipeline OK')"
python -c "from URLLLL.phishing_pipeline.vt_cache import get_cache; c=get_cache(); print('VT Cache OK:', c.stats())"
```

---

## 8. Taking the Clean Snapshot

> ⚠️ **CRITICAL**: Only take the snapshot AFTER everything is tested and working perfectly.

### 8.1 Pre-Snapshot Cleanup

On the server:

```cmd
:: Clear temp files
del /Q C:\Sandbox\uploads\* 2>nul
del /Q C:\Sandbox\reports\* 2>nul
del /Q C:\Sandbox\screenshots\* 2>nul

:: Clear VT cache (start fresh)
del /Q C:\Sandbox\URLLLL\phishing_pipeline\data\vt_cache.db 2>nul

:: Stop the API server (Ctrl+C)
```

### 8.2 Deallocate the VM (from Azure Portal)

1. Go to Azure Portal → Virtual Machines → `knowhow-sandbox-vm`
2. Click **Stop** (deallocate)
3. Wait until status shows **Stopped (deallocated)**

### 8.3 Create the Snapshot

1. Go to **Disks** in the left menu of the VM
2. Click on the OS disk name
3. Click **Create Snapshot**
4. **Name**: `knowhow-clean-snapshot`
5. **Snapshot type**: Full
6. Click **Create**

### 8.4 Start the VM Again

1. Go back to the VM page
2. Click **Start**
3. RDP back in and verify the API still starts correctly

### 8.5 Save the Snapshot Name for the Revert Script

On the **Gateway** server, set:

```powershell
$env:AZURE_SNAPSHOT_NAME = "knowhow-clean-snapshot"
$env:AZURE_VM_NAME = "knowhow-sandbox-vm"
$env:AZURE_RESOURCE_GROUP = "knowhow-sandbox-rg"
```

---

## 9. Post-Snapshot: Updating Code

Since the VM gets reverted to the snapshot after each analysis, code updates follow this workflow:

```
LOCAL: Edit code → git commit → git push
                        │
SERVER: git pull → (code updated) → Re-take snapshot (if major changes)
```

### 9.1 Quick Code Update (No New Snapshot)

If the update is minor and you want it to persist until next revert:

```cmd
cd C:\Sandbox
git pull origin main
```

### 9.2 Permanent Code Update (New Snapshot Required)

If the update is important and must survive reverts:

1. RDP into the server
2. `git pull origin main`
3. Test everything works
4. **Deallocate → Delete old snapshot → Create new snapshot** (repeat Section 8)

---

## 10. Troubleshooting

| Problem | Solution |
|---------|----------|
| `pip install` fails on Windows | Use `python -m pip install -r requirements.txt` |
| `playwright install` fails | Run as Administrator, check internet access |
| Git clone auth fails | Use Personal Access Token (PAT) instead of password |
| Port 8000 not reachable | Check NSG rules + Windows Firewall |
| VT API returns 429 | API rate limited — VT cache will prevent this |
| Models missing after revert | Re-download from Google Drive (should be in snapshot) |
| API returns 401 | Check `KNOWHOW_API_KEY` env var matches header |
| Analysis times out (5 min) | Check VT API key is valid, reduce URL count |

---

## Quick Reference Card

```
┌──────────────────────────────────────────────────────┐
│  KNOWHOW Sandbox — Quick Reference                   │
├──────────────────────────────────────────────────────┤
│  Start API:     uvicorn sandbox.api_server:app       │
│                 --host 0.0.0.0 --port 8000           │
│                                                      │
│  Health Check:  GET  /api/v1/health                  │
│  Submit:        POST /api/v1/analyze                 │
│  Poll Status:   GET  /api/v1/status/{job_id}         │
│  Get Report:    GET  /api/v1/report/{job_id}         │
│  Swagger Docs:  GET  /docs                           │
│                                                      │
│  Header:        X-API-Key: YOUR-KEY                  │
│                                                      │
│  Revert VM:     python sandbox/azure_revert.py       │
│  Dry Run:       python sandbox/azure_revert.py       │
│                 --dry-run                             │
└──────────────────────────────────────────────────────┘
```
