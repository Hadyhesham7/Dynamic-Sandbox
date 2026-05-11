# Development Environment Setup Guide

## Overview

This guide covers everything you need to install and configure before
writing any code. Follow each section in order.

---

## 1. Development Machine Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Windows 10 (64-bit) | Windows 10/11 (64-bit) |
| RAM | 8 GB | 16 GB (for VM + IDE) |
| Disk | 20 GB free | 50 GB free |
| CPU | Any x64 | 4+ cores (for VM) |

---

## 2. Required Software

### A. Visual Studio 2022 Community (FREE) — C/C++ Compiler

**Why:** Compiles the hook DLL. Community Edition is free for students.

**Download:** https://visualstudio.microsoft.com/vs/community/

**During installation, select these workloads:**
- [x] "Desktop development with C++"

**Within that workload, ensure these are checked:**
- [x] MSVC v143 - VS 2022 C++ x64/x86 build tools
- [x] Windows 10/11 SDK (any recent version)
- [x] C++ CMake tools for Windows

> After installation, you will have:
> - `cl.exe` (C/C++ compiler)
> - `cmake.exe` (build system)
> - Windows SDK headers (windows.h, winternl.h, etc.)
> - Developer Command Prompt (where you'll compile)

### B. CMake (usually included with Visual Studio)

**Why:** Build system for the DLL project.

**Verify:** Open "Developer Command Prompt for VS 2022" and run:
```
cmake --version
```
Should show 3.20+. If not installed separately: https://cmake.org/download/

### C. Python 3.10+ (you already have this)

**Why:** Injector, collector, orchestrator, report generator.

**Required packages:**
```
pip install psutil pywin32
```
- `psutil` — process enumeration and monitoring
- `pywin32` — Windows API access from Python (named pipes, etc.)

### D. Git (optional but recommended)

**Why:** To clone MinHook and version control your project.

**Download:** https://git-scm.com/download/win

---

## 3. Required Libraries

### MinHook v1.3.4 (API Hooking Engine)

**What it does:** Handles the low-level complexity of inline API hooking
(instruction disassembly, trampoline creation, thread safety).

**How to get it:**

Option A — Git clone (recommended):
```
cd sandbox\hook_dll\lib
git clone https://github.com/TsudaKageyu/minhook.git
```

Option B — Manual download:
1. Go to https://github.com/TsudaKageyu/minhook
2. Click "Code" → "Download ZIP"
3. Extract into `sandbox\hook_dll\lib\minhook\`

**After this, you should have:**
```
sandbox/hook_dll/lib/minhook/
├── include/
│   └── MinHook.h          ← The header you'll #include
├── src/
│   ├── buffer.c
│   ├── hook.c
│   ├── trampoline.c
│   └── hde/               ← Disassembler engine
│       ├── hde32.c
│       └── hde64.c
├── CMakeLists.txt
└── LICENSE.txt
```

---

## 4. Testing Environment

### VirtualBox + Windows VM (for running malware safely)

> [!WARNING]
> NEVER run malware on your development machine.
> Always use an isolated VM with snapshots.

**VirtualBox:** https://www.virtualbox.org/wiki/Downloads (free)

**Windows VM Setup:**
1. Install VirtualBox
2. Create a new VM: Windows 10 (32-bit or 64-bit)
3. Install Windows 10 in the VM
4. Install Python 3.10+ inside the VM
5. Copy your compiled `hook_monitor.dll` into the VM
6. Take a CLEAN SNAPSHOT (before running any malware)
7. After each analysis: restore to the clean snapshot

**VM Settings for Safety:**
- Network: "Internal Network" or "Not attached" (no internet)
- Shared Folders: Read-only from host, to transfer files in
- Disable clipboard sharing
- Disable drag-and-drop

---

## 5. Debugging Tools (Install on Development Machine)

| Tool | Purpose | Download |
|------|---------|----------|
| **x64dbg / x32dbg** | Debug the hook DLL at assembly level | https://x64dbg.com/ |
| **Process Monitor** | See real-time file/registry/process activity | https://learn.microsoft.com/en-us/sysinternals/downloads/procmon |
| **Process Explorer** | See loaded DLLs, process tree | https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer |
| **API Monitor** | Verify your hooks match real API calls | http://www.rohitab.com/apimonitor |
| **DebugView** | See OutputDebugString messages from DLL | https://learn.microsoft.com/en-us/sysinternals/downloads/debugview |

> x64dbg is optional for now but will be critical when debugging hook issues.
> Process Monitor and API Monitor are essential for verifying your hooks
> capture the same data as professional tools.

---

## 6. How to Build (After Setup)

Open "Developer Command Prompt for VS 2022" (NOT regular cmd/PowerShell):

```bash
cd C:\Users\hadyh\Desktop\Api_Call_Kaggle\sandbox\hook_dll

# Configure for 32-bit build
cmake -S . -B build -A Win32

# Compile
cmake --build build --config Release
```

Output will be in: `sandbox\hook_dll\build\Release\hook_monitor.dll`

---

## 7. Project File Map

After setup is complete, your workspace will look like:

```
Api_Call_Kaggle/
├── old/                            ← Previous project (ML pipeline, datasets)
│   ├── malware_pipeline.py
│   ├── api_list.txt
│   ├── config.json
│   └── ...
│
├── sandbox/                        ← NEW: API Hooking System
│   ├── hook_dll/                   ← C code (compiled to DLL)
│   │   ├── CMakeLists.txt
│   │   ├── src/
│   │   │   ├── dllmain.c          ← Entry point
│   │   │   ├── hook_engine.c/h    ← MinHook wrapper
│   │   │   ├── logger.c/h         ← Named pipe IPC
│   │   │   └── hooks/             ← Hook handlers (8 files)
│   │   ├── lib/minhook/           ← MinHook library
│   │   └── build/                 ← Compiled DLL output
│   │
│   ├── injector/                   ← Python DLL injector
│   ├── collector/                  ← Python log collector
│   ├── orchestrator/               ← Python end-to-end control
│   ├── config/                     ← Settings + API list
│   ├── reports/                    ← JSON output
│   └── tests/                      ← Test scripts
│
└── docs/                           ← Documentation
    └── setup_guide.md              ← This file
```

---

## 8. Verification Checklist

Run these checks to confirm everything is ready:

- [ ] Visual Studio 2022 installed with C++ workload
- [ ] `cmake --version` works in Developer Command Prompt (3.20+)
- [ ] Python 3.10+ installed (`python --version`)
- [ ] `pip install psutil pywin32` completed
- [ ] MinHook source is in `sandbox/hook_dll/lib/minhook/`
- [ ] MinHook has `include/MinHook.h` file
- [ ] VirtualBox installed with a Windows VM
- [ ] Clean VM snapshot taken

Once all items are checked, you're ready for Module 1: CMakeLists.txt + DLL skeleton.
