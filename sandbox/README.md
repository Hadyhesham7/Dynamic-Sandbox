# KNOWHOW Malware Sandbox — API Hooking Engine

A lightweight dynamic malware analysis system that captures API call sequences
during execution for ML-based malware detection.

## Architecture

```
sandbox/
├── hook_dll/               # C DLL — injected into target process
│   ├── src/
│   │   ├── dllmain.c       # DLL entry point
│   │   ├── hook_engine.c   # MinHook wrapper + hook registration
│   │   ├── hook_engine.h
│   │   ├── logger.c        # Thread-safe named pipe logger
│   │   ├── logger.h
│   │   └── hooks/          # Hook handlers by category
│   │       ├── hooks_file.c
│   │       ├── hooks_registry.c
│   │       ├── hooks_process.c
│   │       ├── hooks_network.c
│   │       ├── hooks_memory.c
│   │       ├── hooks_dll.c
│   │       ├── hooks_crypto.c
│   │       └── hooks_system.c
│   ├── lib/minhook/        # MinHook library (submodule)
│   ├── build/              # Compiled output
│   └── CMakeLists.txt      # Build configuration
│
├── injector/               # Python — injects DLL into target
│   └── injector.py
│
├── collector/              # Python — receives logs, builds report
│   ├── collector.py
│   └── report_generator.py
│
├── orchestrator/           # Python — end-to-end control
│   └── orchestrator.py
│
├── config/                 # Configuration files
│   ├── settings.json
│   └── api_list.txt
│
├── reports/                # Output reports (JSON)
├── tests/                  # Test scripts
└── README.md
```

## Data Flow

```
1. orchestrator.py starts collector.py (named pipe server)
2. orchestrator.py launches target.exe
3. injector.py injects hook_monitor.dll into target.exe
4. hook_monitor.dll hooks 89 APIs via MinHook
5. Every API call → logged as JSON via named pipe → collector.py
6. After timeout → collector.py writes report.json
7. report.json → ready for ML pipeline (LSTM model)
```

## Requirements

See docs/setup_guide.md for full setup instructions.

## Quick Start

```bash
# 1. Build the DLL (from sandbox/hook_dll/)
cmake -S . -B build -A Win32
cmake --build build --config Release

# 2. Run analysis
python sandbox/orchestrator/orchestrator.py --target malware.exe --timeout 120
```

## Status

- [ ] Module 1: Project setup + MinHook integration
- [ ] Module 2: Logger (named pipe IPC)
- [ ] Module 3: Hook engine (registration framework)
- [ ] Module 4: Hook handlers (89 APIs)
- [ ] Module 5: Python injector
- [ ] Module 6: Python collector
- [ ] Module 7: Report generator
- [ ] Module 8: Orchestrator
