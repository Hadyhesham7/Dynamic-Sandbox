"""
injector.py — DLL Injector
============================
Injects hook_monitor.dll into a target process using the
classic CreateRemoteThread + LoadLibrary technique.

Usage:
    python injector.py --pid 1234                        # Inject into running process
    python injector.py --exe notepad.exe                 # Launch and inject
    python injector.py --exe malware.exe --suspended     # Launch suspended, inject, resume

The collector (collector.py) must be running FIRST.
"""

import ctypes
import ctypes.wintypes
import os
import sys
import time
import argparse
import subprocess

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF
CREATE_SUSPENDED = 0x00000004

# Windows API functions
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = ctypes.wintypes.HANDLE
OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.restype = ctypes.wintypes.LPVOID
VirtualAllocEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID,
                           ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.restype = ctypes.wintypes.BOOL
WriteProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID,
                               ctypes.wintypes.LPCVOID, ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_size_t)]

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.restype = ctypes.wintypes.HANDLE
CreateRemoteThread.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p,
                               ctypes.c_size_t, ctypes.wintypes.LPVOID,
                               ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD,
                               ctypes.POINTER(ctypes.wintypes.DWORD)]

GetModuleHandleA = kernel32.GetModuleHandleA
GetModuleHandleA.restype = ctypes.wintypes.HMODULE
GetModuleHandleA.argtypes = [ctypes.wintypes.LPCSTR]

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = ctypes.wintypes.LPVOID
GetProcAddress.argtypes = [ctypes.wintypes.HMODULE, ctypes.wintypes.LPCSTR]

WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.restype = ctypes.wintypes.DWORD
WaitForSingleObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = ctypes.wintypes.BOOL
CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.restype = ctypes.wintypes.BOOL
VirtualFreeEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID,
                          ctypes.c_size_t, ctypes.wintypes.DWORD]

ResumeThread = kernel32.ResumeThread
ResumeThread.restype = ctypes.wintypes.DWORD
ResumeThread.argtypes = [ctypes.wintypes.HANDLE]


def get_dll_path():
    """Get the absolute path to hook_monitor.dll (auto-detect architecture)."""
    import struct
    is_64bit = struct.calcsize("P") * 8 == 64

    script_dir = os.path.dirname(os.path.abspath(__file__))
    base = os.path.join(script_dir, "..", "hook_dll")

    # Try architecture-matching build first
    search_order = []
    if is_64bit:
        search_order.append(os.path.join(base, "build64", "Release", "hook_monitor.dll"))
        search_order.append(os.path.join(base, "build64", "Debug", "hook_monitor.dll"))
    search_order.append(os.path.join(base, "build", "Release", "hook_monitor.dll"))
    search_order.append(os.path.join(base, "build", "Debug", "hook_monitor.dll"))

    for path in search_order:
        norm = os.path.normpath(path)
        if os.path.exists(norm):
            arch = "64-bit" if "build64" in path else "32-bit"
            print(f"[INJECTOR] Found {arch} DLL: {norm}")
            return norm

    print(f"[INJECTOR] ERROR: hook_monitor.dll not found!")
    print(f"[INJECTOR]        Build it: cmake -S . -B build64 -A x64 && cmake --build build64 --config Release")
    return None


def inject_dll(pid, dll_path):
    """
    Inject a DLL into a target process using CreateRemoteThread + LoadLibraryA.

    Steps:
    1. Open the target process
    2. Allocate memory in the target for the DLL path string
    3. Write the DLL path into the allocated memory
    4. Get the address of LoadLibraryA in kernel32.dll
    5. Create a remote thread that calls LoadLibraryA(dll_path)
    6. Wait for the thread to complete (DLL is now loaded)
    """
    print(f"[INJECTOR] Target PID: {pid}")
    print(f"[INJECTOR] DLL path:   {dll_path}")

    # Step 1: Open target process
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        error = ctypes.get_last_error()
        print(f"[INJECTOR] ERROR: Cannot open process {pid} (error {error})")
        print(f"[INJECTOR]        Try running as Administrator")
        return False

    print(f"[INJECTOR] Process opened (handle: 0x{process_handle:X})")

    try:
        # Step 2: Allocate memory in target for the DLL path
        dll_path_bytes = dll_path.encode("ascii") + b"\x00"
        alloc_size = len(dll_path_bytes)

        remote_memory = VirtualAllocEx(
            process_handle, None, alloc_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )

        if not remote_memory:
            error = ctypes.get_last_error()
            print(f"[INJECTOR] ERROR: VirtualAllocEx failed (error {error})")
            return False

        print(f"[INJECTOR] Allocated {alloc_size} bytes at 0x{remote_memory:X}")

        # Step 3: Write DLL path into allocated memory
        bytes_written = ctypes.c_size_t(0)
        success = WriteProcessMemory(
            process_handle, remote_memory,
            dll_path_bytes, alloc_size,
            ctypes.byref(bytes_written)
        )

        if not success:
            error = ctypes.get_last_error()
            print(f"[INJECTOR] ERROR: WriteProcessMemory failed (error {error})")
            return False

        print(f"[INJECTOR] Wrote DLL path ({bytes_written.value} bytes)")

        # Step 4: Get address of LoadLibraryA
        h_kernel32 = GetModuleHandleA(b"kernel32.dll")
        load_library_addr = GetProcAddress(h_kernel32, b"LoadLibraryA")

        if not load_library_addr:
            print("[INJECTOR] ERROR: Cannot find LoadLibraryA")
            return False

        print(f"[INJECTOR] LoadLibraryA at 0x{load_library_addr:X}")

        # Step 5: Create remote thread calling LoadLibraryA(dll_path)
        thread_id = ctypes.wintypes.DWORD(0)
        thread_handle = CreateRemoteThread(
            process_handle, None, 0,
            load_library_addr, remote_memory,
            0, ctypes.byref(thread_id)
        )

        if not thread_handle:
            error = ctypes.get_last_error()
            print(f"[INJECTOR] ERROR: CreateRemoteThread failed (error {error})")
            print(f"[INJECTOR]        This may be blocked by antivirus")
            return False

        print(f"[INJECTOR] Remote thread created (TID: {thread_id.value})")

        # Step 6: Wait for LoadLibrary to complete
        print("[INJECTOR] Waiting for DLL to load...")
        WaitForSingleObject(thread_handle, 5000)  # 5 second timeout

        print("[INJECTOR] DLL injected successfully!")
        print("[INJECTOR] Hooks are now active. Check the collector for output.")

        # Cleanup
        CloseHandle(thread_handle)
        VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)  # MEM_RELEASE

        return True

    finally:
        CloseHandle(process_handle)


def launch_and_inject(exe_path, dll_path, suspended=False):
    """Launch an executable and inject the DLL into it."""
    print(f"[INJECTOR] Launching: {exe_path}")

    if suspended:
        # Launch suspended so we can inject before any code runs
        si = subprocess.STARTUPINFO()
        pi = subprocess.STARTUPINFO()

        creation_flags = CREATE_SUSPENDED

        # Use ctypes for CreateProcess to get the thread handle
        class STARTUPINFO(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.wintypes.DWORD),
                ("lpReserved", ctypes.wintypes.LPWSTR),
                ("lpDesktop", ctypes.wintypes.LPWSTR),
                ("lpTitle", ctypes.wintypes.LPWSTR),
                ("dwX", ctypes.wintypes.DWORD),
                ("dwY", ctypes.wintypes.DWORD),
                ("dwXSize", ctypes.wintypes.DWORD),
                ("dwYSize", ctypes.wintypes.DWORD),
                ("dwXCountChars", ctypes.wintypes.DWORD),
                ("dwYCountChars", ctypes.wintypes.DWORD),
                ("dwFillAttribute", ctypes.wintypes.DWORD),
                ("dwFlags", ctypes.wintypes.DWORD),
                ("wShowWindow", ctypes.wintypes.WORD),
                ("cbReserved2", ctypes.wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", ctypes.wintypes.HANDLE),
                ("hStdOutput", ctypes.wintypes.HANDLE),
                ("hStdError", ctypes.wintypes.HANDLE),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", ctypes.wintypes.HANDLE),
                ("hThread", ctypes.wintypes.HANDLE),
                ("dwProcessId", ctypes.wintypes.DWORD),
                ("dwThreadId", ctypes.wintypes.DWORD),
            ]

        startup_info = STARTUPINFO()
        startup_info.cb = ctypes.sizeof(STARTUPINFO)
        process_info = PROCESS_INFORMATION()

        success = kernel32.CreateProcessW(
            exe_path,           # Application name
            None,               # Command line
            None, None,         # Process/Thread security
            False,              # Inherit handles
            CREATE_SUSPENDED,   # Creation flags
            None, None,         # Environment, directory
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
        )

        if not success:
            error = ctypes.get_last_error()
            print(f"[INJECTOR] ERROR: CreateProcess failed (error {error})")
            return False

        pid = process_info.dwProcessId
        print(f"[INJECTOR] Process created (PID: {pid}) in SUSPENDED state")

        # Inject the DLL
        result = inject_dll(pid, dll_path)

        if result:
            # Resume the main thread
            print("[INJECTOR] Resuming target process...")
            ResumeThread(process_info.hThread)
            print("[INJECTOR] Process resumed — monitoring active")

        CloseHandle(process_info.hThread)
        CloseHandle(process_info.hProcess)

        return result
    else:
        # Launch normally, then inject
        proc = subprocess.Popen(exe_path)
        pid = proc.pid
        print(f"[INJECTOR] Process started (PID: {pid})")

        # Small delay to let the process initialize
        time.sleep(0.5)

        return inject_dll(pid, dll_path)


def main():
    parser = argparse.ArgumentParser(description="Sandbox DLL Injector")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pid", type=int, help="PID of running process to inject into")
    group.add_argument("--exe", type=str, help="Path to executable to launch and inject")
    parser.add_argument("--dll", type=str, default=None,
                        help="Path to DLL (default: auto-detect hook_monitor.dll)")
    parser.add_argument("--suspended", action="store_true",
                        help="Launch in suspended state (inject before any code runs)")

    args = parser.parse_args()

    # Find the DLL
    dll_path = args.dll or get_dll_path()
    if not dll_path:
        sys.exit(1)

    print(f"[INJECTOR] DLL: {dll_path}")
    print(f"[INJECTOR] DLL exists: {os.path.exists(dll_path)}")
    print(f"[INJECTOR] DLL size: {os.path.getsize(dll_path):,} bytes")
    print()

    if args.pid:
        success = inject_dll(args.pid, dll_path)
    else:
        exe_path = os.path.abspath(args.exe)
        if not os.path.exists(exe_path):
            print(f"[INJECTOR] ERROR: File not found: {exe_path}")
            sys.exit(1)
        success = launch_and_inject(exe_path, dll_path, args.suspended)

    if success:
        print("\n[INJECTOR] Injection complete.")
        print("[INJECTOR] Check the collector window for API call output.")
    else:
        print("\n[INJECTOR] Injection FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
