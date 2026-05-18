/*
 * dllmain.c — DLL Entry Point
 * ============================
 * This is the first code that runs when the DLL is injected
 * into the target process. It initializes the logger, registers
 * all hooks, and installs them.
 *
 * Flow:
 *   DLL_PROCESS_ATTACH:
 *     1. Initialize logger (connect to named pipe)
 *     2. Register all hook handlers (from each category file)
 *     3. Install all hooks via MinHook
 *
 *   DLL_PROCESS_DETACH:
 *     1. Remove all hooks
 *     2. Shutdown logger
 */

#include <windows.h>
#include <stdio.h>
#include "hook_engine.h"
#include "logger.h"

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD   ul_reason_for_call,
    LPVOID  lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        /* Disable thread attach/detach notifications for performance */
        DisableThreadLibraryCalls(hModule);

        /* Step 1: Initialize the logging system */
        BOOL pipe_connected = logger_init();

        char msg[128];
        _snprintf(msg, sizeof(msg),
            "[SANDBOX] DLL loaded into PID %lu. Pipe: %s\n",
            GetCurrentProcessId(),
            pipe_connected ? "CONNECTED" : "FALLBACK (DebugOutput)");
        OutputDebugStringA(msg);

        /* Step 2: Register all hook handlers */
        register_file_hooks();
        register_registry_hooks();
        register_process_hooks();
        register_network_hooks();
        register_memory_hooks();
        register_dll_hooks();
        register_crypto_hooks();
        register_system_hooks();
        register_services_hooks();
        register_sync_hooks();

        /* Step 3: Install all registered hooks */
        int count = hook_engine_install_all();

        _snprintf(msg, sizeof(msg),
            "[SANDBOX] %d hooks active. Monitoring started.\n", count);
        OutputDebugStringA(msg);

        /*
         * SELF-TEST: Call hooked APIs from within the DLL to verify
         * they actually intercept. If these appear in the report,
         * hooks work. If not, something is fundamentally broken.
         */
        {
            char diag[256];

            /* Test 1: CreateFileW on NUL device */
            HANDLE hTest = CreateFileW(L"NUL", GENERIC_READ, 0, NULL,
                                       OPEN_EXISTING, 0, NULL);
            _snprintf(diag, sizeof(diag),
                "\"test\":\"CreateFileW_NUL\",\"result\":\"%s\"",
                hTest != INVALID_HANDLE_VALUE ? "OK" : "FAIL");
            logger_log_call("__selftest__", "DIAG", diag, "");
            if (hTest != INVALID_HANDLE_VALUE) CloseHandle(hTest);

            /* Test 2: VirtualAlloc + VirtualFree */
            LPVOID pTest = VirtualAlloc(NULL, 4096, 0x1000, 0x04);
            _snprintf(diag, sizeof(diag),
                "\"test\":\"VirtualAlloc_4KB\",\"result\":\"%s\",\"addr\":\"0x%p\"",
                pTest ? "OK" : "FAIL", pTest);
            logger_log_call("__selftest__", "DIAG", diag, "");
            if (pTest) VirtualFree(pTest, 0, 0x8000);

            /* Test 3: Log the actual hooked addresses for debugging */
            HMODULE hK32 = GetModuleHandleW(L"kernel32");
            HMODULE hKB  = GetModuleHandleW(L"kernelbase");
            void* pCFW_k32 = (void*)GetProcAddress(hK32, "CreateFileW");
            void* pCFW_kb  = hKB ? (void*)GetProcAddress(hKB, "CreateFileW") : NULL;
            void* pVA_k32  = (void*)GetProcAddress(hK32, "VirtualAlloc");
            void* pVA_kb   = hKB ? (void*)GetProcAddress(hKB, "VirtualAlloc") : NULL;
            _snprintf(diag, sizeof(diag),
                "\"CreateFileW_k32\":\"0x%p\",\"CreateFileW_kb\":\"0x%p\","
                "\"VirtualAlloc_k32\":\"0x%p\",\"VirtualAlloc_kb\":\"0x%p\"",
                pCFW_k32, pCFW_kb, pVA_k32, pVA_kb);
            logger_log_call("__selftest_addrs__", "DIAG", diag, "");
        }

        break;
    }

    case DLL_PROCESS_DETACH:
    {
        OutputDebugStringA("[SANDBOX] DLL unloading. Removing hooks...\n");

        /* Step 1: Remove all hooks */
        hook_engine_remove_all();

        /* Step 2: Shutdown logger */
        logger_shutdown();

        OutputDebugStringA("[SANDBOX] Shutdown complete.\n");
        break;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        /* Disabled via DisableThreadLibraryCalls */
        break;
    }

    return TRUE;
}
