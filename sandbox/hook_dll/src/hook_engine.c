/*
 * hook_engine.c — Hook Registration Framework
 * =============================================
 * Manages a table of hooks, installs them all via MinHook,
 * and provides clean removal on shutdown.
 */

#include "hook_engine.h"
#include "logger.h"
#include <stdio.h>

/* --- Global Hook Table --- */
static HookEntry g_hooks[MAX_HOOKS];
static int       g_hook_count = 0;

/* ============================================================
 * Registration
 * ============================================================ */

BOOL hook_engine_register(
    const wchar_t* module_name,
    const char*    api_name,
    void*          detour_func,
    void**         original_func)
{
    if (g_hook_count >= MAX_HOOKS) {
        OutputDebugStringA("[SANDBOX] ERROR: Hook table full!\n");
        return FALSE;
    }

    HookEntry* entry = &g_hooks[g_hook_count];
    entry->module_name  = module_name;
    entry->api_name     = api_name;
    entry->detour_func  = detour_func;
    entry->original_func = original_func;
    entry->installed    = FALSE;

    g_hook_count++;
    return TRUE;
}

/* ============================================================
 * Installation
 * ============================================================ */

int hook_engine_install_all(void)
{
    char msg[256];
    int  installed_count = 0;

    /* Initialize MinHook */
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        _snprintf(msg, sizeof(msg),
            "[SANDBOX] ERROR: MH_Initialize failed: %s\n",
            MH_StatusToString(status));
        OutputDebugStringA(msg);
        return 0;
    }

    _snprintf(msg, sizeof(msg),
        "[SANDBOX] Installing %d hooks...\n", g_hook_count);
    OutputDebugStringA(msg);

    /* Create all hooks */
    for (int i = 0; i < g_hook_count; i++) {
        HookEntry* entry = &g_hooks[i];

        /*
         * CRITICAL FIX: Force-load the target DLL if not already present.
         * MH_CreateHookApi internally uses GetModuleHandleW which returns
         * NULL for DLLs not yet loaded (e.g. ws2_32.dll before Python's
         * socket module initializes). LoadLibraryW ensures the DLL is
         * mapped into the process so MinHook can patch its functions.
         */
        HMODULE hTarget = GetModuleHandleW(entry->module_name);
        if (!hTarget) {
            hTarget = LoadLibraryW(entry->module_name);
            if (hTarget) {
                _snprintf(msg, sizeof(msg),
                    "[SANDBOX] Force-loaded %ls for hooking\n",
                    entry->module_name);
                OutputDebugStringA(msg);
            } else {
                _snprintf(msg, sizeof(msg),
                    "[SANDBOX] WARNING: Cannot load %ls — skipping %s\n",
                    entry->module_name, entry->api_name);
                OutputDebugStringA(msg);
                continue;
            }
        }

        status = MH_CreateHookApi(
            entry->module_name,     /* e.g., L"kernel32" */
            entry->api_name,        /* e.g., "CreateFileW" */
            entry->detour_func,     /* Our Hook_CreateFileW */
            entry->original_func    /* &pOriginal_CreateFileW */
        );

        if (status == MH_OK) {
            entry->installed = TRUE;
            installed_count++;
        } else {
            _snprintf(msg, sizeof(msg),
                "[SANDBOX] WARNING: Failed to hook %s: %s\n",
                entry->api_name, MH_StatusToString(status));
            OutputDebugStringA(msg);
        }
    }

    /* Enable all hooks at once (atomic operation) */
    status = MH_EnableHook(MH_ALL_HOOKS);
    if (status != MH_OK) {
        _snprintf(msg, sizeof(msg),
            "[SANDBOX] ERROR: MH_EnableHook(ALL) failed: %s\n",
            MH_StatusToString(status));
        OutputDebugStringA(msg);
    }

    _snprintf(msg, sizeof(msg),
        "[SANDBOX] Successfully installed %d / %d hooks.\n",
        installed_count, g_hook_count);
    OutputDebugStringA(msg);

    return installed_count;
}

/* ============================================================
 * Removal
 * ============================================================ */

void hook_engine_remove_all(void)
{
    /* Disable all hooks */
    MH_DisableHook(MH_ALL_HOOKS);

    /* Remove each hook */
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].installed) {
            /* We need the target address to remove — get it from module */
            HMODULE hMod = GetModuleHandleW(g_hooks[i].module_name);
            if (hMod) {
                void* target = (void*)GetProcAddress(hMod, g_hooks[i].api_name);
                if (target) {
                    MH_RemoveHook(target);
                }
            }
            g_hooks[i].installed = FALSE;
        }
    }

    /* Uninitialize MinHook */
    MH_Uninitialize();

    OutputDebugStringA("[SANDBOX] All hooks removed.\n");
}

int hook_engine_get_count(void)
{
    return g_hook_count;
}
