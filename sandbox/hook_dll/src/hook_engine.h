/*
 * hook_engine.h — Hook Registration Framework
 * =============================================
 * Provides macros and functions to register, install,
 * and remove API hooks using MinHook.
 *
 * Usage pattern in hook handler files:
 *
 *   // 1. Declare the hook (creates typedef + original pointer + detour signature)
 *   typedef HANDLE (WINAPI *PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
 *   static PFN_CreateFileW pOriginal_CreateFileW = NULL;
 *
 *   // 2. Write your detour function
 *   HANDLE WINAPI Hook_CreateFileW(LPCWSTR lpFileName, ...) {
 *       HANDLE result = pOriginal_CreateFileW(lpFileName, ...);
 *       logger_log_call("CreateFileW", "FILE", args, ret);
 *       return result;
 *   }
 *
 *   // 3. Register in the hook table
 *   HOOK_ENTRY("kernel32", "CreateFileW", Hook_CreateFileW, &pOriginal_CreateFileW)
 */

#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include <windows.h>
#include "MinHook.h"

/* --- Hook Table Entry --- */
typedef struct {
    const wchar_t* module_name;   /* e.g., L"kernel32" */
    const char*    api_name;      /* e.g., "CreateFileW" */
    void*          detour_func;   /* Pointer to your Hook_Xxx function */
    void**         original_func; /* Where MinHook stores the original */
    BOOL           installed;     /* TRUE if hook is active */
} HookEntry;

/* Maximum number of hooks we can register */
#define MAX_HOOKS 256

/* --- Public API --- */

/*
 * Register a hook in the global table.
 * Call this during initialization, before install_all_hooks().
 * Returns TRUE on success, FALSE if table is full.
 */
BOOL hook_engine_register(
    const wchar_t* module_name,
    const char*    api_name,
    void*          detour_func,
    void**         original_func
);

/*
 * Initialize MinHook and install all registered hooks.
 * Call this from DllMain after all hooks are registered.
 * Returns the number of hooks successfully installed.
 */
int hook_engine_install_all(void);

/*
 * Disable and remove all hooks, then uninitialize MinHook.
 * Call this from DllMain on DLL_PROCESS_DETACH.
 */
void hook_engine_remove_all(void);

/*
 * Get the number of registered hooks.
 */
int hook_engine_get_count(void);

/* --- Registration Functions (called from each hooks_xxx.c file) --- */
/* Each hook category file provides a register function: */

void register_file_hooks(void);
void register_registry_hooks(void);
void register_process_hooks(void);
void register_network_hooks(void);
void register_memory_hooks(void);
void register_dll_hooks(void);
void register_crypto_hooks(void);
void register_system_hooks(void);
void register_services_hooks(void);
void register_sync_hooks(void);

#endif /* HOOK_ENGINE_H */
