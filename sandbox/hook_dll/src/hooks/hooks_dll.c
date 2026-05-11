/*
 * hooks_dll.c — DLL Loading API Hooks (EXPANDED — 8 APIs)
 * Added: LoadLibraryExA, GetModuleHandleA, GetModuleHandleW
 */
#include <windows.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR); static PFN_LoadLibraryA pO_LLA=NULL;
static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR fn) {
    HMODULE res=pO_LLA(fn); char n[1024],ret[32],args[1280];
    logger_format_str(n,sizeof(n),fn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpLibFileName\":\"%s\"",n);
    logger_log_call("LoadLibraryA","DLL",args,ret); return res;
}

typedef HMODULE (WINAPI *PFN_LoadLibraryW)(LPCWSTR); static PFN_LoadLibraryW pO_LLW=NULL;
static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR fn) {
    HMODULE res=pO_LLW(fn); char n[1024],ret[32],args[1280];
    logger_format_wstr(n,sizeof(n),fn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpLibFileName\":\"%s\"",n);
    logger_log_call("LoadLibraryW","DLL",args,ret); return res;
}

typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR,HANDLE,DWORD); static PFN_LoadLibraryExW pO_LLEW=NULL;
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR fn,HANDLE h,DWORD fl) {
    HMODULE res=pO_LLEW(fn,h,fl); char n[1024],ret[32],args[1280];
    logger_format_wstr(n,sizeof(n),fn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpLibFileName\":\"%s\",\"dwFlags\":\"0x%08X\"",n,fl);
    logger_log_call("LoadLibraryExW","DLL",args,ret); return res;
}

typedef HMODULE (WINAPI *PFN_LoadLibraryExA)(LPCSTR,HANDLE,DWORD); static PFN_LoadLibraryExA pO_LLEA=NULL;
static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR fn,HANDLE h,DWORD fl) {
    HMODULE res=pO_LLEA(fn,h,fl); char n[1024],ret[32],args[1280];
    logger_format_str(n,sizeof(n),fn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpLibFileName\":\"%s\",\"dwFlags\":\"0x%08X\"",n,fl);
    logger_log_call("LoadLibraryExA","DLL",args,ret); return res;
}

typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE,LPCSTR); static PFN_GetProcAddress pO_GPA=NULL;
static FARPROC WINAPI Hook_GetProcAddress(HMODULE hm,LPCSTR fn) {
    FARPROC res=pO_GPA(hm,fn); char mod[32],pn[256],ret[32],args[512];
    logger_format_ptr(mod,sizeof(mod),(const void*)hm); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    if((uintptr_t)fn>0xFFFF) logger_format_str(pn,sizeof(pn),fn);
    else _snprintf(pn,sizeof(pn),"ordinal_%u",(unsigned)(uintptr_t)fn);
    _snprintf(args,sizeof(args),"\"hModule\":\"%s\",\"lpProcName\":\"%s\"",mod,pn);
    logger_log_call("GetProcAddress","DLL",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_FreeLibrary)(HMODULE); static PFN_FreeLibrary pO_FL=NULL;
static BOOL WINAPI Hook_FreeLibrary(HMODULE hm) {
    BOOL res=pO_FL(hm); char mod[32],ret[16],args[64];
    logger_format_ptr(mod,sizeof(mod),(const void*)hm); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hLibModule\":\"%s\"",mod);
    logger_log_call("FreeLibrary","DLL",args,ret); return res;
}

typedef HMODULE (WINAPI *PFN_GetModuleHandleA)(LPCSTR); static PFN_GetModuleHandleA pO_GMHA=NULL;
static HMODULE WINAPI Hook_GetModuleHandleA(LPCSTR fn) {
    HMODULE res=pO_GMHA(fn); char n[512],ret[32],args[768];
    logger_format_str(n,sizeof(n),fn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpModuleName\":\"%s\"",n);
    logger_log_call("GetModuleHandleA","DLL",args,ret); return res;
}

typedef HMODULE (WINAPI *PFN_GetModuleHandleW)(LPCWSTR); static PFN_GetModuleHandleW pO_GMHW=NULL;
static HMODULE WINAPI Hook_GetModuleHandleW(LPCWSTR fn) {
    HMODULE res=pO_GMHW(fn); char n[512],ret[32],args[768];
    logger_format_wstr(n,sizeof(n),fn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpModuleName\":\"%s\"",n);
    logger_log_call("GetModuleHandleW","DLL",args,ret); return res;
}

void register_dll_hooks(void) {
    hook_engine_register(L"kernel32","LoadLibraryA",Hook_LoadLibraryA,(void**)&pO_LLA);
    hook_engine_register(L"kernel32","LoadLibraryW",Hook_LoadLibraryW,(void**)&pO_LLW);
    hook_engine_register(L"kernel32","LoadLibraryExW",Hook_LoadLibraryExW,(void**)&pO_LLEW);
    hook_engine_register(L"kernel32","LoadLibraryExA",Hook_LoadLibraryExA,(void**)&pO_LLEA);
    hook_engine_register(L"kernel32","GetProcAddress",Hook_GetProcAddress,(void**)&pO_GPA);
    hook_engine_register(L"kernel32","FreeLibrary",Hook_FreeLibrary,(void**)&pO_FL);
    hook_engine_register(L"kernel32","GetModuleHandleA",Hook_GetModuleHandleA,(void**)&pO_GMHA);
    hook_engine_register(L"kernel32","GetModuleHandleW",Hook_GetModuleHandleW,(void**)&pO_GMHW);
}
