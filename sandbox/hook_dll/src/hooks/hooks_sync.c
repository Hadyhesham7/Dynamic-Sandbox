/*
 * hooks_sync.c — Synchronization, Handle, Clipboard & Input Hooks (18 APIs)
 * Mutexes: CreateMutexW/A, OpenMutexW/A
 * Handles: CloseHandle, DuplicateHandle
 * Events: CreateEventW/A, WaitForSingleObject
 * Mapping: CreateFileMappingW, MapViewOfFile, UnmapViewOfFile
 * Clipboard: OpenClipboard, GetClipboardData, SetClipboardData
 * Input: SetWindowsHookExA/W, GetAsyncKeyState, keybd_event
 */
#include <windows.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

/* CreateMutexW */
typedef HANDLE (WINAPI *PFN_CreateMutexW)(LPSECURITY_ATTRIBUTES,BOOL,LPCWSTR);
static PFN_CreateMutexW pOrig_CreateMutexW=NULL;
static HANDLE WINAPI Hook_CreateMutexW(LPSECURITY_ATTRIBUTES sa,BOOL own,LPCWSTR name) {
    HANDLE res=pOrig_CreateMutexW(sa,own,name); char n[512],ret[32],args[768];
    logger_format_wstr(n,sizeof(n),name); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpName\":\"%s\"",n);
    logger_log_call("CreateMutexW","SYNC",args,ret); return res;
}

/* CreateMutexA */
typedef HANDLE (WINAPI *PFN_CreateMutexA)(LPSECURITY_ATTRIBUTES,BOOL,LPCSTR);
static PFN_CreateMutexA pOrig_CreateMutexA=NULL;
static HANDLE WINAPI Hook_CreateMutexA(LPSECURITY_ATTRIBUTES sa,BOOL own,LPCSTR name) {
    HANDLE res=pOrig_CreateMutexA(sa,own,name); char n[512],ret[32],args[768];
    logger_format_str(n,sizeof(n),name); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpName\":\"%s\"",n);
    logger_log_call("CreateMutexA","SYNC",args,ret); return res;
}

/* OpenMutexW */
typedef HANDLE (WINAPI *PFN_OpenMutexW)(DWORD,BOOL,LPCWSTR);
static PFN_OpenMutexW pOrig_OpenMutexW=NULL;
static HANDLE WINAPI Hook_OpenMutexW(DWORD da,BOOL ih,LPCWSTR name) {
    HANDLE res=pOrig_OpenMutexW(da,ih,name); char n[512],ret[32],args[768];
    logger_format_wstr(n,sizeof(n),name); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpName\":\"%s\"",n);
    logger_log_call("OpenMutexW","SYNC",args,ret); return res;
}

/* OpenMutexA */
typedef HANDLE (WINAPI *PFN_OpenMutexA)(DWORD,BOOL,LPCSTR);
static PFN_OpenMutexA pOrig_OpenMutexA=NULL;
static HANDLE WINAPI Hook_OpenMutexA(DWORD da,BOOL ih,LPCSTR name) {
    HANDLE res=pOrig_OpenMutexA(da,ih,name); char n[512],ret[32],args[768];
    logger_format_str(n,sizeof(n),name); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpName\":\"%s\"",n);
    logger_log_call("OpenMutexA","SYNC",args,ret); return res;
}

/* CloseHandle */
typedef BOOL (WINAPI *PFN_CloseHandle)(HANDLE);
static PFN_CloseHandle pOrig_CloseHandle=NULL;
static BOOL WINAPI Hook_CloseHandle(HANDLE h) {
    BOOL res=pOrig_CloseHandle(h); char hh[32],ret[16],args[64];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hObject\":\"%s\"",hh);
    logger_log_call("CloseHandle","SYNC",args,ret); return res;
}

/* CreateEventW */
typedef HANDLE (WINAPI *PFN_CreateEventW)(LPSECURITY_ATTRIBUTES,BOOL,BOOL,LPCWSTR);
static PFN_CreateEventW pOrig_CreateEventW=NULL;
static HANDLE WINAPI Hook_CreateEventW(LPSECURITY_ATTRIBUTES sa,BOOL mr,BOOL is,LPCWSTR name) {
    HANDLE res=pOrig_CreateEventW(sa,mr,is,name); char n[512],ret[32],args[768];
    logger_format_wstr(n,sizeof(n),name); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpName\":\"%s\"",n);
    logger_log_call("CreateEventW","SYNC",args,ret); return res;
}

/* CreateEventA */
typedef HANDLE (WINAPI *PFN_CreateEventA)(LPSECURITY_ATTRIBUTES,BOOL,BOOL,LPCSTR);
static PFN_CreateEventA pOrig_CreateEventA=NULL;
static HANDLE WINAPI Hook_CreateEventA(LPSECURITY_ATTRIBUTES sa,BOOL mr,BOOL is,LPCSTR name) {
    HANDLE res=pOrig_CreateEventA(sa,mr,is,name); char n[512],ret[32],args[768];
    logger_format_str(n,sizeof(n),name); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpName\":\"%s\"",n);
    logger_log_call("CreateEventA","SYNC",args,ret); return res;
}

/* WaitForSingleObject */
typedef DWORD (WINAPI *PFN_WaitForSingleObject)(HANDLE,DWORD);
static PFN_WaitForSingleObject pOrig_WFSO=NULL;
static DWORD WINAPI Hook_WaitForSingleObject(HANDLE h,DWORD ms) {
    DWORD res=pOrig_WFSO(h,ms); char hh[32],ret[32],args[128];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"0x%08X",res);
    _snprintf(args,sizeof(args),"\"hHandle\":\"%s\",\"dwMilliseconds\":%lu",hh,ms);
    logger_log_call("WaitForSingleObject","SYNC",args,ret); return res;
}

/* CreateFileMappingW — used in process hollowing */
typedef HANDLE (WINAPI *PFN_CreateFileMappingW)(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCWSTR);
static PFN_CreateFileMappingW pOrig_CreateFMW=NULL;
static HANDLE WINAPI Hook_CreateFileMappingW(HANDLE h,LPSECURITY_ATTRIBUTES sa,DWORD prot,DWORD hi,DWORD lo,LPCWSTR name) {
    HANDLE res=pOrig_CreateFMW(h,sa,prot,hi,lo,name); char n[512],ret[32],args[768];
    logger_format_wstr(n,sizeof(n),name); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"flProtect\":\"0x%08X\",\"lpName\":\"%s\"",prot,n);
    logger_log_call("CreateFileMappingW","SYNC",args,ret); return res;
}

/* MapViewOfFile */
typedef LPVOID (WINAPI *PFN_MapViewOfFile)(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
static PFN_MapViewOfFile pOrig_MapView=NULL;
static LPVOID WINAPI Hook_MapViewOfFile(HANDLE h,DWORD da,DWORD hi,DWORD lo,SIZE_T sz) {
    LPVOID res=pOrig_MapView(h,da,hi,lo,sz); char hh[32],ret[32],args[128];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); logger_format_ptr(ret,sizeof(ret),res);
    _snprintf(args,sizeof(args),"\"hFileMappingObject\":\"%s\",\"dwDesiredAccess\":\"0x%08X\"",hh,da);
    logger_log_call("MapViewOfFile","SYNC",args,ret); return res;
}

/* UnmapViewOfFile */
typedef BOOL (WINAPI *PFN_UnmapViewOfFile)(LPCVOID);
static PFN_UnmapViewOfFile pOrig_UnmapView=NULL;
static BOOL WINAPI Hook_UnmapViewOfFile(LPCVOID addr) {
    BOOL res=pOrig_UnmapView(addr); char a[32],ret[16],args[64];
    logger_format_ptr(a,sizeof(a),addr); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpBaseAddress\":\"%s\"",a);
    logger_log_call("UnmapViewOfFile","SYNC",args,ret); return res;
}

/* OpenClipboard — data theft */
typedef BOOL (WINAPI *PFN_OpenClipboard)(HWND);
static PFN_OpenClipboard pOrig_OpenClip=NULL;
static BOOL WINAPI Hook_OpenClipboard(HWND hw) {
    BOOL res=pOrig_OpenClip(hw); char ret[16];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    logger_log_call("OpenClipboard","SYNC","",ret); return res;
}

/* GetClipboardData */
typedef HANDLE (WINAPI *PFN_GetClipboardData)(UINT);
static PFN_GetClipboardData pOrig_GetClip=NULL;
static HANDLE WINAPI Hook_GetClipboardData(UINT fmt) {
    HANDLE res=pOrig_GetClip(fmt); char ret[32],args[64];
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"uFormat\":%u",fmt);
    logger_log_call("GetClipboardData","SYNC",args,ret); return res;
}

/* SetClipboardData */
typedef HANDLE (WINAPI *PFN_SetClipboardData)(UINT,HANDLE);
static PFN_SetClipboardData pOrig_SetClip=NULL;
static HANDLE WINAPI Hook_SetClipboardData(UINT fmt,HANDLE h) {
    HANDLE res=pOrig_SetClip(fmt,h); char ret[32],args[64];
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"uFormat\":%u",fmt);
    logger_log_call("SetClipboardData","SYNC",args,ret); return res;
}

/* SetWindowsHookExA — keylogger indicator */
typedef HHOOK (WINAPI *PFN_SetWindowsHookExA)(int,HOOKPROC,HINSTANCE,DWORD);
static PFN_SetWindowsHookExA pOrig_SetHookA=NULL;
static HHOOK WINAPI Hook_SetWindowsHookExA(int id,HOOKPROC fn,HINSTANCE mod,DWORD tid) {
    HHOOK res=pOrig_SetHookA(id,fn,mod,tid); char ret[32],args[128];
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"idHook\":%d,\"dwThreadId\":%lu",id,tid);
    logger_log_call("SetWindowsHookExA","SYNC",args,ret); return res;
}

/* SetWindowsHookExW */
typedef HHOOK (WINAPI *PFN_SetWindowsHookExW)(int,HOOKPROC,HINSTANCE,DWORD);
static PFN_SetWindowsHookExW pOrig_SetHookW=NULL;
static HHOOK WINAPI Hook_SetWindowsHookExW(int id,HOOKPROC fn,HINSTANCE mod,DWORD tid) {
    HHOOK res=pOrig_SetHookW(id,fn,mod,tid); char ret[32],args[128];
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"idHook\":%d,\"dwThreadId\":%lu",id,tid);
    logger_log_call("SetWindowsHookExW","SYNC",args,ret); return res;
}

/* GetAsyncKeyState — keylogger */
typedef SHORT (WINAPI *PFN_GetAsyncKeyState)(int);
static PFN_GetAsyncKeyState pOrig_GetAsyncKey=NULL;
static SHORT WINAPI Hook_GetAsyncKeyState(int vKey) {
    SHORT res=pOrig_GetAsyncKey(vKey); char ret[16],args[32];
    _snprintf(ret,sizeof(ret),"%d",res); _snprintf(args,sizeof(args),"\"vKey\":%d",vKey);
    logger_log_call("GetAsyncKeyState","SYNC",args,ret); return res;
}

void register_sync_hooks(void) {
    hook_engine_register(L"kernel32","CreateMutexW",Hook_CreateMutexW,(void**)&pOrig_CreateMutexW);
    hook_engine_register(L"kernel32","CreateMutexA",Hook_CreateMutexA,(void**)&pOrig_CreateMutexA);
    hook_engine_register(L"kernel32","OpenMutexW",Hook_OpenMutexW,(void**)&pOrig_OpenMutexW);
    hook_engine_register(L"kernel32","OpenMutexA",Hook_OpenMutexA,(void**)&pOrig_OpenMutexA);
    hook_engine_register(L"kernel32","CloseHandle",Hook_CloseHandle,(void**)&pOrig_CloseHandle);
    hook_engine_register(L"kernel32","CreateEventW",Hook_CreateEventW,(void**)&pOrig_CreateEventW);
    hook_engine_register(L"kernel32","CreateEventA",Hook_CreateEventA,(void**)&pOrig_CreateEventA);
    hook_engine_register(L"kernel32","WaitForSingleObject",Hook_WaitForSingleObject,(void**)&pOrig_WFSO);
    hook_engine_register(L"kernel32","CreateFileMappingW",Hook_CreateFileMappingW,(void**)&pOrig_CreateFMW);
    hook_engine_register(L"kernel32","MapViewOfFile",Hook_MapViewOfFile,(void**)&pOrig_MapView);
    hook_engine_register(L"kernel32","UnmapViewOfFile",Hook_UnmapViewOfFile,(void**)&pOrig_UnmapView);
    hook_engine_register(L"user32","OpenClipboard",Hook_OpenClipboard,(void**)&pOrig_OpenClip);
    hook_engine_register(L"user32","GetClipboardData",Hook_GetClipboardData,(void**)&pOrig_GetClip);
    hook_engine_register(L"user32","SetClipboardData",Hook_SetClipboardData,(void**)&pOrig_SetClip);
    hook_engine_register(L"user32","SetWindowsHookExA",Hook_SetWindowsHookExA,(void**)&pOrig_SetHookA);
    hook_engine_register(L"user32","SetWindowsHookExW",Hook_SetWindowsHookExW,(void**)&pOrig_SetHookW);
    hook_engine_register(L"user32","GetAsyncKeyState",Hook_GetAsyncKeyState,(void**)&pOrig_GetAsyncKey);
}
