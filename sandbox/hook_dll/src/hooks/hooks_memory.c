/*
 * hooks_memory.c — Memory Manipulation API Hooks (EXPANDED — 11 APIs)
 * Added: VirtualFreeEx, VirtualQuery, VirtualQueryEx, FlushInstructionCache
 */
#include <windows.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

/* VirtualAlloc */
typedef LPVOID (WINAPI *PFN_VirtualAlloc)(LPVOID,SIZE_T,DWORD,DWORD); static PFN_VirtualAlloc pO_VA=NULL;
static LPVOID WINAPI Hook_VirtualAlloc(LPVOID addr,SIZE_T sz,DWORD at,DWORD prot) {
    LPVOID res=pO_VA(addr,sz,at,prot); char ret[32],args[256];
    logger_format_ptr(ret,sizeof(ret),res);
    _snprintf(args,sizeof(args),"\"dwSize\":%llu,\"flAllocationType\":\"0x%08X\",\"flProtect\":\"0x%08X\"",(unsigned long long)sz,at,prot);
    logger_log_call("VirtualAlloc","MEM",args,ret); return res;
}

/* VirtualAllocEx */
typedef LPVOID (WINAPI *PFN_VirtualAllocEx)(HANDLE,LPVOID,SIZE_T,DWORD,DWORD); static PFN_VirtualAllocEx pO_VAEx=NULL;
static LPVOID WINAPI Hook_VirtualAllocEx(HANDLE hp,LPVOID addr,SIZE_T sz,DWORD at,DWORD prot) {
    LPVOID res=pO_VAEx(hp,addr,sz,at,prot); char h[32],ret[32],args[256];
    logger_format_ptr(h,sizeof(h),(const void*)hp); logger_format_ptr(ret,sizeof(ret),res);
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"dwSize\":%llu,\"flProtect\":\"0x%08X\"",h,(unsigned long long)sz,prot);
    logger_log_call("VirtualAllocEx","MEM",args,ret); return res;
}

/* VirtualProtect */
typedef BOOL (WINAPI *PFN_VirtualProtect)(LPVOID,SIZE_T,DWORD,PDWORD); static PFN_VirtualProtect pO_VP=NULL;
static BOOL WINAPI Hook_VirtualProtect(LPVOID addr,SIZE_T sz,DWORD np,PDWORD op) {
    BOOL res=pO_VP(addr,sz,np,op); char a[32],ret[16],args[256];
    logger_format_ptr(a,sizeof(a),addr); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpAddress\":\"%s\",\"dwSize\":%llu,\"flNewProtect\":\"0x%08X\"",a,(unsigned long long)sz,np);
    logger_log_call("VirtualProtect","MEM",args,ret); return res;
}

/* VirtualProtectEx */
typedef BOOL (WINAPI *PFN_VirtualProtectEx)(HANDLE,LPVOID,SIZE_T,DWORD,PDWORD); static PFN_VirtualProtectEx pO_VPEx=NULL;
static BOOL WINAPI Hook_VirtualProtectEx(HANDLE hp,LPVOID addr,SIZE_T sz,DWORD np,PDWORD op) {
    BOOL res=pO_VPEx(hp,addr,sz,np,op); char h[32],a[32],ret[16],args[256];
    logger_format_ptr(h,sizeof(h),(const void*)hp); logger_format_ptr(a,sizeof(a),addr);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"lpAddress\":\"%s\",\"flNewProtect\":\"0x%08X\"",h,a,np);
    logger_log_call("VirtualProtectEx","MEM",args,ret); return res;
}

/* VirtualFree */
typedef BOOL (WINAPI *PFN_VirtualFree)(LPVOID,SIZE_T,DWORD); static PFN_VirtualFree pO_VF=NULL;
static BOOL WINAPI Hook_VirtualFree(LPVOID addr,SIZE_T sz,DWORD ft) {
    BOOL res=pO_VF(addr,sz,ft); char a[32],ret[16],args[128];
    logger_format_ptr(a,sizeof(a),addr); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpAddress\":\"%s\",\"dwFreeType\":\"0x%08X\"",a,ft);
    logger_log_call("VirtualFree","MEM",args,ret); return res;
}

/* VirtualFreeEx */
typedef BOOL (WINAPI *PFN_VirtualFreeEx)(HANDLE,LPVOID,SIZE_T,DWORD); static PFN_VirtualFreeEx pO_VFEx=NULL;
static BOOL WINAPI Hook_VirtualFreeEx(HANDLE hp,LPVOID addr,SIZE_T sz,DWORD ft) {
    BOOL res=pO_VFEx(hp,addr,sz,ft); char h[32],a[32],ret[16],args[256];
    logger_format_ptr(h,sizeof(h),(const void*)hp); logger_format_ptr(a,sizeof(a),addr);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"lpAddress\":\"%s\"",h,a);
    logger_log_call("VirtualFreeEx","MEM",args,ret); return res;
}

/* WriteProcessMemory */
typedef BOOL (WINAPI *PFN_WriteProcessMemory)(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*); static PFN_WriteProcessMemory pO_WPM=NULL;
static BOOL WINAPI Hook_WriteProcessMemory(HANDLE hp,LPVOID ba,LPCVOID buf,SIZE_T sz,SIZE_T* written) {
    BOOL res=pO_WPM(hp,ba,buf,sz,written); char h[32],a[32],ret[16],args[256];
    logger_format_ptr(h,sizeof(h),(const void*)hp); logger_format_ptr(a,sizeof(a),ba);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"lpBaseAddress\":\"%s\",\"nSize\":%llu",h,a,(unsigned long long)sz);
    logger_log_call("WriteProcessMemory","MEM",args,ret); return res;
}

/* ReadProcessMemory */
typedef BOOL (WINAPI *PFN_ReadProcessMemory)(HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*); static PFN_ReadProcessMemory pO_RPM=NULL;
static BOOL WINAPI Hook_ReadProcessMemory(HANDLE hp,LPCVOID ba,LPVOID buf,SIZE_T sz,SIZE_T* rd) {
    BOOL res=pO_RPM(hp,ba,buf,sz,rd); char h[32],a[32],ret[16],args[256];
    logger_format_ptr(h,sizeof(h),(const void*)hp); logger_format_ptr(a,sizeof(a),ba);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"lpBaseAddress\":\"%s\",\"nSize\":%llu",h,a,(unsigned long long)sz);
    logger_log_call("ReadProcessMemory","MEM",args,ret); return res;
}

/* VirtualQuery */
typedef SIZE_T (WINAPI *PFN_VirtualQuery)(LPCVOID,PMEMORY_BASIC_INFORMATION,SIZE_T); static PFN_VirtualQuery pO_VQ=NULL;
static SIZE_T WINAPI Hook_VirtualQuery(LPCVOID addr,PMEMORY_BASIC_INFORMATION mbi,SIZE_T len) {
    SIZE_T res=pO_VQ(addr,mbi,len); char a[32],ret[32],args[128];
    logger_format_ptr(a,sizeof(a),addr); _snprintf(ret,sizeof(ret),"%llu",(unsigned long long)res);
    _snprintf(args,sizeof(args),"\"lpAddress\":\"%s\"",a);
    logger_log_call("VirtualQuery","MEM",args,ret); return res;
}

/* VirtualQueryEx */
typedef SIZE_T (WINAPI *PFN_VirtualQueryEx)(HANDLE,LPCVOID,PMEMORY_BASIC_INFORMATION,SIZE_T); static PFN_VirtualQueryEx pO_VQEx=NULL;
static SIZE_T WINAPI Hook_VirtualQueryEx(HANDLE hp,LPCVOID addr,PMEMORY_BASIC_INFORMATION mbi,SIZE_T len) {
    SIZE_T res=pO_VQEx(hp,addr,mbi,len); char h[32],a[32],ret[32],args[256];
    logger_format_ptr(h,sizeof(h),(const void*)hp); logger_format_ptr(a,sizeof(a),addr);
    _snprintf(ret,sizeof(ret),"%llu",(unsigned long long)res);
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"lpAddress\":\"%s\"",h,a);
    logger_log_call("VirtualQueryEx","MEM",args,ret); return res;
}

/* FlushInstructionCache — used after code injection */
typedef BOOL (WINAPI *PFN_FlushInstructionCache)(HANDLE,LPCVOID,SIZE_T); static PFN_FlushInstructionCache pO_FIC=NULL;
static BOOL WINAPI Hook_FlushInstructionCache(HANDLE hp,LPCVOID addr,SIZE_T sz) {
    BOOL res=pO_FIC(hp,addr,sz); char h[32],a[32],ret[16],args[256];
    logger_format_ptr(h,sizeof(h),(const void*)hp); logger_format_ptr(a,sizeof(a),addr);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"lpBaseAddress\":\"%s\",\"dwSize\":%llu",h,a,(unsigned long long)sz);
    logger_log_call("FlushInstructionCache","MEM",args,ret); return res;
}

void register_memory_hooks(void) {
    hook_engine_register(L"kernel32","VirtualAlloc",Hook_VirtualAlloc,(void**)&pO_VA);
    hook_engine_register(L"kernel32","VirtualAllocEx",Hook_VirtualAllocEx,(void**)&pO_VAEx);
    hook_engine_register(L"kernel32","VirtualProtect",Hook_VirtualProtect,(void**)&pO_VP);
    hook_engine_register(L"kernel32","VirtualProtectEx",Hook_VirtualProtectEx,(void**)&pO_VPEx);
    hook_engine_register(L"kernel32","VirtualFree",Hook_VirtualFree,(void**)&pO_VF);
    hook_engine_register(L"kernel32","VirtualFreeEx",Hook_VirtualFreeEx,(void**)&pO_VFEx);
    hook_engine_register(L"kernel32","WriteProcessMemory",Hook_WriteProcessMemory,(void**)&pO_WPM);
    hook_engine_register(L"kernel32","ReadProcessMemory",Hook_ReadProcessMemory,(void**)&pO_RPM);
    hook_engine_register(L"kernel32","VirtualQuery",Hook_VirtualQuery,(void**)&pO_VQ);
    hook_engine_register(L"kernel32","VirtualQueryEx",Hook_VirtualQueryEx,(void**)&pO_VQEx);
    hook_engine_register(L"kernel32","FlushInstructionCache",Hook_FlushInstructionCache,(void**)&pO_FIC);
}
