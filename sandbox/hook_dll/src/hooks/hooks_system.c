/*
 * hooks_system.c — System, Anti-Debug, Environment & Evasion Hooks (EXPANDED — 18 APIs)
 * Added: SleepEx, NtDelayExecution, GetComputerNameW/A, GetUserNameW/A,
 *        GetSystemDirectoryW, GetTempPathW, SetErrorMode,
 *        OutputDebugStringA, GetVersionExW, GetSystemMetrics, ExitWindowsEx
 */
#include <windows.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

/* IsDebuggerPresent — always return FALSE */
typedef BOOL (WINAPI *PFN_IsDebuggerPresent)(void); static PFN_IsDebuggerPresent pO_IDP=NULL;
static BOOL WINAPI Hook_IsDebuggerPresent(void) {
    pO_IDP(); logger_log_call("IsDebuggerPresent","SYS","","FALSE"); return FALSE;
}

/* CheckRemoteDebuggerPresent */
typedef BOOL (WINAPI *PFN_CheckRemoteDebuggerPresent)(HANDLE,PBOOL); static PFN_CheckRemoteDebuggerPresent pO_CRDP=NULL;
static BOOL WINAPI Hook_CheckRemoteDebuggerPresent(HANDLE hp,PBOOL pDebug) {
    BOOL res=pO_CRDP(hp,pDebug); if(pDebug)*pDebug=FALSE;
    logger_log_call("CheckRemoteDebuggerPresent","SYS","","FALSE"); return TRUE;
}

/* GetSystemInfo */
typedef void (WINAPI *PFN_GetSystemInfo)(LPSYSTEM_INFO); static PFN_GetSystemInfo pO_GSI=NULL;
static void WINAPI Hook_GetSystemInfo(LPSYSTEM_INFO si) {
    pO_GSI(si); char args[128];
    _snprintf(args,sizeof(args),"\"dwNumberOfProcessors\":%lu",si?si->dwNumberOfProcessors:0);
    logger_log_call("GetSystemInfo","SYS",args,"void");
}

/* Sleep — cap long sleeps */
typedef void (WINAPI *PFN_Sleep)(DWORD); static PFN_Sleep pO_Sleep=NULL;
static void WINAPI Hook_Sleep(DWORD ms) {
    char args[64]; _snprintf(args,sizeof(args),"\"dwMilliseconds\":%lu",ms);
    logger_log_call("Sleep","SYS",args,"void");
    if(ms>1000) ms=1000; pO_Sleep(ms);
}

/* SleepEx — cap long sleeps */
typedef DWORD (WINAPI *PFN_SleepEx)(DWORD,BOOL); static PFN_SleepEx pO_SleepEx=NULL;
static DWORD WINAPI Hook_SleepEx(DWORD ms,BOOL alertable) {
    char args[64]; _snprintf(args,sizeof(args),"\"dwMilliseconds\":%lu,\"bAlertable\":%s",ms,alertable?"true":"false");
    logger_log_call("SleepEx","SYS",args,"void");
    if(ms>1000) ms=1000; return pO_SleepEx(ms,alertable);
}

/* GetTickCount */
typedef DWORD (WINAPI *PFN_GetTickCount)(void); static PFN_GetTickCount pO_GTC=NULL;
static DWORD WINAPI Hook_GetTickCount(void) {
    DWORD res=pO_GTC(); char ret[32]; _snprintf(ret,sizeof(ret),"%lu",res);
    logger_log_call("GetTickCount","SYS","",ret); return res;
}

/* GetTickCount64 */
typedef ULONGLONG (WINAPI *PFN_GetTickCount64)(void); static PFN_GetTickCount64 pO_GTC64=NULL;
static ULONGLONG WINAPI Hook_GetTickCount64(void) {
    ULONGLONG res=pO_GTC64(); char ret[32]; _snprintf(ret,sizeof(ret),"%llu",res);
    logger_log_call("GetTickCount64","SYS","",ret); return res;
}

/* GetComputerNameW */
typedef BOOL (WINAPI *PFN_GetComputerNameW)(LPWSTR,LPDWORD); static PFN_GetComputerNameW pO_GCN=NULL;
static BOOL WINAPI Hook_GetComputerNameW(LPWSTR buf,LPDWORD sz) {
    BOOL res=pO_GCN(buf,sz); char n[512],ret[16],args[768];
    logger_format_wstr(n,sizeof(n),buf); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpBuffer\":\"%s\"",n);
    logger_log_call("GetComputerNameW","SYS",args,ret); return res;
}

/* GetComputerNameA */
typedef BOOL (WINAPI *PFN_GetComputerNameA)(LPSTR,LPDWORD); static PFN_GetComputerNameA pO_GCNA=NULL;
static BOOL WINAPI Hook_GetComputerNameA(LPSTR buf,LPDWORD sz) {
    BOOL res=pO_GCNA(buf,sz); char n[512],ret[16],args[768];
    logger_format_str(n,sizeof(n),buf); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpBuffer\":\"%s\"",n);
    logger_log_call("GetComputerNameA","SYS",args,ret); return res;
}

/* GetUserNameW */
typedef BOOL (WINAPI *PFN_GetUserNameW)(LPWSTR,LPDWORD); static PFN_GetUserNameW pO_GUN=NULL;
static BOOL WINAPI Hook_GetUserNameW(LPWSTR buf,LPDWORD sz) {
    BOOL res=pO_GUN(buf,sz); char n[512],ret[16],args[768];
    logger_format_wstr(n,sizeof(n),buf); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpBuffer\":\"%s\"",n);
    logger_log_call("GetUserNameW","SYS",args,ret); return res;
}

/* GetUserNameA */
typedef BOOL (WINAPI *PFN_GetUserNameA)(LPSTR,LPDWORD); static PFN_GetUserNameA pO_GUNA=NULL;
static BOOL WINAPI Hook_GetUserNameA(LPSTR buf,LPDWORD sz) {
    BOOL res=pO_GUNA(buf,sz); char n[512],ret[16],args[768];
    logger_format_str(n,sizeof(n),buf); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpBuffer\":\"%s\"",n);
    logger_log_call("GetUserNameA","SYS",args,ret); return res;
}

/* GetSystemDirectoryW */
typedef UINT (WINAPI *PFN_GetSystemDirectoryW)(LPWSTR,UINT); static PFN_GetSystemDirectoryW pO_GSD=NULL;
static UINT WINAPI Hook_GetSystemDirectoryW(LPWSTR buf,UINT sz) {
    UINT res=pO_GSD(buf,sz); char n[512],ret[16],args[768];
    logger_format_wstr(n,sizeof(n),buf); _snprintf(ret,sizeof(ret),"%u",res);
    _snprintf(args,sizeof(args),"\"lpBuffer\":\"%s\"",n);
    logger_log_call("GetSystemDirectoryW","SYS",args,ret); return res;
}

/* GetTempPathW */
typedef DWORD (WINAPI *PFN_GetTempPathW)(DWORD,LPWSTR); static PFN_GetTempPathW pO_GTP=NULL;
static DWORD WINAPI Hook_GetTempPathW(DWORD sz,LPWSTR buf) {
    DWORD res=pO_GTP(sz,buf); char n[512],ret[16],args[768];
    logger_format_wstr(n,sizeof(n),buf); _snprintf(ret,sizeof(ret),"%lu",res);
    _snprintf(args,sizeof(args),"\"lpBuffer\":\"%s\"",n);
    logger_log_call("GetTempPathW","SYS",args,ret); return res;
}

/* SetErrorMode */
typedef UINT (WINAPI *PFN_SetErrorMode)(UINT); static PFN_SetErrorMode pO_SEM=NULL;
static UINT WINAPI Hook_SetErrorMode(UINT mode) {
    UINT res=pO_SEM(mode); char ret[16],args[64];
    _snprintf(ret,sizeof(ret),"%u",res); _snprintf(args,sizeof(args),"\"uMode\":\"0x%08X\"",mode);
    logger_log_call("SetErrorMode","SYS",args,ret); return res;
}

/* OutputDebugStringA */
typedef void (WINAPI *PFN_OutputDebugStringA)(LPCSTR); static PFN_OutputDebugStringA pO_ODS=NULL;
static void WINAPI Hook_OutputDebugStringA(LPCSTR str) {
    pO_ODS(str); char s[512],args[768];
    logger_format_str(s,sizeof(s),str); _snprintf(args,sizeof(args),"\"lpOutputString\":\"%s\"",s);
    logger_log_call("OutputDebugStringA","SYS",args,"void");
}

/* GetSystemMetrics — sandbox detection */
typedef int (WINAPI *PFN_GetSystemMetrics)(int); static PFN_GetSystemMetrics pO_GSM=NULL;
static int WINAPI Hook_GetSystemMetrics(int idx) {
    int res=pO_GSM(idx); char ret[16],args[32];
    _snprintf(ret,sizeof(ret),"%d",res); _snprintf(args,sizeof(args),"\"nIndex\":%d",idx);
    logger_log_call("GetSystemMetrics","SYS",args,ret); return res;
}

/* ExitWindowsEx — shutdown/reboot */
typedef BOOL (WINAPI *PFN_ExitWindowsEx)(UINT,DWORD); static PFN_ExitWindowsEx pO_EWX=NULL;
static BOOL WINAPI Hook_ExitWindowsEx(UINT fl,DWORD reason) {
    char args[128];
    _snprintf(args,sizeof(args),"\"uFlags\":\"0x%08X\",\"dwReason\":%lu",fl,reason);
    logger_log_call("ExitWindowsEx","SYS",args,"BLOCKED");
    return FALSE; /* Block shutdown attempts */
}

/* ---- PHASE 11: ANTI-EVASION HOOKS ---- */

/* NtDelayExecution — kernel-level Sleep, malware uses to bypass Sleep hooks
 * Cap at 1 second (10,000,000 * 100ns = 1s) */
typedef LONG NTSTATUS;
typedef struct _LARGE_INTEGER_NT { long long QuadPart; } LARGE_INTEGER_NT;
typedef NTSTATUS (NTAPI *PFN_NtDelayExecution)(BOOLEAN,LARGE_INTEGER_NT*);
static PFN_NtDelayExecution pO_NtDelay=NULL;
static NTSTATUS NTAPI Hook_NtDelayExecution(BOOLEAN alertable, LARGE_INTEGER_NT* delay) {
    char args[128];
    long long original_delay = delay ? delay->QuadPart : 0;
    _snprintf(args,sizeof(args),"\"Alertable\":%s,\"DelayInterval\":%lld",
              alertable?"true":"false", original_delay);
    logger_log_call("NtDelayExecution","SYS",args,"fast-forward");
    /* Negative = relative time in 100ns units. -10000000 = 1 second */
    if(delay && delay->QuadPart < -10000000LL) {
        delay->QuadPart = -10000000LL;  /* Cap at 1 second */
    }
    return pO_NtDelay(alertable, delay);
}

/* QueryPerformanceCounter — malware measures elapsed time to detect sandbox.
 * We accelerate the counter 10x so timing checks pass faster. */
typedef BOOL (WINAPI *PFN_QPC)(LARGE_INTEGER*);
static PFN_QPC pO_QPC=NULL;
static LARGE_INTEGER qpc_base = {0};
static int qpc_initialized = 0;
static BOOL WINAPI Hook_QueryPerformanceCounter(LARGE_INTEGER* pc) {
    BOOL res = pO_QPC(pc);
    if(res && pc) {
        /* First call: store base value */
        if(!qpc_initialized) {
            qpc_base.QuadPart = pc->QuadPart;
            qpc_initialized = 1;
        }
        /* Accelerate elapsed time by 10x */
        long long elapsed = pc->QuadPart - qpc_base.QuadPart;
        pc->QuadPart = qpc_base.QuadPart + (elapsed * 10);
    }
    char ret[32]; _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    logger_log_call("QueryPerformanceCounter","SYS","","(accelerated 10x)");
    return res;
}

/* QueryPerformanceFrequency — log only (no modification needed) */
typedef BOOL (WINAPI *PFN_QPF)(LARGE_INTEGER*);
static PFN_QPF pO_QPF=NULL;
static BOOL WINAPI Hook_QueryPerformanceFrequency(LARGE_INTEGER* freq) {
    BOOL res = pO_QPF(freq);
    char ret[32],args[64];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"frequency\":%lld",freq?freq->QuadPart:0);
    logger_log_call("QueryPerformanceFrequency","SYS",args,ret);
    return res;
}

/* WaitForSingleObject — cap at 3 seconds to prevent stalling */
typedef DWORD (WINAPI *PFN_WFSO)(HANDLE,DWORD);
static PFN_WFSO pO_WFSO=NULL;
#define MAX_WAIT_MS 3000
static DWORD WINAPI Hook_WaitForSingleObject(HANDLE h, DWORD ms) {
    char hh[32],args[128],ret[32];
    DWORD original_ms = ms;
    logger_format_ptr(hh,sizeof(hh),(const void*)h);
    if(ms > MAX_WAIT_MS && ms != INFINITE) {
        ms = MAX_WAIT_MS;
    } else if(ms == INFINITE) {
        ms = MAX_WAIT_MS; /* Never allow infinite waits */
    }
    DWORD res = pO_WFSO(h, ms);
    _snprintf(args,sizeof(args),"\"hHandle\":\"%s\",\"dwMilliseconds\":%lu,\"original\":%lu",hh,ms,original_ms);
    _snprintf(ret,sizeof(ret),"%lu",res);
    logger_log_call("WaitForSingleObject","SYS",args,ret);
    return res;
}

/* WaitForMultipleObjects — cap at 3 seconds */
typedef DWORD (WINAPI *PFN_WFMO)(DWORD,const HANDLE*,BOOL,DWORD);
static PFN_WFMO pO_WFMO=NULL;
static DWORD WINAPI Hook_WaitForMultipleObjects(DWORD count,const HANDLE* handles,BOOL waitAll,DWORD ms) {
    char args[128],ret[32];
    DWORD original_ms = ms;
    if(ms > MAX_WAIT_MS && ms != INFINITE) ms = MAX_WAIT_MS;
    else if(ms == INFINITE) ms = MAX_WAIT_MS;
    DWORD res = pO_WFMO(count,handles,waitAll,ms);
    _snprintf(args,sizeof(args),"\"nCount\":%lu,\"bWaitAll\":%s,\"dwMilliseconds\":%lu,\"original\":%lu",
              count,waitAll?"true":"false",ms,original_ms);
    _snprintf(ret,sizeof(ret),"%lu",res);
    logger_log_call("WaitForMultipleObjects","SYS",args,ret);
    return res;
}

void register_system_hooks(void) {
    hook_engine_register(L"kernel32","IsDebuggerPresent",Hook_IsDebuggerPresent,(void**)&pO_IDP);
    hook_engine_register(L"kernel32","CheckRemoteDebuggerPresent",Hook_CheckRemoteDebuggerPresent,(void**)&pO_CRDP);
    hook_engine_register(L"kernel32","GetSystemInfo",Hook_GetSystemInfo,(void**)&pO_GSI);
    hook_engine_register(L"kernel32","Sleep",Hook_Sleep,(void**)&pO_Sleep);
    hook_engine_register(L"kernel32","SleepEx",Hook_SleepEx,(void**)&pO_SleepEx);
    hook_engine_register(L"kernel32","GetTickCount",Hook_GetTickCount,(void**)&pO_GTC);
    hook_engine_register(L"kernel32","GetTickCount64",Hook_GetTickCount64,(void**)&pO_GTC64);
    hook_engine_register(L"kernel32","GetComputerNameW",Hook_GetComputerNameW,(void**)&pO_GCN);
    hook_engine_register(L"kernel32","GetComputerNameA",Hook_GetComputerNameA,(void**)&pO_GCNA);
    hook_engine_register(L"advapi32","GetUserNameW",Hook_GetUserNameW,(void**)&pO_GUN);
    hook_engine_register(L"advapi32","GetUserNameA",Hook_GetUserNameA,(void**)&pO_GUNA);
    hook_engine_register(L"kernel32","GetSystemDirectoryW",Hook_GetSystemDirectoryW,(void**)&pO_GSD);
    hook_engine_register(L"kernel32","GetTempPathW",Hook_GetTempPathW,(void**)&pO_GTP);
    hook_engine_register(L"kernel32","SetErrorMode",Hook_SetErrorMode,(void**)&pO_SEM);
    hook_engine_register(L"kernel32","OutputDebugStringA",Hook_OutputDebugStringA,(void**)&pO_ODS);
    hook_engine_register(L"user32","GetSystemMetrics",Hook_GetSystemMetrics,(void**)&pO_GSM);
    hook_engine_register(L"user32","ExitWindowsEx",Hook_ExitWindowsEx,(void**)&pO_EWX);
    /* Phase 11: Anti-evasion */
    hook_engine_register(L"ntdll","NtDelayExecution",Hook_NtDelayExecution,(void**)&pO_NtDelay);
    hook_engine_register(L"kernel32","QueryPerformanceCounter",Hook_QueryPerformanceCounter,(void**)&pO_QPC);
    hook_engine_register(L"kernel32","QueryPerformanceFrequency",Hook_QueryPerformanceFrequency,(void**)&pO_QPF);
    hook_engine_register(L"kernel32","WaitForSingleObject",Hook_WaitForSingleObject,(void**)&pO_WFSO);
    hook_engine_register(L"kernel32","WaitForMultipleObjects",Hook_WaitForMultipleObjects,(void**)&pO_WFMO);
}

