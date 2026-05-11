/*
 * hooks_process.c — Process API Hooks (EXPANDED — 19 APIs)
 * Added: ShellExecuteExW, SuspendThread, ResumeThread, TerminateThread,
 *        NtTerminateProcess, QueueUserAPC, SetThreadContext,
 *        GetThreadContext, GetExitCodeProcess
 */
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

/* CreateProcessW */
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
static PFN_CreateProcessW pOrig_CreateProcessW=NULL;
static BOOL WINAPI Hook_CreateProcessW(LPCWSTR app,LPWSTR cmd,LPSECURITY_ATTRIBUTES pa,LPSECURITY_ATTRIBUTES ta,BOOL ih,DWORD fl,LPVOID env,LPCWSTR dir,LPSTARTUPINFOW si,LPPROCESS_INFORMATION pi) {
    BOOL res=pOrig_CreateProcessW(app,cmd,pa,ta,ih,fl,env,dir,si,pi);
    char a[1024],c[1024],ret[16],args[2200];
    logger_format_wstr(a,sizeof(a),app); logger_format_wstr(c,sizeof(c),cmd);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpApplicationName\":\"%s\",\"lpCommandLine\":\"%s\",\"dwCreationFlags\":\"0x%08X\"",a,c,fl);
    logger_log_call("CreateProcessW","PROC",args,ret); return res;
}

/* CreateProcessA */
typedef BOOL (WINAPI *PFN_CreateProcessA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
static PFN_CreateProcessA pOrig_CreateProcessA=NULL;
static BOOL WINAPI Hook_CreateProcessA(LPCSTR app,LPSTR cmd,LPSECURITY_ATTRIBUTES pa,LPSECURITY_ATTRIBUTES ta,BOOL ih,DWORD fl,LPVOID env,LPCSTR dir,LPSTARTUPINFOA si,LPPROCESS_INFORMATION pi) {
    BOOL res=pOrig_CreateProcessA(app,cmd,pa,ta,ih,fl,env,dir,si,pi);
    char a[1024],c[1024],ret[16],args[2200];
    logger_format_str(a,sizeof(a),app); logger_format_str(c,sizeof(c),cmd);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpApplicationName\":\"%s\",\"lpCommandLine\":\"%s\",\"dwCreationFlags\":\"0x%08X\"",a,c,fl);
    logger_log_call("CreateProcessA","PROC",args,ret); return res;
}

/* OpenProcess */
typedef HANDLE (WINAPI *PFN_OpenProcess)(DWORD,BOOL,DWORD); static PFN_OpenProcess pOrig_OpenProcess=NULL;
static HANDLE WINAPI Hook_OpenProcess(DWORD da,BOOL ih,DWORD pid) {
    HANDLE res=pOrig_OpenProcess(da,ih,pid); char ret[32],args[128];
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"dwDesiredAccess\":\"0x%08X\",\"dwProcessId\":%lu",da,pid);
    logger_log_call("OpenProcess","PROC",args,ret); return res;
}

/* TerminateProcess */
typedef BOOL (WINAPI *PFN_TerminateProcess)(HANDLE,UINT); static PFN_TerminateProcess pOrig_TerminateProcess=NULL;
static BOOL WINAPI Hook_TerminateProcess(HANDLE hp,UINT ec) {
    BOOL res=pOrig_TerminateProcess(hp,ec); char h[32],ret[16],args[128];
    logger_format_ptr(h,sizeof(h),(const void*)hp); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"uExitCode\":%u",h,ec);
    logger_log_call("TerminateProcess","PROC",args,ret); return res;
}

/* CreateRemoteThread */
typedef HANDLE (WINAPI *PFN_CreateRemoteThread)(HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
static PFN_CreateRemoteThread pOrig_CreateRemoteThread=NULL;
static HANDLE WINAPI Hook_CreateRemoteThread(HANDLE hp,LPSECURITY_ATTRIBUTES sa,SIZE_T ss,LPTHREAD_START_ROUTINE fn,LPVOID p,DWORD fl,LPDWORD tid) {
    HANDLE res=pOrig_CreateRemoteThread(hp,sa,ss,fn,p,fl,tid);
    char h[32],f[32],ret[32],args[256];
    logger_format_ptr(h,sizeof(h),(const void*)hp); logger_format_ptr(f,sizeof(f),(const void*)fn);
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"lpStartAddress\":\"%s\"",h,f);
    logger_log_call("CreateRemoteThread","PROC",args,ret); return res;
}

/* CreateThread */
typedef HANDLE (WINAPI *PFN_CreateThread)(LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
static PFN_CreateThread pOrig_CreateThread=NULL;
static HANDLE WINAPI Hook_CreateThread(LPSECURITY_ATTRIBUTES sa,SIZE_T ss,LPTHREAD_START_ROUTINE fn,LPVOID p,DWORD fl,LPDWORD tid) {
    HANDLE res=pOrig_CreateThread(sa,ss,fn,p,fl,tid); char f[32],ret[32],args[128];
    logger_format_ptr(f,sizeof(f),(const void*)fn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpStartAddress\":\"%s\"",f);
    logger_log_call("CreateThread","PROC",args,ret); return res;
}

/* ExitProcess */
typedef void (WINAPI *PFN_ExitProcess)(UINT); static PFN_ExitProcess pOrig_ExitProcess=NULL;
static void WINAPI Hook_ExitProcess(UINT ec) {
    char args[64]; _snprintf(args,sizeof(args),"\"uExitCode\":%u",ec);
    logger_log_call("ExitProcess","PROC",args,"N/A"); pOrig_ExitProcess(ec);
}

/* CreateToolhelp32Snapshot */
typedef HANDLE (WINAPI *PFN_CreateToolhelp32Snapshot)(DWORD,DWORD); static PFN_CreateToolhelp32Snapshot pOrig_Snap=NULL;
static HANDLE WINAPI Hook_CreateToolhelp32Snapshot(DWORD fl,DWORD pid) {
    HANDLE res=pOrig_Snap(fl,pid); char ret[32],args[128];
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"dwFlags\":\"0x%08X\",\"th32ProcessID\":%lu",fl,pid);
    logger_log_call("CreateToolhelp32Snapshot","PROC",args,ret); return res;
}

/* Process32FirstW / Process32NextW */
typedef BOOL (WINAPI *PFN_Process32FirstW)(HANDLE,LPPROCESSENTRY32W); static PFN_Process32FirstW pOrig_P32F=NULL;
static BOOL WINAPI Hook_Process32FirstW(HANDLE h,LPPROCESSENTRY32W pe) {
    BOOL res=pOrig_P32F(h,pe); char ret[16]; _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    logger_log_call("Process32FirstW","PROC","",ret); return res;
}
typedef BOOL (WINAPI *PFN_Process32NextW)(HANDLE,LPPROCESSENTRY32W); static PFN_Process32NextW pOrig_P32N=NULL;
static BOOL WINAPI Hook_Process32NextW(HANDLE h,LPPROCESSENTRY32W pe) {
    BOOL res=pOrig_P32N(h,pe); char ret[16]; _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    logger_log_call("Process32NextW","PROC","",ret); return res;
}

/* ---- NEW APIs ---- */

/* ShellExecuteExW */
typedef BOOL (WINAPI *PFN_ShellExecuteExW)(SHELLEXECUTEINFOW*); static PFN_ShellExecuteExW pOrig_ShellExec=NULL;
static BOOL WINAPI Hook_ShellExecuteExW(SHELLEXECUTEINFOW* sei) {
    BOOL res=pOrig_ShellExec(sei); char f[1024],p[1024],ret[16],args[2200];
    logger_format_wstr(f,sizeof(f),sei?sei->lpFile:NULL);
    logger_format_wstr(p,sizeof(p),sei?sei->lpParameters:NULL);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpFile\":\"%s\",\"lpParameters\":\"%s\"",f,p);
    logger_log_call("ShellExecuteExW","PROC",args,ret); return res;
}

/* SuspendThread */
typedef DWORD (WINAPI *PFN_SuspendThread)(HANDLE); static PFN_SuspendThread pOrig_SuspendThread=NULL;
static DWORD WINAPI Hook_SuspendThread(HANDLE h) {
    DWORD res=pOrig_SuspendThread(h); char hh[32],ret[32],args[64];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%lu",res);
    _snprintf(args,sizeof(args),"\"hThread\":\"%s\"",hh);
    logger_log_call("SuspendThread","PROC",args,ret); return res;
}

/* ResumeThread */
typedef DWORD (WINAPI *PFN_ResumeThread)(HANDLE); static PFN_ResumeThread pOrig_ResumeThread=NULL;
static DWORD WINAPI Hook_ResumeThread(HANDLE h) {
    DWORD res=pOrig_ResumeThread(h); char hh[32],ret[32],args[64];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%lu",res);
    _snprintf(args,sizeof(args),"\"hThread\":\"%s\"",hh);
    logger_log_call("ResumeThread","PROC",args,ret); return res;
}

/* TerminateThread */
typedef BOOL (WINAPI *PFN_TerminateThread)(HANDLE,DWORD); static PFN_TerminateThread pOrig_TermThread=NULL;
static BOOL WINAPI Hook_TerminateThread(HANDLE h,DWORD ec) {
    BOOL res=pOrig_TermThread(h,ec); char hh[32],ret[16],args[128];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hThread\":\"%s\",\"dwExitCode\":%lu",hh,ec);
    logger_log_call("TerminateThread","PROC",args,ret); return res;
}

/* QueueUserAPC — code injection technique */
typedef DWORD (WINAPI *PFN_QueueUserAPC)(PAPCFUNC,HANDLE,ULONG_PTR); static PFN_QueueUserAPC pOrig_QueueAPC=NULL;
static DWORD WINAPI Hook_QueueUserAPC(PAPCFUNC fn,HANDLE h,ULONG_PTR data) {
    DWORD res=pOrig_QueueAPC(fn,h,data); char f[32],hh[32],ret[32],args[128];
    logger_format_ptr(f,sizeof(f),(const void*)fn); logger_format_ptr(hh,sizeof(hh),(const void*)h);
    _snprintf(ret,sizeof(ret),"%lu",res);
    _snprintf(args,sizeof(args),"\"pfnAPC\":\"%s\",\"hThread\":\"%s\"",f,hh);
    logger_log_call("QueueUserAPC","PROC",args,ret); return res;
}

/* SetThreadContext — used in process hollowing */
typedef BOOL (WINAPI *PFN_SetThreadContext)(HANDLE,const CONTEXT*); static PFN_SetThreadContext pOrig_SetCtx=NULL;
static BOOL WINAPI Hook_SetThreadContext(HANDLE h,const CONTEXT* ctx) {
    BOOL res=pOrig_SetCtx(h,ctx); char hh[32],ret[16],args[64];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hThread\":\"%s\"",hh);
    logger_log_call("SetThreadContext","PROC",args,ret); return res;
}

/* GetThreadContext */
typedef BOOL (WINAPI *PFN_GetThreadContext)(HANDLE,LPCONTEXT); static PFN_GetThreadContext pOrig_GetCtx=NULL;
static BOOL WINAPI Hook_GetThreadContext(HANDLE h,LPCONTEXT ctx) {
    BOOL res=pOrig_GetCtx(h,ctx); char hh[32],ret[16],args[64];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hThread\":\"%s\"",hh);
    logger_log_call("GetThreadContext","PROC",args,ret); return res;
}

/* GetExitCodeProcess */
typedef BOOL (WINAPI *PFN_GetExitCodeProcess)(HANDLE,LPDWORD); static PFN_GetExitCodeProcess pOrig_GetExitCode=NULL;
static BOOL WINAPI Hook_GetExitCodeProcess(HANDLE h,LPDWORD ec) {
    BOOL res=pOrig_GetExitCode(h,ec); char hh[32],ret[16],args[128];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hProcess\":\"%s\",\"exitCode\":%lu",hh,ec?*ec:0);
    logger_log_call("GetExitCodeProcess","PROC",args,ret); return res;
}

/* OpenProcessToken */
typedef BOOL (WINAPI *PFN_OpenProcessToken)(HANDLE,DWORD,PHANDLE); static PFN_OpenProcessToken pOrig_OpenProcTok=NULL;
static BOOL WINAPI Hook_OpenProcessToken(HANDLE h,DWORD da,PHANDLE tok) {
    BOOL res=pOrig_OpenProcTok(h,da,tok); char hh[32],ret[16],args[128];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"ProcessHandle\":\"%s\",\"DesiredAccess\":\"0x%08X\"",hh,da);
    logger_log_call("OpenProcessToken","PROC",args,ret); return res;
}

void register_process_hooks(void) {
    hook_engine_register(L"kernel32","CreateProcessW",Hook_CreateProcessW,(void**)&pOrig_CreateProcessW);
    hook_engine_register(L"kernel32","CreateProcessA",Hook_CreateProcessA,(void**)&pOrig_CreateProcessA);
    hook_engine_register(L"kernel32","OpenProcess",Hook_OpenProcess,(void**)&pOrig_OpenProcess);
    hook_engine_register(L"kernel32","TerminateProcess",Hook_TerminateProcess,(void**)&pOrig_TerminateProcess);
    hook_engine_register(L"kernel32","CreateRemoteThread",Hook_CreateRemoteThread,(void**)&pOrig_CreateRemoteThread);
    hook_engine_register(L"kernel32","CreateThread",Hook_CreateThread,(void**)&pOrig_CreateThread);
    hook_engine_register(L"kernel32","ExitProcess",Hook_ExitProcess,(void**)&pOrig_ExitProcess);
    hook_engine_register(L"kernel32","CreateToolhelp32Snapshot",Hook_CreateToolhelp32Snapshot,(void**)&pOrig_Snap);
    hook_engine_register(L"kernel32","Process32FirstW",Hook_Process32FirstW,(void**)&pOrig_P32F);
    hook_engine_register(L"kernel32","Process32NextW",Hook_Process32NextW,(void**)&pOrig_P32N);
    hook_engine_register(L"shell32","ShellExecuteExW",Hook_ShellExecuteExW,(void**)&pOrig_ShellExec);
    hook_engine_register(L"kernel32","SuspendThread",Hook_SuspendThread,(void**)&pOrig_SuspendThread);
    hook_engine_register(L"kernel32","ResumeThread",Hook_ResumeThread,(void**)&pOrig_ResumeThread);
    hook_engine_register(L"kernel32","TerminateThread",Hook_TerminateThread,(void**)&pOrig_TermThread);
    hook_engine_register(L"kernel32","QueueUserAPC",Hook_QueueUserAPC,(void**)&pOrig_QueueAPC);
    hook_engine_register(L"kernel32","SetThreadContext",Hook_SetThreadContext,(void**)&pOrig_SetCtx);
    hook_engine_register(L"kernel32","GetThreadContext",Hook_GetThreadContext,(void**)&pOrig_GetCtx);
    hook_engine_register(L"kernel32","GetExitCodeProcess",Hook_GetExitCodeProcess,(void**)&pOrig_GetExitCode);
    hook_engine_register(L"advapi32","OpenProcessToken",Hook_OpenProcessToken,(void**)&pOrig_OpenProcTok);
}
