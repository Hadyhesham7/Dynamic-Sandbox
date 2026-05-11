/*
 * hooks_services.c — Windows Services + Privilege Hooks (12 APIs)
 * Services: CreateServiceW/A, OpenServiceW/A, StartServiceW/A,
 *           ControlService, DeleteService, OpenSCManagerW/A
 * Privileges: AdjustTokenPrivileges, LookupPrivilegeValueW
 */
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

/* OpenSCManagerW */
typedef SC_HANDLE (WINAPI *PFN_OpenSCManagerW)(LPCWSTR,LPCWSTR,DWORD);
static PFN_OpenSCManagerW pOrig_OpenSCMW=NULL;
static SC_HANDLE WINAPI Hook_OpenSCManagerW(LPCWSTR m,LPCWSTR db,DWORD da) {
    SC_HANDLE res=pOrig_OpenSCMW(m,db,da); char ret[32],args[128];
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"dwDesiredAccess\":\"0x%08X\"",da);
    logger_log_call("OpenSCManagerW","SVC",args,ret); return res;
}

/* OpenSCManagerA */
typedef SC_HANDLE (WINAPI *PFN_OpenSCManagerA)(LPCSTR,LPCSTR,DWORD);
static PFN_OpenSCManagerA pOrig_OpenSCMA=NULL;
static SC_HANDLE WINAPI Hook_OpenSCManagerA(LPCSTR m,LPCSTR db,DWORD da) {
    SC_HANDLE res=pOrig_OpenSCMA(m,db,da); char ret[32],args[128];
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"dwDesiredAccess\":\"0x%08X\"",da);
    logger_log_call("OpenSCManagerA","SVC",args,ret); return res;
}

/* CreateServiceW */
typedef SC_HANDLE (WINAPI *PFN_CreateServiceW)(SC_HANDLE,LPCWSTR,LPCWSTR,DWORD,DWORD,DWORD,DWORD,LPCWSTR,LPCWSTR,LPDWORD,LPCWSTR,LPCWSTR,LPCWSTR);
static PFN_CreateServiceW pOrig_CreateSvcW=NULL;
static SC_HANDLE WINAPI Hook_CreateServiceW(SC_HANDLE scm,LPCWSTR sn,LPCWSTR dn,DWORD da,DWORD st,DWORD start,DWORD ec,LPCWSTR bp,LPCWSTR lg,LPDWORD tag,LPCWSTR dep,LPCWSTR act,LPCWSTR pw) {
    SC_HANDLE res=pOrig_CreateSvcW(scm,sn,dn,da,st,start,ec,bp,lg,tag,dep,act,pw);
    char name[512],path[1024],ret[32],args[1792];
    logger_format_wstr(name,sizeof(name),sn); logger_format_wstr(path,sizeof(path),bp);
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpServiceName\":\"%s\",\"lpBinaryPathName\":\"%s\",\"dwServiceType\":%lu,\"dwStartType\":%lu",name,path,st,start);
    logger_log_call("CreateServiceW","SVC",args,ret); return res;
}

/* CreateServiceA */
typedef SC_HANDLE (WINAPI *PFN_CreateServiceA)(SC_HANDLE,LPCSTR,LPCSTR,DWORD,DWORD,DWORD,DWORD,LPCSTR,LPCSTR,LPDWORD,LPCSTR,LPCSTR,LPCSTR);
static PFN_CreateServiceA pOrig_CreateSvcA=NULL;
static SC_HANDLE WINAPI Hook_CreateServiceA(SC_HANDLE scm,LPCSTR sn,LPCSTR dn,DWORD da,DWORD st,DWORD start,DWORD ec,LPCSTR bp,LPCSTR lg,LPDWORD tag,LPCSTR dep,LPCSTR act,LPCSTR pw) {
    SC_HANDLE res=pOrig_CreateSvcA(scm,sn,dn,da,st,start,ec,bp,lg,tag,dep,act,pw);
    char name[512],path[1024],ret[32],args[1792];
    logger_format_str(name,sizeof(name),sn); logger_format_str(path,sizeof(path),bp);
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpServiceName\":\"%s\",\"lpBinaryPathName\":\"%s\",\"dwServiceType\":%lu,\"dwStartType\":%lu",name,path,st,start);
    logger_log_call("CreateServiceA","SVC",args,ret); return res;
}

/* OpenServiceW */
typedef SC_HANDLE (WINAPI *PFN_OpenServiceW)(SC_HANDLE,LPCWSTR,DWORD);
static PFN_OpenServiceW pOrig_OpenSvcW=NULL;
static SC_HANDLE WINAPI Hook_OpenServiceW(SC_HANDLE scm,LPCWSTR sn,DWORD da) {
    SC_HANDLE res=pOrig_OpenSvcW(scm,sn,da); char name[512],ret[32],args[768];
    logger_format_wstr(name,sizeof(name),sn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpServiceName\":\"%s\",\"dwDesiredAccess\":\"0x%08X\"",name,da);
    logger_log_call("OpenServiceW","SVC",args,ret); return res;
}

/* OpenServiceA */
typedef SC_HANDLE (WINAPI *PFN_OpenServiceA)(SC_HANDLE,LPCSTR,DWORD);
static PFN_OpenServiceA pOrig_OpenSvcA=NULL;
static SC_HANDLE WINAPI Hook_OpenServiceA(SC_HANDLE scm,LPCSTR sn,DWORD da) {
    SC_HANDLE res=pOrig_OpenSvcA(scm,sn,da); char name[512],ret[32],args[768];
    logger_format_str(name,sizeof(name),sn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpServiceName\":\"%s\",\"dwDesiredAccess\":\"0x%08X\"",name,da);
    logger_log_call("OpenServiceA","SVC",args,ret); return res;
}

/* StartServiceW */
typedef BOOL (WINAPI *PFN_StartServiceW)(SC_HANDLE,DWORD,LPCWSTR*);
static PFN_StartServiceW pOrig_StartSvcW=NULL;
static BOOL WINAPI Hook_StartServiceW(SC_HANDLE h,DWORD argc,LPCWSTR* argv) {
    BOOL res=pOrig_StartSvcW(h,argc,argv); char ret[16],args[64];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"dwNumServiceArgs\":%lu",argc);
    logger_log_call("StartServiceW","SVC",args,ret); return res;
}

/* StartServiceA */
typedef BOOL (WINAPI *PFN_StartServiceA)(SC_HANDLE,DWORD,LPCSTR*);
static PFN_StartServiceA pOrig_StartSvcA=NULL;
static BOOL WINAPI Hook_StartServiceA(SC_HANDLE h,DWORD argc,LPCSTR* argv) {
    BOOL res=pOrig_StartSvcA(h,argc,argv); char ret[16],args[64];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"dwNumServiceArgs\":%lu",argc);
    logger_log_call("StartServiceA","SVC",args,ret); return res;
}

/* ControlService */
typedef BOOL (WINAPI *PFN_ControlService)(SC_HANDLE,DWORD,LPSERVICE_STATUS);
static PFN_ControlService pOrig_ControlSvc=NULL;
static BOOL WINAPI Hook_ControlService(SC_HANDLE h,DWORD ctrl,LPSERVICE_STATUS ss) {
    BOOL res=pOrig_ControlSvc(h,ctrl,ss); char ret[16],args[64];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"dwControl\":%lu",ctrl);
    logger_log_call("ControlService","SVC",args,ret); return res;
}

/* DeleteService */
typedef BOOL (WINAPI *PFN_DeleteService)(SC_HANDLE);
static PFN_DeleteService pOrig_DeleteSvc=NULL;
static BOOL WINAPI Hook_DeleteService(SC_HANDLE h) {
    BOOL res=pOrig_DeleteSvc(h); char ret[16];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    logger_log_call("DeleteService","SVC","",ret); return res;
}

/* AdjustTokenPrivileges — privilege escalation */
typedef BOOL (WINAPI *PFN_AdjustTokenPrivileges)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
static PFN_AdjustTokenPrivileges pOrig_AdjustPriv=NULL;
static BOOL WINAPI Hook_AdjustTokenPrivileges(HANDLE tok,BOOL dis,PTOKEN_PRIVILEGES np,DWORD bl,PTOKEN_PRIVILEGES pp,PDWORD rl) {
    BOOL res=pOrig_AdjustPriv(tok,dis,np,bl,pp,rl); char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"DisableAllPrivileges\":%s,\"PrivilegeCount\":%lu",dis?"true":"false",np?np->PrivilegeCount:0);
    logger_log_call("AdjustTokenPrivileges","SVC",args,ret); return res;
}

/* LookupPrivilegeValueW */
typedef BOOL (WINAPI *PFN_LookupPrivilegeValueW)(LPCWSTR,LPCWSTR,PLUID);
static PFN_LookupPrivilegeValueW pOrig_LookupPriv=NULL;
static BOOL WINAPI Hook_LookupPrivilegeValueW(LPCWSTR sys,LPCWSTR name,PLUID luid) {
    BOOL res=pOrig_LookupPriv(sys,name,luid); char n[256],ret[16],args[512];
    logger_format_wstr(n,sizeof(n),name); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpName\":\"%s\"",n);
    logger_log_call("LookupPrivilegeValueW","SVC",args,ret); return res;
}

void register_services_hooks(void) {
    hook_engine_register(L"advapi32","OpenSCManagerW",Hook_OpenSCManagerW,(void**)&pOrig_OpenSCMW);
    hook_engine_register(L"advapi32","OpenSCManagerA",Hook_OpenSCManagerA,(void**)&pOrig_OpenSCMA);
    hook_engine_register(L"advapi32","CreateServiceW",Hook_CreateServiceW,(void**)&pOrig_CreateSvcW);
    hook_engine_register(L"advapi32","CreateServiceA",Hook_CreateServiceA,(void**)&pOrig_CreateSvcA);
    hook_engine_register(L"advapi32","OpenServiceW",Hook_OpenServiceW,(void**)&pOrig_OpenSvcW);
    hook_engine_register(L"advapi32","OpenServiceA",Hook_OpenServiceA,(void**)&pOrig_OpenSvcA);
    hook_engine_register(L"advapi32","StartServiceW",Hook_StartServiceW,(void**)&pOrig_StartSvcW);
    hook_engine_register(L"advapi32","StartServiceA",Hook_StartServiceA,(void**)&pOrig_StartSvcA);
    hook_engine_register(L"advapi32","ControlService",Hook_ControlService,(void**)&pOrig_ControlSvc);
    hook_engine_register(L"advapi32","DeleteService",Hook_DeleteService,(void**)&pOrig_DeleteSvc);
    hook_engine_register(L"advapi32","AdjustTokenPrivileges",Hook_AdjustTokenPrivileges,(void**)&pOrig_AdjustPriv);
    hook_engine_register(L"advapi32","LookupPrivilegeValueW",Hook_LookupPrivilegeValueW,(void**)&pOrig_LookupPriv);
}
