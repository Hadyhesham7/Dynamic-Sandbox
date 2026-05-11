/*
 * hooks_registry.c — Registry API Hooks (13 APIs)
 */
#include <windows.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

/* RegCreateKeyExW */
typedef LSTATUS (WINAPI *PFN_RegCreateKeyExW)(HKEY,LPCWSTR,DWORD,LPWSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
static PFN_RegCreateKeyExW pOrig_RegCreateKeyExW = NULL;
static LSTATUS WINAPI Hook_RegCreateKeyExW(HKEY hKey,LPCWSTR lpSubKey,DWORD r,LPWSTR c,DWORD o,REGSAM s,LPSECURITY_ATTRIBUTES sa,PHKEY pk,LPDWORD pd) {
    LSTATUS res = pOrig_RegCreateKeyExW(hKey,lpSubKey,r,c,o,s,sa,pk,pd);
    char sk[1024],hk[32],ret[32],args[1280];
    logger_format_wstr(sk,sizeof(sk),lpSubKey); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpSubKey\":\"%s\"",hk,sk);
    logger_log_call("RegCreateKeyExW","REG",args,ret); return res;
}

/* RegCreateKeyExA */
typedef LSTATUS (WINAPI *PFN_RegCreateKeyExA)(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
static PFN_RegCreateKeyExA pOrig_RegCreateKeyExA = NULL;
static LSTATUS WINAPI Hook_RegCreateKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD r,LPSTR c,DWORD o,REGSAM s,LPSECURITY_ATTRIBUTES sa,PHKEY pk,LPDWORD pd) {
    LSTATUS res = pOrig_RegCreateKeyExA(hKey,lpSubKey,r,c,o,s,sa,pk,pd);
    char sk[1024],hk[32],ret[32],args[1280];
    logger_format_str(sk,sizeof(sk),lpSubKey); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpSubKey\":\"%s\"",hk,sk);
    logger_log_call("RegCreateKeyExA","REG",args,ret); return res;
}

/* RegSetValueExW */
typedef LSTATUS (WINAPI *PFN_RegSetValueExW)(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
static PFN_RegSetValueExW pOrig_RegSetValueExW = NULL;
static LSTATUS WINAPI Hook_RegSetValueExW(HKEY hKey,LPCWSTR vn,DWORD r,DWORD t,const BYTE* d,DWORD cb) {
    LSTATUS res = pOrig_RegSetValueExW(hKey,vn,r,t,d,cb);
    char name[512],hk[32],ret[32],ds[512],args[1536];
    logger_format_wstr(name,sizeof(name),vn); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    if((t==REG_SZ||t==REG_EXPAND_SZ)&&d) logger_format_wstr(ds,sizeof(ds),(LPCWSTR)d); else _snprintf(ds,sizeof(ds),"(%lu bytes)",cb);
    _snprintf(ret,sizeof(ret),"%ld",res);
    _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpValueName\":\"%s\",\"dwType\":%lu,\"data\":\"%s\"",hk,name,t,ds);
    logger_log_call("RegSetValueExW","REG",args,ret); return res;
}

/* RegSetValueExA */
typedef LSTATUS (WINAPI *PFN_RegSetValueExA)(HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD);
static PFN_RegSetValueExA pOrig_RegSetValueExA = NULL;
static LSTATUS WINAPI Hook_RegSetValueExA(HKEY hKey,LPCSTR vn,DWORD r,DWORD t,const BYTE* d,DWORD cb) {
    LSTATUS res = pOrig_RegSetValueExA(hKey,vn,r,t,d,cb);
    char name[512],hk[32],ret[32],ds[512],args[1536];
    logger_format_str(name,sizeof(name),vn); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    if((t==REG_SZ||t==REG_EXPAND_SZ)&&d) logger_format_str(ds,sizeof(ds),(LPCSTR)d); else _snprintf(ds,sizeof(ds),"(%lu bytes)",cb);
    _snprintf(ret,sizeof(ret),"%ld",res);
    _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpValueName\":\"%s\",\"dwType\":%lu,\"data\":\"%s\"",hk,name,t,ds);
    logger_log_call("RegSetValueExA","REG",args,ret); return res;
}

/* RegDeleteKeyW */
typedef LSTATUS (WINAPI *PFN_RegDeleteKeyW)(HKEY,LPCWSTR);
static PFN_RegDeleteKeyW pOrig_RegDeleteKeyW = NULL;
static LSTATUS WINAPI Hook_RegDeleteKeyW(HKEY hKey,LPCWSTR sk) {
    LSTATUS res = pOrig_RegDeleteKeyW(hKey,sk);
    char s[1024],hk[32],ret[32],args[1280];
    logger_format_wstr(s,sizeof(s),sk); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpSubKey\":\"%s\"",hk,s);
    logger_log_call("RegDeleteKeyW","REG",args,ret); return res;
}

/* RegDeleteValueW */
typedef LSTATUS (WINAPI *PFN_RegDeleteValueW)(HKEY,LPCWSTR);
static PFN_RegDeleteValueW pOrig_RegDeleteValueW = NULL;
static LSTATUS WINAPI Hook_RegDeleteValueW(HKEY hKey,LPCWSTR vn) {
    LSTATUS res = pOrig_RegDeleteValueW(hKey,vn);
    char n[512],hk[32],ret[32],args[768];
    logger_format_wstr(n,sizeof(n),vn); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpValueName\":\"%s\"",hk,n);
    logger_log_call("RegDeleteValueW","REG",args,ret); return res;
}

/* RegOpenKeyExW */
typedef LSTATUS (WINAPI *PFN_RegOpenKeyExW)(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);
static PFN_RegOpenKeyExW pOrig_RegOpenKeyExW = NULL;
static LSTATUS WINAPI Hook_RegOpenKeyExW(HKEY hKey,LPCWSTR sk,DWORD o,REGSAM s,PHKEY pk) {
    LSTATUS res = pOrig_RegOpenKeyExW(hKey,sk,o,s,pk);
    char sub[1024],hk[32],ret[32],args[1280];
    logger_format_wstr(sub,sizeof(sub),sk); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpSubKey\":\"%s\"",hk,sub);
    logger_log_call("RegOpenKeyExW","REG",args,ret); return res;
}

/* RegOpenKeyExA */
typedef LSTATUS (WINAPI *PFN_RegOpenKeyExA)(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
static PFN_RegOpenKeyExA pOrig_RegOpenKeyExA = NULL;
static LSTATUS WINAPI Hook_RegOpenKeyExA(HKEY hKey,LPCSTR sk,DWORD o,REGSAM s,PHKEY pk) {
    LSTATUS res = pOrig_RegOpenKeyExA(hKey,sk,o,s,pk);
    char sub[1024],hk[32],ret[32],args[1280];
    logger_format_str(sub,sizeof(sub),sk); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpSubKey\":\"%s\"",hk,sub);
    logger_log_call("RegOpenKeyExA","REG",args,ret); return res;
}

/* RegQueryValueExW */
typedef LSTATUS (WINAPI *PFN_RegQueryValueExW)(HKEY,LPCWSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);
static PFN_RegQueryValueExW pOrig_RegQueryValueExW = NULL;
static LSTATUS WINAPI Hook_RegQueryValueExW(HKEY hKey,LPCWSTR vn,LPDWORD r,LPDWORD t,LPBYTE d,LPDWORD cb) {
    LSTATUS res = pOrig_RegQueryValueExW(hKey,vn,r,t,d,cb);
    char n[512],hk[32],ret[32],args[768];
    logger_format_wstr(n,sizeof(n),vn); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpValueName\":\"%s\"",hk,n);
    logger_log_call("RegQueryValueExW","REG",args,ret); return res;
}

/* RegQueryValueExA */
typedef LSTATUS (WINAPI *PFN_RegQueryValueExA)(HKEY,LPCSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);
static PFN_RegQueryValueExA pOrig_RegQueryValueExA = NULL;
static LSTATUS WINAPI Hook_RegQueryValueExA(HKEY hKey,LPCSTR vn,LPDWORD r,LPDWORD t,LPBYTE d,LPDWORD cb) {
    LSTATUS res = pOrig_RegQueryValueExA(hKey,vn,r,t,d,cb);
    char n[512],hk[32],ret[32],args[768];
    logger_format_str(n,sizeof(n),vn); logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"lpValueName\":\"%s\"",hk,n);
    logger_log_call("RegQueryValueExA","REG",args,ret); return res;
}

/* RegEnumKeyExW */
typedef LSTATUS (WINAPI *PFN_RegEnumKeyExW)(HKEY,DWORD,LPWSTR,LPDWORD,LPDWORD,LPWSTR,LPDWORD,PFILETIME);
static PFN_RegEnumKeyExW pOrig_RegEnumKeyExW = NULL;
static LSTATUS WINAPI Hook_RegEnumKeyExW(HKEY hKey,DWORD i,LPWSTR n,LPDWORD cn,LPDWORD r,LPWSTR c,LPDWORD cc,PFILETIME ft) {
    LSTATUS res = pOrig_RegEnumKeyExW(hKey,i,n,cn,r,c,cc,ft);
    char hk[32],ret[32],args[128];
    logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"dwIndex\":%lu",hk,i);
    logger_log_call("RegEnumKeyExW","REG",args,ret); return res;
}

/* RegEnumValueW */
typedef LSTATUS (WINAPI *PFN_RegEnumValueW)(HKEY,DWORD,LPWSTR,LPDWORD,LPDWORD,LPDWORD,LPBYTE,LPDWORD);
static PFN_RegEnumValueW pOrig_RegEnumValueW = NULL;
static LSTATUS WINAPI Hook_RegEnumValueW(HKEY hKey,DWORD i,LPWSTR n,LPDWORD cn,LPDWORD r,LPDWORD t,LPBYTE d,LPDWORD cd) {
    LSTATUS res = pOrig_RegEnumValueW(hKey,i,n,cn,r,t,d,cd);
    char hk[32],ret[32],args[128];
    logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\",\"dwIndex\":%lu",hk,i);
    logger_log_call("RegEnumValueW","REG",args,ret); return res;
}

/* RegCloseKey */
typedef LSTATUS (WINAPI *PFN_RegCloseKey)(HKEY);
static PFN_RegCloseKey pOrig_RegCloseKey = NULL;
static LSTATUS WINAPI Hook_RegCloseKey(HKEY hKey) {
    LSTATUS res = pOrig_RegCloseKey(hKey);
    char hk[32],ret[32],args[64];
    logger_format_ptr(hk,sizeof(hk),(const void*)(uintptr_t)hKey);
    _snprintf(ret,sizeof(ret),"%ld",res); _snprintf(args,sizeof(args),"\"hKey\":\"%s\"",hk);
    logger_log_call("RegCloseKey","REG",args,ret); return res;
}

void register_registry_hooks(void) {
    hook_engine_register(L"advapi32","RegCreateKeyExW",Hook_RegCreateKeyExW,(void**)&pOrig_RegCreateKeyExW);
    hook_engine_register(L"advapi32","RegCreateKeyExA",Hook_RegCreateKeyExA,(void**)&pOrig_RegCreateKeyExA);
    hook_engine_register(L"advapi32","RegSetValueExW",Hook_RegSetValueExW,(void**)&pOrig_RegSetValueExW);
    hook_engine_register(L"advapi32","RegSetValueExA",Hook_RegSetValueExA,(void**)&pOrig_RegSetValueExA);
    hook_engine_register(L"advapi32","RegDeleteKeyW",Hook_RegDeleteKeyW,(void**)&pOrig_RegDeleteKeyW);
    hook_engine_register(L"advapi32","RegDeleteValueW",Hook_RegDeleteValueW,(void**)&pOrig_RegDeleteValueW);
    hook_engine_register(L"advapi32","RegOpenKeyExW",Hook_RegOpenKeyExW,(void**)&pOrig_RegOpenKeyExW);
    hook_engine_register(L"advapi32","RegOpenKeyExA",Hook_RegOpenKeyExA,(void**)&pOrig_RegOpenKeyExA);
    hook_engine_register(L"advapi32","RegQueryValueExW",Hook_RegQueryValueExW,(void**)&pOrig_RegQueryValueExW);
    hook_engine_register(L"advapi32","RegQueryValueExA",Hook_RegQueryValueExA,(void**)&pOrig_RegQueryValueExA);
    hook_engine_register(L"advapi32","RegEnumKeyExW",Hook_RegEnumKeyExW,(void**)&pOrig_RegEnumKeyExW);
    hook_engine_register(L"advapi32","RegEnumValueW",Hook_RegEnumValueW,(void**)&pOrig_RegEnumValueW);
    hook_engine_register(L"advapi32","RegCloseKey",Hook_RegCloseKey,(void**)&pOrig_RegCloseKey);
}
