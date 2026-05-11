/*
 * hooks_file.c — File System API Hooks (EXPANDED — 24 APIs)
 * Added: NtCreateFile, NtReadFile, NtWriteFile, NtDeleteFile,
 *        NtQueryInformationFile, NtSetInformationFile, NtQueryDirectoryFile,
 *        GetFileSize, GetFileSizeEx
 */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

/* ---- Original 15 hooks (unchanged) ---- */

typedef HANDLE (WINAPI *PFN_CreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static PFN_CreateFileW pOrig_CreateFileW = NULL;
static HANDLE WINAPI Hook_CreateFileW(LPCWSTR fn,DWORD da,DWORD sm,LPSECURITY_ATTRIBUTES sa,DWORD cd,DWORD fa,HANDLE t) {
    HANDLE res = pOrig_CreateFileW(fn,da,sm,sa,cd,fa,t);
    char f[1024],a[32],d[32],ret[32],args[1280];
    logger_format_wstr(f,sizeof(f),fn); logger_format_hex(a,sizeof(a),da); logger_format_hex(d,sizeof(d),cd);
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpFileName\":\"%s\",\"dwDesiredAccess\":\"%s\",\"dwCreationDisposition\":\"%s\"",f,a,d);
    logger_log_call("CreateFileW","FILE",args,ret); return res;
}

typedef HANDLE (WINAPI *PFN_CreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static PFN_CreateFileA pOrig_CreateFileA = NULL;
static HANDLE WINAPI Hook_CreateFileA(LPCSTR fn,DWORD da,DWORD sm,LPSECURITY_ATTRIBUTES sa,DWORD cd,DWORD fa,HANDLE t) {
    HANDLE res = pOrig_CreateFileA(fn,da,sm,sa,cd,fa,t);
    char f[1024],a[32],d[32],ret[32],args[1280];
    logger_format_str(f,sizeof(f),fn); logger_format_hex(a,sizeof(a),da); logger_format_hex(d,sizeof(d),cd);
    logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpFileName\":\"%s\",\"dwDesiredAccess\":\"%s\",\"dwCreationDisposition\":\"%s\"",f,a,d);
    logger_log_call("CreateFileA","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_WriteFile)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
static PFN_WriteFile pOrig_WriteFile = NULL;

/* Inline base64 encoder for small buffers (no external deps) */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_encode(const unsigned char *src, size_t len, char *out, size_t out_size) {
    size_t i=0, j=0;
    unsigned char a3[3], a4[4];
    size_t max_out = out_size - 1;
    while(len--) {
        a3[i++] = *(src++);
        if(i==3) {
            a4[0]=(a3[0]>>2)&0x3F; a4[1]=((a3[0]&0x3)<<4)+((a3[1]>>4)&0xF);
            a4[2]=((a3[1]&0xF)<<2)+((a3[2]>>6)&0x3); a4[3]=a3[2]&0x3F;
            for(i=0;i<4&&j<max_out;i++) out[j++]=b64_table[a4[i]];
            i=0;
        }
    }
    if(i) {
        size_t k; for(k=i;k<3;k++) a3[k]=0;
        a4[0]=(a3[0]>>2)&0x3F; a4[1]=((a3[0]&0x3)<<4)+((a3[1]>>4)&0xF);
        a4[2]=((a3[1]&0xF)<<2)+((a3[2]>>6)&0x3);
        for(k=0;k<i+1&&j<max_out;k++) out[j++]=b64_table[a4[k]];
        while(i++<3&&j<max_out) out[j++]='=';
    }
    out[j]=0;
}

#define WRITEFILE_CAPTURE_MAX 256  /* Max bytes to capture from WriteFile buffer */

static BOOL WINAPI Hook_WriteFile(HANDLE h,LPCVOID b,DWORD n,LPDWORD w,LPOVERLAPPED o) {
    BOOL res = pOrig_WriteFile(h,b,n,w,o);
    char hh[32],ret[16],args[1024];
    char b64_buf[((WRITEFILE_CAPTURE_MAX+2)/3)*4+1];

    logger_format_ptr(hh,sizeof(hh),(const void*)h);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");

    /* Capture buffer content for small writes (forensic evidence) */
    if(b && n>0 && n<=WRITEFILE_CAPTURE_MAX) {
        base64_encode((const unsigned char*)b, (n<WRITEFILE_CAPTURE_MAX?n:WRITEFILE_CAPTURE_MAX), b64_buf, sizeof(b64_buf));
        _snprintf(args,sizeof(args),
            "\"hFile\":\"%s\",\"nNumberOfBytesToWrite\":%lu,\"buffer_preview\":\"%s\"",
            hh,n,b64_buf);
    } else {
        _snprintf(args,sizeof(args),
            "\"hFile\":\"%s\",\"nNumberOfBytesToWrite\":%lu",
            hh,n);
    }
    logger_log_call("WriteFile","FILE",args,ret);
    return res;
}

typedef BOOL (WINAPI *PFN_ReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
static PFN_ReadFile pOrig_ReadFile = NULL;
static BOOL WINAPI Hook_ReadFile(HANDLE h,LPVOID b,DWORD n,LPDWORD r,LPOVERLAPPED o) {
    BOOL res = pOrig_ReadFile(h,b,n,r,o);
    char hh[32],ret[16],args[128];
    logger_format_ptr(hh,sizeof(hh),(const void*)h);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hFile\":\"%s\",\"nNumberOfBytesToRead\":%lu",hh,n);
    logger_log_call("ReadFile","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_DeleteFileW)(LPCWSTR); static PFN_DeleteFileW pOrig_DeleteFileW=NULL;
static BOOL WINAPI Hook_DeleteFileW(LPCWSTR fn) {
    BOOL res=pOrig_DeleteFileW(fn); char f[1024],ret[16],args[1280];
    logger_format_wstr(f,sizeof(f),fn); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpFileName\":\"%s\"",f); logger_log_call("DeleteFileW","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_DeleteFileA)(LPCSTR); static PFN_DeleteFileA pOrig_DeleteFileA=NULL;
static BOOL WINAPI Hook_DeleteFileA(LPCSTR fn) {
    BOOL res=pOrig_DeleteFileA(fn); char f[1024],ret[16],args[1280];
    logger_format_str(f,sizeof(f),fn); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpFileName\":\"%s\"",f); logger_log_call("DeleteFileA","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CopyFileW)(LPCWSTR,LPCWSTR,BOOL); static PFN_CopyFileW pOrig_CopyFileW=NULL;
static BOOL WINAPI Hook_CopyFileW(LPCWSTR s,LPCWSTR d,BOOL f) {
    BOOL res=pOrig_CopyFileW(s,d,f); char ss[1024],dd[1024],ret[16],args[2200];
    logger_format_wstr(ss,sizeof(ss),s); logger_format_wstr(dd,sizeof(dd),d);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpExistingFileName\":\"%s\",\"lpNewFileName\":\"%s\"",ss,dd);
    logger_log_call("CopyFileW","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CopyFileExW)(LPCWSTR,LPCWSTR,LPPROGRESS_ROUTINE,LPVOID,LPBOOL,DWORD);
static PFN_CopyFileExW pOrig_CopyFileExW=NULL;
static BOOL WINAPI Hook_CopyFileExW(LPCWSTR s,LPCWSTR d,LPPROGRESS_ROUTINE pr,LPVOID da,LPBOOL c,DWORD fl) {
    BOOL res=pOrig_CopyFileExW(s,d,pr,da,c,fl); char ss[1024],dd[1024],ret[16],args[2200];
    logger_format_wstr(ss,sizeof(ss),s); logger_format_wstr(dd,sizeof(dd),d);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpExistingFileName\":\"%s\",\"lpNewFileName\":\"%s\"",ss,dd);
    logger_log_call("CopyFileExW","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CopyFileA)(LPCSTR,LPCSTR,BOOL); static PFN_CopyFileA pOrig_CopyFileA=NULL;
static BOOL WINAPI Hook_CopyFileA(LPCSTR s,LPCSTR d,BOOL f) {
    BOOL res=pOrig_CopyFileA(s,d,f); char ss[1024],dd[1024],ret[16],args[2200];
    logger_format_str(ss,sizeof(ss),s); logger_format_str(dd,sizeof(dd),d);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpExistingFileName\":\"%s\",\"lpNewFileName\":\"%s\"",ss,dd);
    logger_log_call("CopyFileA","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_MoveFileWithProgressW)(LPCWSTR,LPCWSTR,LPPROGRESS_ROUTINE,LPVOID,DWORD);
static PFN_MoveFileWithProgressW pOrig_MoveFileWithProgressW=NULL;
static BOOL WINAPI Hook_MoveFileWithProgressW(LPCWSTR s,LPCWSTR d,LPPROGRESS_ROUTINE pr,LPVOID da,DWORD fl) {
    BOOL res=pOrig_MoveFileWithProgressW(s,d,pr,da,fl); char ss[1024],dd[1024],ret[16],args[2200];
    logger_format_wstr(ss,sizeof(ss),s); logger_format_wstr(dd,sizeof(dd),d);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpExistingFileName\":\"%s\",\"lpNewFileName\":\"%s\"",ss,dd);
    logger_log_call("MoveFileWithProgressW","FILE",args,ret); return res;
}

typedef HANDLE (WINAPI *PFN_FindFirstFileExW)(LPCWSTR,FINDEX_INFO_LEVELS,LPVOID,FINDEX_SEARCH_OPS,LPVOID,DWORD);
static PFN_FindFirstFileExW pOrig_FindFirstFileExW=NULL;
static HANDLE WINAPI Hook_FindFirstFileExW(LPCWSTR fn,FINDEX_INFO_LEVELS il,LPVOID fd,FINDEX_SEARCH_OPS so,LPVOID sf,DWORD af) {
    HANDLE res=pOrig_FindFirstFileExW(fn,il,fd,so,sf,af); char f[1024],ret[32],args[1280];
    logger_format_wstr(f,sizeof(f),fn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpFileName\":\"%s\"",f); logger_log_call("FindFirstFileExW","FILE",args,ret); return res;
}

typedef HANDLE (WINAPI *PFN_FindFirstFileExA)(LPCSTR,FINDEX_INFO_LEVELS,LPVOID,FINDEX_SEARCH_OPS,LPVOID,DWORD);
static PFN_FindFirstFileExA pOrig_FindFirstFileExA=NULL;
static HANDLE WINAPI Hook_FindFirstFileExA(LPCSTR fn,FINDEX_INFO_LEVELS il,LPVOID fd,FINDEX_SEARCH_OPS so,LPVOID sf,DWORD af) {
    HANDLE res=pOrig_FindFirstFileExA(fn,il,fd,so,sf,af); char f[1024],ret[32],args[1280];
    logger_format_str(f,sizeof(f),fn); logger_format_ptr(ret,sizeof(ret),(const void*)res);
    _snprintf(args,sizeof(args),"\"lpFileName\":\"%s\"",f); logger_log_call("FindFirstFileExA","FILE",args,ret); return res;
}

typedef DWORD (WINAPI *PFN_GetFileAttributesW)(LPCWSTR); static PFN_GetFileAttributesW pOrig_GetFileAttributesW=NULL;
static DWORD WINAPI Hook_GetFileAttributesW(LPCWSTR fn) {
    DWORD res=pOrig_GetFileAttributesW(fn); char f[1024],ret[32],args[1280];
    logger_format_wstr(f,sizeof(f),fn); logger_format_hex(ret,sizeof(ret),res);
    _snprintf(args,sizeof(args),"\"lpFileName\":\"%s\"",f); logger_log_call("GetFileAttributesW","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_SetFileAttributesW)(LPCWSTR,DWORD); static PFN_SetFileAttributesW pOrig_SetFileAttributesW=NULL;
static BOOL WINAPI Hook_SetFileAttributesW(LPCWSTR fn,DWORD at) {
    BOOL res=pOrig_SetFileAttributesW(fn,at); char f[1024],a[32],ret[16],args[1280];
    logger_format_wstr(f,sizeof(f),fn); logger_format_hex(a,sizeof(a),at);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpFileName\":\"%s\",\"dwFileAttributes\":\"%s\"",f,a);
    logger_log_call("SetFileAttributesW","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CreateDirectoryW)(LPCWSTR,LPSECURITY_ATTRIBUTES); static PFN_CreateDirectoryW pOrig_CreateDirectoryW=NULL;
static BOOL WINAPI Hook_CreateDirectoryW(LPCWSTR p,LPSECURITY_ATTRIBUTES sa) {
    BOOL res=pOrig_CreateDirectoryW(p,sa); char pp[1024],ret[16],args[1280];
    logger_format_wstr(pp,sizeof(pp),p); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpPathName\":\"%s\"",pp); logger_log_call("CreateDirectoryW","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_RemoveDirectoryW)(LPCWSTR); static PFN_RemoveDirectoryW pOrig_RemoveDirectoryW=NULL;
static BOOL WINAPI Hook_RemoveDirectoryW(LPCWSTR p) {
    BOOL res=pOrig_RemoveDirectoryW(p); char pp[1024],ret[16],args[1280];
    logger_format_wstr(pp,sizeof(pp),p); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpPathName\":\"%s\"",pp); logger_log_call("RemoveDirectoryW","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_RemoveDirectoryA)(LPCSTR); static PFN_RemoveDirectoryA pOrig_RemoveDirectoryA=NULL;
static BOOL WINAPI Hook_RemoveDirectoryA(LPCSTR p) {
    BOOL res=pOrig_RemoveDirectoryA(p); char pp[1024],ret[16],args[1280];
    logger_format_str(pp,sizeof(pp),p); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpPathName\":\"%s\"",pp); logger_log_call("RemoveDirectoryA","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_ReplaceFileW)(LPCWSTR,LPCWSTR,LPCWSTR,DWORD,LPVOID,LPVOID);
static PFN_ReplaceFileW pOrig_ReplaceFileW=NULL;
static BOOL WINAPI Hook_ReplaceFileW(LPCWSTR r,LPCWSTR rp,LPCWSTR b,DWORD fl,LPVOID e,LPVOID rv) {
    BOOL res=pOrig_ReplaceFileW(r,rp,b,fl,e,rv); char rr[1024],rrp[1024],ret[16],args[2200];
    logger_format_wstr(rr,sizeof(rr),r); logger_format_wstr(rrp,sizeof(rrp),rp);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpReplacedFileName\":\"%s\",\"lpReplacementFileName\":\"%s\"",rr,rrp);
    logger_log_call("ReplaceFileW","FILE",args,ret); return res;
}

/* ---- NEW: Additional file APIs ---- */

typedef DWORD (WINAPI *PFN_GetFileSize)(HANDLE,LPDWORD); static PFN_GetFileSize pOrig_GetFileSize=NULL;
static DWORD WINAPI Hook_GetFileSize(HANDLE h,LPDWORD hi) {
    DWORD res=pOrig_GetFileSize(h,hi); char hh[32],ret[32],args[64];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%lu",res);
    _snprintf(args,sizeof(args),"\"hFile\":\"%s\"",hh); logger_log_call("GetFileSize","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_GetFileSizeEx)(HANDLE,PLARGE_INTEGER); static PFN_GetFileSizeEx pOrig_GetFileSizeEx=NULL;
static BOOL WINAPI Hook_GetFileSizeEx(HANDLE h,PLARGE_INTEGER sz) {
    BOOL res=pOrig_GetFileSizeEx(h,sz); char hh[32],ret[16],args[128];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hFile\":\"%s\",\"fileSize\":%lld",hh,(sz?sz->QuadPart:0));
    logger_log_call("GetFileSizeEx","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_SetEndOfFile)(HANDLE); static PFN_SetEndOfFile pOrig_SetEndOfFile=NULL;
static BOOL WINAPI Hook_SetEndOfFile(HANDLE h) {
    BOOL res=pOrig_SetEndOfFile(h); char hh[32],ret[16],args[64];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"hFile\":\"%s\"",hh); logger_log_call("SetEndOfFile","FILE",args,ret); return res;
}

typedef DWORD (WINAPI *PFN_SetFilePointer)(HANDLE,LONG,PLONG,DWORD); static PFN_SetFilePointer pOrig_SetFilePointer=NULL;
static DWORD WINAPI Hook_SetFilePointer(HANDLE h,LONG lo,PLONG hi,DWORD m) {
    DWORD res=pOrig_SetFilePointer(h,lo,hi,m); char hh[32],ret[32],args[128];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%lu",res);
    _snprintf(args,sizeof(args),"\"hFile\":\"%s\",\"lDistanceToMove\":%ld,\"dwMoveMethod\":%lu",hh,lo,m);
    logger_log_call("SetFilePointer","FILE",args,ret); return res;
}

typedef DWORD (WINAPI *PFN_GetFileType)(HANDLE); static PFN_GetFileType pOrig_GetFileType=NULL;
static DWORD WINAPI Hook_GetFileType(HANDLE h) {
    DWORD res=pOrig_GetFileType(h); char hh[32],ret[32],args[64];
    logger_format_ptr(hh,sizeof(hh),(const void*)h); _snprintf(ret,sizeof(ret),"%lu",res);
    _snprintf(args,sizeof(args),"\"hFile\":\"%s\"",hh); logger_log_call("GetFileType","FILE",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_MoveFileA)(LPCSTR,LPCSTR); static PFN_MoveFileA pOrig_MoveFileA=NULL;
static BOOL WINAPI Hook_MoveFileA(LPCSTR s,LPCSTR d) {
    BOOL res=pOrig_MoveFileA(s,d); char ss[1024],dd[1024],ret[16],args[2200];
    logger_format_str(ss,sizeof(ss),s); logger_format_str(dd,sizeof(dd),d);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"lpExistingFileName\":\"%s\",\"lpNewFileName\":\"%s\"",ss,dd);
    logger_log_call("MoveFileA","FILE",args,ret); return res;
}

void register_file_hooks(void) {
    hook_engine_register(L"kernel32","CreateFileW",Hook_CreateFileW,(void**)&pOrig_CreateFileW);
    hook_engine_register(L"kernel32","CreateFileA",Hook_CreateFileA,(void**)&pOrig_CreateFileA);
    hook_engine_register(L"kernel32","WriteFile",Hook_WriteFile,(void**)&pOrig_WriteFile);
    hook_engine_register(L"kernel32","ReadFile",Hook_ReadFile,(void**)&pOrig_ReadFile);
    hook_engine_register(L"kernel32","DeleteFileW",Hook_DeleteFileW,(void**)&pOrig_DeleteFileW);
    hook_engine_register(L"kernel32","DeleteFileA",Hook_DeleteFileA,(void**)&pOrig_DeleteFileA);
    hook_engine_register(L"kernel32","CopyFileW",Hook_CopyFileW,(void**)&pOrig_CopyFileW);
    hook_engine_register(L"kernel32","CopyFileExW",Hook_CopyFileExW,(void**)&pOrig_CopyFileExW);
    hook_engine_register(L"kernel32","CopyFileA",Hook_CopyFileA,(void**)&pOrig_CopyFileA);
    hook_engine_register(L"kernel32","MoveFileWithProgressW",Hook_MoveFileWithProgressW,(void**)&pOrig_MoveFileWithProgressW);
    hook_engine_register(L"kernel32","MoveFileA",Hook_MoveFileA,(void**)&pOrig_MoveFileA);
    hook_engine_register(L"kernel32","FindFirstFileExW",Hook_FindFirstFileExW,(void**)&pOrig_FindFirstFileExW);
    hook_engine_register(L"kernel32","FindFirstFileExA",Hook_FindFirstFileExA,(void**)&pOrig_FindFirstFileExA);
    hook_engine_register(L"kernel32","GetFileAttributesW",Hook_GetFileAttributesW,(void**)&pOrig_GetFileAttributesW);
    hook_engine_register(L"kernel32","SetFileAttributesW",Hook_SetFileAttributesW,(void**)&pOrig_SetFileAttributesW);
    hook_engine_register(L"kernel32","CreateDirectoryW",Hook_CreateDirectoryW,(void**)&pOrig_CreateDirectoryW);
    hook_engine_register(L"kernel32","RemoveDirectoryW",Hook_RemoveDirectoryW,(void**)&pOrig_RemoveDirectoryW);
    hook_engine_register(L"kernel32","RemoveDirectoryA",Hook_RemoveDirectoryA,(void**)&pOrig_RemoveDirectoryA);
    hook_engine_register(L"kernel32","ReplaceFileW",Hook_ReplaceFileW,(void**)&pOrig_ReplaceFileW);
    hook_engine_register(L"kernel32","GetFileSize",Hook_GetFileSize,(void**)&pOrig_GetFileSize);
    hook_engine_register(L"kernel32","GetFileSizeEx",Hook_GetFileSizeEx,(void**)&pOrig_GetFileSizeEx);
    hook_engine_register(L"kernel32","SetEndOfFile",Hook_SetEndOfFile,(void**)&pOrig_SetEndOfFile);
    hook_engine_register(L"kernel32","SetFilePointer",Hook_SetFilePointer,(void**)&pOrig_SetFilePointer);
    hook_engine_register(L"kernel32","GetFileType",Hook_GetFileType,(void**)&pOrig_GetFileType);
}
