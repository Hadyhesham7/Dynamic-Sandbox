/*
 * hooks_crypto.c — Cryptographic API Hooks (EXPANDED — 16 APIs)
 * CryptoAPI: CryptAcquireContextW, CryptEncrypt, CryptDecrypt, CryptGenKey,
 *            CryptImportKey, CryptExportKey, CryptCreateHash, CryptHashData,
 *            CryptGenRandom, CryptDeriveKey, CryptDestroyKey, CryptDestroyHash
 * BCrypt:    BCryptOpenAlgorithmProvider, BCryptEncrypt, BCryptDecrypt, BCryptGenerateSymmetricKey
 */
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

/* ---- Legacy CryptoAPI ---- */

typedef BOOL (WINAPI *PFN_CryptAcquireContextW)(HCRYPTPROV*,LPCWSTR,LPCWSTR,DWORD,DWORD);
static PFN_CryptAcquireContextW pO_CAC=NULL;
static BOOL WINAPI Hook_CryptAcquireContextW(HCRYPTPROV* pp,LPCWSTR c,LPCWSTR p,DWORD pt,DWORD fl) {
    BOOL res=pO_CAC(pp,c,p,pt,fl); char cn[512],pn[512],ret[16],args[1280];
    logger_format_wstr(cn,sizeof(cn),c); logger_format_wstr(pn,sizeof(pn),p);
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"szContainer\":\"%s\",\"szProvider\":\"%s\",\"dwProvType\":%lu",cn,pn,pt);
    logger_log_call("CryptAcquireContextW","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptEncrypt)(HCRYPTKEY,HCRYPTHASH,BOOL,DWORD,BYTE*,DWORD*,DWORD);
static PFN_CryptEncrypt pO_CE=NULL;
static BOOL WINAPI Hook_CryptEncrypt(HCRYPTKEY k,HCRYPTHASH h,BOOL final,DWORD fl,BYTE* d,DWORD* len,DWORD bl) {
    BOOL res=pO_CE(k,h,final,fl,d,len,bl); char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"Final\":%s,\"dwDataLen\":%lu",final?"true":"false",len?*len:0);
    logger_log_call("CryptEncrypt","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptDecrypt)(HCRYPTKEY,HCRYPTHASH,BOOL,DWORD,BYTE*,DWORD*);
static PFN_CryptDecrypt pO_CD=NULL;
static BOOL WINAPI Hook_CryptDecrypt(HCRYPTKEY k,HCRYPTHASH h,BOOL final,DWORD fl,BYTE* d,DWORD* len) {
    BOOL res=pO_CD(k,h,final,fl,d,len); char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"Final\":%s,\"dwDataLen\":%lu",final?"true":"false",len?*len:0);
    logger_log_call("CryptDecrypt","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptGenKey)(HCRYPTPROV,ALG_ID,DWORD,HCRYPTKEY*); static PFN_CryptGenKey pO_CGK=NULL;
static BOOL WINAPI Hook_CryptGenKey(HCRYPTPROV hp,ALG_ID algid,DWORD fl,HCRYPTKEY* pk) {
    BOOL res=pO_CGK(hp,algid,fl,pk); char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"Algid\":%u,\"dwFlags\":\"0x%08X\"",(unsigned)algid,fl);
    logger_log_call("CryptGenKey","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptImportKey)(HCRYPTPROV,const BYTE*,DWORD,HCRYPTKEY,DWORD,HCRYPTKEY*);
static PFN_CryptImportKey pO_CIK=NULL;
static BOOL WINAPI Hook_CryptImportKey(HCRYPTPROV hp,const BYTE* d,DWORD len,HCRYPTKEY pk,DWORD fl,HCRYPTKEY* out) {
    BOOL res=pO_CIK(hp,d,len,pk,fl,out); char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"dwDataLen\":%lu",len);
    logger_log_call("CryptImportKey","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptExportKey)(HCRYPTKEY,HCRYPTKEY,DWORD,DWORD,BYTE*,DWORD*);
static PFN_CryptExportKey pO_CEK=NULL;
static BOOL WINAPI Hook_CryptExportKey(HCRYPTKEY k,HCRYPTKEY ek,DWORD bt,DWORD fl,BYTE* d,DWORD* len) {
    BOOL res=pO_CEK(k,ek,bt,fl,d,len); char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"dwBlobType\":%lu,\"dwDataLen\":%lu",bt,len?*len:0);
    logger_log_call("CryptExportKey","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptCreateHash)(HCRYPTPROV,ALG_ID,HCRYPTKEY,DWORD,HCRYPTHASH*);
static PFN_CryptCreateHash pO_CCH=NULL;
static BOOL WINAPI Hook_CryptCreateHash(HCRYPTPROV hp,ALG_ID algid,HCRYPTKEY k,DWORD fl,HCRYPTHASH* ph) {
    BOOL res=pO_CCH(hp,algid,k,fl,ph); char ret[16],args[64];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"Algid\":%u",(unsigned)algid);
    logger_log_call("CryptCreateHash","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptHashData)(HCRYPTHASH,const BYTE*,DWORD,DWORD);
static PFN_CryptHashData pO_CHD=NULL;
static BOOL WINAPI Hook_CryptHashData(HCRYPTHASH h,const BYTE* d,DWORD len,DWORD fl) {
    BOOL res=pO_CHD(h,d,len,fl); char ret[16],args[64];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"dwDataLen\":%lu",len);
    logger_log_call("CryptHashData","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptGenRandom)(HCRYPTPROV,DWORD,BYTE*); static PFN_CryptGenRandom pO_CGR=NULL;
static BOOL WINAPI Hook_CryptGenRandom(HCRYPTPROV hp,DWORD len,BYTE* buf) {
    BOOL res=pO_CGR(hp,len,buf); char ret[16],args[64];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE"); _snprintf(args,sizeof(args),"\"dwLen\":%lu",len);
    logger_log_call("CryptGenRandom","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptDeriveKey)(HCRYPTPROV,ALG_ID,HCRYPTHASH,DWORD,HCRYPTKEY*);
static PFN_CryptDeriveKey pO_CDK=NULL;
static BOOL WINAPI Hook_CryptDeriveKey(HCRYPTPROV hp,ALG_ID algid,HCRYPTHASH hh,DWORD fl,HCRYPTKEY* pk) {
    BOOL res=pO_CDK(hp,algid,hh,fl,pk); char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    _snprintf(args,sizeof(args),"\"Algid\":%u",(unsigned)algid);
    logger_log_call("CryptDeriveKey","CRYPT",args,ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptDestroyKey)(HCRYPTKEY); static PFN_CryptDestroyKey pO_CDKy=NULL;
static BOOL WINAPI Hook_CryptDestroyKey(HCRYPTKEY k) {
    BOOL res=pO_CDKy(k); char ret[16]; _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    logger_log_call("CryptDestroyKey","CRYPT","",ret); return res;
}

typedef BOOL (WINAPI *PFN_CryptDestroyHash)(HCRYPTHASH); static PFN_CryptDestroyHash pO_CDH=NULL;
static BOOL WINAPI Hook_CryptDestroyHash(HCRYPTHASH h) {
    BOOL res=pO_CDH(h); char ret[16]; _snprintf(ret,sizeof(ret),"%s",res?"TRUE":"FALSE");
    logger_log_call("CryptDestroyHash","CRYPT","",ret); return res;
}

/* ---- BCrypt (modern crypto) ---- */

typedef NTSTATUS (WINAPI *PFN_BCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*,LPCWSTR,LPCWSTR,ULONG);
static PFN_BCryptOpenAlgorithmProvider pO_BOAP=NULL;
static NTSTATUS WINAPI Hook_BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* ph,LPCWSTR algid,LPCWSTR impl,ULONG fl) {
    NTSTATUS res=pO_BOAP(ph,algid,impl,fl); char n[256],ret[32],args[512];
    logger_format_wstr(n,sizeof(n),algid); _snprintf(ret,sizeof(ret),"0x%08X",(unsigned)res);
    _snprintf(args,sizeof(args),"\"pszAlgId\":\"%s\"",n);
    logger_log_call("BCryptOpenAlgorithmProvider","CRYPT",args,ret); return res;
}

typedef NTSTATUS (WINAPI *PFN_BCryptEncrypt)(BCRYPT_KEY_HANDLE,PUCHAR,ULONG,void*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
static PFN_BCryptEncrypt pO_BE=NULL;
static NTSTATUS WINAPI Hook_BCryptEncrypt(BCRYPT_KEY_HANDLE k,PUCHAR in,ULONG inl,void* pad,PUCHAR iv,ULONG ivl,PUCHAR out,ULONG outl,ULONG* result,ULONG fl) {
    NTSTATUS res=pO_BE(k,in,inl,pad,iv,ivl,out,outl,result,fl); char ret[32],args[128];
    _snprintf(ret,sizeof(ret),"0x%08X",(unsigned)res);
    _snprintf(args,sizeof(args),"\"cbInput\":%lu,\"cbOutput\":%lu",inl,outl);
    logger_log_call("BCryptEncrypt","CRYPT",args,ret); return res;
}

typedef NTSTATUS (WINAPI *PFN_BCryptDecrypt)(BCRYPT_KEY_HANDLE,PUCHAR,ULONG,void*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
static PFN_BCryptDecrypt pO_BD=NULL;
static NTSTATUS WINAPI Hook_BCryptDecrypt(BCRYPT_KEY_HANDLE k,PUCHAR in,ULONG inl,void* pad,PUCHAR iv,ULONG ivl,PUCHAR out,ULONG outl,ULONG* result,ULONG fl) {
    NTSTATUS res=pO_BD(k,in,inl,pad,iv,ivl,out,outl,result,fl); char ret[32],args[128];
    _snprintf(ret,sizeof(ret),"0x%08X",(unsigned)res);
    _snprintf(args,sizeof(args),"\"cbInput\":%lu,\"cbOutput\":%lu",inl,outl);
    logger_log_call("BCryptDecrypt","CRYPT",args,ret); return res;
}

typedef NTSTATUS (WINAPI *PFN_BCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
static PFN_BCryptGenerateSymmetricKey pO_BGSK=NULL;
static NTSTATUS WINAPI Hook_BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE a,BCRYPT_KEY_HANDLE* k,PUCHAR obj,ULONG objl,PUCHAR sec,ULONG secl,ULONG fl) {
    NTSTATUS res=pO_BGSK(a,k,obj,objl,sec,secl,fl); char ret[32],args[128];
    _snprintf(ret,sizeof(ret),"0x%08X",(unsigned)res);
    _snprintf(args,sizeof(args),"\"cbSecret\":%lu",secl);
    logger_log_call("BCryptGenerateSymmetricKey","CRYPT",args,ret); return res;
}

void register_crypto_hooks(void) {
    hook_engine_register(L"advapi32","CryptAcquireContextW",Hook_CryptAcquireContextW,(void**)&pO_CAC);
    hook_engine_register(L"advapi32","CryptEncrypt",Hook_CryptEncrypt,(void**)&pO_CE);
    hook_engine_register(L"advapi32","CryptDecrypt",Hook_CryptDecrypt,(void**)&pO_CD);
    hook_engine_register(L"advapi32","CryptGenKey",Hook_CryptGenKey,(void**)&pO_CGK);
    hook_engine_register(L"advapi32","CryptImportKey",Hook_CryptImportKey,(void**)&pO_CIK);
    hook_engine_register(L"advapi32","CryptExportKey",Hook_CryptExportKey,(void**)&pO_CEK);
    hook_engine_register(L"advapi32","CryptCreateHash",Hook_CryptCreateHash,(void**)&pO_CCH);
    hook_engine_register(L"advapi32","CryptHashData",Hook_CryptHashData,(void**)&pO_CHD);
    hook_engine_register(L"advapi32","CryptGenRandom",Hook_CryptGenRandom,(void**)&pO_CGR);
    hook_engine_register(L"advapi32","CryptDeriveKey",Hook_CryptDeriveKey,(void**)&pO_CDK);
    hook_engine_register(L"advapi32","CryptDestroyKey",Hook_CryptDestroyKey,(void**)&pO_CDKy);
    hook_engine_register(L"advapi32","CryptDestroyHash",Hook_CryptDestroyHash,(void**)&pO_CDH);
    hook_engine_register(L"bcrypt","BCryptOpenAlgorithmProvider",Hook_BCryptOpenAlgorithmProvider,(void**)&pO_BOAP);
    hook_engine_register(L"bcrypt","BCryptEncrypt",Hook_BCryptEncrypt,(void**)&pO_BE);
    hook_engine_register(L"bcrypt","BCryptDecrypt",Hook_BCryptDecrypt,(void**)&pO_BD);
    hook_engine_register(L"bcrypt","BCryptGenerateSymmetricKey",Hook_BCryptGenerateSymmetricKey,(void**)&pO_BGSK);
}
