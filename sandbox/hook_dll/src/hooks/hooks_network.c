/*
 * hooks_network.c — Network API Hooks (12 APIs)
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include "../hook_engine.h"
#include "../logger.h"

/* Helper: format sockaddr to "IP:port" */
static void format_sockaddr(char* buf, size_t sz, const struct sockaddr* sa) {
    if (!sa) { _snprintf(buf,sz,"null"); return; }
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)sa;
        unsigned char* ip = (unsigned char*)&sin->sin_addr;
        _snprintf(buf,sz,"%u.%u.%u.%u:%u",ip[0],ip[1],ip[2],ip[3],ntohs(sin->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        _snprintf(buf,sz,"[IPv6]:%u",ntohs(((const struct sockaddr_in6*)sa)->sin6_port));
    } else {
        _snprintf(buf,sz,"family=%d",sa->sa_family);
    }
}

/* connect */
typedef int (WSAAPI *PFN_connect)(SOCKET,const struct sockaddr*,int);
static PFN_connect pOrig_connect = NULL;
static int WSAAPI Hook_connect(SOCKET s,const struct sockaddr* name,int namelen) {
    int res = pOrig_connect(s,name,namelen);
    char addr[128],ret[16],args[256];
    format_sockaddr(addr,sizeof(addr),name);
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"address\":\"%s\"", (unsigned long long)s, addr);
    logger_log_call("connect","NET",args,ret); return res;
}

/* send */
typedef int (WSAAPI *PFN_send)(SOCKET,const char*,int,int);
static PFN_send pOrig_send = NULL;
static int WSAAPI Hook_send(SOCKET s,const char* buf,int len,int flags) {
    int res = pOrig_send(s,buf,len,flags);
    char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"len\":%d",(unsigned long long)s,len);
    logger_log_call("send","NET",args,ret); return res;
}

/* recv */
typedef int (WSAAPI *PFN_recv)(SOCKET,char*,int,int);
static PFN_recv pOrig_recv = NULL;
static int WSAAPI Hook_recv(SOCKET s,char* buf,int len,int flags) {
    int res = pOrig_recv(s,buf,len,flags);
    char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"len\":%d",(unsigned long long)s,len);
    logger_log_call("recv","NET",args,ret); return res;
}

/* sendto */
typedef int (WSAAPI *PFN_sendto)(SOCKET,const char*,int,int,const struct sockaddr*,int);
static PFN_sendto pOrig_sendto = NULL;
static int WSAAPI Hook_sendto(SOCKET s,const char* buf,int len,int flags,const struct sockaddr* to,int tolen) {
    int res = pOrig_sendto(s,buf,len,flags,to,tolen);
    char addr[128],ret[16],args[256];
    format_sockaddr(addr,sizeof(addr),to);
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"len\":%d,\"to\":\"%s\"",(unsigned long long)s,len,addr);
    logger_log_call("sendto","NET",args,ret); return res;
}

/* recvfrom */
typedef int (WSAAPI *PFN_recvfrom)(SOCKET,char*,int,int,struct sockaddr*,int*);
static PFN_recvfrom pOrig_recvfrom = NULL;
static int WSAAPI Hook_recvfrom(SOCKET s,char* buf,int len,int flags,struct sockaddr* from,int* fromlen) {
    int res = pOrig_recvfrom(s,buf,len,flags,from,fromlen);
    char addr[128],ret[16],args[256];
    format_sockaddr(addr,sizeof(addr),from);
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"len\":%d,\"from\":\"%s\"",(unsigned long long)s,len,addr);
    logger_log_call("recvfrom","NET",args,ret); return res;
}

/* bind */
typedef int (WSAAPI *PFN_bind)(SOCKET,const struct sockaddr*,int);
static PFN_bind pOrig_bind = NULL;
static int WSAAPI Hook_bind(SOCKET s,const struct sockaddr* name,int namelen) {
    int res = pOrig_bind(s,name,namelen);
    char addr[128],ret[16],args[256];
    format_sockaddr(addr,sizeof(addr),name);
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"address\":\"%s\"",(unsigned long long)s,addr);
    logger_log_call("bind","NET",args,ret); return res;
}

/* listen */
typedef int (WSAAPI *PFN_listen)(SOCKET,int);
static PFN_listen pOrig_listen = NULL;
static int WSAAPI Hook_listen(SOCKET s,int backlog) {
    int res = pOrig_listen(s,backlog);
    char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"backlog\":%d",(unsigned long long)s,backlog);
    logger_log_call("listen","NET",args,ret); return res;
}

/* accept */
typedef SOCKET (WSAAPI *PFN_accept)(SOCKET,struct sockaddr*,int*);
static PFN_accept pOrig_accept = NULL;
static SOCKET WSAAPI Hook_accept(SOCKET s,struct sockaddr* addr,int* addrlen) {
    SOCKET res = pOrig_accept(s,addr,addrlen);
    char a[128],ret[32],args[256];
    format_sockaddr(a,sizeof(a),addr);
    _snprintf(ret,sizeof(ret),"%llu",(unsigned long long)res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"peer\":\"%s\"",(unsigned long long)s,a);
    logger_log_call("accept","NET",args,ret); return res;
}

/* closesocket */
typedef int (WSAAPI *PFN_closesocket)(SOCKET);
static PFN_closesocket pOrig_closesocket = NULL;
static int WSAAPI Hook_closesocket(SOCKET s) {
    int res = pOrig_closesocket(s);
    char ret[16],args[64];
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu",(unsigned long long)s);
    logger_log_call("closesocket","NET",args,ret); return res;
}

/* WSASend */
typedef int (WSAAPI *PFN_WSASend)(SOCKET,LPWSABUF,DWORD,LPDWORD,DWORD,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static PFN_WSASend pOrig_WSASend = NULL;
static int WSAAPI Hook_WSASend(SOCKET s,LPWSABUF bufs,DWORD cnt,LPDWORD sent,DWORD fl,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int res = pOrig_WSASend(s,bufs,cnt,sent,fl,ov,cr);
    char ret[16],args[128]; DWORD total=0;
    for(DWORD i=0;i<cnt;i++) total+=bufs[i].len;
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"totalBytes\":%lu",(unsigned long long)s,total);
    logger_log_call("WSASend","NET",args,ret); return res;
}

/* WSARecv */
typedef int (WSAAPI *PFN_WSARecv)(SOCKET,LPWSABUF,DWORD,LPDWORD,LPDWORD,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static PFN_WSARecv pOrig_WSARecv = NULL;
static int WSAAPI Hook_WSARecv(SOCKET s,LPWSABUF bufs,DWORD cnt,LPDWORD recvd,LPDWORD fl,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int res = pOrig_WSARecv(s,bufs,cnt,recvd,fl,ov,cr);
    char ret[16],args[128];
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"socket\":%llu,\"bufferCount\":%lu",(unsigned long long)s,cnt);
    logger_log_call("WSARecv","NET",args,ret); return res;
}

/* socket */
typedef SOCKET (WSAAPI *PFN_socket)(int,int,int);
static PFN_socket pOrig_socket = NULL;
static SOCKET WSAAPI Hook_socket(int af,int type,int protocol) {
    SOCKET res = pOrig_socket(af,type,protocol);
    char ret[32],args[128];
    _snprintf(ret,sizeof(ret),"%llu",(unsigned long long)res);
    _snprintf(args,sizeof(args),"\"af\":%d,\"type\":%d,\"protocol\":%d",af,type,protocol);
    logger_log_call("socket","NET",args,ret); return res;
}

/* gethostbyname */
typedef struct hostent* (WSAAPI *PFN_gethostbyname)(const char*);
static PFN_gethostbyname pOrig_gethostbyname = NULL;
static struct hostent* WSAAPI Hook_gethostbyname(const char* name) {
    /* Log BEFORE calling original to capture the hostname regardless of result */
    char n[512],args[768];
    logger_format_str(n,sizeof(n),name);
    _snprintf(args,sizeof(args),"\"name\":\"%s\"",n);
    struct hostent* res = pOrig_gethostbyname(name);
    logger_log_call("gethostbyname","NET",args,res?"OK":"NULL"); return res;
}

/* getaddrinfo */
typedef INT (WSAAPI *PFN_getaddrinfo)(PCSTR,PCSTR,const ADDRINFOA*,PADDRINFOA*);
static PFN_getaddrinfo pOrig_getaddrinfo = NULL;
static INT WSAAPI Hook_getaddrinfo(PCSTR nodename,PCSTR servname,const ADDRINFOA* hints,PADDRINFOA* result) {
    INT res = pOrig_getaddrinfo(nodename,servname,hints,result);
    char n[512],s[256],ret[16],args[1024];
    logger_format_str(n,sizeof(n),nodename);
    logger_format_str(s,sizeof(s),servname);
    _snprintf(ret,sizeof(ret),"%d",res);
    _snprintf(args,sizeof(args),"\"nodename\":\"%s\",\"servname\":\"%s\"",n,s);
    logger_log_call("getaddrinfo","NET",args,ret); return res;
}

void register_network_hooks(void) {
    hook_engine_register(L"ws2_32","socket",Hook_socket,(void**)&pOrig_socket);
    hook_engine_register(L"ws2_32","connect",Hook_connect,(void**)&pOrig_connect);
    hook_engine_register(L"ws2_32","send",Hook_send,(void**)&pOrig_send);
    hook_engine_register(L"ws2_32","recv",Hook_recv,(void**)&pOrig_recv);
    hook_engine_register(L"ws2_32","sendto",Hook_sendto,(void**)&pOrig_sendto);
    hook_engine_register(L"ws2_32","recvfrom",Hook_recvfrom,(void**)&pOrig_recvfrom);
    hook_engine_register(L"ws2_32","bind",Hook_bind,(void**)&pOrig_bind);
    hook_engine_register(L"ws2_32","listen",Hook_listen,(void**)&pOrig_listen);
    hook_engine_register(L"ws2_32","accept",Hook_accept,(void**)&pOrig_accept);
    hook_engine_register(L"ws2_32","closesocket",Hook_closesocket,(void**)&pOrig_closesocket);
    hook_engine_register(L"ws2_32","WSASend",Hook_WSASend,(void**)&pOrig_WSASend);
    hook_engine_register(L"ws2_32","WSARecv",Hook_WSARecv,(void**)&pOrig_WSARecv);
    hook_engine_register(L"ws2_32","gethostbyname",Hook_gethostbyname,(void**)&pOrig_gethostbyname);
    hook_engine_register(L"ws2_32","getaddrinfo",Hook_getaddrinfo,(void**)&pOrig_getaddrinfo);
}

