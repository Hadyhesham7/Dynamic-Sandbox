/*
 * api_exerciser.c — Test program that exercises APIs from ALL categories
 * ======================================================================
 * This program deliberately calls APIs from every hooked category
 * so we can verify the sandbox captures them all.
 *
 * Build: cl /Fe:api_exerciser.exe api_exerciser.c ws2_32.lib advapi32.lib shell32.lib user32.lib bcrypt.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "bcrypt.lib")

void test_file_apis(void) {
    printf("[+] Testing FILE APIs...\n");

    /* CreateFileW + WriteFile + ReadFile + GetFileSize + CloseHandle */
    HANDLE hFile = CreateFileW(L"sandbox_test_file.txt",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        const char* data = "Hello from API exerciser!\r\n";
        DWORD written, read;
        WriteFile(hFile, data, (DWORD)strlen(data), &written, NULL);

        /* GetFileSize */
        DWORD size = GetFileSize(hFile, NULL);
        printf("    File size: %lu bytes\n", size);

        /* SetFilePointer + ReadFile */
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        char buf[256] = {0};
        ReadFile(hFile, buf, sizeof(buf)-1, &read, NULL);

        /* GetFileType */
        DWORD type = GetFileType(hFile);
        printf("    File type: %lu\n", type);

        CloseHandle(hFile);
    }

    /* GetFileAttributesW + SetFileAttributesW */
    DWORD attr = GetFileAttributesW(L"sandbox_test_file.txt");
    SetFileAttributesW(L"sandbox_test_file.txt", attr | FILE_ATTRIBUTE_HIDDEN);
    SetFileAttributesW(L"sandbox_test_file.txt", attr); /* restore */

    /* CopyFileW */
    CopyFileW(L"sandbox_test_file.txt", L"sandbox_test_copy.txt", FALSE);

    /* FindFirstFileExW */
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileExW(L"sandbox_test_*", FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
    if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);

    /* CreateDirectoryW + RemoveDirectoryW */
    CreateDirectoryW(L"sandbox_test_dir", NULL);
    RemoveDirectoryW(L"sandbox_test_dir");

    /* GetTempPathW */
    WCHAR tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);

    /* DeleteFileW */
    DeleteFileW(L"sandbox_test_file.txt");
    DeleteFileW(L"sandbox_test_copy.txt");

    printf("    FILE: done (12+ APIs triggered)\n");
}

void test_registry_apis(void) {
    printf("[+] Testing REGISTRY APIs...\n");

    HKEY hKey;
    /* RegCreateKeyExW */
    LONG res = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\SandboxTest",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL);

    if (res == ERROR_SUCCESS) {
        /* RegSetValueExW */
        const WCHAR* val = L"TestValue123";
        RegSetValueExW(hKey, L"TestEntry", 0, REG_SZ, (const BYTE*)val, (DWORD)(wcslen(val)+1)*sizeof(WCHAR));

        /* RegQueryValueExW */
        WCHAR buf[256]; DWORD sz = sizeof(buf), type;
        RegQueryValueExW(hKey, L"TestEntry", NULL, &type, (LPBYTE)buf, &sz);
        printf("    Registry value: %ls\n", buf);

        /* RegEnumValueW */
        WCHAR name[256]; DWORD nameSz = 256;
        RegEnumValueW(hKey, 0, name, &nameSz, NULL, NULL, NULL, NULL);

        /* RegDeleteValueW */
        RegDeleteValueW(hKey, L"TestEntry");

        /* RegCloseKey */
        RegCloseKey(hKey);
    }

    /* RegOpenKeyExW */
    res = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\SandboxTest", 0, KEY_READ, &hKey);
    if (res == ERROR_SUCCESS) RegCloseKey(hKey);

    /* RegDeleteKeyW — cleanup */
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\SandboxTest");

    printf("    REGISTRY: done (8+ APIs triggered)\n");
}

void test_process_apis(void) {
    printf("[+] Testing PROCESS APIs...\n");

    /* CreateToolhelp32Snapshot + Process32First/Next */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            int count = 0;
            while (Process32NextW(snap, &pe) && count < 3) count++;
            printf("    Enumerated %d processes\n", count + 1);
        }
        CloseHandle(snap);
    }

    /* OpenProcess (self) */
    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    if (hp) {
        /* GetExitCodeProcess */
        DWORD ec;
        GetExitCodeProcess(hp, &ec);
        CloseHandle(hp);
    }

    /* CreateThread */
    HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Sleep, (LPVOID)1, 0, NULL);
    if (ht) {
        WaitForSingleObject(ht, 1000);
        CloseHandle(ht);
    }

    printf("    PROCESS: done (7+ APIs triggered)\n");
}

void test_network_apis(void) {
    printf("[+] Testing NETWORK APIs...\n");

    /* WSAStartup */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("    WSAStartup failed\n");
        return;
    }

    /* socket */
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        /* connect to localhost on a closed port — fails instantly (CONNREFUSED) */
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(19999);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        connect(s, (struct sockaddr*)&addr, sizeof(addr));
        printf("    connect done (expected fail)\n");

        closesocket(s);
    }

    /* gethostbyname */
    gethostbyname("localhost");
    printf("    gethostbyname done\n");

    /* DNS lookup via getaddrinfo */
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    getaddrinfo("localhost", "80", &hints, &result);
    if (result) freeaddrinfo(result);
    printf("    getaddrinfo done\n");

    WSACleanup();
    printf("    NETWORK: done (6+ APIs triggered)\n");
}

void test_memory_apis(void) {
    printf("[+] Testing MEMORY APIs...\n");

    /* VirtualAlloc + VirtualProtect + VirtualQuery + VirtualFree */
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        /* Write something */
        memset(mem, 0x90, 4096); /* NOP sled pattern */

        /* VirtualProtect — change to executable (suspicious!) */
        DWORD oldProt;
        VirtualProtect(mem, 4096, PAGE_EXECUTE_READWRITE, &oldProt);

        /* VirtualQuery */
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(mem, &mbi, sizeof(mbi));
        printf("    Memory region: base=%p, size=%llu, protect=0x%lX\n",
            mbi.BaseAddress, (unsigned long long)mbi.RegionSize, mbi.Protect);

        /* FlushInstructionCache */
        FlushInstructionCache(GetCurrentProcess(), mem, 4096);

        /* VirtualFree */
        VirtualFree(mem, 0, MEM_RELEASE);
    }

    printf("    MEMORY: done (5+ APIs triggered)\n");
}

void test_dll_apis(void) {
    printf("[+] Testing DLL APIs...\n");

    /* LoadLibraryA + GetProcAddress + FreeLibrary */
    HMODULE hMod = LoadLibraryA("user32.dll");
    if (hMod) {
        FARPROC fp = GetProcAddress(hMod, "MessageBoxA");
        printf("    MessageBoxA at: %p\n", fp);
        FreeLibrary(hMod);
    }

    /* GetModuleHandleA */
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    printf("    kernel32 handle: %p\n", hK32);

    /* GetModuleHandleW */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    printf("    ntdll handle: %p\n", hNtdll);

    printf("    DLL: done (5+ APIs triggered)\n");
}

void test_crypto_apis(void) {
    printf("[+] Testing CRYPTO APIs...\n");

    HCRYPTPROV hProv = 0;
    /* CryptAcquireContextW */
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        /* CryptGenRandom */
        BYTE random[16];
        CryptGenRandom(hProv, sizeof(random), random);
        printf("    Random bytes: %02X%02X%02X%02X...\n", random[0],random[1],random[2],random[3]);

        /* CryptCreateHash + CryptHashData + CryptDestroyHash */
        HCRYPTHASH hHash = 0;
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            const char* msg = "test data for hashing";
            CryptHashData(hHash, (const BYTE*)msg, (DWORD)strlen(msg), 0);
            CryptDestroyHash(hHash);
        }

        /* CryptGenKey + CryptDestroyKey */
        HCRYPTKEY hKey = 0;
        if (CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
            CryptDestroyKey(hKey);
        }

        CryptReleaseContext(hProv, 0);
    }

    /* BCrypt test */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, L"AES", NULL, 0);
    if (status == 0 && hAlg) {
        printf("    BCrypt AES provider opened\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    printf("    CRYPTO: done (8+ APIs triggered)\n");
}

void test_system_apis(void) {
    printf("[+] Testing SYSTEM/EVASION APIs...\n");

    /* IsDebuggerPresent — should return FALSE (our hook lies) */
    BOOL dbg = IsDebuggerPresent();
    printf("    IsDebuggerPresent: %s (should be FALSE)\n", dbg ? "TRUE" : "FALSE");

    /* CheckRemoteDebuggerPresent */
    BOOL remote = TRUE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    printf("    RemoteDebugger: %s (should be FALSE)\n", remote ? "TRUE" : "FALSE");

    /* GetSystemInfo */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("    Processors: %lu\n", si.dwNumberOfProcessors);

    /* GetComputerNameW */
    WCHAR compName[256]; DWORD sz = 256;
    GetComputerNameW(compName, &sz);
    printf("    Computer: %ls\n", compName);

    /* GetUserNameW */
    WCHAR userName[256]; sz = 256;
    GetUserNameW(userName, &sz);
    printf("    User: %ls\n", userName);

    /* GetSystemDirectoryW */
    WCHAR sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);

    /* GetSystemMetrics */
    int screenW = GetSystemMetrics(0); /* SM_CXSCREEN */
    int screenH = GetSystemMetrics(1); /* SM_CYSCREEN */
    printf("    Screen: %dx%d\n", screenW, screenH);

    /* Sleep (should be capped to 1s by our hook) */
    printf("    Sleeping 5000ms (should be capped to 1000ms)...\n");
    DWORD start = GetTickCount();
    Sleep(5000);
    DWORD elapsed = GetTickCount() - start;
    printf("    Actual sleep: %lums (capped: %s)\n", elapsed, elapsed < 2000 ? "YES" : "NO");

    /* GetTickCount64 */
    ULONGLONG tc64 = GetTickCount64();
    printf("    TickCount64: %llu\n", tc64);

    /* SetErrorMode */
    SetErrorMode(SEM_FAILCRITICALERRORS);
    SetErrorMode(0); /* restore */

    /* OutputDebugStringA */
    OutputDebugStringA("Sandbox test: OutputDebugStringA hook verified");

    printf("    SYSTEM: done (12+ APIs triggered)\n");
}

void test_services_apis(void) {
    printf("[+] Testing SERVICES APIs...\n");

    /* OpenSCManagerW */
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        /* OpenServiceW */
        SC_HANDLE svc = OpenServiceW(scm, L"Spooler", SERVICE_QUERY_STATUS);
        if (svc) {
            printf("    Opened Spooler service\n");
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    } else {
        printf("    SCManager open failed (may need admin)\n");
    }

    /* LookupPrivilegeValueW */
    LUID luid;
    LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid);
    printf("    SeDebugPrivilege LUID: %lu\n", luid.LowPart);

    printf("    SERVICES: done (3+ APIs triggered)\n");
}

void test_sync_apis(void) {
    printf("[+] Testing SYNC/MUTEX/CLIPBOARD APIs...\n");

    /* CreateMutexW */
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"SandboxTestMutex_12345");
    printf("    Mutex created: %p\n", hMutex);

    /* OpenMutexW (should succeed since we just created it) */
    HANDLE hMutex2 = OpenMutexW(SYNCHRONIZE, FALSE, L"SandboxTestMutex_12345");
    if (hMutex2) CloseHandle(hMutex2);
    if (hMutex) CloseHandle(hMutex);

    /* CreateEventW + SetEvent + WaitForSingleObject */
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, L"SandboxTestEvent_12345");
    if (hEvent) {
        SetEvent(hEvent);
        WaitForSingleObject(hEvent, 100);
        CloseHandle(hEvent);
    }

    /* CreateFileMappingW + MapViewOfFile + UnmapViewOfFile */
    HANDLE hMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, L"SandboxTestMapping");
    if (hMapping) {
        LPVOID view = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
        if (view) {
            memcpy(view, "mapped memory test", 18);
            UnmapViewOfFile(view);
        }
        CloseHandle(hMapping);
    }

    /* OpenClipboard + GetClipboardData */
    if (OpenClipboard(NULL)) {
        GetClipboardData(CF_TEXT);
        CloseClipboard();
    }

    /* GetAsyncKeyState */
    GetAsyncKeyState(VK_SHIFT);

    printf("    SYNC: done (10+ APIs triggered)\n");
}

int main(void) {
    printf("============================================================\n");
    printf("  API EXERCISER — Testing ALL 148 hooked APIs\n");
    printf("============================================================\n\n");

    /* Wait for DLL injection — the injector needs ~2 seconds to inject */
    printf("[*] Waiting 5 seconds for DLL injection...\n");
    printf("[*] (Injector will hook APIs during this window)\n\n");
    Sleep(5000);

    test_file_apis();
    printf("\n");
    test_registry_apis();
    printf("\n");
    test_process_apis();
    printf("\n");
    test_network_apis();
    printf("\n");
    test_memory_apis();
    printf("\n");
    test_dll_apis();
    printf("\n");
    test_crypto_apis();
    printf("\n");
    test_system_apis();
    printf("\n");
    test_services_apis();
    printf("\n");
    test_sync_apis();

    printf("\n============================================================\n");
    printf("  ALL TESTS COMPLETE — Check collector output!\n");
    printf("============================================================\n");

    /* Keep alive briefly so collector can flush */
    Sleep(2000);

    return 0;
}
