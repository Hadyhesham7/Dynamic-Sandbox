/*
 * monitor_tester.c - Test program for snapshot-based monitors
 * ============================================================
 * Unlike api_exerciser (which cleans up after itself), this program
 * makes PERSISTENT changes that the file/registry/network monitors
 * can detect via before/after snapshots.
 *
 * Compile:
 *   cl /Fe:monitor_tester.exe monitor_tester.c ws2_32.lib advapi32.lib /nologo
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

/* ── Delay for DLL injection ── */
void wait_for_injection(void) {
    printf("[TESTER] Waiting 5 seconds for DLL injection...\n");
    Sleep(5000);
    printf("[TESTER] Starting tests...\n\n");
}

/* ── FILE TESTS: Create persistent files ── */
void test_file_changes(void) {
    char temp_path[MAX_PATH];
    char file1[MAX_PATH], file2[MAX_PATH], dir1[MAX_PATH];
    HANDLE hFile;
    DWORD written;
    const char *payload = "This is a simulated dropped payload file.\r\n"
                          "It contains configuration data for the malware.\r\n"
                          "C2_SERVER=192.168.1.100:4444\r\n";

    GetTempPathA(MAX_PATH, temp_path);

    /* Create a "dropped" executable (actually .txt but named .exe) */
    snprintf(file1, MAX_PATH, "%s\\sandbox_test_dropped.exe", temp_path);
    hFile = CreateFileA(file1, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, "MZ_FAKE_PE_HEADER", 17, &written, NULL);
        WriteFile(hFile, payload, (DWORD)strlen(payload), &written, NULL);
        CloseHandle(hFile);
        printf("[FILE] Created dropped executable: %s\n", file1);
    }

    /* Create a config file */
    snprintf(file2, MAX_PATH, "%s\\sandbox_test_config.dat", temp_path);
    hFile = CreateFileA(file2, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, payload, (DWORD)strlen(payload), &written, NULL);
        CloseHandle(hFile);
        printf("[FILE] Created config file: %s\n", file2);
    }

    /* Create a suspicious directory */
    snprintf(dir1, MAX_PATH, "%s\\sandbox_test_staging", temp_path);
    if (CreateDirectoryA(dir1, NULL)) {
        printf("[FILE] Created staging directory: %s\n", dir1);

        /* Drop a file inside it */
        char inner[MAX_PATH];
        snprintf(inner, MAX_PATH, "%s\\payload.dll", dir1);
        hFile = CreateFileA(inner, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            WriteFile(hFile, "MZ_FAKE_DLL", 11, &written, NULL);
            CloseHandle(hFile);
            printf("[FILE] Dropped DLL in staging: %s\n", inner);
        }
    }

    printf("[FILE] File tests complete (files left on disk for detection)\n\n");
}

/* ── REGISTRY TESTS: Create persistent registry entries ── */
void test_registry_changes(void) {
    HKEY hKey;
    LONG result;
    DWORD dw_val;

    /* Simulate persistence: write to HKCU\...\Run */
    result = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (result == ERROR_SUCCESS) {
        const char *val = "C:\\Temp\\sandbox_test_dropped.exe";
        RegSetValueExA(hKey, "SandboxTestPersistence", 0, REG_SZ,
                       (const BYTE *)val, (DWORD)strlen(val) + 1);
        RegCloseKey(hKey);
        printf("[REG] Set Run key: SandboxTestPersistence -> %s\n", val);
    }

    /* Create a custom test key with multiple values */
    result = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        "Software\\SandboxTest\\Config",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (result == ERROR_SUCCESS) {
        const char *c2 = "192.168.1.100:4444";
        RegSetValueExA(hKey, "C2Server", 0, REG_SZ,
                       (const BYTE *)c2, (DWORD)strlen(c2) + 1);

        dw_val = 1;
        RegSetValueExA(hKey, "Enabled", 0, REG_DWORD,
                       (const BYTE *)&dw_val, sizeof(dw_val));

        dw_val = 30;
        RegSetValueExA(hKey, "BeaconInterval", 0, REG_DWORD,
                       (const BYTE *)&dw_val, sizeof(dw_val));

        RegCloseKey(hKey);
        printf("[REG] Created SandboxTest\\Config with C2 settings\n");
    }

    printf("[REG] Registry tests complete (keys left for detection)\n\n");
}

/* ── NETWORK TESTS: Make connections ── */
void test_network_activity(void) {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in addr;
    const char *http_request = "GET /beacon HTTP/1.1\r\nHost: evil.com\r\n\r\n";

    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Connection 1: HTTP-like to localhost:8080 (suspicious port) */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock != INVALID_SOCKET) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(8080);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        printf("[NET] Connecting to 127.0.0.1:8080 (HTTP alt)...\n");
        connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        /* Send HTTP-like data (will fail but gets hooked) */
        send(sock, http_request, (int)strlen(http_request), 0);
        closesocket(sock);
    }

    /* Connection 2: Common RAT port */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock != INVALID_SOCKET) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(4444);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        printf("[NET] Connecting to 127.0.0.1:4444 (Metasploit)...\n");
        connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        closesocket(sock);
    }

    /* Connection 3: DNS lookup */
    printf("[NET] DNS lookup: evil-c2-server.com...\n");
    gethostbyname("evil-c2-server.com");

    printf("[NET] DNS lookup: update-checker.malware.net...\n");
    gethostbyname("update-checker.malware.net");

    WSACleanup();
    printf("[NET] Network tests complete\n\n");
}

/* ── MEMORY TESTS: Allocate suspicious memory ── */
void test_memory_behavior(void) {
    void *mem;
    DWORD old_prot;

    /* Allocate RWX memory (highly suspicious) */
    mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE);
    if (mem) {
        /* Write fake shellcode pattern */
        memset(mem, 0x90, 4096);  /* NOP sled */
        ((unsigned char *)mem)[0] = 0xCC;  /* INT 3 (breakpoint) */
        printf("[MEM] Allocated RWX memory at %p (4096 bytes)\n", mem);
        printf("[MEM] Wrote NOP sled + breakpoint pattern\n");
        /* Don't free — let the monitor detect it */
    }

    /* Another suspicious allocation */
    mem = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE,
                       PAGE_READWRITE);
    if (mem) {
        /* Change to executable */
        VirtualProtect(mem, 65536, PAGE_EXECUTE_READWRITE, &old_prot);
        memset(mem, 0x41, 65536);  /* 'A' pattern */
        printf("[MEM] Allocated + promoted to RWX: %p (64KB)\n", mem);
    }

    printf("[MEM] Memory tests complete\n\n");
}

/* ── CLEANUP FUNCTION (run separately after testing) ── */
void cleanup(void) {
    char temp_path[MAX_PATH];
    char path[MAX_PATH];

    printf("[CLEANUP] Removing test artifacts...\n");

    GetTempPathA(MAX_PATH, temp_path);

    /* Delete files */
    snprintf(path, MAX_PATH, "%s\\sandbox_test_dropped.exe", temp_path);
    DeleteFileA(path);
    snprintf(path, MAX_PATH, "%s\\sandbox_test_config.dat", temp_path);
    DeleteFileA(path);
    snprintf(path, MAX_PATH, "%s\\sandbox_test_staging\\payload.dll", temp_path);
    DeleteFileA(path);
    snprintf(path, MAX_PATH, "%s\\sandbox_test_staging", temp_path);
    RemoveDirectoryA(path);

    /* Delete registry keys */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "SandboxTestPersistence");
        RegCloseKey(hKey);
    }
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\SandboxTest\\Config");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\SandboxTest");

    printf("[CLEANUP] Done.\n");
}

int main(int argc, char *argv[]) {
    printf("==============================================\n");
    printf("  SANDBOX MONITOR TESTER\n");
    printf("==============================================\n");
    printf("  This program makes PERSISTENT changes to\n");
    printf("  test file, registry, and network monitors.\n");
    printf("==============================================\n\n");

    /* Check for cleanup mode */
    if (argc > 1 && strcmp(argv[1], "--cleanup") == 0) {
        cleanup();
        return 0;
    }

    wait_for_injection();

    test_file_changes();
    test_registry_changes();
    test_network_activity();
    test_memory_behavior();

    printf("==============================================\n");
    printf("  ALL TESTS COMPLETE\n");
    printf("  Files and registry keys left for detection.\n");
    printf("  Run with --cleanup to remove artifacts.\n");
    printf("==============================================\n");

    /* Give monitors time to capture */
    printf("\n[TESTER] Waiting 3 seconds before exit...\n");
    Sleep(3000);

    return 0;
}
