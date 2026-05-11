/*
 * logger.c — Thread-safe named pipe logging system
 * =================================================
 * Sends JSON-formatted API call logs to the Python collector
 * via a named pipe. Uses CRITICAL_SECTION for thread safety.
 */

#include "logger.h"
#include <stdio.h>
#include <string.h>

/* --- Constants --- */
#define PIPE_NAME       L"\\\\.\\pipe\\sandbox_monitor"
#define LOG_BUF_SIZE    8192      /* Max size of a single log line */
#define CONNECT_TIMEOUT 5000     /* ms to wait for pipe connection */

/* --- Module State --- */
static HANDLE          g_pipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_lock;
static BOOL            g_initialized = FALSE;
static LARGE_INTEGER   g_freq;       /* Performance counter frequency */
static LARGE_INTEGER   g_start_time; /* Timestamp of logger init */

/*
 * Re-entrancy guard — prevents infinite recursion.
 * When our hook for WriteFile/CloseHandle/etc fires because
 * the LOGGER itself calls those APIs, we must NOT log that call.
 * Uses __declspec(thread) for per-thread guard.
 */
static __declspec(thread) int g_inside_hook = 0;

int logger_is_reentrant(void) { return g_inside_hook; }
void logger_enter_hook(void)  { g_inside_hook++; }
void logger_leave_hook(void)  { g_inside_hook--; }

/* ============================================================
 * Initialization / Shutdown
 * ============================================================ */

BOOL logger_init(void)
{
    if (g_initialized) return TRUE;

    InitializeCriticalSection(&g_lock);
    QueryPerformanceFrequency(&g_freq);
    QueryPerformanceCounter(&g_start_time);

    /* Try to connect to the named pipe (collector.py must be running) */
    g_pipe = CreateFileW(
        PIPE_NAME,
        GENERIC_WRITE,
        0,              /* No sharing */
        NULL,           /* Default security */
        OPEN_EXISTING,
        0,              /* Default attributes */
        NULL            /* No template */
    );

    if (g_pipe == INVALID_HANDLE_VALUE) {
        /* Pipe not available — try waiting for it */
        if (WaitNamedPipeW(PIPE_NAME, CONNECT_TIMEOUT)) {
            g_pipe = CreateFileW(
                PIPE_NAME, GENERIC_WRITE, 0, NULL,
                OPEN_EXISTING, 0, NULL
            );
        }
    }

    if (g_pipe == INVALID_HANDLE_VALUE) {
        /* Still can't connect — log to OutputDebugString as fallback */
        OutputDebugStringA("[SANDBOX] WARNING: Named pipe not available. "
                          "Logs will go to OutputDebugString.\n");
        g_initialized = TRUE;  /* Still mark as initialized for fallback mode */
        return FALSE;
    }

    /* Set pipe to message mode */
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(g_pipe, &mode, NULL, NULL);

    g_initialized = TRUE;

    /* Send initialization marker */
    logger_log_call("__sandbox_init__", "SYS", "", "OK");

    return TRUE;
}

void logger_shutdown(void)
{
    if (!g_initialized) return;

    /* Send shutdown marker */
    logger_log_call("__sandbox_shutdown__", "SYS", "", "OK");

    if (g_pipe != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_pipe);
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }

    DeleteCriticalSection(&g_lock);
    g_initialized = FALSE;
}

/* ============================================================
 * Core Logging
 * ============================================================ */

static double get_timestamp(void)
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (double)(now.QuadPart - g_start_time.QuadPart) / (double)g_freq.QuadPart;
}

void logger_log_call(
    const char* api_name,
    const char* category,
    const char* args_json,
    const char* ret_value)
{
    if (!g_initialized) return;

    /* Re-entrancy guard: if we're already inside a hook, don't log.
     * This prevents WriteFile->Hook_WriteFile->logger_log_call->WriteFile->... */
    if (g_inside_hook) return;
    g_inside_hook = 1;

    char buf[LOG_BUF_SIZE];
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    double timestamp = get_timestamp();

    /* Format as JSON line */
    int len;
    if (args_json && args_json[0] != '\0') {
        len = _snprintf(buf, sizeof(buf) - 2,
            "{\"api\":\"%s\",\"cat\":\"%s\",\"args\":{%s},\"ret\":\"%s\","
            "\"pid\":%lu,\"tid\":%lu,\"time\":%.6f}",
            api_name, category, args_json, ret_value,
            pid, tid, timestamp);
    } else {
        len = _snprintf(buf, sizeof(buf) - 2,
            "{\"api\":\"%s\",\"cat\":\"%s\",\"args\":{},\"ret\":\"%s\","
            "\"pid\":%lu,\"tid\":%lu,\"time\":%.6f}",
            api_name, category, ret_value,
            pid, tid, timestamp);
    }

    if (len < 0 || len >= (int)(sizeof(buf) - 2)) {
        len = (int)(sizeof(buf) - 3);
    }
    buf[len] = '\n';
    buf[len + 1] = '\0';

    /* Thread-safe write */
    EnterCriticalSection(&g_lock);

    if (g_pipe != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_pipe, buf, len + 1, &written, NULL);
    } else {
        /* Fallback: OutputDebugString */
        OutputDebugStringA(buf);
    }

    LeaveCriticalSection(&g_lock);

    g_inside_hook = 0;  /* Reset re-entrancy guard */
}

/* ============================================================
 * Formatting Utilities
 * ============================================================ */

const char* logger_format_wstr(char* buf, size_t buf_size, LPCWSTR wstr)
{
    if (!wstr) {
        _snprintf(buf, buf_size, "null");
        return buf;
    }

    /* Convert wide string to UTF-8, escaping special characters */
    char temp[2048];
    int converted = WideCharToMultiByte(
        CP_UTF8, 0, wstr, -1,
        temp, sizeof(temp) - 1,
        NULL, NULL
    );

    if (converted <= 0) {
        _snprintf(buf, buf_size, "(conversion failed)");
        return buf;
    }

    /* Escape backslashes and quotes for JSON */
    size_t j = 0;
    for (size_t i = 0; temp[i] && j < buf_size - 2; i++) {
        if (temp[i] == '\\') {
            if (j + 2 >= buf_size - 1) break;
            buf[j++] = '\\';
            buf[j++] = '\\';
        } else if (temp[i] == '"') {
            if (j + 2 >= buf_size - 1) break;
            buf[j++] = '\\';
            buf[j++] = '"';
        } else if (temp[i] == '\n') {
            if (j + 2 >= buf_size - 1) break;
            buf[j++] = '\\';
            buf[j++] = 'n';
        } else if (temp[i] == '\r') {
            if (j + 2 >= buf_size - 1) break;
            buf[j++] = '\\';
            buf[j++] = 'r';
        } else {
            buf[j++] = temp[i];
        }
    }
    buf[j] = '\0';

    return buf;
}

const char* logger_format_str(char* buf, size_t buf_size, LPCSTR str)
{
    if (!str) {
        _snprintf(buf, buf_size, "null");
        return buf;
    }

    /* Escape backslashes and quotes for JSON */
    size_t j = 0;
    for (size_t i = 0; str[i] && j < buf_size - 2; i++) {
        if (str[i] == '\\') {
            if (j + 2 >= buf_size - 1) break;
            buf[j++] = '\\';
            buf[j++] = '\\';
        } else if (str[i] == '"') {
            if (j + 2 >= buf_size - 1) break;
            buf[j++] = '\\';
            buf[j++] = '"';
        } else {
            buf[j++] = str[i];
        }
    }
    buf[j] = '\0';

    return buf;
}

const char* logger_format_hex(char* buf, size_t buf_size, DWORD value)
{
    _snprintf(buf, buf_size, "0x%08X", value);
    return buf;
}

const char* logger_format_ptr(char* buf, size_t buf_size, const void* ptr)
{
    if (!ptr) {
        _snprintf(buf, buf_size, "null");
    } else {
        _snprintf(buf, buf_size, "0x%p", ptr);
    }
    return buf;
}
