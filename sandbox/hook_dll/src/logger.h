/*
 * logger.h — Thread-safe named pipe logging system
 * =================================================
 * All hook handlers call these functions to log API calls.
 * Logs are sent as JSON lines via a named pipe to the
 * Python collector process.
 *
 * Thread Safety: Uses CRITICAL_SECTION to allow multiple
 * threads to log simultaneously without corruption.
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <windows.h>

/* --- Initialization / Shutdown --- */

/* Connect to the named pipe server (run collector.py first).
 * Returns TRUE on success, FALSE if pipe not available. */
BOOL logger_init(void);

/* Flush remaining data and close the pipe connection. */
void logger_shutdown(void);

/* --- Logging Functions --- */

/*
 * Log a single API call with its details.
 *
 * Parameters:
 *   api_name   - Name of the API (e.g., "CreateFileW")
 *   category   - Category string (e.g., "FILE", "REG", "NET")
 *   args_json  - Pre-formatted JSON string of arguments
 *                e.g., "\"lpFileName\":\"C:\\\\evil.txt\",\"dwAccess\":\"0x80000000\""
 *   ret_value  - Return value as string (e.g., "0x0000004C" or "TRUE")
 *
 * Output format (one JSON line per call):
 *   {"api":"CreateFileW","cat":"FILE","args":{...},"ret":"...","pid":1234,"tid":5678,"time":1700000.123}\n
 */
void logger_log_call(
    const char* api_name,
    const char* category,
    const char* args_json,
    const char* ret_value
);

/* --- Utility Helpers --- */

/* Format a wide string (LPCWSTR) safely for JSON output.
 * Handles NULL pointers, escapes backslashes and quotes.
 * Writes result into 'buf' (max 'buf_size' chars).
 * Returns pointer to buf for convenience. */
const char* logger_format_wstr(char* buf, size_t buf_size, LPCWSTR wstr);

/* Format a string (LPCSTR) safely for JSON output.
 * Handles NULL pointers, escapes backslashes and quotes. */
const char* logger_format_str(char* buf, size_t buf_size, LPCSTR str);

/* Format a DWORD as hex string (e.g., "0x80000000"). */
const char* logger_format_hex(char* buf, size_t buf_size, DWORD value);

/* Format a pointer as hex string (e.g., "0x00400000"). */
const char* logger_format_ptr(char* buf, size_t buf_size, const void* ptr);

/* --- Re-entrancy Guard ---
 * Prevents infinite recursion when our own hooks (WriteFile, CloseHandle,
 * GetModuleHandleA) fire during logger operations. */
int  logger_is_reentrant(void);
void logger_enter_hook(void);
void logger_leave_hook(void);

#endif /* LOGGER_H */
