cmake_minimum_required(VERSION 3.15)
project(hook_monitor VERSION 1.0.0 LANGUAGES C)

# ============================================================
# KNOWHOW Malware Sandbox — Hook Monitor DLL
# ============================================================
# This CMake file builds the API hooking DLL that gets
# injected into target processes to capture API call sequences.
# ============================================================

# --- Build MinHook as a static library ---
# We include MinHook source directly so it compiles into our DLL
# (no external DLL dependency for MinHook itself)
set(MINHOOK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/minhook")

add_library(minhook STATIC
    ${MINHOOK_DIR}/src/buffer.c
    ${MINHOOK_DIR}/src/hook.c
    ${MINHOOK_DIR}/src/trampoline.c
    ${MINHOOK_DIR}/src/hde/hde32.c
    ${MINHOOK_DIR}/src/hde/hde64.c
)

target_include_directories(minhook PUBLIC
    ${MINHOOK_DIR}/include
)

# --- Build our Hook Monitor DLL ---
add_library(hook_monitor SHARED
    # Core
    src/dllmain.c
    src/logger.c
    src/hook_engine.c

    # Hook handlers (one file per category)
    src/hooks/hooks_file.c
    src/hooks/hooks_registry.c
    src/hooks/hooks_process.c
    src/hooks/hooks_network.c
    src/hooks/hooks_memory.c
    src/hooks/hooks_dll.c
    src/hooks/hooks_crypto.c
    src/hooks/hooks_system.c
    src/hooks/hooks_services.c
    src/hooks/hooks_sync.c
)

# Include directories for our source files
target_include_directories(hook_monitor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${MINHOOK_DIR}/include
)

# Link MinHook + Windows libraries
target_link_libraries(hook_monitor PRIVATE
    minhook
    ws2_32       # Winsock (for network hook typedefs)
    wininet      # WinINet (for HTTP hook typedefs)
    advapi32     # Registry + Crypto APIs
    shell32      # ShellExecuteEx
    ntdll        # Nt* functions
    bcrypt       # BCrypt APIs (modern crypto)
    user32       # Clipboard, keyboard, window hooks
)

# C standard
set_target_properties(hook_monitor PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    PREFIX ""                           # Output: hook_monitor.dll (no "lib" prefix)
    OUTPUT_NAME "hook_monitor"
)

# Compiler-specific flags
if(MSVC)
    target_compile_options(hook_monitor PRIVATE
        /W3             # Warning level 3
        /WX-            # Don't treat warnings as errors (for development)
        /D_CRT_SECURE_NO_WARNINGS   # Suppress CRT security warnings
        /DUNICODE /D_UNICODE         # Use Unicode APIs
        /DWIN32_LEAN_AND_MEAN        # Prevent winsock.h / winsock2.h conflict
    )
    target_compile_options(minhook PRIVATE
        /W0             # Suppress warnings for third-party code
        /D_CRT_SECURE_NO_WARNINGS
    )
endif()
