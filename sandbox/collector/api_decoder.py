"""
api_decoder.py — API Argument Decoder
=======================================
Translates raw hex values and numeric constants from Windows API calls
into human-readable names.

Example:
    dwDesiredAccess: 0x40000000  →  GENERIC_WRITE
    flProtect: 0x00000040       →  PAGE_EXECUTE_READWRITE (RWX!)
    dwCreationDisposition: 0x02 →  CREATE_ALWAYS

Usage:
    from collector.api_decoder import decode_api_args
    decoded = decode_api_args("CreateFileA", {"dwDesiredAccess": "0x40000000"})
"""


# ── File Access Flags ──
FILE_ACCESS = {
    0x80000000: "GENERIC_READ",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",
    0xC0000000: "GENERIC_READ | GENERIC_WRITE",
    0x001F01FF: "FILE_ALL_ACCESS",
}

CREATION_DISPOSITION = {
    1: "CREATE_NEW",
    2: "CREATE_ALWAYS",
    3: "OPEN_EXISTING",
    4: "OPEN_ALWAYS",
    5: "TRUNCATE_EXISTING",
}

# ── Memory Protection ──
MEM_PROTECT = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE (RWX!)",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

MEM_ALLOC_TYPE = {
    0x1000: "MEM_COMMIT",
    0x2000: "MEM_RESERVE",
    0x3000: "MEM_COMMIT | MEM_RESERVE",
    0x80000: "MEM_RESET",
    0x100000: "MEM_TOP_DOWN",
    0x400000: "MEM_PHYSICAL",
    0x20000000: "MEM_LARGE_PAGES",
}

# ── Registry Root Keys ──
REG_HKEYS = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0x80000005: "HKEY_CURRENT_CONFIG",
    # 64-bit sign-extended
    0xFFFFFFFF80000000: "HKEY_CLASSES_ROOT",
    0xFFFFFFFF80000001: "HKEY_CURRENT_USER",
    0xFFFFFFFF80000002: "HKEY_LOCAL_MACHINE",
    0xFFFFFFFF80000003: "HKEY_USERS",
    0xFFFFFFFF80000005: "HKEY_CURRENT_CONFIG",
}

REG_VALUE_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ (Text String)",
    2: "REG_EXPAND_SZ (Expandable Text)",
    3: "REG_BINARY",
    4: "REG_DWORD (32-bit Integer)",
    5: "REG_DWORD_BIG_ENDIAN",
    7: "REG_MULTI_SZ (Multi-String)",
    11: "REG_QWORD (64-bit Integer)",
}

# ── Process Creation Flags ──
PROCESS_FLAGS = {
    0x00000001: "DEBUG_PROCESS",
    0x00000002: "DEBUG_ONLY_THIS_PROCESS",
    0x00000004: "CREATE_SUSPENDED",
    0x00000008: "DETACHED_PROCESS",
    0x00000010: "CREATE_NEW_CONSOLE",
    0x00000020: "NORMAL_PRIORITY_CLASS",
    0x00000080: "CREATE_NEW_PROCESS_GROUP",
    0x00000200: "CREATE_UNICODE_ENVIRONMENT",
    0x00000400: "CREATE_SEPARATE_WOW_VDM",
    0x08000000: "CREATE_NO_WINDOW",
}

# ── Socket Constants ──
SOCKET_AF = {
    0: "AF_UNSPEC",
    2: "AF_INET (IPv4)",
    23: "AF_INET6 (IPv6)",
}

SOCKET_TYPE = {
    1: "SOCK_STREAM (TCP)",
    2: "SOCK_DGRAM (UDP)",
    3: "SOCK_RAW",
}

SOCKET_PROTOCOL = {
    0: "IPPROTO_DEFAULT",
    6: "IPPROTO_TCP",
    17: "IPPROTO_UDP",
}

# ── Process Access Rights ──
PROCESS_ACCESS = {
    0x0001: "PROCESS_TERMINATE",
    0x0002: "PROCESS_CREATE_THREAD",
    0x0008: "PROCESS_VM_OPERATION",
    0x0010: "PROCESS_VM_READ",
    0x0020: "PROCESS_VM_WRITE",
    0x0040: "PROCESS_DUP_HANDLE",
    0x0400: "PROCESS_QUERY_INFORMATION",
    0x1000: "PROCESS_SYNCHRONIZE",
    0x001F0FFF: "PROCESS_ALL_ACCESS",
    0x1F0FFF: "PROCESS_ALL_ACCESS",
}


def _parse_hex(value):
    """Parse a hex string or integer into an integer."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        try:
            if value.startswith("0x") or value.startswith("0X"):
                return int(value, 16)
            return int(value)
        except (ValueError, TypeError):
            return None
    return None


def _lookup(value, table, combine_flags=False):
    """Look up a value in a decode table."""
    num = _parse_hex(value)
    if num is None:
        return None

    # Direct match
    if num in table:
        return table[num]

    if combine_flags:
        # Try to combine flags
        flags = []
        remaining = num
        for flag_val in sorted(table.keys(), reverse=True):
            if flag_val and (remaining & flag_val) == flag_val:
                flags.append(table[flag_val])
                remaining &= ~flag_val
        if flags:
            return " | ".join(flags)

    return None


# ── Per-API Decoders ──

def _decode_createfile(args):
    """Decode CreateFileA/W arguments."""
    decoded = {}
    da = args.get("dwDesiredAccess")
    if da:
        d = _lookup(da, FILE_ACCESS, combine_flags=True)
        if d:
            decoded["dwDesiredAccess"] = d

    cd = args.get("dwCreationDisposition")
    if cd:
        d = _lookup(cd, CREATION_DISPOSITION)
        if d:
            decoded["dwCreationDisposition"] = d
    return decoded


def _decode_virtualalloc(args):
    """Decode VirtualAlloc/VirtualAllocEx arguments."""
    decoded = {}
    prot = args.get("flProtect")
    if prot:
        d = _lookup(prot, MEM_PROTECT)
        if d:
            decoded["flProtect"] = d

    at = args.get("flAllocationType")
    if at:
        d = _lookup(at, MEM_ALLOC_TYPE, combine_flags=True)
        if d:
            decoded["flAllocationType"] = d
    return decoded


def _decode_virtualprotect(args):
    """Decode VirtualProtect arguments."""
    decoded = {}
    prot = args.get("flNewProtect")
    if prot:
        d = _lookup(prot, MEM_PROTECT)
        if d:
            decoded["flNewProtect"] = d
    return decoded


def _decode_regcreatekey(args):
    """Decode RegCreateKeyExA/W arguments."""
    decoded = {}
    hk = args.get("hKey")
    if hk:
        d = _lookup(hk, REG_HKEYS)
        if d:
            decoded["hKey"] = d
    return decoded


def _decode_regsetvalue(args):
    """Decode RegSetValueExA/W arguments."""
    decoded = {}
    dt = args.get("dwType")
    if dt is not None:
        d = _lookup(dt, REG_VALUE_TYPES)
        if d:
            decoded["dwType"] = d
    return decoded


def _decode_createprocess(args):
    """Decode CreateProcessA/W arguments."""
    decoded = {}
    flags = args.get("dwCreationFlags")
    if flags:
        d = _lookup(flags, PROCESS_FLAGS, combine_flags=True)
        if d:
            decoded["dwCreationFlags"] = d
    return decoded


def _decode_openprocess(args):
    """Decode OpenProcess arguments."""
    decoded = {}
    da = args.get("dwDesiredAccess")
    if da:
        d = _lookup(da, PROCESS_ACCESS, combine_flags=True)
        if d:
            decoded["dwDesiredAccess"] = d
    return decoded


def _decode_socket(args):
    """Decode socket() arguments."""
    decoded = {}
    af = args.get("af")
    if af is not None:
        d = _lookup(af, SOCKET_AF)
        if d:
            decoded["af"] = d

    st = args.get("type")
    if st is not None:
        d = _lookup(st, SOCKET_TYPE)
        if d:
            decoded["type"] = d

    proto = args.get("protocol")
    if proto is not None:
        d = _lookup(proto, SOCKET_PROTOCOL)
        if d:
            decoded["protocol"] = d
    return decoded


# ── API → Decoder Mapping ──

_DECODERS = {
    "CreateFileA": _decode_createfile,
    "CreateFileW": _decode_createfile,
    "VirtualAlloc": _decode_virtualalloc,
    "VirtualAllocEx": _decode_virtualalloc,
    "NtAllocateVirtualMemory": _decode_virtualalloc,
    "VirtualProtect": _decode_virtualprotect,
    "VirtualProtectEx": _decode_virtualprotect,
    "NtProtectVirtualMemory": _decode_virtualprotect,
    "RegCreateKeyExA": _decode_regcreatekey,
    "RegCreateKeyExW": _decode_regcreatekey,
    "RegOpenKeyExA": _decode_regcreatekey,
    "RegOpenKeyExW": _decode_regcreatekey,
    "RegSetValueExA": _decode_regsetvalue,
    "RegSetValueExW": _decode_regsetvalue,
    "CreateProcessA": _decode_createprocess,
    "CreateProcessW": _decode_createprocess,
    "OpenProcess": _decode_openprocess,
    "socket": _decode_socket,
}


def decode_api_args(api_name, arguments):
    """
    Decode raw API arguments into human-readable form.

    Args:
        api_name: Name of the API (e.g., "CreateFileA")
        arguments: dict of raw arguments

    Returns:
        dict of decoded argument names → readable values.
        Only includes arguments that were successfully decoded.
        Returns empty dict if no decoder exists for this API.
    """
    decoder = _DECODERS.get(api_name)
    if not decoder or not arguments:
        return {}
    try:
        return decoder(arguments)
    except Exception:
        return {}


def enrich_call(call):
    """
    Enrich a single API call dict with decoded arguments.
    Adds 'decoded_args' key alongside existing 'arguments'.

    Args:
        call: dict with 'api' and 'arguments' keys

    Returns:
        The same call dict, with 'decoded_args' added if applicable.
    """
    api = call.get("api", "")
    args = call.get("arguments", {})
    decoded = decode_api_args(api, args)
    if decoded:
        call["decoded_args"] = decoded
    return call


def format_decoded_args(decoded):
    """Format decoded args as a compact one-line string."""
    if not decoded:
        return ""
    parts = [f"{k}={v}" for k, v in decoded.items()]
    return " | ".join(parts)
"""
    >>> from collector.api_decoder import decode_api_args
    >>> decode_api_args("CreateFileA", {"dwDesiredAccess": "0x40000000", "dwCreationDisposition": "0x00000002"})
    {'dwDesiredAccess': 'GENERIC_WRITE', 'dwCreationDisposition': 'CREATE_ALWAYS'}
"""
