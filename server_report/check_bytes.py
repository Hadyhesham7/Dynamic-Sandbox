import ctypes, struct

k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

h_k32 = k32.GetModuleHandleW('kernel32')
h_kb = k32.GetModuleHandleW('kernelbase')

api = b'CreateFileW'
a_k32 = k32.GetProcAddress(h_k32, api)
a_kb = k32.GetProcAddress(h_kb, api)

print(f"kernel32!CreateFileW  @ 0x{a_k32:016X}")
print(f"kernelbase!CreateFileW @ 0x{a_kb:016X}")

# Read the JMP [rip+disp32] instruction at kernel32
# FF 25 XX XX XX XX = JMP [rip + disp32]
buf = (ctypes.c_ubyte * 6)()
ctypes.memmove(buf, a_k32, 6)

if buf[0] == 0xFF and buf[1] == 0x25:
    # Read the 4-byte displacement
    disp = struct.unpack('<i', bytes(buf[2:6]))[0]
    # RIP = instruction address + instruction length (6 bytes)
    rip_after = a_k32 + 6
    # Target address in memory that holds the actual function pointer
    target_ptr_addr = rip_after + disp
    
    # Read the 8-byte pointer at that location
    ptr_buf = (ctypes.c_ubyte * 8)()
    ctypes.memmove(ptr_buf, target_ptr_addr, 8)
    actual_target = struct.unpack('<Q', bytes(ptr_buf))[0]
    
    print(f"\nJMP [rip+0x{disp:X}]")
    print(f"  Pointer stored at: 0x{target_ptr_addr:016X}")
    print(f"  Actual JMP target: 0x{actual_target:016X}")
    print(f"  kernelbase addr:   0x{a_kb:016X}")
    print(f"  Match: {actual_target == a_kb}")

# Also check VirtualAlloc (48 FF 25 = different JMP encoding)
api2 = b'VirtualAlloc'
a_k32_va = k32.GetProcAddress(h_k32, api2)
a_kb_va = k32.GetProcAddress(h_kb, api2)

buf2 = (ctypes.c_ubyte * 8)()
ctypes.memmove(buf2, a_k32_va, 8)
print(f"\nVirtualAlloc:")
print(f"  kernel32  @ 0x{a_k32_va:016X}: {' '.join(f'{b:02X}' for b in buf2)}")

if buf2[0] == 0x48 and buf2[1] == 0xFF and buf2[2] == 0x25:
    disp = struct.unpack('<i', bytes(buf2[3:7]))[0]
    rip_after = a_k32_va + 7  # REX + FF 25 + 4 bytes = 7 bytes
    target_ptr_addr = rip_after + disp
    ptr_buf = (ctypes.c_ubyte * 8)()
    ctypes.memmove(ptr_buf, target_ptr_addr, 8)
    actual_target = struct.unpack('<Q', bytes(ptr_buf))[0]
    print(f"  JMP [rip+0x{disp:X}]")
    print(f"  Actual target: 0x{actual_target:016X}")
    print(f"  kernelbase:    0x{a_kb_va:016X}")
    print(f"  Match: {actual_target == a_kb_va}")
