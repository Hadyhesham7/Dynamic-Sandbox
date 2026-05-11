"""Create a test Office OLE file for sandbox testing (without COM)."""
import os
import struct

# Create a minimal OLE compound document that oletools can recognize
# This is a simplified OLE2 header that marks it as a .doc
doc_path = os.path.join("sandbox", "tests", "test_macro_doc.doc")

# OLE2 magic header
ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Create a minimal file that oletools recognizes as OLE
# But is too small for full parsing - enough to test routing
with open(doc_path, "wb") as f:
    # Write OLE2 header (minimum 512 bytes)
    header = bytearray(512)
    header[0:8] = ole_magic
    header[8:10] = b"\x00\x00"  # minor version
    header[10:12] = struct.pack("<H", 3)  # major version (3 = Office 2003)
    header[12:14] = struct.pack("<H", 0xFFFE)  # byte order (little-endian)
    header[14:16] = struct.pack("<H", 9)  # sector size power (2^9 = 512)
    header[16:18] = struct.pack("<H", 6)  # mini sector size power (2^6 = 64)
    f.write(header)
    
    # Add some padding to look like a real doc
    f.write(b"\x00" * 4096)

print(f"Created test OLE document: {doc_path} ({os.path.getsize(doc_path)} bytes)")
print("Note: This is a minimal OLE file for routing tests.")
print("For full macro testing, enable VBA project access in Word and run create_test_doc.py")
