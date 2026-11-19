#!/usr/bin/env python3
"""Test raw NV_Read with different auth candidates."""

import sys
import struct

def u32(x): return x & 0xffffffff
def u16(x): return x & 0xffff
def tpm2b(data): return bytes([len(data)]) + bytes(data) if data else b""

def make_auth_area(session_handle, password, attrs=0x01):
    """Create auth_area with empty nonce for password session."""
    # TPM_RS_PW password session: handle + empty nonce + attributes + empty hmac
    structure = struct.pack('>I', session_handle) + b'' + bytes([attrs]) + b''
    return struct.pack('>I', len(structure)) + structure

def build_nv_read_command(index, size, offset, password):
    """Build NV_Read command with password auth."""
    handles = u32(index) + u32(index)  # two handles = index + index
    params = u16(size) + u16(offset)
    auth_area = make_auth_area(0x40000009, password)  # TPM_RS_PW session handle
    return build(tables.CC_NV_READ, params, handles=handles, auth_area=auth_area)

def hex_dump(data):
    return ' '.join(f'{b:02X}' for b in data)

# Test NV_Read(0x01802006, 16, 0) with different auth candidates
index = 0x01802006
size = 16
offset = 0

print("Testing NV_Read(0x01802006, 16, 0) with different auth candidates:")
print("=" * 60)

# Try empty password (standard approach)
command = build_nv_read_command(index, size, offset, b"")
print(f"Empty password: {hex_dump(command)}")

# Try various password candidates
candidates = {
    "empty": b"",
    "00": b"\x00",
    "01": b"\x01",
    "0001": b"\x00\x01",
    "deadbeef": bytes.fromhex("deadbeef"),
    "NPCT": b"NPCT",
    "nvtest": b"nvtest",
    "test123": b"test123",
    "12345678": b"12345678",
}

for name, pw in candidates.items():
    try:
        command = build_nv_read_command(index, size, offset, pw)
        print(f"Password '{name}': {hex_dump(command)}")
    except Exception as e:
        print(f"Password '{name}': ERROR - {e}")

print("\n" + "=" * 60)
print("Sanity check: NV_Read(0x01C00002) with empty password (should work):")
command = build_nv_read_command(0x01C00002, 861, 0, b"")
print(f"Empty password: {hex_dump(command)}")