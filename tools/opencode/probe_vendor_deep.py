#!/usr/bin/env python3
"""Deep probe of vendor commands with various param structures."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32, u16, u8, tpm2b, Reader, password_auth
from tpm_re import tables

def hex_dump(data):
    return ' '.join(f'{b:02X}' for b in data)

with DeviceTransport("/dev/tpmrm0") as t:
    print("=== Vendor commands that succeeded with empty params ===")
    for cc in [0x20000204, 0x20000213, 0x20000216]:
        resp = t.transceive(build(cc, b""))
        print(f"  0x{cc:08X}: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")
        if resp.ok and resp.params:
            print(f"    params: {hex_dump(resp.params)}")

    print("\n=== Vendor commands needing handles/params - probe with different structures ===")
    
    # Try various parameter structures for commands that returned INSUFFICIENT
    # 0x20000200: INSUFFICIENT (handle 1) with empty, VALUE (handle 1) with param=1
    # 0x20000211: INSUFFICIENT (handle 1) with empty, VALUE (handle 1) with param=1
    
    for cc in [0x20000200, 0x20000211]:
        print(f"\n  0x{cc:08X}:")
        
        # Try with TPM_RH_OWNER (0x40000001) as handle
        for handle_val in [0x40000001, 0x4000000C, 0x40000009, 0x4000000D, 0x4000000B]:
            handles = u32(handle_val)
            params = u32(1)  # try a simple param
            resp = t.transceive(build(cc, params, handles=handles, auth_area=password_auth()))
            print(f"    handle={handle_val:#x} param=1: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")
            if resp.ok and resp.params:
                print(f"      params: {hex_dump(resp.params)}")

    # 0x20000201, 0x20000202, 0x20000203: INSUFFICIENT (parameter 1) with empty
    # 0x20000214: INSUFFICIENT (parameter 1) with empty
    
    print("\n=== Vendor commands needing parameters ===")
    for cc in [0x20000201, 0x20000202, 0x20000203, 0x20000214]:
        print(f"\n  0x{cc:08X}:")
        
        # Try with just u32 parameter
        for param in [u32(1), u32(0), u16(1), u16(0), b""]:
            resp = t.transceive(build(cc, param))
            status = 'OK' if resp.ok else f'rc=0x{resp.rc:04X}'
            print(f"    param={hex_dump(param)}: {status}")
            if resp.ok and resp.params:
                print(f"      params: {hex_dump(resp.params)}")

    # Try 0x20000204/0x20000213/0x20000216 with some params
    print("\n=== Vendor commands that worked - probe with params ===")
    for cc in [0x20000204, 0x20000213, 0x20000216]:
        print(f"\n  0x{cc:08X}:")
        for param in [u32(1), u32(0), u16(4), u16(0), u16(64), b"\x01"]:
            resp = t.transceive(build(cc, param))
            status = 'OK' if resp.ok else f'rc=0x{resp.rc:04X}'
            print(f"    param={hex_dump(param)}: {status}")
            if resp.ok and resp.params:
                print(f"      params: {hex_dump(resp.params)}")