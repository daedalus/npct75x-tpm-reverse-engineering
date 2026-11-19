#!/usr/bin/env python3
"""Deep probe of vendor commands with likely params."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32, u16, u8, tpm2b, Reader
from tpm_re import tables

VENDOR_CC = [0x20000200, 0x20000201, 0x20000202, 0x20000203, 0x20000204,
             0x20000211, 0x20000213, 0x20000214, 0x20000216]

with DeviceTransport("/dev/tpmrm0") as t:
    for cc in VENDOR_CC:
        print(f"\n=== 0x{cc:08X} ===")
        # Try with empty params
        resp = t.transceive(build(cc, b""))
        print(f"  empty params: {'OK' if resp.ok else f'rc=0x{resp.rc:04X} {resp.describe()}'}")
        
        # Try with a simple parameter
        resp2 = t.transceive(build(cc, u32(1)))
        print(f"  param=1:      {'OK' if resp2.ok else f'rc=0x{resp2.rc:04X} {resp2.describe()}'}")
        
        if resp.ok and resp.params:
            print(f"  params: {resp.params.hex()}")
        if resp2.ok and resp2.params:
            print(f"  params(param=1): {resp2.params.hex()}")

# Test NV_ReadPublic on a vendor index to understand structure
print("\n=== NV_ReadPublic on interesting indices ===")
for idx in [0x01802006, 0x01C00002, 0x01C0000A]:
    try:
        from tpm_re import caps, device
        pub = device.nv_read_public(t, idx)
        print(f"NV 0x{idx:08X}: attributes={pub.attributes:#x}, data_size={pub.data_size}, auth_policy={pub.auth_policy.hex()}")
    except Exception as e:
        print(f"NV 0x{idx:08X}: error: {e}")

# Test what handles exist
print("\n=== Handles via capability ===")
handles = caps.handles(t, tables.CAP_HANDLES)
print(f"Handles: {[hex(h) for h in handles]}")
