#!/usr/bin/env python3
"""Probe vendor commands 0x20000200..0x20000216 with minimal params."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32, u16, password_auth, u8, tpm2b
from tpm_re import tables

CC_FIRMWARE_READ = 0x00000179

# Vendor command codes from the capability listing
VENDOR_CC = [0x20000200, 0x20000201, 0x20000202, 0x20000203, 0x20000204,
             0x20000211, 0x20000213, 0x20000214, 0x20000216]

with DeviceTransport("/dev/tpmrm0") as t:
    for cc in VENDOR_CC:
        # Try with empty params
        command = build(cc, b"")
        resp = t.transceive(command)
        status = "OK" if resp.ok else f"rc=0x{resp.rc:04X} {resp.describe()}"
        print(f"0x{cc:08X}: {status}")
        if resp.ok and resp.params:
            print(f"  params: {resp.params.hex()}")
    
    # Also try FirmwareRead with a parameter
    print("\nFirmwareRead (0x179) with param:")
    command = build(CC_FIRMWARE_READ, u32(0))
    resp = t.transceive(command)
    status = "OK" if resp.ok else f"rc=0x{resp.rc:04X} {resp.describe()}"
    print(f"  param=0: {status}")
    if resp.ok and resp.params:
        print(f"  params: {resp.params.hex()}")