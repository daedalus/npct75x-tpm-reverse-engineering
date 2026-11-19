#!/usr/bin/env python3
"""Test whether vendor commands change TPM state affecting NV_ReadPublic."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32, u16, password_auth, Reader
from tpm_re import tables
from tpm_re.device import nv_read_public, nv_read_hazard

with DeviceTransport("/dev/tpmrm0") as t:
    # Baseline
    print("BASELINE 1: NV_ReadPublic(0x01C00002)")
    try:
        pub = nv_read_public(t, 0x01C00002)
        print(f"  OK: attrs={pub.attributes:#x} auth_policy={pub.auth_policy.hex()!r} data_size={pub.data_size}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # Run a vendor command that returns INSUFFICIENT (0x20000200 with handle=0x40000001, param=1 -> rc=0x0184)
    print("\nRUN VENDOR 0x20000200 (handle=0x40000001, param=1)")
    handles = u32(0x40000001)
    params = u32(1)
    auth_area = password_auth()
    command = build(0x20000200, params, handles=handles, auth_area=auth_area)
    resp = t.transceive(command)
    print(f"  rc=0x{resp.rc:04X} {'OK' if resp.ok else resp.describe()}")
    if resp.ok and resp.params:
        print(f"  params: {resp.params.hex()}")

    # Baseline again
    print("\nBASELINE 2: NV_ReadPublic(0x01C00002) after vendor cmd")
    try:
        pub = nv_read_public(t, 0x01C00002)
        print(f"  OK: attrs={pub.attributes:#x} auth_policy={pub.auth_policy.hex()!r} data_size={pub.data_size}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # Run another vendor cmd that returned OK (0x20000204 with empty params)
    print("\nRUN VENDOR 0x20000204 (empty params)")
    resp = t.transceive(build(0x20000204, b""))
    print(f"  0x20000204: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")
    if resp.ok and resp.params:
        print(f"  params: {resp.params.hex()}")

    print("\nBASELINE 3: NV_ReadPublic(0x01C00002) after OK vendor cmd")
    try:
        pub = nv_read_public(t, 0x01C00002)
        print(f"  OK: attrs={pub.attributes:#x} auth_policy={pub.auth_policy.hex()!r} data_size={pub.data_size}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # Run vendor cmd that needs handles and gave VALUE error
    print("\nRUN VENDOR 0x20000211 (handle=0x40000001, param=1)")
    handles = u32(0x40000001)
    params = u32(1)
    auth_area = password_auth()
    command = build(0x20000211, params, handles=handles, auth_area=auth_area)
    resp = t.transceive(command)
    print(f"  0x20000211: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")

    print("\nBASELINE 4: NV_ReadPublic(0x01C00002) after vendor 0x20000211")
    try:
        pub = nv_read_public(t, 0x01C00002)
        print(f"  OK: attrs={pub.attributes:#x} auth_policy={pub.auth_policy.hex()!r} data_size={pub.data_size}")
    except Exception as e:
        print(f"  ERROR: {e}")
