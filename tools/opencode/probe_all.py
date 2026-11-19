#!/usr/bin/env python3
"""Comprehensive probe of remaining hypotheses."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, Reader, u32, u16, password_auth, u8, tpm2b
from tpm_re import tables
from tpm_re.device import nv_read_public, nv_read_hazard

def hex_dump(data):
    return ' '.join(f'{b:02X}' for b in data)

with DeviceTransport("/dev/tpmrm0") as t:
    # 1) NV_ReadPublic on indices with different auth policies
    print("=== NV_ReadPublic ===")
    for idx in [0x01C00002, 0x01C0000A]:
        try:
            pub = nv_read_public(t, idx)
            hazard = nv_read_hazard(pub)
            print(f"NV 0x{idx:08X}: attrs={pub.attributes:#x} name_alg={pub.name_alg:#x} "
                  f"auth_policy={pub.auth_policy.hex()!r} data_size={pub.data_size} hazard={hazard}")
        except Exception as e:
            print(f"NV 0x{idx:08X}: ERROR {e}")

    # 2) Vendor cmd 0x20000204 with handle=index+index (i.e., handles=[index, index])
    print("\n=== Vendor cmd 0x20000204 (handle=index+index, empty params) ===")
    for i in range(5):
        cc = 0x20000204
        handles = u32(i) + u32(i)  # index + index
        params = u16(4) + u16(0)   # size=4, offset=0
        auth_area = password_auth()
        command = build(cc, params, handles=handles, auth_area=auth_area)
        resp = t.transceive(command)
        status = "OK" if resp.ok else f"rc=0x{resp.rc:04X} {resp.describe()}"
        print(f"  i={i:#x} handles={hex_dump(handles)} params={hex_dump(params)}: {status}")

    # 3) Vendor cmd 0x20000213 with handle
    print("\n=== Vendor cmd 0x20000213 (handle=index+index, param=0200001a) ===")
    for i in range(3):
        cc = 0x20000213
        handles = u32(i) + u32(i)
        params = u16(64) + u16(0)  # size=64, offset=0
        auth_area = password_auth()
        command = build(cc, params, handles=handles, auth_area=auth_area)
        resp = t.transceive(command)
        status = "OK" if resp.ok else f"rc=0x{resp.rc:04X} {resp.describe()}"
        print(f"  i={i:#x} handles={hex_dump(handles)} params={hex_dump(params)}: {status}")

    # 4) Probe vendor cmd 0x20000214 with handle
    print("\n=== Vendor cmd 0x20000214 (handle=index+index, param=0200001a) ===")
    for i in range(3):
        cc = 0x20000214
        handles = u32(i) + u32(i)
        params = u16(4) + u16(0)
        auth_area = password_auth()
        command = build(cc, params, handles=handles, auth_area=auth_area)
        resp = t.transceive(command)
        status = "OK" if resp.ok else f"rc=0x{resp.rc:04X} {resp.describe()}"
        print(f"  i={i:#x} handles={hex_dump(handles)} params={hex_dump(params)}: {status}")

    # 5) NV_ReadPublic on 0x01802006 with various auth values (via auth_area param)
    print("\n=== NV_ReadPublic 0x01802006 with auth candidates ===")
    for pw in [b"", b"\x00", b"\x01", b"TPM"]:
        try:
            pub = nv_read_public(t, 0x01802006)
            hazard = nv_read_hazard(pub)
            print(f"  pw={pw!r}: attrs={pub.attributes:#x} auth_policy={pub.auth_policy.hex()!r} "
                  f"data_size={pub.data_size} hazard={hazard}")
        except Exception as e:
            print(f"  pw={pw!r}: ERROR {e}")

    # 6) NV_ReadPublic on 0x01C00002 (known to work with empty password)
    print("\n=== NV_ReadPublic 0x01C00002 (should work) ===")
    try:
        pub = nv_read_public(t, 0x01C00002)
        hazard = nv_read_hazard(pub)
        print(f"  OK: attrs={pub.attributes:#x} auth_policy={pub.auth_policy.hex()!r} "
              f"data_size={pub.data_size} hazard={hazard}")
    except Exception as e:
        print(f"  ERROR {e}")
