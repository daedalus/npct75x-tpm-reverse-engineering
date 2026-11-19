#!/usr/bin/env python3
"""Deep probe of vendor command structures and NV index 0x01802006 auth."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32, u16, password_auth, tpm2b, u8
from tpm_re import tables
from tpm_re.device import nv_read_public, nv_read_hazard

def hex_dump(data):
    return ' '.join(f'{b:02X}' for b in data)

def auth_with_password(password: bytes, session_handle=0x40000009, attrs=0x01):
    """Build authArea with given password (nonce empty for password session)."""
    structure = (
        u32(session_handle)
        + tpm2b(b"")
        + u8(attrs)
        + tpm2b(password)
    )
    return u32(len(structure)) + structure

with DeviceTransport("/dev/tpmrm0") as t:
    print("=" * 60)
    print("PROBE: Vendor cmd 0x20000214 with various handle + param combos")
    print("=" * 60)

    handle_candidates = [
        0x40000001,  # TPM_RH_OWNER
        0x40000002,  # TPM_RH_ENDORSEMENT
        0x40000003,  # TPM_RH_PLATFORM
        0x40000005,  # TPM_RH_EK
        0x40000006,  # TPM_RH_NULL
        0x40000009,  # TPM_RS_PW
        0x4000000A,  # TPM_RH_LOCKOUT
        0x4000000C,  # TPM_RH_EPM
    ]

    param_candidates = [
        u32(1),
        u32(0),
        u32(0x01800000),
        u32(0x01C00002),
        u32(0x01C0000A),
        u16(4),
        u16(64),
        b"\x01",
        b"\x00\x00\x00\x00",
    ]

    found = False
    for handle in handle_candidates:
        for param in param_candidates:
            handles = u32(handle)
            resp = t.transceive(build(0x20000214, param, handles=handles,
                                      auth_area=password_auth()))
            status = "OK" if resp.ok else f"rc=0x{resp.rc:04X}"
            if resp.ok:
                found = True
                print(f"\n  FOUND: handle=0x{handle:08X} param={hex_dump(param)}")
                print(f"    params: {hex_dump(resp.params)}")
                try:
                    pub = nv_read_public(t, 0x01C00002)
                    print(f"    NV_ReadPublic(0x01C00002): OK, attrs={pub.attributes:#x}")
                except Exception as e:
                    print(f"    NV_ReadPublic(0x01C00002): ERROR {e}")

    if not found:
        print("\n  No handle+param combination succeeded with 0x20000214")
        print("  Common failures: rc=0x0095 SIZE, 0x01DA INSUFFICIENT, 0x0184 VALUE")

    print("\n" + "=" * 60)
    print("PROBE: NV 0x01802006 auth candidates with custom password auth area")
    print("=" * 60)

    limited_auth = [
        b"",
        b"\x00",
        b"\x01",
        b"\xff",
        b"\x80\x00",
        b"\x00\x00",
        b"\x00\x01",
        b"\x01\x00",
        b"TPM",
        b"owner",
        b"platform",
        b"test123",
        b"\x00\x00\x00\x00",
        b"\x01\x02\x03\x04",
        b"\x00\x11\x22\x33",
        b"\xaa\xbb\xcc\xdd",
        b"NPCT",
        b"Nuvoton",
        b"1234",
        b"abcdef",
    ]

    print(f"Testing {len(limited_auth)} auth candidates for NV 0x01802006...")
    success = False
    for pw in limited_auth:
        try:
            auth_area = auth_with_password(pw)
            resp = t.transceive(build(tables.CC_NV_READ, u16(16) + u16(0),
                                    handles=u32(0x01802006) + u32(0x01802006),
                                    auth_area=auth_area))
            if resp.ok:
                success = True
                print(f"\n  SUCCESS with auth={pw!r}")
                print(f"    NV_Read returned {resp.params.hex()}")
                break
            elif resp.rc == 0x9A2:
                pass
            else:
                print(f"    auth={pw!r}: rc=0x{resp.rc:04X} {resp.describe()}")
        except Exception as e:
            print(f"    auth={pw!r}: exception {e}")

    if not success:
        print("\n  No auth value succeeded among tested candidates.")
        print("  Likely requires manufacturer-specific password from firmware/doc.")

    print("\n" + "=" * 60)
    print("PROBE: Vendor cmd 0x20000200 with index handle")
    print("=" * 60)
    for idx in [0x01802006, 0x01C00002, 0x01C0000A]:
        handles = u32(idx) + u32(idx)
        resp = t.transceive(build(0x20000200, u32(1), handles=handles,
                                  auth_area=password_auth()))
        print(f"  idx=0x{idx:08X}: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")
        if resp.ok and resp.params:
            print(f"    params: {hex_dump(resp.params)}")

    print("\n" + "=" * 60)
    print("PROBE: Vendor cmd 0x20000211 with index handle")
    print("=" * 60)
    for idx in [0x01802006, 0x01C00002, 0x01C0000A]:
        handles = u32(idx) + u32(idx)
        resp = t.transceive(build(0x20000211, u32(1), handles=handles,
                                  auth_area=password_auth()))
        print(f"  idx=0x{idx:08X}: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")
        if resp.ok and resp.params:
            print(f"    params: {hex_dump(resp.params)}")

    print("\n" + "=" * 60)
    print("PROBE: Vendor cmd 0x20000200 with owner handle + various params")
    print("=" * 60)
    handle = 0x40000001  # TPM_RH_OWNER
    for param_size in [0, 1, 2, 4, 8, 16]:
        for param_val in [0, 1, 0xFFFFFFFF, 0x01802006]:
            param = u32(param_val) if param_size == 4 else u16(param_val) if param_size == 2 else b""
            resp = t.transceive(build(0x20000200, param,
                                      handles=u32(handle),
                                      auth_area=password_auth()))
            print(f"  handle=0x{handle:08X} param=0x{param_val:x}({param_size}B): "
                  f"{'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")
            if resp.ok and resp.params:
                print(f"    params: {hex_dump(resp.params)}")