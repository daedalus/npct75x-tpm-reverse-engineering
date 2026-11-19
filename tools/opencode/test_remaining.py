#!/usr/bin/env python3
"""Test remaining vendor commands and NV 0x01802006 auth derivation."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32, u16, password_auth, tpm2b, u8
from tpm_re import tables
from tpm_re.device import nv_read_public, nv_read_hazard

def hex_dump(data):
    return ' '.join(f'{b:02X}' for b in data)

with DeviceTransport("/dev/tpmrm0") as t:
    print("=" * 60)
    print("TEST: Vendor commands 0x20000201/0x20000202/0x20000203")
    print("=" * 60)
    print("These returned INSUFFICIENT (parameter 1/2) with empty params")

    # Try various param structures
    param_sets = [
        (u32(1), b""),
        (u32(0), b""),
        (u16(1), b""),
        (u16(0), b""),
        (b"\x01", b""),
        (b"\x00\x00", b""),
        (u32(1), u32(2)),
        (u32(1), u16(2)),
        (u16(4), u32(1)),
    ]

    for cc in [0x20000201, 0x20000202, 0x20000203]:
        print(f"\n--- Vendor cmd 0x{cc:08X} ---")
        for p1, p2 in param_sets:
            combined = p1 + p2 if isinstance(p2, bytes) else p1 + p2
            resp = t.transceive(build(cc, combined))
            status = "OK" if resp.ok else f"rc=0x{resp.rc:04X}"
            if resp.ok:
                print(f"  param={hex_dump(combined)}: {status} -> params={hex_dump(resp.params) if resp.params else 'empty'}")
            else:
                if resp.rc not in [0x01DA, 0x02DA, 0x0095]:
                    print(f"  param={hex_dump(combined)}: {status}")

    print("\n" + "=" * 60)
    print("TEST: NV 0x01802006 auth from vendor property values")
    print("=" * 60)

    # Get current vendor property 0x1 value
    from tpm_re.caps import _get
    data, more = _get(t, tables.CAP_VENDOR_PROPERTY, 1, 1)
    # Parse: moreData(1) + capability(4) + count(4) + entries
    # Each entry: property(4) + value(4) = 8 bytes
    off = 1 + 4  # skip moreData and capability
    count = int.from_bytes(data[off:off+4], 'big')
    off += 4
    prop1_val = None
    for i in range(count):
        prop = int.from_bytes(data[off+i*8:off+i*8+4], 'big')
        val = int.from_bytes(data[off+i*8+4:off+i*8+8], 'big')
        if prop == 1:
            prop1_val = val
            print(f"  vendor property 0x1 = 0x{val:08X} ({val})")

    if prop1_val is not None:
        # Try vendor property value as auth (various encodings)
        candidates = []
        candidates.extend([
            prop1_val.to_bytes(4, 'big'),
            prop1_val.to_bytes(4, 'little'),
            prop1_val.to_bytes(16, 'big'),
            prop1_val.to_bytes(16, 'little'),
        ])
        # Also try XOR with something, shifts, etc.
        for i in range(256):
            candidates.append(bytes([i]))
            candidates.append(bytes([i] * 2))

        print(f"  Testing {len(candidates)} auth candidates derived from property 0x1...")
        found = False
        for pw in candidates:
            # Build proper auth area with password
            structure = (
                u32(0x40000009)   # session handle
                + tpm2b(b"")      # nonce empty
                + u8(0x01)        # session attributes
                + tpm2b(pw)       # password
            )
            auth_area = u32(len(structure)) + structure

            resp = t.transceive(build(tables.CC_NV_READ, u16(16) + u16(0),
                                    handles=u32(0x01802006) + u32(0x01802006),
                                    auth_area=auth_area))
            if resp.ok:
                found = True
                print(f"\n  SUCCESS with auth={pw!r}")
                print(f"    NV data: {hex_dump(resp.params)}")
                break
            # Skip BAD_AUTH
        if not found:
            print(f"  No auth candidate succeeded.")

    print("\n" + "=" * 60)
    print("TEST: Verify all vendor commands that return OK with empty params")
    print("=" * 60)
    for cc in [0x20000204, 0x20000213, 0x20000216]:
        resp = t.transceive(build(cc, b""))
        print(f"  0x{cc:08X}: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'} "
              f"params={hex_dump(resp.params) if resp.params else '(empty)'}")

    print("\n" + "=" * 60)
    print("TEST: Try vendor cmd 0x20000201/0x20000202/0x20000203 with handle")
    print("=" * 60)
    for cc in [0x20000201, 0x20000202, 0x20000203]:
        print(f"\n--- Vendor cmd 0x{cc:08X} with handles ---")
        for handle in [0x40000001, 0x40000003, 0x40000009]:
            for param in [b"", u32(1), u32(0)]:
                resp = t.transceive(build(cc, param, handles=u32(handle),
                                        auth_area=password_auth()))
                status = "OK" if resp.ok else f"rc=0x{resp.rc:04X}"
                if resp.ok or resp.rc not in [0x01DA, 0x02DA, 0x0095]:
                    print(f"  handle=0x{handle:08X} param={hex_dump(param)}: {status}")
                    if resp.ok and resp.params:
                        print(f"    params: {hex_dump(resp.params)}")

print("\nDone.")