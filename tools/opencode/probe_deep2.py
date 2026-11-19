#!/usr/bin/env python3
"""Deep probe: vendor commands and NV auth continuation."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32, u16, password_auth, tpm2b, u8, Reader
from tpm_re import tables
from tpm_re import caps
from tpm_re.device import nv_read_public, nv_read_hazard

def hex_dump(data):
    return ' '.join(f'{b:02X}' for b in data)

with DeviceTransport("/dev/tpmrm0") as t:
    print("=" * 60)
    print("PROBE 1: Vendor cmd 0x20000216 deep analysis")
    print("=" * 60)
    
    for i in range(5):
        resp = t.transceive(build(0x20000216, b""))
        status = "OK" if resp.ok else f"rc=0x{resp.rc:04X}"
        print(f"  0x20000216 #{i}: {status} params={hex_dump(resp.params) if resp.params else '(empty)'}")

    print("\n" + "=" * 60)
    print("PROBE 2: Vendor cmd 0x20000213 deep analysis (all params)")
    print("=" * 60)
    
    # Get all vendor properties properly
    props = caps.vendor_properties(t)
    for p in props:
        print(f"  {p}")

    print("\n" + "=" * 60)
    print("PROBE 3: NV 0x01802006 - brute-force auth with common patterns")
    print("=" * 60)
    
    # Try auth derived from EK certificate strings, issuer, etc.
    # from the knowledge notes: issuer CN=NPCTxxx ECC384 LeafCA 022110, O=Nuvoton, C=TW
    
    auth_candidates = [
        b"Nuvoton", b"NPCT75x", b"Lenovo", b"TPM", b"owner", b"platform",
        b"TPM2", b"Nuvoton Technology", b"ECC384", b"LeafCA", b"NPCT",
        b"\x00" * 16, b"\x00" * 8, b"\x00" * 4, b"\x00" * 32, b"\x00" * 64,
        b"NPC", b"TPM2\0", b"PC", b"T", b"\x01\x02\x03\x04\x05\x06\x07\x08",
        b"ABCDEFGH", b"test", b"12345678", b"0123456789",
    ]
    
    # Add variations with issuer info
    for base in [b"Nuvoton", b"NPCT75x", b"TPM2", b"Lenovo", b"owner", b"platform"]:
        for suffix in [b"", b"-NPCT75x", b"-Nuvoton", b"-TPM", b"-Lenovo"]:
            auth_candidates.append(base + suffix)
        for suffix in [b"\x00", b"\x00\x00", b"\x00\x00\x00\x00"]:
            auth_candidates.append(base + suffix)
    
    print(f"Testing {len(auth_candidates)} auth candidates...")
    found = False
    for pw in auth_candidates:
        structure = (
            u32(0x40000009) + tpm2b(b"") + u8(0x01) + tpm2b(pw)
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
        elif resp.rc != 0x9A2:
            print(f"    auth={pw!r}: rc=0x{resp.rc:04X} {resp.describe()}")
    
    if not found:
        print("  No auth candidate succeeded.")
    
    print("\n" + "=" * 60)
    print("PROBE 4: NV 0x01802006 - try all vendor property values as auth")
    print("=" * 60)
    
    # Get vendor properties and try their values as auth
    props = caps.vendor_properties(t)
    for p in props:
        val = p.get('value', 0)
        for pw in [val.to_bytes(4, 'big'), val.to_bytes(4, 'little'),
                   val.to_bytes(8, 'big'), val.to_bytes(16, 'big'),
                   val.to_bytes(16, 'little')]:
            structure = u32(0x40000009) + tpm2b(b"") + u8(0x01) + tpm2b(pw)
            auth_area = u32(len(structure)) + structure
            resp = t.transceive(build(tables.CC_NV_READ, u16(16) + u16(0),
                                    handles=u32(0x01802006) + u32(0x01802006),
                                    auth_area=auth_area))
            if resp.ok:
                print(f"  SUCCESS with auth from prop {hex(p.get('property',0))}: {pw!r}")
                break
    
    print("\n" + "=" * 60)
    print("PROBE 5: Vendor cmd 0x20000211 with empty params + handles")
    print("=" * 60)
    
    # Try 0x20000211 with different handle types
    handles_to_try = [0x40000001, 0x40000002, 0x40000003, 0x40000005,
                      0x40000006, 0x40000009, 0x4000000A, 0x4000000C,
                      0x40000000, 0x40000004, 0x40000007, 0x40000008]
    for h in handles_to_try:
        handles = u32(h)
        resp = t.transceive(build(0x20000211, b"", handles=handles, auth_area=password_auth()))
        status = "OK" if resp.ok else f"rc=0x{resp.rc:04X}"
        print(f"  handle=0x{h:08X}: {status}")

print("\nDONE")