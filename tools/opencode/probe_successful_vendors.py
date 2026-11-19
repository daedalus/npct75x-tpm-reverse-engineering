#!/usr/bin/env python3
"""Deep probe of vendor commands that returned OK with empty params."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32, u16, password_auth, Reader
from tpm_re import tables
from tpm_re.device import nv_read_public, nv_read_hazard

def hex_dump(data):
    return ' '.join(f'{b:02X}' for b in data)

with DeviceTransport("/dev/tpmrm0") as t:
    print("=" * 60)
    print("DETAILED ANALYSIS OF SUCCESSFUL VENDOR COMMANDS")
    print("=" * 60)

    # 0x20000204: params = 02 00 00 1A (4 bytes = 0x0000001A00000200 little-endian?)
    print("\n--- 0x20000204: params = 02 00 00 1A ---")
    resp = t.transceive(build(0x20000204, b""))
    if resp.ok:
        params = resp.params
        print(f"  Raw: {hex_dump(params)}")
        # Try different interpretations
        if len(params) == 4:
            le = int.from_bytes(params, 'little')
            be = int.from_bytes(params, 'big')
            print(f"  LE: 0x{le:08X} ({le})")
            print(f"  BE: 0x{be:08X} ({be})")
            # Could be two u16s
            u16_1 = int.from_bytes(params[0:2], 'little')
            u16_2 = int.from_bytes(params[2:4], 'little')
            print(f"  u16 LE: {u16_1}, {u16_2}")
            u16_1 = int.from_bytes(params[0:2], 'big')
            u16_2 = int.from_bytes(params[2:4], 'big')
            print(f"  u16 BE: {u16_1}, {u16_2}")

    # 0x20000213: params = FF FF A7 00 FB FF 7F FF FB FF FF FB F0 FF FF AA AA (16 bytes)
    print("\n--- 0x20000213: params = 16 bytes ---")
    resp = t.transceive(build(0x20000213, b""))
    if resp.ok:
        params = resp.params
        print(f"  Raw: {hex_dump(params)}")
        print(f"  Length: {len(params)} bytes")
        # Try as 4 u32s LE
        if len(params) == 16:
            for i in range(4):
                le = int.from_bytes(params[i*4:(i+1)*4], 'little')
                be = int.from_bytes(params[i*4:(i+1)*4], 'big')
                print(f"  Word {i}: LE=0x{le:08X} BE=0x{be:08X}")

    # 0x20000216: empty params
    print("\n--- 0x20000216: empty params ---")
    resp = t.transceive(build(0x20000216, b""))
    print(f"  Returns: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")

    print("\n" + "=" * 60)
    print("PROBE: Try vendor 0x20000204 with handle=0x40000001 (owner)")
    print("=" * 60)
    handles = u32(0x40000001)
    auth = password_auth()
    for param in [b"", u32(0), u32(1), u16(4), u16(64)]:
        resp = t.transceive(build(0x20000204, param, handles=handles, auth_area=auth))
        print(f"  param={hex_dump(param)}: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")
        if resp.ok and resp.params:
            print(f"    params: {hex_dump(resp.params)}")

    print("\n" + "=" * 60)
    print("PROBE: Try vendor 0x20000213 with handle=0x40000001 (owner)")
    print("=" * 60)
    for param in [b"", u32(0), u32(1), u16(4), u16(64)]:
        resp = t.transceive(build(0x20000213, param, handles=handles, auth_area=auth))
        print(f"  param={hex_dump(param)}: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")
        if resp.ok and resp.params:
            print(f"    params: {hex_dump(resp.params)}")

    print("\n" + "=" * 60)
    print("PROBE: Try vendor 0x20000216 with handle=0x40000001 (owner)")
    print("=" * 60)
    for param in [b"", u32(0), u32(1)]:
        resp = t.transceive(build(0x20000216, param, handles=handles, auth_area=auth))
        print(f"  param={hex_dump(param)}: {'OK' if resp.ok else f'rc=0x{resp.rc:04X}'}")
        if resp.ok and resp.params:
            print(f"    params: {hex_dump(resp.params)}")

    print("\n" + "=" * 60)
    print("SAMPLING: Vendor property 0x1 over longer interval")
    print("=" * 60)
    from tpm_re.caps import _get
    for i in range(5):
        data, more = _get(t, tables.CAP_VENDOR_PROPERTY, 1, 1)
        rd = Reader(data, label="TPML_TAGGED_TPM_PROPERTY")
        count = rd.u32()
        key = rd.u32() if count else 0
        value = rd.u32() if count else 0
        resp = t.transceive(build(0x00000181))  # ReadClock
        rd2 = Reader(resp.params, label="ReadClock")
        time_ms = rd2.u32()
        clock_ms = rd2.u32()
        print(f"  sample {i}: prop0x1=0x{value:08X} ({value}) time={time_ms} clock={clock_ms}")
        import time
        time.sleep(5)

    print("\n" + "=" * 60)
    print("CHECK: NV index 0x01802006 public area details")
    print("=" * 60)
    pub = nv_read_public(t, 0x01802006)
    print(f"  index: 0x{pub.index:08X}")
    print(f"  name_alg: 0x{pub.name_alg:04X} ({tables.ALG_NAMES.get(pub.name_alg)})")
    print(f"  attributes: 0x{pub.attributes:08X}")
    for flag, name in tables.NV_ATTR_BITS.items():
        if pub.attributes & flag:
            print(f"    {name}")
    type_code = (pub.attributes & tables.NV_TYPE_MASK) >> 4
    print(f"  type: NT_{tables.NV_TYPE_NAMES.get(type_code, f'0x{type_code:X}')}")
    print(f"  auth_policy: {pub.auth_policy.hex()!r}")
    print(f"  data_size: {pub.data_size}")
    print(f"  name: {pub.name.hex()}")