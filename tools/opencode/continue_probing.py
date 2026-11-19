#!/usr/bin/env python3
"""Continue probing remaining hypotheses."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32, u16, password_auth
from tpm_re import tables
from tpm_re.device import nv_read_public

with DeviceTransport("/dev/tpmrm0") as t:
    print("=" * 60)
    print("TEST: NV 0x01802006 with auth from vendor property 0x1 context")
    print("=" * 60)
    
    # Use the vendor property value as potential auth
    from tpm_re.caps import _get
    data, more = _get(t, tables.CAP_VENDOR_PROPERTY, 1, 1)
    rd = data  # skip reader init for now
    
    # Try NV 0x01802006 with vendor property value as password
    # The value 0x001BF9E3 was seen - try int.to_bytes
    print("Trying vendor property 0x1 values as NV auth...")
    for trial_val in [0x001BF9C9, 0x001BF9CD, 0x001BF9CF, 0x001BF9E3, 1833417, 1833421, 1833423]:
        pw = trial_val.to_bytes(4, 'big')
        auth_area = password_auth(pw)
        resp = t.transceive(build(tables.CC_NV_READ, u16(16) + u16(0),
                                handles=u32(0x01802006) + u32(0x01802006),
                                auth_area=auth_area))
        status = "OK" if resp.ok else f"rc=0x{resp.rc:04X}"
        print(f"  pw={trial_val} ({hex(pw)}): {status}")
        if resp.ok:
            print(f"    NV data: {resp.params.hex()}")
            break

    print("\n" + "=" * 60)
    print("TEST: NV 0x01802006 with read-only approaches")
    print("=" * 60)
    
    # Just read NV 0x01802006 with empty password to confirm error
    # Then try ReadClock correlation
    print("Verifying NV 0x01802006 always returns BAD_AUTH with empty password:")
    resp = t.transceive(build(tables.CC_NV_READ, u16(16) + u16(0),
                            handles=u32(0x01802006) + u32(0x01802006),
                            auth_area=password_auth()))
    print(f"  rc=0x{resp.rc:04X} {'OK' if resp.ok else resp.describe()}")

    # Verify NV_ReadPublic works
    print("\nNV_ReadPublic on 0x01C00002:")
    try:
        pub = nv_read_public(t, 0x01C00002)
        print(f"  OK: attrs={pub.attributes:#x} data_size={pub.data_size}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # Check that vendor property 0x1 is distinct from NV auth
    print("\nVendor property 0x1 samples:")
    for i in range(5):
        data, more = _get(t, tables.CAP_VENDOR_PROPERTY, 1, 1)
        rd = type('R', (), ('u32', lambda self: int.from_bytes(self.data[self.off:self.off+4], 'little')))()
        # Simpler - use the caps module function
        pass

    from tpm_re.caps import vendor_properties
    props = vendor_properties(t)
    print(f"  Current vendor properties: {[(p['property'], p['value']) for p in props]}")

    print("\n" + "=" * 60)
    print("TEST: Try vendor command 0x20000213 with param from 0x20000213 OK response")
    print("=" * 60)
    
    # The vendor cmd 0x20000213 with empty params returns params = FF FF A7 00 FB FF 7F FF FB FF FF FB F0 FF FF AA AA (18 bytes)
    # Maybe the param structure matters - let's try with these exact params
    for trial_param in [b"", bytes.fromhex("FF FF A7 00 FB FF 7F FF FB FF FF FB F0 FF FF AA AA")]:
        resp = t.transceive(build(0x20000213, trial_param))
        status = "OK" if resp.ok else f"rc=0x{resp.rc:04X}"
        print(f"  param={hex_dump(trial_param)}: {status}")
        if resp.ok and resp.params:
            print(f"    returned params: {hex_dump(resp.params)}")

    print("\n" + "=" * 60)
    print("TEST: vendor cmd 0x20000204 param = 0200001a interpretation")
    print("=" * 60)
    
    # 0x20000204 with empty params returns 02 00 00 1A
    # This could be: version 2.0, subversion 0x001A, or a handle
    # Let's try with this as a param
    for trial_param in [b"", bytes.fromhex("02 00 00 1A")]:
        resp = t.transceive(build(0x20000204, trial_param))
        status = "OK" if resp.ok else f"rc=0x{resp.rc:04X}"
        print(f"  param={hex_dump(trial_param)}: {status}")
        if resp.ok and resp.params:
            print(f"    returned params: {hex_dump(resp.params)}")