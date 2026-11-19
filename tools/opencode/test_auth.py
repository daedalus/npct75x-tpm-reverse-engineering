"""Test NV_Read auth candidates for index 0x01802006."""
import sys
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re import tables
from tpm_re.wire import build, Reader, u32, u16, password_auth, tpm2b, u8

def make_auth(password: bytes, session_handle: int = 0x40000009, attrs: int = 0x01) -> bytes:
    """Build authArea with given password."""
    structure = (
        u32(session_handle)
        + tpm2b(b"")                # nonce MUST be empty for password session
        + u8(attrs)
        + tpm2b(password)           # hmac carries the password
    )
    return u32(len(structure)) + structure

def nv_read(index: int, size: int, offset: int, password: bytes):
    handles = u32(index) + u32(index)
    params = u16(size) + u16(offset)
    auth_area = make_auth(password)
    command = build(tables.CC_NV_READ, params, handles=handles, auth_area=auth_area)
    with DeviceTransport("/dev/tpmrm0") as t:
        resp = t.transceive(command)
    return resp

candidates = {
    "empty": b"",
    "00"*64: b"\x00"*64,
    "01"*64: b"\x01"*64,
    "deadbeef": bytes.fromhex("deadbeef"),
    "NPCT": b"NPCT",
    "nvtest": b"nvtest",
}

for name, pw in candidates.items():
    resp = nv_read(0x01802006, 16, 0, pw)
    status = "OK" if resp.ok else f"FAIL rc=0x{resp.rc:04X} {resp.describe()}"
    print(f"auth={name!r}: {status}")

# Also test an EK cert index (which we know works with empty password) for sanity
print("\nSanity check: NV_Read(0x01C00002) with empty password:")
resp = nv_read(0x01C00002, 861, 0, b"")
status = "OK" if resp.ok else f"FAIL rc=0x{resp.rc:04X} {resp.describe()}"
print(f"auth=empty: {status}")
