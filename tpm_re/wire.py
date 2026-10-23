"""TPM 2.0 wire-format primitives.

Everything here is written from TPM 2.0 Part 1/2 (structures) and is
deliberately dependency-free: the goal is that a reverse engineer can read,
patch and extend the marshalling instead of trusting a library.

Layout reminders
----------------
command  = tag(2) size(4) commandCode(4) handles [authArea params]
response = tag(2) size(4) responseCode(4) [paramSize(4) if tag==SESSIONS]
           params [authArea]

The asymmetry is real and specified (Part 1): on a *command* the
authorization area sits between the handle area and the parameter area,
while on a *response* the parameter area comes first.  This was confirmed
on the wire against the NPCT75x (see knowledge/NPCT75x.md).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ST_NO_SESSIONS = 0x8001
ST_SESSIONS = 0x8002
ST_AUDIT = 0x8004

TAG_NAMES = {
    ST_NO_SESSIONS: "NO_SESSIONS",
    ST_SESSIONS: "SESSIONS",
    ST_AUDIT: "AUDIT",
}

# Password (empty-auth) session handle.
TPM_RS_PW = 0x40000009

HEADER_SIZE = 10


class WireError(ValueError):
    """Raised when a buffer does not conform to the TPM 2.0 wire format."""


# --------------------------------------------------------------------------
# marshalling
# --------------------------------------------------------------------------

def u8(value: int) -> bytes:
    return struct.pack(">B", value & 0xFF)


def u16(value: int) -> bytes:
    return struct.pack(">H", value & 0xFFFF)


def u32(value: int) -> bytes:
    return struct.pack(">I", value & 0xFFFFFFFF)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF)


def tpm2b(data: bytes) -> bytes:
    if len(data) > 0xFFFF:
        raise WireError(f"TPM2B payload too long: {len(data)}")
    return u16(len(data)) + data


class Reader:
    """Bounds-checked cursor over a TPM 2.0 structure."""

    def __init__(self, data: bytes, offset: int = 0, label: str = "buffer"):
        self.data = data
        self.off = offset
        self.label = label

    def take(self, count: int) -> bytes:
        end = self.off + count
        if count < 0 or end > len(self.data):
            raise WireError(
                f"{self.label}: need {count} bytes at offset {self.off}, "
                f"have {len(self.data) - self.off}"
            )
        chunk = self.data[self.off:end]
        self.off = end
        return chunk

    def u8(self) -> int:
        return struct.unpack(">B", self.take(1))[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def tpm2b(self) -> bytes:
        return self.take(self.u16())

    def rest(self) -> bytes:
        return self.take(len(self.data) - self.off)

    def remaining(self) -> int:
        return len(self.data) - self.off

    def at_end(self) -> bool:
        return self.off >= len(self.data)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

@dataclass
class Command:
    cc: int
    params: bytes = b""
    handles: bytes = b""
    auth_area: bytes | None = None  # authorizationSize + TPMS_AUTH_COMMAND[]

    def to_bytes(self) -> bytes:
        tag = ST_NO_SESSIONS if self.auth_area is None else ST_SESSIONS
        trailer = b"" if self.auth_area is None else self.auth_area
        body = self.handles + trailer + self.params
        size = HEADER_SIZE + len(body)
        return u16(tag) + u32(size) + u32(self.cc) + body

    def hex(self) -> str:
        return self.to_bytes().hex()


def build(cc: int, params: bytes = b"", *, handles: bytes = b"",
          auth_area: bytes | None = None) -> bytes:
    """Serialise a command.

    ``params`` already includes the handle area for commands without
    sessions (the distinction is irrelevant there).  When ``auth_area`` is
    given, ``handles`` and ``params`` must be supplied separately: the
    command layout is handles, authorization area, parameters.
    """
    if auth_area is not None and not handles:
        raise WireError(
            "a session command needs its handle bytes separately from its "
            "parameters (pass handles=...)"
        )
    return Command(cc=cc, params=params, handles=handles,
                   auth_area=auth_area).to_bytes()


def password_auth(handle: int = TPM_RS_PW, attributes: int = 0x01) -> bytes:
    """authArea holding one empty-password session (TPM_RS_PW).

    The leading UINT32 is ``authorizationSize``: the byte length of the
    TPMS_AUTH_COMMAND structures that follow it -- *not* a session count.
    Getting this wrong makes the TPM read a truncated auth area and answer
    TPM_RC_SIZE.
    """
    structure = (
        u32(handle)                  # sessionHandle
        + tpm2b(b"")                 # nonce (empty for password session)
        + u8(attributes)             # sessionAttributes
        + tpm2b(b"")                 # hmac (empty password)
    )
    return u32(len(structure)) + structure


# --------------------------------------------------------------------------
# responses
# --------------------------------------------------------------------------

@dataclass
class Response:
    tag: int
    size: int
    rc: int
    params: bytes = b""
    auth_area: bytes = b""
    raw: bytes = field(default=b"", repr=False)

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def describe(self) -> str:
        name = TAG_NAMES.get(self.tag, f"0x{self.tag:04X}")
        return (
            f"tag={name} size={self.size} rc=0x{self.rc:03X} "
            f"({decode_rc(self.rc)}) params={len(self.params)}B"
        )


def parse_response(data: bytes) -> Response:
    if len(data) < HEADER_SIZE:
        raise WireError(f"response shorter than header: {len(data)} bytes")
    tag, size, rc = struct.unpack(">HII", data[:HEADER_SIZE])
    if size != len(data):
        raise WireError(f"header size {size} != buffer length {len(data)}")
    params = b""
    auth = b""
    if rc == 0:
        if tag == ST_SESSIONS:
            if len(data) < HEADER_SIZE + 4:
                raise WireError("SESSIONS response missing parameterSize")
            param_size = struct.unpack(">I", data[HEADER_SIZE:HEADER_SIZE + 4])[0]
            start = HEADER_SIZE + 4
            if start + param_size > len(data):
                raise WireError(
                    f"parameterSize {param_size} exceeds response body"
                )
            params = data[start:start + param_size]
            auth = data[start + param_size:]
        else:
            params = data[HEADER_SIZE:]
    return Response(tag=tag, size=size, rc=rc, params=params, auth_area=auth, raw=data)


# --------------------------------------------------------------------------
# response codes
# --------------------------------------------------------------------------

# Format 0 (no parameter/handle/session trim).
_RC_FORMAT0 = {
    0x000: "SUCCESS",
    0x01E: "BAD_TAG",
    0x100: "INITIALIZE",
    0x101: "FAILURE",
    0x102: "SEQUENCE",
    0x103: "PRIVATE",
    0x104: "HMAC",
    0x105: "DISABLED",
    0x106: "EXCLUSIVE",
    0x107: "AUTH_TYPE",
    0x108: "AUTH_MISSING",
    0x109: "POLICY",
    0x10A: "PCR",
    0x10B: "PCR_CHANGED",
    0x10C: "UPGRADE",
    0x10D: "TOO_MANY_CONTEXTS",
    0x10E: "AUTH_UNAVAILABLE",
    0x10F: "REBOOT",
    0x110: "UNBALANCED",
    0x111: "COMMAND_SIZE",
    0x112: "COMMAND_CODE",
    0x113: "AUTHSIZE",
    0x114: "AUTHFAIL",
    0x115: "AUTH2FAIL",
    0x116: "BADCONTEXT",
    0x117: "NOCONTEXT",
    0x118: "NOCLEAR",
    0x119: "RESPONSE",
    0x11A: "INTEGRITY",
    0x11B: "TESTING",
    0x11C: "NOCRYPT",
    0x11D: "NOAUTH",
    0x11E: "AUTHORIZE",
    0x901: "CONTEXT_GAP",
    0x902: "OBJECT_MEMORY",
    0x903: "SESSION_MEMORY",
    0x904: "MEMORY",
    0x905: "SESSION_HANDLES",
    0x906: "OBJECT_HANDLES",
    0x907: "LOCALITY",
    0x908: "YIELDED",
    0x909: "CANCELED",
    0x90A: "TESTING",
    0x920: "NV_RATE",
    0x921: "LOCKOUT",
    0x922: "RETRY",
    0x923: "NV_UNAVAILABLE",
    0x924: "NV_UNINITIALIZED",
    0x925: "NV_SPACE",
    0x926: "NV_DEFINED",
}

# Format 1 base codes (low byte).
_RC_FORMAT1 = {
    0x081: "ASYMMETRIC",
    0x082: "ATTRIBUTES",
    0x083: "HASH",
    0x084: "VALUE",
    0x085: "HIERARCHY",
    0x087: "KEY_SIZE",
    0x088: "MGF",
    0x089: "MODE",
    0x08A: "TYPE",
    0x08B: "HANDLE",
    0x08C: "KDF",
    0x08D: "RANGE",
    0x08E: "AUTH_FAIL",
    0x08F: "NONCE",
    0x090: "PP",
    0x092: "SCHEME",
    0x095: "SIZE",
    0x096: "SYMMETRIC",
    0x097: "TAG",
    0x098: "SELECTOR",
    0x09A: "INSUFFICIENT",
    0x09B: "SIGNATURE",
    0x09C: "KEY",
    0x09D: "POLICY",
    0x09F: "INTEGRITY",
    0x0A0: "TICKET",
    0x0A1: "RESERVED_BITS",
    0x0A2: "BAD_AUTH",
    0x0A3: "EXPIRED",
    0x0A4: "POLICY_CC",
    0x0A5: "BINDING",
    0x0A6: "CURVE",
    0x0A7: "ECC_POINT",
}

# 0x910..0x91E: reference-value family.
_RC_FORMAT0.update({
    0x910 + i: f"REFERENCE_{'H' if i < 8 else 'S'}{i % 8}"
    for i in range(15)
})


def decode_rc(rc: int) -> str:
    """Best-effort TPM_RC decoder.

    Format 1 encodes the offending parameter/handle (bits 11:8) or session
    (bit 11) next to a base code in the low byte. Format 0 codes are direct.
    Unmapped values are reported explicitly rather than guessed.
    """
    if rc in _RC_FORMAT0:
        return _RC_FORMAT0[rc]
    low = rc & 0xFF
    if low in _RC_FORMAT1:
        base = _RC_FORMAT1[low]
        if rc & 0x800:          # session number, bit 0x800 is the session flag
            return f"{base} (session {(rc >> 8) & 0x07})"
        return f"{base} (parameter/handle {(rc >> 8) & 0x0F})"
    return f"UNMAPPED_RC_0x{rc:03X}"


# --------------------------------------------------------------------------
# presentation helpers
# --------------------------------------------------------------------------

def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(
            f"{base + offset:08x}  {hexpart:<{width * 3}} |{ascii_part}|"
        )
    return "\n".join(lines)


def u32be_to_str(value: int) -> str:
    """TPM_PT string properties pack four bytes big-endian."""
    return "".join(chr((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def parse_hex(text: str) -> bytes:
    """Accept '0x...' prefixed, spaced or bare hex command lines."""
    stripped = text.strip()
    if stripped.lower().startswith("0x"):
        stripped = stripped[2:]
    cleaned = "".join(ch for ch in stripped if ch in "0123456789abcdefABCDEF")
    if not cleaned:
        raise WireError("no hex digits in input")
    if len(cleaned) % 2:
        raise WireError("hex string has an odd number of digits")
    return bytes.fromhex(cleaned)
