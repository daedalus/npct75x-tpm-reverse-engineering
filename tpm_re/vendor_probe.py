"""Gated, state-touching probes of the vendor surface.

Everything in this module does something the rest of the toolkit refuses to
do by default, so each entry point is only reachable through an explicit CLI
flag:

* ``send_vendor`` sends a vendor command (``0x2000xxxx``) whose semantics are
  undocumented.  The response could, in principle, change TPM state.
* ``sample_property`` reads a vendor property repeatedly and correlates it
  with ReadClock, to tell a monotonic counter from a timer or RNG.
* ``brute_force_nv_auth`` tries a wordlist of passwords against an NV index.
  Each miss on an index without ``TPMA_NV_NO_DA`` increments the
  dictionary-attack lockout counter and can lock the TPM.

These consolidate the one-off scripts that used to live under
``tools/opencode/``.  They are investigation tools, not safe read-only
queries; the caller owns the consequences.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from . import tables
from .caps import _get
from .transport import DeviceTransport
from .wire import (
    Reader,
    build,
    decode_rc,
    password_auth,
    tpm2b,
    u8,
    u16,
    u32,
)

CC_READ_CLOCK = 0x00000181

# Vendor command codes advertised by the NPCT75x (see knowledge/NPCT75x.md).
NPCT_VENDOR_CC = (
    0x20000200, 0x20000201, 0x20000202, 0x20000203, 0x20000204,
    0x20000211, 0x20000213, 0x20000214, 0x20000216,
)

# A small default wordlist drawn from the NPCT75x investigation notes.
DEFAULT_NV_WORDLIST = (
    b"", b"\x00", b"\x01", b"\xff",
    b"\x00\x00", b"\x00\x01", b"\x01\x00",
    b"\x00\x00\x00\x00", b"\x01\x02\x03\x04", b"\xaa\xbb\xcc\xdd",
    b"TPM", b"TPM2", b"NPCT", b"NPCT75x", b"Nuvoton", b"Lenovo",
    b"owner", b"platform", b"test123", b"1234", b"abcdef",
)


def _custom_auth(password: bytes, handle: int = 0x40000009, attrs: int = 0x01) -> bytes:
    """authArea carrying ``password`` in the HMAC field of a password session."""
    structure = u32(handle) + tpm2b(b"") + u8(attrs) + tpm2b(password)
    return u32(len(structure)) + structure


# --------------------------------------------------------------------------
# vendor command send
# --------------------------------------------------------------------------

@dataclass
class ProbeResult:
    cc: int
    rc: int
    ok: bool
    params: bytes
    description: str

    def to_dict(self) -> dict:
        return {
            "cc": f"0x{self.cc:08X}",
            "rc": f"0x{self.rc:03X}",
            "rc_name": decode_rc(self.rc),
            "ok": self.ok,
            "params_hex": self.params.hex(),
        }


def send_vendor(t: DeviceTransport, cc: int, *, params: bytes = b"",
                handles: bytes = b"", password: bool = False) -> ProbeResult:
    """Send one vendor command and return its decoded response."""
    auth_area = password_auth() if password else None
    command = build(cc, params, handles=handles, auth_area=auth_area)
    resp = t.transceive(command)
    return ProbeResult(
        cc=cc, rc=resp.rc, ok=resp.ok, params=resp.params,
        description=resp.describe(),
    )


def sweep_vendor(t: DeviceTransport,
                 codes: tuple[int, ...] = NPCT_VENDOR_CC) -> list[ProbeResult]:
    """Send each vendor command with empty parameters and collect replies."""
    return [send_vendor(t, cc) for cc in codes]


# --------------------------------------------------------------------------
# property sampling
# --------------------------------------------------------------------------

def sample_property(t: DeviceTransport, prop: int = 0x1, *, count: int = 10,
                    interval_s: float = 1.0) -> list[dict]:
    """Sample a vendor property, correlated with ReadClock, over time.

    Lets you tell a monotonic counter (tracks ``clock``) from a free-running
    timer (tracks ``time``) from entropy (tracks neither).
    """
    samples: list[dict] = []
    for i in range(count):
        data, _ = _get(t, tables.CAP_VENDOR_PROPERTY, prop, 1)
        rd = Reader(data, label="TPML_TAGGED_TPM_PROPERTY")
        n = rd.u32()
        key = rd.u32() if n else 0
        value = rd.u32() if n else 0

        resp = t.transceive(build(CC_READ_CLOCK))
        rd2 = Reader(resp.params, label="ReadClock")
        time_ms = rd2.u32()
        clock_ms = rd2.u32()

        samples.append({
            "sample": i,
            "property": f"0x{key:08X}",
            "value": value,
            "value_hex": f"0x{value:08X}",
            "time_ms": time_ms,
            "clock_ms": clock_ms,
        })
        if i + 1 < count:
            time.sleep(interval_s)
    return samples


# --------------------------------------------------------------------------
# NV auth brute force (dictionary attack)
# --------------------------------------------------------------------------

@dataclass
class BruteForceResult:
    index: int
    tried: int
    found: bytes | None
    data: bytes | None
    locked_out: bool

    def to_dict(self) -> dict:
        return {
            "index": f"0x{self.index:08X}",
            "tried": self.tried,
            "found": None if self.found is None else self.found.hex(),
            "data_hex": None if self.data is None else self.data.hex(),
            "locked_out": self.locked_out,
        }


def brute_force_nv_auth(t: DeviceTransport, index: int, size: int = 16,
                        offset: int = 0,
                        wordlist: tuple[bytes, ...] = DEFAULT_NV_WORDLIST,
                        ) -> BruteForceResult:
    """Try each password in ``wordlist`` against NV_Read of ``index``.

    DANGEROUS on an index without ``TPMA_NV_NO_DA``: every wrong guess
    increments the dictionary-attack failure counter and the TPM eventually
    enters lockout (rc ``LOCKOUT`` 0x921).  Stops early on success or lockout.
    """
    tried = 0
    for pw in wordlist:
        auth_area = _custom_auth(pw)
        resp = t.transceive(build(
            tables.CC_NV_READ, u16(size) + u16(offset),
            handles=u32(index) + u32(index), auth_area=auth_area,
        ))
        tried += 1
        if resp.ok:
            data = Reader(resp.params, label="NV_Read").tpm2b()
            return BruteForceResult(index=index, tried=tried, found=pw,
                                    data=data, locked_out=False)
        if resp.rc == 0x921:  # TPM_RC_LOCKOUT
            return BruteForceResult(index=index, tried=tried, found=None,
                                    data=None, locked_out=True)
    return BruteForceResult(index=index, tried=tried, found=None,
                            data=None, locked_out=False)


def load_wordlist(path) -> tuple[bytes, ...]:
    """Load a password wordlist: one entry per line.

    A line of the form ``hex:DEADBEEF`` is decoded from hex; any other line is
    taken as raw UTF-8 bytes (trailing newline stripped).
    """
    from pathlib import Path
    words: list[bytes] = []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("hex:"):
            words.append(bytes.fromhex(line[4:].strip()))
        else:
            words.append(line.encode("utf-8"))
    return tuple(words)
