"""TPM2_GetCapability decoding.

This module is the main entry point for "what does this chip claim to be".
Vendor property discovery lives here too.  TPM_CAP_VENDOR_PROPERTY (0x100)
is the specified capability for the vendor property space; the NPCT75x
answers there with properties 0x0..0x2 (confirmed on the wire), while the
other capabilities ignore the property field.  `vendor_properties` follows
moreData paging and reports only what the device actually returns.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import tables
from .transport import DeviceTransport
from .wire import (
    Reader,
    build,
    decode_rc,
    u32,
    u32be_to_str,
)

MAX_CAP_COUNT = 0x40


class CapabilityError(RuntimeError):
    pass


def _get(t: DeviceTransport, cap: int, prop: int, count: int) -> tuple[bytes, bool]:
    resp = t.transceive(build(tables.CC_GET_CAPABILITY, u32(cap) + u32(prop) + u32(count)))
    if not resp.ok:
        raise CapabilityError(
            f"GetCapability(cap=0x{cap:02X}, prop=0x{prop:08X}) failed: "
            f"{resp.describe()}"
        )
    rd = Reader(resp.params, label="GetCapability")
    more = bool(rd.u8())
    # TPMS_CAPABILITY_DATA echoes the capability that was requested:
    #   BYTE moreData; TPM_CAP capability; TPMU_CAPABILITIES data;
    echoed = rd.u32()
    if echoed != cap:
        raise CapabilityError(
            f"GetCapability echoed capability 0x{echoed:02X}, asked for 0x{cap:02X}"
        )
    return rd.rest(), more


# --------------------------------------------------------------------------
# typed queries
# --------------------------------------------------------------------------

@dataclass
class Properties:
    fixed: dict[int, int] = field(default_factory=dict)
    variable: dict[int, int] = field(default_factory=dict)

    def get(self, prop: int, default=None):
        return self.fixed.get(prop, self.variable.get(prop, default))


def properties(t: DeviceTransport, start: int = 0x100) -> Properties:
    """Read fixed (0x1xx) then variable (0x2xx) properties."""
    result = Properties()
    for base, target in ((0x100, result.fixed), (0x200, result.variable)):
        prop = base
        for _ in range(8):  # bounded paging
            data, more = _get(t, tables.CAP_TPM_PROPERTIES, prop, MAX_CAP_COUNT)
            rd = Reader(data, label="TPML_TAGGED_TPM_PROPERTY")
            count = rd.u32()
            for _ in range(count):
                key = rd.u32()
                value = rd.u32()
                target[key] = value
                prop = key + 1
            if not more or count == 0:
                break
    return result


def algs(t: DeviceTransport) -> list[dict]:
    data, _ = _get(t, tables.CAP_ALGS, 0, MAX_CAP_COUNT)
    rd = Reader(data, label="TPML_ALG_PROPERTY")
    out = []
    for _ in range(rd.u32()):
        alg = rd.u16()
        attrs = rd.u32()
        out.append({
            "alg": alg,
            "name": tables.ALG_NAMES.get(alg, f"ALG_0x{alg:04X}"),
            "attributes": attrs,
            "asymmetric": bool(attrs & 0x0001),
            "symmetric": bool(attrs & 0x0002),
            "hash": bool(attrs & 0x0004),
            "object": bool(attrs & 0x0008),
            "signing": bool(attrs & 0x0100),
            "encrypting": bool(attrs & 0x0200),
            "method": bool(attrs & 0x0400),
        })
    return out


def pcr_banks(t: DeviceTransport) -> list[dict]:
    data, _ = _get(t, tables.CAP_PCRS, 0, MAX_CAP_COUNT)
    rd = Reader(data, label="TPML_PCR_SELECTION")
    out = []
    for _ in range(rd.u32()):
        alg = rd.u16()
        size = rd.u8()
        bitmap = rd.take(size)
        indices = []
        for byte_index, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (1 << bit):
                    indices.append(byte_index * 8 + bit)
        out.append({
            "alg": alg,
            "name": tables.ALG_NAMES.get(alg, f"ALG_0x{alg:04X}"),
            "select_bytes": size,
            "bitmap": bitmap.hex(),
            "indices": indices,
        })
    return out


def handles(t: DeviceTransport, handle_type: int, count: int = MAX_CAP_COUNT) -> list[int]:
    data, _ = _get(t, tables.CAP_HANDLES, handle_type, count)
    rd = Reader(data, label="TPML_HANDLE")
    return [rd.u32() for _ in range(rd.u32())]


def commands(t: DeviceTransport, start: int = tables.TPM_CC_FIRST,
             limit: int = 512) -> list[dict]:
    """List advertised command codes (TPML_CCA, 4-byte TPMA_CC entries).

    The property argument of GetCapability(CAP_COMMANDS) is the command code
    to start at, so the list is paged by advancing past the last entry.
    """
    out: list[dict] = []
    seen: set[int] = set()
    prop = start
    for _ in range(16):  # bounded paging
        data, more = _get(t, tables.CAP_COMMANDS, prop, MAX_CAP_COUNT)
        rd = Reader(data, label="TPML_CCA")
        count = rd.u32()
        if count == 0:
            break
        progressed = False
        for _ in range(count):
            attrs = rd.u32()
            cc = attrs & 0xFFFF
            if cc in seen:
                continue
            seen.add(cc)
            progressed = True
            out.append({
                "cc": cc,
                "name": tables.describe_cc(cc),
                "attributes": attrs,
                "nv": bool(attrs & 0x400000),
                "extensive": bool(attrs & 0x800000),
                "flushed": bool(attrs & 0x1000000),
                "c_handles": (attrs >> 25) & 0x7,
                "r_handle": bool(attrs & 0x10000000),
                "vendor": bool(attrs & 0x20000000),
            })
            prop = cc + 1
        if not more or not progressed or len(out) >= limit:
            break
    return out



def ecc_curves(t: DeviceTransport) -> list[int]:
    data, _ = _get(t, tables.CAP_ECC_CURVES, 0, MAX_CAP_COUNT)
    rd = Reader(data, label="TPML_ECC_CURVE")
    return [rd.u16() for _ in range(rd.u32())]


# --------------------------------------------------------------------------
# vendor surface discovery
# --------------------------------------------------------------------------

def vendor_properties(t: DeviceTransport, start: int = 0x00,
                      limit: int = 256) -> list[dict]:
    """Read the vendor property space via TPM_CAP_VENDOR_PROPERTY (0x100).

    Paging follows the same rules as TPM_PT properties: the property field is
    a starting value, and moreData says another page is available.  Values
    are reported raw; their meaning is vendor-specific and not guessed here.
    """
    out: list[dict] = []
    seen: set[int] = set()
    prop = start
    for _ in range(16):  # bounded paging
        data, more = _get(t, tables.CAP_VENDOR_PROPERTY, prop, MAX_CAP_COUNT)
        rd = Reader(data, label="TPML_TAGGED_TPM_PROPERTY")
        count = rd.u32()
        if count == 0:
            break
        progressed = False
        for _ in range(count):
            key = rd.u32()
            value = rd.u32()
            if key in seen:
                continue
            seen.add(key)
            progressed = True
            out.append({
                "property": key,
                "value": value,
                "name": f"VENDOR_PROP_0x{key:08X}",
            })
            prop = key + 1
        if not more or not progressed or len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def property_name(prop: int) -> str:
    name = tables.TPM_PT_NAMES.get(prop)
    if name:
        return name
    if prop >= 0x20000000:
        return f"VENDOR_0x{prop:08X}"
    return f"PT_0x{prop:08X}"


def format_property(prop: int, value: int) -> str:
    if prop in tables.PT_AS_STRING:
        return repr(u32be_to_str(value))
    if prop == 0x102:  # REVISION, packed as major*100 + minor
        return f"{value // 100}.{value % 100:02d}"
    if prop in (0x10B, 0x10C):
        # Vendor-defined, but the spec recommends major in the high 16 bits
        # and minor in the low 16 bits.
        return (
            f"0x{value:08X} (major.minor "
            f"{(value >> 16) & 0xFFFF}.{value & 0xFFFF})"
        )
    if prop in (0x11A, 0x11B):  # context hash / sym algorithm ids
        return f"0x{value:04X} ({tables.ALG_NAMES.get(value, 'unknown algorithm')})"
    return f"0x{value:08X} ({value})"


def decode_flags(value: int, names: dict[int, str]) -> list[str]:
    return [name for bit, name in names.items() if value & bit]
