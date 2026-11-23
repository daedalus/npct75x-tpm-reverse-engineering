"""Parser for AMI Aptio NVAR UEFI variable records.

The AMI variable store lives in the SPI flash NVRAM region (memory-mapped at
``0xFF000000`` on this AMD platform) and is **not** exposed through Linux's
``efivars``.  Records have this layout::

    offset 0x00: b"NVAR"
    offset 0x04: u16  record size (including the NVAR header)
    offset 0x06: 3 bytes  checksum/flags
    offset 0x09: u16  GUID index into an AMI-private table
    offset 0x0b: NUL-terminated UTF-8 variable name
    offset ...:  variable data

This parser was validated against a live read-only 16 MiB dump of
``/dev/mem`` at ``0xFF000000`` (SHA-256
``ca8f5baf7a716aa17ce486707d2a08c17c06efee02b8579d35bcbc987662c65e``),
which revealed ``TpmFwUpdRollNonce`` -- previously believed absent from this
machine -- as a 16-byte value.  See ``knowledge/NPCT75x.md`` §9.20.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NvarRecord:
    """One AMI NVAR variable record."""

    offset: int
    size: int
    guid_index: int
    name: str
    data: bytes

    @property
    def data_offset(self) -> int:
        return self.offset + 11 + len(self.name.encode()) + 1


def parse_nvar_records(blob: bytes) -> list[NvarRecord]:
    """Extract all plausible NVAR records from a flash/NVRAM image.

    Scans for the ``NVAR`` signature and validates the size field and a
    printable NUL-terminated name.  False positives inside opaque variable
    payloads are filtered by those checks.
    """
    out: list[NvarRecord] = []
    pos = 0
    while True:
        start = blob.find(b"NVAR", pos)
        if start < 0:
            break
        pos = start + 4
        if pos + 9 > len(blob):
            break
        size = int.from_bytes(blob[pos : pos + 2], "little")
        if size < 12 or size > 0x4000 or start + size > len(blob):
            continue
        guid_index = int.from_bytes(blob[pos + 5 : pos + 7], "little")
        name_start = pos + 7
        name_end = blob.find(b"\x00", name_start, name_start + 120)
        if name_end <= name_start:
            continue
        raw_name = blob[name_start:name_end]
        if not raw_name or not all(32 <= c < 127 for c in raw_name):
            continue
        name = raw_name.decode("ascii")
        data_offset = name_end + 1
        out.append(
            NvarRecord(start, size, guid_index, name, blob[data_offset : start + size])
        )
    return out


def find_variable(blob: bytes, name: str) -> list[NvarRecord]:
    """Return all records whose variable name matches ``name`` exactly."""
    return [r for r in parse_nvar_records(blob) if r.name == name]


def roll_nonce(blob: bytes) -> bytes | None:
    """Return the 16-byte ``TpmFwUpdRollNonce`` payload, if present."""
    for rec in find_variable(blob, "TpmFwUpdRollNonce"):
        if len(rec.data) == 16:
            return rec.data
    return None
