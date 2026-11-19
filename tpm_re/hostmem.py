"""Host physical-memory inspection via /proc/kcore.

Two read-only helpers that used to live under ``knowledge/tools/``:

* ``map_physical`` — translate a physical address (e.g. the TPM's MMIO base
  ``0xFED40000``) through the ELF program headers of ``/proc/kcore`` and dump
  the bytes mapped there.  (was ``knowledge/tools/memmap.py``)
* ``scan_kcore`` — stream ``/proc/kcore`` in chunks looking for firmware
  signatures (NPCT / Nuvoton / TPM markers).  (was
  ``knowledge/tools/scan_kcore.py``)

Both read ``/proc/kcore`` only; neither writes anything.  Reading
``/proc/kcore`` usually requires root (and a kernel built with
``CONFIG_PROC_KCORE``); the caller gets a clear error otherwise.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

KCORE = Path("/proc/kcore")

# TPM TIS/CRB MMIO window on most x86 platforms.
TPM_MMIO_BASE = 0xFED40000

DEFAULT_MARKERS = (
    b"NPCT", b"Nuvoton", b"NUVOTON", b"nvton", b"TPM_FW", b"TPM FMP",
)


class HostMemError(RuntimeError):
    """Raised when /proc/kcore is unreadable or lacks the mapping."""


@dataclass
class ProgramHeader:
    p_type: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_flags: int


def _read_program_headers(handle) -> list[ProgramHeader]:
    hdr = handle.read(64)
    if len(hdr) < 64 or hdr[:4] != b"\x7fELF":
        raise HostMemError("/proc/kcore is not an ELF image")
    e_phoff = struct.unpack_from("<Q", hdr, 32)[0]
    e_phentsize = struct.unpack_from("<H", hdr, 54)[0]
    e_phnum = struct.unpack_from("<H", hdr, 56)[0]
    handle.seek(e_phoff)
    phs: list[ProgramHeader] = []
    for _ in range(e_phnum):
        ph = handle.read(e_phentsize)
        if len(ph) < e_phentsize:
            break
        phs.append(ProgramHeader(
            p_type=struct.unpack_from("<I", ph, 0)[0],
            p_flags=struct.unpack_from("<I", ph, 4)[0],
            p_offset=struct.unpack_from("<Q", ph, 8)[0],
            p_vaddr=struct.unpack_from("<Q", ph, 16)[0],
            p_paddr=struct.unpack_from("<Q", ph, 24)[0],
            p_filesz=struct.unpack_from("<Q", ph, 32)[0],
            p_memsz=struct.unpack_from("<Q", ph, 40)[0],
        ))
    return phs


def map_physical(target: int = TPM_MMIO_BASE, length: int = 256,
                 path: Path = KCORE) -> dict:
    """Return the bytes mapped at physical address ``target`` via /proc/kcore."""
    try:
        with open(path, "rb") as handle:
            phs = _read_program_headers(handle)
            for ph in phs:
                if ph.p_type != 1:  # PT_LOAD
                    continue
                span = max(ph.p_filesz, ph.p_memsz)
                if ph.p_paddr <= target < ph.p_paddr + span:
                    vaddr = ph.p_vaddr + (target - ph.p_paddr)
                    handle.seek(ph.p_offset + (vaddr - ph.p_vaddr))
                    data = handle.read(length)
                    return {
                        "target": f"0x{target:08X}",
                        "found": True,
                        "paddr_start": f"0x{ph.p_paddr:x}",
                        "paddr_end": f"0x{ph.p_paddr + span:x}",
                        "vaddr": f"0x{vaddr:x}",
                        "data_hex": data.hex(),
                        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
                    }
    except PermissionError as exc:
        raise HostMemError(
            f"permission denied reading {path}: {exc}. /proc/kcore needs root."
        ) from exc
    except FileNotFoundError as exc:
        raise HostMemError(f"{path} not present (CONFIG_PROC_KCORE off?)") from exc
    return {"target": f"0x{target:08X}", "found": False}


def scan_kcore(markers: tuple[bytes, ...] = DEFAULT_MARKERS,
               total_bytes: int = 2 * 1024 * 1024 * 1024,
               chunk_bytes: int = 64 * 1024 * 1024,
               path: Path = KCORE) -> list[dict]:
    """Scan the first ``total_bytes`` of /proc/kcore for firmware markers."""
    hits: list[dict] = []
    try:
        with open(path, "rb") as handle:
            for start in range(0, total_bytes, chunk_bytes):
                handle.seek(start)
                chunk = handle.read(chunk_bytes)
                if not chunk:
                    break
                for marker in markers:
                    idx = chunk.find(marker)
                    if idx != -1:
                        pos = start + idx
                        context = chunk[max(0, idx - 32):idx + 64]
                        hits.append({
                            "marker": marker.decode("latin-1"),
                            "offset": f"0x{pos:x}",
                            "context_hex": context.hex(),
                        })
    except PermissionError as exc:
        raise HostMemError(
            f"permission denied reading {path}: {exc}. /proc/kcore needs root."
        ) from exc
    except FileNotFoundError as exc:
        raise HostMemError(f"{path} not present (CONFIG_PROC_KCORE off?)") from exc
    return hits
