"""Offline firmware acquisition and image analysis.

This module folds in two standalone helpers that used to live under
``tools/``:

* ``fetch`` — download a vendor BIOS/EC package and record exactly what was
  fetched (URL, timestamp, size, SHA-256), so a later carve/analysis step
  can cite the precise artifact.  (was ``tools/lenovo_bios_fetch.sh``)
* ``scan_fmp`` — scan an extracted BIOS ROM for UEFI Firmware Management
  Protocol (FMP) capsules and the ``TPM FMP H`` marker, and report any
  Nuvoton/NPCT strings inside each capsule image.  (was
  ``tools/find_fmp.py`` and ``tools/opencode/parse_fmp.py``)
* ``scan_ami_capsules`` — parse the ``AMI `` TPM FMP capsule *payload* format
  decoded from the AMI DXE driver; this is what a Nuvoton/Lenovo update
  package would carry.

All file-based helpers operate on paths the caller names: no path is ever
hard-coded.
"""

from __future__ import annotations

import hashlib
import re
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# UEFI FMP capsule: EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER starts with the
# capsule GUID, but the *self-extracting* capsule type word 0x80000003 is the
# marker the old parser keyed on, so we keep both signals.
FMP_CAPSULE_TYPE = 0x80000003
FMP_MARKER = b"TPM FMP H"
NUVOTON_MARKERS = (b"Nuvoton", b"NPCT75x", b"NPCT7", b"NPCT")

_USER_AGENT = "tpm_re-fetch/1.0 (+https://example.invalid)"


class FirmwareError(RuntimeError):
    """A download failed verification, or an image could not be read."""


# --------------------------------------------------------------------------
# fetch
# --------------------------------------------------------------------------

@dataclass
class FetchResult:
    url: str
    path: Path
    meta_path: Path
    size: int
    sha256: str

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "path": str(self.path),
            "meta": str(self.meta_path),
            "size": self.size,
            "sha256": self.sha256,
        }


def fetch(url: str, out_dir: Path, *, name: str | None = None,
          expected_sha256: str | None = None, retries: int = 3,
          timeout_s: float = 60.0) -> FetchResult:
    """Download ``url`` into ``out_dir`` and write ``<name>.meta`` beside it.

    Honours the environment's HTTPS proxy (``urllib`` reads ``HTTPS_PROXY``).
    The download is rejected on a SHA-256 mismatch when ``expected_sha256`` is
    given.  Vendor support pages often block plain fetches (HTTP 403); a direct
    download URL is required.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not name:
        tail = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        name = tail or "download.bin"
    dest = out_dir / name
    part = dest.with_name(dest.name + ".part")

    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout_s) as resp:
                hasher = hashlib.sha256()
                size = 0
                with part.open("wb") as handle:
                    while True:
                        chunk = resp.read(1 << 16)
                        if not chunk:
                            break
                        handle.write(chunk)
                        hasher.update(chunk)
                        size += len(chunk)
            break
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            part.unlink(missing_ok=True)
            if attempt == retries:
                raise FirmwareError(f"download failed after {retries} tries: {exc}") from exc
            time.sleep(2 * attempt)
    else:  # pragma: no cover - loop always breaks or raises
        raise FirmwareError(f"download failed: {last_error}")

    sha = hasher.hexdigest()
    if expected_sha256 and sha.lower() != expected_sha256.lower():
        part.unlink(missing_ok=True)
        raise FirmwareError(
            f"SHA-256 mismatch: expected {expected_sha256.lower()}, got {sha}"
        )
    part.replace(dest)

    meta_path = dest.with_name(dest.name + ".meta")
    meta_path.write_text(
        f"url={url}\n"
        f"fetched={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"size={size}\n"
        f"sha256={sha}\n"
    )
    return FetchResult(url=url, path=dest, meta_path=meta_path, size=size, sha256=sha)


# --------------------------------------------------------------------------
# FMP capsule scan
# --------------------------------------------------------------------------

@dataclass
class FmpCapsule:
    offset: int
    capsule_type: int
    version: int
    header_size: int
    flags: int
    guid: str
    image_size: int
    contains_nuvoton: bool = False
    contains_tpm2: bool = False
    nuvoton_strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "offset": f"0x{self.offset:08X}",
            "capsule_type": f"0x{self.capsule_type:08X}",
            "version": f"0x{self.version:08X}",
            "header_size": self.header_size,
            "flags": f"0x{self.flags:08X}",
            "guid": self.guid,
            "image_size": self.image_size,
            "contains_nuvoton": self.contains_nuvoton,
            "contains_tpm2": self.contains_tpm2,
            "nuvoton_strings": self.nuvoton_strings[:10],
        }


@dataclass
class FmpReport:
    source: str
    size: int
    marker_offsets: list[int] = field(default_factory=list)
    capsules: list[FmpCapsule] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "size": self.size,
            "marker": FMP_MARKER.decode(),
            "marker_offsets": [f"0x{o:08X}" for o in self.marker_offsets],
            "capsules": [c.to_dict() for c in self.capsules],
        }


def _parse_capsule(data: bytes, offset: int) -> FmpCapsule | None:
    if offset + 40 > len(data):
        return None
    capsule_type = struct.unpack_from(">I", data, offset)[0]
    version = struct.unpack_from("<I", data, offset + 4)[0]
    header_size = struct.unpack_from("<I", data, offset + 8)[0]
    flags = struct.unpack_from("<I", data, offset + 12)[0]
    guid = data[offset + 16:offset + 32]
    image_size = struct.unpack_from("<Q", data, offset + 32)[0]

    # The image payload follows the 40-byte fixed header.  Scan the whole
    # capsule (header + image), clamped so a bogus size cannot read past the
    # end of the file.
    span = 40 + image_size if 0 < image_size <= len(data) else 4096
    window = data[offset:min(len(data), offset + span)]

    strings = re.findall(rb"[ -~]{4,}", window)
    nuvoton = [
        s.decode("ascii")
        for s in strings
        if any(m in s for m in NUVOTON_MARKERS)
    ]
    return FmpCapsule(
        offset=offset,
        capsule_type=capsule_type,
        version=version,
        header_size=header_size,
        flags=flags,
        guid=guid.hex(),
        image_size=image_size,
        contains_nuvoton=any(m in window for m in NUVOTON_MARKERS),
        contains_tpm2=b"TPM2" in window,
        nuvoton_strings=nuvoton,
    )


def scan_fmp(path: Path) -> FmpReport:
    """Find FMP capsules and the ``TPM FMP H`` marker in a BIOS ROM image."""
    path = Path(path)
    data = path.read_bytes()
    report = FmpReport(source=str(path), size=len(data))

    start = 0
    while True:
        pos = data.find(FMP_MARKER, start)
        if pos == -1:
            break
        report.marker_offsets.append(pos)
        start = pos + 1

    for offset in range(0, max(0, len(data) - 4), 4):
        if struct.unpack_from(">I", data, offset)[0] == FMP_CAPSULE_TYPE:
            capsule = _parse_capsule(data, offset)
            if capsule is not None:
                report.capsules.append(capsule)
    return report


# --------------------------------------------------------------------------
# AMI TPM FMP capsule image (decoded from section1.pe, see knowledge/NPCT75x.md
# section 7.1).  This is the *payload* inside an FMP capsule, not the UEFI
# capsule wrapper.  The DXE's CheckImage/SetImage require the "AMI " magic at
# image offset 0 and a section table containing both a type-1 (version) and a
# type-2 (firmware) section.
# --------------------------------------------------------------------------

AMI_MAGIC = b"AMI "
AMI_SECTION_VERSION = 1
AMI_SECTION_FIRMWARE = 2
_AMI_SECTION_SIZE = 16
_AMI_MAX_SECTIONS = 1024


@dataclass
class AmiSection:
    """One 16-byte section descriptor inside an AMI TPM FMP capsule."""

    offset: int          # relative to the section table base
    section_type: int
    size: int
    data_offset: int     # absolute offset in the scanned buffer

    def to_dict(self) -> dict:
        return {
            "offset": f"0x{self.offset:08X}",
            "data_offset": f"0x{self.data_offset:08X}",
            "type": self.section_type,
            "size": self.size,
        }


@dataclass
class AmiCapsule:
    offset: int                    # absolute offset of the "AMI " magic
    version: int                   # u32 at +0x10, stored to TpmFmpVersion
    lowest_supported_version: int  # u32 at +0x14
    section_table_offset: int      # u32 at +0x04, relative to this capsule
    sections: list[AmiSection] = field(default_factory=list)

    @property
    def has_firmware(self) -> bool:
        return any(s.section_type == AMI_SECTION_FIRMWARE and s.size
                   for s in self.sections)

    @property
    def firmware_section(self) -> AmiSection | None:
        return next((s for s in self.sections
                     if s.section_type == AMI_SECTION_FIRMWARE and s.size),
                    None)

    def to_dict(self) -> dict:
        return {
            "offset": f"0x{self.offset:08X}",
            "version": f"0x{self.version:08X}",
            "lowest_supported_version": f"0x{self.lowest_supported_version:08X}",
            "section_table_offset": f"0x{self.section_table_offset:08X}",
            "has_firmware": self.has_firmware,
            "sections": [s.to_dict() for s in self.sections],
        }


def _parse_ami_capsule(data: bytes, pos: int) -> AmiCapsule | None:
    """Parse one ``AMI `` capsule at *pos*, or return None if malformed."""
    if pos + 0x18 > len(data) or data[pos:pos + 4] != AMI_MAGIC:
        return None
    table_rel = struct.unpack_from("<I", data, pos + 4)[0]
    version = struct.unpack_from("<I", data, pos + 0x10)[0]
    lowest = struct.unpack_from("<I", data, pos + 0x14)[0]

    # Fixed header is 0x18 bytes; the table has a 4-byte count followed by
    # 12 reserved bytes, then 16-byte descriptors.
    if table_rel < 0x18:
        return None
    table = pos + table_rel
    if table + 4 > len(data):
        return None
    count = struct.unpack_from("<I", data, table)[0]
    if not 0 < count <= _AMI_MAX_SECTIONS:
        return None
    desc_start = table + 0x10
    if desc_start + count * _AMI_SECTION_SIZE > len(data):
        return None

    sections: list[AmiSection] = []
    for i in range(count):
        desc = desc_start + i * _AMI_SECTION_SIZE
        sec_off, sec_type, sec_size = struct.unpack_from("<QII", data, desc)
        data_off = table + sec_off
        if sec_off and not (table <= data_off <= len(data)):
            return None
        if sec_size and data_off + sec_size > len(data):
            return None
        sections.append(AmiSection(offset=sec_off, section_type=sec_type,
                                   size=sec_size, data_offset=data_off))

    # SetImage bails out unless it found one section of each required type.
    have = {s.section_type for s in sections}
    if AMI_SECTION_VERSION not in have or AMI_SECTION_FIRMWARE not in have:
        return None
    return AmiCapsule(offset=pos, version=version,
                      lowest_supported_version=lowest,
                      section_table_offset=table_rel, sections=sections)


def scan_ami_capsules(data: bytes) -> list[AmiCapsule]:
    """Scan a buffer for structurally valid AMI TPM FMP capsule images."""
    found: list[AmiCapsule] = []
    start = 0
    while True:
        pos = data.find(AMI_MAGIC, start)
        if pos == -1:
            break
        start = pos + 1
        cap = _parse_ami_capsule(data, pos)
        if cap is not None:
            found.append(cap)
    return found


# Lenovo/Nuvoton "DevCap" firmware packages carry a UEFI boot-service driver
# plus a contiguous replay script of pre-built TPM 2.0 vendor commands that
# performs the firmware update.  Parsing is offline; no command is ever sent.
DEVCAP_MAGIC = bytes.fromhex("911cc146aec301b03566677d")
DEVCAP_CONTAINER_GUID = bytes.fromhex("139459944a5c674d99a86e9b2bb146a2")
DEVCAP_DESCRIPTOR_SIZE = 0x20
DEVCAP_TRAILER_SIZE = 0x100
DEVCAP_WRITE_HEADER_LEN = 16
DEVCAP_CC_NAMES = {
    0x20000200: "setup",
    0x20000201: "erase_ranges",
    0x20000202: "write_firmware",
    0x20000203: "commit",
    0x20000204: "read_info_4",
    0x20000211: "preconfig",
    0x20000213: "read_firmware_state",
    0x20000214: "read_info_14",
    0x20000216: "read_info_16",
}


@dataclass
class DevCapCommand:
    """One pre-built TPM command in a DevCap update script."""

    offset: int
    tag: int
    size: int
    cc: int
    params: bytes

    @property
    def name(self) -> str:
        return DEVCAP_CC_NAMES.get(self.cc, f"VENDOR_0x{self.cc:08X}")

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "tag": f"0x{self.tag:04X}",
            "size": self.size,
            "cc": f"0x{self.cc:08X}",
            "name": self.name,
            "params_len": len(self.params),
        }


@dataclass
class DevCapScript:
    """A parsed DevCap container with its vendor-command replay script."""

    descriptor_offset: int
    script_offset: int
    script_size: int
    commands: list[DevCapCommand]
    trailer: bytes

    @property
    def firmware(self) -> bytes:
        """Concatenate the data portion of every ``0x20000202`` chunk."""
        return b"".join(
            cmd.params[DEVCAP_WRITE_HEADER_LEN:]
            for cmd in self.commands
            if cmd.cc == 0x20000202
        )

    def to_dict(self) -> dict:
        return {
            "descriptor_offset": self.descriptor_offset,
            "script_offset": self.script_offset,
            "script_size": self.script_size,
            "trailer_sha256": hashlib.sha256(self.trailer).hexdigest(),
            "commands": [c.to_dict() for c in self.commands],
            "firmware_size": len(self.firmware),
            "firmware_sha256": hashlib.sha256(self.firmware).hexdigest(),
        }


def scan_devcap_script(data: bytes) -> DevCapScript | None:
    """Parse a DevCap container and its vendor-command replay script.

    ``None`` is returned when the container GUID, descriptor magic, size field
    or command walk do not validate.  The script ends exactly where the 256-byte
    trailing signature region begins.
    """
    if len(data) < 0x120 or data[4:20] != DEVCAP_CONTAINER_GUID:
        return None
    desc = data.find(DEVCAP_MAGIC)
    if desc < 0:
        return None
    script_start = desc + DEVCAP_DESCRIPTOR_SIZE
    if script_start + 10 > len(data) - DEVCAP_TRAILER_SIZE:
        return None
    script_size = struct.unpack_from("<Q", data, desc + 0x10)[0]
    script_end = script_start + script_size
    if script_end != len(data) - DEVCAP_TRAILER_SIZE:
        return None

    commands: list[DevCapCommand] = []
    pos = script_start
    while pos < script_end:
        if pos + 10 > script_end:
            return None
        tag, size = struct.unpack_from(">HI", data, pos)
        if tag not in (0x8001, 0x8002) or size < 10 or pos + size > script_end:
            return None
        cc = struct.unpack_from(">I", data, pos + 6)[0]
        commands.append(DevCapCommand(pos, tag, size, cc, data[pos + 10:pos + size]))
        pos += size
    if pos != script_end or not commands:
        return None
    return DevCapScript(desc, script_start, script_size, commands,
                        data[script_end:])
