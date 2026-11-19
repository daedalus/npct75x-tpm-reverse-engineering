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

Both operate on files the caller names: no path is ever hard-coded.
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
