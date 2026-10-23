"""Carve candidate TPM firmware payloads out of vendor update packages.

Purpose: a vendor BIOS/EC update ships as a self-extracting PE, a CAB, an ISO
or a bare flash image.  Before any decompilation can start we need to answer
"where in this blob could the TPM firmware be?".

This tool deliberately stops at *candidates*:

  * marker hits (NPCT / Nuvoton / Infineon / TCG strings)
  * container and section signatures around them
  * Shannon entropy of the surrounding window
  * printable strings for human triage
  * an optional extraction of each window for follow-up with REA

It never claims that a window *is* valid firmware.  Validating that requires
the update protocol and a checksum/format parser derived from a known-good
image.
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path

MARKERS = {
    b"NPCT": "Nuvoton NPCT family",
    b"NPCT7": "Nuvoton NPCT7xx",
    b"Nuvoton": "Nuvoton vendor string",
    b"nuvoton": "Nuvoton vendor string (lower)",
    b"TPM2": "TCG TPM2 reference",
    b"TCG2": "TCG event-log reference",
    b"TCG ": "TCG reference",
    b"SLB96": "Infineon SLB96xx",
    b"IFXTPM": "Infineon vendor marker",
    b"STM33": "STMicroelectronics ST33",
    b"tpm2-firmware": "generic TPM firmware label",
}

CONTAINERS = {
    b"MZ": "PE / DOS executable",
    b"MSCF": "Microsoft CAB",
    b"PK\x03\x04": "ZIP",
    b"7z\xbc\xaf\x27\x1c": "7-Zip",
    b"Rar!\x1a\x07": "RAR",
    b"\x1f\x8b\x08": "gzip",
    b"\xfd7zXZ\x00": "xz",
    b"_FVH": "UEFI firmware volume",
    b"\xd0\x0d\xfe\xed": "UEFI capsule / FMP",
    b"\x5a\xa5\xf0\x0f": "Intel flash descriptor (LE)",
}

WINDOW_BEFORE = 0x100
WINDOW_AFTER = 0x1000


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def ascii_runs(data: bytes, min_len: int = 5) -> list[str]:
    runs: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= min_len:
                runs.append(current.decode("ascii"))
            current.clear()
    if len(current) >= min_len:
        runs.append(current.decode("ascii"))
    return runs


def find_container(data: bytes) -> list[dict]:
    hits = []
    for signature, name in CONTAINERS.items():
        start = 0
        while True:
            index = data.find(signature, start)
            if index < 0:
                break
            hits.append({"offset": index, "kind": name,
                         "signature_hex": signature.hex()})
            start = index + 1
            if len(hits) > 64:
                return hits
    return sorted(hits, key=lambda item: item["offset"])


def scan_bytes(data: bytes, source: str = "<memory>") -> dict:
    candidates = []
    for marker, description in MARKERS.items():
        start = 0
        while True:
            index = data.find(marker, start)
            if index < 0:
                break
            window_start = max(0, index - WINDOW_BEFORE)
            window_end = min(len(data), index + WINDOW_AFTER)
            window = data[index:window_end]
            candidates.append({
                "source": source,
                "offset": index,
                "offset_hex": f"0x{index:X}",
                "marker": marker.decode("latin-1"),
                "marker_meaning": description,
                "entropy": shannon_entropy(window[:4096]),
                "sha256_window": hashlib.sha256(window).hexdigest(),
                "strings": ascii_runs(window)[:12],
                "window_start": window_start,
                "window_end": window_end,
            })
            start = index + len(marker)
    candidates.sort(key=lambda item: item["offset"])
    return {
        "source": source,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "containers": find_container(data),
        "candidates": candidates,
    }


def scan_file(path: Path) -> dict:
    return scan_bytes(path.read_bytes(), str(path))


def scan_path(path: Path, extract_dir: Path | None = None) -> list[dict]:
    targets: list[Path]
    if path.is_dir():
        targets = sorted(p for p in path.rglob("*") if p.is_file())
    else:
        targets = [path]
    reports = []
    data_cache: dict[Path, bytes] = {}
    for target in targets:
        try:
            report = scan_file(target)
        except OSError as exc:
            reports.append({"source": str(target), "error": str(exc)})
            continue
        reports.append(report)
        if extract_dir and report["candidates"]:
            data_cache[target] = target.read_bytes()
            _extract(target, report, data_cache[target], extract_dir)
    return reports


def _extract(source: Path, report: dict, data: bytes, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    seen = set()
    for candidate in report["candidates"]:
        span = (candidate["window_start"], candidate["window_end"])
        if span in seen:
            continue
        seen.add(span)
        name = f"{source.name}.{candidate['offset']:08x}.{candidate['marker']}.bin"
        name = "".join(ch if ch.isprintable() and ch not in "/\\ " else "_" for ch in name)
        (out_dir / name).write_bytes(data[span[0]:span[1]])
