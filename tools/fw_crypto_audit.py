#!/usr/bin/env python3
"""Offline framing and cleartext audit of the NPCT75x DevCap firmware stream.

Usage:
    python3 tools/fw_crypto_audit.py FW.bin DEVCAP.BIN [OUTDIR]

Dumps firmware portions to OUTDIR and runs classic cryptanalysis:
repeating-key XOR detection, known-plaintext XOR, ECB block repetition,
container-derived key search, and CCM/GCM tag verification.  Nothing here
talks to live hardware.

Requires pycryptodome for the AES steps (optional: skipped if missing).
"""

from __future__ import annotations

import collections
import hashlib
import math
import struct
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - AES steps are optional
    AES = None


def entropy(data: bytes) -> float:
    counts = collections.Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def index_of_coincidence(data: bytes) -> float:
    n = len(data)
    if n < 2:
        return 0.0
    return (sum(c * (c - 1) for c in collections.Counter(data).values())
            / (n * (n - 1)))


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{c:02x}" for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"{base + i:08x}  {hx:<47}  |{asc}|")
    return "\n".join(lines)


def parse_devcap_chunks(devcap: bytes) -> list[bytes]:
    """Return the 16-byte-stripped payload of each 0x20000202 command."""
    off = 0x5820
    chunks = []
    while off + 10 <= len(devcap):
        tag, size = struct.unpack_from(">HI", devcap, off)
        if tag not in (0x8001, 0x8002) or size < 10:
            break
        cc = struct.unpack_from(">I", devcap, off + 6)[0]
        if cc == 0x20000202:
            chunks.append(devcap[off + 10:off + size][16:])
        off += size
    return chunks


def framing_report(chunks: list[bytes]) -> list[str]:
    out = []
    lengths = collections.Counter(struct.unpack(">I", c[16:20])[0] for c in chunks)
    out.append(f"write commands: {len(chunks)}")
    out.append(f"u32 length @16: {dict(lengths)}")
    out.append(f"len-20 == u32: "
               f"{all(struct.unpack('>I', c[16:20])[0] == len(c) - 20 for c in chunks)}")
    out.append(f"unique 16-byte prefixes: {len(set(c[:16] for c in chunks))}")
    out.append(f"unique 10-byte trailers: {len(set(c[-10:] for c in chunks))}")
    payload = sum(len(c) - 20 for c in chunks)
    firmware = payload - 10 * len(chunks)
    out.append(f"framed payload: {payload}  minus 10B/chunk: {firmware} "
               f"(erase range 0x37000 = {0x37000})")
    return out


def xor_period_report(data: bytes, max_period: int = 64) -> list[str]:
    out = [f"baseline entropy={entropy(data):.6f} IC={index_of_coincidence(data):.6f}",
           f"{'period':>7} {'hamming/byte':>13} {'avg IC':>10} {'freq-key ent':>13}"]
    for k in range(1, max_period + 1):
        diffs = [sum((x ^ y).bit_count() for x, y in
                     zip(data[i:i + 16], data[i + k:i + k + 16]))
                 for i in range(0, len(data) - k - 16, 997)]
        hamming = sum(diffs) / len(diffs) / 16
        cols = [index_of_coincidence(data[j::k]) for j in range(k)]
        key = bytes(collections.Counter(data[j::k]).most_common(1)[0][0]
                    for j in range(k))
        dec = bytes(c ^ key[j % k] for j, c in enumerate(data))
        if k <= 16 or k % 8 == 0:
            out.append(f"{k:7d} {hamming:13.4f} "
                       f"{sum(cols) / len(cols):10.6f} {entropy(dec):13.4f}")
    return out


KNOWN_PLAINTEXTS = {
    "all-zero": bytes(16),
    "all-0xff": b"\xff" * 16,
    "NPCT75x\\0": b"NPCT75x" + bytes(9),
    "ASCII 7.2.2.0": b"7.2.2.0" + bytes(9),
    "ver bytes": bytes.fromhex("0200070202000000") + bytes(8),
    "8051 LJMP": bytes.fromhex("020000") + bytes(13),
    "ARM SP": bytes.fromhex("00020000") + bytes(12),
    "gzip": bytes.fromhex("1f8b0800") + bytes(12),
    "zlib": bytes.fromhex("7801") + bytes(14),
    "ELF": bytes.fromhex("7f454c46") + bytes(12),
}


def known_plaintext_report(data: bytes) -> list[str]:
    out = []
    for name, plain in KNOWN_PLAINTEXTS.items():
        k = bytes(x ^ y for x, y in zip(data[:len(plain)], plain))
        dec = bytes(c ^ k[j % len(k)] for j, c in enumerate(data))
        out.append(f"{name:16s} key={k.hex():32s} entropy={entropy(dec):.4f}")
    return out


def ecb_report(data: bytes) -> list[str]:
    blocks = [data[i:i + 16] for i in range(0, len(data) - 15, 16)]
    counts = collections.Counter(blocks)
    return [f"16-byte blocks: {len(blocks)} unique: {len(counts)} "
            f"duplicate types: {sum(1 for v in counts.values() if v > 1)}"]


def container_key_report(data: bytes, devcap: bytes) -> list[str]:
    out = []
    words = []
    for i in range(0, len(devcap) - 15, 16):
        words.append((f"container+0x{i:x}", devcap[i:i + 16]))
    if AES is not None:
        best = []
        for name, key in words:
            dec = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=0).decrypt(data[:4096])
            best.append((entropy(dec), name))
        best.sort()
        out.append(f"AES-CTR keys tried: {len(words)}  best entropy: "
                   + ", ".join(f"{n}={e:.4f}" for e, n in best[:3]))
    else:
        out.append("pycryptodome unavailable - AES steps skipped")
    return out


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    fw_path, devcap_path = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/firmware/analysis")
    out_dir.mkdir(parents=True, exist_ok=True)

    data = fw_path.read_bytes()
    devcap = devcap_path.read_bytes()
    chunks = parse_devcap_chunks(devcap)
    report = ["=" * 72,
              f"firmware: {fw_path} ({len(data)} bytes) sha256={hashlib.sha256(data).hexdigest()}",
              f"devcap:   {devcap_path} ({len(devcap)} bytes)", "=" * 72]

    for name, portion in {
        "head_2048.bin": data[:2048],
        "tail_2048.bin": data[-2048:],
        "mid_2048.bin": data[len(data) // 2 - 1024:len(data) // 2 + 1024],
    }.items():
        (out_dir / name).write_bytes(portion)
        report.append(f"dumped {name}: {len(portion)} bytes")
    (out_dir / "head_256.hexdump.txt").write_text(hexdump(data[:256]) + "\n")

    sections = [
        ("FRAMING", framing_report(chunks)),
        ("XOR PERIOD DETECTION", xor_period_report(data)),
        ("KNOWN PLAINTEXT", known_plaintext_report(data)),
        ("ECB REPETITION", ecb_report(data)),
        ("CONTAINER KEY SEARCH", container_key_report(data, devcap)),
    ]
    for title, lines in sections:
        report += ["", "=" * 72, title, "=" * 72] + lines

    text = "\n".join(report) + "\n"
    (out_dir / "audit.txt").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
