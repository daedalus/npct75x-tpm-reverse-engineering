"""Turn sigrok-cli SPI annotation text into a TPM byte stream.

``tpm_re frames`` needs the bytes that crossed MOSI (commands) or MISO
(responses).  sigrok-cli can emit one annotation per decoded byte::

    sigrok-cli -i capture.sr \
        -P spi:cs=D0:clk=D1:mosi=D2:miso=D3 \
        -A spi=mosi:miso > annotations.txt
    python3 -m tpm_re sigrok annotations.txt --direction mosi -o command.bin
    python3 -m tpm_re frames command.bin

The exact annotation wording depends on the sigrok version and the protocol
decoder, so this parser is deliberately tolerant: it takes the text after the
last ``:`` on each line, keeps two-digit hex tokens, and ignores everything
else.  (was ``tools/sigrok_to_frames.py``)
"""

from __future__ import annotations

import re
from pathlib import Path

_BYTE = re.compile(r"(?:0x)?([0-9a-fA-F]{2})")


def parse_annotations(text: str, direction: str = "mosi") -> tuple[bytes, int]:
    """Return (bytes, number of source lines that contributed bytes)."""
    out = bytearray()
    lines_used = 0
    direction = direction.lower()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        prefix, sep, payload = line.rpartition(":")
        if sep and prefix:
            if direction not in prefix.lower():
                continue
        else:
            payload = line
        found = bytearray()
        for token in payload.replace(",", " ").split():
            match = _BYTE.fullmatch(token)
            if match:
                found.append(int(match.group(1), 16))
                continue
            # A contiguous run such as "80010000000c" is one annotation.
            if len(token) % 2 == 0 and len(token) >= 4:
                try:
                    found.extend(bytes.fromhex(token.removeprefix("0x")))
                except ValueError:
                    pass
        if found:
            out.extend(found)
            lines_used += 1
    return bytes(out), lines_used


def as_hexdump(data: bytes, width: int = 16) -> str:
    """Text form that ``frames.parse_hexdump_text`` understands."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        lines.append(f"{offset:08x}: {chunk.hex()}")
    return "\n".join(lines) + ("\n" if lines else "")


def convert(input_path: Path, out_path: Path | None = None,
            direction: str = "mosi", fmt: str = "bin") -> tuple[Path, int, int]:
    """Read an annotation file and write a byte stream (or hexdump).

    Returns (output path, bytes written, source lines used).
    """
    input_path = Path(input_path)
    text = input_path.read_text(errors="replace")
    data, used = parse_annotations(text, direction=direction)

    out = Path(out_path) if out_path else input_path.with_suffix(".bin")
    if out.resolve() == input_path.resolve():
        # never overwrite the annotation file (e.g. an input named *.bin)
        out = input_path.with_name(input_path.name + ".frames.bin")

    if fmt == "hex":
        out.write_text(as_hexdump(data))
    else:
        out.write_bytes(data)
    return out, len(data), used
