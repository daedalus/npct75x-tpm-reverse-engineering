#!/usr/bin/env python3
"""Turn sigrok-cli SPI annotation text into a TPM byte stream.

`tpm_re frames` needs the bytes that crossed MOSI (commands) or MISO
(responses).  sigrok-cli can emit one annotation per decoded byte:

    sigrok-cli -i capture.sr \
        -P spi:cs=D0:clk=D1:mosi=D2:miso=D3 \
        -A spi=mosi:miso > annotations.txt
    tools/sigrok_to_frames.py annotations.txt --direction mosi -o command.bin
    python3 -m tpm_re frames command.bin

The exact annotation wording depends on the sigrok version and the protocol
decoder, so this parser is deliberately tolerant: it takes the text after the
last ':' on each line, keeps two-digit hex tokens, and ignores everything
else.  Read the output summary; if no bytes matched, inspect a few lines of
the annotation file and adjust --direction.
"""

from __future__ import annotations

import argparse
import re
import sys
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
    """Text form that frames.parse_hexdump_text understands."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        lines.append(f"{offset:08x}: {chunk.hex()}")
    return "\n".join(lines) + ("\n" if lines else "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", help="sigrok-cli annotation text")
    parser.add_argument("-o", "--out", help="output file (default: <input>.bin)")
    parser.add_argument("--direction", default="mosi",
                        help="annotation direction to keep: mosi or miso")
    parser.add_argument("--format", choices=("bin", "hex"), default="bin",
                        help="bin (raw bytes) or hex (text hexdump)")
    args = parser.parse_args(argv)

    text = Path(args.input).read_text(errors="replace")
    data, used = parse_annotations(text, direction=args.direction)
    out = Path(args.out) if args.out else Path(args.input).with_suffix(".bin")

    if args.format == "hex":
        out.write_text(as_hexdump(data))
    else:
        out.write_bytes(data)

    print(f"annotations: {used} line(s) -> {len(data)} byte(s) "
          f"({args.direction})", file=sys.stderr)
    if not data:
        print("no byte tokens matched; inspect the annotation file and check "
              "--direction", file=sys.stderr)
        return 1
    print(f"wrote {out}", file=sys.stderr)
    print(f"next: python3 -m tpm_re frames {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
