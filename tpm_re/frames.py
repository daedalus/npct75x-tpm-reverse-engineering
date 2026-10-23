"""Decode captured TPM 2.0 byte streams into frames.

Sources this is meant for:
  * `strace -xx -e read,write` output of a process talking to /dev/tpm0
  * sigrok/UART/SPI captures after the transport framing has been stripped
  * an arbitrary binary blob sliced out of firmware or a disk image

Nothing here contacts a TPM.  Classification of command vs response is
explicit: `auto` uses the plausibility of the command code, never the state
of the machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import tables
from .wire import HEADER_SIZE, ST_AUDIT, ST_NO_SESSIONS, ST_SESSIONS, decode_rc

_HEX_TOKEN = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class Frame:
    offset: int
    tag: int
    size: int
    code: int
    raw: bytes
    role: str  # "command" | "response" | "unknown"

    def to_dict(self) -> dict:
        data = {
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:X}",
            "tag": f"0x{self.tag:04X}",
            "tag_name": {
                ST_NO_SESSIONS: "NO_SESSIONS",
                ST_SESSIONS: "SESSIONS",
                ST_AUDIT: "AUDIT",
            }.get(self.tag, f"UNKNOWN_0x{self.tag:04X}"),
            "size": self.size,
            "role": self.role,
            "body_hex": self.raw[HEADER_SIZE:].hex(),
        }
        if self.role == "command":
            data["cc"] = f"0x{self.code:08X}"
            data["cc_name"] = tables.describe_cc(self.code)
        elif self.role == "response":
            data["rc"] = f"0x{self.code:03X}"
            data["rc_name"] = decode_rc(self.code)
        else:
            data["code"] = f"0x{self.code:08X}"
        return data


def _looks_like_command(code: int) -> bool:
    return code in tables.KNOWN_CC or bool(code & tables.VENDOR_CC_MASK)


def split_frames(data: bytes, role: str = "auto") -> tuple[list[Frame], list[str]]:
    frames: list[Frame] = []
    problems: list[str] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < HEADER_SIZE:
            problems.append(
                f"trailing {len(data) - offset} byte(s) at offset 0x{offset:X}"
            )
            break
        tag, size, code = (
            int.from_bytes(data[offset:offset + 2], "big"),
            int.from_bytes(data[offset + 2:offset + 6], "big"),
            int.from_bytes(data[offset + 6:offset + 10], "big"),
        )
        if tag not in (ST_NO_SESSIONS, ST_SESSIONS, ST_AUDIT):
            problems.append(
                f"offset 0x{offset:X}: implausible tag 0x{tag:04X}; resynchronising"
            )
            offset += 1
            continue
        if size < HEADER_SIZE or size > 0x10000 or offset + size > len(data):
            problems.append(
                f"offset 0x{offset:X}: implausible size {size}; resynchronising"
            )
            offset += 1
            continue
        frame_role = role
        if role == "auto":
            frame_role = "command" if _looks_like_command(code) else "response"
        frames.append(Frame(
            offset=offset, tag=tag, size=size, code=code,
            raw=data[offset:offset + size], role=frame_role,
        ))
        offset += size
    return frames, problems


def load_bytes(path: Path) -> bytes:
    """Read binary, or decode a hexdump/text hex stream."""
    raw = path.read_bytes()
    if _is_probably_binary(raw):
        return raw
    text = raw.decode("utf-8", "replace")
    return parse_hexdump_text(text)


def _is_probably_binary(data: bytes) -> bool:
    if not data:
        return True
    printable = sum(1 for b in data[:4096] if 32 <= b < 127 or b in (9, 10, 13))
    return printable / min(len(data), 4096) < 0.85


_STRACE_CALL = re.compile(r"^\s*(?:\d+\s+)?(read|write)\((\d+),\s*\"(.*)$")
_ESCAPES = {
    "n": 10, "t": 9, "r": 13, "0": 0, "a": 7, "b": 8, "f": 12, "v": 11,
    "\\": 92, '"': 34, "'": 39,
}


def _unescape(raw: str) -> tuple[bytes, bool, str]:
    """Decode the body of a strace string literal.

    Returns (bytes, truncated, remainder) where remainder is unused input
    after the closing quote.  ``truncated`` is true when strace elided bytes
    with ``...``, which means the capture is evidence but not a whole frame.
    """
    out = bytearray()
    i = 0
    truncated = False
    while i < len(raw):
        char = raw[i]
        if char == '"':
            if out.endswith(b"..."):
                del out[-3:]
                truncated = True
            return bytes(out), truncated, raw[i + 1:]
        if char != "\\":
            out.extend(char.encode("utf-8", "replace"))
            i += 1
            continue
        if i + 1 >= len(raw):
            break
        nxt = raw[i + 1]
        if nxt == "x" and i + 3 < len(raw):
            try:
                out.append(int(raw[i + 2:i + 4], 16))
                i += 4
                continue
            except ValueError:
                pass
        if raw.startswith("...", i + 1):
            # strace cut the string short (with -s N)
            truncated = True
            i += 4
            continue
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
            continue
        octal = re.match(r"[0-7]{1,3}", raw[i + 1:])
        if octal:
            out.append(int(octal.group(0), 8) & 0xFF)
            i += 1 + len(octal.group(0))
            continue
        out.extend(nxt.encode("utf-8", "replace"))
        i += 2
    truncated = True  # no closing quote: strace was interrupted/truncated
    return bytes(out), truncated, ""


def parse_strace(text: str, fd: int | None = None) -> tuple[bytes, list[str]]:
    """Collect TPM command/response bytes from strace read/write calls.

    Works on ``strace -f -xx -s N -e trace=read,write`` output.  Bytes are
    concatenated in trace order, so ``split_frames`` sees each transfer as a
    complete frame.  Truncated transfers are reported, not silently padded.
    """
    data = bytearray()
    problems: list[str] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        match = _STRACE_CALL.match(line)
        if not match:
            continue
        direction, call_fd, rest = match.groups()
        if fd is not None and int(call_fd) != fd:
            continue
        chunk, truncated, remainder = _unescape(rest)
        if remainder.startswith("..."):
            # strace puts the elision marker *after* the closing quote:
            #   "..."..., 832) = 832
            truncated = True
        if truncated:
            problems.append(
                f"line {lineno}: {direction} on fd {call_fd} was truncated by "
                f"strace ({len(chunk)} bytes captured); re-run with a larger -s"
            )
        if direction == "write":
            data.extend(chunk)
            continue
        # For read, the return value after "= N" is the number of bytes the
        # kernel actually filled; the count argument is only the buffer size.
        result = re.search(r"\)\s*=\s*(-?\d+)", remainder)
        if result:
            count = int(result.group(1))
            if count < 0:
                chunk = b""  # failed syscall: no data
            elif count < len(chunk):
                chunk = chunk[:count]
            elif count > len(chunk) and not truncated:
                problems.append(
                    f"line {lineno}: read reported {count} bytes but only "
                    f"{len(chunk)} were captured"
                )
        data.extend(chunk)
    return bytes(data), problems


def parse_hexdump_text(text: str) -> bytes:
    """Accept `hexdump -C`, `xxd`, bare hex lines, or Python-bytes style."""
    out = bytearray()
    hexdump_mode = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # drop the ASCII column of hexdump -C / xxd
        line = line.split("|")[0]
        if line.startswith("0x") and " " not in line:
            out.extend(bytes.fromhex(line[2:]))
            continue
        # An offset column is either "00000000:" or 6+ hex digits followed by
        # two or more spaces.  A four-digit data token with a single space
        # ("8001 0000") is data, not an offset.
        match = re.match(r"^([0-9a-fA-F]{6,16})(:?)(\s+)(.*)$", line)
        if match and (match.group(2) == ":" or len(match.group(3)) >= 2):
            hexdump_mode = hexdump_mode or len(match.group(3)) >= 2
            line = match.group(4)
        elif hexdump_mode and re.fullmatch(r"[0-9a-fA-F]{4,16}", line):
            continue  # offset-only trailer line ("00000010")
        for token in line.split():
            token = token.strip()
            if not _HEX_TOKEN.fullmatch(token) or len(token) == 1:
                continue
            if len(token) % 2:
                token = "0" + token
            out.extend(bytes.fromhex(token))
    return bytes(out)
