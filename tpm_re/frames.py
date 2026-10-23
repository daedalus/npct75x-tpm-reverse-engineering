"""Decode captured TPM 2.0 byte streams into frames.

Sources this is meant for:
  * `strace -xx -e read,write` output of a process talking to /dev/tpm0
  * sigrok/UART/SPI captures after the transport framing has been stripped
  * an arbitrary binary blob sliced out of firmware or a disk image

Nothing here contacts a TPM.  Classification of command vs response is
explicit: strace input carries the direction (write = command, read =
response); otherwise `auto` uses the plausibility of the code, and only a
code that is both a known command and a known response code is settled by
command/response alternation.  It never uses the state of the machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import tables
from .wire import (
    HEADER_SIZE,
    ST_AUDIT,
    ST_NO_SESSIONS,
    ST_SESSIONS,
    TAG_NAMES,
    decode_rc,
)

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
            "tag_name": TAG_NAMES.get(self.tag, f"UNKNOWN_0x{self.tag:04X}"),
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


def _looks_like_response(code: int) -> bool:
    return code <= 0xFFF and not decode_rc(code).startswith("UNMAPPED")


def _classify(code: int, previous: str | None) -> str:
    is_cc, is_rc = _looks_like_command(code), _looks_like_response(code)
    if is_cc and is_rc:
        # e.g. 0x14C is GetTime and TPM_RC_NV_DEFINED: commands and
        # responses alternate, so take the opposite of the previous frame.
        return "response" if previous == "command" else "command"
    return "command" if is_cc else "response"


def split_frames(data: bytes, role: str = "auto",
                 base: int = 0) -> tuple[list[Frame], list[str]]:
    """Split a byte stream into frames; ``base`` offsets reported positions."""
    frames: list[Frame] = []
    problems: list[str] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < HEADER_SIZE:
            problems.append(
                f"trailing {len(data) - offset} byte(s) at offset 0x{base + offset:X}"
            )
            break
        tag, size, code = (
            int.from_bytes(data[offset:offset + 2], "big"),
            int.from_bytes(data[offset + 2:offset + 6], "big"),
            int.from_bytes(data[offset + 6:offset + 10], "big"),
        )
        if tag not in (ST_NO_SESSIONS, ST_SESSIONS, ST_AUDIT):
            problems.append(
                f"offset 0x{base + offset:X}: implausible tag 0x{tag:04X}; resynchronising"
            )
            offset += 1
            continue
        if size < HEADER_SIZE or size > 0x10000 or offset + size > len(data):
            problems.append(
                f"offset 0x{base + offset:X}: implausible size {size}; resynchronising"
            )
            offset += 1
            continue
        frame_role = role
        if role == "auto":
            frame_role = _classify(code, frames[-1].role if frames else None)
        frames.append(Frame(
            offset=base + offset, tag=tag, size=size, code=code,
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


_PID_PREFIX = r"^\s*(?:\[pid\s+(\d+)\]\s*|(\d+)\s+)?"
_STRACE_CALL = re.compile(_PID_PREFIX + r"(read|write)\((\d+),\s*(.*)$")
_STRACE_RESUMED = re.compile(_PID_PREFIX + r"<\.\.\.\s*(read|write) resumed>\s*(.*)$")
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


def parse_strace_segments(
    text: str, fd: int | None = None,
) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Collect (direction, bytes) transfers from strace read/write calls.

    Works on ``strace -f -xx -s N -e trace=read,write`` output, including
    ``[pid N]`` prefixes and calls split by ``<unfinished ...>`` /
    ``<... read resumed>``.  Truncated transfers are reported, not silently
    padded.
    """
    segments: list[tuple[str, bytes]] = []
    problems: list[str] = []
    pending: dict[str | None, tuple[str, int]] = {}  # pid -> (call, fd)
    for lineno, line in enumerate(text.splitlines(), 1):
        match = _STRACE_CALL.match(line)
        if match:
            pid = match.group(1) or match.group(2)
            direction, call_fd, rest = match.group(3), int(match.group(4)), match.group(5)
            if not rest.startswith('"'):
                if "<unfinished" in rest:
                    pending[pid] = (direction, call_fd)
                continue
            rest = rest[1:]
        else:
            match = _STRACE_RESUMED.match(line)
            if not match:
                continue
            pid = match.group(1) or match.group(2)
            direction, rest = match.group(3), match.group(4)
            started = pending.pop(pid, None)
            if started is None or started[0] != direction or not rest.startswith('"'):
                continue  # a resumed write: its data was on the first line
            call_fd, rest = started[1], rest[1:]
        if fd is not None and call_fd != fd:
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
        if direction == "read":
            # The return value after "= N" is the number of bytes the kernel
            # actually filled; the count argument is only the buffer size.
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
        if chunk:
            segments.append((direction, chunk))
    return segments, problems


def parse_strace(text: str, fd: int | None = None) -> tuple[bytes, list[str]]:
    """Concatenate strace transfers in trace order (direction discarded)."""
    segments, problems = parse_strace_segments(text, fd=fd)
    return b"".join(chunk for _, chunk in segments), problems


def split_strace_frames(
    segments: list[tuple[str, bytes]],
) -> tuple[list[Frame], list[str], int]:
    """Split strace transfers using their direction as the frame role.

    Consecutive transfers in the same direction are joined first, because a
    reader may fetch the header and the body of one response separately.
    Returns (frames, problems, total bytes).
    """
    runs: list[tuple[str, bytearray]] = []
    for direction, chunk in segments:
        if runs and runs[-1][0] == direction:
            runs[-1][1].extend(chunk)
        else:
            runs.append((direction, bytearray(chunk)))
    parsed: list[Frame] = []
    problems: list[str] = []
    offset = 0
    for direction, chunk in runs:
        role = "command" if direction == "write" else "response"
        found, issues = split_frames(bytes(chunk), role=role, base=offset)
        parsed.extend(found)
        problems.extend(issues)
        offset += len(chunk)
    return parsed, problems, offset


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
            digits = line[2:]
            if not _HEX_TOKEN.fullmatch(digits):
                continue
            if len(digits) % 2:
                digits = "0" + digits
            out.extend(bytes.fromhex(digits))
            continue
        # An offset column is either "00000000:" or 6+ hex digits followed by
        # two or more spaces.  A four-digit data token with a single space
        # ("8001 0000") is data, not an offset.
        match = re.match(r"^([0-9a-fA-F]{6,16})(:?)(\s+)(.*)$", line)
        if match and (match.group(2) == ":" or len(match.group(3)) >= 2):
            hexdump_mode = hexdump_mode or len(match.group(3)) >= 2
            line = match.group(4)
            if match.group(2) == ":":
                # xxd: the ASCII column follows the hex after two spaces and
                # may itself look like hex ("dead"), so drop it.
                line = re.split(r"\s{2,}", line, maxsplit=1)[0]
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
