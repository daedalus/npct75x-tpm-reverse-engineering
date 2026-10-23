"""Transport to a local TPM 2.0 character device.

Only the kernel TCTI is implemented (the /dev/tpmX path).  That is the
lowest common denominator and the one that matters for hardware RE: every
byte written here lands on the TIS/CRB interface untouched.

Reads are size-delimited by the TPM header, so a short read is completed
instead of being reported as a truncated frame.
"""

from __future__ import annotations

import os
import select
import struct
import time

from .wire import HEADER_SIZE, WireError, hexdump, parse_response, Response

DEFAULT_CANDIDATES = (
    "/dev/tpmrm0",   # resource-managed, preferred
    "/dev/tpm0",     # raw, first-come-first-served
)


class TransportError(RuntimeError):
    pass


class DeviceTransport:
    def __init__(self, path: str | None = None, timeout_s: float = 60.0):
        self.path = path or self._select()
        self.timeout_s = timeout_s
        try:
            self.fd = os.open(self.path, os.O_RDWR)
        except PermissionError as exc:
            raise TransportError(
                f"permission denied opening {self.path}: {exc}. "
                "Add the user to the 'tss' group, or run as root."
            ) from exc
        except FileNotFoundError as exc:
            raise TransportError(
                f"no TPM device at {self.path}. "
                "Check /sys/class/tpm and the kernel tpm_tis/tpm_crb driver."
            ) from exc

    @staticmethod
    def _select() -> str:
        for candidate in DEFAULT_CANDIDATES:
            if os.path.exists(candidate):
                return candidate
        raise TransportError(
            "no /dev/tpm* device found; this host exposes no kernel TPM"
        )

    def close(self) -> None:
        if getattr(self, "fd", None) is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self) -> "DeviceTransport":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- raw io ------------------------------------------------------------

    def _write_all(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(self.fd, view)
            if written <= 0:
                raise TransportError("device accepted 0 bytes")
            view = view[written:]

    def _read_some(self, count: int, deadline: float, what: str) -> bytes:
        # os.read blocks, so wait for readability first; otherwise the
        # deadline could only be checked after a hung read returned.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError(f"timeout waiting for {what}")
        ready, _, _ = select.select([self.fd], [], [], remaining)
        if not ready:
            raise TransportError(f"timeout waiting for {what}")
        chunk = os.read(self.fd, count)
        if not chunk:
            raise TransportError(f"device closed while waiting for {what}")
        return chunk

    def _read_stamped(self) -> bytes:
        buf = bytearray()
        deadline = time.monotonic() + self.timeout_s
        while len(buf) < HEADER_SIZE:
            buf.extend(self._read_some(4096, deadline, "response header"))
        size = struct.unpack(">I", bytes(buf[2:6]))[0]
        if not HEADER_SIZE <= size <= 0x10000:
            raise TransportError(f"implausible response size {size}")
        while len(buf) < size:
            buf.extend(self._read_some(size - len(buf), deadline, "response body"))
        return bytes(buf[:size])

    # -- public ------------------------------------------------------------

    def transceive(self, command: bytes) -> Response:
        if len(command) < HEADER_SIZE:
            raise WireError("command shorter than 10-byte header")
        declared = struct.unpack(">I", command[2:6])[0]
        if declared != len(command):
            raise WireError(
                f"command header says {declared} bytes, got {len(command)}"
            )
        self._write_all(command)
        return parse_response(self._read_stamped())

    def exchange(self, command: bytes, *, dump: bool = False) -> Response:
        if dump:
            print(">>> " + command.hex())
            print(hexdump(command))
        response = self.transceive(command)
        if dump:
            print("<<< " + response.describe())
            print(hexdump(response.raw))
        return response
