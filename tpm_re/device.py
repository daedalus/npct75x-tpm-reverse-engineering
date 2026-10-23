"""Read-only device queries: NV, PCR, event log, endorsement key certificates.

Every function here maps one-to-one onto a TPM 2.0 command so that the wire
bytes stay auditable.  Nothing in this module mutates TPM state.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import tables
from .transport import DeviceTransport
from .wire import (
    Reader,
    build,
    password_auth,
    u16,
    u32,
)
from .tables import decode_nv_attributes

EK_CERT_INDICES = {
    0x01C00002: "RSA endorsement key certificate",
    0x01C0000A: "ECC endorsement key certificate",
}

EVENT_TYPES = {
    0x00000000: "EV_PREBOOT_CERT",
    0x00000001: "EV_POST_CODE",
    0x00000002: "EV_UNUSED",
    0x00000003: "EV_NO_ACTION",
    0x00000004: "EV_SEPARATOR",
    0x00000005: "EV_ACTION",
    0x00000006: "EV_EVENT_TAG",
    0x00000007: "EV_S_CRTM_CONTENTS",
    0x00000008: "EV_S_CRTM_VERSION",
    0x00000009: "EV_CPU_MICROCODE",
    0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
    0x0000000B: "EV_TABLE_OF_DEVICES",
    0x0000000C: "EV_COMPACT_HASH",
    0x0000000D: "EV_IPL",
    0x0000000E: "EV_IPL_PARTITION_DATA",
    0x0000000F: "EV_NONHOST_CODE",
    0x00000010: "EV_NONHOST_CONFIG",
    0x00000011: "EV_NONHOST_INFO",
    0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
    0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0x80000002: "EV_EFI_VARIABLE_BOOT",
    0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
    0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
    0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
    0x80000006: "EV_EFI_GPT_EVENT",
    0x80000007: "EV_EFI_ACTION",
    0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    0x80000009: "EV_EFI_HANDOFF_TABLES",
    0x80000010: "EV_EFI_HCRTM_EVENT",
    0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
}


@dataclass
class NvPublic:
    index: int
    name_alg: int
    attributes: int
    auth_policy: bytes
    data_size: int
    name: bytes = b""

    def to_dict(self) -> dict:
        return {
            "index": f"0x{self.index:08X}",
            "name_alg": tables.ALG_NAMES.get(self.name_alg, f"0x{self.name_alg:04X}"),
            "attributes": f"0x{self.attributes:08X}",
            "attribute_flags": decode_nv_attributes(self.attributes),
            "data_size": self.data_size,
            "auth_policy_hex": self.auth_policy.hex(),
            "name_hex": self.name.hex(),
        }


def nv_read_public(t: DeviceTransport, index: int) -> NvPublic:
    resp = t.transceive(build(tables.CC_NV_READ_PUBLIC, u32(index)))
    if not resp.ok:
        raise RuntimeError(f"NV_ReadPublic(0x{index:08X}) failed: {resp.describe()}")
    rd = Reader(resp.params, label="NV_ReadPublic")
    inner = Reader(rd.tpm2b(), label="TPMS_NV_PUBLIC")
    public = NvPublic(
        index=inner.u32(),
        name_alg=inner.u16(),
        attributes=inner.u32(),
        auth_policy=inner.tpm2b(),
        data_size=inner.u16(),
    )
    public.name = rd.tpm2b()
    return public


def nv_read(t: DeviceTransport, index: int, size: int, offset: int = 0,
            auth_handle: int | None = None) -> bytes:
    """Read NV data with an empty password session."""
    handles = u32(auth_handle if auth_handle is not None else index) + u32(index)
    params = u16(size) + u16(offset)
    resp = t.transceive(
        build(tables.CC_NV_READ, params, handles=handles,
              auth_area=password_auth())
    )
    if not resp.ok:
        raise RuntimeError(f"NV_Read(0x{index:08X}) failed: {resp.describe()}")
    return Reader(resp.params, label="NV_Read").tpm2b()


def nv_dump(t: DeviceTransport, index: int, chunk: int = 0x400) -> bytes:
    public = nv_read_public(t, index)
    out = bytearray()
    offset = 0
    while offset < public.data_size:
        want = min(chunk, public.data_size - offset)
        out.extend(nv_read(t, index, want, offset))
        offset += want
    return bytes(out)


def nv_indices(t: DeviceTransport) -> list[int]:
    return _handles(t, tables.NV_INDEX_RANGE)


def _handles(t: DeviceTransport, handle_type: int) -> list[int]:
    from .caps import handles
    return handles(t, handle_type)


# --------------------------------------------------------------------------
# PCR
# --------------------------------------------------------------------------

def pcr_read(t: DeviceTransport, algs: list[int], indices: list[int]) -> dict:
    select = bytearray(3)
    for index in indices:
        if not 0 <= index < 24:
            raise ValueError(f"PCR index out of range: {index}")
        select[index // 8] |= 1 << (index % 8)
    selection = u32(len(algs))
    for alg in algs:
        selection += u16(alg) + bytes([len(select)]) + bytes(select)

    resp = t.transceive(build(tables.CC_PCR_READ, selection))
    if not resp.ok:
        raise RuntimeError(f"PCR_Read failed: {resp.describe()}")
    rd = Reader(resp.params, label="PCR_Read")
    counter = rd.u32()

    applied = []
    for _ in range(rd.u32()):
        alg = rd.u16()
        size = rd.u8()
        applied.append({"alg": alg, "bitmap": rd.take(size).hex()})

    digests = []
    for _ in range(rd.u32()):
        digests.append(rd.tpm2b())

    return {"counter": counter, "applied": applied, "digests": digests}


def parse_event_log(data: bytes) -> list[dict]:
    """Parse a TCG2 (crypto-agile) or legacy SHA1 event log.

    Unknown layouts stop the parse with an explicit `truncated` marker rather
    than silently dropping events.
    """
    events = []
    offset = 0
    while offset < len(data):
        start = offset
        if len(data) - offset < 12:
            events.append({"offset": start, "error": "trailing bytes", "raw_hex": data[offset:].hex()})
            break
        pcr_index = int.from_bytes(data[offset:offset + 4], "big")
        event_type = int.from_bytes(data[offset + 4:offset + 8], "big")
        offset += 8
        digests: list[dict] = []
        declared = int.from_bytes(data[offset:offset + 4], "big")
        agile = False
        if 1 <= declared <= 4:
            probe = offset + 4
            candidate = []
            valid = True
            for _ in range(declared):
                if probe + 2 > len(data):
                    valid = False
                    break
                alg = int.from_bytes(data[probe:probe + 2], "big")
                length = tables.DIGEST_LEN.get(alg)
                if length is None or probe + 2 + length > len(data):
                    valid = False
                    break
                candidate.append({"alg": alg, "digest": data[probe + 2:probe + 2 + length]})
                probe += 2 + length
            if valid and probe + 4 <= len(data):
                digests = candidate
                offset = probe
                agile = True

        if not agile:
            # legacy TCG_PCR_EVENT: fixed 20-byte SHA1 digest
            if len(data) - offset < 20 + 4:
                events.append({"offset": start, "error": "truncated legacy event"})
                break
            digests = [{"alg": 0x04, "digest": data[offset:offset + 20]}]
            offset += 20

        event_size = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
        event_data = data[offset:offset + event_size]
        offset += event_size

        events.append({
            "offset": start,
            "pcr": pcr_index,
            "event_type": event_type,
            "type_name": EVENT_TYPES.get(event_type, f"EV_0x{event_type:08X}"),
            "agile": agile,
            "digests": [
                {
                    "alg": d["alg"],
                    "name": tables.ALG_NAMES.get(d["alg"], f"0x{d['alg']:04X}"),
                    "hex": d["digest"].hex(),
                }
                for d in digests
            ],
            "event_size": event_size,
            "event_text": _event_text(event_data),
            "event_hex": event_data[:64].hex(),
        })
    return events


def _event_text(event_data: bytes) -> str:
    """Best-effort text rendering of an event payload.

    Firmware strings are usually UCS-2; binary blobs are left as hex by the
    caller.  We only claim text when the bytes actually look like text.
    """
    if not event_data:
        return ""
    if b"\x00" in event_data and len(event_data) % 2 == 0:
        text = event_data.decode("utf-16-le", "replace")
    else:
        text = event_data.decode("latin-1", "replace")
    printable = sum(1 for ch in text if ch.isprintable())
    if printable / max(len(text), 1) < 0.6:
        return ""
    return text.replace("\x00", "").strip()


# --------------------------------------------------------------------------
# endorsement key certificates
# --------------------------------------------------------------------------

@dataclass
class Certificate:
    index: int
    der: bytes
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    parsed: bool = False
    note: str | None = None
    fields: dict = field(default_factory=dict)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    def to_dict(self) -> dict:
        return {
            "index": f"0x{self.index:08X}",
            "description": EK_CERT_INDICES.get(self.index, "NV certificate"),
            "sha256": self.sha256,
            "size": len(self.der),
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "parsed": self.parsed,
            "note": self.note,
        }


def read_ek_certificate(t: DeviceTransport, index: int) -> Certificate:
    der = nv_dump(t, index)
    cert = Certificate(index=index, der=der)
    openssl = shutil.which("openssl")
    if not openssl:
        cert.note = "openssl not available; DER kept for offline parsing"
        return cert
    with tempfile.NamedTemporaryFile(suffix=".der") as handle:
        handle.write(der)
        handle.flush()
        proc = subprocess.run(
            [openssl, "x509", "-inform", "DER", "-noout",
             "-subject", "-issuer", "-dates", "-serial", "-fingerprint", "-sha256"],
            input=der, capture_output=True,
        )
    if proc.returncode != 0:
        cert.note = proc.stderr.decode(errors="replace").strip()[:200]
        return cert
    cert.parsed = True
    for line in proc.stdout.decode(errors="replace").splitlines():
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "subject":
            cert.subject = value
        elif key == "issuer":
            cert.issuer = value
        elif key == "notbefore":
            cert.not_before = value
        elif key == "notafter":
            cert.not_after = value
        else:
            cert.fields[key] = value
    return cert


def read_all_ek_certificates(t: DeviceTransport) -> list[Certificate]:
    certs = []
    for index in EK_CERT_INDICES:
        try:
            certs.append(read_ek_certificate(t, index))
        except RuntimeError as exc:
            cert = Certificate(index=index, der=b"", note=str(exc))
            certs.append(cert)
    return certs


def write_certificates(certs: list[Certificate], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for cert in certs:
        if not cert.der:
            continue
        path = out_dir / f"ek-{cert.index:08x}.der"
        path.write_bytes(cert.der)
        written.append(path)
    return written
