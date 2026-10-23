"""ACPI TPM2 table parsing plus read-only system inventory.

The TPM2 table is the firmware's contract with the OS: it names the start
method and the address of the control area.  On this class of machine it is
also the only place that tells you whether the OS is driving a FIFO/TIS or a
CRB interface -- which in turn decides whether a bus-level capture is
SPI/LPC TIS or memory-mapped CRB.

Reading /sys/firmware/acpi/tables/TPM2 requires root; the parser itself is
pure and unit-tested against synthetic tables.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path

START_METHODS = {
    1: "ACPI (legacy, memory-mapped)",
    2: "FIFO / TIS (memory-mapped)",
    3: "CRB (memory-mapped)",
    4: "CRB with ACPI start",
    5: "FIFO / TIS with ACPI start",
    6: "CRB with ARM SMC",
    7: "FIFO / TIS with ARM SMC",
    8: "CRB with ARM SMC (alternate)",
    9: "FIFO / TIS with ARM SMC (alternate)",
}

_TABLE = Path("/sys/firmware/acpi/tables/TPM2")


@dataclass
class Tpm2Table:
    signature: str
    length: int
    revision: int
    oem_id: str
    oem_table_id: str
    platform_class: int
    control_address: int
    start_method: int
    method_specific: bytes = b""
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "signature": self.signature,
            "length": self.length,
            "revision": self.revision,
            "oem_id": self.oem_id,
            "oem_table_id": self.oem_table_id,
            "platform_class": self.platform_class,
            "control_address": f"0x{self.control_address:016X}",
            "start_method": self.start_method,
            "start_method_name": START_METHODS.get(
                self.start_method, f"UNKNOWN_{self.start_method}"
            ),
            "method_specific_hex": self.method_specific.hex(),
            "problems": self.problems,
        }


def parse_tpm2_table(data: bytes) -> Tpm2Table:
    problems = []
    if len(data) < 52:
        raise ValueError(f"TPM2 table too short: {len(data)} bytes (need >= 52)")
    signature = data[0:4].decode("ascii", "replace")
    if signature != "TPM2":
        problems.append(f"unexpected signature {signature!r}")
    length = int.from_bytes(data[4:8], "big")
    revision = data[8]
    oem_id = data[10:16].decode("ascii", "replace").rstrip("\x00 ")
    oem_table_id = data[16:24].decode("ascii", "replace").rstrip("\x00 ")
    platform_class = int.from_bytes(data[36:38], "big")
    control_address = int.from_bytes(data[40:48], "big")
    start_method = int.from_bytes(data[48:52], "big")
    if length != len(data):
        problems.append(f"header length {length} != file length {len(data)}")
    if start_method not in START_METHODS:
        problems.append(f"unrecognised start method {start_method}")
    return Tpm2Table(
        signature=signature,
        length=length,
        revision=revision,
        oem_id=oem_id,
        oem_table_id=oem_table_id,
        platform_class=platform_class,
        control_address=control_address,
        start_method=start_method,
        method_specific=data[52:],
        problems=problems,
    )


def read_tpm2_table(path: Path = _TABLE) -> tuple[Tpm2Table | None, str | None]:
    try:
        raw = path.read_bytes()
    except PermissionError:
        return None, f"{path} is root-only; re-run with sudo to read it"
    except FileNotFoundError:
        return None, f"{path} not present; firmware published no TPM2 table"
    return parse_tpm2_table(raw), None


# --------------------------------------------------------------------------
# host inventory
# --------------------------------------------------------------------------

def _read(path: str | Path, default=None):
    try:
        return Path(path).read_text(errors="replace").strip()
    except (OSError, ValueError):
        return default


def _first_line(path: str | Path):
    value = _read(path)
    return value.splitlines()[0] if value else None


def tpm_sysfs() -> dict:
    base = Path("/sys/class/tpm")
    devices = sorted(p.name for p in base.glob("tpm*")) if base.exists() else []
    out = {"devices": devices, "detail": {}}
    for name in devices:
        root = base / name
        driver = None
        device = root / "device"
        try:
            link = os.readlink(device)
        except OSError:
            link = None
        if link:
            driver_link = device / "driver"
            try:
                driver = os.path.basename(os.readlink(driver_link))
            except OSError:
                driver = None
        out["detail"][name] = {
            "version_major": _read(root / "tpm_version_major"),
            "device_link": link,
            "driver": driver,
            "modalias": _read(device / "modalias"),
            "caps": _read(root / "caps"),
            "has_ppi": (root / "ppi").exists(),
            "pcr_banks": sorted(p.name for p in root.glob("pcr-*")),
            "uevent": _read(root / "uevent"),
        }
    return out


def platform_identity() -> dict:
    dmi = Path("/sys/class/dmi/id")
    return {
        "sys_vendor": _read(dmi / "sys_vendor"),
        "product_name": _read(dmi / "product_name"),
        "product_version": _read(dmi / "product_version"),
        "board_name": _read(dmi / "board_name"),
        "bios_vendor": _read(dmi / "bios_vendor"),
        "bios_version": _read(dmi / "bios_version"),
        "bios_date": _read(dmi / "bios_date"),
        "kernel": platform.release(),
        "cmdline": _read("/proc/cmdline"),
        "lockdown": _read("/sys/kernel/security/lockdown"),
    }


def kernel_tpm_config() -> dict:
    config = Path(f"/boot/config-{platform.release()}")
    wanted = {}
    if not config.exists():
        return wanted
    for line in config.read_text(errors="replace").splitlines():
        if line.startswith("CONFIG_TCG") or line.startswith("# CONFIG_TCG"):
            key, _, value = line.partition("=")
            wanted[key.lstrip("# ").strip()] = value or "n"
    return wanted


def tpm_modules_on_disk() -> list[str]:
    root = Path(f"/lib/modules/{platform.release()}/kernel/drivers/char/tpm")
    if not root.exists():
        return []
    return sorted(str(p.relative_to(root)) for p in root.rglob("*.ko*"))


def event_log_info() -> dict:
    candidates = [
        Path("/sys/kernel/security/tpm0/binary_bios_measurements"),
        Path("/sys/kernel/security/tpm0/binary_bios_measurements.bin"),
    ]
    for path in candidates:
        if path.exists():
            try:
                stat = path.stat()
                return {"path": str(path), "size": stat.st_size,
                        "readable": os.access(path, os.R_OK)}
            except OSError as exc:
                return {"path": str(path), "error": str(exc)}
    return {}


def collect() -> dict:
    table, note = read_tpm2_table()
    return {
        "platform": platform_identity(),
        "tpm_sysfs": tpm_sysfs(),
        "acpi_tpm2": table.to_dict() if table else None,
        "acpi_tpm2_note": note,
        "kernel_tpm_config": kernel_tpm_config(),
        "tpm_modules_present": tpm_modules_on_disk(),
        "event_log": event_log_info(),
    }
