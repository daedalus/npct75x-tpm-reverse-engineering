"""Assemble a dossier for one local TPM.

`collect` is read-only and failure-tolerant: each section records its own
error instead of aborting the whole run, because during reverse engineering a
partially answered question is still evidence.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from . import acpi, caps, device, tables
from .transport import DeviceTransport


def _safe(section: str, func, default=None):
    try:
        return func(), None
    except Exception as exc:  # noqa: BLE001 - evidence gathering must not abort
        return default, f"{section}: {type(exc).__name__}: {exc}"


def _props_to_dict(props: dict[int, int]) -> dict:
    out = {}
    for prop, value in sorted(props.items()):
        out[caps.property_name(prop)] = {
            "property": f"0x{prop:08X}",
            "raw": f"0x{value:08X}",
            "value": value,
            "formatted": caps.format_property(prop, value),
        }
    return out


def collect(transport: DeviceTransport, include_vendor: bool = False) -> dict:
    errors: dict[str, str] = {}

    properties, err = _safe("properties", lambda: caps.properties(transport))
    if err:
        errors["properties"] = err
    algorithms, err = _safe("algorithms", lambda: caps.algs(transport), [])
    if err:
        errors["algorithms"] = err
    banks, err = _safe("pcr_banks", lambda: caps.pcr_banks(transport), [])
    if err:
        errors["pcr_banks"] = err
    nv_indices, err = _safe("nv_indices", lambda: device.nv_indices(transport), [])
    if err:
        errors["nv_indices"] = err
    nv_public = []
    for index in nv_indices or []:
        public, err = _safe(
            f"nv_public[0x{index:08X}]",
            lambda idx=index: device.nv_read_public(transport, idx),
        )
        if public:
            nv_public.append(public.to_dict())
        elif err:
            errors[f"nv_public_0x{index:08X}"] = err
    certificates, err = _safe(
        "certificates", lambda: device.read_all_ek_certificates(transport), []
    )
    if err:
        errors["certificates"] = err
    commands, err = _safe("commands", lambda: caps.commands(transport), [])
    if err:
        errors["commands"] = err
    curves, err = _safe("ecc_curves", lambda: caps.ecc_curves(transport), [])
    if err:
        errors["ecc_curves"] = err
    vendor = []
    if include_vendor:
        vendor, err = _safe(
            "vendor_properties", lambda: caps.vendor_properties(transport), []
        )
        if err:
            errors["vendor_properties"] = err

    fixed = properties.fixed if properties else {}
    variable = properties.variable if properties else {}

    return {
        "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "transport": transport.path,
        "system": acpi.collect(),
        "tpm": {
            "identity": _identity(fixed, variable),
            "fixed_properties": _props_to_dict(fixed),
            "variable_properties": _props_to_dict(variable),
            "algorithms": algorithms,
            "pcr_banks": banks,
            "nv_indices": [f"0x{i:08X}" for i in nv_indices or []],
            "nv_public": nv_public,
            "certificates": [c.to_dict() for c in certificates or []],
            "commands": commands,
            "ecc_curves": curves,
            "vendor_properties": vendor,
        },
        "errors": errors,
    }


def _identity(fixed: dict[int, int], variable: dict[int, int]) -> dict:
    from .wire import u32be_to_str

    def text(value):
        return u32be_to_str(value).rstrip("\x00") if value is not None else None

    vendor = "".join(
        (text(fixed.get(prop)) or "")
        for prop in (0x106, 0x107, 0x108, 0x109)
    )
    permanent = variable.get(0x200, 0)
    startup = variable.get(0x201, 0)
    return {
        "family": text(fixed.get(0x100)),
        "revision": caps.format_property(0x102, fixed[0x102]) if 0x102 in fixed else None,
        "manufacturer": text(fixed.get(0x105)),
        "vendor_strings": vendor,
        "firmware_version_1": f"0x{fixed.get(0x10B, 0):08X}",
        "firmware_version_2": f"0x{fixed.get(0x10C, 0):08X}",
        "vendor_tpm_type": fixed.get(0x10A),
        "pcr_count": fixed.get(0x112),
        "input_buffer": fixed.get(0x10D),
        "max_command_size": fixed.get(0x11E),
        "max_response_size": fixed.get(0x11F),
        "nv_index_max": fixed.get(0x117),
        "total_commands": fixed.get(0x129),
        "library_commands": fixed.get(0x12A),
        "vendor_commands": fixed.get(0x12B),
        "permanent_flags": caps.decode_flags(permanent, tables.PERMANENT_BITS),
        "startup_flags": caps.decode_flags(startup, tables.STARTUP_CLEAR_BITS),
        "transient_avail": variable.get(0x207),
        "persistent_avail": variable.get(0x209),
    }


def render_markdown(dossier: dict) -> str:
    lines: list[str] = []
    add = lines.append
    tpm = dossier["tpm"]
    identity = tpm["identity"]
    system = dossier["system"]

    add("# TPM dossier")
    add("")
    add(f"- generated: `{dossier['generated']}`")
    add(f"- transport: `{dossier['transport']}`")
    add(f"- platform: {system['platform'].get('sys_vendor')} "
        f"{system['platform'].get('product_name')} / BIOS "
        f"{system['platform'].get('bios_version')} "
        f"({system['platform'].get('bios_date')})")
    add("")

    add("## Identity (observed from the device)")
    add("")
    add("| field | value |")
    add("| --- | --- |")
    for key in (
        "family", "revision", "manufacturer", "vendor_strings",
        "firmware_version_1", "firmware_version_2", "vendor_tpm_type",
        "pcr_count", "input_buffer", "max_command_size", "max_response_size",
        "nv_index_max", "total_commands", "library_commands", "vendor_commands",
        "transient_avail", "persistent_avail",
    ):
        add(f"| {key} | `{identity.get(key)}` |")
    add(f"| permanent_flags | {', '.join(identity.get('permanent_flags') or []) or '-'} |")
    add(f"| startup_flags | {', '.join(identity.get('startup_flags') or []) or '-'} |")
    add("")

    add("## Kernel interface")
    add("")
    sysfs = system.get("tpm_sysfs", {})
    for name, detail in (sysfs.get("detail") or {}).items():
        add(f"- `{name}`: driver `{detail.get('driver')}`, "
            f"device `{detail.get('device_link')}`, "
            f"modalias `{detail.get('modalias')}`, "
            f"version_major `{detail.get('version_major')}`")
        if detail.get("pcr_banks"):
            add(f"  - sysfs PCR bank dirs: {', '.join(detail['pcr_banks'])}")
    table = system.get("acpi_tpm2")
    if table:
        add(f"- ACPI TPM2: start method {table['start_method']} "
            f"({table['start_method_name']}), control area "
            f"`{table['control_address']}`, OEM `{table['oem_id']}`/`{table['oem_table_id']}`")
    elif system.get("acpi_tpm2_note"):
        add(f"- ACPI TPM2: {system['acpi_tpm2_note']}")
    config = system.get("kernel_tpm_config") or {}
    if config:
        add(f"- kernel TCG config: "
            + ", ".join(f"{k}={v}" for k, v in sorted(config.items())))
    log = system.get("event_log") or {}
    if log:
        add(f"- event log: `{log.get('path')}` ({log.get('size')} bytes, "
            f"readable={log.get('readable')})")
    add("")

    add("## PCR banks")
    add("")
    add("| algorithm | indices |")
    add("| --- | --- |")
    for bank in tpm["pcr_banks"]:
        add(f"| {bank['name']} | {bank['indices']} |")
    add("")

    add("## NV indices")
    add("")
    add("| index | name alg | size | attributes |")
    add("| --- | --- | --- | --- |")
    for public in tpm["nv_public"]:
        add(f"| `{public['index']}` | {public['name_alg']} | {public['data_size']} | "
            f"{', '.join(public['attribute_flags'])} |")
    add("")

    add("## Endorsement key certificates")
    add("")
    for cert in tpm["certificates"]:
        add(f"- `{cert['index']}` sha256 `{cert['sha256'][:32]}…`, "
            f"{cert['size']} bytes")
        if cert.get("parsed"):
            add(f"  - issuer: {cert.get('issuer')}")
            add(f"  - validity: {cert.get('not_before')} .. {cert.get('not_after')}")
        elif cert.get("note"):
            add(f"  - note: {cert['note']}")
    add("")

    add("## Variable properties (state)")
    add("")
    add("| property | raw | meaning |")
    add("| --- | --- | --- |")
    for name, entry in tpm["variable_properties"].items():
        add(f"| {name} | `{entry['raw']}` | {entry['formatted']} |")
    add("")

    if tpm.get("vendor_properties"):
        add("## Vendor properties (TPM_CAP_VENDOR_PROPERTY)")
        add("")
        add("| property | raw | decimal |")
        add("| --- | --- | --- |")
        for entry in tpm["vendor_properties"]:
            add(f"| `0x{entry['property']:08X}` | `0x{entry['value']:08X}` | "
                f"{entry['value']} |")
        add("")

    if dossier.get("errors"):
        add("## Collection errors")
        add("")
        for key, message in dossier["errors"].items():
            add(f"- `{key}`: {message}")
        add("")

    return "\n".join(lines)


def write(dossier: dict, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "tpm-dossier.json"
    md_path = out_dir / "tpm-dossier.md"
    json_path.write_text(json.dumps(dossier, indent=2) + "\n")
    md_path.write_text(render_markdown(dossier) + "\n")
    # raw DER is written by the `certs --out` subcommand, not the dossier
    return json_path, md_path
