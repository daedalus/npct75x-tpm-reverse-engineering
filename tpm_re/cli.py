"""Command-line interface for the TPM reverse-engineering toolkit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import acpi, caps, carve, device, frames, probe, tables
from .transport import DeviceTransport, TransportError
from .wire import (
    WireError,
    build,
    decode_rc,
    hexdump,
    parse_hex,
    parse_response,
    password_auth,
    u16,
    u32,
)

# Commands that cannot change TPM state.  Everything else needs --allow-write.
READ_ONLY_CC = {
    0x0000014C,  # GetTime
    0x0000014E,  # NV_Read
    0x00000169,  # NV_ReadPublic
    0x00000173,  # ReadPublic
    0x00000178,  # ECC_Parameters
    0x0000017A,  # GetCapability
    0x0000017B,  # GetRandom
    0x0000017C,  # GetTestResult
    0x0000017D,  # Hash
    0x0000017E,  # PCR_Read
    0x00000181,  # ReadClock
    0x00000189,  # PolicyGetDigest
    0x0000018A,  # TestParms
}

WRITE_FAMILIES = (
    (0x00000141, "FieldUpgradeData"),
    (0x0000012F, "FieldUpgradeStart"),
    (0x00000126, "Clear"),
    (0x00000127, "ClearControl"),
    (0x0000012A, "NV_DefineSpace"),
    (0x00000122, "NV_UndefineSpace"),
    (0x00000137, "NV_Write"),
    (0x0000014F, "NV_ReadLock"),
    (0x00000138, "NV_WriteLock"),
    (0x00000120, "EvictControl"),
    (0x00000129, "HierarchyChangeAuth"),
)


def _json_print(payload) -> None:
    print(json.dumps(payload, indent=2))


def _parse_indices(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, high = part.split("-", 1)
            out.extend(range(int(low, 0), int(high, 0) + 1))
        else:
            out.append(int(part, 0))
    return out


def _bank_alg(name: str) -> int:
    for alg, alg_name in tables.ALG_NAMES.items():
        if alg_name.lower() == name.lower():
            return alg
    raise SystemExit(f"unknown bank {name!r}; try sha1, sha256, sha384, sha512")


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------

def cmd_probe(args) -> int:
    with DeviceTransport(args.tcti) as transport:
        dossier = probe.collect(transport, include_vendor=args.vendor)
    if args.json or not args.out:
        _json_print(dossier)
    if args.out:
        json_path, md_path = probe.write(dossier, Path(args.out))
        print(f"wrote {json_path}", file=sys.stderr)
        print(f"wrote {md_path}", file=sys.stderr)
        print(probe.render_markdown(dossier))
    return 0


def cmd_props(args) -> int:
    with DeviceTransport(args.tcti) as transport:
        props = caps.properties(transport)
    selected = {}
    if args.fixed or not args.variable:
        selected.update({f"fixed.0x{k:03X}": (k, v) for k, v in sorted(props.fixed.items())})
    if args.variable:
        selected.update({f"variable.0x{k:03X}": (k, v) for k, v in sorted(props.variable.items())})
    for label, (prop, value) in selected.items():
        print(f"{label} {caps.property_name(prop):<24} "
              f"0x{value:08X}  {caps.format_property(prop, value)}")
    return 0


def cmd_caps(args) -> int:
    with DeviceTransport(args.tcti) as transport:
        props = caps.properties(transport)
        algs = caps.algs(transport)
        banks = caps.pcr_banks(transport)
        commands = caps.commands(transport)
        curves = caps.ecc_curves(transport)
    if args.json:
        _json_print({
            "algorithms": algs,
            "pcr_banks": banks,
            "commands": commands,
            "ecc_curves": curves,
            "properties": {
                "fixed": {f"0x{k:03X}": v for k, v in props.fixed.items()},
                "variable": {f"0x{k:03X}": v for k, v in props.variable.items()},
            },
        })
        return 0
    print(f"algorithms: {len(algs)}")
    for alg in algs:
        kinds = [k for k in ("asymmetric", "symmetric", "hash", "object",
                             "signing", "encrypting", "method") if alg[k]]
        print(f"  0x{alg['alg']:04X} {alg['name']:<12} {','.join(kinds)}")
    print(f"pcr banks: {len(banks)}")
    for bank in banks:
        print(f"  {bank['name']:<8} indices={bank['indices']}")
    vendor_count = sum(1 for entry in commands if entry["vendor"])
    print(f"commands advertised: {len(commands)} ({vendor_count} vendor)")
    for entry in commands[: args.limit]:
        mark = " vendor" if entry["vendor"] else ""
        print(f"  0x{entry['cc']:08X} {entry['name']:<28} "
              f"attrs=0x{entry['attributes']:08X}{mark}")
    if len(commands) > args.limit:
        print(f"  ... {len(commands) - args.limit} more (use --limit)")
    if vendor_count:
        names = ", ".join(f"0x{c['cc']:08X}" for c in commands if c["vendor"])
        print(f"vendor command codes: {names}")
    print(f"ecc curves: {len(curves)}")
    for curve in curves:
        print(f"  0x{curve:04X}")
    return 0


def cmd_vendor(args) -> int:
    with DeviceTransport(args.tcti) as transport:
        props = caps.vendor_properties(transport, start=args.start)
    if args.json:
        _json_print(props)
        return 0
    if not props:
        print("no vendor properties in the probed range")
        return 0
    print(f"vendor properties: {len(props)}")
    for entry in props:
        print(f"  0x{entry['property']:08X}  raw=0x{entry['value']:08X}  "
              f"({entry['value']})")
    return 0


def cmd_raw(args) -> int:
    if args.command:
        command = parse_hex(args.command)
    elif args.password:
        if not args.handles:
            print("--password needs --handles (the handle area is not "
                  "inferable from a single body blob)", file=sys.stderr)
            return 2
        command = build(
            int(args.cc, 0),
            parse_hex(args.body) if args.body else b"",
            handles=parse_hex(args.handles),
            auth_area=password_auth(),
        )
    else:
        command = build(
            int(args.cc, 0),
            parse_hex(args.body) if args.body else b"",
        )
    cc = int.from_bytes(command[6:10], "big")
    if not args.allow_write and cc not in READ_ONLY_CC:
        warnings = [name for code, name in WRITE_FAMILIES if code == cc]
        print(
            f"refusing to send 0x{cc:08X} ({tables.describe_cc(cc)}): not in the "
            f"read-only allowlist. State-changing command families include "
            f"{', '.join(name for _, name in WRITE_FAMILIES)}. "
            f"Pass --allow-write to override.",
            file=sys.stderr,
        )
        if warnings:
            print(f"this exact code is {warnings[0]}", file=sys.stderr)
        return 2
    with DeviceTransport(args.tcti) as transport:
        response = transport.transceive(command)
    print(f">>> {command.hex()}")
    print(hexdump(command))
    print(f"<<< {response.describe()}")
    print(hexdump(response.raw))
    if response.params:
        print("--- params ---")
        print(hexdump(response.params))
    if args.json:
        _json_print({
            "command": command.hex(),
            "response": response.raw.hex(),
            "rc": f"0x{response.rc:03X}",
            "rc_name": decode_rc(response.rc),
            "params": response.params.hex(),
        })
    return 0 if response.ok else 1


def cmd_pcrs(args) -> int:
    algs = [_bank_alg(args.bank)]
    indices = _parse_indices(args.indices)
    with DeviceTransport(args.tcti) as transport:
        result = device.pcr_read(transport, algs, indices)
    print(f"update counter: {result['counter']}")
    for digest in result["digests"]:
        print(f"  {digest.hex()}")
    if args.eventlog:
        path = Path(args.eventlog)
        events = device.parse_event_log(path.read_bytes())
        for event in events:
            print(
                f"  [{event.get('pcr')}] {event.get('type_name')} "
                f"agile={event.get('agile')} size={event.get('event_size')}"
            )
            if event.get("event_text"):
                print(f"      {event['event_text'][:120]!r}")
    return 0


def cmd_nv(args) -> int:
    with DeviceTransport(args.tcti) as transport:
        if args.index is None:
            for index in device.nv_indices(transport):
                public = device.nv_read_public(transport, index)
                print(f"0x{index:08X} size={public.data_size} "
                      f"attrs={','.join(public.to_dict()['attribute_flags'])}")
            return 0
        index = int(args.index, 0)
        public = device.nv_read_public(transport, index)
        print(json.dumps(public.to_dict(), indent=2))
        data = device.nv_dump(transport, index)
        print(f"read {len(data)} bytes")
        if args.dump_dir:
            out = Path(args.dump_dir)
            out.mkdir(parents=True, exist_ok=True)
            path = out / f"nv-{index:08x}.bin"
            path.write_bytes(data)
            print(f"wrote {path}")
        else:
            print(hexdump(data[: args.head]))
    return 0


def cmd_certs(args) -> int:
    with DeviceTransport(args.tcti) as transport:
        certs = device.read_all_ek_certificates(transport)
    if args.out:
        written = device.write_certificates(certs, Path(args.out))
        for path in written:
            print(f"wrote {path}")
    for cert in certs:
        if args.json:
            print(json.dumps(cert.to_dict(), indent=2))
        else:
            print(f"0x{cert.index:08X} sha256={cert.sha256} size={len(cert.der)}")
            if cert.parsed:
                print(f"  issuer: {cert.issuer}")
                print(f"  subject: {cert.subject}")
                print(f"  validity: {cert.not_before} .. {cert.not_after}")
            elif cert.note:
                print(f"  note: {cert.note}")
    return 0


def cmd_acpi(args) -> int:
    if args.json:
        _json_print(acpi.collect())
        return 0
    table, note = acpi.read_tpm2_table()
    if table:
        for key, value in table.to_dict().items():
            print(f"{key}: {value}")
    elif note:
        print(note)
    print()
    system = acpi.collect()
    for key, value in system.items():
        if key in ("acpi_tpm2", "acpi_tpm2_note"):
            continue
        print(f"{key}: {value}")
    return 0


def cmd_frames(args) -> int:
    if args.strace:
        text = Path(args.input).read_text(errors="replace")
        data, problems = frames.parse_strace(text, fd=args.fd)
    else:
        data = frames.load_bytes(Path(args.input))
        problems = []
    parsed, split_problems = frames.split_frames(data, role=args.role)
    problems.extend(split_problems)
    if args.json:
        _json_print({
            "input": str(args.input),
            "bytes": len(data),
            "frames": [frame.to_dict() for frame in parsed],
            "problems": problems,
        })
        return 0
    print(f"{len(data)} bytes -> {len(parsed)} frames")
    for frame in parsed:
        info = frame.to_dict()
        if frame.role == "command":
            print(f"  +0x{frame.offset:04X} size={frame.size:<5} "
                  f"CMD 0x{frame.code:08X} {info['cc_name']}")
        elif frame.role == "response":
            print(f"  +0x{frame.offset:04X} size={frame.size:<5} "
                  f"RSP 0x{frame.code:03X} {info['rc_name']}")
        else:
            print(f"  +0x{frame.offset:04X} size={frame.size:<5} ? 0x{frame.code:08X}")
        if args.dump:
            print(hexdump(frame.raw, base=frame.offset))
    for problem in problems:
        print(f"  ! {problem}", file=sys.stderr)
    return 0


def cmd_carve(args) -> int:
    reports = carve.scan_path(
        Path(args.input),
        extract_dir=Path(args.extract) if args.extract else None,
    )
    if args.json:
        _json_print(reports)
        return 0
    for report in reports:
        if "error" in report:
            print(f"{report['source']}: {report['error']}")
            continue
        print(f"{report['source']} ({report['size']} bytes, sha256 {report['sha256'][:16]}…)")
        for container in report["containers"]:
            print(f"  container 0x{container['offset']:08X} {container['kind']}")
        for candidate in report["candidates"]:
            print(f"  marker {candidate['marker']!r} at 0x{candidate['offset']:08X} "
                  f"({candidate['marker_meaning']}) entropy={candidate['entropy']}")
            for text in candidate["strings"][:6]:
                print(f"      {text!r}")
        if not report["candidates"]:
            print("  no TPM markers found")
    return 0


def cmd_selftest(args) -> int:
    """Round-trip checks that need no hardware."""
    command = build(0x0000017A, u32(0x06) + u32(0x100) + u32(0x10))
    assert command[:2] == b"\x80\x01"
    assert int.from_bytes(command[2:6], "big") == len(command) == 22
    response = parse_response(bytes.fromhex("80010000000a00000000"))
    assert response.ok and response.tag == 0x8001
    assert decode_rc(0) == "SUCCESS"
    assert "AUTH_FAIL" in decode_rc(0x98E)
    assert frames.split_frames(command)[0][0].role == "command"
    print("selftest: ok")
    return 0


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tpm-re",
        description="Read-only reverse-engineering helpers for a local TPM 2.0",
    )
    parser.add_argument("--tcti", metavar="DEVICE",
                        help="TPM character device (default: /dev/tpmrm0, then /dev/tpm0)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("probe", help="full read-only dossier")
    p.add_argument("--vendor", action="store_true", help="also probe vendor properties")
    p.add_argument("--out", metavar="DIR", help="write tpm-dossier.{json,md} here")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("props", help="TPM properties")
    p.add_argument("--fixed", action="store_true")
    p.add_argument("--variable", action="store_true")
    p.set_defaults(func=cmd_props)

    p = sub.add_parser("caps", help="algorithms, PCR banks, command inventory")
    p.add_argument("--limit", type=int, default=32)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_caps)

    p = sub.add_parser("vendor", help="read the vendor property space (read-only)")
    p.add_argument("--start", type=lambda v: int(v, 0), default=0,
                   help="first vendor property to ask for (default 0)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_vendor)

    p = sub.add_parser("raw", help="send one raw command (read-only by default)")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--command", help="complete command as hex, header included")
    group.add_argument("--cc", help="command code, e.g. 0x17a")
    p.add_argument("--body", help="parameters as hex (no handles)")
    p.add_argument("--handles", help="handle area as hex (required with --password)")
    p.add_argument("--password", action="store_true",
                   help="insert an empty password session between handles and "
                        "parameters")
    p.add_argument("--allow-write", action="store_true",
                   help="permit commands outside the read-only allowlist")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_raw)

    p = sub.add_parser("pcrs", help="read PCR values")
    p.add_argument("--bank", default="sha256")
    p.add_argument("--indices", default="0-7")
    p.add_argument("--eventlog", metavar="PATH",
                   help="also parse a TCG event log file")
    p.set_defaults(func=cmd_pcrs)

    p = sub.add_parser("nv", help="enumerate or dump NV indices")
    p.add_argument("--index", help="NV index to read, e.g. 0x01c00002")
    p.add_argument("--dump-dir", metavar="DIR")
    p.add_argument("--head", type=int, default=128)
    p.set_defaults(func=cmd_nv)

    p = sub.add_parser("certs", help="dump endorsement key certificates")
    p.add_argument("--out", metavar="DIR")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_certs)

    p = sub.add_parser("acpi", help="ACPI TPM2 table and host inventory")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_acpi)

    p = sub.add_parser("frames", help="decode captured TPM byte streams")
    p.add_argument("input")
    p.add_argument("--role", choices=("auto", "command", "response"), default="auto")
    p.add_argument("--strace", action="store_true",
                   help="input is strace -xx read/write output")
    p.add_argument("--fd", type=int, default=None,
                   help="only use this file descriptor (default: all)")
    p.add_argument("--dump", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_frames)

    p = sub.add_parser("carve", help="scan vendor images for TPM firmware candidates")
    p.add_argument("input")
    p.add_argument("--extract", metavar="DIR")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_carve)

    p = sub.add_parser("selftest", help="offline sanity checks")
    p.set_defaults(func=cmd_selftest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (TransportError, WireError, caps.CapabilityError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
