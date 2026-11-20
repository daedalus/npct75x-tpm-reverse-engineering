#!/usr/bin/env python3
"""Probe FUM setup PLATFORM authorisation without touching firmware state.

Consolidates the one-off ``opencode/fum_*.py`` scripts into a single,
reviewable tool.  The only state-touching command it can emit is the vendor
setup command ``0x20000200`` with the PLATFORM handle ``0x4000000C``; a wrong
password returns ``BAD_AUTH`` (no DA lockout on the platform hierarchy).

Safety invariants
-----------------

* Never sends ``0x2000012f``, ``0x20000211``, ``0x20000202``, ``0x20000214``,
  erase, write, commit, or a full DevCap replay.
* Captures the read-only ``0x20000213`` baseline before and after; aborts if
  the TPM is not healthy at the start and reports any change at the end.
* ``--check-only`` performs only read-only health queries.

Usage::

    python3 tools/fum_probe.py --check-only
    python3 tools/fum_probe.py --list-candidates
    python3 tools/fum_probe.py                       # all candidates, setup only
    python3 tools/fum_probe.py --candidate nvauth_32
    python3 tools/fum_probe.py --tcti /dev/tpmrm0 --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tpm_re.transport import DeviceTransport  # noqa: E402
from tpm_re.fum import (  # noqa: E402
    FUM_SETUP_CC,
    HEALTH_BASELINE,
    HEALTH_CC,
    candidate_auths,
    setup_command,
)
from tpm_re.firmware import scan_devcap_script  # noqa: E402
from tpm_re.wire import build, decode_rc  # noqa: E402

DEVCAP_DEFAULT = ROOT / "out/firmware/NuvotonTpmDevCap.BIN"


def health(t: DeviceTransport) -> tuple[bool, str]:
    """Return (healthy, hex) from the read-only 0x20000213 baseline."""
    resp = t.transceive(build(HEALTH_CC))
    if resp.rc != 0:
        return False, f"rc={resp.rc:03X} ({decode_rc(resp.rc)})"
    return resp.params == HEALTH_BASELINE, resp.params.hex()


def load_setup_params(path: Path) -> bytes:
    """Return the setup (CC 0x20000200) parameter block from a DevCap file."""
    script = scan_devcap_script(path.read_bytes())
    matches = [c for c in script.commands if c.cc == FUM_SETUP_CC]
    if len(matches) != 1:
        raise ValueError(f"{path}: expected one setup command, found {len(matches)}")
    return matches[0].params


def run(args: argparse.Namespace) -> int:
    cands = candidate_auths()
    if args.list_candidates:
        for name, auth in cands.items():
            print(f"{name:34s} {auth.hex()}")
        return 0

    params = load_setup_params(args.devcap)
    results = []

    with DeviceTransport(args.tcti, timeout_s=15) as t:
        ok, before = health(t)
        if not ok:
            print(f"TPM not at expected health baseline: {before}", file=sys.stderr)
            return 2
        if args.check_only:
            print(f"healthy: {before}")
            return 0

        names = [args.candidate] if args.candidate else list(cands)
        unknown = [n for n in names if n not in cands]
        if unknown:
            print(f"unknown candidate(s): {', '.join(unknown)}", file=sys.stderr)
            return 2

        for name in names:
            try:
                resp = t.transceive(setup_command(params, cands[name]))
                results.append({
                    "candidate": name,
                    "rc": f"0x{resp.rc:03X}",
                    "rc_name": decode_rc(resp.rc),
                    "ok": resp.ok,
                    "params": resp.params.hex(),
                })
                if args.json:
                    continue
                print(f"{name:34s} rc={resp.rc:03X} ({decode_rc(resp.rc)}) "
                      f"len={len(resp.params)}")
                if resp.ok:
                    print("*** SETUP ACCEPTED", resp.params.hex()[:100])
            except Exception as exc:  # noqa: BLE001 - evidence gathering
                results.append({"candidate": name, "error": f"{type(exc).__name__}: {exc}"})
                if not args.json:
                    print(f"{name:34s} EXC {type(exc).__name__}: {exc}")

        ok_after, after = health(t)

    if args.json:
        json.dump({"before": before, "after": after, "healthy": ok_after,
                   "results": results}, sys.stdout, indent=2)
        print()
    else:
        print(f"after 0x{HEALTH_CC:08X}: {after} "
              f"({'HEALTHY' if ok_after else 'BASELINE CHANGED'})")
    return 0 if ok_after else 3


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tcti", default="/dev/tpmrm0", help="TPM device path")
    p.add_argument("--devcap", type=Path, default=DEVCAP_DEFAULT,
                   help="DevCap BIN supplying the 302-byte setup params")
    p.add_argument("--candidate", help="probe only this named candidate")
    p.add_argument("--list-candidates", action="store_true",
                   help="print candidate names/paths and exit (no TPM access)")
    p.add_argument("--check-only", action="store_true",
                   help="only verify the read-only health baseline")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args()
    try:
        raise SystemExit(run(args))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
