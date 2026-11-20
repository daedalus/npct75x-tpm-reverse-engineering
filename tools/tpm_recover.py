#!/usr/bin/env python3
"""Recover a wedged NPCT75x TPM with one S3 suspend/resume cycle.

This encodes the procedure that worked on 2026-11-20 (knowledge/NPCT75x.md
§10.15).  A wedge shows up as ``EINVAL`` on writes to ``/dev/tpm*`` and read
timeouts; the platform device is still bound, so the tpm_tis driver's resume
callback re-initialises the TIS interface without a reboot.

What this script does
---------------------

1. Probe three known read-only vendor commands and compare with the live
   baseline captured on this machine.  If they already match, do nothing.
2. Verify the platform device is still bound.  If it has disappeared, S3
   cannot help -- external hardware restoration is the only known route.
3. Arm a RTC wakealarm, then suspend to RAM (``mem``) and wait for resume.
4. Probe again and report whether the TPM recovered.

What this script never does
---------------------------

* No erase/write/commit, no ``0x2000012f``/``0x20000211``, no DevCap replay.
* No PPI request (``transition_action`` is ``2: Reboot``, and guessing an op
  code can select ``TPM Clear``).
* No reboot, no power cycle, no module unload/rebind, no /dev/mem poking
  (blocked by ``CONFIG_STRICT_DEVMEM`` anyway).

Usage::

    sudo python3 tools/tpm_recover.py              # probe, then S3 if wedged
    python3 tools/tpm_recover.py --check-only      # probe only, no root needed
    sudo python3 tools/tpm_recover.py --force      # S3 even if currently healthy
    sudo python3 tools/tpm_recover.py --dry-run     # show steps, do not suspend

The RTC alarm is mandatory: without a wake source the machine would stay
suspended until physical intervention.  The script arms and verifies it
before writing to ``/sys/power/state``.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tpm_re.transport import DeviceTransport, TransportError  # noqa: E402
from tpm_re.vendor_probe import send_vendor  # noqa: E402

# Read-only commands with fixed responses observed on the healthy NPCT75x
# (knowledge/NPCT75x.md §10.15).  A wedge makes all of them time out or fail.
BASELINE: dict[int, bytes] = {
    0x20000204: bytes.fromhex("0200001a"),
    0x20000213: bytes.fromhex("ffffa700fbff7ffffbfffffffbf0ffffaaaa"),
    0x20000216: b"",
}

DEFAULT_DEVICE = "MSFT0101:00"
POWER_STATE = Path("/sys/power/state")
RTC_ALARM = Path("/sys/class/rtc/rtc0/wakealarm")
DRIVER_DIR = Path("/sys/bus/platform/drivers/tpm_tis")


class RecoveryError(RuntimeError):
    """A precondition failed; no suspend was attempted."""


def probe_health(path: str | None = None, timeout_s: float = 5.0) -> tuple[bool, list[str]]:
    """Return ``(healthy, observations)`` from the three baseline commands.

    Any transport error (``BrokenPipeError``, ``EINVAL``, timeout, ...) counts
    as unhealthy.  The caller may run this without root as long as it can open
    ``/dev/tpmrm0``.
    """
    observations: list[str] = []
    healthy = True
    try:
        with DeviceTransport(path=path, timeout_s=timeout_s) as tpm:
            for cc, expected in BASELINE.items():
                try:
                    result = send_vendor(tpm, cc)
                except Exception as exc:  # noqa: BLE001 - any failure means wedge
                    healthy = False
                    observations.append(
                        f"0x{cc:08X}: ERROR {type(exc).__name__}: {exc}"
                    )
                    continue
                match = result.rc == 0 and result.params == expected
                healthy &= match
                observations.append(
                    f"0x{cc:08X}: rc=0x{result.rc:03X} "
                    f"params={result.params.hex() or '<empty>'} "
                    f"{'OK' if match else 'MISMATCH (expected ' + expected.hex() + ')'}"
                )
    except TransportError as exc:
        healthy = False
        observations.append(f"transport: {exc}")
    return healthy, observations


def check_preconditions(device: str) -> None:
    """Fail early if the platform device is gone or S3 is unavailable."""
    bound = DRIVER_DIR / device
    if not bound.exists():
        raise RecoveryError(
            f"platform device {device} is not bound to tpm_tis. "
            "S3 cannot recover a device that is no longer enumerated; "
            "external hardware restoration is required."
        )
    if not POWER_STATE.exists():
        raise RecoveryError(f"{POWER_STATE} missing: suspend support unavailable")
    if "mem" not in POWER_STATE.read_text().split():
        raise RecoveryError(f"'mem' is not a supported suspend state in {POWER_STATE}")
    if not RTC_ALARM.exists():
        raise RecoveryError(f"{RTC_ALARM} missing: cannot guarantee a wake source")


def arm_alarm(delay_s: int) -> int:
    """Clear, set and verify the RTC wakealarm; return the target epoch."""
    target = int(time.time()) + delay_s
    RTC_ALARM.write_text("0\n")
    RTC_ALARM.write_text(f"{target}\n")
    armed = RTC_ALARM.read_text().strip()
    if not armed or int(armed) != target:
        raise RecoveryError(
            f"RTC alarm verification failed: wrote {target}, read {armed!r}"
        )
    return target


def suspend_and_wait(delay_s: int) -> None:
    """Arm the alarm, suspend to RAM, and return once the system resumes."""
    target = arm_alarm(delay_s)
    print(f"[*] RTC wakealarm armed for epoch {target} (+{delay_s}s)")
    print("[*] suspending to mem; waiting for a wake source...")
    POWER_STATE.write_text("mem\n")
    # Writing to /sys/power/state blocks until resume.  An unknown wake source
    # may fire early; that is fine, we only care that we came back.
    print(f"[*] resumed at epoch {int(time.time())}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--check-only", action="store_true",
                   help="probe TPM health and exit; never suspend")
    p.add_argument("--force", action="store_true",
                   help="suspend even if the TPM currently looks healthy")
    p.add_argument("--dry-run", action="store_true",
                   help="print the steps but do not suspend")
    p.add_argument("--device", default=DEFAULT_DEVICE,
                   help=f"platform device name (default: {DEFAULT_DEVICE})")
    p.add_argument("--alarm-delay", type=int, default=120,
                   help="RTC wakealarm delay in seconds (default: 120)")
    p.add_argument("--tcti", default=None,
                   help="TPM device path (default: auto-detect /dev/tpmrm0, /dev/tpm0)")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="per-command probe timeout in seconds (default: 5)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.alarm_delay < 10:
        print("--alarm-delay must be at least 10 seconds", file=sys.stderr)
        return 2

    print("[*] probing TPM health")
    healthy, observations = probe_health(args.tcti, args.timeout)
    for line in observations:
        print(f"    {line}")
    print(f"[*] TPM is {'healthy' if healthy else 'WEDGED'}")

    if args.check_only:
        return 0 if healthy else 1
    if healthy and not args.force:
        print("[*] nothing to do; use --force to suspend anyway")
        return 0

    if os.geteuid() != 0:
        print("root is required to suspend and set the RTC alarm; "
              "re-run with sudo (or use --check-only)", file=sys.stderr)
        return 2

    try:
        check_preconditions(args.device)
    except RecoveryError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print("[*] dry run: would arm RTC alarm and suspend to mem")
        return 0

    try:
        suspend_and_wait(args.alarm_delay)
    except Exception as exc:  # noqa: BLE001 - surface any suspend failure
        print(f"[!] suspend failed: {exc}", file=sys.stderr)
        return 1

    print("[*] re-probing TPM health after resume")
    recovered, observations = probe_health(args.tcti, args.timeout)
    for line in observations:
        print(f"    {line}")
    if recovered:
        print("[+] TPM recovered")
        return 0
    print("[!] TPM still wedged after S3; external hardware restoration "
          "is the remaining known route", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
