"""Offline tests for the TPM recovery helper (no real suspend, no TPM)."""

import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import tpm_recover  # noqa: E402
from tpm_re.wire import ST_NO_SESSIONS, Response  # noqa: E402


def _response(params: bytes) -> Response:
    raw = struct.pack(">HII", ST_NO_SESSIONS, 10 + len(params), 0) + params
    return Response(tag=ST_NO_SESSIONS, size=len(raw), rc=0,
                    params=params, auth_area=b"", raw=raw)


class FakeTransport:
    """Minimal DeviceTransport stand-in keyed by command code."""

    def __init__(self, replies: dict[int, bytes], error: Exception | None = None):
        self.replies = replies
        self.error = error

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def transceive(self, command: bytes) -> Response:
        if self.error is not None:
            raise self.error
        cc = struct.unpack(">I", command[6:10])[0]
        return _response(self.replies.get(cc, b""))


class ProbeHealthTests(unittest.TestCase):
    def test_baseline_is_healthy(self):
        with mock.patch.object(tpm_recover, "DeviceTransport",
                               return_value=FakeTransport(tpm_recover.BASELINE)):
            healthy, lines = tpm_recover.probe_health()
        self.assertTrue(healthy)
        self.assertEqual(len(lines), 3)
        self.assertTrue(all("OK" in line for line in lines))

    def test_mismatched_response_is_wedged(self):
        bad = dict(tpm_recover.BASELINE)
        bad[0x20000213] = b"\x00" * 18
        with mock.patch.object(tpm_recover, "DeviceTransport",
                               return_value=FakeTransport(bad)):
            healthy, lines = tpm_recover.probe_health()
        self.assertFalse(healthy)
        self.assertIn("MISMATCH", " ".join(lines))

    def test_transport_error_is_wedged(self):
        boom = BrokenPipeError(32, "Broken pipe")
        with mock.patch.object(tpm_recover, "DeviceTransport",
                               return_value=FakeTransport({}, error=boom)):
            healthy, lines = tpm_recover.probe_health()
        self.assertFalse(healthy)
        self.assertTrue(any("BrokenPipeError" in line for line in lines))

    def test_open_failure_is_wedged(self):
        with mock.patch.object(
            tpm_recover, "DeviceTransport",
            side_effect=tpm_recover.TransportError("no device"),
        ):
            healthy, lines = tpm_recover.probe_health()
        self.assertFalse(healthy)
        self.assertTrue(any("no device" in line for line in lines))


class AlarmTests(unittest.TestCase):
    def test_arm_alarm_sets_and_verifies(self):
        with tempfile.TemporaryDirectory() as td:
            alarm = Path(td) / "wakealarm"
            alarm.write_text("")
            with mock.patch.object(tpm_recover, "RTC_ALARM", alarm):
                target = tpm_recover.arm_alarm(120)
            self.assertEqual(alarm.read_text().strip(), str(target))

    def test_arm_alarm_rejects_bad_write(self):
        class Stub:
            def write_text(self, value):
                pass  # ignore the write

            def read_text(self):
                return ""

        with mock.patch.object(tpm_recover, "RTC_ALARM", Stub()):
            with self.assertRaises(tpm_recover.RecoveryError):
                tpm_recover.arm_alarm(120)


class ArgsTests(unittest.TestCase):
    def test_defaults(self):
        args = tpm_recover.parse_args([])
        self.assertEqual(args.alarm_delay, 120)
        self.assertFalse(args.check_only)
        self.assertFalse(args.force)
        self.assertFalse(args.dry_run)


if __name__ == "__main__":
    unittest.main()
