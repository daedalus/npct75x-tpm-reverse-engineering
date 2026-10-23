import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from tpm_re import caps, device, tables


def agile_event(pcr: int, event_type: int, digests: list[tuple[int, bytes]], payload: bytes) -> bytes:
    out = pcr.to_bytes(4, "big") + event_type.to_bytes(4, "big")
    out += len(digests).to_bytes(4, "big")
    for alg, digest in digests:
        out += alg.to_bytes(2, "big") + digest
    out += len(payload).to_bytes(4, "big") + payload
    return out


def legacy_event(pcr: int, event_type: int, digest: bytes, payload: bytes) -> bytes:
    return (
        pcr.to_bytes(4, "big")
        + event_type.to_bytes(4, "big")
        + digest
        + len(payload).to_bytes(4, "big")
        + payload
    )


class EventLogTests(unittest.TestCase):
    def test_agile_event(self):
        payload = "Spec ID Event03".encode("utf-16-le")
        log = agile_event(0, 0x03, [(0x000B, b"\x11" * 32), (0x0004, b"\x22" * 20)], payload)
        events = device.parse_event_log(log)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertTrue(event["agile"])
        self.assertEqual(event["pcr"], 0)
        self.assertEqual(event["type_name"], "EV_NO_ACTION")
        self.assertEqual([d["name"] for d in event["digests"]], ["SHA256", "SHA1"])
        self.assertEqual(event["event_text"], "Spec ID Event03")

    def test_legacy_event(self):
        log = legacy_event(4, 0x04, b"\x33" * 20, b"\x00\x00\x00\x00")
        events = device.parse_event_log(log)
        self.assertEqual(len(events), 1)
        self.assertFalse(events[0]["agile"])
        self.assertEqual(events[0]["pcr"], 4)
        self.assertEqual(events[0]["type_name"], "EV_SEPARATOR")

    def test_multiple_events(self):
        log = (
            agile_event(0, 0x03, [(0x000B, b"\x11" * 32)], b"\x00\x00")
            + legacy_event(7, 0x01, b"\x44" * 20, b"POST CODE")
        )
        events = device.parse_event_log(log)
        self.assertEqual([e["pcr"] for e in events], [0, 7])

    def test_truncated_tail_reported(self):
        log = agile_event(0, 0x03, [(0x000B, b"\x11" * 32)], b"") + b"\x00\x01"
        events = device.parse_event_log(log)
        self.assertTrue(any("error" in e for e in events))


class NvAttributeTests(unittest.TestCase):
    def test_observed_ek_certificate_bits(self):
        # TPMA_NV read from this host's RSA EK certificate index.
        flags = tables.decode_nv_attributes(0x620F1408)
        for expected in ("POLICYWRITE", "POLICY_DELETE", "WRITEALL", "PPREAD",
                         "OWNERREAD", "AUTHREAD", "POLICYREAD", "NO_DA",
                         "WRITTEN", "PLATFORMCREATE"):
            self.assertIn(expected, flags)
        self.assertIn("NT_ORDINARY", flags)

    def test_unknown_bits_surface(self):
        flags = tables.decode_nv_attributes(0x0000000C)
        self.assertIn("AUTHWRITE", flags)
        self.assertIn("POLICYWRITE", flags)
        flags = tables.decode_nv_attributes(0x00000300)  # bits 8-9 are reserved
        self.assertIn("UNKNOWN_0x00000300", flags)


class PropertyFormattingTests(unittest.TestCase):
    def test_four_cc_strings(self):
        self.assertIn("NTC", caps.format_property(0x105, 0x4E544300))
        self.assertIn("NPCT", caps.format_property(0x106, 0x4E504354))

    def test_revision_bcd(self):
        self.assertEqual(caps.format_property(0x102, 0x8A), "1.38")

    def test_vendor_property_name(self):
        self.assertEqual(caps.property_name(0x20000001), "VENDOR_0x20000001")
        self.assertEqual(caps.property_name(0x105), "MANUFACTURER")
        self.assertEqual(caps.property_name(0x7FF), "PT_0x000007FF")

    def test_flag_decode(self):
        flags = caps.decode_flags(0x00000006, tables.PERMANENT_BITS)
        self.assertEqual(flags, ["endorsementAuthSet", "lockoutAuthSet"])


class CcTests(unittest.TestCase):
    def test_names(self):
        self.assertEqual(tables.describe_cc(0x17A), "GetCapability")
        self.assertEqual(tables.describe_cc(0x14E), "NV_Read")
        self.assertEqual(tables.describe_cc(0x20000001), "VENDOR_0x20000001")
        self.assertEqual(tables.describe_cc(0x1FF), "UNKNOWN_0x000001FF")


if __name__ == "__main__":
    unittest.main()
