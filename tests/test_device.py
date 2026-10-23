import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import struct
import unittest

from tpm_re import caps, device, tables
from tpm_re.wire import Response


class FakeTPM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.commands = []

    def transceive(self, command):
        self.commands.append(command)
        return self.replies.pop(0)


def ok(params: bytes) -> Response:
    return Response(tag=0x8001, size=10 + len(params), rc=0, params=params)


def pcr_reply(counter: int, alg: int, indices: list[int], fill: int) -> Response:
    bitmap = bytearray(3)
    for index in indices:
        bitmap[index // 8] |= 1 << (index % 8)
    body = struct.pack(">I", counter)
    body += struct.pack(">IHB", 1, alg, 3) + bytes(bitmap)
    body += struct.pack(">I", len(indices))
    for index in indices:
        body += struct.pack(">H", 32) + bytes([fill + index]) * 32
    return ok(body)


def nv_public_reply(index: int, attributes: int, size: int) -> Response:
    inner = struct.pack(">IHI", index, 0x000B, attributes) + struct.pack(">H", 0)
    inner += struct.pack(">H", size)
    return ok(struct.pack(">H", len(inner)) + inner + struct.pack(">H", 0))


def agile_event(pcr: int, event_type: int, digests: list[tuple[int, bytes]], payload: bytes) -> bytes:
    out = pcr.to_bytes(4, "little") + event_type.to_bytes(4, "little")
    out += len(digests).to_bytes(4, "little")
    for alg, digest in digests:
        out += alg.to_bytes(2, "little") + digest
    out += len(payload).to_bytes(4, "little") + payload
    return out


def legacy_event(pcr: int, event_type: int, digest: bytes, payload: bytes) -> bytes:
    return (
        pcr.to_bytes(4, "little")
        + event_type.to_bytes(4, "little")
        + digest
        + len(payload).to_bytes(4, "little")
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


class PcrReadTests(unittest.TestCase):
    def test_pages_past_eight_and_labels_digests(self):
        tpm = FakeTPM([
            pcr_reply(5, 0x000B, list(range(8)), 0),
            pcr_reply(5, 0x000B, list(range(8, 16)), 0),
            pcr_reply(6, 0x000B, [16, 17], 0),
        ])
        result = device.pcr_read(tpm, [0x000B], list(range(18)))
        self.assertEqual([e["pcr"] for e in result["pcrs"]], list(range(18)))
        self.assertEqual(result["pcrs"][17]["digest"], bytes([17]) * 32)
        self.assertEqual(result["missing"], {})
        self.assertTrue(result["counter_changed"])
        self.assertEqual(len(tpm.commands), 3)

    def test_unallocated_bank_is_reported_missing(self):
        empty = ok(struct.pack(">III", 7, 0, 0))
        result = device.pcr_read(FakeTPM([empty]), [0x000C], [0, 1])
        self.assertEqual(result["pcrs"], [])
        self.assertEqual(result["missing"], {0x000C: [0, 1]})


class NvSafetyTests(unittest.TestCase):
    def test_refuses_index_without_no_da(self):
        tpm = FakeTPM([nv_public_reply(0x01500000, 0x00040004 | 0x20000000, 16)])
        with self.assertRaises(device.DeviceError):
            device.nv_dump(tpm, 0x01500000)
        self.assertEqual(len(tpm.commands), 1)  # NV_Read was never sent

    def test_no_da_index_reads_in_nv_buffer_max_chunks(self):
        props = struct.pack(">B", 0) + struct.pack(">I", tables.CAP_TPM_PROPERTIES)
        props += struct.pack(">III", 1, 0x12C, 4)
        nv_data = lambda data: Response(  # noqa: E731
            tag=0x8002, size=0, rc=0,
            params=struct.pack(">H", len(data)) + data,
        )
        tpm = FakeTPM([
            nv_public_reply(0x01C00002, 0x620F1408, 6),
            ok(props),
            nv_data(b"abcd"),
            nv_data(b"ef"),
        ])
        self.assertEqual(device.nv_dump(tpm, 0x01C00002), b"abcdef")
        sizes = [struct.unpack(">H", c[-4:-2])[0] for c in tpm.commands[2:]]
        self.assertEqual(sizes, [4, 2])


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
