import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from tpm_re import caps
from tpm_re.wire import Response


def capability_reply(cap: int, body: bytes, more: int = 0) -> Response:
    params = bytes([more]) + struct.pack(">I", cap) + body
    return Response(tag=0x8001, size=10 + len(params), rc=0, params=params)


class FakeTPM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.commands = []

    def transceive(self, command):
        self.commands.append(command)
        return self.replies.pop(0)


class PropertyTests(unittest.TestCase):
    def test_pages_fixed_properties(self):
        first = capability_reply(
            caps.tables.CAP_TPM_PROPERTIES,
            struct.pack(">I", 1) + struct.pack(">II", 0x100, 0x322E3000),
            more=1,
        )
        second = capability_reply(
            caps.tables.CAP_TPM_PROPERTIES,
            struct.pack(">I", 1) + struct.pack(">II", 0x101, 0),
            more=0,
        )
        # variable properties, one empty page each base
        empty_fixed_done = capability_reply(
            caps.tables.CAP_TPM_PROPERTIES,
            struct.pack(">I", 0),
            more=0,
        )
        empty_var = capability_reply(
            caps.tables.CAP_TPM_PROPERTIES,
            struct.pack(">I", 0),
            more=0,
        )
        tpm = FakeTPM([first, second, empty_fixed_done, empty_var])
        props = caps.properties(tpm)
        self.assertEqual(props.fixed, {0x100: 0x322E3000, 0x101: 0})
        # second call must have continued after the last property
        request = tpm.commands[1]
        self.assertEqual(struct.unpack(">I", request[14:18])[0], 0x101)

    def test_capability_echo_mismatch_is_an_error(self):
        tpm = FakeTPM([capability_reply(0x01, struct.pack(">I", 0))])
        with self.assertRaises(caps.CapabilityError):
            caps._get(tpm, caps.tables.CAP_TPM_PROPERTIES, 0x100, 1)


class CommandTests(unittest.TestCase):
    def test_tpma_cc_entries_are_four_bytes(self):
        # NV_Read: plain command; a vendor code with the V bit set
        body = struct.pack(">I", 2)
        body += struct.pack(">I", 0x0000014E)
        body += struct.pack(">I", 0x200000FF)
        tpm = FakeTPM([
            capability_reply(caps.tables.CAP_COMMANDS, body, more=0),
        ])
        commands = caps.commands(tpm)
        self.assertEqual([c["cc"] for c in commands], [0x14E, 0x200000FF])
        self.assertEqual(commands[1]["name"], "VENDOR_0x200000FF")
        self.assertFalse(commands[0]["vendor"])
        self.assertTrue(commands[1]["vendor"])

    def test_duplicate_command_stops_paging(self):
        body = struct.pack(">I", 1) + struct.pack(">I", 0x0000014E)
        tpm = FakeTPM([
            capability_reply(caps.tables.CAP_COMMANDS, body, more=1),
            capability_reply(caps.tables.CAP_COMMANDS, body, more=1),
        ])
        commands = caps.commands(tpm)
        self.assertEqual(len(commands), 1)
        self.assertEqual(len(tpm.replies), 0)


class HandleTests(unittest.TestCase):
    def test_handles_follow_more_data(self):
        first = capability_reply(
            caps.tables.CAP_HANDLES,
            struct.pack(">III", 2, 0x01802006, 0x01C00002), more=1,
        )
        second = capability_reply(
            caps.tables.CAP_HANDLES, struct.pack(">II", 1, 0x01C0000A), more=0,
        )
        tpm = FakeTPM([first, second])
        self.assertEqual(caps.handles(tpm, 0x01000000),
                         [0x01802006, 0x01C00002, 0x01C0000A])
        # second page starts after the last handle seen
        self.assertEqual(struct.unpack(">I", tpm.commands[1][14:18])[0], 0x01C00003)


class VendorPropertyTests(unittest.TestCase):
    def test_vendor_capability_and_paging(self):
        first = capability_reply(
            caps.tables.CAP_VENDOR_PROPERTY,
            struct.pack(">I", 2)
            + struct.pack(">II", 0, 0)
            + struct.pack(">II", 1, 0x1AD090),
            more=1,
        )
        second = capability_reply(
            caps.tables.CAP_VENDOR_PROPERTY,
            struct.pack(">I", 1) + struct.pack(">II", 2, 0x4BF0),
            more=0,
        )
        tpm = FakeTPM([first, second])
        found = caps.vendor_properties(tpm)
        self.assertEqual(
            [(e["property"], e["value"]) for e in found],
            [(0, 0), (1, 0x1AD090), (2, 0x4BF0)],
        )
        # the vendor capability code is 0x100, not TPM_PROPERTIES
        self.assertEqual(struct.unpack(">I", tpm.commands[0][10:14])[0], 0x100)


if __name__ == "__main__":
    unittest.main()
