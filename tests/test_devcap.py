import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tpm_re import firmware


def make_devcap(chunks=(b"AAAA", b"BBBB")):
    """Build a synthetic DevCap container with a vendor-command script."""
    cmds = b""
    cmds += struct.pack(">HII", 0x8001, 15, 0x20000200) + b"setup"
    for chunk in chunks:
        params = b"\x00" * 16 + chunk
        cmds += struct.pack(">HII", 0x8001, 10 + len(params), 0x20000202) + params
    cmds += struct.pack(">HII", 0x8001, 15, 0x20000203) + b"final"

    desc = (firmware.DEVCAP_MAGIC + struct.pack("<I", 1)
            + struct.pack("<Q", len(cmds)) + b"\x00" * 8)
    assert len(desc) == 0x20
    header = struct.pack("<I", 1) + firmware.DEVCAP_CONTAINER_GUID
    header += struct.pack("<IIIII", len(cmds) + 0x220, 0, len(cmds) + 0x200,
                          0x100, 0x256)
    header += struct.pack("<II", 0x100, len(cmds) + 0x100)
    return header + b"\x00" * (0x5800 - len(header)) + desc + cmds + b"\x11" * 0x100


class DevCapScriptTests(unittest.TestCase):
    def test_parse_synthetic(self):
        data = make_devcap()
        script = firmware.scan_devcap_script(data)
        self.assertIsNotNone(script)
        self.assertEqual(script.descriptor_offset, 0x5800)
        self.assertEqual(script.script_offset, 0x5820)
        self.assertEqual(len(script.commands), 4)
        self.assertEqual([c.cc for c in script.commands],
                         [0x20000200, 0x20000202, 0x20000202, 0x20000203])
        self.assertEqual(script.firmware, b"AAAABBBB")
        self.assertEqual(hashlib.sha256(script.firmware).hexdigest(),
                         script.to_dict()["firmware_sha256"])

    def test_bad_guid_rejected(self):
        data = bytearray(make_devcap())
        data[4] ^= 0xFF
        self.assertIsNone(firmware.scan_devcap_script(bytes(data)))

    def test_bad_script_size_rejected(self):
        data = bytearray(make_devcap())
        struct.pack_into("<Q", data, 0x5810, 1234)
        self.assertIsNone(firmware.scan_devcap_script(bytes(data)))

    def test_truncated_command_rejected(self):
        data = bytearray(make_devcap())
        struct.pack_into(">I", data, 0x5820 + 2, 9999)
        self.assertIsNone(firmware.scan_devcap_script(bytes(data)))

    def test_real_nuvoton_package_if_present(self):
        path = Path("/tmp/opencode/fwpkg/extracted/nuvoton/NuvotonTpmDevCap.BIN")
        if not path.exists():
            self.skipTest("Lenovo Nuvoton package not downloaded")
        script = firmware.scan_devcap_script(path.read_bytes())
        self.assertIsNotNone(script)
        self.assertEqual(len(script.commands), 257)
        self.assertEqual(len(script.firmware), 232840)
        self.assertEqual(hashlib.sha256(script.firmware).hexdigest(),
                         "6659e5c55beb02bf55ecb818b7cb9288e59e7cd5e4ee6f0254f7e0b37b42ca16")


if __name__ == "__main__":
    unittest.main()
