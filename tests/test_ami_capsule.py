import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tpm_re import firmware


def make_capsule(version=0x03000000, lowest=0x01000000,
                 version_data=b"\x02\x00\x00\x1a",
                 firmware_data=b"Nuvoton NPCT75x firmware image"):
    """Build a synthetic AMI TPM FMP capsule image.

    Layout decoded from section1.pe SetImage (knowledge/NPCT75x.md 7.1):

        +0x00  "AMI " magic
        +0x04  u32 section-table offset, relative to this capsule
        +0x08  8 reserved bytes
        +0x10  u32 version
        +0x14  u32 lowest supported version
        table: u32 count, 12 reserved, then 16-byte descriptors
        descriptor: u64 data offset (relative to table), u32 type, u32 size
    """
    table_rel = 0x18
    fixed = (firmware.AMI_MAGIC + struct.pack("<I", table_rel) + b"\x00" * 8
             + struct.pack("<II", version, lowest))
    assert len(fixed) == table_rel

    # Descriptor offsets are relative to the section-table base: 0x10 header
    # plus two 0x10 descriptors puts the first payload at 0x30.
    ver_off = 0x30
    fw_off = ver_off + len(version_data)
    table = struct.pack("<I", 2) + b"\x00" * 12
    table += struct.pack("<QII", ver_off, firmware.AMI_SECTION_VERSION,
                         len(version_data))
    table += struct.pack("<QII", fw_off, firmware.AMI_SECTION_FIRMWARE,
                         len(firmware_data))
    return fixed + table + version_data + firmware_data


class AmiCapsuleTests(unittest.TestCase):
    def test_parses_synthetic_capsule(self):
        blob = make_capsule()
        caps = firmware.scan_ami_capsules(blob)
        self.assertEqual(len(caps), 1)
        cap = caps[0]
        self.assertEqual(cap.version, 0x03000000)
        self.assertEqual(cap.lowest_supported_version, 0x01000000)
        self.assertEqual(cap.section_table_offset, 0x18)
        self.assertEqual([s.section_type for s in cap.sections], [1, 2])

    def test_firmware_section_is_extractable(self):
        payload = b"TPM2 firmware payload \x00\x01\x02"
        cap = firmware.scan_ami_capsules(make_capsule(firmware_data=payload))[0]
        sec = cap.firmware_section
        self.assertIsNotNone(sec)
        self.assertTrue(cap.has_firmware)
        blob = make_capsule(firmware_data=payload)
        self.assertEqual(blob[sec.data_offset:sec.data_offset + sec.size],
                         payload)

    def test_rejects_missing_firmware_section(self):
        blob = bytearray(make_capsule())
        # Change the second descriptor's type away from the required value.
        desc = 0x18 + 0x10 + 0x10
        struct.pack_into("<I", blob, desc + 8, 3)
        self.assertEqual(firmware.scan_ami_capsules(bytes(blob)), [])

    def test_rejects_truncated_section_table(self):
        blob = make_capsule()
        self.assertEqual(firmware.scan_ami_capsules(blob[:-8]), [])

    def test_rejects_section_data_past_end(self):
        blob = bytearray(make_capsule())
        desc = 0x18 + 0x10 + 0x10
        struct.pack_into("<Q", blob, desc, 0xffff0000)
        self.assertEqual(firmware.scan_ami_capsules(bytes(blob)), [])

    def test_finds_multiple_capsules_in_noise(self):
        first = make_capsule(version=1)
        second = make_capsule(version=2)
        blob = b"\xff" * 13 + first + b"\x00" * 7 + second
        caps = firmware.scan_ami_capsules(blob)
        self.assertEqual([c.version for c in caps], [1, 2])
        self.assertEqual(caps[0].offset, 13)
        self.assertEqual(caps[1].offset, 13 + len(first) + 7)

    def test_ignores_bare_magic_and_random_data(self):
        self.assertEqual(firmware.scan_ami_capsules(b"AMI "), [])
        self.assertEqual(firmware.scan_ami_capsules(b"\xff" * 512 + b"AMI "), [])

    def test_cli_scans_and_extracts(self):
        import contextlib
        import io
        import tempfile

        from tpm_re.cli import main

        payload = b"TPM2 firmware payload"
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "capsule.bin"
            out = Path(td) / "fw.bin"
            src.write_bytes(make_capsule(firmware_data=payload))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["ami", str(src), "--extract", str(out)])
            self.assertEqual(rc, 0)
            self.assertIn("1 AMI capsule(s)", buf.getvalue())
            self.assertEqual(out.read_bytes(), payload)

    def test_to_dict_is_json_friendly(self):
        cap = firmware.scan_ami_capsules(make_capsule())[0]
        d = cap.to_dict()
        self.assertEqual(d["version"], "0x03000000")
        self.assertEqual(d["has_firmware"], True)
        self.assertEqual(len(d["sections"]), 2)
        self.assertEqual(d["sections"][1]["type"], 2)


if __name__ == "__main__":
    unittest.main()
