import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from tpm_re import acpi


def make_table(start_method: int = 2, control: int = 0xFED40000, extra: bytes = b"\x00" * 24) -> bytes:
    total = 52 + len(extra)
    header = bytearray(36)
    header[0:4] = b"TPM2"
    header[4:8] = total.to_bytes(4, "little")
    header[8] = 2
    header[10:16] = b"LENOVO"
    header[16:24] = b"TPM2TBL "
    body = bytearray()
    body += (0).to_bytes(2, "little")      # platform class
    body += (0).to_bytes(2, "little")      # reserved
    body += control.to_bytes(8, "little")
    body += start_method.to_bytes(4, "little")
    return bytes(header) + bytes(body) + extra


class ParseTests(unittest.TestCase):
    def test_fifo_table(self):
        table = acpi.parse_tpm2_table(make_table())
        self.assertEqual(table.signature, "TPM2")
        self.assertEqual(table.length, 76)
        self.assertEqual(table.oem_id, "LENOVO")
        self.assertEqual(table.control_address, 0xFED40000)
        self.assertEqual(table.start_method, 2)
        self.assertIn("FIFO", table.to_dict()["start_method_name"])
        self.assertEqual(table.problems, [])

    def test_fields_are_little_endian(self):
        data = make_table(start_method=6, control=0x00000000FED40040)
        self.assertEqual(data[48:52], b"\x06\x00\x00\x00")
        table = acpi.parse_tpm2_table(data)
        self.assertEqual(table.start_method, 6)
        self.assertEqual(table.control_address, 0xFED40040)

    def test_crb_table(self):
        table = acpi.parse_tpm2_table(make_table(start_method=3))
        self.assertIn("CRB", table.to_dict()["start_method_name"])

    def test_unknown_start_method_is_flagged(self):
        table = acpi.parse_tpm2_table(make_table(start_method=0x42))
        self.assertTrue(any("start method" in p for p in table.problems))

    def test_short_table_rejected(self):
        with self.assertRaises(ValueError):
            acpi.parse_tpm2_table(b"TPM2" + b"\x00" * 8)

    def test_bad_signature_recorded(self):
        data = bytearray(make_table())
        data[0:4] = b"XXXX"
        table = acpi.parse_tpm2_table(bytes(data))
        self.assertTrue(any("signature" in p for p in table.problems))


class InventoryTests(unittest.TestCase):
    def test_collect_shape(self):
        report = acpi.collect()
        for key in ("platform", "tpm_sysfs", "acpi_tpm2", "acpi_tpm2_note",
                    "kernel_tpm_config", "tpm_modules_present", "event_log"):
            self.assertIn(key, report)
        self.assertIn("kernel", report["platform"])


if __name__ == "__main__":
    unittest.main()
