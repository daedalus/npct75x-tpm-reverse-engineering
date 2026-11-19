import sys
import struct
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tpm_re import firmware, sigrok, vendor_probe


class SigrokParserTests(unittest.TestCase):
    def test_keeps_requested_direction(self):
        text = (
            "spi:mosi: 0x80\n"
            "spi:mosi: 0x01\n"
            "spi:miso: 0xff\n"
        )
        data, used = sigrok.parse_annotations(text, direction="mosi")
        self.assertEqual(data, b"\x80\x01")
        self.assertEqual(used, 2)

    def test_contiguous_hex_annotation(self):
        data, _ = sigrok.parse_annotations("spi:mosi: 80010000000c\n")
        self.assertEqual(data, bytes.fromhex("80010000000c"))

    def test_hexdump_roundtrips_through_frames(self):
        from tpm_re import frames

        text = sigrok.as_hexdump(bytes.fromhex("80010000000c0000017b00000004"))
        self.assertEqual(frames.parse_hexdump_text(text),
                         bytes.fromhex("80010000000c0000017b00000004"))


class FmpScanTests(unittest.TestCase):
    def _capsule(self, image: bytes) -> bytes:
        header = struct.pack(">I", firmware.FMP_CAPSULE_TYPE)      # type (BE marker)
        header += struct.pack("<I", 1)                             # version
        header += struct.pack("<I", 0x20)                          # header size
        header += struct.pack("<I", 0)                             # flags
        header += b"\x00" * 16                                     # guid
        header += struct.pack("<Q", len(image))                   # image size
        return header + image

    def test_finds_capsule_and_nuvoton_strings(self):
        blob = b"\x00" * 16 + self._capsule(b"junk Nuvoton NPCT75x firmware blob")
        path = Path(self.tmp) / "image.rom"
        path.write_bytes(blob)
        report = firmware.scan_fmp(path)
        self.assertEqual(len(report.capsules), 1)
        cap = report.capsules[0]
        self.assertTrue(cap.contains_nuvoton)
        self.assertIn("Nuvoton", " ".join(cap.nuvoton_strings))

    def test_finds_tpm_fmp_marker(self):
        path = Path(self.tmp) / "marker.rom"
        path.write_bytes(b"\xff\xff" + firmware.FMP_MARKER + b"\x00\x00")
        report = firmware.scan_fmp(path)
        self.assertEqual(report.marker_offsets, [2])

    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = self._tmpdir.name

    def tearDown(self):
        self._tmpdir.cleanup()


class WordlistTests(unittest.TestCase):
    def test_loads_raw_and_hex_lines(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("NPCT\nhex:deadbeef\n\n")
            name = fh.name
        try:
            words = vendor_probe.load_wordlist(name)
        finally:
            Path(name).unlink()
        self.assertIn(b"NPCT", words)
        self.assertIn(bytes.fromhex("deadbeef"), words)
        self.assertIn(b"", words)  # the blank line is an empty password


if __name__ == "__main__":
    unittest.main()
