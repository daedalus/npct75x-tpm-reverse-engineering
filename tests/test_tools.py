import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest


def _load_tool(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parents[1] / "tools" / filename
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sigrok = _load_tool("sigrok_to_frames", "sigrok_to_frames.py")


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


if __name__ == "__main__":
    unittest.main()
