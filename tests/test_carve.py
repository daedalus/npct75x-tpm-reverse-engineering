import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from tpm_re import carve


class EntropyTests(unittest.TestCase):
    def test_uniform_bytes(self):
        self.assertEqual(carve.shannon_entropy(b""), 0.0)
        self.assertEqual(carve.shannon_entropy(b"\x00" * 100), 0.0)
        self.assertAlmostEqual(carve.shannon_entropy(bytes(range(256))), 8.0, places=3)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.blob = (
            b"\x00" * 512
            + b"MZ" + b"\x90" * 64
            + b"NPCT75x" + b"\x00" * 256
            + b"Nuvoton" + b"\x00" * 128
            + bytes(range(256)) * 4
        )

    def test_markers_found(self):
        report = carve.scan_bytes(self.blob, "synthetic")
        markers = {(c["marker"], c["offset"]) for c in report["candidates"]}
        self.assertIn(("NPCT", self.blob.find(b"NPCT")), markers)
        self.assertIn(("Nuvoton", self.blob.find(b"Nuvoton")), markers)
        self.assertEqual(report["size"], len(self.blob))
        self.assertEqual(len(report["sha256"]), 64)

    def test_container_detected(self):
        report = carve.scan_bytes(self.blob)
        kinds = [c["kind"] for c in report["containers"]]
        self.assertTrue(any("PE" in kind for kind in kinds))

    def test_strings_are_extracted(self):
        report = carve.scan_bytes(self.blob)
        candidate = next(c for c in report["candidates"] if c["marker"] == "NPCT")
        self.assertTrue(any("NPCT75x" in s for s in candidate["strings"]))

    def test_extraction_writes_window(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "bios.bin"
            source.write_bytes(self.blob)
            reports = carve.scan_path(source, extract_dir=Path(tmp) / "out")
            self.assertEqual(len(reports), 1)
            written = list((Path(tmp) / "out").glob("*.bin"))
            self.assertTrue(written)
            self.assertTrue(any(path.read_bytes() for path in written))

    def test_noisy_signature_does_not_hide_others(self):
        data = b"MZ" * 200 + b"_FVH"
        kinds = {hit["kind"] for hit in carve.find_container(data)}
        self.assertIn("UEFI firmware volume", kinds)

    def test_fmp_capsule_guid(self):
        guid = bytes.fromhex("edd5cb6d2de8444cbda17194199ad92a")
        kinds = {hit["kind"] for hit in carve.find_container(b"\x00" * 16 + guid)}
        self.assertIn("UEFI FMP capsule", kinds)

    def test_window_hash_matches_extracted_file(self):
        import hashlib
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "bios.bin"
            source.write_bytes(self.blob)
            report = carve.scan_path(source, extract_dir=Path(tmp) / "out")[0]
            hashes = {hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in (Path(tmp) / "out").glob("*.bin")}
            for candidate in report["candidates"]:
                self.assertIn(candidate["sha256_window"], hashes)

    def test_no_markers(self):
        report = carve.scan_bytes(b"\x00" * 4096)
        self.assertEqual(report["candidates"], [])


if __name__ == "__main__":
    unittest.main()
