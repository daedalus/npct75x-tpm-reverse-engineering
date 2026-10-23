import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from tpm_re import wire


class BuildTests(unittest.TestCase):
    def test_header_layout(self):
        command = wire.build(0x0000017A, wire.u32(0x06) + wire.u32(0x100) + wire.u32(0x10))
        self.assertEqual(command[:2], b"\x80\x01")
        self.assertEqual(struct.unpack(">I", command[2:6])[0], len(command))
        self.assertEqual(struct.unpack(">I", command[6:10])[0], 0x17A)

    def test_sessions_tag_and_size(self):
        handles = wire.u32(0x01C00002) + wire.u32(0x01C00002)
        params = wire.u16(4) + wire.u16(0)
        auth = wire.password_auth()
        command = wire.build(0x0000014E, params, handles=handles, auth_area=auth)
        self.assertEqual(command[:2], b"\x80\x02")
        self.assertEqual(struct.unpack(">I", command[2:6])[0], len(command))
        # handles, then authorization area, then parameters
        self.assertEqual(command[10:], handles + auth + params)

    def test_sessions_requires_handles(self):
        with self.assertRaises(wire.WireError):
            wire.build(0x0000014E, wire.u16(4) + wire.u16(0),
                       auth_area=wire.password_auth())

    def test_password_auth_shape(self):
        auth = wire.password_auth()
        self.assertEqual(struct.unpack(">I", auth[:4])[0], len(auth) - 4)  # authorizationSize
        self.assertEqual(struct.unpack(">I", auth[4:8])[0], wire.TPM_RS_PW)
        self.assertEqual(auth[8:10], b"\x00\x00")                      # empty nonce
        self.assertEqual(auth[10], 0x01)                               # continueSession
        self.assertEqual(auth[11:13], b"\x00\x00")                     # empty hmac
        self.assertEqual(len(auth), 13)


class ResponseTests(unittest.TestCase):
    def test_no_sessions(self):
        raw = bytes.fromhex("80010000000c00000000abcd")
        response = wire.parse_response(raw)
        self.assertTrue(response.ok)
        self.assertEqual(response.params, bytes.fromhex("abcd"))

    def test_sessions_uses_parameter_size(self):
        # tag, size=20, rc, paramSize=2, params, authArea(empty)
        raw = bytes.fromhex("8002000000140000000000000002beef00000000")
        response = wire.parse_response(raw)
        self.assertEqual(response.params, b"\xbe\xef")
        self.assertEqual(response.auth_area, b"\x00\x00\x00\x00")

    def test_size_mismatch_is_rejected(self):
        with self.assertRaises(wire.WireError):
            wire.parse_response(bytes.fromhex("8001000000ff00000000"))

    def test_error_response_has_no_params(self):
        raw = bytes.fromhex("80010000000a00000184")
        response = wire.parse_response(raw)
        self.assertFalse(response.ok)
        self.assertEqual(response.rc, 0x184)


class ReaderTests(unittest.TestCase):
    def test_bounds(self):
        reader = wire.Reader(b"\x01\x02")
        self.assertEqual(reader.u16(), 0x0102)
        with self.assertRaises(wire.WireError):
            reader.take(1)

    def test_tpm2b(self):
        reader = wire.Reader(b"\x00\x03abcZ")
        self.assertEqual(reader.tpm2b(), b"abc")
        self.assertEqual(reader.rest(), b"Z")


class RcTests(unittest.TestCase):
    def test_format_zero(self):
        self.assertEqual(wire.decode_rc(0), "SUCCESS")
        self.assertEqual(wire.decode_rc(0x10A), "PCR")
        self.assertEqual(wire.decode_rc(0x921), "LOCKOUT")

    def test_format_one_session(self):
        self.assertIn("AUTH_FAIL", wire.decode_rc(0x98E))
        self.assertIn("session 1", wire.decode_rc(0x98E))

    def test_format_one_value(self):
        decoded = wire.decode_rc(0x184)
        self.assertIn("VALUE", decoded)
        self.assertIn("parameter/handle 1", decoded)

    def test_unmapped_is_explicit(self):
        self.assertTrue(wire.decode_rc(0x7FF).startswith("UNMAPPED"))


class PresentationTests(unittest.TestCase):
    def test_hexdump_rows(self):
        text = wire.hexdump(bytes(range(20)))
        self.assertIn("00000000", text)
        self.assertIn("00000010", text)
        self.assertIn("|", text)

    def test_parse_hex(self):
        self.assertEqual(wire.parse_hex("80 01 00"), b"\x80\x01\x00")
        self.assertEqual(wire.parse_hex("0x8001"), b"\x80\x01")

    def test_four_cc(self):
        self.assertEqual(wire.u32be_to_str(0x4E544300), "NTC\x00")


if __name__ == "__main__":
    unittest.main()
