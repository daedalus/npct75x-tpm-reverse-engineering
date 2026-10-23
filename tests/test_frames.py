import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from tpm_re import frames, wire


def command(cc: int, body: bytes = b"") -> bytes:
    return wire.build(cc, body)


def response(rc: int = 0, body: bytes = b"") -> bytes:
    size = 10 + len(body)
    return b"\x80\x01" + size.to_bytes(4, "big") + rc.to_bytes(4, "big") + body


class SplitTests(unittest.TestCase):
    def test_command_and_response(self):
        stream = command(0x17A, b"\x00\x00\x00\x06") + response(0, b"\x00\x00")
        parsed, problems = frames.split_frames(stream)
        self.assertEqual(problems, [])
        self.assertEqual([f.role for f in parsed], ["command", "response"])
        self.assertEqual(parsed[0].code, 0x17A)
        self.assertIn("GetCapability", parsed[0].to_dict()["cc_name"])
        self.assertEqual(parsed[1].code, 0)
        self.assertEqual(parsed[1].to_dict()["rc_name"], "SUCCESS")

    def test_vendor_command_is_classified_as_command(self):
        parsed, _ = frames.split_frames(command(0x20000001, b"\x00"))
        self.assertEqual(parsed[0].role, "command")
        self.assertEqual(parsed[0].to_dict()["cc_name"], "VENDOR_0x20000001")

    def test_garbage_resynchronises(self):
        stream = b"\xde\xad" + command(0x17B, b"\x00\x00\x00\x04") + response()
        parsed, problems = frames.split_frames(stream)
        self.assertEqual(len(parsed), 2)
        self.assertTrue(any("implausible tag" in p for p in problems))

    def test_truncated_tail_is_reported(self):
        parsed, problems = frames.split_frames(command(0x17B) + b"\x00\x01")
        self.assertEqual(len(parsed), 1)
        self.assertTrue(any("trailing" in p for p in problems))

    def test_error_response_overlapping_a_command_code(self):
        # 0x14C is both GetTime and TPM_RC_NV_DEFINED
        stream = command(0x12A, b"\x00" * 4) + response(0x14C)
        parsed, _ = frames.split_frames(stream)
        self.assertEqual([f.role for f in parsed], ["command", "response"])
        self.assertEqual(parsed[1].to_dict()["rc_name"], "NV_DEFINED")

    def test_forced_role(self):
        parsed, _ = frames.split_frames(response(), role="command")
        self.assertEqual(parsed[0].role, "command")


class HexInputTests(unittest.TestCase):
    def test_hexdump_c_format(self):
        text = (
            "00000000  80 01 00 00 00 0c 00 00  01 7b 00 00 00 04  |.........{....|\n"
            "00000010\n"
        )
        self.assertEqual(frames.parse_hexdump_text(text).hex(), "80010000000c0000017b00000004")

    def test_bare_hex_lines(self):
        self.assertEqual(frames.parse_hexdump_text("8001 0000").hex(), "80010000")

    def test_xxd_ascii_column_that_looks_like_hex(self):
        text = "00000000: 8001 0000 000a  dead\n"
        self.assertEqual(frames.parse_hexdump_text(text).hex(), "80010000000a")

    def test_odd_prefixed_line_does_not_raise(self):
        self.assertEqual(frames.parse_hexdump_text("0x801").hex(), "0801")

    def test_xxd_with_ascii_column(self):
        text = "00000000: 8001 0000 000a 0000 0180  ........\n"
        self.assertEqual(frames.parse_hexdump_text(text).hex(), "80010000000a00000180")


class StraceInputTests(unittest.TestCase):
    TRACE = (
        '4242  write(3, "\\x80\\x01\\x00\\x00\\x00\\x0c\\x00\\x00\\x01\\x7b'
        '\\x00\\x00\\x00\\x04", 12) = 12\n'
        '4242  read(3, "\\x80\\x01\\x00\\x00\\x00\\x0a\\x00\\x00\\x00\\x00", 4096) = 10\n'
        '4243  write(4, "\\xde\\xad", 2) = 2\n'
    )

    def test_bytes_are_collected_in_order(self):
        data, problems = frames.parse_strace(self.TRACE)
        self.assertEqual(problems, [])
        parsed, _ = frames.split_frames(data)
        self.assertEqual([f.role for f in parsed], ["command", "response"])
        self.assertEqual(parsed[0].code, 0x17B)

    def test_fd_filter(self):
        data, _ = frames.parse_strace(self.TRACE, fd=4)
        self.assertEqual(data, b"\xde\xad")

    def test_failed_read_contributes_nothing(self):
        trace = '1  read(3, "\\x80\\x01", 10) = -1 EIO (Input/output error)\n'
        data, _ = frames.parse_strace(trace)
        self.assertEqual(data, b"")

    def test_direction_sets_role(self):
        trace = (
            '1  write(3, "\\x80\\x01\\x00\\x00\\x00\\x0e\\x00\\x00\\x01\\x2a'
            '\\x00\\x00\\x00\\x00", 14) = 14\n'
            '1  read(3, "\\x80\\x01\\x00\\x00\\x00\\x0a\\x00\\x00\\x01\\x4c", 4096) = 10\n'
        )
        segments, _ = frames.parse_strace_segments(trace)
        self.assertEqual([d for d, _ in segments], ["write", "read"])
        parsed, problems, total = frames.split_strace_frames(segments)
        self.assertEqual(problems, [])
        self.assertEqual(total, 24)
        self.assertEqual([f.role for f in parsed], ["command", "response"])
        self.assertEqual(parsed[1].offset, 14)

    def test_pid_prefix_and_resumed_read(self):
        trace = (
            '[pid  77] write(3, "\\x80\\x01\\x00\\x00\\x00\\x0a\\x00\\x00\\x01\\x7c", 10) = 10\n'
            '[pid  77] read(3,  <unfinished ...>\n'
            '[pid  78] write(5, "\\x00", 1) = 1\n'
            '[pid  77] <... read resumed>"\\x80\\x01\\x00\\x00\\x00\\x0a\\x00\\x00\\x00\\x00", 4096) = 10\n'
        )
        segments, problems = frames.parse_strace_segments(trace, fd=3)
        self.assertEqual(problems, [])
        self.assertEqual([d for d, _ in segments], ["write", "read"])
        self.assertEqual(segments[1][1][-4:], b"\x00\x00\x00\x00")

    def test_truncated_string_is_reported(self):
        trace = '1  write(3, "\\x80\\x01\\x00\\x00\\x00\\x0c\\x00...", 12) = 12\n'
        data, problems = frames.parse_strace(trace)
        self.assertEqual(data[:4], b"\x80\x01\x00\x00")
        self.assertTrue(any("truncated" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
