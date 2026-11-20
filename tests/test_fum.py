"""Offline tests for the safe FUM setup probe helpers (no TPM required)."""

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from tpm_re.fum import (  # noqa: E402
    FUM_SETUP_CC,
    HEALTH_BASELINE,
    HEALTH_CC,
    PASSWORD_SESSION,
    PLATFORM_HANDLE,
    candidate_auths,
    password_session,
    setup_command,
)
from tpm_re.nvauth import NV_AUTH_VALUE  # noqa: E402
from tpm_re.wire import ST_SESSIONS  # noqa: E402


class TestPasswordSession(unittest.TestCase):
    def test_tpm2b_uses_u16_length_prefix(self):
        """Regression: the old one-off scripts used u32 and got 0xA84."""
        area = password_session(bytes(32))
        # authorizationSize (u32), sessionHandle (u32), nonce TPM2B (u16=0),
        # attributes (u8), hmac TPM2B (u16=32), then 32 bytes.
        size = struct.unpack_from(">I", area, 0)[0]
        self.assertEqual(size, 4 + 2 + 1 + 2 + 32)
        self.assertEqual(len(area), 4 + size)
        self.assertEqual(struct.unpack_from(">I", area, 4)[0], PASSWORD_SESSION)
        self.assertEqual(struct.unpack_from(">H", area, 8)[0], 0)  # nonce len
        self.assertEqual(area[10], 0x01)  # attributes
        self.assertEqual(struct.unpack_from(">H", area, 11)[0], 32)  # hmac len

    def test_empty_auth(self):
        area = password_session(b"")
        size = struct.unpack_from(">I", area, 0)[0]
        self.assertEqual(size, 4 + 2 + 1 + 2)
        self.assertEqual(struct.unpack_from(">H", area, 11)[0], 0)


class TestSetupCommand(unittest.TestCase):
    def test_layout(self):
        params = bytes(range(16))
        raw = setup_command(params, NV_AUTH_VALUE)
        self.assertEqual(struct.unpack_from(">H", raw, 0)[0], ST_SESSIONS)
        self.assertEqual(struct.unpack_from(">I", raw, 2)[0], len(raw))
        self.assertEqual(struct.unpack_from(">I", raw, 6)[0], FUM_SETUP_CC)
        self.assertEqual(struct.unpack_from(">I", raw, 10)[0], PLATFORM_HANDLE)
        self.assertTrue(raw.endswith(params))

    def test_never_builds_other_command_codes(self):
        # setup_command has no cc parameter by design; only 0x20000200 exists.
        params = bytes(4)
        self.assertEqual(struct.unpack_from(">I", setup_command(params), 6)[0],
                         FUM_SETUP_CC)


class TestCandidates(unittest.TestCase):
    def test_defaults_include_known_values(self):
        cands = candidate_auths()
        self.assertEqual(cands["nvauth_32"], NV_AUTH_VALUE)
        self.assertEqual(cands["zeros32"], bytes(32))
        self.assertIn("hmac_nvauth_key_zero16", cands)
        self.assertTrue(all(0 <= len(v) <= 64 for v in cands.values()))

    def test_health_baseline(self):
        self.assertEqual(len(HEALTH_BASELINE), 18)
        self.assertEqual(HEALTH_CC, 0x20000213)


if __name__ == "__main__":
    unittest.main()
