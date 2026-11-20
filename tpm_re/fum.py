"""Safe, testable helpers for probing FUM setup authorisation.

The only command this module ever builds is the vendor setup command
``0x20000200`` with the PLATFORM handle ``0x4000000C``.  It never emits
``0x2000012f`` / ``0x20000211``, erase, write, commit, or a full DevCap
replay.  Wrong PLATFORM passwords return ``BAD_AUTH`` and do not increment
DA lockout, so repeated setup probes are non-destructive.

Wire-format note
----------------
``TPM2B`` uses a **u16** length prefix.  The original one-off scripts in
``opencode/fum_*.py`` defined ``tpm2b()`` with a u32 prefix; the two extra
bytes per field made the TPM misparse the auth area and return a misleading
``0xA84 VALUE (session 2)``.  This module uses :func:`tpm_re.wire.tpm2b` so
the verdict is the ordinary ``0x9A2 BAD_AUTH (session 1)`` for a wrong auth.
"""

from __future__ import annotations

import hashlib
import hmac

from .wire import build, tpm2b, u32, u8

FUM_SETUP_CC = 0x20000200
PLATFORM_HANDLE = 0x4000000C
PASSWORD_SESSION = 0x40000009  # TPM_RS_PW

# Baseline returned by 0x20000213 on this machine; used to verify the TPM is
# still healthy after a batch of setup probes.
HEALTH_CC = 0x20000213
HEALTH_BASELINE = bytes.fromhex("ffffa700fbff7ffffbfffffffbf0ffffaaaa")


def password_session(auth: bytes = b"", *, handle: int = PASSWORD_SESSION,
                     attributes: int = 0x01) -> bytes:
    """Return an authArea with one password session carrying ``auth``.

    The leading UINT32 is ``authorizationSize`` (byte length of the following
    TPMS_AUTH_COMMAND structures), not a session count.  Nonce and hmac are
    TPM2B and therefore use u16 length prefixes.
    """
    structure = u32(handle) + tpm2b(b"") + u8(attributes) + tpm2b(auth)
    return u32(len(structure)) + structure


def setup_command(params: bytes, auth: bytes = b"", *,
                  handle: int = PLATFORM_HANDLE) -> bytes:
    """Build the wire command for CC ``0x20000200`` (FUM setup).

    ``params`` is the 302-byte parameter block from the DevCap file.  Anything
    else (erase/write/commit) is deliberately not constructible here.
    """
    return build(FUM_SETUP_CC, params, handles=u32(handle),
                 auth_area=password_session(auth))


def candidate_auths(nv_digest: bytes | None = None) -> dict[str, bytes]:
    """Return known and previously untried PLATFORM auth candidates.

    ``nv_digest`` defaults to the statically derived NV ``0x01802006`` auth
    (``SHA256(UTF-16LE("NovemberRain\\0"))``).  All entries have been rejected
    live; the set is kept so a future probe can be compared against a known
    baseline rather than re-derived ad hoc.
    """
    if nv_digest is None:
        from .nvauth import NV_AUTH_VALUE
        nv_digest = NV_AUTH_VALUE
    nov_utf16 = "NovemberRain".encode("utf-16le") + b"\x00\x00"
    nov_ascii = b"NovemberRain"
    z16 = bytes(16)

    cands: dict[str, bytes] = {}
    def add(name: str, value: bytes) -> None:
        if 0 <= len(value) <= 64:
            cands.setdefault(name, value)

    # Primary candidates (previously tried, re-tested with correct framing).
    add("nvauth_32", nv_digest)
    add("ascii_novemberrain", nov_ascii)
    add("utf16_novemberrain_nul", nov_utf16)
    add("zeros32", bytes(32))

    # Zero-nonce derivations: TpmFwUpdRollNonce is absent from NVRAM, so a
    # default/zero nonce was plausible.  All rejected live.
    add("nv_data_zeros16", z16)
    add("hmac_nvauth_key_zero16", hmac.new(nv_digest, z16, hashlib.sha256).digest())
    add("hmac_novutf16_key_zero16", hmac.new(nov_utf16, z16, hashlib.sha256).digest())
    add("hmac_novascii_key_zero16", hmac.new(nov_ascii, z16, hashlib.sha256).digest())
    add("sha256_novutf16_plus_zero16", hashlib.sha256(nov_utf16 + z16).digest())
    add("sha256_novascii_plus_zero16", hashlib.sha256(nov_ascii + z16).digest())
    add("sha256_nvauth_plus_zero16", hashlib.sha256(nv_digest + z16).digest())
    add("nvauth_first16", nv_digest[:16])
    add("nvauth_last16", nv_digest[16:])
    return cands
