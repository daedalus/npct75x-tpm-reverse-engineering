"""Statically derived auth value for NV index ``0x01802006``.

The AMI TPM FMP DXE driver (``section1.pe``) creates this index on this
platform.  ``TpmFmpUefiDrv_nv_init`` copies 26 bytes from its ``NovemberRain``
variable, hashes them with SHA-256 and passes the 32-byte digest as the
``authValue`` to ``NV_DefineSpace``.  ``TpmFmpUefiDrv_version_payload`` then
uses an HMAC-SHA256 session keyed by the same digest to read the index.

The value is proven statically; live validation is deferred because the TPM
is wedged.  See ``knowledge/NPCT75x.md`` sections 6 and 8.
"""

from __future__ import annotations

import hashlib

NV_AUTH_INDEX = 0x01802006
NV_AUTH_SEED = "NovemberRain"
NV_AUTH_VALUE = bytes.fromhex(
    "4a2a5d8442d17e746f46ed1d990ee2213250e04005bbded804565ecfdab0afdf"
)


def auth_seed(passphrase: str = NV_AUTH_SEED) -> bytes:
    """Return the UTF-16LE passphrase plus the terminating NUL pair."""
    return passphrase.encode("utf-16-le") + b"\x00\x00"


def derive_nv_auth(passphrase: str = NV_AUTH_SEED) -> bytes:
    """Derive the 32-byte NV ``0x01802006`` auth value from a passphrase."""
    return hashlib.sha256(auth_seed(passphrase)).digest()
