"""Offline reconstruction of TPM 2.0 policy digests.

Implements the TCG reference implementation's ``PolicyContextUpdate``
(two-stage hash, no TPM2B length prefixes) for the two assertions used by
the NPCT75x FMP driver's ``GetRtTpmFwUpdPolicyHndl`` chain: ``PolicySecret``
and ``PolicyCommandCode``. All digests validated against this TPM via
``tpm2_getpolicydigest`` on 2026-11-23; see ``knowledge/NPCT75x.md`` §9.14.

Reference: TCG TPM 2.0 Part 4 supporting routines, ``Policy_spt.c``::

    first = H(policyDigest || TPM_CC_PolicySecret || Name(authHandle))
    digest = H(first || policyRef)

Note the spec text writes ``H(policyDigest || CC || Name || policyRef)``;
the reference implementation splits it into two hash operations, and
``CryptUpdateDigest2B`` hashes only the buffer bytes (not the u16 size).
"""

from __future__ import annotations

import hashlib

TPM_CC_POLICY_SECRET = 0x151
TPM_CC_POLICY_COMMAND_CODE = 0x16C


def name_from_public(public: bytes, name_alg: bytes = b"\x00\x0b") -> bytes:
    """Compute a TPM2B Name from a marshalled public area and nameAlg u16."""
    return name_alg + hashlib.sha256(public).digest()


def policy_secret(
    policy_digest: bytes,
    name: bytes,
    policy_ref: bytes = b"",
    auth_hash: str = "sha256",
) -> bytes:
    """Extend ``policy_digest`` with a PolicySecret assertion.

    ``name`` is the TPM2B Name of the authorizing entity (e.g. ``000b ||
    SHA256(nvPublic)``). ``policy_ref`` is the caller-supplied qualification.
    """
    first = hashlib.new(
        auth_hash,
        policy_digest + TPM_CC_POLICY_SECRET.to_bytes(4, "big") + name,
    ).digest()
    return hashlib.new(auth_hash, first + policy_ref).digest()


def policy_command_code(
    policy_digest: bytes, command_code: int, auth_hash: str = "sha256"
) -> bytes:
    """Extend ``policy_digest`` with a PolicyCommandCode assertion."""
    return hashlib.new(
        auth_hash,
        policy_digest
        + TPM_CC_POLICY_COMMAND_CODE.to_bytes(4, "big")
        + command_code.to_bytes(4, "big"),
    ).digest()
