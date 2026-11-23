"""Offline policy digest tests validated against live TPM observations."""

from tpm_re.policy import (
    name_from_public,
    policy_command_code,
    policy_secret,
)

NV_PUBLIC = bytes.fromhex("01802006000b6205000500000010")
NV_NAME = bytes.fromhex(
    "000b37fc61fbff2a5b188db2edb3187fedee69e84fd336aeb0d55ec94c52cc8e2f71"
)
ZERO = bytes(32)


def test_name_from_public():
    assert name_from_public(NV_PUBLIC) == NV_NAME


def test_policy_secret_empty_ref_matches_tpm():
    # tpm2_getpolicydigest after PolicySecret(NV), 2026-11-23
    assert policy_secret(ZERO, NV_NAME).hex() == (
        "8ba293e24e36d61e96820d954a58f066afe480b3170ca81a3937ba93bc29fb63"
    )


def test_policy_secret_with_qualification_matches_tpm():
    # tpm2_policysecret -q aabbccdd on a trial session
    assert policy_secret(ZERO, NV_NAME, bytes.fromhex("aabbccdd")).hex() == (
        "bed3db11f6d93f2ec2e4fbc34f059088ff9ae0a090022686dc0ccc390164d85f"
    )


def test_policy_command_code_only_matches_tpm():
    # tpm2_getpolicydigest after PolicyCommandCode(0x129) from a fresh session
    assert policy_command_code(ZERO, 0x129).hex() == (
        "be698d8bd14927cd7ed7bdd93be41f27ff2626bd2d8a1540e2f9445f2ee5ab2e"
    )


def test_policy_command_code_after_policy_secret_matches_tpm():
    # full chain observed live: PolicySecret(NV) -> PolicyCommandCode(0x129)
    secret = policy_secret(ZERO, NV_NAME)
    assert policy_command_code(secret, 0x129).hex() == (
        "a97509ad745372145620b2d4fe0bad0510db4e375e5c68d7490a30f4af84679b"
    )
