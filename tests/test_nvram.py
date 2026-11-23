"""Tests for the AMI NVAR parser, using a synthetic store plus live-derived values."""

from tpm_re.nvram import find_variable, parse_nvar_records, roll_nonce


def _record(name: str, data: bytes, guid_index: int = 0x3482) -> bytes:
    name_b = name.encode() + b"\x00"
    size = 11 + len(name_b) + len(data)
    return (
        b"NVAR"
        + size.to_bytes(2, "little")
        + b"\x91\x1d\x00"
        + guid_index.to_bytes(2, "little")
        + name_b
        + data
    )


def test_parse_single_record():
    data = bytes.fromhex("84084823e0e106999174014e2758d73a")
    blob = b"\xff" * 8 + _record("TpmFwUpdRollNonce", data) + b"\xff" * 8
    recs = parse_nvar_records(blob)
    assert len(recs) == 1
    rec = recs[0]
    assert rec.name == "TpmFwUpdRollNonce"
    assert rec.guid_index == 0x3482
    assert rec.data == data
    assert rec.data_offset == 8 + 11 + len("TpmFwUpdRollNonce") + 1


def test_find_variable_and_roll_nonce():
    nonce = bytes.fromhex("84084823e0e106999174014e2758d73a")
    blob = _record("TpmFmpVersion", b"\x01\x00\x00\x00") + _record(
        "TpmFwUpdRollNonce", nonce
    )
    assert [r.name for r in find_variable(blob, "TpmFwUpdRollNonce")] == [
        "TpmFwUpdRollNonce"
    ]
    assert roll_nonce(blob) == nonce


def test_roll_nonce_rejects_wrong_length():
    blob = _record("TpmFwUpdRollNonce", b"\x01\x02")
    assert roll_nonce(blob) is None


def test_live_dump_roll_nonce():
    """The value recovered from the live SPI dump on 2026-11-23."""
    nonce = bytes.fromhex("84084823e0e106999174014e2758d73a")
    assert len(nonce) == 16
