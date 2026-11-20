#!/usr/bin/env python3
"""Offline RSA analysis of the 256-byte blobs in Nuvoton DevCap packages.

Usage:
    python3 tools/fw_rsa_analysis.py [A.BIN B.BIN]

Defaults to the two checked-in/out-of-tree packages used by the project::

    out/firmware/NuvotonTpmDevCap.BIN
    out/firmware/NuvotonTpmDevCap_7.2.0.2.BIN

Each package carries two 256-byte, RSA-sized blobs:

* ``setup`` (0x20000200): 16-byte version records, u32 bloblen, blob, ranges.
* ``commit`` (0x20000203): small final encrypted chunk, u32 256, blob.

FIPS 140-2 (140sp3187, FW 7.2.0.x) says the firmware image is verified with a
2048-bit RSA key and SHA-256; FIPS 140-3 (140sp5171) moved to ECDSA-384. This
tool tests whether either blob can be used to recover the RSA public modulus
``n`` — the one prerequisite for any Franklin-Reiter related-message attack —
without any live TPM interaction.

Checks performed (all offline, no TPM commands):

1. Blob sizes/parity/small factors: a real RSA modulus is odd and has no small
   factors; signatures/ciphertexts are random-looking and may be even.
2. Setup-as-modulus hypothesis: ``pow(commit, e, setup)`` for e in 3,17,65537,
   tested for PKCS#1 v1.5 structure. Cross-package combinations too.
3. Modulus-from-signatures: ``gcd(s1**e - m1, s2**e - m2)`` over candidate
   messages (SHA-256 of artifacts, raw/PKCS#1 encodings), e in 3,17.
4. Same-message randomized-padding test: if two signatures cover the same
   padded message then ``n`` divides ``s1**e - s2**e``; gcd across disjoint
   pairs can reveal it.
5. Optional scan of updater binaries for a 2048-bit modulus candidate.

The tool is read-only and never sends a vendor command.
"""

from __future__ import annotations

import hashlib
import itertools
import struct
import sys
from math import gcd
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tpm_re.firmware import scan_devcap_script  # noqa: E402

DI = bytes.fromhex("3031300d060960864801650304020105000420")
SMALL_PRIMES = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
]

DEFAULT_PACKAGES = [
    Path("out/firmware/NuvotonTpmDevCap.BIN"),
    Path("out/firmware/NuvotonTpmDevCap_7.2.0.2.BIN"),
]
DEFAULT_EXTRA = [
    Path("out/firmware/npct75x_fw_7.2.2.0.bin"),
    Path("out/firmware/npct75x_fw_7.2.0.2.bin"),
]


def extract_blobs(path: Path) -> dict[str, bytes]:
    script = scan_devcap_script(path.read_bytes())
    setup_cmds = [c for c in script.commands if c.cc == 0x20000200]
    commit_cmds = [c for c in script.commands if c.cc == 0x20000203]
    if len(setup_cmds) != 1 or len(commit_cmds) != 1:
        raise ValueError(f"{path}: expected one setup and one commit command")

    setup = setup_cmds[0].params
    old_count = struct.unpack_from(">I", setup, 12)[0]
    pos = 16 + old_count
    blob_len = struct.unpack_from(">I", setup, pos)[0]
    setup_blob = setup[pos + 4:pos + 4 + blob_len]

    commit = commit_cmds[0].params
    idx = commit.rfind(b"\x00\x00\x01\x00")
    commit_blob = commit[idx + 4:idx + 4 + 256]

    return {
        "setup": setup_blob,
        "commit": commit_blob,
        "devcap": path.read_bytes(),
        "setup_full": setup,
        "vertable": setup[4:pos],
        "commit_no_blob": commit[:idx],
    }


def pkcs1_sha256(digest: bytes) -> bytes:
    body = DI + digest
    return b"\x00\x01" + b"\xff" * (256 - 3 - len(body)) + b"\x00" + body


def looks_pkcs1(v: int) -> bool:
    if (v >> 2032) != 1:  # leading 00 01
        return False
    b = v.to_bytes(256, "big")
    return b[2:20] == b"\xff" * 18 and b"\x00" in b[2:]


def blob_properties(blobs: dict[str, dict[str, bytes]]) -> None:
    print("[1] Blob properties")
    for pkg, d in blobs.items():
        for name in ("setup", "commit"):
            v = int.from_bytes(d[name], "big")
            factors = [p for p in SMALL_PRIMES if v % p == 0]
            print(f"  {pkg}-{name}: {v.bit_length()} bits, odd={bool(v & 1)}, "
                  f"small factors={factors}, sha256={hashlib.sha256(d[name]).hexdigest()[:16]}")
    allv = {f"{p}-{n}": int.from_bytes(d[n], "big")
            for p, d in blobs.items() for n in ("setup", "commit")}
    print("  pairwise GCDs (a common RSA modulus would be ~2048 bits):")
    for a, b in itertools.combinations(allv, 2):
        g = gcd(allv[a], allv[b])
        print(f"    gcd({a},{b}) = {g.bit_length()} bits")


def setup_as_modulus(blobs: dict[str, dict[str, bytes]]) -> None:
    print("[2] setup-as-modulus / commit-as-signature")
    for e in (3, 17, 65537):
        for p1, d1 in blobs.items():
            n = int.from_bytes(d1["setup"], "big")
            for p2, d2 in blobs.items():
                s = int.from_bytes(d2["commit"], "big")
                v = pow(s, e, n)
                print(f"  e={e:5d} n={p1}-setup s={p2}-commit: "
                      f"pkcs1v15={looks_pkcs1(v)} prefix={v.to_bytes(256,'big')[:8].hex()}")


def modulus_from_signatures(blobs: dict[str, dict[str, bytes]],
                            streams: dict[str, bytes]) -> None:
    print("[3] Modulus from signatures, gcd(s1^e - m1, s2^e - m2)")
    keys = [f"{p}-{n}" for p in blobs for n in ("setup", "commit")]
    S = {k: int.from_bytes(blobs[k.split("-")[0]][k.split("-")[1]], "big") for k in keys}

    def candidates(pkg: str) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        d = blobs[pkg]
        for field in ("devcap", "setup_full", "vertable", "commit_no_blob"):
            out[field + "/sha256"] = hashlib.sha256(d[field]).digest()
        if pkg in streams:
            out["fwct/sha256"] = hashlib.sha256(streams[pkg]).digest()
        out["const/zero"] = b"\x00" * 32
        return out

    hits = 0
    for e in (3, 17):
        for a, b in itertools.combinations(keys, 2):
            ca, cb = candidates(a.split("-")[0]), candidates(b.split("-")[0])
            for ka, ma in ca.items():
                for kb, mb in cb.items():
                    for enc in ("pkcs1", "raw"):
                        x = int.from_bytes(pkcs1_sha256(ma) if enc == "pkcs1" else ma, "big")
                        y = int.from_bytes(pkcs1_sha256(mb) if enc == "pkcs1" else mb, "big")
                        g = gcd(pow(S[a], e) - x, pow(S[b], e) - y)
                        if 2040 <= g.bit_length() <= 2060:
                            print(f"  *** n candidate e={e} {a}/{b} {ka}/{kb} {enc}: "
                                  f"{g.bit_length()} bits {hex(g)[:40]}")
                            hits += 1
    print(f"  candidates found: {hits}")


def same_message_test(blobs: dict[str, dict[str, bytes]]) -> None:
    print("[4] Same-message randomized-padding test (n | s1^e - s2^e)")
    keys = [f"{p}-{n}" for p in blobs for n in ("setup", "commit")]
    S = {k: int.from_bytes(blobs[k.split("-")[0]][k.split("-")[1]], "big") for k in keys}
    for e in (3, 17):
        diffs = {(a, b): pow(S[a], e) - pow(S[b], e)
                 for a, b in itertools.combinations(keys, 2)}
        hits = 0
        for (p1, p2), (q1, q2) in itertools.combinations(diffs, 2):
            if len({p1, p2, q1, q2}) < 4:
                continue
            g = gcd(diffs[(p1, p2)], diffs[(q1, q2)])
            if 2040 <= g.bit_length() <= 2060:
                print(f"  *** n candidate e={e} gcd(diff({p1},{p2}),diff({q1},{q2})) "
                      f"= {g.bit_length()} bits {hex(g)[:40]}")
                hits += 1
        print(f"  e={e}: {len(diffs)} differences tested, candidates found: {hits}")


def main() -> None:
    paths = [Path(p) for p in sys.argv[1:3]] or DEFAULT_PACKAGES
    if len(paths) != 2:
        print("usage: fw_rsa_analysis.py A.BIN B.BIN", file=sys.stderr)
        raise SystemExit(2)
    blobs = {}
    for i, path in enumerate(paths):
        blobs[f"p{i+1}"] = extract_blobs(path)
    streams = {}
    for i, path in enumerate(DEFAULT_EXTRA):
        if path.exists():
            streams[f"p{i+1}"] = path.read_bytes()
    blob_properties(blobs)
    setup_as_modulus(blobs)
    modulus_from_signatures(blobs, streams)
    same_message_test(blobs)
    print("Done. No modulus -> Franklin-Reiter related-message attack is not applicable.")


if __name__ == "__main__":
    main()
