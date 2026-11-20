#!/usr/bin/env python3
"""Cross-version analysis of two Nuvoton DevCap firmware streams.

Usage:
    python3 tools/fw_cross_version.py A.BIN B.BIN [OUTDIR]

Given two encrypted field-upgrade packages, check the properties that would
make an offline known-plaintext attack possible:

* identical per-chunk nonces (AES-CTR IV reuse across versions),
* identical ciphertext blocks (ECB reuse across versions),
* setup-command key material usable as an AES key (CCM/GCM tag verification).

The tool is entirely offline.  It never talks to a TPM and never sends a
vendor command.  ``pycryptodome`` is optional; without it the tag checks are
skipped and only the structural/entropy checks run.
"""

from __future__ import annotations

import collections
import hashlib
import math
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tpm_re.firmware import scan_devcap_script  # noqa: E402

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - optional
    AES = None


def entropy(data: bytes) -> float:
    counts = collections.Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def setup_fields(params: bytes) -> dict:
    """Decode the 0x20000200 parameter layout shared by both packages."""
    old_count = struct.unpack_from(">I", params, 12)[0]
    pos = 16 + old_count
    blob_len = struct.unpack_from(">I", params, pos)[0]
    pos += 4
    return {
        "new_version": params[8:12].hex(),
        "old_versions": [params[16 + 6 * i:22 + 6 * i].hex()
                         for i in range(old_count // 6)],
        "blob_len": blob_len,
        "blob": params[pos:pos + blob_len],
        "ranges": params[pos + blob_len:],
    }


def stream_parts(script) -> tuple[list[bytes], list[bytes], list[bytes]]:
    """Return (nonce, ciphertext, tag) per write command.

    ``DevCapScript.firmware`` concatenates ``params[16:]``: a 16-byte random
    nonce, a big-endian u32 length, ciphertext, then a 10-byte tag.
    """
    nonces, blocks, tags = [], [], []
    for cmd in script.commands:
        if cmd.cc != 0x20000202:
            continue
        payload = cmd.params[16:]
        length = struct.unpack_from(">I", payload, 16)[0]
        nonces.append(payload[:16])
        blocks.append(payload[20:20 + length - 10])
        tags.append(payload[20 + length - 10:20 + length])
    return nonces, blocks, tags


def tag_sweep(key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bool:
    if AES is None:
        return False
    for nlen in range(7, 14):
        for aad in (b"", nonce[:4]):
            try:
                cipher = AES.new(key, AES.MODE_CCM, nonce=nonce[:nlen],
                                 mac_len=10, aad=aad)
                plaintext = cipher.decrypt(ct)
                if cipher.verify(tag):
                    return True
            except Exception:
                pass
    for nlen in (12, 16):
        for aad in (b"", nonce[:4]):
            try:
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce[:nlen],
                                 mac_len=10, aad=aad)
                plaintext = cipher.decrypt(ct)
                if cipher.verify(tag):
                    return True
            except Exception:
                pass
    return False


def report(path_a: Path, path_b: Path, out_dir: Path) -> str:
    a = scan_devcap_script(path_a.read_bytes())
    b = scan_devcap_script(path_b.read_bytes())
    if a is None or b is None:
        raise SystemExit("one or both inputs are not valid DevCap containers")

    sa, sb = setup_fields(a.commands[0].params), setup_fields(b.commands[0].params)
    na, ca, ta = stream_parts(a)
    nb, cb, tb = stream_parts(b)
    fa, fb = a.firmware, b.firmware

    block_b = collections.defaultdict(list)
    for i in range(0, len(fb) - 15, 16):
        block_b[fb[i:i + 16]].append(i)
    cross_blocks = sum(1 for i in range(0, len(fa) - 15, 16)
                       if fa[i:i + 16] in block_b)

    hits = []
    for label, script, nonce, ct, tag in (("A", a, na[0], ca[0], ta[0]),
                                          ("B", b, nb[0], cb[0], tb[0])):
        blob = sa["blob"] if label == "A" else sb["blob"]
        for off in range(max(0, len(blob) - 15)):
            if tag_sweep(blob[off:off + 16], nonce, ct, tag):
                hits.append(f"{label} setup blob +0x{off:x} verifies tag")

    lines = [
        "=" * 72,
        f"A: {path_a}  script=0x{a.script_offset:x}  cmds={len(a.commands)}",
        f"   new={sa['new_version']} old={sa['old_versions']} "
        f"blob={sa['blob_len']} ranges={sa['ranges'].hex()}",
        f"B: {path_b}  script=0x{b.script_offset:x}  cmds={len(b.commands)}",
        f"   new={sb['new_version']} old={sb['old_versions']} "
        f"blob={sb['blob_len']} ranges={sb['ranges'].hex()}",
        f"write chunks: A={len(na)} B={len(nb)}",
        f"nonce overlap: {len(set(na) & set(nb))}",
        f"same-index nonce reuse: "
        f"{sum(x == y for x, y in zip(na, nb))}/{min(len(na), len(nb))}",
        f"cross-image identical 16B ciphertext blocks: {cross_blocks}",
        f"ciphertext block overlap: {len(set(ca) & set(cb))}",
        f"A entropy={entropy(fa):.6f} unique16B="
        f"{len(set(fa[i:i+16] for i in range(0, len(fa)-15, 16)))}",
        f"B entropy={entropy(fb):.6f} unique16B="
        f"{len(set(fb[i:i+16] for i in range(0, len(fb)-15, 16)))}",
        f"setup-blob AES key tag hits: {len(hits)}",
    ] + hits

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "cross_version.txt").write_text("\n".join(lines) + "\n")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    out = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/firmware/analysis")
    print(report(Path(sys.argv[1]), Path(sys.argv[2]), out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
