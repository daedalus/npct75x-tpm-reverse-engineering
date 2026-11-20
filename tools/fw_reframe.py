#!/usr/bin/env python3
"""Extract the NPCT75x DevCap firmware ciphertext stream with chunk metadata.

NOTE: this does not change the crypto results.  ``fw_deep_analysis._load()``
and ``fw_crypto_harness`` already strip the framing correctly via
``cmd.params[36:-10]``; ``DevCapScript.firmware`` includes the framing
(IV + length + tag) and is a different representation, not an error.
This tool makes the layout explicit and emits per-chunk JSON for auditing.

The real layout, verified over all 252 + 261 write commands, is:

    offset  size  field
    0       16    fixed header  00 00 00 1c | 00 00 00 10 | 00 00 00 10 | 00 00 00 10
    16      16    per-chunk IV (unique in every chunk, both packages)
    32      4     big-endian length = len(ciphertext) + 10
    36      N     ciphertext (length field minus 10)
    36+N    10    tag

Usage:
    python3 tools/fw_reframe.py [--out OUTDIR]

Writes out/firmware/reframed/<name>.bin (concatenated ciphertext),
<name>.json (chunk metadata) and a comparison against the legacy stream.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tpm_re.firmware import scan_devcap_script  # noqa: E402

FIXED_HDR = bytes.fromhex("0000001c000000100000001000000010")
DEVCAPS = [
    ROOT / "out" / "firmware" / "NuvotonTpmDevCap.BIN",
    ROOT / "out" / "firmware" / "NuvotonTpmDevCap_7.2.0.2.BIN",
]


def parse(path: Path) -> dict:
    script = scan_devcap_script(path.read_bytes())
    chunks = []
    for c in script.commands:
        if c.cc != 0x20000202:
            continue
        p = c.params
        hdr = p[:16]
        iv = p[16:32]
        ln = struct.unpack_from(">I", p, 32)[0]
        ct = p[36:-10]
        tag = p[-10:]
        assert hdr == FIXED_HDR, f"unexpected fixed header in {path.name}"
        assert ln == len(ct) + 10, f"length mismatch in {path.name}"
        chunks.append({
            "iv": iv.hex(), "length_field": ln, "ct_len": len(ct),
            "ct": ct, "tag": tag.hex(),
        })
    legacy = script.firmware
    reframed = b"".join(c["ct"] for c in chunks)
    return {
        "name": path.stem,
        "n_chunks": len(chunks),
        "n_ivs": len({c["iv"] for c in chunks}),
        "n_tags": len({c["tag"] for c in chunks}),
        "total_ct_len": len(reframed),
        "total_tag_len": sum(c["ct_len"] + 10 for c in chunks),
        "ct_sha256": hashlib.sha256(reframed).hexdigest(),
        "legacy_len": len(legacy),
        "legacy_sha256": hashlib.sha256(legacy).hexdigest(),
        "first_iv": chunks[0]["iv"] if chunks else "",
        "chunks": chunks,
        "reframed": reframed,
        "legacy": legacy,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=ROOT / "out" / "firmware" / "reframed")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    results = []
    for dc in DEVCAPS:
        r = parse(dc)
        results.append(r)
        (out / f"{r['name']}.bin").write_bytes(r["reframed"])
        meta = {k: v for k, v in r.items() if k not in ("reframed", "legacy", "chunks")}
        meta["chunks"] = [{k: v for k, v in c.items() if k != "ct"} for c in r["chunks"]]
        (out / f"{r['name']}.json").write_text(json.dumps(meta, indent=2) + "\n")
        print(f"{r['name']}: {r['n_chunks']} chunks, {r['total_ct_len']} ciphertext bytes, "
              f"{r['n_ivs']} unique IVs, {r['n_tags']} unique tags")
        print(f"  reframed SHA-256: {r['ct_sha256']}")
        print(f"  legacy  SHA-256: {r['legacy_sha256']} ({r['legacy_len']} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
