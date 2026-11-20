#!/usr/bin/env python3
"""Two-window sliding XOR differential of two encrypted firmware streams.

Usage:
    python3 tools/fw_slide_xor.py A.BIN B.BIN [OUTDIR] [WINDOW] [TOP_LAGS]

Loads two Nuvoton DevCap containers, extracts their 0x20000202 write streams,
then slides *two independent windows of equal length* across the two buffers:

    A[i : i+W]  XOR  B[j : j+W]

with i and j chosen independently.  Equivalently, for lag d = j - i the window
starts at position i in A and i+d in B, and i is swept over every valid offset.
This detects a block of bytes that was copied from one version into the other
but shifted by n bytes (d = +/-n), which a single fixed anchor per lag misses.

For each (i, j, d) the XOR window is scored for:

* Shannon entropy (bits/byte),
* zero-byte fraction (ciphertext-byte equality),
* index of coincidence,
* longest constant-byte run.

FFT cross-correlation of the 256 byte-value indicators first computes the
total equality count at every lag d.  Lags with the most anomalous totals are
candidate shifts; a cumulative-sum sweep then finds, for each candidate lag,
the window position with the highest XOR-zero count, and only those peaks are
re-scored with the full window statistics.  Entirely offline; no TPM access.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tpm_re.firmware import scan_devcap_script  # noqa: E402


def load_stream(path: Path, *, raw: bool = False) -> np.ndarray:
    script = scan_devcap_script(path.read_bytes())
    if script is None:
        raise SystemExit(f"{path}: not a valid DevCap container")
    if raw:
        data = script.firmware
    else:
        # params layout: [0:16] constant header, [16:32] nonce, [32:36] BE
        # length, [36:-10] ciphertext, [-10:] tag.  The BE length counts
        # ciphertext + tag (verified: 906 = 896 + 10).  DevCapScript.firmware
        # is params[16:], so strip nonce/length/tag to avoid identical length
        # fields creating a fake equality signal.
        parts = []
        for cmd in script.commands:
            if cmd.cc != 0x20000202:
                continue
            body = cmd.params[16:]
            length = int.from_bytes(body[16:20], "big")
            if length != len(body) - 20:
                raise SystemExit(
                    f"{path}: chunk at 0x{cmd.offset:X}: length {length} != "
                    f"{len(body) - 20}"
                )
            parts.append(body[20:-10])
        data = b"".join(parts)
    return np.frombuffer(data, dtype=np.uint8)


def equality_counts(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """matches[d] = #{i : a[i] == b[i-d]}, indexed directly by lag d.

    FFT cross-correlation of one-hot byte indicators.  Negative lags wrap to
    the end of the circular buffer.  Verified against direct comparison.
    """
    n = 1 << (int(math.ceil(math.log2(len(a) + len(b)))) + 1)
    total = np.zeros(n, dtype=np.float64)
    for v in range(256):
        fa = np.fft.rfft((a == v).astype(np.float64), n)
        fb = np.fft.rfft((b == v).astype(np.float64), n)
        total += np.fft.irfft(fa * np.conjugate(fb), n)
    return np.rint(total).astype(np.int64)


def window_stats(x: np.ndarray) -> dict:
    x = np.asarray(x, dtype=np.uint8)
    n = len(x)
    if n == 0:
        return {}
    counts = np.bincount(x, minlength=256).astype(np.float64)
    p = counts / n
    entropy = float(-(p[p > 0] * np.log2(p[p > 0])).sum())
    ic = float((counts * (counts - 1)).sum() / (n * (n - 1))) if n > 1 else 0.0
    change = np.flatnonzero(x[1:] != x[:-1]) + 1
    starts = np.concatenate(([0], change))
    ends = np.concatenate((change, [n]))
    return {
        "entropy": entropy,
        "zero_frac": int(counts[0]) / n,
        "ic": ic,
        "longest_run": int((ends - starts).max()),
        "distinct": int((counts > 0).sum()),
    }


def scan_lag(a: np.ndarray, b: np.ndarray, d: int, window: int,
             top_k: int = 3) -> list[tuple[int, int, int, window_stats]]:
    """Slide two equal-length windows at lag d = j - i over all start offsets."""
    if d >= 0:
        i_min = 0
        i_max = min(len(a) - window, len(b) - d - window)
    else:
        i_min = -d
        i_max = min(len(a) - window, len(b) - d - window)
    if i_max < i_min:
        return []

    m = i_max - i_min + 1
    xa = a[i_min:i_max + window]
    xb = b[i_min + d:i_max + d + window]
    eq = (xa == xb)
    cs = np.concatenate(([0], np.cumsum(eq, dtype=np.int64)))
    sums = cs[window:] - cs[:-window]  # XOR-zero count at each window position
    top = np.argsort(-sums)[:top_k]

    out = []
    for t in top:
        i = i_min + int(t)
        j = i + d
        x = np.bitwise_xor(a[i:i + window], b[j:j + window])
        out.append((i, j, int(sums[t]), window_stats(x)))
    return out


def longest_common_substring(a: np.ndarray, b: np.ndarray,
                             seed: int = 8) -> tuple[int, int, int]:
    """Longest exact byte run shared by both streams (keystream-reuse test).

    Seeds a 16-byte hash index with all ``seed``-byte substrings of B, extends
    every hit into A, and returns (length, A offset, B offset).
    """
    a, b = bytes(a), bytes(b)
    idx: dict[bytes, list[int]] = {}
    for j in range(len(b) - seed + 1):
        idx.setdefault(b[j:j + seed], []).append(j)
    best = (0, -1, -1)
    for i in range(len(a) - seed + 1):
        for j in idx.get(a[i:i + seed], ()):
            n = seed
            while i + n < len(a) and j + n < len(b) and a[i + n] == b[j + n]:
                n += 1
            if n > best[0]:
                best = (n, i, j)
    return best


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    out_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("out/firmware/analysis")
    window = int(sys.argv[4]) if len(sys.argv) > 4 else 512
    top_lags = int(sys.argv[5]) if len(sys.argv) > 5 else 200
    raw = "--raw" in sys.argv[6:]

    a = load_stream(Path(sys.argv[1]), raw=raw)
    b = load_stream(Path(sys.argv[2]), raw=raw)
    out_dir.mkdir(parents=True, exist_ok=True)

    matches = equality_counts(a, b)
    p = 1.0 / 256.0
    min_overlap = max(window * 8, 4096)
    lo, hi = -(len(b) - min_overlap), len(a) - min_overlap
    lags = np.arange(lo, hi + 1)
    overlap = np.where(lags >= 0,
                       np.minimum(len(a) - lags, len(b)),
                       np.minimum(len(a), len(b) + lags))
    counts = matches[lags % len(matches)]
    zero_frac = counts / overlap
    zscore = (counts - overlap * p) / np.sqrt(overlap * p * (1 - p))

    # Candidate lags: strongest total equality signal, plus lag 0.
    cand = list(lags[np.argsort(-zscore)[:top_lags]])
    if 0 not in cand:
        cand.append(0)

    results = []
    for d in cand:
        for i, j, zeros, s in scan_lag(a, b, int(d), window, top_k=3):
            results.append((i, j, int(d), zeros, s))

    results.sort(key=lambda r: -r[3])
    best = results[:40]

    lcs_len, lcs_i, lcs_j = longest_common_substring(a, b)

    lines = [
        "=" * 82,
        f"A={len(a)} bytes  B={len(b)} bytes  window W={window}",
        f"lags available: {len(lags):,} ({lo}..{hi}), min overlap {min_overlap}",
        f"candidate lags scanned: {len(cand)} (top |z| of total equality + lag 0)",
        f"total-equality z: mean={zscore.mean():.3f} std={zscore.std():.3f} "
        f"max={zscore.max():.3f}",
        f"window XOR-zero fraction across candidates: "
        f"min={min(r[4]['zero_frac'] for r in results):.6f} "
        f"max={max(r[4]['zero_frac'] for r in results):.6f} "
        f"(random expectation {p:.6f})",
        f"longest exact shared byte run: {lcs_len} "
        f"(A+{lcs_i}, B+{lcs_j}); random expectation "
        f"~{math.log(len(a) * len(b), 256):.2f} bytes",
        "",
        "Top (i, j) window pairs by XOR-zero count:",
        "  i=A start  j=B start  d=j-i  zeros/W  entropy  IC  run  distinct",
    ]
    for i, j, d, zeros, s in best:
        lines.append(
            f"  i={i:7d} j={j:7d} d={d:+8d} zeros={zeros:4d}/{window} "
            f"entropy={s['entropy']:.4f} zero_frac={s['zero_frac']:.4f} "
            f"ic={s['ic']:.4f} run={s['longest_run']:3d} distinct={s['distinct']:3d}"
        )
    text = "\n".join(lines) + "\n"
    (out_dir / "slide_xor.txt").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
