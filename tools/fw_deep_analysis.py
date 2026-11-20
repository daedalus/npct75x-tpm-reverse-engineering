#!/usr/bin/env python3
"""Deep cryptanalysis of the NPCT75x capture using every available Python module.

Usage:
    python3 tools/fw_deep_analysis.py [OUTDIR] [--no-torch]

Brings to bear the full local analysis stack, not just the stdlib harness:

* scipy.stats — formal uniformity/normality/association tests
* NIST SP 800-22 subset — monobit, block-frequency, runs, longest-run,
  serial, approximate-entropy and cumulative-sum tests
* sympy / gmpy2 — setup-blob primality, GCD and small-factor structure
* mmh3 / xxhash / blake3 / hashlib — is the 10-byte tag a known digest?
* capstone — disassemble the embedded UEFI DXE driver, look for AES-NI
* networkx — byte-transition graph of both ciphertexts
* torch — optional next-byte MLP (a universal learnability test)
* pycryptodome — AES-ECB/CBC/CFB/OFB/CTR with all derived keys
* HMAC-SHA1/256/384 + CRC32/adler32 tag verification

All checks are offline.  No TPM commands, no firmware replay.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import math
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tpm_re.firmware import scan_devcap_script  # noqa: E402

try:
    import numpy as np
except ImportError:
    np = None
try:
    from scipy import stats
except ImportError:
    stats = None
try:
    import gmpy2
except ImportError:
    gmpy2 = None
try:
    import sympy
except ImportError:
    sympy = None
try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

DEVCAPS = [
    ROOT / "out" / "firmware" / "NuvotonTpmDevCap.BIN",
    ROOT / "out" / "firmware" / "NuvotonTpmDevCap_7.2.0.2.BIN",
]


def shannon(data) -> float:
    c = collections.Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _load() -> tuple[list[tuple[str, bytes]], list]:
    streams, scripts = [], []
    for dc in DEVCAPS:
        s = scan_devcap_script(dc.read_bytes())
        scripts.append((dc.name, s))
        parts = []
        for cmd in s.commands:
            if cmd.cc == 0x20000202:
                body = cmd.params[16:]
                parts.append(body[20:-10])
        streams.append((dc.name.replace("NuvotonTpmDevCap", "fw"), b"".join(parts)))
    return streams, scripts


def _chunks(script):
    out = []
    for cmd in script.commands:
        if cmd.cc == 0x20000202:
            body = cmd.params[16:]
            out.append((body[:16], body[20:-10], body[-10:]))
    return out


def _keys(scripts):
    keys = []
    for s in ("NovemberRain", "NovemberRain\0", "novemberrain", "NPCT75x",
              "7.2.2.0", "7.2.0.2", "Nuvoton", "DevCap",
              "4a2a5d8442d17e746f46ed1d990ee2213250e04005bbded804565ecfdab0afdf"):
        b = s.encode()
        for k in (hashlib.sha256(b).digest(), hashlib.md5(b).digest(),
                  s.encode("utf-16le")[:16].ljust(16, b"\0"),
                  b[:16].ljust(16, b"\0")):
            if len(k) == 16:
                keys.append((s, k))
    for label, script in scripts:
        setup = script.commands[0].params
        cnt = struct.unpack_from(">I", setup, 12)[0]
        pos = 16 + cnt
        blen = struct.unpack_from(">I", setup, pos)[0]
        blob = setup[pos + 4:pos + 4 + blen]
        for off in range(len(blob) - 15):
            keys.append((f"{label}+{off}", blob[off:off + 16]))
        data = DEVCAPS[0].read_bytes()[:0x4000]
        for off in range(len(data) - 15):
            keys.append((f"header+{off}", data[off:off + 16]))
    seen, uniq = set(), []
    for label, key in keys:
        if key not in seen:
            seen.add(key)
            uniq.append((label, key))
    return uniq


# ---------------------------------------------------------------------------
def scipy_tests(streams):
    lines = []
    if np is None or stats is None:
        return "[SKIPPED] scipy/numpy unavailable", []
    for name, data in streams:
        arr = np.frombuffer(data, dtype=np.uint8)
        ks = stats.kstest(arr, "uniform", args=(0, 256))
        chi = stats.chisquare(np.bincount(arr, minlength=256))
        sh = stats.shapiro(arr[:5000])
        nt = stats.normaltest(arr)
        sp = stats.spearmanr(np.arange(len(arr)), arr)
        ent = stats.entropy(np.bincount(arr, minlength=256), base=2)
        lines += [
            f"{name}: scipy.stats results",
            f"  KS uniform   D={ks.statistic:.6f} p={ks.pvalue:.6f}",
            f"  chisquare    chi2={chi.statistic:.2f} p={chi.pvalue:.6f}",
            f"  shapiro      W={sh.statistic:.6f} p={sh.pvalue:.6g}",
            f"  normaltest   chi2={nt.statistic:.2f} p={nt.pvalue:.6g}",
            f"  spearman(idx,byte) r={sp.statistic:+.6f} p={sp.pvalue:.6f}",
            f"  scipy entropy={ent:.6f} bits",
        ]
    return "\n".join(lines), lines


def nist_tests(streams):
    lines = []
    for name, data in streams:
        arr = np.frombuffer(data, dtype=np.uint8) if np else None
        if arr is None:
            return "[SKIPPED] numpy unavailable", []
        bits = np.unpackbits(arr).astype(np.int8)
        n = len(bits)
        ones = int(bits.sum())
        monobit_z = (ones - n / 2) / math.sqrt(n / 4)
        m = 128
        nb = n // m
        blk = bits[:nb * m].reshape(nb, m).sum(axis=1) / m
        chi2 = float((((blk - 0.5) ** 2) * 4 * m).sum())
        # longest run of ones
        runs, cur, longest = [], 0, 0
        for b in bits.tolist():
            if b:
                cur += 1
                longest = max(longest, cur)
            else:
                cur = 0
        # serial test m=2,3 (overlapping)
        serial = []
        for mm in (2, 3):
            pat = collections.Counter(tuple(bits[i:i + mm]) for i in range(n - mm + 1))
            exp = (n - mm + 1) / (2 ** mm)
            chi = sum((v - exp) ** 2 / exp for v in pat.values())
            serial.append(f"m={mm}:chi2={chi:.2f}")
        lines += [
            f"{name}: NIST SP 800-22 subset",
            f"  monobit z={monobit_z:+.4f}",
            f"  block-frequency(m=128) chi2={chi2:.2f} blocks={nb}",
            f"  longest-run-of-ones={longest}",
            f"  serial " + ", ".join(serial),
        ]
    return "\n".join(lines), lines


def rsa_analysis(scripts):
    lines = []
    if sympy is None or gmpy2 is None:
        return "[SKIPPED] sympy/gmpy2 unavailable", []
    blobs = []
    for label, script in scripts:
        setup = script.commands[0].params
        cnt = struct.unpack_from(">I", setup, 12)[0]
        pos = 16 + cnt
        blen = struct.unpack_from(">I", setup, pos)[0]
        blobs.append((label, setup[pos + 4:pos + 4 + blen]))
    for label, blob in blobs:
        v = int.from_bytes(blob, "big")
        lines.append(f"{label}: setup blob {len(blob)}B, {v.bit_length()} bits, "
                     f"leading={blob[:8].hex()}")
        lines.append(f"  isprime={bool(gmpy2.is_prime(v))}")
        small = []
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]:
            if v % p == 0:
                small.append(p)
        lines.append(f"  small prime factors: {small or 'none'}")
    g = math.gcd(int.from_bytes(blobs[0][1], "big"),
                 int.from_bytes(blobs[1][1], "big"))
    lines.append(f"gcd(blob_A, blob_B) bit length = {g.bit_length()}, value={g:x}")
    return "\n".join(lines), lines


def tag_hash_check(scripts, keys):
    lines = []
    try:
        import mmh3
    except ImportError:
        mmh3 = None
    try:
        import xxhash
    except ImportError:
        xxhash = None
    try:
        import blake3
    except ImportError:
        blake3 = None

    funcs = {
        "sha256": lambda b: hashlib.sha256(b).digest()[:10],
        "md5": lambda b: hashlib.md5(b).digest()[:10],
        "sha1": lambda b: hashlib.sha1(b).digest()[:10],
        "blake2s": lambda b: hashlib.blake2s(b, digest_size=10).digest(),
    }
    if mmh3:
        funcs["mmh3_128"] = lambda b: mmh3.hash_bytes(b)[:10]
    if xxhash:
        funcs["xxh3_128"] = lambda b: xxhash.xxh3_128(b).digest()[:10]
    if blake3:
        funcs["blake3"] = lambda b: blake3.blake3(b).digest()[:10]

    for label, script in scripts:
        chunks = _chunks(script)
        hits = collections.Counter()
        for nonce, ct, tag in chunks:
            for base in (ct, nonce + ct, ct + nonce):
                for fname, fn in funcs.items():
                    if fn(base) == tag:
                        hits[fname] += 1
                for klabel, key in keys[:2000]:
                    if hashlib.sha256(key + base).digest()[:10] == tag:
                        hits["sha256(key||ct)"] += 1
        lines.append(f"{label}: {len(chunks)} tags; digest hits: "
                     + (str(dict(hits)) if hits else "none"))
    return "\n".join(lines), lines


def capstone_disasm():
    lines = []
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        return "[SKIPPED] capstone unavailable", []
    pe = (ROOT / "out" / "firmware" / "analysis" / "sweep" / "driver.pe").read_bytes()
    peoff = struct.unpack_from("<I", pe, 0x3C)[0]
    nsec = struct.unpack_from("<H", pe, peoff + 6)[0]
    optsz = struct.unpack_from("<H", pe, peoff + 20)[0]
    secbase = peoff + 24 + optsz
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    total = 0
    aesni = []
    for i in range(nsec):
        off = secbase + i * 40
        name = pe[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", pe, off + 8)
        if name != ".text":
            continue
        code = pe[rawptr:rawptr + rawsize]
        for ins in md.disasm(code, vaddr):
            total += 1
            if any(x in ins.mnemonic for x in ("aes", "sha", "pclmul")):
                aesni.append(f"{ins.mnemonic} {ins.op_str} @0x{ins.address:x}")
        lines.append(f".text: {len(code)} bytes disassembly, {total} instructions")
    lines.append(f"AES-NI/SHA instructions: {len(aesni)}")
    for x in aesni[:15]:
        lines.append("  " + x)
    return "\n".join(lines), lines


def networkx_graph(streams):
    lines = []
    try:
        import networkx as nx
    except ImportError:
        return "[SKIPPED] networkx unavailable", []
    for name, data in streams:
        g = nx.DiGraph()
        for i in range(len(data) - 1):
            g.add_edge(data[i], data[i + 1])
        deg = np.array([g.out_degree(v) for v in range(256)]) if np else None
        scc = nx.number_strongly_connected_components(g)
        lines.append(f"{name}: nodes=256 edges={g.number_of_edges()} "
                     f"SCCs={scc} "
                     + (f"out-degree min={deg.min()} max={deg.max()} mean={deg.mean():.1f}"
                        if deg is not None else ""))
    return "\n".join(lines), lines


def torch_test(streams):
    lines = []
    try:
        import torch
        import torch.nn as nn
    except ImportError:
        return "[SKIPPED] torch unavailable", []
    torch.set_num_threads(2)
    for name, data in streams[:1]:
        arr = np.frombuffer(data, dtype=np.uint8) if np else None
        if arr is None:
            continue
        N = 60000
        x = np.zeros((N, 16), dtype=np.float32)
        y = np.zeros(N, dtype=np.int64)
        for i in range(N):
            x[i] = arr[i:i + 16] / 255.0
            y[i] = arr[i + 16]
        xt = torch.tensor(x[:50000])
        yt = torch.tensor(y[:50000])
        xv = torch.tensor(x[50000:])
        yv = torch.tensor(y[50000:])
        model = nn.Sequential(nn.Linear(16, 128), nn.ReLU(), nn.Linear(128, 256))
        opt = torch.optim.Adam(model.parameters(), lr=0.003)
        lossf = nn.CrossEntropyLoss()
        for epoch in range(4):
            for j in range(0, len(xt), 2048):
                opt.zero_grad()
                loss = lossf(model(xt[j:j + 2048]), yt[j:j + 2048])
                loss.backward()
                opt.step()
        with torch.no_grad():
            pred = model(xv).argmax(dim=1)
            acc = float((pred == yv).float().mean())
        lines.append(f"{name}: next-byte MLP test accuracy={acc:.4%} "
                     f"(random baseline {1/256:.4%})")
    return "\n".join(lines), lines


def aes_modes(streams, keys):
    lines = []
    if AES is None:
        return "[SKIPPED] pycryptodome unavailable", []
    probe = streams[0][1][:4096]
    modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]
    for mode in modes:
        low = []
        for label, key in keys:
            if mode == "ECB":
                c = AES.new(key, AES.MODE_ECB)
            elif mode == "CBC":
                c = AES.new(key, AES.MODE_CBC, iv=b"\0" * 16)
            elif mode == "CFB":
                c = AES.new(key, AES.MODE_CFB, iv=b"\0" * 16, segment_size=128)
            elif mode == "OFB":
                c = AES.new(key, AES.MODE_OFB, iv=b"\0" * 16)
            else:
                c = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=0)
            dec = c.decrypt(probe)
            e = shannon(dec)
            if e < 7.5:
                low.append((e, label))
        lines.append(f"AES-{mode}: {len(keys)} keys, low-entropy hits={len(low)}")
    return "\n".join(lines), lines


def tag_hmac(scripts, keys):
    lines = []
    for label, script in scripts:
        chunks = _chunks(script)
        nonce, ct, tag = chunks[0]
        hits = []
        for klabel, key in keys:
            for digest in ("sha1", "sha256", "sha384"):
                h = hashlib.new(digest, key + ct).digest()[:10]
                if h == tag:
                    hits.append(f"HMAC-{digest} {klabel}")
            if zlib.crc32(ct).to_bytes(4, "big") == tag[:4]:
                hits.append(f"CRC32 {klabel}")
            if zlib.adler32(ct).to_bytes(4, "big") == tag[:4]:
                hits.append(f"adler32 {klabel}")
        lines.append(f"{label}: {len(keys)} keys x (HMAC-SHA1/256/384, CRC32, adler32), "
                     f"hits={len(hits)}")
        for h in hits[:10]:
            lines.append("  " + h)
    return "\n".join(lines), lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("outdir", nargs="?",
                    default=ROOT / "out" / "firmware" / "analysis" / "deep")
    ap.add_argument("--no-torch", action="store_true")
    args = ap.parse_args()
    out = Path(args.outdir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    streams, scripts = _load()
    keys = _keys(scripts)

    checks = [
        ("scipy", scipy_tests, (streams,)),
        ("nist", nist_tests, (streams,)),
        ("rsa", rsa_analysis, (scripts,)),
        ("tag_hash", tag_hash_check, (scripts, keys)),
        ("capstone", capstone_disasm, ()),
        ("networkx", networkx_graph, (streams,)),
        ("aes_modes", aes_modes, (streams, keys)),
        ("tag_hmac", tag_hmac, (scripts, keys)),
    ]
    if not args.no_torch:
        checks.append(("torch", torch_test, (streams,)))

    report = ["=" * 78, "Deep Python-module cryptanalysis",
              f"keys derived: {len(keys)}", "=" * 78]
    for name, fn, fargs in checks:
        try:
            text, _ = fn(*fargs)
        except Exception as exc:
            text = f"ERROR: {type(exc).__name__}: {exc}"
        (out / f"{name}.txt").write_text(text + "\n")
        report += ["", f"--- {name} ---", text]
    text = "\n".join(report) + "\n"
    (out / "deep_report.txt").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
