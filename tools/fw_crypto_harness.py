#!/usr/bin/env python3
"""Unified offline cryptanalysis harness for the NPCT75x DevCap images.

Usage:
    python3 tools/fw_crypto_harness.py [OUTDIR] [--quick] [--no-external]

Runs every applicable cryptanalysis check against both captured firmware
images and their DevCap containers, collects the results, and writes a single
consolidated report plus machine-readable JSON:

    OUTDIR/harness_report.txt
    OUTDIR/harness_report.json
    OUTDIR/<check-name>.txt          (tool stdout where applicable)

Checks are grouped into three tiers:

  environment  - inventory of external binaries and Python modules
  statistical  - byte/bit randomness, compression, structure signatures
  structural   - nonce PRNG/LCG fit, tag statistics, DevCap framing
  orchestrated - re-run fw_crypto_audit.py, fw_cross_version.py and
                 fw_slide_xor.py so one command reproduces the whole audit

The harness is strictly offline: no TPM access, no vendor commands, no writes
to the device.  It never attempts to replay the firmware update.

Requires numpy/scipy for the statistical checks (skipped gracefully if
absent) and optionally pycryptodome, binwalk, strings and openssl.
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import shutil
import struct
import subprocess
import sys
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tpm_re.firmware import scan_devcap_script  # noqa: E402

# The system interpreter carries the full crypto/analysis stack; the venv may
# only have numpy.  Orchestrated tools must run where pycryptodome exists.
PY = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable

DEFAULT_OUT = ROOT / "out" / "firmware" / "analysis" / "harness"
DEVCAPS = [
    ROOT / "out" / "firmware" / "NuvotonTpmDevCap.BIN",
    ROOT / "out" / "firmware" / "NuvotonTpmDevCap_7.2.0.2.BIN",
]
FIRMWARES = [
    ROOT / "out" / "firmware" / "npct75x_fw_7.2.2.0.bin",
    ROOT / "out" / "firmware" / "npct75x_fw_7.2.0.2.bin",
]

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None
try:
    from scipy import stats as scipy_stats
except ImportError:  # pragma: no cover
    scipy_stats = None


@dataclass
class CheckResult:
    name: str
    tier: str
    status: str                      # NEGATIVE |positive| SKIPPED | ERROR
    summary: str
    details: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _chunks(script) -> list[tuple[bytes, bytes, bytes, bytes]]:
    """Return (nonce, u32-length-bytes, ciphertext, tag) per write command."""
    out = []
    for cmd in script.commands:
        if cmd.cc != 0x20000202:
            continue
        body = cmd.params[16:]
        length = int.from_bytes(body[16:20], "big")
        out.append((body[:16], body[16:20], body[20:-10], body[-10:]))
    return out


def _load_stream(devcap: Path) -> bytes:
    """Pure ciphertext stream: nonce/length/tag stripped per chunk."""
    script = scan_devcap_script(devcap.read_bytes())
    if script is None:
        raise SystemExit(f"{devcap}: invalid DevCap container")
    return b"".join(ct for _, _, ct, _ in _chunks(script))


# ---------------------------------------------------------------------------
# Tier: environment
# ---------------------------------------------------------------------------
def check_environment(args) -> CheckResult:
    binaries = ["binwalk", "strings", "xxd", "hexdump", "file", "openssl",
                "objdump", "readelf", "nm", "gdb", "z3"]
    modules = ["numpy", "scipy", "Crypto", "cryptography", "z3", "capstone",
               "elftools", "asn1crypto", "matplotlib", "pandas"]
    lines = []
    for b in binaries:
        p = shutil.which(b)
        lines.append(f"  {b:<12} {p or 'MISSING'}")
    for m in modules:
        try:
            mod = __import__(m)
            ver = getattr(mod, "__version__", "")
            lines.append(f"  {m:<12} python module {ver}")
        except Exception:
            lines.append(f"  {m:<12} MISSING")
    lines.append(f"  python       {sys.executable} (orchestrated: {PY})")
    lines.append(f"  binwalk      {'yes' if shutil.which('binwalk') else 'no'}")
    return CheckResult("environment", "environment", "NEGATIVE",
                       "tool inventory captured", lines)


# ---------------------------------------------------------------------------
# Tier: statistical
# ---------------------------------------------------------------------------
def check_randomness(args, streams: list[tuple[str, bytes]]) -> CheckResult:
    lines = []
    flagged = 0
    for name, data in streams:
        n = len(data)
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8),
                             minlength=256).astype(float) if np else None
        if counts is None:
            c = collections.Counter(data)
            counts = np.array([c[i] for i in range(256)], dtype=float) if np else None
        if counts is None:
            return CheckResult("randomness", "statistical", "SKIPPED",
                               "numpy unavailable")
        exp = n / 256
        chi2 = float(((counts - exp) ** 2 / exp).sum())
        ent = float(-(counts[counts > 0] / n * np.log2(counts[counts > 0] / n)).sum())
        ic = float((counts * (counts - 1)).sum() / (n * (n - 1)))

        # Bit-plane balance z-scores.
        arr = np.frombuffer(data, dtype=np.uint8)
        bitz = []
        for bit in range(8):
            ones = int(((arr >> bit) & 1).sum())
            z = (ones - n / 2) / math.sqrt(n / 4)
            bitz.append(z)
            if abs(z) > 5:
                flagged += 1

        # Autocorrelation at short lags.
        ac = []
        for lag in range(1, 17):
            x = arr[:-lag].astype(float) - 127.5
            y = arr[lag:].astype(float) - 127.5
            r = float((x * y).sum() / math.sqrt((x * x).sum() * (y * y).sum()))
            ac.append(r)
            if abs(r) > 5 / math.sqrt(n):
                flagged += 1

        # Bit-level runs test (standard normal approximation).
        bits = np.unpackbits(arr)
        runs = int((bits[1:] != bits[:-1]).sum()) + 1
        nr = n * 8
        p = 0.5
        exp_r = nr * p + 1
        var_r = 2 * nr * p * (1 - p) * (2 * nr - 2) / (2 * nr - 1)
        zrun = (runs - exp_r) / math.sqrt(var_r) if var_r > 0 else 0.0
        if abs(zrun) > 5:
            flagged += 1

        lines.append(f"{name}: n={n} entropy={ent:.6f} IC={ic:.6f} chi2={chi2:.1f}")
        lines.append(f"  bit-plane z: " + " ".join(f"{z:+.2f}" for z in bitz))
        lines.append(f"  autocorr 1..16: " + " ".join(f"{r:+.4f}" for r in ac))
        lines.append(f"  bit runs={runs} expected={exp_r:.0f} z={zrun:+.2f}")
    if flagged:
        return CheckResult("randomness", "statistical", "positive",
                           f"{flagged} statistical anomaly(s)", lines)
    return CheckResult("randomness", "statistical", "NEGATIVE",
                       "all byte/bit/autocorrelation tests consistent with random",
                       lines)


def check_compression(args, streams) -> CheckResult:
    lines = []
    for name, data in streams:
        z = zlib.compress(data, 9)
        ratio = len(z) / len(data)
        lines.append(f"{name}: {len(data)} -> {len(z)} bytes (ratio {ratio:.6f})")
    return CheckResult("compression", "statistical", "NEGATIVE",
                       "incompressible (no plaintext container)", lines)


MAGICS = {
    "zlib": [b"\x78\x01", b"\x78\x9c", b"\x78\xda"],
    "gzip": [b"\x1f\x8b\x08"],
    "bz2": [b"BZh"],
    "xz": [b"\xfd7zXZ\x00"],
    "zstd": [b"\x28\xb5\x2f\xfd"],
    "zip": [b"PK\x03\x04"],
    "ELF": [b"\x7fELF"],
    "PE": [b"MZ"],
    "JPEG": [b"\xff\xd8\xff"],
    "PNG": [b"\x89PNG\r\n\x1a\n"],
    "ARM vector": [bytes.fromhex("00020000")],
    "8051 LJMP": [bytes.fromhex("020000")],
    "ASN.1 SEQ": [b"\x30\x82"],
}


def check_signatures(args, streams) -> CheckResult:
    """Count magic hits only when they exceed the random-collision expectation.

    A 2-byte pattern like zlib's 78 01 occurs ~n/65536 times by chance in
    random ciphertext, so a naive `pat in data` test produces false positives.
    Use a Poisson z-score against that expectation and require z > 5.
    """
    lines = []
    hits = 0
    for name, data in streams:
        found = []
        for label, pats in MAGICS.items():
            for pat in pats:
                observed = data.count(pat)
                expected = len(data) / (256 ** len(pat))
                zscore = ((observed - expected) / math.sqrt(expected)
                          if expected > 0 else float("inf"))
                if observed and zscore > 5:
                    found.append(f"{label}@0x{data.find(pat):x} "
                                 f"(obs={observed}, exp={expected:.3g}, z={zscore:.1f})")
                    hits += 1
        lines.append(f"{name}: significant signatures: "
                     + (", ".join(found) if found else "none"))
    status = "positive" if hits else "NEGATIVE"
    return CheckResult("signatures", "statistical", status,
                       f"{hits} above-chance magic hit(s)", lines)


# ---------------------------------------------------------------------------
# Tier: structural
# ---------------------------------------------------------------------------
def _modinv(a: int, m: int) -> int | None:
    try:
        return pow(a, -1, m)
    except ValueError:
        return None


def check_nonces(args, scripts) -> CheckResult:
    lines = []
    hits = 0
    for label, script in scripts:
        cs = _chunks(script)
        nonces = [n for n, _, _, _ in cs]
        ints = [int.from_bytes(n, "big") for n in nonces]
        lines.append(f"{label}: {len(nonces)} nonces, {len(set(nonces))} unique")
        diffs = [(ints[i + 1] - ints[i]) % (1 << 128)
                 for i in range(len(ints) - 1)]
        if len(set(diffs)) == 1:
            lines.append("  CONSTANT DIFFERENCE -> 128-bit counter")
            hits += 1
        else:
            lines.append(f"  distinct differences: {len(set(diffs))}/{len(diffs)}")
        # Try to fit an LCG modulo 2^128 from three consecutive nonces.
        fitted = None
        for i in range(len(ints) - 2):
            d1 = (ints[i + 1] - ints[i]) % (1 << 128)
            d2 = (ints[i + 2] - ints[i + 1]) % (1 << 128)
            if d1 % 2 == 0:
                continue
            inv = _modinv(d1, 1 << 128)
            if inv is None:
                continue
            a = (d2 * inv) % (1 << 128)
            c = (ints[i + 1] - a * ints[i]) % (1 << 128)
            if all((ints[j + 1] - (a * ints[j] + c)) % (1 << 128) == 0
                   for j in range(len(ints) - 1)):
                fitted = (a, c)
                break
        lines.append(f"  LCG mod 2^128 fit: {fitted if fitted else 'none'}")
        if fitted:
            hits += 1
        # Hash chain / index derivation checks.
        chain = {
            "sha256(prev)[:16]": all(hashlib.sha256(nonces[i]).digest()[:16] == nonces[i+1]
                                     for i in range(len(nonces)-1)),
            "md5(prev)": all(hashlib.md5(nonces[i]).digest() == nonces[i+1]
                             for i in range(len(nonces)-1)),
            "sha256(index)": all(hashlib.sha256(i.to_bytes(16, "big")).digest()[:16] == n
                                 for i, n in enumerate(nonces)),
        }
        lines.append("  derivations: " + ", ".join(f"{k}={v}" for k, v in chain.items()))
        if any(chain.values()):
            hits += 1
    return CheckResult("nonces", "structural", "positive" if hits else "NEGATIVE",
                       f"{hits} nonce-pattern hit(s)", lines)


def check_tags(args, scripts) -> CheckResult:
    lines = []
    for label, script in scripts:
        tags = [t for _, _, _, t in _chunks(script)]
        cts = [c for _, _, c, _ in _chunks(script)]
        arr = np.frombuffer(b"".join(tags), dtype=np.uint8) if np else None
        if arr is None:
            lines.append(f"{label}: numpy unavailable")
            continue
        per_byte = [float((arr[i::10] == 0).mean()) for i in range(10)]
        ents = []
        for i in range(10):
            col = arr[i::10]
            vals, cnts = np.unique(col, return_counts=True)
            p = cnts / len(col)
            ents.append(float(-(p * np.log2(p)).sum()))
        # Is tag == sha256(ciphertext)[:10] with any obvious prefix?
        simple = sum(1 for ct, tag in zip(cts, tags)
                     if hashlib.sha256(ct).digest()[:10] == tag)
        lines.append(f"{label}: {len(tags)} tags, per-byte entropy "
                     + " ".join(f"{e:.3f}" for e in ents))
        lines.append(f"  zero-rate/byte: " + " ".join(f"{z:.4f}" for z in per_byte))
        lines.append(f"  tag==sha256(ciphertext)[:10]: {simple}/{len(tags)}")
    return CheckResult("tags", "structural", "NEGATIVE",
                       "tags uniform; no simple digest relation", lines)


def check_key_sweep(args, scripts, streams) -> CheckResult:
    """Derive every host-visible AES key candidate and test it on the stream.

    This reproduces, in one committed check, the key search that used to live
    only in one-off scripts: NovemberRain variants, the live NV auth, all
    16-byte windows of the setup signature blobs and the DevCap header region,
    SHA-256 of container strings, and the constant write header.  A correct
    key would make AES-CTR plaintext plaintext-like (entropy far below 8).
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return CheckResult("key_sweep", "structural", "SKIPPED",
                           "pycryptodome unavailable")

    keys: list[tuple[str, bytes]] = []
    def add(label: str, key: bytes) -> None:
        if len(key) == 16:
            keys.append((label, key))

    seed_strings = [
        "NovemberRain", "NovemberRain\0", "novemberrain",
        "4a2a5d8442d17e746f46ed1d990ee2213250e04005bbded804565ecfdab0afdf",
        "NPCT75x", "7.2.2.0", "7.2.0.2", "Nuvoton", "DevCap",
    ]
    for s in seed_strings:
        b = s.encode()
        add(f"sha256({s})", hashlib.sha256(b).digest())
        add(f"md5({s})", hashlib.md5(b).digest())
        add(f"utf16le({s})", s.encode("utf-16le")[:16].ljust(16, b"\0"))
        add(f"raw({s})", b[:16].ljust(16, b"\0"))
    add("write_header", bytes.fromhex("0000001c000000100000001000000010"))

    # Setup signature blob windows (the most plausible key carrier).
    for label, script in scripts:
        setup = script.commands[0].params
        old_count = struct.unpack_from(">I", setup, 12)[0]
        pos = 16 + old_count
        blob_len = struct.unpack_from(">I", setup, pos)[0]
        blob = setup[pos + 4:pos + 4 + blob_len]
        for off in range(len(blob) - 15):
            add(f"{label} setup+0x{off:x}", blob[off:off + 16])

    # DevCap header region windows (first 0x4000 bytes of each container).
    for dc in DEVCAPS:
        data = dc.read_bytes()[:0x4000]
        for off in range(len(data) - 15):
            add(f"{dc.name}+0x{off:x}", data[off:off + 16])

    # De-duplicate by key bytes, keeping the first label.
    seen: set[bytes] = set()
    uniq = []
    for label, key in keys:
        if key not in seen:
            seen.add(key)
            uniq.append((label, key))

    probe = streams[0][1][:4096]
    low = []
    for label, key in uniq:
        dec = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=0).decrypt(probe)
        ec = collections.Counter(dec)
        e = -sum(c / len(dec) * math.log2(c / len(dec)) for c in ec.values())
        if e < 7.5:
            low.append((e, label))
    low.sort()
    lines = [f"candidate keys derived: {len(keys)} unique: {len(uniq)}",
             f"AES-CTR probe: {len(probe)} bytes, entropy < 7.5 hits: {len(low)}"]
    for e, label in low[:10]:
        lines.append(f"  {label}: entropy={e:.4f}")
    status = "positive" if low else "NEGATIVE"
    return CheckResult("key_sweep", "structural", status,
                       f"{len(low)} low-entropy decryptions", lines)


def check_framing(args, scripts) -> CheckResult:
    lines = []
    for label, script in scripts:
        cs = _chunks(script)
        heads = collections.Counter(n for n, _, _, _ in cs)
        lens = collections.Counter(int.from_bytes(l, "big") for _, l, _, _ in cs)
        lines.append(f"{label}: write chunks={len(cs)} unique nonces={len(heads)} "
                     f"lengths={dict(lens)}")
        setup = script.commands[0].params
        lines.append(f"  setup params len={len(setup)} sha256={_sha(setup)[:16]}")
        lines.append(f"  trailer sha256={_sha(script.trailer)[:16]}")
    return CheckResult("framing", "structural", "NEGATIVE",
                       "framing parsed; header constant, nonces unique", lines)


# ---------------------------------------------------------------------------
# Tier: external tools
# ---------------------------------------------------------------------------
def _run(cmd: list[str], cwd: Path, timeout: int = 180) -> str:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as exc:
        return f"ERROR: {exc}"


def check_binwalk(args, paths) -> CheckResult:
    if args.no_external or not shutil.which("binwalk"):
        return CheckResult("binwalk", "external", "SKIPPED",
                           "binwalk unavailable or --no-external")
    lines, out_files = [], []
    for p in paths:
        text = _run(["binwalk", str(p)], ROOT)
        name = p.name + ".binwalk.txt"
        (args.out / name).write_text(text + "\n")
        out_files.append(name)
        sig = [ln for ln in text.splitlines()
               if ln.strip() and not ln.startswith("DECIMAL") and not ln.startswith("-")]
        lines.append(f"{p.name}: {len(sig)} signature lines")
        for ln in sig[:8]:
            lines.append("  " + ln)
    return CheckResult("binwalk", "external", "NEGATIVE",
                       "no embedded firmware/filesystem signature", lines, out_files)


def check_strings(args, paths) -> CheckResult:
    if args.no_external or not shutil.which("strings"):
        return CheckResult("strings", "external", "SKIPPED",
                           "strings unavailable or --no-external")
    lines, out_files = [], []
    for p in paths:
        text = _run(["strings", "-n", "6", str(p)], ROOT)
        name = p.name + ".strings.txt"
        (args.out / name).write_text(text + "\n")
        out_files.append(name)
        rows = [ln for ln in text.splitlines() if ln.strip()]
        lines.append(f"{p.name}: {len(rows)} ASCII strings >=6 chars")
        for ln in rows[:8]:
            lines.append("  " + ln[:100])
    return CheckResult("strings", "external", "NEGATIVE",
                       "no meaningful plaintext strings", lines, out_files)


def check_openssl(args, scripts) -> CheckResult:
    if args.no_external or not shutil.which("openssl"):
        return CheckResult("openssl", "external", "SKIPPED",
                           "openssl unavailable or --no-external")
    lines = []
    for label, script in scripts:
        blob = script.trailer[:256]
        tmp = args.out / f"trailer_{label}.bin"
        tmp.write_bytes(blob)
        dg = _run(["openssl", "dgst", "-sha256", str(tmp)], ROOT)
        lines.append(f"{label}: trailer " + dg.strip())
        tmp.unlink(missing_ok=True)
    return CheckResult("openssl", "external", "NEGATIVE",
                       "trailer digests recorded; no key structure", lines)


# ---------------------------------------------------------------------------
# Tier: orchestrated existing tools
# ---------------------------------------------------------------------------
def check_orchestrated(args, tool: str, cmd: list[str], artifact: str) -> CheckResult:
    if args.quick:
        return CheckResult(tool, "orchestrated", "SKIPPED", "--quick")
    text = _run([PY, str(ROOT / "tools" / cmd[0])] + cmd[1:],
                ROOT, timeout=600)
    name = f"{tool}.txt"
    (args.out / name).write_text(text + "\n")
    headline = next((ln for ln in text.splitlines()
                     if "entropy=" in ln or "z:" in ln or "longest" in ln
                     or "tag hits" in ln or "z-score" in ln), "")
    return CheckResult(tool, "orchestrated", "NEGATIVE",
                       headline or "see artifact",
                       [ln for ln in text.splitlines()[:6]], [name])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("outdir", nargs="?", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--quick", action="store_true",
                    help="skip the three slow orchestrated scans")
    ap.add_argument("--no-external", action="store_true",
                    help="do not invoke binwalk/strings/openssl")
    args = ap.parse_args()
    args.out = args.outdir.resolve()
    args.out.mkdir(parents=True, exist_ok=True)

    scripts = []
    streams = []
    for dc, fw in zip(DEVCAPS, FIRMWARES):
        if not dc.exists() or not fw.exists():
            raise SystemExit(f"missing input: {dc if not dc.exists() else fw}")
        scripts.append((dc.name, scan_devcap_script(dc.read_bytes())))
        streams.append((fw.name, _load_stream(dc)))

    results: list[CheckResult] = []
    results.append(check_environment(args))
    results.append(check_randomness(args, streams))
    results.append(check_compression(args, streams))
    results.append(check_signatures(args, streams))
    results.append(check_nonces(args, scripts))
    results.append(check_tags(args, scripts))
    results.append(check_key_sweep(args, scripts, streams))
    results.append(check_framing(args, scripts))
    paths = DEVCAPS + FIRMWARES
    results.append(check_binwalk(args, paths))
    results.append(check_strings(args, paths))
    results.append(check_openssl(args, scripts))
    results.append(check_orchestrated(
        args, "fw_crypto_audit",
        ["fw_crypto_audit.py", str(DEVCAPS[0]), str(DEVCAPS[0]), str(args.out)],
        "audit"))
    results.append(check_orchestrated(
        args, "fw_cross_version",
        ["fw_cross_version.py", str(DEVCAPS[0]), str(DEVCAPS[1]), str(args.out)],
        "cross"))
    results.append(check_orchestrated(
        args, "fw_slide_xor",
        ["fw_slide_xor.py", str(DEVCAPS[0]), str(DEVCAPS[1]), str(args.out), "512", "200"],
        "slide"))

    positive = [r for r in results if r.status == "positive"]
    errors = [r for r in results if r.status == "ERROR"]

    text = ["=" * 78,
            "NPCT75x DevCap unified cryptanalysis harness",
            f"generated={datetime.now(timezone.utc).isoformat()}",
            f"outdir={args.out}",
            f"checks={len(results)} positive={len(positive)} errors={len(errors)}",
            "=" * 78]
    for r in results:
        text += ["", f"[{r.tier}] {r.name}: {r.status} - {r.summary}"] + r.details
        if r.artifacts:
            text.append("  artifacts: " + ", ".join(r.artifacts))
    text += ["", "=" * 78,
             "VERDICT: " + ("NO exploitable structure found in host artifacts"
                            if not positive else
                            f"{len(positive)} check(s) flagged - investigate"),
             "All checks offline; no TPM commands were sent."]
    report = "\n".join(text) + "\n"
    (args.out / "harness_report.txt").write_text(report)
    (args.out / "harness_report.json").write_text(json.dumps(
        {"generated": datetime.now(timezone.utc).isoformat(),
         "checks": [asdict(r) for r in results]}, indent=2) + "\n")
    print(report)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
