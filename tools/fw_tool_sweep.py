#!/usr/bin/env python3
"""Exhaustive external-tool sweep over the NPCT75x capture artifacts.

Usage:
    python3 tools/fw_tool_sweep.py [OUTDIR]

Runs every available binary-analysis utility with several modes against the
two DevCap containers, the two extracted ciphertext streams, the embedded PE
driver, and the two downloaded Lenovo ZIP packages.  All stdout/stderr is
captured to OUTDIR/<tool>/<artifact>.txt and a consolidated index is written
to OUTDIR/tool_sweep_report.txt.

Strictly offline: no network, no TPM, no firmware-update replay.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "out" / "firmware" / "analysis" / "sweep"
ARTIFACTS = [
    ROOT / "out" / "firmware" / "NuvotonTpmDevCap.BIN",
    ROOT / "out" / "firmware" / "NuvotonTpmDevCap_7.2.0.2.BIN",
    ROOT / "out" / "firmware" / "npct75x_fw_7.2.2.0.bin",
    ROOT / "out" / "firmware" / "npct75x_fw_7.2.0.2.bin",
]
DRIVER = ROOT / "out" / "firmware" / "analysis" / "sweep" / "driver.pe"
ZIP_PKGS = [
    Path("/tmp/opencode/fwpkg/nuvoton_tpm_fw_update_v2.0.zip"),
    Path("/tmp/opencode/fwpkg2/nuvoton_tpm_fw_update.zip"),
]

HASHES = ["md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum"]
OPENSSL_DIGESTS = ["md5", "sha1", "sha256", "sha384", "sha512",
                   "sha3-256", "sha3-512", "blake2s256", "blake2b512",
                   "ripemd160", "sm3"]


def run(cmd: list[str], cwd: Path, timeout: int = 120) -> str:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout)
        return (r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else "")).strip()
    except Exception as exc:
        return f"ERROR: {exc}"


def main() -> int:
    out = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)

    # Carve the embedded PE driver from the first DevCap (binwalk offset 0x118).
    data = ARTIFACTS[0].read_bytes()
    DRIVER.write_bytes(data[0x118:0x118 + 0x6000])

    entries: list[tuple[str, str, str]] = []  # (tool, artifact, status)

    def capture(tool: str, artifact: str, text: str) -> None:
        d = out / tool
        d.mkdir(parents=True, exist_ok=True)
        safe = artifact.replace("/", "_") + ".txt"
        (d / safe).write_text(text + "\n")
        status = "ERROR" if text.startswith("ERROR:") else "ok"
        entries.append((tool, artifact, status))

    all_files = list(ARTIFACTS) + [DRIVER] + [p for p in ZIP_PKGS if p.exists()]

    # ---- file / hashes -----------------------------------------------------
    for tool in HASHES:
        if shutil.which(tool):
            for p in all_files:
                capture(tool, p.name, run([tool, str(p)], ROOT))
    if shutil.which("file"):
        for p in all_files:
            capture("file", p.name, run(["file", str(p)], ROOT))
    if shutil.which("exiftool"):
        for p in all_files:
            capture("exiftool", p.name, run(["exiftool", str(p)], ROOT))

    # ---- openssl digests ---------------------------------------------------
    if shutil.which("openssl"):
        for digest in OPENSSL_DIGESTS:
            for p in all_files:
                txt = run(["openssl", "dgst", f"-{digest}", str(p)], ROOT)
                capture(f"openssl_dgst_{digest}", p.name, txt)

    # ---- binwalk modes -----------------------------------------------------
    if shutil.which("binwalk"):
        for mode, flag in [("binwalk_B", "-B"), ("binwalk_A", "-A"),
                           ("binwalk_I", "-I")]:
            for p in all_files:
                capture(mode, p.name, run(["binwalk", flag, str(p)], ROOT))
        # Entropy analysis writes a PNG into cwd; run it in a dedicated dir.
        for p in ARTIFACTS:
            edir = out / "binwalk_E"
            edir.mkdir(parents=True, exist_ok=True)
            txt = run(["binwalk", "-E", str(p)], edir, timeout=600)
            capture("binwalk_E", p.name, txt)
        # Extraction pass into a temp dir (signatures only, no carving).
        edir = out / "binwalk_extract"
        edir.mkdir(parents=True, exist_ok=True)
        txt = run(["binwalk", "-e", "-C", str(edir), str(ARTIFACTS[0])], ROOT)
        capture("binwalk_extract", ARTIFACTS[0].name, txt)

    # ---- strings variants --------------------------------------------------
    if shutil.which("strings"):
        for mode, flags in [("strings_n4", ["-n", "4"]),
                            ("strings_n6", ["-n", "6"]),
                            ("strings_n8", ["-n", "8"]),
                            ("strings_off", ["-n", "5", "-t", "d"]),
                            ("strings_utf16le", ["-el", "-n", "4"]),
                            ("strings_utf16be", ["-eb", "-n", "4"])]:
            for p in all_files:
                capture(mode, p.name, run(["strings"] + flags + [str(p)], ROOT))

    # ---- hex dumps ---------------------------------------------------------
    if shutil.which("xxd"):
        for p in all_files:
            capture("xxd_head", p.name, run(["xxd", "-l", "256", str(p)], ROOT))
            capture("xxd_tail", p.name,
                    run(["xxd", "-s", "-256", str(p)], ROOT))
    if shutil.which("hexdump"):
        for p in all_files:
            capture("hexdump_C", p.name,
                    run(["hexdump", "-C", "-n", "256", str(p)], ROOT))
    if shutil.which("od"):
        for p in all_files:
            capture("od", p.name, run(["od", "-Ax", "-tx1", "-N", "256", str(p)], ROOT))

    # ---- archive listings --------------------------------------------------
    for tool in ("unzip", "7z"):
        if shutil.which(tool):
            args = ["-l"] if tool == "unzip" else ["l"]
            for p in ZIP_PKGS + list(ARTIFACTS):
                capture(f"{tool}_list", p.name, run([tool] + args + [str(p)], ROOT))

    # ---- PE driver disassembly ---------------------------------------------
    if DRIVER.exists():
        for label, binary, flags in [("objdump_x", "objdump", ["-x"]),
                                      ("objdump_d", "objdump", ["-d"]),
                                      ("objdump_s", "objdump", ["-s"]),
                                      ("objdump_p", "objdump", ["-p"]),
                                      ("nm", "nm", ["-a"]),
                                      ("readelf", "readelf", ["-a"])]:
            if shutil.which(binary):
                capture(label, DRIVER.name,
                        run([binary] + flags + [str(DRIVER)], ROOT))
        if shutil.which("gdb"):
            cmds = ["-batch", "-ex", f"file {DRIVER}", "-ex", "info files",
                    "-ex", "info sections", "-ex", "disassemble"]
            capture("gdb", DRIVER.name, run(["gdb"] + cmds, ROOT))

    # ---- decompression sanity (expected failure on ciphertext) -----------
    for tool, flag in [("gzip", "-t"), ("bzip2", "-t"), ("xz", "-t"),
                       ("zstd", "-t")]:
        if shutil.which(tool):
            for p in ARTIFACTS[2:]:
                capture(f"{tool}_test", p.name, run([tool, flag, str(p)], ROOT))

    # ---- z3 SMT-LIB: try to solve a 128-bit LCG from nonces ---------------
    if shutil.which("z3") or shutil.which("z3"):
        sys.path.insert(0, str(ROOT))
        from tpm_re.firmware import scan_devcap_script
        script = scan_devcap_script(ARTIFACTS[0].read_bytes())
        nonces = [c.params[16:32] for c in script.commands if c.cc == 0x20000202][:4]
        ints = [int.from_bytes(n, "big") for n in nonces]
        smt = ["(set-logic QF_BV)",
               "(declare-const a (_ BitVec 128))", "(declare-const c (_ BitVec 128))"]
        for i in range(3):
            ni, ni1 = f"(_ bv{ints[i]} 128)", f"(_ bv{ints[i+1]} 128)"
            smt.append(f"(assert (= {ni1} (bvadd (bvmul a {ni}) c)))")
        smt += ["(check-sat)", "(get-model)"]
        smt_path = out / "z3_lcg.smt2"
        smt_path.write_text("\n".join(smt) + "\n")
        zbin = shutil.which("z3")
        capture("z3_lcg", "nonce LCG constraints",
                run([zbin, str(smt_path)], ROOT, timeout=120) if zbin else "z3 missing")

    from collections import Counter
    counts = Counter(t for t, _, _ in entries)
    lines = ["=" * 78, "External tool sweep",
             f"generated={datetime.now(timezone.utc).isoformat()}",
             f"outdir={out}", f"captures={len(entries)}", "=" * 78]
    for tool, n in sorted(counts.items()):
        lines.append(f"  {tool:<24} {n} capture(s)")
    errors = [e for e in entries if e[2] == "ERROR"]
    lines.append(f"  errors: {len(errors)}")
    for e in errors[:10]:
        lines.append(f"    {e[0]} {e[1]}")
    lines.append("VERDICT: all tool output captured under OUTDIR/<tool>/")
    report = "\n".join(lines) + "\n"
    (out / "tool_sweep_report.txt").write_text(report)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
