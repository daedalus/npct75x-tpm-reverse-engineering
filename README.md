# tpm_re — read-only TPM 2.0 reverse-engineering toolkit

`tpm_re` talks straight to `/dev/tpmrm0` and marshals TPM 2.0 commands itself. There is no `tpm2-tools` dependency, so every byte on the wire is visible, explainable, and patchable. The only external tool used is `openssl`, and only to summarise X.509 EK certificates.

The toolkit was written while reverse engineering the discrete TPM in a Lenovo ThinkCentre M75q Gen 2 (Nuvoton **NPCT75x**, firmware **7.2**). The observed facts and the open questions live in [`knowledge/NPCT75x.md`](knowledge/NPCT75x.md).

## Current status (2026-11-20)

* Offline suite: **97 tests pass** (`python3 -m pytest tests/ -q`).
* NV `0x01802006` auth is **statically derived and live-confirmed**:
  `SHA256(UTF-16LE("NovemberRain") + 0000)` = `4a2a5d84…df`. See
  [`tpm_re/nvauth.py`](tpm_re/nvauth.py). `NV_Read` with this auth returns 16
  bytes; an empty password returns `BAD_AUTH`. The TPM was temporarily
  wedged by a `0x20000202` probe but the hardware was later restored.
* The BIOS image contains **AMD fTPM**, not NPCT75x firmware. The AMI FMP
  driver is a version-reporting/capsule-dispatch shim; its `SetImage` path and
  the `AMI ` capsule layout are decoded in section 7.1 of the knowledge file.
* `python3 -m tpm_re ami FILE --extract FW.bin` parses such a capsule offline.
* Vendor command `0x2000012f` is statically identified as a Nuvoton variant of
  `FieldUpgradeStart`; it is state-changing and has not been probed live.
* The TPM is operational again (`/dev/tpm0`, `MSFT0101:00`); the recovery
  attempts that failed earlier are recorded in `knowledge/NPCT75x.md` §6.1.
* A public Lenovo Nuvoton firmware package was fetched with provenance. Its
  `NuvotonTpmDevCap.BIN` uses a **DevCap** container (not `AMI `) holding a
  257-command vendor replay script; `0x20000200/201/202/203` are
  setup/erase/write/commit, and the 252 `0x20000202` chunks yield the
  **232,840-byte NPCT75x 7.2.2.0 firmware stream** (SHA-256 `6659e5c5…2ca16`).
  See `knowledge/NPCT75x.md` §7.2–7.4.
* Each chunk frames a 16-byte IV/nonce, a big-endian `u32` length and a 10-byte
  trailer; 225,280 bytes of actual firmware remain — exactly the erase range.
  Known-plaintext/XOR/ECB/AES key search and CCM/GCM tag verification all
  failed: the key is TPM-internal. Reports: `out/firmware/analysis/`.
* `python3 -m tpm_re devcap NuvotonTpmDevCap.BIN --extract FW.bin` parses this
  script offline. The `0x20000202` wedge is explained: the probe sent 16 bytes
  where the script always sends 942.
* `python3 tools/fw_crypto_audit.py FW.bin DEVCAP.BIN OUTDIR` reproduces the
  portion dumps and the cleartext audit (repeating-key XOR, known plaintext,
  ECB, container key search).
* wolfTPM v4.2.0 identifies this exact module (`NPCT75x"!!4rls, Fw 7.2`) and
  maps `0x20000213` to `NTC2_GetConfig` (18-byte `CFG_STRUCT`) and
  `0x20000211` to the state-changing `NTC2_PreConfig`. The live `Cfg_H` is
  `0xf0`, so SPDM is already enabled. See `knowledge/NPCT75x.md` §9.
* The nine V-bit commands in `TPM_CAP_COMMANDS` are the complete vendor
  surface. None of them, and none of the Nuvoton SPDM vendor commands, reads
  firmware. Public Nuvoton security targets state explicitly that field
  upgrade never exposes plaintext; a dump therefore needs physical access to
  the chip (programmer, JTAG or fault injection), which is not available.
  Host-side paths (`/dev/mem` under `STRICT_DEVMEM`, `/dev/spidev`, I²C, EFI
  variables, NV indices) were checked and ruled out — §9 for details.
* The TPM cannot be reconfigured from the host into a JTAG/SPI/I²C debug
  port: the certified part defines no maintenance interface, NPCT75x GPIOs
  are output-only, and SPDM only encrypts the same TIS traffic. §10.6 has the
  source cross-references. A read-only `TPM2_GetTestResult` probe returned a
  225-byte diagnostic record, not a memory dump (§10.7).
* A second Lenovo Nuvoton package (`nuvoton_tpm_fw_update.zip`) yielded a
  7.2.0.2 DevCap with 266 commands and a 241,302-byte stream (pure ciphertext
  233,472 bytes). Cross-version comparison found 0 shared nonces, 0 identical
  16B blocks and 0 shared ciphertext blocks; `tools/fw_cross_version.py`
  reproduces it. §10.8.
* `tools/fw_slide_xor.py` slides two independent equal-length windows over both
  ciphertext streams to detect a block shifted by *n* bytes. Framing must be
  stripped first (identical BE length fields otherwise fake equality at lags
  `0`/`±1`/`±926`). On pure ciphertext the equality z-score is a perfect random
  null (std 1.001, max 4.85), best window is 11/512 zero bytes, and the longest
  exact shared run is 0 — no keystream reuse or shifted copy. §10.9.
* `python3 tools/fw_crypto_harness.py` runs the whole offline audit in one
  command: tool inventory, byte/bit randomness (chi-squared, bit-plane z,
  autocorrelation, runs), compression, above-chance magic signatures, nonce
  counter/LCG/hash-chain checks, tag statistics, a 15,718-unique-key AES-CTR
  sweep, binwalk/strings/openssl, and orchestrated re-runs of all three `fw_*`
  tools. Reports land in `out/firmware/analysis/harness/`
  (`harness_report.txt` + JSON). Current verdict: no exploitable structure.
  §10.10.
* `python3 tools/fw_tool_sweep.py` runs **every available external binary** in
  multiple modes — `file`, `binwalk` (`-B`/`-A`/`-E`/`-I`/`-e`), `strings`
  (4 encodings, 3 minimum lengths, offsets), `xxd`, `hexdump`, `od`, 11
  `openssl dgst` hashes, 5 checksum utilities, `exiftool`, `unzip`, `7z`,
  `objdump`, `nm`, `readelf`, `gdb`, gzip/bzip2/xz/zstd integrity tests, and
  a `z3` SMT-LIB nonce-LCG solve. 246 captures land under
  `out/firmware/analysis/sweep/`.
* `python3 tools/fw_deep_analysis.py` brings the full Python stack:
  `scipy.stats`, a NIST SP 800-22 subset, `sympy`/`gmpy2` setup-blob analysis,
  `mmh3`/`xxhash`/`blake3` tag checks, `capstone` driver disassembly,
  `networkx` byte-transition graph, an optional `torch` next-byte predictor,
  all five AES modes over 15,676 keys, and HMAC/CRC tag checks. §10.11.

* `python3 tools/fw_reframe.py` emits the pure per-chunk ciphertext stream and
  JSON metadata (IV, length, tag) for both packages, making the framing
  `16B fixed header | 16B IV | BE len | ct | 10B tag` explicit. It is an audit
  aid, not a fix — the crypto harnesses already strip the framing correctly.
  §10.12.

* `python3 tools/fw_rsa_analysis.py` extracts both 256-byte blobs per package
  (setup + commit) and tests whether the firmware-update RSA modulus can be
  recovered (setup-as-modulus, signature gcd, same-message padding, blob
  properties). All negative: no `n`, so a related-message attack is
  inapplicable. §10.13.

## Safety model

* Every command goes through an explicit read-only allowlist.
* State-changing commands are refused unless `--allow-write` is passed.
* `raw` refuses non-allowlisted command codes before opening the device.
* Vendor commands are **listed but never sent**: their semantics are unknown.
* Nothing in this toolkit writes NV, changes auth, starts sessions, or enters firmware-update mode.
* One read can still change state: an `NV_Read` that fails authorization on an index without `TPMA_NV_NO_DA` increments the dictionary-attack lockout counter. `nv --index` (and the EK certificate reader) therefore refuse such indices unless `--allow-da` is passed. `raw` does not apply this check, so a hand-built `NV_Read` is your own responsibility.

## Requirements

* Linux with a TPM 2.0 character device (`/dev/tpmrm0`; the user must be in the `tss` group for the resource manager, or run as root for `/dev/tpm0`).
* Python 3.11+ (standard library only).
* Optional: `openssl` for certificate summaries.

## Quick start

```sh
python3 -m tpm_re probe --vendor --out out/      # full dossier (JSON + Markdown)
python3 -m tpm_re vendor                         # vendor property space
python3 -m tpm_re caps                           # algorithms, banks, commands
python3 -m tpm_re props                          # TPM_PT fixed + variable
python3 -m tpm_re nv                             # enumerate NV indices
python3 -m tpm_re nv --index 0x01C00002 --head 64
python3 -m tpm_re certs                          # EK certificates
python3 -m tpm_re pcrs --indices 0-7
python3 -m tpm_re acpi                           # host/ACPI inventory
```

### Commands

| command | purpose |
|---|---|
| `probe` | assemble the full dossier; `--vendor` adds the vendor surface |
| `props` | `TPM_PT_FIXED` and `TPM_PT_VAR` properties, decoded |
| `caps` | algorithms, PCR banks, ECC curves, advertised commands |
| `vendor` | read `TPM_CAP_VENDOR_PROPERTY` (0x100), paging included |
| `raw` | send one command; handles/params/auth passed separately |
| `pcrs` | PCR digests labelled by bank and index (pages past 8), optional TCG event-log parse |
| `nv` | list indices, dump one index to a file (`--allow-da` for non-`NO_DA` indices) |
| `certs` | read the RSA/ECC EK certificates from NV |
| `acpi` | DMI, ACPI TPM2 table, kernel TPM config |
| `frames` | decode captured TPM byte streams (hex dump or strace) |
| `carve` | scan vendor images for TPM firmware candidates |
| `fmp` | scan a BIOS image for UEFI FMP capsules and the `TPM FMP H` marker |
| `fetch` | download a firmware/BIOS package and record a `.meta` (URL, size, SHA-256) |
| `sigrok` | convert sigrok SPI annotations into a TPM byte stream for `frames` |
| `memmap` | map a physical address (default: the TPM MMIO base) via `/proc/kcore` |
| `kcore` | scan `/proc/kcore` for NPCT/Nuvoton/TPM firmware markers |
| `vendor-probe` | **gated** — send vendor commands of unknown semantics (`--allow-vendor`) |
| `selftest` | offline sanity checks |

Everything is reachable through this one entry point; there are no separate
helper scripts to run.

### Gated, state-touching probes

The read-only default is enforced, but three investigation paths can change
TPM state and are therefore each behind an explicit flag:

```sh
# send an undocumented vendor command (or sweep all known NPCT vendor codes)
python3 -m tpm_re vendor-probe --allow-vendor --cc 0x20000204
python3 -m tpm_re vendor-probe --allow-vendor

# sample a vendor property over time, correlated with ReadClock
python3 -m tpm_re vendor --sample 0x1 --count 10 --interval 1

# read an NV index with a specific password, or dictionary-attack its auth
python3 -m tpm_re nv --index 0x01802006 --password deadbeef --allow-da
python3 -m tpm_re nv --index 0x01802006 --bruteforce wordlist.txt --allow-da
```

`vendor-probe` refuses to send anything without `--allow-vendor`. The NV
password and brute-force paths refuse without `--allow-da`, because every
failed auth on an index lacking `TPMA_NV_NO_DA` increments the
dictionary-attack lockout counter and can lock the TPM. A `--bruteforce -`
uses the built-in wordlist; a file has one password per line (`hex:DEADBEEF`
for binary auth values).

`raw` example — note that for a session command the handle area and parameter area are separate arguments, because the wire layout is `handles | authorizationSize + auth | parameters`:

```sh
python3 -m tpm_re raw --cc 0x14e \
    --handles 0x01C00002,0x01C00002 \
    --body 0x00400000 --password
```

## Decoding captures

```sh
python3 -m tpm_re frames capture.hex          # hexdump-style text
python3 -m tpm_re frames --strace capture.trace
```

With `--strace` the syscall direction decides the role (write = command, read = response). For other input, `frames` are classified by structure and code plausibility, never by machine state; a code that is both a command code and a response code (e.g. `0x14C`, `GetTime` / `TPM_RC_NV_DEFINED`) is settled by command/response alternation. Unknown command codes are shown as raw values.

For a hardware SPI capture, turn sigrok-cli annotations into a byte stream first:

```sh
sigrok-cli -i capture.sr -P spi:cs=D0:clk=D1:mosi=D2:miso=D3 \
    -A spi=mosi:miso > annotations.txt
python3 -m tpm_re sigrok annotations.txt --direction mosi -o command.bin
python3 -m tpm_re frames command.bin
```

## Design notes

* **Wire first.** `wire.py` owns marshalling, session auth areas, response parsing and `TPM_RC` decoding. The layout comments there are the spec reference for the rest of the package.
* **Evidence over guesses.** Unknown constants, vendor properties and vendor command codes stay raw and are labelled as unknown.
* **Fail visibly.** A malformed response raises `WireError` with the offset and the actual length instead of yielding a plausible-looking value.
* **Read-only by default.** The CLI's allowlist is the enforcement point.

Two wire-format details cost real debugging time and are worth repeating:

1. A `GetCapability` response is `moreData(1) | capability(4) | union`. Skipping the echoed `capability` shifts every parsed entry by four bytes.
2. In a *command* with sessions the order is `handles | authorizationSize | auth structures | parameters`. `authorizationSize` is the byte length of the auth structures only. Our first attempt put parameters before the auth area and got `TPM_RC_SIZE` (0x095) for every `NV_Read`.
3. Integers in the ACPI `TPM2` table and in the TCG event log are **little-endian**; only the TPM command stream is big-endian.
4. A vendor command code keeps the `TPMA_CC.V` bit: the wire code is `0x2000xxxx`, not the 16-bit `commandIndex` alone.

## Tests

```sh
python3 -m unittest discover -s tests -t .
```

The suite is offline: it uses fake transports and synthetic buffers, so it can run without a TPM. Live checks are the CLI commands above.

## Consolidation note

Earlier iterations left a scatter of one-off helper scripts under `tools/`,
`tools/opencode/` and `knowledge/tools/`. They have all been folded into the
single `tpm-re` CLI:

| old script(s) | now |
|---|---|
| `find_fmp.py`, `opencode/parse_fmp.py` | `tpm-re fmp` (module `tpm_re/firmware.py`) |
| `lenovo_bios_fetch.sh` | `tpm-re fetch` (module `tpm_re/firmware.py`) |
| `sigrok_to_frames.py` | `tpm-re sigrok` (module `tpm_re/sigrok.py`) |
| `knowledge/tools/memmap.py` | `tpm-re memmap` (module `tpm_re/hostmem.py`) |
| `knowledge/tools/scan_kcore.py` | `tpm-re kcore` (module `tpm_re/hostmem.py`) |
| `tpm2_acpi.py` | already covered by `tpm-re acpi` (removed) |
| `opencode/probe_*`, `test_auth.py`, `sample_vendor_prop.py`, … | `tpm-re vendor-probe`, `vendor --sample`, `nv --password/--bruteforce` (module `tpm_re/vendor_probe.py`) |

The experiment scripts had hard-coded paths and sent undocumented vendor
commands and brute-forced NV auth inline; the folded-in versions take their
targets as arguments and sit behind the `--allow-vendor` / `--allow-da` gates
described above. There are no standalone scripts left to run.

## Roadmap

1. Acquire the Lenovo BIOS/EC update for this machine (`tpm-re fetch`), scan it for the FMP capsule (`tpm-re fmp` / `tpm-re carve`), extract the NPCT75x firmware payload, and analyse it with REA, an external tool that is not part of this repository (`inspect_firmware_regions`, `inspect_binary_layout`).
2. ~~Characterise the vendor surface.~~ Done: properties `0x0..0x2` and the nine vendor codes `0x20000200..0x20000216` are enumerated; `0x20000213` is sourced from wolfTPM as `NTC2_GetConfig`, and no command reads firmware (§4.2 and §9 of the knowledge file).
3. Optional hardware path: a physical chip programmer, vendor JTAG port or fault-injection setup. SPI/I²C bus capture only observes commands and cannot read the on-chip flash; no such hardware is currently available.

## Field notes

See [`knowledge/NPCT75x.md`](knowledge/NPCT75x.md) for detailed observations.

## Open issues

1. What do vendor properties `0x0..0x2` mean?
2. What do vendor commands `0x20000200..0x20000216` do? Which are read-only?
3. Where does the TPM get its firmware? Candidate: the ThinkCentre M75q Gen 2 Flash BIOS Update (`ds547344`, BIOS `M47KT33A`). Support page blocks plain fetches; a direct `download.lenovo.com` URL needs verification.
4. Why is the BIOS measurement log empty?
5. Does `FIRMWARE_VERSION_2` combine with version 1 into a four-part version?

---

*Last updated: 2026-11-20*
