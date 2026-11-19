# tpm_re — read-only TPM 2.0 reverse-engineering toolkit

`tpm_re` talks straight to `/dev/tpmrm0` and marshals TPM 2.0 commands itself. There is no `tpm2-tools` dependency, so every byte on the wire is visible, explainable, and patchable. The only external tool used is `openssl`, and only to summarise X.509 EK certificates.

The toolkit was written while reverse engineering the discrete TPM in a Lenovo ThinkCentre M75q Gen 2 (Nuvoton **NPCT75x**, firmware **7.2**). The observed facts and the open questions live in [`knowledge/NPCT75x.md`](knowledge/NPCT75x.md).

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
| `selftest` | offline sanity checks |

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

## Roadmap

1. Acquire the Lenovo BIOS/EC update for this machine, extract the NPCT75x firmware payload, and analyse it with REA, an external tool that is not part of this repository (`inspect_firmware_regions`, `inspect_binary_layout`).
2. Characterise the vendor surface: properties `0x0..0x2` and the nine vendor command codes (`0x20000200..0x20000216`). Read-only probes only after their semantics are sourced from documentation.
3. Optional hardware path: SPI capture between the PCH and the TPM, then `tools/sigrok_to_frames.py` to turn MOSI/MISO bytes into frames.

## Generated tools (from `/tmp/opencode/`)

These scripts were extracted during the investigation and placed under `tools/opencode/`:

- `continue_probing.py`
- `deep_probe.py`
- `long_sample.py`
- `parse_fmp.py`
- `probe_all.py`
- `probe_deep2.py`
- `probe_state.py`
- `probe_successful_vendors.py`
- `probe_vendor2.py`
- `probe_vendor_cmds.py`
- `probe_vendor_deep.py`
- `sample_vendor_prop.py`
- `test_auth.py`
- `test_raw_auth.py`
- `test_remaining.py`

Plus core toolkit files:
- `find_fmp.py` — scans BIOS image for FMP ("TPM FMP H") signatures
- `tpm2_acpi.py` — parses the TPM2 ACPI table
- `sigrok_to_frames.py` — converts SPI frame traffic into frames
- `lenovo_bios_fetch.sh` — downloads the Lenovo BIOS/EFI package
- `memmap.py` — maps physical TPM addresses via `/proc/kcore` program headers
- `scan_kcore.py` — scans `/proc/kcore` chunks for NPCT/Nuvoton/TPM firmware signatures

All files are ready for commit. The firmware extraction itself remains blocked until hardware access (SPI dump) or vendor documentation is available.

## Field notes

See [`knowledge/NPCT75x.md`](knowledge/NPCT75x.md) for detailed observations.

## Open issues

1. What do vendor properties `0x0..0x2` mean?
2. What do vendor commands `0x20000200..0x20000216` do? Which are read-only?
3. Where does the TPM get its firmware? Candidate: the ThinkCentre M75q Gen 2 Flash BIOS Update (`ds547344`, BIOS `M47KT33A`). Support page blocks plain fetches; a direct `download.lenovo.com` URL needs verification.
4. Why is the BIOS measurement log empty?
5. Does `FIRMWARE_VERSION_2` combine with version 1 into a four-part version?

## Tests

Run the test suite:

```sh
python3 -m unittest discover -s tests -t .
```

## Roadmap items

- [ ] Obtain sudo passwordless access (currently requires password) to read `/dev/mem` for physical memory dumps.
- [ ] Hardware SPI capture (Bus Pirate / logic analyzer) to dump TPM chip flash.
- [ ] Fetch Lenovo NPCT75x TPM firmware update package from support site.

---

*Last updated: 2026-11-19*
