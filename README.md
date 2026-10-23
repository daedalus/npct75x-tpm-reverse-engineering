# tpm_re — read-only TPM 2.0 reverse-engineering toolkit

`tpm_re` talks straight to `/dev/tpmrm0` and marshals TPM 2.0 commands
itself. There is no `tpm2-tools` dependency, so every byte on the wire is
visible, explainable, and patchable. The only external tool used is
`openssl`, and only to summarise X.509 EK certificates.

The toolkit was written while reverse engineering the discrete TPM in a
Lenovo ThinkCentre M75q Gen 2 (Nuvoton **NPCT75x**, firmware **7.2**). The
observed facts and the open questions live in
[`knowledge/NPCT75x.md`](knowledge/NPCT75x.md).

## Safety model

* Every command goes through an explicit read-only allowlist.
* State-changing commands are refused unless `--allow-write` is passed.
* `raw` refuses non-allowlisted command codes before opening the device.
* Vendor commands are **listed but never sent**: their semantics are unknown.
* Nothing in this toolkit writes NV, changes auth, starts sessions, or
  enters firmware-update mode.

## Requirements

* Linux with a TPM 2.0 character device (`/dev/tpmrm0`; the user must be in
  the `tss` group for the resource manager, or run as root for `/dev/tpm0`).
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
| --- | --- |
| `probe` | assemble the full dossier; `--vendor` adds the vendor surface |
| `props` | `TPM_PT_FIXED` and `TPM_PT_VAR` properties, decoded |
| `caps` | algorithms, PCR banks, ECC curves, advertised commands |
| `vendor` | read `TPM_CAP_VENDOR_PROPERTY` (0x100), paging included |
| `raw` | send one command; handles/params/auth passed separately |
| `pcrs` | PCR digests, optional TCG event-log parse |
| `nv` | list indices, dump one index to a file |
| `certs` | read the RSA/ECC EK certificates from NV |
| `acpi` | DMI, ACPI TPM2 table, kernel TPM config |
| `frames` | decode captured TPM byte streams (hex dump or strace) |
| `carve` | scan vendor images for TPM firmware candidates |
| `selftest` | offline sanity checks |

`raw` example — note that for a session command the handle area and
parameter area are separate arguments, because the wire layout is
`handles | authorizationSize + auth | parameters`:

```sh
python3 -m tpm_re raw --cc 0x14e \
    --handles 0x01C00002,0x01C00002 \
    --body 0x00400000 --password
```

### Decoding captures

```sh
python3 -m tpm_re frames capture.hex          # hexdump-style text
python3 -m tpm_re frames --strace capture.trace
```

Both command and response frames are classified by structure and command
code plausibility, never by machine state. Unknown command codes are shown
as raw values.

## Design notes

* **Wire first.** `wire.py` owns marshalling, session auth areas, response
  parsing and `TPM_RC` decoding. The layout comments there are the spec
  reference for the rest of the package.
* **Evidence over guesses.** Unknown constants, vendor properties and
  vendor command codes stay raw and are labelled as unknown.
* **Fail visibly.** A malformed response raises `WireError` with the offset
  and the actual length instead of yielding a plausible-looking value.
* **Read-only by default.** The CLI's allowlist is the enforcement point.

Two wire-format details cost real debugging time and are worth repeating:

1. A `GetCapability` response is `moreData(1) | capability(4) | union`.
   Skipping the echoed `capability` shifts every parsed entry by four bytes.
2. In a *command* with sessions the order is
   `handles | authorizationSize | auth structures | parameters`.
   `authorizationSize` is the byte length of the auth structures only.
   Our first attempt put parameters before the auth area and got
   `TPM_RC_SIZE` (0x095) for every `NV_Read`.

## Tests

```sh
python3 -m unittest discover -s tests -t .
```

The suite is offline: it uses fake transports and synthetic buffers, so it
can run without a TPM. Live checks are the CLI commands above.

## Roadmap

1. Acquire the Lenovo BIOS/EC update for this machine, extract the NPCT75x
   firmware payload, and analyse it with REA (`inspect_firmware_regions`,
   `inspect_binary_layout`).
2. Characterise the vendor surface: properties `0x0..0x2` and the nine
   vendor command codes. Read-only probes only after their semantics are
   sourced from documentation.
3. Optional hardware path: SPI capture between the PCH and the TPM, then
   `tools/sigrok_to_frames.py` to turn MOSI/MISO bytes into frames.
