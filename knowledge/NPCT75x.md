# NPCT75x — field notes

Target: the discrete TPM 2.0 on a Lenovo ThinkCentre M75q Gen 2
(`11JQSASC00`, board `32E4`, BIOS `M47KT33A` dated 2023-11-29).
Host OS during collection: Debian 13, kernel `6.12.95+deb13-amd64`,
Secure Boot disabled, lockdown `[none] integrity confidentiality`.

Everything below is labelled as one of:

* **Observed** — returned by the device or read from sysfs/DMI.
* **Derived** — a direct consequence of an observation plus a published
  encoding rule.
* **Hypothesis** — a working guess, with the evidence that suggests it.
* **Unknown** — not established; do not treat as fact.

---

## 1. Identity

**Observed** (`GET_CAPABILITY(TPM_CAP_TPM_PROPERTIES)` + `ReadClock`):

| property | value |
| --- | --- |
| family indicator | `0x322E3000` → `"2.0\0"` |
| level | `0` |
| revision | `0x8A` → spec 1.38 |
| day/year | `0x12F` / `0x7E3` (303 / 2019) |
| manufacturer | `0x4E544300` → `"NTC\0"` (Nuvoton) |
| vendor string 1–4 | `"NPCT"`, `"75x\0"`, `"\"!!4"`, `"rls\0"` |
| vendor TPM type | `0` |
| firmware version 1 | `0x00070002` |
| firmware version 2 | `0x00020000` |
| input buffer | 1024 |
| max command / response | 2048 / 2048 |
| PCR count | 24 |
| max digest | 48 (SHA-384) |
| NV index max | 2048 |
| NV buffer max | 1024 |
| total / library / vendor commands | 113 / 104 / 9 |
| permanent flags | `tpmGeneratedEPS` (`0x400`) |
| startup clear | `phEnable, shEnable, ehEnable, phEnableNV` (`0x0F`) |

**Derived**: the EK certificate SAN carries
`tcg-at-tpmManufacturer=id:4E544300`, `tcg-at-tpmModel=NPCT75x`,
`tcg-at-tpmVersion=id:00070002`. The version value matches
`FIRMWARE_VERSION_1`, and the spec recommends major in the high 16 bits and
minor in the low 16 bits, so **7.2**. `FIRMWARE_VERSION_2` = `0x00020000`
is vendor-defined; `2.0` is the raw major.minor reading, and whether it
composes with `7.2` into a four-part version is **unknown**.

**Observed** (`TPM2_ReadClock`): one sample gave `time` = 53,251,633,034 ms,
`clock` = 53,339,945,806 ms, `resetCount` = 135, `restartCount` = 0,
`safe` = 1. Time/clock advance at ~1 ms/ms. `resetCount` is cumulative
across power cycles.

---

## 2. Interface

**Observed**:

* ACPI device `MSFT0101:00` → `/sys/devices/platform/MSFT0101:00` →
  `/dev/tpm0`; driver `tpm_tis` (TIS/FIFO, *not* CRB).
* `/dev/tpmrm0` is usable as a normal user in group `tss`.
* sysfs PCR bank directories: `pcr-sha1`, `pcr-sha256`; no `pcr-sha384`.
* `CONFIG_TCG_TPM2_HMAC` is **not** set in the running kernel.
* `/sys/kernel/security/tpm0/binary_bios_measurements` exists, is readable,
  and is **0 bytes** — no measured-boot event log is exposed.
* `/sys/firmware/acpi/tables/TPM2` is root-only; without `sudo` the toolkit
  reports that instead of guessing the start method.

**Open**: firmware-update mode has **not** been entered and will not be
entered without an explicit decision. The vendor commands
(`0x20000200..`) are the likely control path, but nothing is sent yet.

---

## 3. PCRs and NV

**Observed** (`PCR_Read`, one boot):

* update counter `238`
* SHA-256 PCR[0] `542a3ee043bfa39befa63df6c3f4848654aedd9f61cda9ff05ad6ee391168d95`
* SHA-256 PCR[4] `7bd2e701605ccc1c150eb45ddebdf447a05a6482ab251f35e95979b12afc0aec`
* SHA-256 PCR[7] `56a8e45a395cd1707f402948a6c9c5e39eb8759b2e65fbced1b786ba4f872f2c`
* SHA-1 PCR[0] `4bda354b8b6908639e17939e4ac2f775f7180e73`

**Observed** NV indices:

| index | size | attributes | content |
| --- | --- | --- | --- |
| `0x01C00002` | 861 | `0x620F1408` | RSA EK certificate (DER) |
| `0x01C0000A` | 659 | `0x620F1408` | ECC EK certificate (DER) |
| `0x01802006` | 16 | `0x62050005` | platform NV, 16 bytes, contents were not interpreted |

Attribute flags for the EK indices: `POLICYWRITE, POLICY_DELETE, WRITEALL,
PPREAD, OWNERREAD, AUTHREAD, POLICYREAD, NO_DA, WRITTEN, PLATFORMCREATE`.
For `0x01802006`: `PPWRITE, AUTHWRITE, PPREAD, AUTHREAD, NO_DA, WRITTEN,
PLATFORMCREATE`.

**Observed**: both EK certificates read with an empty password session. The
index auth value is empty and `TPM_RS_PW` is accepted. Reads are 64-byte
chunks under the 1024-byte `NV_BUFFER_MAX`.

Certificate summary (`openssl x509`):

| index | SHA-256 | subject | issuer | validity |
| --- | --- | --- | --- | --- |
| `0x01C00002` | `4f05a5c51b8511c8da41e0cf790eebe76e3c8834df7d8f790dafcd3cb1ee57ff` | empty | `CN=NPCTxxx ECC384 LeafCA 022110, O=Nuvoton Technology Corporation, C=TW` | 2023-10-08 → 2043-10-08 |
| `0x01C0000A` | `1449381eec39287ef3089b337949db28ed8012ce23a9d7285c304c1b0ad99de5` | empty | same | same |

Both have a critical SAN of type `DirName` with the TPM manufacturer/model/
version attributes above. Key usage: RSA cert = key encipherment, ECC cert =
key agreement. Empty subject plus critical SAN is normal for TPM EK certs.

---

## 4. Vendor surface

### 4.1 Vendor properties — **real, and easy to miss**

The specified capability is `TPM_CAP_VENDOR_PROPERTY = 0x100`. The initial
scan used capability values `0x00..0x0F` and found nothing meaningful,
because those capabilities ignore the property field. Probing `0x100` with
starting property `0` returns **three** properties:

| property | observed value | behaviour |
| --- | --- | --- |
| `0x00000000` | `0x00000000` | static |
| `0x00000001` | `0x001AD0A0` … `0x001AD0A6` across samples | not wall-clock: static over a 15 s gap and over 50 s, then `+2` between two samples 5 s apart, after about 55 s of the session. Slowly and irregularly incrementing. |
| `0x00000002` | `0x00004BF0` (19,440) | static across all samples |

Paging is well-formed: asking for property `0` returns `0,1,2`; asking for
`1` returns `1,2`; asking for `2` returns `2`; asking for `3` (or `0x10`,
`0x100`, `0x1000`, `0x20000000`) returns an empty list with `moreData = 0`.
So the vendor property space on this chip is exactly `0x0..0x2`.

**Hypothesis**: property 1 is a coarse internal counter/timestamp, not a
command counter (1, 2 and 10 `GetRandom` calls produced no change) and not
TPM time in milliseconds. The increment is too irregular to pin down from
two samples; a longer sampling run with `ReadClock` alongside it would
settle it. The meaning of properties 0 and 2 is **unknown**; `0x4BF0` looks
bitmask-like but that is not evidence.

### 4.2 Vendor commands — **listed, not called**

`TPM_PT_VENDOR_COMMANDS` says 9. `GET_CAPABILITY(TPM_CAP_COMMANDS)` lists
exactly nine entries with the `TPMA_CC.V` bit set. Their `commandIndex`
values (bits 15:0) are `0x200..0x216`; **Derived**: the command code on the
wire carries the V bit (bit 29), so the codes are:

```
0x20000200  0x20000201  0x20000202  0x20000203  0x20000204
0x20000211  0x20000213  0x20000214  0x20000216
```

Earlier versions of the toolkit dropped the V bit and printed
`0x00000200..`; those bare values are not valid command codes. Vendor codes
have no names in the TPM 2.0 tables, so the toolkit prints them as
`VENDOR_0x2000xxxx`. Sending them is gated behind `--allow-write`; the
read-only subset has been characterised live, and the update path is
**still never exercised** (see §7.2 for why `0x20000202` is permanently
banned).

### 4.3 Vendor-command semantics from the Nuvoton DevCap driver (static)

Disassembling the UEFI boot-service driver embedded in the Nuvoton firmware
package (§7.2, `NuvotonTpmDevCap.BIN` at file offset `0x118`) resolves part of
the vendor surface. The driver builds TPM commands as byte arrays with
**big-endian** command codes and calls a common sender at VA `0x23c0`:

* **VA `0x1427`** builds `80 01 00 00 00 0a 20 00 02 13` — a 10-byte,
  no-handle, no-parameter **`0x20000213`** command. After the send it
  byte-swaps the response code (masks `0xff0000`/`0xff00`) and requires it to
  be zero, then requires the **last byte of the response to be `0xAA`**
  (`cmp BYTE PTR [rsp+rax+0x40],0xaa` at VA `0x14e7`). Our previously probed
  live response, `ffffa700fbff7ffffbfffffffbf0ffffaaaa` (18 bytes), ends in
  `aa aa`, matching the driver's validation exactly. This is strong evidence
  that `0x20000213` is a read-only firmware/state query and that we decoded
  its response format correctly.
* **VA `0x3644`** builds a session-tagged command with CC big-endian
  `0x20000200`, handle `0x4000000C`, a session area whose 4-byte size is
  computed at runtime, and the 32-bit value `0x40000009` in the session area.
  The size field is patched from `authSize + payloadLen + 8`. This matches the
  live observation that `0x20000200` requires a handle and a session.
* Other commands in the same driver use `0x0000012E` and `0x0000017A`
  (`GetCapability`) with the same handle `0x4000000C`, confirming that this NV
  index is central to the firmware-update flow.
* The driver's error strings name failure modes we observed live:
  `Bad vendor code tag`, `Bad vendor code version`, `Bad vendor operation
  tag`, `Invalid source version`, `Blocked by TPM FW policy`, `Deferred
  Physical Presence Failed`, `Authorization failed`, `Target FW is already
  installed`.

None of this authorises sending the state-changing commands: `0x20000202`
with 16 parameter bytes already wedged the chip once (§6.1).

---

## 5. Wire-format lessons (these were real bugs)

### 5.1 GetCapability echoes the capability

```
response params = moreData(1) | capability(4) | TPML(count + entries)
```

Skipping the 4-byte echo shifts every entry. Symptom: property keys appeared
as `{0x0a: 0x100, 0x322e3000: 0x101, ...}` — i.e. each value landed in the
key of the next pair. With the echo consumed, `GetCapability(TPM_CAP_TPM_PROPERTIES,
0x100, 0x40)` returned 46 properties (`0x100..0x12D`) and
`NV_BUFFER_MAX = 1024`, matching `tpm2_getcap`.

### 5.2 Commands put authorization before parameters

```
command = tag(2) size(4) cc(4) handles(authArea) parameters
authArea = authorizationSize(4) + TPMS_AUTH_COMMAND[...]
```

`authorizationSize` is the **byte length of the auth structures only** — not
a session count and not including itself. One empty password session is
9 bytes, so the field is `0x00000009` and the whole auth area is 13 bytes.

The first implementation placed parameters before the auth area (the
response layout) and every `NV_Read` returned `TPM_RC_SIZE` (0x095). The
fix was confirmed two ways: by replaying the byte layout observed in
`strace` of `tpm2_nvread`, and by the spec line that the command
authorization area sits between the handle area and the parameter area.
Responses keep the other order: `paramSize | params | authArea`.

Minimal working `NV_Read` (35 bytes):

```
8002 00000023 0000014e
01c00002 01c00002
00000009 40000009 0000 01 0000
0040 0000
```

### 5.3 Other traps

* `TPML_CCA` entries are 4-byte `TPMA_CC` values (`commandIndex` in bits
  0–15, vendor flag `V` in bit 29), not 8-byte `{cc, attrs}` pairs. The
  command code is `commandIndex | V << 29`. Reading 8 bytes per entry fails on the first
  page boundary with an "offset 260, have 0" error.
* `GetCapability(TPM_CAP_ALGS)` can return `moreData = 1` when the requested
  count is exactly the number of returned entries. Use a large count and
  page if needed.
* For `TPM_CAP_COMMANDS`, the property argument is the *starting command
  code*, so paging advances to `last_cc + 1`.
* The ACPI `TPM2` table and the TCG event log are little-endian. Parsing
  them big-endian turns start method `6` into `0x06000000`.
* `PCR_Read` returns at most eight digests per call; label each digest
  from the returned `pcrSelectionOut` and repeat for the rest.

Cross-checks used during development:

```sh
export TPM2TOOLS_TCTI=device:/dev/tpmrm0
tpm2_getcap properties-fixed
tpm2_getcap algorithms
tpm2_getcap commands
tpm2_nvreadpublic
tpm2_nvread 0x01c00002 -s 64 -o /tmp/ek-head.bin
strace -f -xx -s 256 -e trace=write,read tpm2_nvread 0x01c00002 -s 64 -o /dev/null
```

`tpm2-tools` 5.7 here rejects `properties-vendor`; `python3 -m tpm_re vendor`
is the working path for the vendor property space.

---

## 6. AMI TPM FMP driver — NV `0x01802006` auth value (from Ghidra)

**Derived (statically proven)** from the AMI TPM Firmware Management driver
loaded in Ghidra as `section1.pe` (`TpmFmpUefiDrv_*` functions). This DXE driver
is what *creates* NV index `0x01802006` on this platform, so its code is
authoritative for the index auth value that live probing could not recover.

The chain in `TpmFmpUefiDrv_nv_init`:

1. `gBS->CopyMem` copies 26 bytes (`0x1a`) from `u_NovemberRain_000093a8`
   (`0x93a8`) into a local buffer. Those bytes are **UTF-16LE
   `"NovemberRain\0"`**: `4e006f00760065006d006200650072005200610069006e000000`.
   (`NovemberRain` is the UEFI variable name; there are also
   `TpmFwUpdMode` and `TpmFwUpdRollNonce` variables nearby.)
2. It enumerates NV indices (`FUN_00007020`) and, for `0x1802006`, calls
   `TpmFmpUefiDrv_version_payload(puVar3, local_858, 0x1a, ...)`.
3. When defining the index it calls `FUN_00008674(1, &buf, &len, out)` — a
   plain **SHA-256** (the standard IV `6a09e667 bb67ae85 3c6ef372 a54ff53a
   510e527f 9b05688c 1f83d9ab 5be0cd19` is visible in the function) over the
   26-byte buffer, producing a 32-byte digest.
4. That 32-byte digest is used as the `authValue` in `NV_DefineSpace`
   (`TpmFmpUefiDrv_nv_init_data`, attrs `0x42050005`, nameAlg `0xb`=SHA256,
   index `0x1802006`). Confirmed in x86-64 disassembly at `0x3571–0x35ae`.

Therefore the **NV `0x01802006` auth value** is:

```
SHA256( UTF-16LE("NovemberRain") || 00 00 )
= 4a2a5d8442d17e746f46ed1d990ee2213250e04005bbded804565ecfdab0afdf
```

`FUN_0000630c` / `FUN_00005a6c` implement **HMAC-SHA256** (ipad `0x36`, opad
`0x5c`) with this digest as the HMAC key, used to authorize the NV_Read of the
version payload. This explains why every empty/common-password attempt failed.

**Status**: statically proven **and live-confirmed on 2026-11-19**. After the
TPM hardware was restored, `NV_Read 0x01802006` with the 32-byte digest as
`TPM_RS_PW` succeeded and returned 16 bytes (`00` × 16); an empty password in
the same session still returned `0x9A2 BAD_AUTH`. This closes open question 0.

### 6.1 Non-reboot recovery attempts (2026-11-19)

With explicit authorization to reset the TPM but not reboot the platform:

* `/dev/tpm*` is absent. `tpm_tis` is **built into the kernel**
  (`CONFIG_TCG_TIS=y`), so `modprobe -r tpm_tis` reports "Module tpm_tis is
  builtin" and there is no module to reload.
* A sysfs rebind (`echo MSFT0101:00 > /sys/bus/platform/drivers/tpm_tis/bind`)
  fails with `EIO`; the probe returns `-ENODEV` because the silicon never
  answers. No new TPM lines appear in `dmesg`.
* S3 suspend/resume (RTC-alarm wake, `mem_sleep = s2idle [deep]`) completed
  cleanly but created no TPM device; a post-resume bind failed the same way.
* TPM MMIO at `0xfed40000` still reads `ffffffff` for `ACCESS` (`+0x00`),
  `STS` (`+0x18`) and `DID_VID` (`+0xf00`).
* The DSDT exposes `\_SB_.TPM_._DSM` with a PPI-style function 2 that forwards
  an operation byte through an SMI, and function 4 returning `TRST=2`. PPI
  operations are applied at the next platform boot, and guessing the op code
  could select "TPM Clear", so it was not invoked.

**2026-11-19 post-mortem:** a full warm reboot and then a true cold power
cycle (RTC-alarm shutdown, ~150 s off, automatic power-on) were both
authorized and performed. Neither recovered the chip. After *both* cycles
`/dev/tpm*` is absent, the `TPM2` ACPI table is gone, `\_SB_.TPM_` is now
enumerated as `PNP0C31:00` ("TPM 1.2 Device") with `_STA = 0` (disabled), and
MMIO at `0xfed40000` still reads `ffffffff` for `ACCESS`, `STS` and `DID_VID`.
UEFI TPM configuration variables (`TpmServFlags`, `OldTPM20FlagData`,
`TpmDefaultSetting`, `TPMPERBIOSFLAGS`) are byte-for-byte unchanged, so the
firmware is disabling the device because the silicon never answers, not
because a setting changed.

Conclusion at the time: the `0x20000202` probe with 16 zero-byte parameters
appeared to wedge this NPCT75x permanently; no software-level or
platform-level reset recovered it. **Update:** the TPM hardware was later
restored externally (2026-11-19), `/dev/tpm0` and the `MSFT0101:00` device
returned, and the NV auth was successfully validated live (see above). The
recovery attempts above remain recorded as failed on that occasion.

---

## 7. AMI TPM FMP driver — structure (from Ghidra)

Decompiling `section1.pe` shows the DXE is both an FMP **device** (reports the
TPM version) and an FMP **update client** (accepts `AMI ` capsules and
dispatches them to several backends). It still carries no firmware image of
its own.

**Correction to an earlier note**: the data at `0x8c80`/`0x8c88` is *not* the
FMP GUID — it is the vendor GUID used for the `TpmFmp*` UEFI variables
(`41ac299a-ce34-418c-86c3-600be599794f`). `TpmFmpUefiDrv_main_install`
installs the FMP protocol with GUID **`86c77a67-0b97-4633-a187-49104d0685c7`**
(data at `0x8c40`). The GUID at `0x8be0`,
`e5dd1403-d622-c24e-8488-c71b17f5e802`, is `gEfiHashProtocolGuid`;
`aa40b6f5-0187-4e36-be59-0504efebc417` is `gEfiHashAlgorithmSha256Guid`.
Both are consumed by `TpmFmpUefiDrv_setup_hash`.

FMP device descriptor (UTF-16LE strings in the image, file offset = VA):

| Offset | Value |
|---|---|
| `0x8ce0` | `AMI TPM Firmware Management Update Protocol` |
| `0x8dc0` | `XX.XX.XX.XX` (display-version template) |
| `0x8dd8` | `%02x.%02x.%02x.%02x` (version format string) |

`TpmFmpUefiDrv_main` queries the version twice, allocates a 24-byte (`0x18`)
buffer, calls `TpmFmpUefiDrv_firmware_write(..., 0x18, "%02x...", version)`,
and populates an FMP `EFI_FIRMWARE_IMAGE_DESCRIPTOR` (image size `0x70`,
lowest-supported-version index `0xf`, `Unsigned = 1`).

The misleading names are the trap:

* `TpmFmpUefiDrv_capsule_process` is **not a capsule parser** — it is a
  `SPrint`-style formatter. Its body branches on `%` (`0x25`), `.`, `0`–`9`,
  hex digits `A`–`F`/`a`–`f`, `-`, ` `, `*`, `\n`, `\r`, and tracks width,
  precision and left-align flags. It formats a string into the caller buffer.
* `TpmFmpUefiDrv_firmware_write` therefore **writes no firmware**: it calls
  that formatter to render the TPM version string (`XX.XX.XX.XX`) into the
  24-byte descriptor buffer.
* `TpmFmpUefiDrv_version_payload` reads the 16-byte NV index with `NV_Read`
  (CC `0x14e`), authorizing with the HMAC-SHA256 session key derived in §6,
  and returns up to 16 bytes. This confirms the auth chain from the other
  direction.

Consequences:

* The FMP *descriptor* reports `FIRMWARE_VERSION_1/2` (GetCapability properties
  `0x10B`/`0x10C`) through the UEFI FMP framework, but the driver contains no
  firmware image of its own — so no payload can be carved from it or from the
  BIOS ROM.
* The driver's PE image is embedded in `IMAGEM47.ROM` at file offset
  `0xc0b4a4` (MZ header). A full byte-for-byte match against the extracted
  `section1.pe` fails because extraction applied relocation fixups.
* The standard FMP capsule GUID `6DCBD5ED-E82D-4C44-BDA1-7194199AD92A` does
  **not** occur anywhere in the ROM — reinforcing that no TPM firmware
  capsule is shipped in the BIOS.
* Runtime efivars contain only the generic AMI/Lenovo TPM config variables
  (`TpmServFlags`, `OldTPM20FlagData`, `TpmDefaultSetting`,
  `TPMPERBIOSFLAGS`). None of the driver's own variables (`NovemberRain`,
  `TpmFwUpdMode`, `TpmFwUpdRollNonce`, `TpmFmp*`) are present — consistent
  with those being runtime-only.
* `TpmFwUpdMode` is managed by two small functions using variable GUID
  `ed292d58-1ed2-422f-b685-7bce8c69edf2` (dwords `ed292d58`, `422f1ed2`,
  `ce7b85b6`, `f2ed698c`, built on the stack so it is not a contiguous
  constant in either the PE or the ROM). `FUN_00002be4` deletes it at driver
  init via `SetVariable(name, guid, 0, 0, 0)`. `FUN_00002c30` reads it with
  `GetVariable`, deletes any stale value, then zeroes 17 bytes with
  `FUN_00000320` (a `memset` helper) and writes them back with attributes `3`
  (NV|BS). A present variable is therefore an "update mode active" flag;
  absence means normal operation. The GUID occurs in neither the ROM nor the
  runtime efivars.

### 7.1 FMP capsule format and update backends

`main_install` installs the six-entry protocol table:
`GetImageInfo @0x830`, `GetImage @0x928` (stub returning `EFI_UNSUPPORTED`),
`SetImage @0xa74`, `CheckImage @0x934`, `EraseCapsule @0x928`,
`WriteCapsule @0x928`. The update path is therefore real. Disassembling the
not-auto-defined functions at those addresses (file offset = VA) shows:

* Both `CheckImage` and `SetImage` require the ASCII magic **`AMI `**
  (`0x20494d41`) at offset `0` of the capsule image. `SetImage` reads a version
  dword at `+0x10` and a lowest-supported-version dword at `+0x14`.
* The capsule has a section table of 16-byte descriptors (offset `8`, size `4`,
  type `4`); section types `1` and `2` are recognized. Each section payload is
  tried against a chain of backends until one succeeds:
  `0x1618` → `0x4cc8` → `0x4220` → `0x553c` → `0x3b4c`.
* `FUN_00004220` and `FUN_00003b4c` are both clients of the **same** FMP
  protocol GUID `86c77a67-0b97-4633-a187-49104d0685c7`. The first validates
  via `CheckImage` (protocol slot 3); the second calls `GetImageInfo` (slot 0)
  and requires the image-type GUID at `image+4` to equal
  `41e18891-fb01-4da3-a483-5b05ccbb5767` (built byte-by-byte on the stack, so
  it does not appear as a contiguous constant in the driver). Both show the
  confirmation *"Are you sure want to flash TPM FW. All TPM data will be
  cleared"*, then call `SetImage`. Strings `It might be TPM recovery` /
  `Keep Process?` and `Remaining Updates Count: %04d` belong to this flow.
  A second GUID, `27bc9064-eded-4820-85ce-47ba9b3e4920`, is used for the
  client's UEFI variable access. Neither GUID occurs anywhere in
  `IMAGEM47.ROM`, confirming no matching capsule is shipped in the BIOS.
* Successful/failed updates are recorded in the `TpmFmpLastUpdVersion`
  (`0x8e00`), `TpmFmpVersion` (`0x8da0`), `TpmFmpLowestSupportVersion`
  (`0x8e98`) and `TpmFmpLastUpdState` (`0x8e30`) UEFI variables.

So the mechanism to flash a TPM firmware capsule is present; only the capsule
itself is missing. A Lenovo/Nuvoton TPM firmware update package would supply
it, and its sections can be parsed with the layout above.

That layout is implemented offline as `tpm_re.firmware.scan_ami_capsules()`
and the `python3 -m tpm_re ami FILE [--extract FW.bin] [--json]` command. It
validates the `AMI ` magic, the section-table bounds and the presence of both
required section types, and can carve the type-2 firmware payload. A scan of
`IMAGEM47.ROM` finds zero `AMI ` magic occurrences, as expected.

### 7.2 External Lenovo TPM firmware packages — DevCap format

Two public Lenovo packages were downloaded with `python3 -m tpm_re fetch`
(URL + SHA-256 recorded in the `.meta` sidecars):

| package | URL | SHA-256 |
|---|---|---|
| `nuvoton_tpm_fw_update_v2.0.zip` | `https://download.lenovo.com/pccbbs/thinkcentre_drivers/nuvoton_tpm_fw_update_v2.0.zip` | `0412f9741235c838759726a91554ab361c8553e5b45f26466fed7c286fa3fe4c` |
| `m920_tpm20_7.85.4555.0.zip` | `https://download.lenovo.com/pccbbs/thinkcentre_drivers/tpmfwcapupd_m920_tpm20_7.85.4555.0.zip` | `90c31b7ab4a16d9fc6b669fd4910540f574d76f23cd9d343e6f61b278539ef12` |

The Nuvoton package contains `NuvotonTpmDevCap.BIN` (262,902 bytes,
SHA-256 `a9539285308a878b…`) and the Infineon package contains
`IFX_Tpm2020DevCap.BIN` (717,643 bytes). Both use the **same custom DevCap
container**, not the `AMI ` capsule format:

* header: u32 `1`, GUID `94599413-5c4a-4d67-99a8-6e9b2bb146a2`, u32 total size,
  u32 zero, u32 `total-0x200`, u32 `0x100`, u32 `0x256`, u32 `0x100`,
  u32 `total-0x100`, then zeros to `0x118`;
* a **UEFI boot-service driver PE** at `0x118` (x64, subsystem 11, four
  sections `.text/.xdata/.reloc`) with strings including `Nuvoton TPM Device:`,
  `Nuvoton TPM Firmware Version:`, `Bad vendor code tag`, `Invalid source
  version`, `Blocked by TPM FW policy`, `Deferred Physical Presence Failed`;
* for the Nuvoton BIN, a firmware descriptor at `0x5800`: a version table
  listing source versions `7.2.0.1`, `7.2.0.2`, `7.2.1.0` and target `7.2.2.0`
  (bytes `02 00 07 02 00 01/00 02/01 00` and `02 00 07 02 02 00`), a u64 size
  `0x3A9D6` (240,086), and a 16-byte digest at `0x5850`;
* from `0x5860` to `total-0x100` the data is high-entropy (~7.95 bits/byte),
  i.e. a **signed/encrypted firmware payload** (~240 KB), not plaintext code.

The Nuvoton readme states this package updates `TPM20_7.2.0.1`, `7.2.0.2` and
`7.2.1.0` to `7.2.2.0`, and is intended for M75q-**1** (not our Gen 2). Our live
TPM reports `TPM_PT_FIRMWARE_VERSION_1 = 0x00070002` (7.2), `VENDOR_STRING_1/2
= "NPCT" / "75x"`, so the payload family is at least related. Crucially,
`python3 -m tpm_re ami` finds **zero** `AMI ` capsules in either DevCap BIN or
the extracted UEFI driver, so the §7.1 parser does not apply here.

### 7.3 The payload is a **replayable vendor-command script** — firmware extracted

The region we initially called "high entropy" is not random at all: starting at
file offset **`0x5820`** it is a contiguous sequence of **257 pre-built TPM
2.0 commands**, each with a big-endian `tag|size|commandCode` header. Walking
`size` from command to command consumes exactly `0x3A9D6` bytes and lands on
`0x401F6`, the start of the 256-byte trailing signature/digest. This is the
entire "encrypted" region — it is a **firmware update script**, and the vendor
commands are now unambiguous:

| # | command | size | params | meaning |
|---|---|---|---|---|
| 1 | `0x20000200` | 312 | 302 | **update setup**: version table (7.2.0.1, 7.2.0.2, 7.2.1.0 → 7.2.2.0), 16-byte digest `ba438def602ed63ef53c7dea2538`, target ranges `0x0008A000..0x000C0FFF` |
| 2–4 | `0x20000201` | 18 | 8 | **erase/prepare flash ranges**: `0x0008A000..0x000A1FFF`, `0x000A2000..0x000B9FFF`, `0x000BA000..0x000C0FFF` (225,280 B total) |
| 5–255 | `0x20000202` ×251 | 952 | 942 | **write firmware data**: fixed 16-byte header `0000001c 00000010 00000010 00000010` + 926 bytes of firmware |
| 256 | `0x20000202` | 440 | 430 | final partial chunk: same header + 414 bytes |
| 257 | `0x20000203` | 328 | 318 | **commit/finalize**: starts with version `02 00 07 02 02 00` (7.2.2.0), then per-block digests and a final 256-byte digest |

The `0x20000202` data stream (concatenating the 926/414-byte payloads after
each 16-byte header) is **232,840 bytes**, SHA-256
`6659e5c55beb02bf55ecb818b7cb9288e59e7cd5e4ee6f0254f7e0b37b42ca16`. It is
kept at `out/firmware/npct75x_fw_7.2.2.0.bin` (gitignored) alongside the source
`out/firmware/NuvotonTpmDevCap.BIN` (SHA-256 `a9539285…fbc8baf`). Its byte
entropy is **7.9979 bits/byte** with all 256 byte values near-uniform (counts
808–1401) and no ASCII strings at all, so this is the **encrypted firmware
image as delivered to the TPM** — the TPM decrypts it internally during the
update. The 16-byte digest in the setup command (`ba438def…388e35`) does not
match SHA-256 of the stream, the script, or the setup params, so it likely
covers the plaintext. We now have the exact byte stream, not just a container.

This also explains the `0x20000202` wedge precisely: our probe sent **16 zero
bytes**, while every legitimate call in this script sends **942 bytes** (or
430 for the last chunk). The command is a raw flash write, so a short buffer
left the firmware updater in an invalid state. **Never resend it.**

The commit command `0x20000203` carries 318 bytes of per-block digest data;
the final 256 bytes of the `0x20000200` setup params (offset 302) and the
256-byte file trailer are the signature region. Neither has been verified
against the extracted stream yet.

### 7.4 Chunk framing and known-plaintext attack on the encrypted stream

Dumping the stream (head/tail/mid and single-chunk files under
`out/firmware/analysis/`) exposed structure invisible in a flat hexdump: the
stream contains **257 occurrences of `00 00`** where 232,840 random bytes
would give ~3.6. All 252 of them sit at offset 16 of a chunk and are the first
two bytes of a big-endian `u32` length:

```
0x20000202 params (942 B):  00 00 00 1c | 00000010 00000010 00000010  (16 B fixed)
                             + 16 B random-looking prefix
                             + u32 BE length = 906 (or 394 for the final chunk)
                             + 906 (or 394) bytes of payload
```

`u32 == len(chunk) - 20` holds for all 252 chunks. Accounting for a further
**10-byte trailer** per chunk gives `251*(926-30) + (414-30) = 225280 =
0x37000`, *exactly* the total of the three `0x20000201` erase ranges. The
framing is therefore 16-byte IV/nonce + 4-byte length + 896-byte ciphertext +
10-byte tag (10 is a legal AES-CCM tag length). All 252 prefixes and all 252
trailers are unique; none chains from the previous chunk by SHA-256, MD5 or
last-16-bytes.

A cleartext attack was run (`out/firmware/analysis/report.txt`, `report2.txt`):

| Attack | Result |
|---|---|
| Repeating-key XOR, periods 1–64 (Hamming + index of coincidence) | No structure: Hamming 3.91–4.05 bits/byte, IC 0.003912–0.003922 everywhere |
| Frequency-derived XOR keys, all 64 periods | Entropy stays 7.9973–7.9990 |
| Known plaintext (zeros, `0xff`, `NPCT75x`, `7.2.2.0`, version bytes, 8051 `LJMP`, ARM SP, gzip, zlib, ELF) | Entropy 7.9990–7.9991 for all; no key shorter than the header survives |
| Repeated 16-byte blocks (ECB oracle) | 14,552 blocks, all 14,552 unique |
| XOR / AES-ECB / AES-CTR with 15,308 keys sliced from setup, commit, script and trailer | Best entropy 7.9365 — random variation, no hit |
| AES-CCM `mac_len=10` and AES-GCM tag verification, 614 `NovemberRain`/setup/commit-derived keys × 7 nonce lengths × AAD variants | 12,280 combinations, **zero** tag-verified decryptions |
| Compression signatures in first 256 bytes | None |

Conclusion: the key is **internal to the TPM** (fuse/ROM-derived), and the
package contains only ciphertext plus a 256-byte signature. The framing is now
fully decoded, but offline decryption is not feasible from this artifact
alone.

---

## 8. NV `0x01802006` access chain — standard TPM commands only

A second decompilation pass mapped every reference to the index. The driver
never sends a vendor CC to reach it; it uses the ordinary TPM 2.0 command
set. Decoded with the CC names in `tpm_re/tables.py` (constants are stored
little-endian in the PE, so e.g. `0x69010000` → wire CC `0x169`):

| Function | CC | Command | Role |
|---|---|---|---|
| `FUN_00005bd4` | `0x169` | `NV_ReadPublic` | Reads the NV public area (nameAlg, attrs, dataSize, authPolicy) before any access |
| `TpmFmpUefiDrv_version_payload` | `0x14E` | `NV_Read` | Reads the 16-byte payload, authorized by the §6 HMAC session |
| `TpmFmpUefiDrv_nv_init` | `0x12A` | `NV_DefineSpace` | Creates the index with attrs `0x42050005`, nameAlg SHA256, size 16 |
| `FUN_00007124` | `0x176` | `StartAuthSession` | Creates the policy session |
| `FUN_0000716c` | `0x151` | `PolicySecret` | Contributes a secret to the policy digest |
| `TpmFmpUefiDrv_data_hash_check` | `0x149` | `PolicyNV` | Compares against the NV payload (`0x10` bytes) |
| `FUN_00006980` | `0x16C` | `PolicyCommandCode` | Limits the session to one command |
| `FUN_00006aec` | `0x189` | `PolicyGetDigest` | Retrieves the resulting policy digest |
| `FUN_00006d34` | `0x12E` | `SetPrimaryPolicy` | Installs the digest as a primary policy |

This matches the driver's debug strings `TPM2SimpleGetPolicyHandleWithPHAuthNull`,
`GetRtTpmFwUpdPolicyHndl` and `Tpm20ResetEmptyPlatformAuth`: the policy chain
is firmware-update authorization, not an obscure vendor protocol. The 16-byte
payload participates in a `PolicyNV` comparison, so it is best understood as
an authorization/anti-rollback value rather than a firmware image.

### 8.1 New vendor command: `0x2000012f`

The earlier statement "no `0x200002xx` vendor command in the driver" remains
true, but the search range was too narrow. A full scan for `0x2000xxxx`
immediates found **`0x2000012f`** twice, both in code:

* `FUN_00003904` (driver init) selects the firmware-update-start command by
  TPM detection: success from `FUN_000047ac` → `0x2000012f`; otherwise
  `0x129` (`HierarchyChangeAuth`) or `0x12f` (`FieldUpgradeStart`).
* The `SetImage` backend at `0x4cc8` passes the same value into
  `FUN_00007b38` / `FUN_00003134`, which build a policy session restricted to
  that command via `PolicyCommandCode` (CC `0x16C`).

So `0x2000012f` is the **vendor counterpart of standard `FieldUpgradeStart`
(`0x12f`)**, used when the driver detects this platform's TPM. It is a
state-changing update-start command — it has not been probed live.

Associated detection/state:

* `FUN_000047ac` reads a TPM capability/property and compares a magic value
  (`0x584649` = ASCII `IFX` in little-endian order) to choose vendor vs.
  standard command; it can also read TPM MMIO at `0xfed40f00`.
* `FUN_000035fc` runs `TpmFmpUefiDrv_data_hash_check` with the chosen command
  code, then stores the resulting 16-byte value in the `TpmFwUpdRollNonce`
  UEFI variable (GUID `f7486a10-4927-0dd3-92d8-7ca3e19ea6b3`). Note this is
  the policy/anti-rollback nonce, distinct from the `NovemberRain` auth seed.

---

## 9. Device-side dump attempts and external cross-checks (2026-11-20)

### 10.1 The vendor command surface is complete — there is no read-back command

**Observed** (`tpm2_getcap commands`, a read-only `GET_CAPABILITY(TPM_CAP_COMMANDS)`
call). Exactly nine entries carry `TPMA_CC.V = 1`:

```
0x20000200  0x20000201  0x20000202  0x20000203  0x20000204
0x20000211  0x20000213  0x20000214  0x20000216
```

`tpm2-getcap` prints the first and sixth as `0x22000200`/`0x22000211`
because its `value` field folds in the `cHandles = 1` attribute; the wire
command codes remain `0x20000200` and `0x20000211`. All nine are already
listed in §4.2. None of them is a firmware/flash read.

**Derived** from wolfTPM v4.2.0 (`wolftpm/tpm2.h`, source cloned and read
offline from `https://github.com/wolfSSL/wolfTPM`):

* `TPM_CC_NTC2_PreConfig = CC_VEND + 0x0211` → `0x20000211` (auth required,
  state-changing, unprobed here).
* `TPM_CC_NTC2_GetConfig = CC_VEND + 0x0213` → `0x20000213` (read-only).

`NTC2_GetConfig` returns an 18-byte `CFG_STRUCT`, not an opaque bitmask. Our
live response `ffffa700fbff7ffffbfffffffbf0ffffaaaa` decodes as:

| field | value | field | value |
| --- | --- | --- | --- |
| `Base0` | `0xff` | `Cfg_D` | `0xff` |
| `Base1` | `0xff` | `Cfg_E` | `0xff` |
| `GpioAltCfg` | `0xa7` | `Cfg_F` | `0xff` |
| `GpioInitValue` | `0x00` | `Cfg_G` | `0xfb` |
| `GpioPullUp` | `0xfb` | `Cfg_H` | `0xf0` |
| `GpioPushPull` | `0xff` | `Cfg_I` | `0xff` |
| `Cfg_A` | `0x7f` | `Cfg_J` | `0xff` |
| `Cfg_B` | `0xff` | `isValid` | `0xaa` |
| `Cfg_C` | `0xfb` | `isLocked` | `0xaa` |

wolfTPM defines `NTC2_CFG_H_SPDM_DISABLE = 0x02`, i.e. SPDM is enabled when
`Cfg_H` bit 1 is **clear**. Our `Cfg_H = 0xf0` therefore indicates SPDM is
already enabled on this chip. That is a configuration observation only — it
does not provide a firmware read path.

The Nuvoton-specific SPDM vendor commands are `GET_PUBK`, `GIVE_PUB`,
`TPM2_CMD`, `GET_STS_` and `SPDMONLY` (wolfSPDM, `src/vendor/spdm_nuvoton.c`).
`TPM2_CMD` merely wraps ordinary TPM commands in an AES-256-GCM encrypted
SPDM session; none of these commands reads firmware.

### 10.2 Public security targets confirm the plaintext never leaves the chip

* 2017 ANSSI ST for FW `7.2.0.1` (same family as our target): *"The Field
  Upgrade process does not expose the FW as plain text and uses
  authentication to verify the integrity and source of the FW."*
* 2026 NPCT7xx ST (rev 1.59, config 1.4.5.5): Booter and Cryplib are in ROM
  and their versions *"can't be changed or obtained by the TOE user"*;
  BootLoader and Upgradeable Software live in on-chip non-volatile memory.
  The internal version is exposed through `TPM_PT_VENDOR_STRING_3` — which
  is exactly why our `"!!4"` value matches wolfTPM's identification string
  `NPCT75x"!!4rls, Fw 7.2`.

**Derived**: the ciphertext we extracted is the *only* firmware
representation available over any host-visible interface. The decrypted
image exists only inside the TPM package.

### 10.3 Host-side read paths tried and ruled out

* `/dev/mem`: passwordless `sudo` is available, but `CONFIG_STRICT_DEVMEM`
  applies. Physical page 0 reads as zeros; the read at `0x100000` fails with
  EPERM. No system RAM or firmware region is reachable.
* `/dev/spidev*`: absent. `/dev/i2c-0..7` exist but are root-only; the only
  enumerated devices are `0x36`/`0x37` (`dummy`) and `0x50` (`ee1004`, DIMM
  SPD). `i2cdetect` is not installed. No TPM firmware path on any I²C bus.
* `/dev/gpiochip0` exists (root-only), but there is no evidence that any GPIO
  is wired to `TPM_RST` on this ThinkCentre — the GPIO-reset instructions in
  wolfTPM are for a Nuvoton daughter board on an SBC. Toggling GPIOs is
  therefore gated and was not attempted.
* EFI variables contain only small TPM flag blobs (10–12 bytes), no capsule
  or firmware image.
* `NV_ReadPublic` lists only three indices (`0x01802006`, `0x01C00002`,
  `0x01C0000A`); none holds firmware.

### 10.4 Further offline crypto dead ends

* The proven NV auth secret
  `4a2a5d8442d17e746f46ed1d990ee2213250e04005bbded804565ecfdab0afdf` and
  all `NovemberRain`/UTF-16LE-derived 16-byte keys were tried as AES keys
  with CCM `mac_len = 10` over seven nonce lengths and two AAD variants —
  zero tag-verified decryptions.
* The 252-byte trailing array in the `0x20000203` commit command has one byte
  per write chunk but entropy `7.16`; using each byte as a per-chunk XOR or
  subtract key leaves chunk entropy at ~`7.79`, so it is not a simple key
  stream.
* Together with §7.4 this closes the practical offline key-recovery search:
  the key is internal to the TPM, and the package contains ciphertext plus
  signature only.

### 10.5 What would actually be needed

A plaintext dump requires physical access to the NPCT75x package: a
SOIC/DFN chip programmer, a vendor JTAG/debug port, or fault injection. None
of those is present. No further host command or offline attack against the
captured package can produce plaintext.

### 10.6 Can the TPM be made to present a JTAG/SPI/I²C debug port?

No — not from the host, by software. Four independent sources agree:

* The FIPS 140-2 policy for NPCT7xx (`140sp3187.pdf`, §3, Table 7) lists only
  SPI bus, PP pin, platform reset and power as physical ports and states
  "The Module does not include a maintenance interface." The FIPS 140-3
  policy for hardware `0x00FC` (`140sp5057.pdf`) lists SPI, I²C, GPIO,
  power management and host interfaces only. The CC security target
  (`st2017.txt`, pp. 14–17) describes 28/32 pins: power/ground, SMBus/I²C,
  SPI, physical presence and GPIO. No JTAG, SWD or test-access port is
  documented in any of them.
* The only host-visible bus on this machine is LPC TIS:
  `/sys/class/tpm/tpm0/device` resolves to `platform/MSFT0101:00` with the
  `tpm_tis` platform driver. There is no `/dev/spidev*` and no TPM on any
  enumerated I²C bus.
* `0x20000211` (`NTC2_PreConfig`) writes the 18-byte `CFG_STRUCT`
  (`Base0`/`Base1` = I²C location, `GpioAltCfg`, `GpioInitValue`,
  `GpioPullUp`, `GpioPushPull`, `Cfg_A`..`Cfg_J`, `isValid`, `isLocked`).
  NPCT75x has only GPIO3 and GPIO4, and wolfTPM §16.2.2 documents them as
  **output-only** (push-pull, open-drain, open-drain with pull-up). There is
  no debug alternate function and no input mode, so the GPIOs cannot become
  a JTAG/SPI/I²C port. The live `Cfg_H=0xf0` already has SPDM enabled and
  `isLocked=0xaa`; the command needs PLATFORM auth and remains gated.
* SPDM (`GET_PUBK`, `GIVE_PUB`, `TPM2_CMD`, `GET_STS_`, `SPDMONLY`) only
  wraps the same TIS commands in AES-256-GCM on the same bus. It adds
  confidentiality, not a new interface. The nine vendor commands are
  update/config/query only; none reads flash, RAM or registers. Loading
  custom debug firmware is blocked by ECDSA-P384 verification of update
  images (FIPS 140-3 §4.5), and Booter/CrypLib are ROM.

Toggling host GPIO4 would only reset the TPM on a Nuvoton SBC daughter
board; there is no evidence it is wired on this ThinkCentre. The debug-port
route therefore reduces to the same physical requirement as §10.5.

### 10.7 Read-only diagnostic surface: `TPM2_GetTestResult`

`tpm2_gettestresult` is the one device-side command we had not exercised.
Live it returns `status: success` plus a 225-byte Nuvoton diagnostic blob
(`aa55 0000 0000 01 fe 01 00 04 00 ...`), mostly a run of big-endian u32
values in `0x29`–`0x34` followed by a short binary tail. Entropy is `2.35`
with 34 distinct byte values — a structured test record, not a memory dump.
No firmware marker, signature or recognizable code. Captured at
`out/firmware/analysis/gettestresult.{bin,hex}`.

### 10.8 Second encrypted image and offline decode attempts

A second Lenovo package was found at
`https://download.lenovo.com/pccbbs/thinkcentre_drivers/nuvoton_tpm_fw_update.zip`
(SHA-256 `a7be7ccf0f65b46ff84c8ecf78b04828aeb6e9e0d9f8b0c8ba094095c8339a6b`).
It targets M725s/M715q Gen 2/M920z/M820z and upgrades `7.2.0.1 → 7.2.0.2`.
Its `NuvotonTpmDevCap.BIN` (271,586 bytes, SHA-256
`642eda01e0fa50a6c68d4fc6ffc72a93933ecbb6c02e0cc52a354c3b3b8fc20b`) is the
same DevCap format: 266 commands, 261 `0x20000202` writes, 241,302-byte
firmware stream (SHA-256
`9b696c07015376878820c25b9932386a1ec5c8554c034869bdb59e4be66f2c09`).
Both are preserved under `out/firmware/` and compared by
`tools/fw_cross_version.py`.

FIPS 140-3 policy `140sp5057.pdf` states that `NTC_FIELD_UPGRADE` protects the
input firmware payload with **AES-CTR** and ECDSA signature verification, and
lists separate "Firmware Update Keys (ECC)" and "Firmware Update Keys (AES)"
in the Object Administrator role. The key is installed at manufacturing, not
derived from host-readable material.

Setup-command layout is now pinned down for both packages: version table,
`u32 bloblen = 256`, a 256-byte high-entropy blob (RSA-2048-sized, likely the
manufacturer signature), and an 8-byte erase range. Each `0x20000202` write is
`16B random nonce + BE u32 length + ciphertext + 10B tag`; the tag is
uniformly random (per-byte entropy 7.10–7.28 across 251 samples).

Negative results from this round (all reproducible offline):

* No decompression format is present (zlib/gzip/bzip2/lzma/zstd/xz magic
  scan), and the stream is not a repeating-key XOR (periods 1–64).
* 619 derived keys — `NovemberRain` in ASCII/UTF-16LE/null-terminated/doubled
  forms, the live NV auth SHA-256, GUID/version/commit strings, SHA-256 of
  DevCap regions, all 16-byte DevCap windows, and the setup blob windows —
  produced **zero** AES-CCM/GCM tag verifications and no low-entropy
  CTR/CFB/OFB/CBC/ECB decryptions.
* The 16-byte write header is a constant `0000001c000000100000001000000010`;
  the nonce is the following 16 bytes. No nonce repeats within or between the
  two images, no nonce equals a hash of its ciphertext, and no tag links to
  the next nonce.
* Cross-version exploit conditions are absent: 0 shared nonces, 0 identical
  16-byte ciphertext blocks, 0 shared ciphertext blocks. Both streams have
  entropy ≈7.998 and all sampled blocks unique.
* CRC32/adler32 and obvious HMAC constructions do not reproduce the 10-byte
  tag. Keystream-reuse XOR between chunks is at the random expectation
  (~3.5 zero bytes per 896-byte pair).
* The DXE driver's `NovemberRain` handling (Ghidra `FUN_00003134`,
  `TpmFmpUefiDrv_nv_init`) is NV-auth/policy material only; it does not derive
  a firmware AES key. `TpmFwUpdRollNonce` is a UEFI variable, absent on this
  host.
* The `DevCapWIN.EXE`/`DevCapWINx64.EXE` tools only replay the pre-built
  commands in the BIN; they do not decrypt it.
* No persistent TPM key object exists (`handles-persistent` empty), and the
  standard command inventory has no `TPM2_FirmwareRead` (the `0x122`/`0x124`
  indexes are `NV_UndefineSpace`/`ChangeEPS`).

Conclusion: the payload key is a manufacturing-installed AES key inside the
NPCT75x. With two independently randomized ciphertext images and no reused
nonce or block, there is no offline distinguisher available from the host
artifacts. Plaintext still requires reading the chip's internal flash or
otherwise extracting that key from the silicon.

### 10.9 Two-window sliding XOR differential (2026-11-20)

`tools/fw_slide_xor.py` slides two equal-length windows over the two images
independently: for lag `d = j - i` it compares `A[i:i+W]` with `B[j:j+W]`,
sweeping `i` across every valid offset. This detects a block copied between
versions but shifted by `n` bytes, which a single fixed anchor per lag misses.
A first pass uses FFT cross-correlation of the 256 byte-value indicators to
rank lags by total byte equality; a cumulative-sum sweep then locates the best
window at each candidate lag and re-scores those peaks for Shannon entropy,
zero-byte fraction, index of coincidence and longest constant-byte run.

Two artifacts had to be removed before the result was meaningful:

1. `DevCapScript.firmware` concatenates `nonce(16) || BE length(4) ||
   ciphertext || tag(10)` per chunk. The 4-byte length fields are identical
   across versions at aligned chunk positions, producing false equality at
   lags `0`, `±1` and `±926` (real z 30.9/8.7/35.6 vs permutation-control max
   5.95). The tool now strips nonce, length and tag by default and operates on
   **225,280 / 233,472 bytes of pure ciphertext**; `--raw` retains the framed
   stream for reproducing that artifact.
2. FFT lag indexing was verified against direct comparison at seven lags
   before use (exact match).

Clean-ciphertext result (W=512, 450,561 lags, 201 candidate lags, ~90M windows):

* Total-equality z: mean `0.001`, std `1.001`, max `4.852` — exactly the
  random null (expected max ≈4.7 for this many tests).
* Best window: `11/512` zero XOR bytes (2.15%); random expectation 2/512.
  Entropy `7.55`, IC `0.0041`, longest constant run `2`.
* Longest exact shared byte run between the two ciphertexts: **0 bytes** at
  seed length 8 (random expectation ≈4.45), i.e. no reused keystream block of
  even 8 bytes.

Conclusion: no shifted-block copy, no keystream reuse and no cross-version
plaintext correlate exists in the host artifacts. The earlier "structure" was
entirely the DevCap framing. This closes the sliding-window differential
avenue; it adds no key material.

### 10.10 Unified offline cryptanalysis harness (2026-11-20)

`tools/fw_crypto_harness.py` is the single entry point that reproduces every
offline avenue that has been tried against these images. It runs 14 checks in
four tiers and writes `out/firmware/analysis/harness/harness_report.txt` and
`.json` plus per-tool artifacts. It is strictly offline: no TPM commands and
no firmware-update replay.

* **environment** — inventories `binwalk`, `strings`, `openssl`, `objdump`,
  `gdb`, `z3`, and the Python modules (`numpy`, `scipy`, `pycryptodome`,
  `cryptography`, `capstone`, `elftools`, `asn1crypto`, `matplotlib`,
  `pandas`). Orchestrated tools are pinned to `/usr/bin/python3`, which is the
  interpreter with the full crypto stack (the venv has only numpy).
* **statistical** — byte chi-squared, Shannon entropy, IC, eight bit-plane
  balance z-scores, byte autocorrelation at lags 1–16, bit-level runs test,
  zlib compression ratio, and magic-signature counts scored as Poisson
  collisions (a naive 2-byte-magic scan falsely "finds" zlib/PE in random
  data; requiring z > 5 removes that).
  Results: entropy `7.999176`/`7.999132`, IC `0.003906`/`0.003907`,
  chi-squared `257`/`281` (df 255), all bit z within ±2.8, all autocorrelations
  within ±0.005, runs z `+0.06`/`+0.10`, compression ratio `1.00034`,
  zero above-chance signatures.
* **structural** — nonce counter/128-bit-LCG/hash-chain fit (none across 252
  and 261 nonces), per-tag byte entropy `7.11–7.28` with no `sha256(ct)[:10]`
  relation, framing parse (constant 16-byte header, all nonces unique), and a
  derived-key sweep of **15,718 unique keys** (NovemberRain variants, NV auth,
  setup-blob windows, DevCap header windows, string hashes) with **zero**
  AES-CTR decryptions below entropy 7.5.
* **external** — `binwalk` finds only the embedded PE driver and SHA-256
  constants in the *containers*, nothing in the ciphertext streams; `strings`
  finds no plaintext in the streams; `openssl dgst` records trailer digests.
* **orchestrated** — re-runs `fw_crypto_audit.py`, `fw_cross_version.py` and
  `fw_slide_xor.py` so one command reproduces all three previously separate
  reports.

Verdict: **no exploitable structure in the host artifacts**. This is the
consolidated negative result; the remaining gap is still the manufacturing
AES key inside the NPCT75x, reachable only with physical chip access.

### 10.11 Exhaustive external tools and deep Python modules (2026-11-20)

Two further scripts widen the net beyond the harness.

`tools/fw_tool_sweep.py` — 246 captures across every available external
binary, in several modes each: `file`, `binwalk -B/-A/-E/-I/-e`, `strings`
(lengths 4/6/8, decimal offsets, UTF-16LE and UTF-16BE), `xxd` and `hexdump`
and `od` head/tail, `md5sum`/`sha1sum`/`sha256sum`/`sha512sum`/`cksum`,
11 `openssl dgst` algorithms (MD5 through SM3), `exiftool`, `unzip -l`,
`7z l`, `objdump -x/-d/-s/-p`, `nm`, `readelf`, `gdb -batch`, gzip/bzip2/xz/
zstd integrity tests, and a `z3` SMT-LIB solve of the nonce LCG constraints.
Output: `out/firmware/analysis/sweep/<tool>/<artifact>.txt` plus
`tool_sweep_report.txt`. Results: `binwalk` sees only the embedded PE driver
and SHA-256 constants inside the *containers*, nothing inside the ciphertext
streams; all four decompression tests fail as expected; `z3` returns `unsat`
for a 128-bit LCG fitted to four consecutive nonces, confirming the
algebraic result in §10.10.

`tools/fw_deep_analysis.py` — the full local Python stack:

* `scipy.stats`: chi-squared p=0.45/0.12 (df 255), Spearman(index, byte)
  r≈0 (p>0.87), entropy 7.9992. KS and normality tests reject, but they are
  inapplicable here: KS assumes a continuous distribution and byte values are
  discrete; uniform-discrete data is deliberately non-normal.
* NIST SP 800-22 subset: monobit z −0.95/−1.56, block-frequency chi² 13,953
  over 14,080 blocks and 14,737 over 14,592 blocks (≈1 per block), longest
  run of ones 22/19, serial chi² 1.8/3.4 at m=2 and 3.4/7.5 at m=3 — all
  within acceptance regions.
* `sympy`/`gmpy2`: both setup blobs are 2046–2048-bit composites, not prime;
  gcd is 2; one has small factors 5 and 23, which is the expected frequency
  for random 2048-bit integers, not a key-structure signal.
* `mmh3`/`xxhash`/`blake3`/`hashlib` and HMAC-SHA1/256/384, CRC32 and adler32
  over 15,676 keys: zero matches for any of the 513 ten-byte tags.
* `capstone` disassembly of the embedded UEFI DXE driver's `.text`: 5,752
  decoded instructions with skipdata (the first ~1.4 KB is a high-entropy
  non-code blob, then EDK2 assertion strings around 0x800–0xc00 and real
  x86-64 code from ~0x1000). Zero AES-NI, SHA or PCLMUL instructions — the
  driver is a capsule-dispatch shim, and decryption happens inside the TPM,
  which agrees with the Ghidra result in §7.4. `networkx` byte-transition
  graphs: 63,432/63,680 of 65,536 possible edges, one strongly connected
  component, balanced out-degrees 239–255.
* `torch` next-byte MLP: 0.44% test accuracy versus the 0.3906% random
  baseline (≈0.8σ for 10k test samples) — the stream is not learnable.
* `pycryptodome` AES-ECB/CBC/CFB/OFB/CTR over all 15,676 derived keys: zero
  decryptions with entropy below 7.5.

Every additional tool agrees with the harness verdict: the ciphertext is
indistinguishable from random and no host-derivable key exists. Physical
access to the NPCT75x remains the only path to plaintext.

### 10.12 Firmware-packing scheme, EK surface and framing audit (2026-11-20)

A follow-up pass checked whether the "offline is closed" verdict overlooked a
different firmware-packing scheme or a key-bearing host artifact.

**FIPS 140-3 service table (policy 140sp5171, firmware 7.2.5.1, §4.3):** the
`NTC_FIELD_UPGRADE` service is explicitly `AES CTR` + `ECDSA SigVer`, role
Object Administrator, with *Firmware Update Keys (ECC)* and *Firmware Update
Keys (AES)* both marked `E` (execute). Table 6 stores both as `Flash:Obfuscated`
and zeroises both on `Clear TPM`; the ECC key's "Used With" field names the
AES key and vice versa. The older policy (140sp3187, 7.2.0.x) instead describes
a 2048-bit RSA firmware-update key verifying a SHA-256 signature — consistent
with the 256-byte setup blob being an RSA-2048 signature in our 7.2.2.0/7.2.0.2
packages. Nuvoton's `CryptoTool` (AN_0045) uses ECDH + AES-CFB for NuMicro OTA;
CFB was tested below even though the TPM service table says CTR.

**Live EK surface:** `tpm2_getcap handles-nv-index` returns only
`0x01802006`, `0x1C00002` (RSA EK cert) and `0x1C0000A` (ECC EK cert). Both
certs read with empty auth and are issued by `CN=NPCTxxx ECC384 LeafCA 022110`.
The ECC leaf is P-256, the RSA leaf is 2048-bit; these are endorsement keys,
distinct from the firmware-update keys. There are no persistent or transient
objects, and no EC point (P-256 or P-384) anywhere in the 256-byte setup blob.

**Framing audit:** `tools/fw_reframe.py` makes the per-chunk layout explicit —
16-byte fixed header `00 00 00 1c 00 00 00 10 00 00 00 10 00 00 00 10`,
16-byte random IV, big-endian `len(ct)+10`, ciphertext, 10-byte tag — verified
over 252/252 and 261/261 writes. This does **not** overturn the earlier crypto
results: `fw_deep_analysis._load()` and `fw_crypto_harness` already extract
`cmd.params[36:-10]`; `DevCapScript.firmware` returns the full framed body
(`params[16:]`), a different representation. Re-running AES-CTR/CBC/CFB/OFB on
the explicit stream with all 15,676 derived keys still gave zero hits, as did
AES-CFB at segment sizes 8/16/32/64/128 and a fresh sweep of 34 whole-artifact
hashes. Blob-derived KDFs (SHA-256/512, MD5, HMAC with `NovemberRain`, PBKDF2,
IV combinations) and IV-as-key variants were also negative.

**Other dead ends:** the Dell `DELLTPM_NPCT750_X10_7.2.3.1_64_v1.exe` utility
(SHA-256 `4ad47d120ab3d0895d695b9701957f081a9e3904e9b9811d837f78826e7f472f`)
contains only Dell PFS platform-firmware capsules, no TPM blob. The embedded
driver's SHA-256 constants are at PE offset `0x380`; there is no AES S-box.

The service table's `AES CTR` + manufacturing-installed, obfuscated keys —
not extractable via any standard or discovered vendor command — confirms the
earlier conclusion. Software-only decoding remains closed.

### 10.13 RSA blob analysis: no modulus, so no related-message attack (2026-11-20)

The 256-byte setup blob was tested as the RSA artifact suggested by the
FIPS 140-2 policy. A second, previously unexamined 256-byte blob was found in
the `0x20000203` commit command of each package (`u32 256` at offset 58,
followed by the blob), giving four RSA-sized values.

`tools/fw_rsa_analysis.py` reproduces all checks offline:

* **Not moduli.** The four blobs are 2046–2048-bit random-looking values, three
  are even and two have small factors (5, 23, 11, 29, 43). Pairwise GCDs are
  1–3 bits: no shared 2048-bit modulus.
* **Setup-as-modulus fails.** `pow(commit, e, setup)` for `e` in 3, 17, 65537,
  same- and cross-package, gives no PKCS#1 v1.5 `00 01 ff…ff 00` prefix in any
  of 12 combinations. The setup blob is therefore not the firmware-update
  public modulus.
* **Modulus-from-signatures fails.** `gcd(s1**e - m1, s2**e - m2)` over all
  blob pairs, `e` in 3, 17, messages = SHA-256 of DevCap / firmware stream /
  setup / version table / commit-body, PKCS#1-DigestInfo and raw encodings:
  zero 2040–2060-bit candidates.
* **Same-message randomized padding fails.** If two blobs signed the identical
  padded message, `n` would divide `s1**e - s2**e`; gcd across disjoint pairs
  produced no 2048-bit factor at `e` = 3 or 17.
* **`rsakeyfind` (Halderman/Heninger RSAKeyFinder 1.0)** found no BER-encoded
  RSA private/public key in any artifact (both DevCaps, both firmware streams,
  reframed stream, DXE driver `.text`, EK certs, updater EXEs/SYS,
  `section1.pe`). A further 6,662 odd 2048-bit no-small-factor windows in the
  updater binaries, tested as candidate `n` against all four blobs at `e` = 3
  and 65537, produced zero PKCS#1 hits.

A Franklin–Reiter related-message attack requires two RSA *encryptions*
`c1 = m1**e mod n`, `c2 = m2**e mod n` under a **known** modulus `n` with a
known affine relation `m2 = a*m1 + b`. Here the blobs are RSA *signatures*
`m**d mod n` under a manufacturing-installed key, `n` is unpublished and
obfuscated in TPM flash, and no candidate `n` exists in any host artifact. The
prerequisite is absent, so the attack is inapplicable. Firmware decoding stays
closed without physical extraction.

### 10.14 Cross-vendor packages, GetTestResult, and CC key details

**HP SoftPaq SP111032 ships the identical encrypted firmware.** HP's public
TPM firmware update for 7.2.2.0
(`https://ftp.hp.com/pub/softpaq/sp111001-111500/sp111032.exe`, SHA-256
`edb3e356848ae2a68b1d964c86399a3d67235f5c2d405218f05dad91504d1489`) extracts
`FU_2.0_7.2.2.0_0.bin` (240,086 bytes, SHA-256
`5bbc726c5e2084a0fc8b1b5c8aa11b6bbb548494bfe43927b9ac3c781c60a72d`). Its
layout is an HP-specific 48-byte header, the 256-byte setup blob at offset 48,
padding to offset 376, then 252 firmware chunks on a 952-byte stride, a short
commit chunk, and the 256-byte commit signature.

A byte-level comparison against `out/firmware/NuvotonTpmDevCap.BIN` (Lenovo
7.2.2.0) found:

- all 252 firmware chunk IVs, ciphertexts and 10-byte tags identical;
- the 256-byte setup blob (`ba438def…`) and 256-byte commit blob
  (`eb0790e8…`) identical (SHA-256 `58028c31…` for the latter);
- HP's 253rd chunk is the same 6-byte commit value with the same tag and IV.

This is decisive: Nuvoton encrypts the firmware **once** with a single global
key and fixed per-chunk nonces, then hands the same payload to every OEM. No
OEM package can provide a second encryption under a different key, a reused
nonce, or a plaintext copy. Dell's 7.2.2.0 and 7.2.3.1 utilities were already
shown to contain only platform firmware PFS capsules (§10.x); the HP package
closes the remaining cross-vendor avenue.

**`TPM2_GetTestResult` is not a key source.** The live command returns 225
bytes beginning `aa55 0000 000001fe 0100 0400 0011 …`. At offset 8 onward it
is a run of big-endian small integers (41, 52, 43, 44, 42, …) consistent with
Nuvoton self-test counters, followed by build constants
(`00040001 0103 0020 00001000 …`). Every 16-byte sliding window and the
SHA-256/MD5 of the whole blob were tested as AES-128 keys against the first
firmware chunk under GCM/CCM/EAX tag verification and as an AES-ECB keystream
looking for an ARM vector-table prefix: zero hits. The command is read-only
and safe; it yields no key material.

**CC documentation agrees with the FIPS policies.** The TPM 1.2 Security
Target states that field-upgrade data is decrypted with AES-128-CTR and
integrity-protected with an RSA PKCS#1 v2.0 signature. The NPCT7xx TPM 2.0
targets call the deliverable a "Zip file with the encrypted field upgrade
payload" sent by Nuvoton to the OEM, and require signature/digest verification
before leaving the firmware-update mode. The FIPS 140-3 policies for 7.2.4.1
and 7.2.5.1 confirm `NTC_FIELD_UPGRADE` = AES-CTR + ECDSA SigVer with
manufacturing-installed, obfuscated, Clear-zeroized firmware-update keys; the
7.2.5.1 table also lists an "ECDSA SigVer (legacy)" service for older images.
No document publishes a modulus, public key, or key-derivation input.

Consequently every offline decoding route is exhausted. A plaintext dump now
requires either a key leak from Nuvoton, a decrypted image published elsewhere,
or authorized physical extraction from the NPCT75x package.

### 10.15 Authorized live FUM experiments — second wedge (2026-11-20)

After the offline routes above were exhausted, live FUM probing was explicitly
authorized. The goal was a decryption/read-back oracle; **no erase, write,
commit, `0x2000012f`, `0x20000211` or full DevCap replay was ever sent.** All
experiments used CC `0x20000200` (setup) or the read-only vendor commands.

* **Bare DevCap setup is not a wire command.** The stored 312-byte command
  (`tag=0x8001`, SHA-256 `02407501…`) has no handle, and returns
  `rc=0x184 VALUE (handle 1)`. The real tool injects a handle and an auth area.
* **Setup requires PLATFORM.** With handle `0x4000000C` and an empty
  `TPM_RS_PW` session (SHA-256 `3cb30cc8…`) the answer is `rc=0x9A2 BAD_AUTH
  (session 1)`. All other handles (`0x40000001`, `0x4000000B`, `0x4000000D`,
  `0x4000000A`, `0x4000000C`, `0x81000000`, `0x01802006`) return
  `VALUE (handle 1)`, so `0x4000000C` is mandatory and its authValue is
  non-empty.
* **The PLATFORM authValue is unknown.** Correctly formed HMAC password
  sessions using the NovemberRain NV digest, its ASCII/SHA-256 forms, 32 zero
  bytes and the setup digest, across four cpHash layouts and three attribute
  bytes, all return `rc=0xA84 VALUE (session 2)`, i.e. HMAC rejected. Guessing
  the secret was abandoned.
* **Read commands expose nothing.** `0x20000204`, `0x20000213`, `0x20000216`
  return their fixed responses with or without handle/session; adding any
  parameter yields `SIZE`. `0x20000214` is a 1-byte selector: bare →
  `INSUFFICIENT (parameter 1)`, one byte → `COMMAND_CODE`, two or more → `SIZE`.
* **A blind 1-byte selector sweep on `0x20000214` wedged the TPM.** Roughly
  halfway through the 0x00..0xFF sweep, `DeviceTransport` raised
  `BrokenPipeError`; one selector evidently dispatched a state-changing
  operation. The chip has not answered since: blocking writes to `/dev/tpm0`
  and `/dev/tpmrm0` return `EINVAL (22)` and reads time out, and `tpm2_*`
  tools report `EPERM` reading the response header. Restarting `tpm2-abrmd`
  did not help.

This is the same wedge signature as §6.1. No reboot or power cycle was
attempted in this phase (no authorization). The previous incident recovered
only through **external hardware restoration** — warm reboot and cold power
cycle both failed — so that was expected to be required again. The live FUM
path is closed twice over: setup is gated by an unknown PLATFORM authValue and
§10.1 establishes there is no firmware read-back command even inside FUM.

**Recovery by S3 suspend/resume (2026-11-20).** Unlike the first incident,
`/dev/tpm0` and the `MSFT0101:00` device were still present while wedged, so
the driver's resume path could be exercised. A single S3 cycle
(`mem`/`deep`, RTC alarm armed via `/sys/class/rtc/rtc0/wakealarm`, though an
unknown source woke the box after ~8 s) fully recovered the chip: writes stop
returning `EINVAL`, `0x20000213` again returns
`ffffa700fbff7ffffbfffffffbf0ffffaaaa`, `0x20000204`/`0x20000216` return their
baseline values, `tpm2_getcap` and `tpm2_gettestresult` work, and `NV_Read` with
the NovemberRain auth returns the 16-byte index. **An S3 cycle is therefore a
valid non-reboot recovery for a wedged NPCT75x when the platform device is
still bound** — the earlier S3 attempt failed only because the device had
already disappeared. `/dev/mem` MMIO poking remains blocked by
`CONFIG_STRICT_DEVMEM`, and PPI `transition_action` is `2: Reboot`.

---

### 10.16 New artifact sweep and residual decode gaps (2026-11-20)

A fresh pass looked for artifacts outside the exhausted ciphertext/crypto
paths (§10.10–10.15). All were negative:

* **DevCap container gaps** — the 22,560-byte pre-command region is entirely
  the embedded PE UEFI DXE driver (`MZ` at `0x118`, length `0x56f8`); the
  256-byte trailing region is the commit signature. No plaintext firmware,
  key blob or hidden section. Strings in the driver are only the known error
  table (`Authorization failed`, `Target FW is already installed`, …).
* **`DevCapWIN.EXE` / `DevCapWINx64.EXE`** — generic Nuvoton updaters; the
  `November` string is the CRT month table, not a password. No AES key,
  platform auth or vendor CC immediates (`0x200002xx`) are embedded — the
  tool reads the command codes from the DevCap file at runtime.
* **EK certificates** — read-only `NV_Read` of the two platform-created
  indices exposed `0x1C00002` (RSA-2048 EK cert, `Key Encipherment`) and
  `0x1C0000A` (P-256 ECDH EK cert), both issued by `NPCTxxx ECC384 LeafCA
  022110`. These are device EKs, not firmware keys; cross-vendor payloads are
  byte-identical (§10.14), so no firmware key can be wrapped to them.
* **FUM auth, raw password variant** — the earlier HMAC attempts (§10.15)
  were re-checked against `_custom_auth()`: a `TPM_RS_PW` session carries the
  authValue itself in the hmac field, which is what the working NV auth uses.
  32 raw candidates (NovemberRain derivations, SHA-1/256, MD5, UTF-16,
  setup digest, common words) all return `rc=0xA84`; the TPM stays healthy
  (`0x20000213` baseline unchanged). PLATFORM authValue remains unknown and
  is not simply NovemberRain-derived.
* **Residual crypto gap closed** — tested (a) AES-ECB/HMAC of chunk counters
  against the 16-byte IVs (15,676 candidate keys, 7 counter encodings, zero
  hits) and (b) AES-CTR using each chunk's own IV as the 128-bit initial
  counter (the prior sweeps all used counter 0 on the concatenated stream).
  Best decryption entropy was 7.447 on 512 bytes — i.e. random. No signal.
* **Advisories** — SA-005/CVE-2025-2884 is DoS-only ("No confidential data is
  at risk"); SA-006/CVE-2026-6726 is attestation-key falsification; SA-004 and
  SA-007 are physical/timing side channels. None gives a firmware read
  primitive on 7.2.2.0.

Conclusion: offline decoding is closed unless a genuinely new key-bearing
artifact appears. Remaining routes are a published decrypted image, a key
leak, explicitly authorized physical extraction, or a safe FUM read command
(which the complete nine-command vendor surface shows does not exist).

### 9.15 PLATFORM auth is runtime/policy-derived (Ghidra, 2026-11-20)

A full decompilation pass over `TpmFmpUefiDrv` (`section1.pe`) renamed all 73
functions. The auth path resolves as follows:

| Address | Name | Role |
|---|---|---|
| `0x4220` | `TpmFmpUefiDrvSetImage` | FMP `SetImage`; calls reset-auth at `0x450F` |
| `0x2d18` | `Tpm20ResetEmptyPlatformAuth` | error string at `0x9B70` confirms the name |
| `0x3134` | `GetRtTpmFwUpdPolicyHndl` | HMAC-SHA256 of `NovemberRain` + roll nonce |
| `0x35fc` | `ProvisionTpmFwUpdRollNonce` | generates/writes the 16-byte nonce |
| `0x6e94` | `NpctVendorCmd93_SetAuthBlob` | vendor CC `0x93`, subcmd `0x129` |
| `0x716c` | `NpctVendorCmdE5_HmacAuth` | vendor CC `0xE5`, subcmd `0x151` |
| `0x756c` | `NpctVendorCmd93_HmacAuth` | vendor CC `0x93`, subcmd `0x149` |
| `0x630c` | `NpctVendorCmd93_137_HmacAuth` | vendor CC `0x93`, subcmd `0x137` |
| `0x6aec` | `NpctVendorCmd4C` | vendor CC `0x4C`, subcmd `0x189` |
| `0x66fc` | `NpctGetRandomBytes` | vendor CC `0x4C`, subcmd `0x17B` |
| `0x2acc` | `SubmitVendorCommand` | low-level submit via `DAT_0000a128+0x140` |
| `0x5a6c` | `HmacSha256TwoPart` | HMAC-SHA256 (ipad `0x36`, opad `0x5c`) |
| `0x8674` | `Sha256HashBuffers` | SHA-256 over a buffer list |

`ProvisionTpmFwUpdRollNonce` is the decisive find. It calls
`NpctGetRandomBytes(0x10, ...)`, copies `NovemberRain` into two buffers, hashes
them with `TpmFmpUefiDrv_data_hash_check`, then **writes the 16-byte nonce into
the `TpmFwUpdRollNonce` UEFI variable** (`SetVariable`, attrs `3`, size `0x10`,
GUID `106a48f7-d30d-2749-a37c-d892b3a69ee1`). `GetRtTpmFwUpdPolicyHndl` reads
that variable back and HMACs it with `NovemberRain` to obtain the policy handle.
`TpmFmpUefiDrvSetImage` uses subcommand `0x12F` (the one that wedged the TPM).

Consequences:

* The PLATFORM auth is **not a fixed static string** — it is BIOS/runtime state.
  The driver *clears* it to empty using a policy session bound to a per-update
  random nonce that it provisions (see §9.15 correction). This explains why
  every offline XOR/AES/HMAC/sliding-window search over static artifacts failed.
* ~~The driver talks to the TPM over vendor command codes `0x93`, `0xE5`,
  `0x4C`, …~~ **Superseded — see the correction below.** Those small values are
  response-buffer sizes; the driver uses only *standard* TPM 2.0 commands.
  Initial size-field placeholders misread as command codes include `0xDD`
  (`0x6ebd`), `0x15F` (`0x67c9`), `0xE9`, `0xDF`; `0xe5dd1403` is the GUID
  component `0314dde5-…`, not a command.
* The nonce variable is **absent from live NVRAM** (checked 2026-11-20): neither
  `TpmFwUpdRollNonce` nor `TpmFwUpdMode`, and none of the other driver GUIDs,
  appear among the 156 exported EFI variables. The 16-byte NV index
  `0x01802006` is all zeroes. This is consistent with the driver only
  provisioning/clearing the nonce during an actual FMP capsule update — which
  this machine has never run through.
* Recovering the live PLATFORM auth therefore requires either running the
  driver's provisioning step (state-changing, effectively an update) or driving
  the standard policy commands (`SetPrimaryPolicy`, `PolicySecret`, `PolicyNV`,
  `HierarchyChangeAuth`) with the correct nonce/session. Both remain outside
  the non-destructive boundary.

#### Driver command map — standard TPM 2.0 commands, not vendor commands

**Correction (2026-11-20).** The small values previously read as "vendor command
codes" (`0x93`, `0xE5`, `0x4C`, …) are actually **maximum response-buffer sizes**
passed as the fourth argument to the UEFI protocol call in `SubmitVendorCommand`
(`0x2acc`). The real TPM command is the big-endian dword at payload offset 6
(shown byte-swapped by the decompiler, e.g. `0x29010000` → `0x00000129`).
Cross-checked against wolfTPM's `TPM_CC_T`: every value resolves to a **standard
TPM 2.0 command**. There is no separate vendor command surface in this driver —
`0x2000012f` is the vendor *alias* of standard `TPM_CC_FieldUpgradeStart`
(`0x0000012f`), which is why both spellings appear in the literature.

`SubmitVendorCommand(length, payload*, maxResponseSize*, response*)` calls
`(**(protocol + 0x18))(protocol, length, payload, maxResponseSize, response)`
and overwrites the size argument with the actual response size on success.
Payload prefix: tag `0x8002` (`TPM_ST_SESSIONS`) or `0x8001`
(`TPM_ST_NO_SESSIONS`), then size, then command code.

| Function | Address | TPM command | Code | maxRsp | Notes |
|---|---|---|---|---|---|
| `NpctVendorCmd9E` | `0x5bd4` | `NV_ReadPublic` | `0x169` | `0x9E` | reads a two-field blob |
| `NpctVendorCmd93_137_HmacAuth` | `0x630c` | `NV_Write` | `0x137` | `0x93` | HMAC over 6 buffers + caller data |
| `NpctGetRandomBytes` | `0x66fc` | `GetRandom` | `0x17B` | `0x4C` | reads `param_1` random bytes |
| `NpctVendorCmd50` | `0x67c4` | `StartAuthSession` | `0x176` | `0x50` | handle `0x04000007`; creates session |
| `NpctVendorCmd93_16C` | `0x6980` | `PolicyCommandCode` | `0x16C` | `0x93` | two u32 params |
| `NpctVendorCmd0A` | `0x6a44` | `FlushContext` | `0x165` | `0x0A` | flush/close handle |
| `NpctVendorCmd4C` | `0x6aec` | `PolicyGetDigest` | `0x189` | `0x4C` | reads a length-prefixed blob |
| `NpctVendorCmd93_SetPolicyHandle` | `0x6bdc` | `HierarchyChangeAuth` | `0x129` | `0x93` | handle `0x4000000C` |
| `NpctVendorCmd93_12E` | `0x6d34` | `SetPrimaryPolicy` | `0x12E` | `0x93` | handles `0x4000000C`, `0x40000009` |
| `NpctVendorCmd93_SetAuthBlob` | `0x6e94` | `HierarchyChangeAuth` | `0x129` | `0x93` | handles `0x4000000C`, `0x40000009`; auth blob |
| `NpctVendorCmd40B` | `0x7020` | `GetCapability` (+`0x17A`) | `0x17A` | `0x40B` | returns a 128-byte blob |
| `NpctVendorCmdE5_HmacAuth` | `0x716c` | `PolicySecret` | `0x151` | `0xE5` | HMAC with nonce + `NovemberRain` |
| `NpctVendorCmd93_HmacAuth` | `0x756c` | `PolicyNV` | `0x149` | `0x93` | HMAC with `NovemberRain` |

`HierarchyChangeAuth` appears twice with different payloads: `0x6bdc` sets a
policy handle, `0x6e94` sets an auth blob. Both target platform handle
`0x4000000C`. This is the pair `Tpm20ResetEmptyPlatformAuth` drives. Other
families (`0x100` magic probes, `0x200` legacy owner check, `0x1E` deferred PP)
are separate compatibility checks, not the FMP auth path.

**Implication for the auth problem:** all of these are *standard* TPM commands on
`/dev/tpmrm0`, so in principle they can be issued from Linux. But the PLATFORM
auth is still not recoverable: `HierarchyChangeAuth` *writes* the auth and no TPM
command reads a hierarchy authValue back. The `0x93`/`0xE5` values wedging the
TPM earlier were sizing-sensitive payloads, not an undocumented command family;
the state-changing commands themselves (`SetPrimaryPolicy`, `PolicySecret`,
`HierarchyChangeAuth`, `FieldUpgradeStart`) remain off-limits without explicit
authorization.

#### Exact policy/HMAC derivation (definitive offline closure)

`HmacSha256TwoPart(key, n, ptr[], len[], out)` at `0x5a6c` is textbook
HMAC-SHA256 (ipad `0x36` at `0xa030`, opad `0x5c` at `0xa040`): key copied into a
64-byte block, `SHA256((key^ipad) || data)`, then
`SHA256((key^opad) || inner)`. The data is `n` buffers addressed by `ptr[]`
with parallel `len[]`.

`Tpm2PolicySecret_HmacAuth` (`0x716c`, TPM `PolicySecret`=`0x151`) computes:

```
nonce        = 16 B read from TpmFwUpdRollNonce UEFI variable
digestNonce  = SHA256(nonce)                       # 0x6d3, 32 B
cpHash       = SHA256(8 buffers: cmdCode 0x151, NV public area from
               NV_ReadPublic, policy session handle, digestNonce,
               random blob, …)                     # 0x5c8, 32 B
authKey      = SHA256(UTF-16LE("NovemberRain\0"))  # 0x506, 32 B
             = 4a2a5d8442d17e746f46ed1d990ee2213250e04005bbded804565ecfdab0afdf
hmac         = HMAC-SHA256(authKey,
                 cpHash || TPM_GetRandom(32) || StartAuthSession blob || 0x00)
```

**Correction to the earlier "policy digest becomes the PLATFORM auth" claim.**
Re-reading both `HierarchyChangeAuth` wrappers settles what is actually written:

* `Tpm2HierarchyChangeAuth_SetAuthBlob` (`0x6e94`, `0x129`) sends `newAuth` =
  the caller's `param_1` bytes at `0x16d`; with `(0, NULL, …)` it writes an
  **empty** authValue. This is the first thing `Tpm20ResetEmptyPlatformAuth`
  tries. It succeeds only if the current PLATFORM auth is already empty.
* `Tpm2HierarchyChangeAuth_PolicyHandle` (`0x6bdc`, `0x129`) sends
  `local_17d = 0` — i.e. `newAuth` size **zero** — using the *policy session*
  handle as the authorization. It also writes an **empty** authValue; the
  policy session is only the *authorization* for the reset.

So the driver never installs the policy digest as the PLATFORM authValue. The
full `Tpm20ResetEmptyPlatformAuth` (`0x2d18`) flow is:

1. Try `HierarchyChangeAuth(empty, password session)` → done if auth was empty.
2. On failure, read a cached 32-byte policy digest from an AMI proprietary
   variable store (`ReadUefiVariableByGuid` `0x80e4`: protocol `0314dde5-…`,
   record `ac61fe57-65dd-5240-b539-c7b42a868668`); compare its header `0x129`.
3. Build the policy via `GetRtTpmFwUpdPolicyHndl(0x129, …)`, optionally checking
   the recomputed `PolicyGetDigest` against the cached value.
4. Call `HierarchyChangeAuth_PolicyHandle(policySession)` — reset PLATFORM auth
   to **empty**, authorized by the policy. FUM setup then works with an empty
   password.

`ProvisionTpmFwUpdRollNonce` (`0x35fc`) is the writer of that cached digest
(protocol call at `0x138` with the same `0314dde5-…` GUID, data from
`PolicyGetDigest`) and of the `TpmFwUpdRollNonce` UEFI variable. Both the cached
digest and the nonce are runtime/provisioning state; the digest lives in AMI
NVRAM under `ac61fe57-…`, **not** in the 156 exported efivars (re-checked
2026-11-20: no `ac61fe57`, `0314dde5`, `106a48f7`, `582d29ed` or `677ac786`).

**Net effect is unchanged:** the PLATFORM auth is non-empty on this machine
because the update path never ran; the driver would clear it to empty using a
policy session seeded by the absent nonce. The policy digest is a one-way
function of the nonce and live TPM randomness, no TPM command reads a hierarchy
authValue back, and the cached digest is not exposed to Linux. Every offline
route remains closed and no live policy action is authorized.

### 9.15 FV2_main.bin decompilation (2026-11-20)

Loaded the 16 MiB M47KT41A BIOS's `FV2_main` segment (`0x6f3000`,
`0x6fe000` B, SHA-256 `482e5dcbc595fee524c87cd4f5088ea0fc65d5b21dc890244706d802982afc80`)
into Ghidra and decompiled all 158 auto-detected functions. It is **not** the
TPM FMP driver and contains no TP-related material:

* Two embedded Windows kernel USB-filter drivers (`x86`/`x64` `usbf.sys`,
  PDB `D:\bussnessSoft\SmartUsb\SourceCode\usbfilter\product\{x86,x64}\usbf.pdb`),
  which expose an SMM-communication interface:
  `BtdGetACPISmmCommTbl` (`0xd6ac`, RSDP → RSDT → "UEFI" table walk),
  `BtdSmmCommBufferAccessRev2` (`0xdb18`),
  `CompareSmmCommTableGuid` (`0xdc94`), and
  `TriggerSmiViaIoPort` (`0x930c`, raw `out` to the SMI port).
* A large EDK2/Phoenix `securewipe2.144` UEFI application with OPAL/ATA/NVMe
  erase, password prompts, PNG/GIF/JPEG decoders and GUI code (build paths
  `d:\sct\securewipe2.144\...`).
* Keyword scans for `tpm`, `Nuvoton`, `NovemberRain`, `TpmFmp`, `TCG` (only
  `TCG OPAL`, a storage standard), `PCR`, `Seal`, `NV index`, `GetRandom`,
  `PlatformAuth` returned nothing relevant.

No TPM, Nuvoton, policy-auth, or key material. The `section1.pe`
`TpmFmpUefiDrv` remains the correct Ghidra program for the auth work; the
`FV2_main.bin` renames above are local Ghidra-database changes only.

### 9.16 binwalk LZMA extraction of the BIOS segments (2026-11-20)

**Correction to earlier scope:** the M47KT41A ROM contains the TPM driver, but
only inside **LZMA-compressed** nested firmware volumes. The earlier string
sweeps that found no `Nuvoton`/`NovemberRain`/`PlatformAuth` used raw bytes and
zlib only; they did not decompress LZMA. `binwalk -e` on the carved segments in
`/tmp/opencode/bios/segments/` extracts the compressed members into
`/tmp/opencode/bios/seg_extract/<segment>/<segment>.extracted/`.

The relevant extracted members:

| member | size | content |
|---|---|---|
| `FV2_main/…/111028` | 13,963,280 B | decompressed UEFI FV (`8C8CE578-…`) containing the AMI TPM FMP driver plus a Lenovo `LDEVFWUPD` driver |
| `FV2_main/…/3E770` | 2,531,344 B | AMD fTPM material (`0314dde5` protocol GUID, no NovemberRain/TpmFmp) |
| `FV2_main/…/F2648` | 278,544 B | TPM **vendor-ID string table** only (`AMD … NUVOTON … WINBOND`, `TPM 1.2`/`TPM 2.0`) |
| `FV6_2mb/…/2100` | 4,194,336 B | AMD PSP/fTPM PEI strings; not Nuvoton |

Two PE images inside `111028` reference `NovemberRain`/`TpmFwUpdRollNonce`:

* `PE_3217d4` — SHA-256 `9ce07f4188c125105b7ec6ec167ed98129c1a49edc3fd399920232624d8232b5`,
  44,480 B. `.text` is **byte-identical** to `~/section1.pe`
  (SHA-256 `8940d5aea6834217c478f16be10604946120796323f1fc8bfe16f11039aeca6a`);
  only 5 bytes differ, at `0x8c90–0x8c96` in `.data` (build metadata). This is
  the same `TpmFmpUefiDrv` already decompiled in Ghidra — no new logic.
* `PE_712c64` — SHA-256 `ec3406baa6097562ac17650a7c61a57e6f211be1ec5ef070b396b9ee1982b8f3`,
  53,280 B. A different, larger Lenovo `LDEVFWUPD` (device firmware-update)
  driver. Disassembly (capstone) of its `.text` shows a **second, independent
  implementation of the same platform-auth flow**:
  * `0x6158` reads the 16-byte `TpmFwUpdRollNonce` variable (GUID built on stack
    at `0x6182–0x619d` as `106a48f7-d30d-2749-a37c-d892b3a69ee1`), opens a
    **policy** session (`cl=1` at `0x8565`), HMACs the nonce with UTF-16
    `NovemberRain` (calls `0x8540` → `0x8588` → `0x8988`), then submits
    `HierarchyChangeAuth` (`edx=0x129` at `0x6274`) via the generic TIS submit
    primitive `0x5c28` (also used for `0x149`/`0x4c` commands).
  * `0x6618` is a nonce-provisioning / digest-cache routine: `GetRandom`
    (`0x9310` path), writes `TpmFwUpdRollNonce`, builds both protocol GUIDs
    `0314dde5-…` (hash interface) and `ac61fe57-…` (cached-policy record),
    then `LocateProtocol` (`[gBS+0x138]`) and reads the 32-byte cached digest
    via `[iface+8]`/`[iface+0x98]`. This confirms the cached policy digest is
    obtained through the AMI `0314dde5` protocol, which is why it was absent
    from the 156 exported efivars.
  * No nonce value, no authValue, and no manufacturing key are stored in the
    driver; everything is regenerated at runtime from live TPM randomness.

Also decoded from `111028`: a BIOS setup prompt at `0x228f84`
("Enables or Disables **Platform Hierarchy randomization** … OVERRIDE
ChangePlatformAuth ELINK for production platforms supporting TXT"). This is a
development-only AMI setup option; it is consistent with the BIOS randomizing
PLATFORM auth at boot, i.e. it explains *why* PLATFORM auth is non-empty, but
it exposes no recoverable value.

**Net effect:** the binwalk extraction changes the evidence base (the driver is
present, compressed) but not the conclusion. No stored nonce, cached digest, or
key material exists in any BIOS segment; the second driver re-derives the same
runtime policy. Offline auth recovery remains closed; no live action is
authorized.

### 9.17 Full extraction of `_FV2_main.bin.extracted/` (2026-11-20)

Continued recursive extraction of all 30 files in
`/tmp/opencode/bios/seg_extract/FV2_main/_FV2_main.bin.extracted/`. Result:
**no new key-bearing artifact**; every remaining file is accounted for.

* The `*.7z` siblings are raw LZMA-alone streams (binwalk output). `7z x -so`
  confirms each decompresses byte-for-byte to its plain-named partner (e.g.
  `1095F8.7z` → `1095F8`, 47,810 B), so those plain files are already the
  decoded output — not a further compression layer.
* `1095F8`, `10A2D8`, `108C38`, `106780`, `13360`, `10AC68`, `10BF60`,
  `10DD30`, `10F0E8`, `1094E0` are **AMI-wrapped BMP bitmaps** (BIOS splash /
  logo images), not compressed firmware modules. Each has a 4-byte AMI
  wrapper (`u24 size` + `0x19`) followed by the `42 4d` = `BM` BMP signature
  at offset 4; binwalk identifies e.g. `1095F8` as a 125×127×24 PC bitmap and
  `106780` as a 768×432×32 bitmap. Their low-entropy repeated-byte patterns
  are bitmap pixel data. `1094E0` additionally carries an `IMA` palette
  chunk. No TPM/crypto content.
* `34330` is a small UEFI FV with five PE images (AmdS3Lib / S3 table code),
  e.g. "AmdS3Lib table Signature check fail". No TPM content.
* `13360` holds two nested LZMA streams at `0x43B09` (4,864 B) and `0x4EB70`
  (3,328 B), recovered with `binwalk -e`. Both expand to opaque binary with no
  strings, PE/FV headers, or signatures — not key material.
* **`3E770` AES S-boxes are TLS, not TPM.** The reported tables
  `0x1EBE6C` (inverse S-box, starts `52 09 6a d5 …`) and `0x1EC08C`
  (S-box, starts `63 7c 77 7b …`) are standard AES tables. They live in the
  PE at file offset `0x8A11C` whose FFS GUID immediately before `MZ` is
  `3aceb0c0-3c72-11e4-9a56-74d435052646` — the EDK2 `NetworkPkg/TlsDxe`
  driver (confirmed against upstream `.inf`). RIP-relative xrefs from `.text`
  at `0x1287C1…0x128ACB` (AES decrypt) and `0x13155C…0x131756` (key
  expansion / encrypt), plus the GHASH reduction constant
  `0xE100000000000000` at `0x128C1B`, confirm OpenSSL AES-GCM used for TLS
  records. No TPM / Nuvoton / NovemberRain strings occur anywhere in `3E770`;
  all `policy` strings are X.509 certificate-policy names. This is generic
  UEFI network-stack crypto and is unrelated to NPCT75x firmware decryption.
* `111028` contains seven AES S-box instances; they map to BIOS setup/HII
  code, an OpenSSL `CryptoPkg` library, and AMI `RegisterPasswordUpdateProtocolNotify`
  DXE/SMM modules — none TPM firmware-update related.
* A byte-level scan of every extracted file for `NovemberRain`, `Nuvoton`,
  `NPCT75`, `TpmFwUpd`, `RollNonce`, `HierarchyChangeAuth` and all five known
  GUIDs (ASCII and UTF-16LE) matched **only** `PE_3217d4`, `PE_712c64`, and
  their parent `111028` — the two drivers already fully analysed in §9.16.

**Net effect:** offline key/auth recovery remains closed. No live action is
authorized.

### 9.18 Read-only hardware re-probe after S3 recovery (2026-11-20)

With the TPM recovered and no new live authorization, a strictly read-only
dossier was collected from `/dev/tpmrm0`. Key results:

* **NV space** is exactly three indices: `0x01802006` (16 bytes, **all zero**
  when read with the derived `NovemberRain` digest) and the RSA/ECC EK
  certificates at `0x01C00002` (861 B) / `0x01C0000A` (659 B). No persistent
  or transient object handles exist; `GetCapability(CAP_HANDLES)` returns
  empty for both ranges, so there is no hidden key object to load.
* **Property scan**: every property `0x000..0x500` was queried individually;
  67 returned data, all inside the documented fixed (`0x1xx`) and variable
  (`0x2xx`) ranges. No vendor-specific TPM properties exist outside
  `CAP_VENDOR_PROPERTY = 0x100`.
* **`ReadClock`**: `time = 86,747,795 ms`, `clock = 86,005,306 ms`,
  `resetCount = 2`, `restartCount = 0`, `safe = 1`. The S3 recovery therefore
  left the chip with two lifetime resets.
* **New correlation — vendor property 1 is the `GetTestResult` diagnostic
  counter.** The u16 big-endian field at offset 13 of the 225-byte Nuvoton
  diagnostic blob (§10.7) and `VENDOR_PROP_0x00000001` were sampled together
  five times and matched **exactly** on every sample:
  `0x12F0 → 0x12F0 → 0x12F2 → 0x12F2 → 0x12F2`. They increment in lockstep
  in short bursts, then hold. This resolves the "what drives property 1"
  question: it is a firmware-internal diagnostic counter exposed through two
  read-only interfaces, not a command counter, wall clock, or nonce.
* **Both interfaces changed across the reset boundary.** The earlier
  baseline recorded `PROP1 = 0x001AD0A0` and `PROP2 = 0x00004BF0`; current
  readings are `PROP1 ≈ 0x12F2` and `PROP2 = 0x6060`. The diagnostic blob's
  offset-13 field likewise moved from `0x10BC` to `0x12F0` while the rest of
  its structure was preserved. `PROP2` remains static within a session; its
  meaning is still unknown, but it is not a constant burn-in value.
* **Baseline vendor reads unchanged**: `0x20000204 → 0200001a`,
  `0x20000213 → ffffa700fbff7ffffbfffffffbf0ffffaaaa`,
  `0x20000216 → (empty)`, all `rc=000`.

No auth-bearing material was found. The correlation narrows the vendor
property semantics but does not move the PLATFORM authValue problem.

## 10. Open questions

0. ~~What is the auth value for NV `0x01802006`?~~ Answered in §6 and
   confirmed live: `SHA256(UTF-16LE("NovemberRain\0"))` =
   `4a2a5d8442d17e746f46ed1d990ee2213250e04005bbded804565ecfdab0afdf`.
   `NV_Read` with this auth returns 16 bytes; empty password returns BAD_AUTH.
1. ~~What drives vendor property 1?~~ §9.18 shows it is the same diagnostic
   counter exposed at offset 13 of the `GetTestResult` blob; both increment
   in lockstep. Properties 0 (always `0`) and 2 (session-static, currently
   `0x6060`) remain unexplained.
2. What do vendor commands `0x20000200..0x20000216` do? Which are read-only?
   §8.1 adds `0x2000012f`, statically identified as a vendor
   `FieldUpgradeStart`; it is state-changing and unprobed.
3. Where does the TPM get its firmware? The working assumption is on-die
   flash in the NPCT75x package with no public read-back command. §7 shows the
   BIOS FMP driver has a real capsule-dispatch/`SetImage` path but ships no
   firmware image, so it is not the source. The practical source is a
   Nuvoton/Lenovo TPM firmware updater package.
4. Which Lenovo/Nuvoton package contains the TPM payload? A BIOS update will
   not (§7). Candidate: a dedicated Nuvoton NPCT75x firmware/updater release
   or the Lenovo TPM firmware update for this platform. The Lenovo support
   page blocks plain fetches; a direct `download.lenovo.com` URL still needs
   verification.
5. Why is the BIOS measurement log empty? (Could be a firmware/OS policy,
   not necessarily a TPM property.)
6. Does `FIRMWARE_VERSION_2` combine with version 1 into a four-part
   version? Nuvoton's own updater naming would settle it.
