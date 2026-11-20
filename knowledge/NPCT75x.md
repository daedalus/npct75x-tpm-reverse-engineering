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
`VENDOR_0x2000xxxx`. **Their semantics and side effects are
unknown; none have been sent.** Sending them is gated behind `--allow-write`
and is out of scope until the vendor documentation or the firmware image
explains them.

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
= "NPCT" / "75x"`, so the payload family is at least related, but the exact
source version and decryption/verification path are not yet resolved. Crucially,
`python3 -m tpm_re ami` finds **zero** `AMI ` capsules in either DevCap BIN or
the extracted UEFI driver, so the §7.1 parser does not apply here.

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

## 9. Open questions

0. ~~What is the auth value for NV `0x01802006`?~~ Answered in §6 and
   confirmed live: `SHA256(UTF-16LE("NovemberRain\0"))` =
   `4a2a5d8442d17e746f46ed1d990ee2213250e04005bbded804565ecfdab0afdf`.
   `NV_Read` with this auth returns 16 bytes; empty password returns BAD_AUTH.
1. What do vendor properties `0x0..0x2` mean, and what drives property 1?
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
