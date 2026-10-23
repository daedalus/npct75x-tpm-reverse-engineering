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

## 6. Open questions

1. What do vendor properties `0x0..0x2` mean, and what drives property 1?
2. What do vendor commands `0x20000200..0x20000216` do? Which are read-only?
3. Where does the TPM get its firmware? The working assumption is on-die
   flash in the NPCT75x package with no public read-back command, so the
   vendor BIOS/EC update is the practical source.
4. Which Lenovo package contains the TPM payload? Candidate: the ThinkCentre
   M75q Gen 2 Flash BIOS Update (`ds547344`, BIOS `M47KT33A`). The support
   page blocks plain fetches; a direct `download.lenovo.com` URL still needs
   verification.
5. Why is the BIOS measurement log empty? (Could be a firmware/OS policy,
   not necessarily a TPM property.)
6. Does `FIRMWARE_VERSION_2` combine with version 1 into a four-part
   version? Nuvoton's own updater naming would settle it.
