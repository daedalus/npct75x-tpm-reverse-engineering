# Final Checkpoint Summary: Vendor Commands Probed, NV Auth Unknown, Firmware Not in BIOS

## Objective
Use REA to reverse engineer the actual hardware/firmware (Nuvoton NPCT75x) of the local TPM, not the kernel driver or tpm2-tools stack.

## Completed Work

### Device Profile
- **Device**: Nuvoton NPCT75x discrete TPM 2.0, firmware version 7.2 (ver1 `0x00070002`, ver2 `0x00020000`), spec 1.38
- **Interface**: ACPI `MSFT0101:00`, driver `tpm_tis`, `/dev/tpmrm0`; ACPI TPM2 table root-only
- **NV_Read Fixed**: Command layout corrected to `handles | authorizationSize + auth | params`; `device.nv_read` now works with handles/params separately
- **User access**: `dclavijo` in group `tss`, no sudo (password required)

### Wire Layout Corrected
- Command layout: `tag size cc | handles | authorizationSize + auth | params`  
- Responses: `paramSize | params | auth`
- GetCapability: `TPML_CCA` entries parsed as 4-byte `TPMA_CC` (cc in bits 0-15), not 8-byte pairs
- Vendor capability: `TPM_CAP_VENDOR_PROPERTY = 0x100` added to `tables.py`

### Certificates Verified
- **RSA**: 861 B, sha256 `4f05a5c51b8511c8da41e0cf790eebe76e3c8834df7d8f790dafcd3cb1ee57ff`
- **ECC**: 659 B, sha256 `1449381eec39287ef3089b337949db28ed8012ce23a9d7285c304c1b0ad99de5`
- **Issuer**: `CN=NPCTxxx ECC384 LeafCA 022110`, O=Nuvoton Technology Corporation, C=TW
- **Validity**: Oct 8 2023 → Oct 8 2043

### Vendor Surface Mapped (NEW)
- **Properties**: `0x0=0` (static), `0x1` slowly and irregularly incrementing (+2 every ~30s, not wall-clock), `0x2=0x00004BF0` (static, 19440)
- **Vendor commands (9 total)**:
  - `0x20000200` → VALUE (handle 1) with no session; BAD_AUTH (session 1) with auth
  - `0x20000201` → INSUFFICIENT (param 2) with handles+empty params; SIZE with any params
  - `0x20000202` → INSUFFICIENT (param 2) with handles+empty params; SIZE with params
  - `0x20000203` → INSUFFICIENT (param 1) with handles+empty params; SIZE with params
  - `0x20000204` → OK with `02 00 00 1A` (4 bytes), no handles
  - `0x20000211` → handle=0x4000000C + password session → BAD_AUTH (empty pw); NONCE (non-empty pw); ATTRIBUTES (PP attrs); VALUE (owner/platform/endorsement session). **Needs specific session/auth that we have not found.**
  - `0x20000213` → OK with 18 bytes `ffffa700fbff7ffffbfffffffbf0ffffaaaa`, no handles
  - `0x20000214` → SIZE with handle 0x4000000C; INSUFFICIENT (param 1) with no handle; BAD_AUTH (session 1) with auth
  - `0x20000216` → OK with empty params, no handles

### Firmware Acquisition Status
- **Lenovo BIOS package** `m47jt3eusa.zip` downloaded and extracted → `IMAGEM47.ROM` (16 MiB)
- **NPCT75x firmware NOT found as raw binary** in ROM; BIOS contains AMD fTPM firmware only (confirmed by "AMD fTPM Driver", "PspFtpmHandler" strings)
- **FMP driver**: `obj_2_FirmwareVolume_7155752.bin/.../section1.pe` (44480 bytes) contains `"TPM FMP H"` strings, confirms FMP capsule handling in BIOS
- **Firmware extraction**: Not done; requires REA `inspect_firmware_regions` tooling or hardware SPI dump

### NV 0x01802006 Status
- **Index**: 16 bytes, attrs `PPWRITE, AUTHWRITE, PPREAD, AUTHREAD, NO_DA, WRITTEN, PLATFORMCREATE, NT_ORDINARY`
- **Auth handle**: MUST be the NV index itself (`0x01802006`) due to AUTHREAD attribute. Owner/platform/endorsement handles are rejected (NV_AUTHORIZATION or VALUE)
- **Auth value**: STILL UNKNOWN. Tested:
  - Empty password (BAD_AUTH)
  - Common strings: TPM, platform, owner, Nuvoton, NPCT75x, Lenovo, ThinkCentre, M75q, Gen 2, 7.2, 00070002, 00020000 (all NONCE or BAD_AUTH)
  - EK cert issuer: NPCTxxx, ECC384, LeafCA, 022110 (NONCE)
  - Vendor cmd 0x20000213 params (18 bytes) (NONCE)
  - Vendor cmd 0x20000204 params (4 bytes) (NONCE)
  - Vendor cmd 0x20000216 params (empty) (BAD_AUTH)
  - Vendor property 0x1 value (1833493) in various encodings (NONCE)
  - 16-byte patterns (0x00, 0xFF, 0x55, 0xAA) (NONCE)
  - Short passwords: 0, 1, password, auth (NONCE)
  - **Conclusion**: The auth value is manufacturer-configured, NOT derivable from the live TPM data we have access to. It requires firmware extraction or Nuvoton documentation.

### Remaining
- Firmware acquisition: requires hardware SPI dump (no /dev/spidev, no sigrok hardware, no sudo for /dev/mem)
- NV 0x01802006 auth value: requires firmware or vendor documentation
- Vendor command 0x20000211 semantics: requires vendor documentation (it validates sessions in a specific order: auth → nonce → value)
- Vendor commands 0x20000200/02/03/04/14: semantics unknown; param structures not yet found

## Final Status
✅ All tooling and documentation complete  
✅ NV_Read fixed (handles/params separation)  
✅ Wire layout corrected (auth before params)  
✅ Certificates verified (RSA/ECC EK certs)  
✅ Vendor capability discovered (0x100, 9 commands, properties 0x0..0x2)  
✅ Vendor commands probed and characterized (3 OK with fixed responses, 6 need specific inputs)  
✅ Offline test suite passing (76 tests)  
✅ Dossier complete with JSON/MD  
✅ FMP driver parsed (PE32+ analysis complete)  
✅ BIOS contains AMD fTPM only (not NPCT75x)  

❌ NPCT75x firmware NOT extracted (blocked on hardware access)  
❌ NV 0x01802006 auth value NOT found (blocked on firmware/vendor docs)  
❌ Vendor command 0x20000211/0x20000214 semantics NOT fully determined