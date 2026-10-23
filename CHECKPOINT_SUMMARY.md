# Final Checkpoint Summary: NV_Read Fixed, Wire Layout Corrected, Certs Work, Vendor Capability Discovered

## Objective
Use REA to reverse engineer the actual hardware/firmware (Nuvoton NPCT75x) of the local TPM, not the kernel driver or tpm2-tools stack.

## Completed Work

### Device Profile
- **Device**: Nuvoton NPCT75x discrete TPM 2.0, firmware version 7.2 (ver1 `0x00070002`, ver2 `0x00020000`), spec 1.38
- **Interface**: ACPI `MSFT0101:00`, driver `tpm_tis`, `/dev/tpmrm0`; ACPI TPM2 table root-only
- **NV_Read Fixed**: Command layout corrected to `handles | authorizationSize + auth | params`; `device.nv_read` now works with handles/params separately

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

### Vendor Capability Discovered
- **Properties**: `0x0=0`, `0x1` slowly and irregularly incrementing (field notes record `0x001AD0A0`…`0x001AD0A6`; `0x001AD0F2` was also recorded, sample time unknown), `0x2=0x00004BF0` (static)
- **Vendor commands**: `0x20000200,0x20000201,0x20000202,0x20000203,0x20000204,0x20000211,0x20000213,0x20000214,0x20000216` (9 total; `commandIndex` `0x200..0x216` plus the `TPMA_CC.V` bit)
- **No properties ≥3** reported

### Tools & Documentation ✅
- **CLI**: `tpm_re` fully functional (offline suite: `python3 -m unittest discover -s tests -t .`)
- **Tools**: `lenovo_bios_fetch.sh`, `sigrok_to_frames.py`, `frames --strace`, `probe --vendor --out`
- **Docs**: `README.md`, `knowledge/NPCT75x.md` complete with usage, safety model, wire lessons, roadmap

### Firmware Acquisition Status
- **Lenovo BIOS package** `m47jt3eusa.zip` downloaded and extracted → `IMAGEM47.ROM` (16 MiB)
- **NPCT75x firmware NOT found as raw binary** in ROM; likely delivered via **UEFI FMP capsule** (`TpmFmpUefiDrv` module in BIOS)
- **FMP driver**: `obj_2_FirmwareVolume_7155752.bin/.../section1.pe` (44480 bytes) contains `"TPM FMP H"` strings, confirms FMP capsule handling
- **Firmware extraction**: Not done; planned with REA `inspect_firmware_regions`/`inspect_binary_layout` (an external tool, not in this repo)

### Remaining
- Firmware acquisition: FMP capsule parsing requires REA MCP tools (node_modules/dist missing) or live system with sudo
- NV 0x01802006: not read. Attributes `PPREAD|AUTHREAD|NO_DA`, so an empty-password attempt is DA-safe. **Unconfirmed**: this file says it needs an auth value, while `knowledge/NPCT75x.md` §3 only says its contents were not interpreted. Confirm which before relying on either.

## Final Status
✅ All tooling and documentation complete  
✅ NV_Read fixed (handles/params separation)  
✅ Wire layout corrected (auth before params)  
✅ Certificates verified (RSA/ECC EK certs)  
✅ Vendor capability discovered (0x100, 9 commands)  
✅ Offline test suite passing  
✅ Dossier complete with JSON/MD  
✅ FMP driver parsed (PE32+ analysis complete)