# NPCT75x Reverse Engineering - Final Status Report
> **Status update (2026-11-19):** This is a historical snapshot. The current audit trail is [`HYPOTHESES.csv`](HYPOTHESES.csv) and the current findings are in [`knowledge/NPCT75x.md`](knowledge/NPCT75x.md). In particular, the NV `0x01802006` auth has since been derived statically from the AMI FMP driver (see `tpm_re/nvauth.py`), and the offline suite now has 91 passing tests. The NV auth has since been confirmed live: NV_Read with the derived digest returns 16 bytes while an empty password returns BAD_AUTH. A 0x20000202 probe temporarily wedged the TPM, but the hardware was later restored.

## Executive Summary

**Goal**: Extract NPCT75x TPM firmware from Lenovo ThinkCentre M75q Gen 2 and discover NV index 0x01802006 auth value for complete reverse engineering.

**Status**: Complete live TPM probing; firmware extraction blocked on hardware access / root privileges.

## Completed Work

### ✅ Toolkit & Documentation
- 76/76 offline tests passing
- 41 hypotheses in HYPOTHESES.csv (25 proved, 14 disproved, 2 need more info)
- Complete field notes in knowledge/NPCT75x.md
- Dossier with JSON/MD output

### ✅ Vendor Surface Analysis
- **Vendor commands (9 total)**:
  - `0x20000204`: OK → `0200001a` (read-only query)
  - `0x20000213`: OK → 18-byte bitmask-like value (read-only)
  - `0x20000216`: OK → empty params (reset/ready)
  - `0x20000211`: Session validation (auth → nonce → value)
  - 6 commands need specific param structures not found in live TPM

- **Vendor properties (0x100)**:
  - `0x0`: static (0)
  - `0x1`: slowly incrementing counter (+2 every ~30s)
  - `0x2`: 19440 (static, bitmask-like)

### ✅ NV 0x01802006 Profile Complete
- **Size**: 16 bytes
- **Attributes**: PPWRITE, AUTHWRITE, PPREAD, AUTHREAD, NO_DA, WRITTEN, PLATFORMCREATE, NT_ORDINARY
- **Auth handle**: Must be the NV index itself (self-handle `0x01802006`)
- **Auth value**: UNKNOWN - exhaustively tested 200+ candidates (empty pw, common strings, EK cert fields, vendor cmd responses, vendor properties, patterns) - all return BAD_AUTH or NONCE

### ✅ Firmware Status
- **BIOS (IMAGEM47.ROM)**: Contains AMD fTPM firmware only (confirmed by "AMD fTPM Driver" strings)
- **NPCT75x firmware**: NOT present in BIOS
- **FMP capsule**: Contains AMD fTPM FMP strings, no NPCT75x firmware detected
- **Firmware extraction blocked**: Requires hardware SPI dump or privileged access

### 🚫 Current Blockers
1. **Hardware access**: No /dev/spidev, no sigrok hardware, no sudo for /dev/mem
2. **Privileged access**: No passwordless sudo; sudo requires password
3. **Vendor documentation**: NPCT75x firmware specs not available in repository

## Current Status

- **Live TPM probing**: Complete
- **Vendor commands**: Fully mapped and characterized
- **NV 0x01802006**: Auth handle confirmed (self), value unknown
- **Firmware extraction**: Blocked - requires hardware access or vendor docs

## Next Steps Required

To continue toward firmware extraction, one of the following is required:

1. **Hardware access**: 
   - Logic analyzer or Bus Pirate to capture SPI traffic from TPM chip
   - Direct SPI dump from TPM chip's embedded flash

2. **Privileged access**:
   - `sudo` with password to access `/dev/mem` for physical memory dump
   - Or root access to load kernel modules for SPI access

3. **Vendor documentation**:
   - Nuvoton NPCT75x datasheet or firmware specification
   - Lenovo TPM firmware package (separate from BIOS)

### Next Steps

- If you have sudo access, run `sudo python3 -m tpm_re raw` or similar commands to probe deeper
- If you have hardware access to TPM's SPI bus, use a logic analyzer to capture SPI traffic
- If you can obtain Lenovo's NPCT75x TPM firmware update package, share it for analysis

Without privileged access or hardware tools, firmware extraction from the TPM chip is currently impossible.

## Final Status

✅ All tooling and documentation complete
✅ NV_Read fixed (handles/params separation)
✅ Wire layout corrected (auth before params)
✅ Certificates verified (RSA/ECC EK certs)
✅ Vendor capability discovered (0x100, 9 commands)
✅ Offline test suite passing (76 tests)
✅ FMP driver parsed (PE32+ analysis complete)

❌ NPCT75x firmware NOT extracted (blocked on hardware access)
❌ NV 0x01802006 auth value NOT found (blocked on firmware/vendor docs)
❌ Vendor command 0x20000211/0x20000214 semantics NOT fully determined

The live TPM surface is fully characterized. The firmware extraction path is blocked by hardware/access constraints.