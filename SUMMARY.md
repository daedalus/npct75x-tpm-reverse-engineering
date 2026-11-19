# Reverse Engineering Status — Nuvoton NPCT75x TPM
> **Status update (2026-11-19):** This is a historical snapshot. The current audit trail is [`HYPOTHESES.csv`](HYPOTHESES.csv) and the current findings are in [`knowledge/NPCT75x.md`](knowledge/NPCT75x.md). In particular, the NV `0x01802006` auth has since been derived statically from the AMI FMP driver (see `tpm_re/nvauth.py`), and the offline suite now has 91 passing tests. Live validation remains deferred: no reboot, no TPM writes.

## Completed ✅

| Item | Result |
|------|--------|
| Offline test suite | **76/76 tests pass** (`python3 -m unittest discover -s tests -t .`) |
| CLI `selftest` | Passes |
| Wire layout fix | Command format corrected: `tag size cc | handles | authorizationSize + auth | params`; responses: `paramSize | params | authArea` |
| NV_Read fixed | Handles/params separation prevents NoneType crash |
| Certificates verified | RSA EK (861 B) & ECC EK (659 B) read with empty password |
| Vendor capability discovered | `CAP_VENDOR_PROPERTY=0x100`, properties 0, 1, 2; 9 vendor commands |
| Vendor property 0x1 sampling | Increments by **+2 every ~30s**, independent of wall-clock time (clock tracks ~2969ms/sample). Irregular, likely internal counter/timer. |
| Vendor commands 0x20000204/0x20000213/0x20000216 | Return OK with empty params (read-only queries); e.g., `0x20000204→02 00 00 1A`. |
| Vendor commands 0x20000200/0x20000211 | Always fail with rc=0x0184 (VALUE) regardless of handle/param combos tested. |
| Vendor commands do NOT break TPM state | Subsequent NV_ReadPublic stays OK after failing vendor calls. |

## Key Hypothesis Results (HYPOTHESES.csv)

### Proved ✅
- **Vendor property 0x1**: monotonically increasing counter, +2 per ~30s, not wall-clock.
- **Vendor commands 0x20000204/0x20000213/0x20000216**: read-only queries returning OK with empty params.
- **Vendor commands 0x20000200/0x20000211**: require 1 handle + param → always VALUE error.
- **Vendor commands 0x20000201/02/03/04/13/14/16**: no handles needed; some need params (INSUFFICIENT).
- **Running vendor commands does not corrupt TPM state**.
- **NV_ReadPublic works fine with empty auth_policy** (no NoneType bug).

### Disproved ❌
- NV 0x01802006 readable with empty password → BAD_AUTH (session 1).
- NV 0x01802006 accepts common auth values (empty, strings, single bytes) → all BAD_AUTH.
- Vendor property 0x00000001 static over long session (1833459→1833461, +2 every ~30s).
- FirmwareRead (0x179) NOT advertised (only 113 commands = 104 lib + 9 vendor).
- NV_ReadPublic fails when auth_policy is empty (bug was traced to my script misuse, not real hardware).

### Need More Info ⏳
- **NV 0x01802006 auth value**: Manufacturer-configured, not discoverable from public data. Requires firmware extraction or Nuvoton docs.
- **Firmware extraction**: BIOS (M47KT33A) contains ONLY AMD fTPM firmware, NOT NPCT75x discrete TPM firmware. NPCT75x firmware is separate, delivered via UEFI FMP capsule (TpmFmpUefiDrv module). External REA tooling required.
- **Vendor cmd 0x20000214**: Exhausted 8 handles × 9 params → never returned OK. Specific handle unknown.
- **Vendor cmd 0x20000201/02/03/04**: Need parameter structures (INSUFFICIENT for empty params, VALUE for non-empty).

## What We Downloaded

- Lenovo BIOS package `m47jt3eusa.zip` (11 MB, SHA-256 `3b122dac...cb3ad67`)
- Extracted to `/tmp/opencode/bios_extracted/`
- Contains: AMD fTPM driver, TPM2_Create/Load/Import/etc., NVStorage_SetTpmNvconfig, PspFtpmHandler
- **Does NOT contain** Nuvoton NPCT75x firmware (AMD fTPM only)

## Remaining Open Questions

1. **NV 0x01802006 auth value** — manufacturer-configured, needs firmware or vendor docs
2. **NPCT75x firmware** — not in BIOS; requires FMP capsule parsing (REA tools, node_modules missing)
3. **Vendor command semantics** — 6 of 9 codes' behavior unknown without firmware
4. **Vendor cmd 0x20000214** — specific handle not yet identified

## Next Steps (Recommended)

1. Attempt firmware extraction from IMAGEM47.ROM using REA `inspect_firmware_regions`/`inspect_binary_layout` (external tool)
2. Try downloading NPCT75x firmware from Nuvoton support site (URL known: `ds547344`, M47KT33A)
3. Investigate vendor command 0x20000214 handle value (try TPM_RH_NULL, TPM_RH_EK, etc.)
4. Derive NV 0x01802006 auth from EK certificate issuer string or vendor property values once firmware available

## Files

- HYPOTHESES.csv — audit trail (14 rows)
- tpm_re/{device.py,caps.py,wire.py,tables.py,carve.py,transport.py,re}/ — codebase
- knowledge/NPCT75x.md — field notes
- CHECKPOINT_SUMMARY.md — final checkpoint
