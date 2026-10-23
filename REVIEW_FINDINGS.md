# Code review findings (2026-10-23)

This was a full review of `tpm_re/`, `tools/`, `tests/` and the docs at
commit `06f82f7`. Each finding gives its location, what was wrong, what it
broke, and how it was fixed. All findings are fixed on branch
`claude/zealous-hawking-3biu2l`.

At review time all 60 tests passed. Several findings went unnoticed because
the tests built their fixtures with the same wrong assumption as the code
(big-endian ACPI and event-log fixtures, and response-code expectations
copied from the wrong table). Those tests were corrected rather than kept.

Severity:

* **High**: wrong results on real hardware.
* **Medium**: unsafe behaviour, or wrong or incomplete output in common use.
* **Low**: edge cases and cleanups.

## Summary

| # | Sev. | Area | Finding |
| --- | --- | --- | --- |
| 1 | High | `acpi.py` | ACPI TPM2 table parsed big-endian |
| 2 | High | `device.py` | TCG event log parsed big-endian |
| 3 | High | `wire.py` | Format-0 response-code table numbered sequentially, not per spec |
| 4 | High | `wire.py` | `decode_rc` ignored the format-1 P bit |
| 5 | High | `caps.py`, docs | Vendor command codes lost the `TPMA_CC.V` bit |
| 6 | Medium | `device.py`, `cli.py` | "Read-only" `nv --index` could increment the DA lockout counter |
| 7 | Medium | `device.py`, `cli.py` | `pcrs` silently truncated to 8 digests and printed them unlabelled |
| 8 | Medium | `frames.py` | Error responses misclassified as commands; strace direction discarded; `[pid N]` lines missed |
| 9 | Medium | `carve.py` | Container scan blinded by `MZ` noise; FDT magic labelled as capsule; window hash did not match extracted file |
| 10 | Medium | `cli.py`, `device.py` | Device failures crashed with a traceback |
| 11 | Low | `cli.py` | `raw --cc --handles` without `--password` dropped the handles |
| 12 | Low | `tables.py` | `orderly` mapped to bit 4 instead of bit 31 |
| 13 | Low | `transport.py` | Read timeout could never fire |
| 14 | Low | `device.py` | `nv_dump` used a fixed 1 KiB chunk instead of `NV_BUFFER_MAX` |
| 15 | Low | `caps.py` | `handles()` did not page; `properties(start=)` ignored its argument |
| 16 | Low | `probe.py`, `carve.py` | Dead code in `probe.write`; `scan_path` read files twice |
| 17 | Low | `tools/sigrok_to_frames.py` | Default output could overwrite the input |
| 18 | Low | `frames.py` | Hex input: odd `0x…` line raised; xxd ASCII column parsed as data |
| 19 | Low | `cli.py` | `selftest` relied on `assert` (skipped under `python -O`) |
| 20 | Low | `.gitignore` | Ineffective and stray patterns |
| 21 | Docs | `CHECKPOINT_SUMMARY.md`, `README.md`, `knowledge/` | Contradictions and claims that no longer held |

## Details

### 1. ACPI TPM2 table parsed big-endian (High)

`tpm_re/acpi.py`, `parse_tpm2_table`.

ACPI tables are little-endian. Length, platform class, control-area address
and start method were read as big-endian. On real firmware, start method 6
read as `0x06000000` and was reported as "unrecognised", and the
header-length check failed on every table. The test fixture was built
big-endian too, so the test passed.

**Fix:** all fields are now read little-endian. The fixture is
little-endian, and `test_fields_are_little_endian` checks the raw bytes of
start method 6.

### 2. TCG event log parsed big-endian (High)

`tpm_re/device.py`, `parse_event_log`.

UEFI writes the event log little-endian. PCR index, event type, digest
count, algorithm IDs and event size were all read big-endian. On any real
`binary_bios_measurements` file, PCR and type values came out as garbage,
and the agile/legacy detection fell back to the legacy layout.

**Fix:** the parser reads little-endian. The test fixtures were converted.

### 3. Format-0 response-code table did not match the spec (High)

`tpm_re/wire.py`, `_RC_FORMAT0`.

Codes `0x100…0x11E` were numbered one after another, but TPM 2.0 Part 2
Table 16 is sparse. Examples:

* `0x103` is `SEQUENCE` (it was decoded as `PRIVATE`).
* `0x127` is `PCR` (the old table put it at `0x10A`).
* `0x149` is `NV_AUTHORIZATION` and `0x14C` is `NV_DEFINED`; both were
  `UNMAPPED`.

The table also invented warnings `0x924–0x926` and `REFERENCE_H7`
(`0x917`). Every error a user saw from a real TPM could be mislabelled.

**Fix:** the table was rewritten from Part 2. `REFERENCE_H0..H6` is
`0x910..0x916` and `REFERENCE_S0..S6` is `0x918..0x91E`, and `NOT_USED`
(`0x97F`) was added. The tests now check the sparse values.

### 4. `decode_rc` ignored the P bit (High)

`tpm_re/wire.py`, `decode_rc`.

In format 1, bit 6 (P) means N is a parameter number. Otherwise, N 1–7 is a
handle and N 8–15 is a session. The lookup used `rc & 0xFF`, so any code
with P set (for example `0x1D5`, `SIZE` on parameter 1) became `UNMAPPED`.
Handle errors were also reported vaguely as "parameter/handle".

**Fix:** the base code is now looked up by `0x080 | (rc & 0x3F)`, and the
result is reported as `parameter N`, `handle N` or `session N`. `selftest`
covers both the session and the parameter case.

### 5. Vendor command codes lost the V bit (High)

`tpm_re/caps.py`, `commands()`; `knowledge/NPCT75x.md` §2, §4.2;
`CHECKPOINT_SUMMARY.md`.

`cc = attrs & 0xFFFF` dropped `TPMA_CC.V` (bit 29). This had several
effects:

* The NPCT75x vendor commands were recorded as `0x00000200…`, but on the
  wire they are `0x20000200…`.
* `describe_cc` labelled them `UNKNOWN_` instead of `VENDOR_`.
* Deduplication could merge a vendor index with a library code.
* The docs reasoned from the stripped value ("outside `TPM_CC_FIRST`").
* Any future attempt to send the recorded codes would have sent the wrong
  command.

**Fix:** the code is now `commandIndex | (attrs & 0x20000000)`. The test
expects `0x200000FF` / `VENDOR_0x200000FF`. The docs list
`0x20000200..0x20000216` and explain the derivation.

### 6. NV read could increment the DA lockout counter (Medium)

`tpm_re/device.py`, `nv_dump`; `tpm_re/cli.py`, `nv`.

`nv --index X` always sent `NV_Read` with an empty password. If the index
lacks `TPMA_NV_NO_DA` and its auth value is not empty, each attempt
increments the dictionary-attack failure counter, and repeated runs can
lock the TPM out. That contradicted the README's read-only claim.

**Fix:** a new `nv_read_hazard()` check runs after `NV_ReadPublic`.
`nv_dump` raises `DeviceError` before sending `NV_Read` unless the index is
`NO_DA` or the user passes `--allow-da`. The README's safety model now
documents this, and notes that `raw` does not apply the check. Tested by
`NvSafetyTests`.

### 7. `pcrs` truncated and unlabelled (Medium)

`tpm_re/device.py`, `pcr_read`; `tpm_re/cli.py`, `pcrs`.

One `PCR_Read` returns at most eight digests. `--indices 0-23` silently
returned 8 hashes, printed without the PCR each belonged to.

**Fix:** `pcr_read` repeats the command until every requested PCR is
returned. Each digest is labelled from the returned `pcrSelectionOut`.
PCRs the TPM never returns (for example an unallocated bank) are listed as
`missing`, and `counter_changed` flags a PCR update between calls. The CLI
prints `sha256[ 7] <digest>` lines. The return value keeps the `digests`
key for compatibility.

### 8. Frame classification and strace parsing (Medium)

`tpm_re/frames.py`, `tpm_re/cli.py`, `frames`.

* Format-0 response codes `0x11F–0x155` overlap command codes, so a
  10-byte `NV_DEFINED` (`0x14C`) response was decoded as `GetTime`.
* `parse_strace` knew each transfer's direction (write = command, read =
  response) but threw it away.
* `strace -f` lines prefixed with `[pid N]`, and calls split into
  `<unfinished ...>` / `<... read resumed>`, were skipped.

**Fix:**

* New `parse_strace_segments` keeps the direction, handles both pid prefix
  styles, and matches resumed reads to their pending call.
* New `split_strace_frames` joins consecutive same-direction transfers and
  assigns the role from the direction. `frames --strace` uses it when
  `--role auto`.
* For non-strace input, a code that is both a known command and a known
  response code is settled by command/response alternation.

`parse_strace` keeps its old signature.

### 9. Carving on real ROM images (Medium)

`tpm_re/carve.py`.

* `find_container` returned as soon as it had collected 65 hits in total.
  On a 16 MiB ROM, `MZ` alone used that up, so firmware-volume and capsule
  hits were never reported, and the early return skipped sorting.
* `\xd0\x0d\xfe\xed` is the flattened-device-tree magic, but it was
  labelled "UEFI capsule / FMP".
* `sha256_window` hashed `[marker, end)`, while `--extract` wrote
  `[marker - 0x100, end)`, so the recorded hash never matched the
  extracted file.

**Fix:**

* The hit limit (64) now applies per signature, and the result is always
  sorted.
* Detection of the FMP capsule GUID (`6DCBD5ED-E82D-4C44-BDA1-7194199AD92A`)
  was added, and the FDT magic is labelled as FDT.
* Entropy, strings and hash all cover exactly the extracted window.

All three are covered by tests.

### 10. Tracebacks on device errors (Medium)

`tpm_re/cli.py`, `main`; `tpm_re/device.py`.

`device` raised a bare `RuntimeError`, and `pcr_read` a `ValueError`, but
`main` caught only transport, wire and capability errors. For example,
`nv --index 0x01802006` crashed with a traceback.

**Fix:** a new `device.DeviceError` type. `main` also catches it, plus
`ValueError` and `OSError` (such as a missing input file), and prints an
`error:` line with exit code 1.

### 11. `raw --handles` ignored without `--password` (Low)

`tpm_re/cli.py`, `cmd_raw`.

Without `--password`, `--handles` was silently dropped, so
`raw --cc 0x169 --handles 01c00002` sent an `NV_ReadPublic` with no handle.

**Fix:** the handle bytes are now passed through to `build`.

### 12. `orderly` bit (Low)

`tpm_re/tables.py`, `STARTUP_CLEAR_BITS`.

`TPMA_STARTUP_CLEAR.orderly` is bit 31 (`0x80000000`), not `0x10`.

**Fix:** corrected.

### 13. Transport timeout never fired (Low)

`tpm_re/transport.py`.

The deadline was checked only after a blocking `os.read` returned, so a
hung device blocked forever.

**Fix:** `select.select` with the remaining time now runs before each read.

### 14. NV chunk size (Low)

`tpm_re/device.py`, `nv_dump`.

A fixed 1024-byte chunk fails on TPMs with a smaller `NV_BUFFER_MAX`.

**Fix:** `nv_dump` reads `TPM_PT_NV_BUFFER_MAX` with one `GetCapability`
call, falling back to 64 bytes if that fails. The chunk can still be passed
explicitly.

### 15. Capability paging gaps (Low)

`tpm_re/caps.py`.

`handles()` read a single page, so more than 64 NV indices were silently
truncated. `properties()` accepted a `start` argument it never used.

**Fix:** `handles()` follows `moreData` and accepts only handles in
increasing order. The unused argument was removed.

### 16. Dead code and double reads (Low)

* `probe.write` built a certificate list and then deleted it. Removed.
* `carve.scan_path` read every file twice. It now reads each file once.
  The `scan_file` helper had no remaining users and was removed.

### 17. sigrok tool could overwrite its input (Low)

`tools/sigrok_to_frames.py`.

The default output `<input>.with_suffix(".bin")` is the input itself when
the input is already `*.bin`.

**Fix:** in that case the output becomes `<input>.frames.bin`.

### 18. Hex input edge cases (Low)

`tpm_re/frames.py`, `parse_hexdump_text`.

* A `0x…` line with an odd number of digits raised an uncaught
  `ValueError`.
* xxd's ASCII column was not removed, so hex-looking text in it (such as
  `dead`) was parsed as bytes.

**Fix:** odd digit counts are left-padded, and for xxd-style (`offset:`)
lines everything after the first run of two or more spaces is dropped.

### 19. `selftest` used `assert` (Low)

`tpm_re/cli.py`.

`python -O` removes `assert` statements, so the self-test always passed
under `-O`.

**Fix:** explicit checks that report the names of failing checks and exit
with 1.

### 20. `.gitignore` (Low)

* `/tmp/opencode/tpmre/` is resolved relative to the repo root, so it
  matched nothing.
* `section1.pe` was already covered by `*.pe`.
* `git/` and `git-` looked accidental.

**Fix:** all four removed. `out/` was added, the evidence directory the
README's `probe --out out/` writes to.

### 21. Documentation (Docs)

* `CHECKPOINT_SUMMARY.md` reported both "60 tests" and "53+ tests"; the
  counts were replaced with the command to run the suite.
* It recorded vendor property 1 as `0x001AD0F2`, while the field notes
  record `0x001AD0A0…A6`. Because the property increments, both values are
  now kept, and the sample time of `0x001AD0F2` is marked unknown.
* It said NV `0x01802006` "requires auth", while the field notes say only
  that its contents were not interpreted. The summary now flags this as
  **unconfirmed**. Someone with the hardware needs to settle it.
* REA is now described as an external tool that is not in this
  repository.
* The README's safety model now mentions the DA-lockout guard. Its design
  notes record the endianness and V-bit lessons, and the knowledge file's
  wire-lessons section adds them along with PCR paging.

## Verification

* `python3 -m unittest discover -s tests -t .`: 76 tests, all passing (60
  before; corrected tests plus new regression tests for findings 1–9, 14
  and 15).
* `python3 -m tpm_re selftest`: ok.
* `frames --strace` was smoke-tested on a synthetic `[pid N]` trace in
  which an `NV_DefineSpace` command is followed by an `NV_DEFINED`
  response.
* Not verified: no TPM was available in the review environment, so nothing
  was re-run against the NPCT75x. Before relying on the fixed ACPI and
  event-log parsers, re-run `acpi` (as root), `pcrs --indices 0-23` and
  `caps` on the target machine.
