#!/usr/bin/env python3
import mmap, re

CHUNK = 64 * 1024 * 1024  # 64MB chunks
TOTAL_SCAN = 2 * 1024 * 1024 * 1024  # 2GB

with open('/proc/kcore', 'rb') as f:
    for start in range(0, TOTAL_SCAN, CHUNK):
        f.seek(start)
        chunk = f.read(CHUNK)
        if not chunk:
            break
        for pattern in [b'NPCT', b'Nuvoton', b'NUVOTON', b'nvton', b'TPM_FW', b'firmware']:
            idx = chunk.find(pattern)
            if idx != -1:
                pos = start + idx
                context = chunk[max(0,idx-32):idx+64]
                print(f"Pattern {pattern} at file offset {pos:#x}: {context.hex()[:80]}...")
        # Progress
        if (start // CHUNK) % 10 == 0:
            print(f"  scanned {start//1024//1024} MB...")

print("Done scanning first 2GB.")