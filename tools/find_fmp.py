import sys

with open('/tmp/opencode/bios_extracted/IMAGEM47.ROM', 'rb') as f:
    data = f.read()

signature = b'TPM FMP H'
pos = data.find(signature)
if pos != -1:
    print(f'Found TPM FMP H signature at offset 0x{pos:x}')
    start = max(0, pos-32)
    end = min(len(data), pos+64)
    for i in range(start, end, 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[max(0, i):min(end, i+16)])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[max(0, i):min(end, i+16)])
        print(f'{i:08x}: {hex_part} | {ascii_part}')
    print(f'Found at offset 0x{pos:x}')
else:
    print("NOT FOUND")

# Also search for any FMP-related signatures
import re
patterns = [b'FMP', b'TPM', b'fTPM', b'PspFtpm', b'AMD fTPM']
for p in patterns:
    pos = data.find(p)
    if pos != -1:
        print(f"Found {p} at 0x{pos:x}")

# Search for PE header at various offsets
import struct

for offset in range(0, len(data)-0x400, 256):
    if data[offset:offset+4] == b'PE\x00\x00':
        print(f'PE header at 0x{offset:x}')
        break
else:
    print("No PE header found with PE\\x00\\x00")
