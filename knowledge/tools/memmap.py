import struct

with open('/proc/kcore', 'rb') as f:
    hdr = f.read(64)
    e_phoff = struct.unpack_from('<Q', hdr, 32)[0]
    e_phentsize = struct.unpack_from('<H', hdr, 54)[0]
    e_phnum = struct.unpack_from('<H', hdr, 56)[0]

    f.seek(e_phoff)
    phs = []
    for i in range(e_phnum):
        ph = f.read(e_phentsize)
        if len(ph) < e_phentsize:
            break
        p_type = struct.unpack_from('<I', ph, 0)[0]
        p_flags = struct.unpack_from('<I', ph, 4)[0]
        p_offset = struct.unpack_from('<Q', ph, 8)[0]
        p_vaddr = struct.unpack_from('<Q', ph, 16)[0]
        p_paddr = struct.unpack_from('<Q', ph, 24)[0]
        p_filesz = struct.unpack_from('<Q', ph, 32)[0]
        p_memsz = struct.unpack_from('<Q', ph, 40)[0]
        phs.append((p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags))

target = 0xfed40000
for (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags) in phs:
    if p_type != 1: continue
    paddr_end = p_paddr + max(p_filesz, p_memsz)
    if p_paddr <= target < paddr_end:
        vaddr = p_vaddr + (target - p_paddr)
        f.seek(p_offset + (vaddr - p_vaddr))
        data = f.read(256)
        print(f"Found mapping: paddr={p_paddr:x}-{paddr_end:x}")
        print(f"  vaddr=0x{vaddr:x}")
        print(f"  data: {data.hex()}")
        print(f"  ascii: {''.join(chr(b) if 32<=b<127 else '.' for b in data)}")
        break
