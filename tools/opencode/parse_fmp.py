#!/usr/bin/env python3
"""Parse FMP capsules in IMAGEM47.ROM."""
import struct, re

def parse_fmp_capsule(data, offset):
    # FMP capsule header format (UEFI spec):
    # DWORD  CapsuleType (0x80000003 = UEFI FMP)
    # DWORD  CapsuleVersion
    # DWORD  CapsuleHeaderSize (always 0xEA0 for UEFI FMP)
    # DWORD  CapsuleFlags
    # GUID   CapsuleGuid
    # QWORD  CapsuleImageSize
    
    try:
        capsule_type = struct.unpack('>I', data[offset:offset+4])[0]
        capsule_version = struct.unpack('<I', data[offset+4:offset+8])[0]
        capsule_header_size = struct.unpack('<I', data[offset+8:offset+12])[0]
        capsule_flags = struct.unpack('<I', data[offset+12:offset+16])[0]
        capsule_guid = struct.unpack('<16s', data[offset+16:offset+32])[0]
        capsule_image_size = struct.unpack('<Q', data[offset+32:offset+40])[0]
    except Exception as e:
        print(f"  Error parsing header at offset {hex(offset)}: {e}")
        return
    
    print(f"Capsule at {hex(offset)}:")
    print(f"  Type: 0x{capsule_type:08X} {'(UEFI FMP)' if capsule_type == 0x80000003 else ''}")
    print(f"  Version: 0x{capsule_version:08X}")
    print(f"  Header Size: {capsule_header_size} (0x{capsule_header_size:04X})")
    print(f"  Flags: 0x{capsule_flags:08X}")
    print(f"  Guid: {capsule_guid}")
    print(f"  Image Size: {capsule_image_size} (0x{capsule_image_size:X})")
    
    # Check for Nuvoton NPCT75x
    if b'Nuvoton' in data[offset:offset+capsule_image_size] or b'NPCT75x' in data[offset:offset+capsule_image_size]:
        print(f"  *** CONTAINS NUVOTON NPCT75x ***")
    
    # Check for TPM firmware
    if b'TPM2' in data[offset:offset+capsule_image_size]:
        print(f"  *** CONTAINS TPM2 ***")
    
    # Try to find strings in the image
    image = data[offset+capsule_header_size:offset+capsule_header_size+capsule_image_size]
    print(f"  First 256 bytes:")
    for i in range(0, min(256, len(image)), 16):
        row = ' '.join(f'{b:02X}' for b in image[i:i+16])
        print(f"  {i:08X}: {row}")
    
    # Look for NPCT75x or Nuvoton strings
    strings = re.findall(rb'[ -~]{4,}', image)
    relevant_strings = [s.decode('ascii') for s in strings if b'NPCT' in s or b'Nuvoton' in s]
    if relevant_strings:
        print(f"  *** NUVOTON strings found: {relevant_strings[:10]} ***")
    elif b'AMD fTPM' in image:
        print(f"  *** AMD fTPM firmware (not NPCT75x) ***")
    elif b'TPM' in image:
        print(f"  *** Generic TPM ***")
    
    print()

def main():
    with open('/tmp/opencode/bios_extracted/IMAGEM47.ROM', 'rb') as f:
        data = f.read()
    
    # Check for FMP capsules
    print("Searching for UEFI FMP capsules...")
    fmp_offsets = []
    for offset in range(0, len(data)-12, 4):
        val = struct.unpack('>I', data[offset:offset+4])[0]
        if val == 0x80000003:  # UEFI FMP capsule
            fmp_offsets.append(offset)
    
    print(f"Found {len(fmp_offsets)} FMP capsules")
    for offset in fmp_offsets:
        parse_fmp_capsule(data, offset)

if __name__ == '__main__':
    main()