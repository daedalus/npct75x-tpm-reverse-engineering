#!/usr/bin/env python3
import struct
import sys

try:
    with open('/sys/firmware/acpi/tables/TPM2', 'rb') as f:
        data = f.read()
    
    print(f"TPM2 table length: {len(data)} bytes")
    sig = data[0:4]
    hdr_len = struct.unpack('<I', data[4:8])[0]
    print(f"Signature: {sig}")
    print(f"HDR_LEN: {hdr_len}")
    
    # ACPI table header is 36 bytes, then TPM2 specific data
    # TPM2 table format (from ACPI spec):
    # offset 36: platform_class (1)
    # offset 37: reserved (3)
    # offset 40: reserved (4)
    # offset 44: control_address_base (8) - TPM base address!
    # offset 52: start_method (1)
    # offset 53: reserved (1)
    # offset 54: reserved (1)
    # offset 55: reserved (1)
    # offset 56: reserved (1)
    # offset 57: reserved (1)
    # offset 58: reserved (1)
    # offset 59: reserved (1)
    # offset 60: tpm_interface_type (1)
    # offset 61: reserved (3)
    # offset 64: gpio address (12)
    
    if len(data) >= 44:
        base_addr = struct.unpack('<Q', data[44:52])[0]
        start_method = data[52] if len(data) > 52 else 0
        interface_type = data[60] if len(data) > 60 else 0
        print(f"Control Address Base: 0x{base_addr:X}")
        print(f"Start Method: {start_method}")
        print(f"Interface Type: {interface_type} (0=FIFO, 1=CRB)")
    
    # Dump raw hex for manual inspection
    print("Raw data (first 80 bytes):")
    for i in range(0, min(80, len(data)), 16):
        print(f"  {i:04x}: {data[i:i+16].hex()}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()