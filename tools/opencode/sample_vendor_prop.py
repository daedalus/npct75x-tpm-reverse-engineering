#!/usr/bin/env python3
"""Sample vendor property 0x1 with ReadClock correlation."""
import sys
import time
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re import tables
from tpm_re.wire import build, Reader, u32, u16, u32be_to_str
from tpm_re.caps import _get

CC_READ_CLOCK = 0x00000181
CC_FIRMWARE_READ = 0x00000179

with DeviceTransport("/dev/tpmrm0") as t:
    for i in range(10):
        # Read vendor property 0x1
        data, more = _get(t, tables.CAP_VENDOR_PROPERTY, 1, 1)
        rd = Reader(data, label="TPML_TAGGED_TPM_PROPERTY")
        count = rd.u32()
        key = rd.u32() if count else 0
        value = rd.u32() if count else 0
        
        # Read clock
        resp = t.transceive(build(CC_READ_CLOCK))
        rd2 = Reader(resp.params, label="ReadClock")
        time_ms = rd2.u32()
        clock_ms = rd2.u32()
        reset_count = rd2.u32()
        restart_count = rd2.u32()
        safe = rd2.u8()
        
        print(f"sample {i}: prop0x1=0x{value:08X} ({value}) time={time_ms} clock={clock_ms} reset={reset_count} restart={restart_count} safe={safe}")
        time.sleep(1)