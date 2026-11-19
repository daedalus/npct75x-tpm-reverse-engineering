#!/usr/bin/env python3
"""Long sampling of vendor property 0x1 with ReadClock correlation."""
import sys, time
sys.path.insert(0, "/home/dclavijo/my_code/npct75x-tpm-reverse-engineering")
from tpm_re.transport import DeviceTransport
from tpm_re.wire import build, u32
from tpm_re import tables
from tpm_re import caps
from tpm_re.device import nv_read_public

with DeviceTransport("/dev/tpmrm0") as t:
    print("Long sampling: vendor property 0x1 + ReadClock correlation (60s)")
    samples = []
    start = time.time()
    for i in range(20):  # 20 samples over 60s
        data, more = caps._get(t, tables.CAP_VENDOR_PROPERTY, 1, 0x40)
        rd = caps.Reader(data, label="TPML_TAGGED_TPM_PROPERTY")
        count = rd.u32()
        key = rd.u32()
        val = rd.u32()
        resp = t.transceive(build(0x00000181))  # ReadClock
        rd2 = caps.Reader(resp.params, label="ReadClock")
        time_ms = rd2.u32()
        clock_ms = rd2.u32()
        samples.append((i, key, val, time_ms, clock_ms))
        print(f"  sample {i}: prop=0x{key:08X} val=0x{val:08X} ({val}) time={time_ms} clock={clock_ms}")
        time.sleep(3)
    
    print("\nTotal elapsed:", time.time() - start)
    print("Samples:")
    for s in samples:
        print(f"  {s}")
