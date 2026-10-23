"""Tools for reverse engineering a local TPM 2.0.

The package is intentionally dependency-free and every TPM interaction is a
direct write to a character device, so that wire-level behaviour stays
observable.

Submodules:
    wire        TPM 2.0 marshalling, headers, response-code decoding
    transport   /dev/tpmX read/write with size-delimited framing
    caps        TPM2_GetCapability decoding and vendor-property discovery
    device      NV, PCR, event-log and EK-certificate queries
    acpi        ACPI TPM2 table and host inventory
    frames      decode captured TPM byte streams
    carve       locate candidate TPM firmware payloads in vendor images
    probe       assemble a dossier from all of the above
    cli         argparse front end
"""

__version__ = "0.1.0"
