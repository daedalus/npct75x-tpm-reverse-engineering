"""Constant tables used to turn raw TPM 2.0 numbers into something readable.

Names follow TPM 2.0 Part 2.  Anything not listed is reported as a raw value
instead of being invented, so unknown vendor extensions stay visible.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# capabilities (TPM_CAP) -- used by TPM2_GetCapability
# --------------------------------------------------------------------------
CAP_ALGS = 0x00
CAP_HANDLES = 0x01
CAP_COMMANDS = 0x02
CAP_PP_COMMANDS = 0x03
CAP_AUDIT_COMMANDS = 0x04
CAP_PCRS = 0x05
CAP_TPM_PROPERTIES = 0x06
CAP_PCR_PROPERTIES = 0x07
CAP_ECC_CURVES = 0x08
CAP_AUTH_POLICIES = 0x09
CAP_ACT = 0x0A
CAP_VENDOR_PROPERTY = 0x100

CAP_NAMES = {
    CAP_ALGS: "ALGS",
    CAP_HANDLES: "HANDLES",
    CAP_COMMANDS: "COMMANDS",
    CAP_PP_COMMANDS: "PP_COMMANDS",
    CAP_AUDIT_COMMANDS: "AUDIT_COMMANDS",
    CAP_PCRS: "PCRS",
    CAP_TPM_PROPERTIES: "TPM_PROPERTIES",
    CAP_PCR_PROPERTIES: "PCR_PROPERTIES",
    CAP_ECC_CURVES: "ECC_CURVES",
    CAP_AUTH_POLICIES: "AUTH_POLICIES",
    CAP_ACT: "ACT",
    CAP_VENDOR_PROPERTY: "VENDOR_PROPERTY",
}

# --------------------------------------------------------------------------
# TPM_PT_* properties
# --------------------------------------------------------------------------
TPM_PT_NAMES = {
    0x100: "FAMILY_INDICATOR",
    0x101: "LEVEL",
    0x102: "REVISION",
    0x103: "DAY_OF_YEAR",
    0x104: "YEAR",
    0x105: "MANUFACTURER",
    0x106: "VENDOR_STRING_1",
    0x107: "VENDOR_STRING_2",
    0x108: "VENDOR_STRING_3",
    0x109: "VENDOR_STRING_4",
    0x10A: "VENDOR_TPM_TYPE",
    0x10B: "FIRMWARE_VERSION_1",
    0x10C: "FIRMWARE_VERSION_2",
    0x10D: "INPUT_BUFFER",
    0x10E: "HR_TRANSIENT_MIN",
    0x10F: "HR_PERSISTENT_MIN",
    0x110: "HR_LOADED_MIN",
    0x111: "ACTIVE_SESSIONS_MAX",
    0x112: "PCR_COUNT",
    0x113: "PCR_SELECT_MIN",
    0x114: "CONTEXT_GAP_MAX",
    0x116: "NV_COUNTERS_MAX",
    0x117: "NV_INDEX_MAX",
    0x118: "MEMORY",
    0x119: "CLOCK_UPDATE",
    0x11A: "CONTEXT_HASH",
    0x11B: "CONTEXT_SYM",
    0x11C: "CONTEXT_SYM_SIZE",
    0x11D: "ORDERLY_COUNT",
    0x11E: "MAX_COMMAND_SIZE",
    0x11F: "MAX_RESPONSE_SIZE",
    0x120: "MAX_DIGEST",
    0x121: "MAX_OBJECT_CONTEXT",
    0x122: "MAX_SESSION_CONTEXT",
    0x123: "PS_FAMILY_INDICATOR",
    0x124: "PS_LEVEL",
    0x125: "PS_REVISION",
    0x126: "PS_DAY_OF_YEAR",
    0x127: "PS_YEAR",
    0x128: "SPLIT_MAX",
    0x129: "TOTAL_COMMANDS",
    0x12A: "LIBRARY_COMMANDS",
    0x12B: "VENDOR_COMMANDS",
    0x12C: "NV_BUFFER_MAX",
    0x12D: "MODES",
    0x12E: "MAX_CAP_BUFFER",
    # variable
    0x200: "PERMANENT",
    0x201: "STARTUP_CLEAR",
    0x202: "HR_NV_INDEX",
    0x203: "HR_LOADED",
    0x204: "HR_LOADED_AVAIL",
    0x205: "HR_ACTIVE",
    0x206: "HR_ACTIVE_AVAIL",
    0x207: "HR_TRANSIENT_AVAIL",
    0x208: "HR_PERSISTENT",
    0x209: "HR_PERSISTENT_AVAIL",
    0x20A: "NV_COUNTERS",
    0x20B: "NV_COUNTERS_AVAIL",
    0x20C: "ALGORITHM_SET",
    0x20D: "LOADED_CURVES",
    0x20E: "LOCKOUT_COUNTER",
    0x20F: "MAX_AUTH_FAIL",
    0x210: "LOCKOUT_INTERVAL",
    0x211: "LOCKOUT_RECOVERY",
    0x212: "NV_WRITE_RECOVERY",
    0x213: "AUDIT_COUNTER_0",
    0x214: "AUDIT_COUNTER_1",
}

# Fixed properties whose value is four ASCII bytes rather than an integer.
PT_AS_STRING = {
    0x100: "FAMILY_INDICATOR",
    0x105: "MANUFACTURER",
    0x106: "VENDOR_STRING_1",
    0x107: "VENDOR_STRING_2",
    0x108: "VENDOR_STRING_3",
    0x109: "VENDOR_STRING_4",
}

# --------------------------------------------------------------------------
# algorithms
# --------------------------------------------------------------------------
ALG_NAMES = {
    0x0000: "ERROR",
    0x0001: "RSA",
    0x0003: "TDES",
    0x0004: "SHA1",
    0x0005: "HMAC",
    0x0006: "AES",
    0x0007: "MGF1",
    0x0008: "KEYEDHASH",
    0x0009: "XOR",
    0x000B: "SHA256",
    0x000C: "SHA384",
    0x000D: "SHA512",
    0x0010: "NULL",
    0x0012: "SM3_256",
    0x0013: "SM4",
    0x0014: "RSASSA",
    0x0015: "RSAES",
    0x0016: "RSAPSS",
    0x0017: "OAEP",
    0x0018: "ECDSA",
    0x0019: "ECDH",
    0x001A: "ECDAA",
    0x001B: "SM2",
    0x001C: "ECSCHNORR",
    0x001D: "ECMQV",
    0x0020: "KDF1_SP800_56A",
    0x0021: "KDF2",
    0x0022: "KDF1_SP800_108",
    0x0023: "ECC",
    0x0025: "SYMCIPHER",
    0x0026: "CAMELLIA",
    0x0040: "CTR",
    0x0041: "OFB",
    0x0042: "CBC",
    0x0043: "CFB",
    0x0044: "ECB",
}

# TPMA_ALGORITHM bits
ALG_ATTR_BITS = {
    0x0001: "asymmetric",
    0x0002: "symmetric",
    0x0004: "hash",
    0x0008: "object",
    0x0100: "signing",
    0x0200: "encrypting",
    0x0400: "method",
}

# algorithm -> digest length, for event-log and PCR decoding
DIGEST_LEN = {
    0x0004: 20,   # SHA1
    0x000B: 32,   # SHA256
    0x000C: 48,   # SHA384
    0x000D: 64,   # SHA512
    0x0012: 32,   # SM3_256
}

# --------------------------------------------------------------------------
# handle types (high byte of a TPM_HANDLE)
# --------------------------------------------------------------------------
HT_NAMES = {
    0x00: "PCR",
    0x01: "NV_INDEX",
    0x02: "HMAC_SESSION",
    0x03: "LOADED_SESSION",
    0x40: "PASSWORD_SESSION",
    0x80: "TRANSIENT",
    0x81: "PERSISTENT",
    0x90: "PERMANENT",
}

# NV index number space
NV_INDEX_RANGE = 0x01000000
NV_PLATFORM_RANGE = 0x01400000

# --------------------------------------------------------------------------
# TPMA_NV bits (TPM 2.0 Part 2, Table 28; TPM_NT occupies bits 4-7)
# --------------------------------------------------------------------------
NV_ATTR_BITS = {
    0x00000001: "PPWRITE",
    0x00000002: "OWNERWRITE",
    0x00000004: "AUTHWRITE",
    0x00000008: "POLICYWRITE",
    0x00000400: "POLICY_DELETE",
    0x00000800: "WRITELOCKED",
    0x00001000: "WRITEALL",
    0x00002000: "WRITEDEFINE",
    0x00004000: "WRITE_STCLEAR",
    0x00008000: "GLOBALLOCK",
    0x00010000: "PPREAD",
    0x00020000: "OWNERREAD",
    0x00040000: "AUTHREAD",
    0x00080000: "POLICYREAD",
    0x02000000: "NO_DA",
    0x04000000: "ORDERLY",
    0x08000000: "CLEAR_STCLEAR",
    0x10000000: "READLOCKED",
    0x20000000: "WRITTEN",
    0x40000000: "PLATFORMCREATE",
    0x80000000: "READ_STCLEAR",
}

NV_TYPE_MASK = 0xF0
NV_TYPE_NAMES = {
    0x0: "ORDINARY",
    0x1: "COUNTER",
    0x2: "BITS",
    0x3: "EXTEND",
    0x4: "PIN_FAIL",
    0x5: "PIN_PASS",
}


def decode_nv_attributes(value: int) -> list[str]:
    names = [name for bit, name in NV_ATTR_BITS.items() if value & bit]
    type_code = (value & NV_TYPE_MASK) >> 4
    names.append(f"NT_{NV_TYPE_NAMES.get(type_code, f'0x{type_code:X}')}")
    unknown = value & ~sum(NV_ATTR_BITS) & ~NV_TYPE_MASK
    if unknown:
        names.append(f"UNKNOWN_0x{unknown:08X}")
    return names

# --------------------------------------------------------------------------
# TPMA_PERMANENT / TPMA_STARTUP_CLEAR bit names
# --------------------------------------------------------------------------
PERMANENT_BITS = {
    0x00000001: "ownerAuthSet",
    0x00000002: "endorsementAuthSet",
    0x00000004: "lockoutAuthSet",
    0x00000100: "disableClear",
    0x00000200: "inLockout",
    0x00000400: "tpmGeneratedEPS",
}

STARTUP_CLEAR_BITS = {
    0x00000001: "phEnable",
    0x00000002: "shEnable",
    0x00000004: "ehEnable",
    0x00000008: "phEnableNV",
    0x80000000: "orderly",
}

# --------------------------------------------------------------------------
# command codes used by this toolkit
# --------------------------------------------------------------------------
CC_NV_READ_PUBLIC = 0x00000169
CC_NV_READ = 0x0000014E
CC_PCR_READ = 0x0000017E
CC_GET_CAPABILITY = 0x0000017A
CC_GET_RANDOM = 0x0000017B
CC_READ_PUBLIC = 0x00000173

# First command code in the TPM 2.0 assigned range (TPM_CC_FIRST); the
# starting point for GetCapability(TPM_CAP_COMMANDS).
TPM_CC_FIRST = 0x0000011F

# Command codes, used to tell a command frame from a response frame in a raw
# stream and to label captures.  These are best-effort names from the TPM 2.0
# Part 2 command table; every consumer must still print the raw code, and
# unknown codes are surfaced rather than guessed.
KNOWN_CC = {
    0x0000011F: "NV_UndefineSpaceSpecial",
    0x00000120: "EvictControl",
    0x00000121: "HierarchyControl",
    0x00000122: "NV_UndefineSpace",
    0x00000124: "ChangeEPS",
    0x00000125: "ChangePPS",
    0x00000126: "Clear",
    0x00000127: "ClearControl",
    0x00000128: "ClockSet",
    0x00000129: "HierarchyChangeAuth",
    0x0000012A: "NV_DefineSpace",
    0x0000012B: "PCR_Allocate",
    0x0000012C: "PCR_SetAuthPolicy",
    0x0000012D: "PP_Commands",
    0x0000012E: "SetPrimaryPolicy",
    0x0000012F: "FieldUpgradeStart",
    0x00000130: "ClockRateAdjust",
    0x00000131: "CreatePrimary",
    0x00000132: "NV_GlobalWriteLock",
    0x00000133: "GetCommandAuditDigest",
    0x00000134: "NV_Increment",
    0x00000135: "NV_SetBits",
    0x00000136: "NV_Extend",
    0x00000137: "NV_Write",
    0x00000138: "NV_WriteLock",
    0x00000139: "DictionaryAttackLockReset",
    0x0000013A: "DictionaryAttackParameters",
    0x0000013B: "NV_ChangeAuth",
    0x0000013C: "PCR_Event",
    0x0000013D: "PCR_Reset",
    0x0000013E: "SequenceComplete",
    0x0000013F: "SetAlgorithmSet",
    0x00000140: "SetCommandCodeAuditStatus",
    0x00000141: "FieldUpgradeData",
    0x00000142: "IncrementalSelfTest",
    0x00000143: "SelfTest",
    0x00000144: "Startup",
    0x00000145: "Shutdown",
    0x00000146: "StirRandom",
    0x00000147: "ActivateCredential",
    0x00000148: "Certify",
    0x00000149: "PolicyNV",
    0x0000014A: "CertifyCreation",
    0x0000014B: "Duplicate",
    0x0000014C: "GetTime",
    0x0000014D: "GetSessionAuditDigest",
    0x0000014E: "NV_Read",
    0x0000014F: "NV_ReadLock",
    0x00000150: "ObjectChangeAuth",
    0x00000151: "PolicySecret",
    0x00000152: "Rewrap",
    0x00000153: "Create",
    0x00000154: "ECDH_ZGen",
    0x00000155: "HMAC",
    0x00000156: "Import",
    0x00000157: "Load",
    0x00000158: "Quote",
    0x00000159: "RSA_Decrypt",
    0x0000015B: "HMAC_Start",
    0x0000015C: "SequenceUpdate",
    0x0000015D: "Sign",
    0x0000015E: "Unseal",
    0x00000160: "PolicySigned",
    0x00000161: "ContextLoad",
    0x00000162: "ContextSave",
    0x00000163: "ECDH_KeyGen",
    0x00000164: "EncryptDecrypt",
    0x00000165: "FlushContext",
    0x00000167: "LoadExternal",
    0x00000168: "MakeCredential",
    0x00000169: "NV_ReadPublic",
    0x0000016A: "PolicyAuthorize",
    0x0000016B: "PolicyAuthValue",
    0x0000016C: "PolicyCommandCode",
    0x0000016D: "PolicyCounterTimer",
    0x0000016E: "PolicyCpHash",
    0x0000016F: "PolicyLocality",
    0x00000170: "PolicyNameHash",
    0x00000171: "PolicyOR",
    0x00000172: "PolicyTicket",
    0x00000173: "ReadPublic",
    0x00000174: "RSA_Encrypt",
    0x00000176: "StartAuthSession",
    0x00000177: "VerifySignature",
    0x00000178: "ECC_Parameters",
    0x00000179: "FirmwareRead",
    0x0000017A: "GetCapability",
    0x0000017B: "GetRandom",
    0x0000017C: "GetTestResult",
    0x0000017D: "Hash",
    0x0000017E: "PCR_Read",
    0x0000017F: "PolicyPCR",
    0x00000180: "PolicyRestart",
    0x00000181: "ReadClock",
    0x00000182: "PCR_Extend",
    0x00000183: "PCR_SetAuthValue",
    0x00000184: "NV_Certify",
    0x00000185: "EventSequenceComplete",
    0x00000186: "HashSequenceStart",
    0x00000187: "PolicyPhysicalPresence",
    0x00000188: "PolicyDuplicationSelect",
    0x00000189: "PolicyGetDigest",
    0x0000018A: "TestParms",
    0x0000018B: "Commit",
    0x0000018C: "PolicyPassword",
    0x0000018D: "ZGen_2Phase",
    0x0000018E: "EC_Ephemeral",
    0x0000018F: "PolicyNvWritten",
    0x00000190: "PolicyTemplate",
    0x00000191: "CreateLoaded",
    0x00000192: "PolicyAuthorizeNV",
    0x00000193: "EncryptDecrypt2",
    0x00000194: "AC_GetCapability",
    0x00000195: "AC_Send",
    0x00000196: "Policy_AC_SendSelect",
    0x00000197: "CertifyX509",
    0x00000198: "ACT_SetTimeout",
}

# Vendor command space: TPM_CC_VENDOR_BIT (bit 29) set in the command code.
VENDOR_CC_MASK = 0x20000000


def describe_cc(cc: int) -> str:
    """Render a command code with its best-effort name."""
    name = KNOWN_CC.get(cc)
    if name:
        return name
    if cc & VENDOR_CC_MASK:
        return f"VENDOR_0x{cc:08X}"
    return f"UNKNOWN_0x{cc:08X}"
