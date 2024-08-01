// =============================================================================
// USES
// =============================================================================

use open_enum::open_enum;

// =============================================================================
// TYPE
// =============================================================================

// TPM2RC represents a TPM_RC.
// See definition in Part 2: Structures, section 6.6.
#[open_enum]
#[repr(u32)]
pub enum TPM2RC {
    Success = 0x00000000,
    // FMT0 error codes
    Initialize = TPM2RC::RC_VER_1,
    Failure = TPM2RC::RC_VER_1 + 0x001,
    Sequence = TPM2RC::RC_VER_1 + 0x003,
    Private = TPM2RC::RC_VER_1 + 0x00B,
    Hmac = TPM2RC::RC_VER_1 + 0x019,
    Disabled = TPM2RC::RC_VER_1 + 0x020,
    Exclusive = TPM2RC::RC_VER_1 + 0x021,
    AuthType = TPM2RC::RC_VER_1 + 0x024,
    AuthMissing = TPM2RC::RC_VER_1 + 0x025,
    Policy = TPM2RC::RC_VER_1 + 0x026,
    Pcr = TPM2RC::RC_VER_1 + 0x027,
    PCRChanged = TPM2RC::RC_VER_1 + 0x028,
    Upgrade = TPM2RC::RC_VER_1 + 0x02D,
    TooManyContexts = TPM2RC::RC_VER_1 + 0x02E,
    AuthUnavailable = TPM2RC::RC_VER_1 + 0x02F,
    Reboot = TPM2RC::RC_VER_1 + 0x030,
    Unbalanced = TPM2RC::RC_VER_1 + 0x031,
    CommandSize = TPM2RC::RC_VER_1 + 0x042,
    CommandCode = TPM2RC::RC_VER_1 + 0x043,
    AuthSize = TPM2RC::RC_VER_1 + 0x044,
    AuthContext = TPM2RC::RC_VER_1 + 0x045,
    NVRange = TPM2RC::RC_VER_1 + 0x046,
    NVSize = TPM2RC::RC_VER_1 + 0x047,
    NVLocked = TPM2RC::RC_VER_1 + 0x048,
    NVAuthorization = TPM2RC::RC_VER_1 + 0x049,
    NVUninitialized = TPM2RC::RC_VER_1 + 0x04A,
    NVSpace = TPM2RC::RC_VER_1 + 0x04B,
    NVDefined = TPM2RC::RC_VER_1 + 0x04C,
    BadContext = TPM2RC::RC_VER_1 + 0x050,
    CPHash = TPM2RC::RC_VER_1 + 0x051,
    Parent = TPM2RC::RC_VER_1 + 0x052,
    NeedsTest = TPM2RC::RC_VER_1 + 0x053,
    NoResult = TPM2RC::RC_VER_1 + 0x054,
    Sensitive = TPM2RC::RC_VER_1 + 0x055,
    // FMT1 error codes
    CAsymmetric = TPM2RC::RC_FMT_1 + 0x001,
    Attributes = TPM2RC::RC_FMT_1 + 0x002,
    Hash = TPM2RC::RC_FMT_1 + 0x003,
    Value = TPM2RC::RC_FMT_1 + 0x004,
    Hierarchy = TPM2RC::RC_FMT_1 + 0x005,
    KeySize = TPM2RC::RC_FMT_1 + 0x007,
    Mgf = TPM2RC::RC_FMT_1 + 0x008,
    Mode = TPM2RC::RC_FMT_1 + 0x009,
    Type = TPM2RC::RC_FMT_1 + 0x00A,
    Handle = TPM2RC::RC_FMT_1 + 0x00B,
    Kdf = TPM2RC::RC_FMT_1 + 0x00C,
    Range = TPM2RC::RC_FMT_1 + 0x00D,
    AuthFail = TPM2RC::RC_FMT_1 + 0x00E,
    Nonce = TPM2RC::RC_FMT_1 + 0x00F,
    PP = TPM2RC::RC_FMT_1 + 0x010,
    Scheme = TPM2RC::RC_FMT_1 + 0x012,
    Size = TPM2RC::RC_FMT_1 + 0x015,
    Symmetric = TPM2RC::RC_FMT_1 + 0x016,
    Tag = TPM2RC::RC_FMT_1 + 0x017,
    Selector = TPM2RC::RC_FMT_1 + 0x018,
    Insufficient = TPM2RC::RC_FMT_1 + 0x01A,
    Signature = TPM2RC::RC_FMT_1 + 0x01B,
    Key = TPM2RC::RC_FMT_1 + 0x01C,
    PolicyFail = TPM2RC::RC_FMT_1 + 0x01D,
    Integrity = TPM2RC::RC_FMT_1 + 0x01F,
    Ticket = TPM2RC::RC_FMT_1 + 0x020,
    ReservedBits = TPM2RC::RC_FMT_1 + 0x021,
    BadAuth = TPM2RC::RC_FMT_1 + 0x022,
    Expired = TPM2RC::RC_FMT_1 + 0x023,
    PolicyCC = TPM2RC::RC_FMT_1 + 0x024,
    Binding = TPM2RC::RC_FMT_1 + 0x025,
    Curve = TPM2RC::RC_FMT_1 + 0x026,
    ECCPoint = TPM2RC::RC_FMT_1 + 0x027,
    // Warnings
    ContextGap = TPM2RC::RC_WARN + 0x001,
    ObjectMemory = TPM2RC::RC_WARN + 0x002,
    SessionMemory = TPM2RC::RC_WARN + 0x003,
    Memory = TPM2RC::RC_WARN + 0x004,
    SessionHandles = TPM2RC::RC_WARN + 0x005,
    ObjectHandles = TPM2RC::RC_WARN + 0x006,
    Locality = TPM2RC::RC_WARN + 0x007,
    Yielded = TPM2RC::RC_WARN + 0x008,
    Canceled = TPM2RC::RC_WARN + 0x009,
    Testing = TPM2RC::RC_WARN + 0x00A,
    ReferenceH0 = TPM2RC::RC_WARN + 0x010,
    ReferenceH1 = TPM2RC::RC_WARN + 0x011,
    ReferenceH2 = TPM2RC::RC_WARN + 0x012,
    ReferenceH3 = TPM2RC::RC_WARN + 0x013,
    ReferenceH4 = TPM2RC::RC_WARN + 0x014,
    ReferenceH5 = TPM2RC::RC_WARN + 0x015,
    ReferenceH6 = TPM2RC::RC_WARN + 0x016,
    ReferenceS0 = TPM2RC::RC_WARN + 0x018,
    ReferenceS1 = TPM2RC::RC_WARN + 0x019,
    ReferenceS2 = TPM2RC::RC_WARN + 0x01A,
    ReferenceS3 = TPM2RC::RC_WARN + 0x01B,
    ReferenceS4 = TPM2RC::RC_WARN + 0x01C,
    ReferenceS5 = TPM2RC::RC_WARN + 0x01D,
    ReferenceS6 = TPM2RC::RC_WARN + 0x01E,
    NVRate = TPM2RC::RC_WARN + 0x020,
    Lockout = TPM2RC::RC_WARN + 0x021,
    Retry = TPM2RC::RC_WARN + 0x022,
    NVUnavailable = TPM2RC::RC_WARN + 0x023,
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl TPM2RC {
    pub const RC_VER_1: u32 = 0x00000100;
    pub const RC_FMT_1: u32 = 0x00000080;
    pub const RC_WARN: u32 = 0x00000900;
    pub const RC_P: u32 = 0x00000040;
    pub const RC_S: u32 = 0x00000800;
}
