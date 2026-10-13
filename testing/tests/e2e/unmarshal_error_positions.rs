//! Unmarshalling errors of command parameters report the correct response code and parameter
//! position.

use crate::_common::{
    create_primary_raw_handle, ecc_key, hex, patch_handle, response_rc, rsa_key, rsa_signing_key,
    send, set_hierarchy_enabled, transact_rc_of, unmarshal_response,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::create_simulator;

/// Invalid HierarchyControl / ClockRateAdjust parameters return TPM_RC_VALUE with the correct parameter number.
#[test]
fn command_parameter_errors() {
    let mut sim = create_simulator!();

    // 1. HierarchyControl (0x0121): invalid parameter 1 (enable = RH_NULL = 0x40000007) -> VALUE + P1
    // Total size: 10 (hdr) + 4 (auth handle) + 4 (auth size) + 9 (PW session) + 4 (enable) + 1 (state) = 32 (0x20)
    let req_hier_bad_p1 = hex(concat!(
        "8002 00000020 00000121",
        "4000000C",
        "00000009",
        "40000009 0000 01 0000",
        "40000007",
        "01",
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_hier_bad_p1),
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "HierarchyControl with invalid enable (param 1) must return TPM_RC_VALUE + P1"
    );

    // 2. HierarchyControl (0x0121): valid parameter 1 (enable = RH_OWNER), invalid parameter 2 (state = 2) -> VALUE + P2
    let req_hier_bad_p2 = hex(concat!(
        "8002 00000020 00000121",
        "4000000C",
        "00000009",
        "40000009 0000 01 0000",
        "40000001",
        "02",
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_hier_bad_p2),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "HierarchyControl with invalid state (param 2) must return TPM_RC_VALUE + P2"
    );

    // 3. ClockRateAdjust (0x0130): invalid parameter 1 (rate_adjust = 4) -> VALUE + P1
    // Total size: 10 (hdr) + 4 (auth handle) + 4 (auth size) + 9 (PW session) + 1 (rate_adjust) = 28 (0x1C)
    let req_clock_bad_p1 = hex(concat!(
        "8002 0000001C 00000130",
        "4000000C",
        "00000009",
        "40000009 0000 01 0000",
        "04",
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_clock_bad_p1),
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "ClockRateAdjust with invalid rate_adjust (param 1) must return TPM_RC_VALUE + P1"
    );
}

/// Truncated / invalid ContextLoad and GetRandom parameters report TPM_RC_INSUFFICIENT / TPM_RC_VALUE + P1.
#[test]
fn context_load_and_get_random_errors() {
    let mut sim = create_simulator!();

    // 1. TPM2_ContextLoad (0x0161): truncated parameter 1 (only 4 bytes of sequence) -> INSUFFICIENT + P1
    let req_ctx_load_truncated = hex("8001 0000000E 00000161 00000001");
    assert_eq!(
        transact_rc_of(&mut sim, &req_ctx_load_truncated),
        TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
        "ContextLoad with truncated parameter 1 must return TPM_RC_INSUFFICIENT + P1"
    );

    // 2. TPM2_ContextLoad (0x0161): invalid saved_handle (0x00000001) in parameter 1 -> VALUE + P1 (not H1)
    // Total size: 10 (hdr) + 8 (sequence) + 4 (saved_handle) + 4 (hierarchy) + 2 (blob_size=0) = 28 (0x1C)
    let req_ctx_load_bad_saved_handle = hex(concat!(
        "8001 0000001C 00000161",
        "0000000000000001",
        "00000001",
        "40000001",
        "0000",
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_ctx_load_bad_saved_handle),
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "ContextLoad with invalid saved_handle in parameter 1 must return TPM_RC_VALUE + P1"
    );

    // 3. TPM2_ContextLoad (0x0161): disabled hierarchy (RH_OWNER with shEnable = CLEAR)
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let req_ctx_load_disabled_hierarchy = hex(concat!(
        "8001 0000001C 00000161",
        "0000000000000001",
        "80000000",
        "40000001",
        "0000",
    ));
    // C TPM2_ContextLoad parses the (here empty) context blob before it ever looks at the
    // hierarchy (ContextLoad.c: TPM2B_DIGEST_Unmarshal of the integrity, the HIERARCHY check only
    // comes after integrity/decryption), so the result is the bare TPM_RC_INSUFFICIENT returned by
    // that unmarshal.
    assert_eq!(
        transact_rc_of(&mut sim, &req_ctx_load_disabled_hierarchy),
        TpmRc::INSUFFICIENT.get(),
        "ContextLoad with an empty context blob must return bare TPM_RC_INSUFFICIENT"
    );
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, true);

    // 4. TPM2_GetRandom (0x017B): 1-byte parameter 1 -> INSUFFICIENT + P1
    let req_get_random_truncated = hex("8001 0000000B 0000017B 00");
    assert_eq!(
        transact_rc_of(&mut sim, &req_get_random_truncated),
        TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
        "GetRandom with 1-byte parameter 1 must return TPM_RC_INSUFFICIENT + P1"
    );
}

/// VerifySignature and PolicySigned reject a signature with sigAlg TPM_ALG_NULL (TPM_RC_SCHEME).
#[test]
fn null_signature_algorithm_rejected() {
    let mut sim = create_simulator!();

    // A loaded RSASSA signing key.
    let key_handle = create_primary_raw_handle(&mut sim, rsa_signing_key());

    // Start a Trial Policy Session via StartAuthSession (0x0176)
    let start_session_req = hex(concat!(
        "8001 0000002B 00000176",
        "40000007",                             // tpmKey = RH_NULL
        "40000007",                             // bind = RH_NULL
        "00100102030405060708090a0b0c0d0e0f10", // nonceCaller (16 bytes)
        "0000",                                 // encryptedSalt (size 0)
        "03",                                   // sessionType = Trial (0x03)
        "0010",                                 // symmetric = NULL
        "000b",                                 // authHash = SHA256
    ));
    let resp = send(&mut sim, &start_session_req);
    assert_eq!(response_rc(&resp), 0, "StartAuthSession should succeed");
    let session_handle = u32::from_be_bytes(resp[10..14].try_into().unwrap());

    // 1. TPM2_VerifySignature (0x0177) with signature.sigAlg == TPM_ALG_NULL (0x0010)
    // Header: tag = 0x8001 (ST_NO_SESSIONS), size = 10 + 4 (keyHandle) + 2 (digest size=0) + 2 (sigAlg=0x0010) = 18 (0x12)
    let req_verify_sig_null = patch_handle(
        hex(concat!(
            "8001 00000012 00000177",
            "00000000", // keyHandle
            "0000",     // digest (param 1, size = 0)
            "0010",     // signature (param 2, sigAlg = TPM_ALG_NULL)
        )),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_verify_sig_null),
        TpmRc::SCHEME.with(Position::parameter(2)).get(),
        "VerifySignature with TPM_ALG_NULL signature must return TPM_RC_SCHEME + P2"
    );

    // 2. TPM2_PolicySigned (0x0160) with auth.sigAlg == TPM_ALG_NULL (0x0010)
    // Header: tag = 0x8001 (ST_NO_SESSIONS), size = 10 + 8 (handles) + 2 (nonceTPM) + 2 (cpHashA) + 2 (policyRef) + 4 (expiration) + 2 (auth=0x0010) = 30 (0x1E)
    let req_policy_signed_null = patch_handle(
        patch_handle(
            hex(concat!(
                "8001 0000001E 00000160",
                "00000000", // authObject
                "00000000", // policySession
                "0000",     // nonceTPM (param 1)
                "0000",     // cpHashA (param 2)
                "0000",     // policyRef (param 3)
                "00000000", // expiration (param 4)
                "0010",     // auth (param 5, sigAlg = TPM_ALG_NULL)
            )),
            10,
            key_handle,
        ),
        14,
        session_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_policy_signed_null),
        TpmRc::SCHEME.with(Position::parameter(5)).get(),
        "PolicySigned with TPM_ALG_NULL auth signature must return TPM_RC_SCHEME + P5"
    );
}

/// Malformed NV_DefineSpace publicInfo and object command parameters return SIZE / RESERVED_BITS / HASH / VALUE with positions.
#[test]
fn nv_define_space_and_object_command_errors() {
    let mut sim = create_simulator!();

    // 1. TPM2_NV_DefineSpace (0x012A): publicInfo (param 2) with size == 0 -> TPM_RC_SIZE + P2
    // Header: 8002, size = 10 + 4 + 4 + 9 + 2 (auth) + 2 (publicInfo size=0) = 31 (0x1F)
    let req_nv_def_zero_size = hex(concat!(
        "8002 0000001F 0000012A",
        "40000001",                       // RH_OWNER
        "00000009 40000009 0000 01 0000", // PW session
        "0000",                           // auth (param 1)
        "0000",                           // publicInfo (param 2, size = 0)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_nv_def_zero_size),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "NV_DefineSpace with size == 0 publicInfo (param 2) must return TPM_RC_SIZE + P2"
    );

    // 2. TPM2_NV_DefineSpace (0x012A): publicInfo (param 2) with reserved bits in TPMA_NV -> TPM_RC_RESERVED_BITS + P2
    // Header: 8002, size = 10 + 4 + 4 + 9 + 2 (auth) + 16 (publicInfo) = 45 (0x2D)
    let req_nv_def_reserved_bits = hex(concat!(
        "8002 0000002D 0000012A",
        "40000001",                              // RH_OWNER
        "00000009 40000009 0000 01 0000",        // PW session
        "0000",                                  // auth (param 1)
        "000E 01000001 000B 00000100 0000 0000", // publicInfo (param 2, bit 8 reserved)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_nv_def_reserved_bits),
        TpmRc::RESERVED_BITS.with(Position::parameter(2)).get(),
        "NV_DefineSpace with reserved TPMA_NV bits in publicInfo (param 2) must return TPM_RC_RESERVED_BITS + P2"
    );

    // 3. TPM2_NV_DefineSpace (0x012A): publicInfo (param 2) with invalid nameAlg (0x0001 RSA) -> TPM_RC_HASH + P2
    let req_nv_def_bad_hash = hex(concat!(
        "8002 0000002D 0000012A",
        "40000001",                              // RH_OWNER
        "00000009 40000009 0000 01 0000",        // PW session
        "0000",                                  // auth (param 1)
        "000E 01000001 0001 00020002 0000 0000", // publicInfo (param 2, nameAlg = 0x0001 RSA)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_nv_def_bad_hash),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "NV_DefineSpace with invalid nameAlg in publicInfo (param 2) must return TPM_RC_HASH + P2"
    );

    // 3b. TPM2_NV_DefineSpace (0x012A): publicInfo (param 2) with invalid nvIndex (0x00000001) AND invalid nameAlg (0x0001 RSA) -> TPM_RC_VALUE + P2
    let req_nv_def_bad_idx_and_hash = hex(concat!(
        "8002 0000002D 0000012A",
        "40000001",                       // RH_OWNER
        "00000009 40000009 0000 01 0000", // PW session
        "0000",                           // auth (param 1)
        // publicInfo (param 2, nvIndex = 0x00000001 invalid, nameAlg = 0x0001 RSA)
        "000E 00000001 0001 00020002 0000 0000",
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_nv_def_bad_idx_and_hash),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "NV_DefineSpace with invalid nvIndex in publicInfo (param 2) must return TPM_RC_VALUE + P2 before checking nameAlg"
    );

    // 4. TPM2_CreatePrimary (0x0131): inPublic (param 2) with size == 0 -> TPM_RC_SIZE + P2
    // Header: 8002, size = 10 + 4 + 4 + 9 + 6 (inSensitive) + 2 (inPublic size=0) + 2 + 4 = 41 (0x29)
    let req_cp_zero_pub = hex(concat!(
        "8002 00000029 00000131",
        "40000001",                       // RH_OWNER
        "00000009 40000009 0000 01 0000", // PW session
        "0004 0000 0000",                 // inSensitive (param 1)
        "0000",                           // inPublic (param 2, size = 0)
        "0000",                           // outsideInfo (param 3)
        "00000000",                       // creationPCR (param 4)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_cp_zero_pub),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "CreatePrimary with size == 0 inPublic (param 2) must return TPM_RC_SIZE + P2"
    );

    // 5. TPM2_CreateLoaded (0x0191): inPublic (param 2, TPM2B_TEMPLATE) with size == 0 -> TPM_RC_INSUFFICIENT + P2
    // Header: 8002, size = 10 + 4 + 4 + 9 + 6 (inSensitive) + 2 (inPublic size=0) = 35 (0x23)
    let req_cl_zero_pub = hex(concat!(
        "8002 00000023 00000191",
        "40000001",                       // RH_OWNER
        "00000009 40000009 0000 01 0000", // PW session
        "0004 0000 0000",                 // inSensitive (param 1)
        "0000",                           // inPublic (param 2, size = 0)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_cl_zero_pub),
        TpmRc::INSUFFICIENT.with(Position::parameter(2)).get(),
        "CreateLoaded with size == 0 inPublic template (param 2) must return TPM_RC_INSUFFICIENT + P2"
    );

    // 6. TPM2_LoadExternal (0x0167): inPublic (param 2) with size == 0 -> TPM_RC_SIZE + P2
    // Header: 8001 (no sessions), size = 10 + 2 (inPrivate=0) + 2 (inPublic=0) + 4 (hierarchy=RH_NULL) = 18 (0x12)
    let req_le_zero_pub = hex(concat!(
        "8001 00000012 00000167",
        "0000",     // inPrivate (param 1, size = 0)
        "0000",     // inPublic (param 2, size = 0)
        "40000007", // hierarchy (param 3, RH_NULL)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_le_zero_pub),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "LoadExternal with size == 0 inPublic (param 2) must return TPM_RC_SIZE + P2"
    );

    // 6b. TPM2_LoadExternal with size == 0 inPublic and invalid hierarchy (param 3) -> still TPM_RC_SIZE + P2 (not VALUE + P3)
    let req_le_zero_pub_bad_hier = hex(concat!(
        "8001 00000012 00000167",
        "0000",     // inPrivate (param 1, size = 0)
        "0000",     // inPublic (param 2, size = 0)
        "80000001", // invalid hierarchy (param 3)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_le_zero_pub_bad_hier),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "LoadExternal with size == 0 inPublic and invalid hierarchy must fail at param 2 with TPM_RC_SIZE + P2"
    );

    // 6c. TPM2_LoadExternal with size == 0 inPublic and trailing bytes -> still TPM_RC_SIZE + P2 (not unadorned TPM_RC_SIZE)
    let req_le_zero_pub_trailing = hex(concat!(
        "8001 00000013 00000167",
        "0000",     // inPrivate (param 1, size = 0)
        "0000",     // inPublic (param 2, size = 0)
        "40000007", // hierarchy (param 3, RH_NULL)
        "FF",       // trailing byte
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_le_zero_pub_trailing),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "LoadExternal with size == 0 inPublic and trailing bytes must fail at param 2 with TPM_RC_SIZE + P2"
    );
}

/// Object commands reject a keyedHash public area with nameAlg TPM_ALG_NULL with TPM_RC_HASH.
#[test]
fn object_public_null_name_alg_rejected() {
    let mut sim = create_simulator!();

    // A loaded RSA storage parent so handle resolution and session validation pass.
    let parent_handle = create_primary_raw_handle(
        &mut sim,
        rsa_key(
            TpmaObject::RESTRICTED
                | TpmaObject::DECRYPT
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH,
            None,
            Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
        ),
    );

    // KeyedHash public area with nameAlg = TPM_ALG_NULL (0x0010):
    // type = 0x0008 (KEYEDHASH)
    // nameAlg = 0x0010 (NULL)
    // objectAttributes = 0x00040040 (SIGN_ENCRYPT | USER_WITH_AUTH)
    // authPolicy = size 0 (0x0000)
    // parameters.keyedHashDetail.scheme = 0x0010 (NULL)
    // unique.keyedHash = size 0 (0x0000)
    // Total TPMT_PUBLIC size = 2 + 2 + 4 + 2 + 2 + 2 = 14 bytes (0x000E)
    // TPM2B_PUBLIC size prefix = 0x000E -> 16 bytes total:
    // "000E 0008 0010 00040040 0000 0010 0000"

    // 1. TPM2_CreatePrimary (0x0131) with nameAlg = TPM_ALG_NULL -> TPM_RC_HASH + P2 (0x2C3)
    // Header: 8002, size = 10 + 4 + 4 + 9 + 6 (inSensitive) + 16 (inPublic) + 2 + 4 = 55 (0x37)
    let req_cp_null_name_alg = hex(concat!(
        "8002 00000037 00000131",
        "40000001",                               // RH_OWNER
        "00000009 40000009 0000 01 0000",         // PW session
        "0004 0000 0000",                         // inSensitive (param 1)
        "000E 0008 0010 00040040 0000 0010 0000", // inPublic (param 2, nameAlg = NULL)
        "0000",                                   // outsideInfo (param 3)
        "00000000",                               // creationPCR (param 4)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_cp_null_name_alg),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "CreatePrimary with nameAlg == TPM_ALG_NULL must return TPM_RC_HASH + P2 (0x2C3)"
    );

    // 2. TPM2_Create (0x0153) with nameAlg = TPM_ALG_NULL -> TPM_RC_HASH + P2 (0x2C3)
    // Note: command parameter unmarshalling occurs before handle resolution!
    let req_create_null_name_alg = patch_handle(
        hex(concat!(
            "8002 00000037 00000153",
            "00000000",                               // parentHandle
            "00000009 40000009 0000 01 0000",         // PW session
            "0004 0000 0000",                         // inSensitive (param 1)
            "000E 0008 0010 00040040 0000 0010 0000", // inPublic (param 2, nameAlg = NULL)
            "0000",                                   // outsideInfo (param 3)
            "00000000",                               // creationPCR (param 4)
        )),
        10,
        parent_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_create_null_name_alg),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Create with nameAlg == TPM_ALG_NULL must return TPM_RC_HASH + P2 (0x2C3)"
    );

    // 3. TPM2_Load (0x0157) with nameAlg = TPM_ALG_NULL -> TPM_RC_HASH + P2 (0x2C3)
    // Header: 8002, size = 10 + 4 + 4 + 9 + 2 (inPrivate size=0) + 16 (inPublic) = 45 (0x2D)
    let req_load_null_name_alg = patch_handle(
        hex(concat!(
            "8002 0000002D 00000157",
            "00000000",                               // parentHandle
            "00000009 40000009 0000 01 0000",         // PW session
            "0000",                                   // inPrivate (param 1)
            "000E 0008 0010 00040040 0000 0010 0000", // inPublic (param 2, nameAlg = NULL)
        )),
        10,
        parent_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_load_null_name_alg),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Load with nameAlg == TPM_ALG_NULL must return TPM_RC_HASH + P2 (0x2C3)"
    );

    // 4. TPM2_Import (0x0156) with nameAlg = TPM_ALG_NULL -> TPM_RC_HASH + P2 (0x2C3)
    // Header: 8002, size = 10 + 4 + 4 + 9 + 2 (encryptionKey) + 16 (objectPublic) + 2 (duplicate) + 2 (inSymSeed) + 2 (symmetricAlg=NULL) = 51 (0x33)
    let req_import_null_name_alg = patch_handle(
        hex(concat!(
            "8002 00000033 00000156",
            "00000000",                               // parentHandle
            "00000009 40000009 0000 01 0000",         // PW session
            "0000",                                   // encryptionKey (param 1)
            "000E 0008 0010 00040040 0000 0010 0000", // objectPublic (param 2, nameAlg = NULL)
            "0000",                                   // duplicate (param 3)
            "0000",                                   // inSymSeed (param 4)
            "0010",                                   // symmetricAlg (param 5)
        )),
        10,
        parent_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_import_null_name_alg),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Import with nameAlg == TPM_ALG_NULL must return TPM_RC_HASH + P2 (0x2C3)"
    );

    // 4b. TPM2_CreateLoaded (0x0191) with nameAlg = TPM_ALG_NULL -> TPM_RC_HASH + P2 (0x2C3)
    // Header: 8002, size = 10 + 4 + 4 + 9 + 6 (inSensitive) + 16 (inPublic) = 49 (0x31)
    let req_create_loaded_null_name_alg = hex(concat!(
        "8002 00000031 00000191",
        "40000001",                       // RH_OWNER
        "00000009 40000009 0000 01 0000", // PW session
        "0004 0000 0000",                 // inSensitive (param 1)
        // inPublic template (param 2, nameAlg = NULL)
        "000E 0008 0010 00040040 0000 0010 0000",
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_create_loaded_null_name_alg),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "CreateLoaded with nameAlg == TPM_ALG_NULL must return TPM_RC_HASH + P2 (0x2C3)"
    );

    // 5. TPM2_LoadExternal (0x0167) with nameAlg = TPM_ALG_NULL and hierarchy = RH_NULL -> SUCCEEDS (0x00000000)
    // inPrivate: sensitiveType = KEYEDHASH (0x0008), authValue = size 0 (0x0000), seedValue = size 0 (0x0000),
    //            sensitive.bits = size 4 ("deadbeef") -> 2 + 2 + 2 + 6 = 12 bytes (0x000C)
    // inPublic: type = KEYEDHASH (0x0008), nameAlg = NULL (0x0010), attrs = SIGN_ENCRYPT | USER_WITH_AUTH (0x00040040),
    //           authPolicy = 0x0000, scheme = HMAC (0x0005) + SHA256 (0x000B), unique = 0x0000 -> 16 bytes (0x0010)
    // hierarchy = RH_NULL (0x40000007)
    // Total size: 10 (hdr) + 14 (inPrivate) + 18 (inPublic) + 4 (hierarchy) = 46 (0x2E)
    let req_load_external_null_name_alg = hex(concat!(
        "8001 0000002E 00000167",
        "000C 0008 0000 0000 0004 deadbeef",
        "0010 0008 0010 00040040 0000 0005 000B 0000",
        "40000007",
    ));
    let resp = send(&mut sim, &req_load_external_null_name_alg);
    assert_eq!(
        response_rc(&resp),
        0,
        "LoadExternal with nameAlg == TPM_ALG_NULL must succeed"
    );
    let loaded_handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);

    // 6. TPM2_ReadPublic (0x0173) on the loaded null-nameAlg object -> SUCCEEDS and returns nameAlg = NULL
    let req_read_public = patch_handle(hex("8001 0000000E 00000173 00000000"), 10, loaded_handle);
    let resp = send(&mut sim, &req_read_public);
    assert_eq!(
        response_rc(&resp),
        0,
        "ReadPublic on object with null nameAlg must succeed"
    );
    // Parse ReadPublicRsp (the response of tpm2::commands::ReadPublic)
    let resp_len = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
    let parsed_rsp = unmarshal_response::<tpm2::commands::ReadPublic>(&resp[..resp_len])
        .expect("ReadPublicRsp unmarshal must succeed for null nameAlg object");
    assert_eq!(
        parsed_rsp.out_public.to_struct_nullable().unwrap().name_alg,
        None
    );
}

/// RSA_Encrypt / RSA_Decrypt reject signature schemes (VALUE + P2) and OAEP with NULL hash (HASH + P2).
#[test]
fn rsa_encrypt_decrypt_signature_scheme_rejected() {
    let mut sim = create_simulator!();

    // A loaded RSA decryption key.
    let key_handle = create_primary_raw_handle(
        &mut sim,
        rsa_key(TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH, None, None),
    );

    // 1. TPM2_RSA_Encrypt (0x0174) with RSASSA (0x0014) in inScheme (param 2) -> TPM_RC_VALUE + P2
    // Header (10) + keyHandle (4) + message (2) + inScheme (4) + label (2) = 22 (0x16)
    let req_enc_rsassa = patch_handle(
        hex("8001 00000016 00000174 00000000 0000 0014 000B 0000"),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_enc_rsassa),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "RSA_Encrypt with RSASSA in inScheme (param 2) must return TPM_RC_VALUE + P2"
    );

    // 2. TPM2_RSA_Encrypt (0x0174) with RSAPSS (0x0016) in inScheme (param 2) -> TPM_RC_VALUE + P2
    let req_enc_rsapss = patch_handle(
        hex("8001 00000016 00000174 00000000 0000 0016 000B 0000"),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_enc_rsapss),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "RSA_Encrypt with RSAPSS in inScheme (param 2) must return TPM_RC_VALUE + P2"
    );

    // 3. TPM2_RSA_Encrypt (0x0174) with OAEP (0x0017) + NULL hash (0x0010) in inScheme (param 2) -> TPM_RC_HASH + P2
    let req_enc_oaep_null_hash = patch_handle(
        hex("8001 00000016 00000174 00000000 0000 0017 0010 0000"),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_enc_oaep_null_hash),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "RSA_Encrypt with OAEP and NULL inner hash in inScheme (param 2) must return TPM_RC_HASH + P2"
    );

    // 4. TPM2_RSA_Decrypt (0x0159) with RSASSA (0x0014) in inScheme (param 2) -> TPM_RC_VALUE + P2
    // Header (10) + keyHandle (4) + authSize (4) + PW session (9) + cipherText (2) + inScheme (4) + label (2) = 35 (0x23)
    let req_dec_rsassa = patch_handle(
        hex(concat!(
            "8002 00000023 00000159",
            "00000000",
            "00000009 40000009 0000 01 0000",
            "0000",
            "0014 000B",
            "0000",
        )),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_dec_rsassa),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "RSA_Decrypt with RSASSA in inScheme (param 2) must return TPM_RC_VALUE + P2"
    );

    // 5. TPM2_RSA_Decrypt (0x0159) with RSAPSS (0x0016) in inScheme (param 2) -> TPM_RC_VALUE + P2
    let req_dec_rsapss = patch_handle(
        hex(concat!(
            "8002 00000023 00000159",
            "00000000",
            "00000009 40000009 0000 01 0000",
            "0000",
            "0016 000B",
            "0000",
        )),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_dec_rsapss),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "RSA_Decrypt with RSAPSS in inScheme (param 2) must return TPM_RC_VALUE + P2"
    );

    // 6. TPM2_RSA_Decrypt (0x0159) with OAEP (0x0017) + NULL hash (0x0010) in inScheme (param 2) -> TPM_RC_HASH + P2
    let req_dec_oaep_null_hash = patch_handle(
        hex(concat!(
            "8002 00000023 00000159",
            "00000000",
            "00000009 40000009 0000 01 0000",
            "0000",
            "0017 0010",
            "0000",
        )),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_dec_oaep_null_hash),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "RSA_Decrypt with OAEP and NULL inner hash in inScheme (param 2) must return TPM_RC_HASH + P2"
    );
}

/// Empty inSensitive, bad sensitiveType, RSA 512-bit keyBits and malformed ECC points report the right RC + P1.
#[test]
fn sensitive_rsa_bits_and_ecc_point_errors() {
    let mut sim = create_simulator!();

    // 1. TPM2_CreatePrimary (0x0131): inSensitive (param 1) with size == 0 -> TPM_RC_SIZE + P1
    // (Even when inPublic (param 2) also has size == 0, param 1 error takes precedence during unmarshalling)
    let req_cp_zero_sens = hex(concat!(
        "8002 00000025 00000131",
        "40000001",                       // RH_OWNER
        "00000009 40000009 0000 01 0000", // PW session
        "0000",                           // inSensitive (param 1, size = 0)
        "0000",                           // inPublic (param 2, size = 0)
        "0000",                           // outsideInfo (param 3)
        "00000000",                       // creationPCR (param 4)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_cp_zero_sens),
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "CreatePrimary with size == 0 inSensitive (param 1) must return TPM_RC_SIZE + P1"
    );

    // 2. TPM2_LoadExternal (0x0167): inPrivate (param 1) with invalid sensitiveType (0x0099) -> TPM_RC_TYPE + P1
    let req_le_bad_priv = hex(concat!(
        "8001 00000014 00000167",
        "0002 0099", // inPrivate (param 1, size = 2, sensitiveType = 0x0099 invalid)
        "0000",      // inPublic (param 2, size = 0)
        "40000007",  // hierarchy (param 3, RH_NULL)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_le_bad_priv),
        TpmRc::TYPE.with(Position::parameter(1)).get(),
        "LoadExternal with invalid sensitiveType in inPrivate (param 1) must return TPM_RC_TYPE + P1"
    );

    // 3. TPM2_TestParms (0x018A): parameters (param 1) with RSA key_bits = 512 (0x0200) -> TPM_RC_VALUE + P1
    let req_test_parms_bad_rsa_bits = hex(concat!(
        "8001 00000016 0000018A",
        "0001",     // type = TPM_ALG_RSA
        "0010",     // symmetric = TPM_ALG_NULL
        "0010",     // scheme = TPM_ALG_NULL
        "0200",     // keyBits = 512 (invalid RSA key bits)
        "00000000", // exponent = 0
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_test_parms_bad_rsa_bits),
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "TestParms with unsupported RSA keyBits (512) must return TPM_RC_VALUE + P1"
    );

    // 4. TPM2_ECDH_ZGen (0x0154): inPoint (param 1) with size == 0 or malformed TpmsEccPoint -> TPM_RC_SIZE + P1
    let key_handle = create_primary_raw_handle(
        &mut sim,
        ecc_key(
            TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
            TpmtEccScheme::Ecdh(TpmiAlgHash::Sha256),
        ),
    );

    let req_ecdh_zero_point = patch_handle(
        hex(concat!(
            "8002 0000001D 00000154",
            "00000000",
            "00000009 40000009 0000 01 0000",
            "0000", // inPoint (param 1, size = 0)
        )),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_ecdh_zero_point),
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "ECDH_ZGen with size == 0 inPoint (param 1) must return TPM_RC_SIZE + P1"
    );

    let req_ecdh_truncated_point = patch_handle(
        hex(concat!(
            "8002 0000001F 00000154",
            "00000000",
            "00000009 40000009 0000 01 0000",
            "0002 0000", // inPoint (param 1, size = 2, x.size = 0, missing y coordinate)
        )),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_ecdh_truncated_point),
        TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
        "ECDH_ZGen with truncated TpmsEccPoint in inPoint (param 1) must return TPM_RC_INSUFFICIENT + P1"
    );

    let req_ecdh_mismatched_size_point = patch_handle(
        hex(concat!(
            "8002 00000021 00000154",
            "00000000",
            "00000009 40000009 0000 01 0000",
            // inPoint (param 1, size = 2, x.size = 0, y.size = 0 -> consumed 4 != size 2)
            "0002 0000 0000",
        )),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_ecdh_mismatched_size_point),
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "ECDH_ZGen with size-mismatched TpmsEccPoint in inPoint (param 1) must return TPM_RC_SIZE + P1"
    );

    // 5. TPM2_CreateLoaded (0x0191): inPublic (param 2, TPM2B_TEMPLATE) with size == 0 -> TPM_RC_INSUFFICIENT + P2
    // Total size: 10 (hdr) + 4 (parentHandle) + 4 (auth size) + 9 (PW session) + 6 (inSensitive default) + 2 (inPublic size=0) = 35 (0x23)
    let req_create_loaded_zero_template = hex(concat!(
        "8002 00000023 00000191",
        "40000001", // RH_OWNER
        "00000009 40000009 0000 01 0000",
        "0004 0000 0000", // inSensitive (param 1, size = 4, valid empty TpmsSensitiveCreate)
        "0000",           // inPublic (param 2, size = 0)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_create_loaded_zero_template),
        TpmRc::INSUFFICIENT.with(Position::parameter(2)).get(),
        "CreateLoaded with size == 0 inPublic (param 2) must return TPM_RC_INSUFFICIENT + P2"
    );

    // 6. TPM2_CreateLoaded (0x0191): inPublic (param 2, TPM2B_TEMPLATE) with invalid type -> TPM_RC_TYPE + P2
    // Total size: 10 + 4 + 4 + 9 + 6 + 4 = 37 (0x25)
    let req_create_loaded_bad_template_type = hex(concat!(
        "8002 00000025 00000191",
        "40000001", // RH_OWNER
        "00000009 40000009 0000 01 0000",
        "0004 0000 0000", // inSensitive (param 1)
        "0002 FFFF",      // inPublic (param 2, size = 2, type = 0xFFFF invalid)
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_create_loaded_bad_template_type),
        TpmRc::TYPE.with(Position::parameter(2)).get(),
        "CreateLoaded with invalid type in inPublic (param 2) must return TPM_RC_TYPE + P2"
    );

    // 7. TPM2_Commit (0x018B): P1 (param 1, TPM2B_ECC_POINT) with size == 0 -> TPM_RC_SIZE + P1
    // First create an ECDAA signing ECC key.
    let commit_key_handle = create_primary_raw_handle(
        &mut sim,
        ecc_key(
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                hash_alg: TpmiAlgHash::Sha256,
                count: 0,
            }),
        ),
    );

    // Total size: 10 (hdr) + 4 (signHandle) + 4 (auth size) + 9 (PW session) + 2 (P1 size=0) + 2 (s2 size=0) + 2 (y2 size=0) = 33 (0x21)
    let req_commit_zero_p1 = patch_handle(
        hex(concat!(
            "8002 00000021 0000018B",
            "00000000",
            "00000009 40000009 0000 01 0000",
            "0000", // P1 (param 1, size = 0 -> invalid for TPM2B_ECC_POINT)
            "0000", // s2 (param 2, size = 0)
            "0000", // y2 (param 3, size = 0)
        )),
        10,
        commit_key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_commit_zero_p1),
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "Commit with size == 0 P1 (param 1) must return TPM_RC_SIZE + P1"
    );
}

/// Malformed session areas (invalid handle, reserved attribute bits, sizes) return the right RC with session positions.
#[test]
fn session_area_errors() {
    let mut sim = create_simulator!();

    // 1. Invalid session handle (0x80000000) in session 1 of TPM2_ClearControl (0x0127)
    // Header: tag = 0x8002 (ST_SESSIONS), size = 28 (0x1C), cmd = 0x00000127 (ClearControl)
    // Handle 1 (auth): RH_PLATFORM (0x4000000C)
    // Auth area size: 9 bytes (0x00000009)
    // Session 1: handle = 0x80000000 (invalid), nonce = 0x0000, attributes = 0x01, hmac = 0x0000
    // Parameter 1: disable = 0x00
    let req_invalid_session_handle = hex(concat!(
        "8002 0000001C 00000127",
        "4000000C",
        "00000009",
        "80000000 0000 01 0000",
        "00",
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_invalid_session_handle),
        TpmRc::VALUE.with(Position::session(1)).get(),
        "Invalid session handle in session 1 must return TPM_RC_VALUE + TPM_RC_S + TPM_RC_1"
    );

    // 2. Reserved bits set in TpmaSession (0x08) in session 1
    let req_reserved_session_bits = hex(concat!(
        "8002 0000001C 00000127",
        "4000000C",
        "00000009",
        "40000009 0000 08 0000",
        "00",
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_reserved_session_bits),
        TpmRc::RESERVED_BITS.with(Position::session(1)).get(),
        "Reserved bits in TpmaSession of session 1 must return TPM_RC_RESERVED_BITS + TPM_RC_S + TPM_RC_1"
    );

    // 3. More than 3 sessions in the authorization area (4 password sessions) -> SIZE + S4
    // Auth area size: 36 bytes (0x00000024 = 4 * 9 bytes)
    // Total size: 10 (header) + 4 (handle) + 4 (auth size) + 36 (4 sessions) + 1 (param) = 55 (0x37)
    let req_four_sessions = hex(concat!(
        "8002 00000037 00000127",
        "4000000C",
        "00000024",
        "40000009 0000 01 0000",
        "40000009 0000 01 0000",
        "40000009 0000 01 0000",
        "40000009 0000 01 0000",
        "00",
    ));
    assert_eq!(
        transact_rc_of(&mut sim, &req_four_sessions),
        TpmRc::SIZE.with(Position::session(4)).get(),
        "Exceeding 3 authorization sessions must return TPM_RC_SIZE + TPM_RC_S + TPM_RC_4"
    );
}

/// A malformed TPM2_Sign validation ticket is reported with the correct parameter position.
#[test]
fn sign_validation_ticket_error() {
    let mut sim = create_simulator!();

    // A loaded RSASSA signing key.
    let key_handle = create_primary_raw_handle(&mut sim, rsa_signing_key());

    // TPM2_Sign (0x015D)
    // Handle 1: keyHandle
    // Auth area: 1 PW session (9 bytes)
    // Param 1 (digest): size = 0 (0x0000)
    // Param 2 (inScheme): TPM_ALG_NULL (0x0010)
    // Param 3 (validation: TPMT_TK_HASHCHECK):
    //   tag = 0x8024 (TPM_ST_HASHCHECK)
    //   hierarchy = 0x12345678 (invalid hierarchy!)
    //   digest = size 0 (0x0000)
    // Total size: 10 + 4 + 4 + 9 + 2 + 2 + 8 = 39 (0x27)
    let req_sign_bad_validation_hierarchy = patch_handle(
        hex(concat!(
            "8002 00000027 0000015D",
            "00000000",
            "00000009",
            "40000009 0000 01 0000",
            "0000",
            "0010",
            "8024 12345678 0000",
        )),
        10,
        key_handle,
    );
    assert_eq!(
        transact_rc_of(&mut sim, &req_sign_bad_validation_hierarchy),
        TpmRc::VALUE.with(Position::parameter(3)).get(),
        "Sign with invalid hierarchy in validation ticket (param 3) must return TPM_RC_VALUE + P3"
    );
}
