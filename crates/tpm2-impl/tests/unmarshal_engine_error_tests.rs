#![forbid(unsafe_code)]

//! End-to-end tests verifying that `TpmEngine` preserves specific unmarshalling error codes
//! and session/parameter/handle positions when dispatching TPM 2.0 commands.

mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::errors::{Position, TpmRc};
use tpm2_impl::{GlobalState, TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn response_rc(resp: &[u8]) -> u32 {
    u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]])
}

#[test]
fn test_engine_session_unmarshalling_error_codes_and_positions() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Invalid session handle (0x80000000) in session 1 of TPM2_ClearControl (0x0127)
    // Header: tag = 0x8002 (ST_SESSIONS), size = 28 (0x1C), cmd = 0x00000127 (ClearControl)
    // Handle 1 (auth): RH_PLATFORM (0x4000000C)
    // Auth area size: 9 bytes (0x00000009)
    // Session 1: handle = 0x80000000 (invalid), nonce = 0x0000, attributes = 0x01, hmac = 0x0000
    // Parameter 1: disable = 0x00
    let req_invalid_session_handle = hex!(
        "8002 0000001C 00000127"
        "4000000C"
        "00000009"
        "80000000 0000 01 0000"
        "00"
    );
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &req_invalid_session_handle, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::session(1)).get(),
        "Invalid session handle in session 1 must return TPM_RC_VALUE + TPM_RC_S + TPM_RC_1"
    );

    // 2. Reserved bits set in TpmaSession (0x08) in session 1
    let req_reserved_session_bits = hex!(
        "8002 0000001C 00000127"
        "4000000C"
        "00000009"
        "40000009 0000 08 0000"
        "00"
    );
    tpm.execute_command_separate(&mut global_state, &req_reserved_session_bits, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::RESERVED_BITS.with(Position::session(1)).get(),
        "Reserved bits in TpmaSession of session 1 must return TPM_RC_RESERVED_BITS + TPM_RC_S + TPM_RC_1"
    );

    // 3. More than 3 sessions in the authorization area (4 password sessions) -> SIZE + S4
    // Auth area size: 36 bytes (0x00000024 = 4 * 9 bytes)
    // Total size: 10 (header) + 4 (handle) + 4 (auth size) + 36 (4 sessions) + 1 (param) = 55 (0x37)
    let req_four_sessions = hex!(
        "8002 00000037 00000127"
        "4000000C"
        "00000024"
        "40000009 0000 01 0000"
        "40000009 0000 01 0000"
        "40000009 0000 01 0000"
        "40000009 0000 01 0000"
        "00"
    );
    tpm.execute_command_separate(&mut global_state, &req_four_sessions, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::session(4)).get(),
        "Exceeding 3 authorization sessions must return TPM_RC_SIZE + TPM_RC_S + TPM_RC_4"
    );
}

#[test]
fn test_engine_command_parameter_error_codes_and_positions() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. HierarchyControl (0x0121): invalid parameter 1 (enable = RH_NULL = 0x40000007) -> VALUE + P1
    // Total size: 10 (hdr) + 4 (auth handle) + 4 (auth size) + 9 (PW session) + 4 (enable) + 1 (state) = 32 (0x20)
    let req_hier_bad_p1 = hex!(
        "8002 00000020 00000121"
        "4000000C"
        "00000009"
        "40000009 0000 01 0000"
        "40000007"
        "01"
    );
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &req_hier_bad_p1, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "HierarchyControl with invalid enable (param 1) must return TPM_RC_VALUE + P1"
    );

    // 2. HierarchyControl (0x0121): valid parameter 1 (enable = RH_OWNER), invalid parameter 2 (state = 2) -> VALUE + P2
    let req_hier_bad_p2 = hex!(
        "8002 00000020 00000121"
        "4000000C"
        "00000009"
        "40000009 0000 01 0000"
        "40000001"
        "02"
    );
    tpm.execute_command_separate(&mut global_state, &req_hier_bad_p2, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "HierarchyControl with invalid state (param 2) must return TPM_RC_VALUE + P2"
    );

    // 3. ClockRateAdjust (0x0130): invalid parameter 1 (rate_adjust = 4) -> VALUE + P1
    // Total size: 10 (hdr) + 4 (auth handle) + 4 (auth size) + 9 (PW session) + 1 (rate_adjust) = 28 (0x1C)
    let req_clock_bad_p1 = hex!(
        "8002 0000001C 00000130"
        "4000000C"
        "00000009"
        "40000009 0000 01 0000"
        "04"
    );
    tpm.execute_command_separate(&mut global_state, &req_clock_bad_p1, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "ClockRateAdjust with invalid rate_adjust (param 1) must return TPM_RC_VALUE + P1"
    );
}

#[test]
fn test_engine_sign_validation_ticket_parameter_position() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Populate a loaded signing key at handle 0x80000001
    let key_handle = 0x80000001;
    let public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::SIGN_ENCRYPT | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: Some(tpm2::TpmtRsaScheme::Rsassa(tpm2::TpmiAlgHash::Sha256)),
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    global_state.transient_objects[0] = Some(tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: tpm2::Tpm2bName::default().into(),
        auth: tpm2::Tpm2bAuth::default().into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: tpm2::Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    });

    // TPM2_Sign (0x015D)
    // Handle 1: keyHandle = 0x80000001
    // Auth area: 1 PW session (9 bytes)
    // Param 1 (digest): size = 0 (0x0000)
    // Param 2 (inScheme): TPM_ALG_NULL (0x0010)
    // Param 3 (validation: TPMT_TK_HASHCHECK):
    //   tag = 0x8024 (TPM_ST_HASHCHECK)
    //   hierarchy = 0x12345678 (invalid hierarchy!)
    //   digest = size 0 (0x0000)
    // Total size: 10 + 4 + 4 + 9 + 2 + 2 + 8 = 39 (0x27)
    let req_sign_bad_validation_hierarchy = hex!(
        "8002 00000027 0000015D"
        "80000001"
        "00000009"
        "40000009 0000 01 0000"
        "0000"
        "0010"
        "8024 12345678 0000"
    );
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &req_sign_bad_validation_hierarchy,
        &mut resp,
    );
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(3)).get(),
        "Sign with invalid hierarchy in validation ticket (param 3) must return TPM_RC_VALUE + P3"
    );
}

#[test]
fn test_engine_context_load_and_get_random_parameter_positions() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. TPM2_ContextLoad (0x0161): truncated parameter 1 (only 4 bytes of sequence) -> INSUFFICIENT + P1
    let req_ctx_load_truncated = hex!(
        "8001 0000000E 00000161"
        "00000001"
    );
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &req_ctx_load_truncated, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
        "ContextLoad with truncated parameter 1 must return TPM_RC_INSUFFICIENT + P1"
    );

    // 2. TPM2_ContextLoad (0x0161): invalid saved_handle (0x00000001) in parameter 1 -> VALUE + P1 (not H1)
    // Total size: 10 (hdr) + 8 (sequence) + 4 (saved_handle) + 4 (hierarchy) + 2 (blob_size=0) = 28 (0x1C)
    let req_ctx_load_bad_saved_handle = hex!(
        "8001 0000001C 00000161"
        "0000000000000001"
        "00000001"
        "40000001"
        "0000"
    );
    tpm.execute_command_separate(&mut global_state, &req_ctx_load_bad_saved_handle, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "ContextLoad with invalid saved_handle in parameter 1 must return TPM_RC_VALUE + P1"
    );

    // 3. TPM2_ContextLoad (0x0161): disabled hierarchy (RH_OWNER with sh_enable = false) -> HIERARCHY + P1 (not H1)
    global_state.sh_enable = false;
    let req_ctx_load_disabled_hierarchy = hex!(
        "8001 0000001C 00000161"
        "0000000000000001"
        "80000000"
        "40000001"
        "0000"
    );
    tpm.execute_command_separate(
        &mut global_state,
        &req_ctx_load_disabled_hierarchy,
        &mut resp,
    );
    // C TPM2_ContextLoad parses the (here empty) context blob before it ever looks at the
    // hierarchy (ContextLoad.c: TPM2B_DIGEST_Unmarshal of the integrity, the HIERARCHY check only
    // comes after integrity/decryption), so the result is the bare TPM_RC_INSUFFICIENT returned by
    // that unmarshal.
    assert_eq!(
        response_rc(&resp),
        TpmRc::INSUFFICIENT.get(),
        "ContextLoad with an empty context blob must return bare TPM_RC_INSUFFICIENT"
    );
    global_state.sh_enable = true;

    // 4. TPM2_GetRandom (0x017B): 1-byte parameter 1 -> INSUFFICIENT + P1
    let req_get_random_truncated = hex!(
        "8001 0000000B 0000017B"
        "00"
    );
    tpm.execute_command_separate(&mut global_state, &req_get_random_truncated, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
        "GetRandom with 1-byte parameter 1 must return TPM_RC_INSUFFICIENT + P1"
    );
}

#[test]
fn test_engine_nv_define_space_and_object_commands_error_codes_and_positions() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let mut resp = [0u8; 256];

    // 1. TPM2_NV_DefineSpace (0x012A): publicInfo (param 2) with size == 0 -> TPM_RC_SIZE + P2
    // Header: 8002, size = 10 + 4 + 4 + 9 + 2 (auth) + 2 (publicInfo size=0) = 31 (0x1F)
    let req_nv_def_zero_size = hex!(
        "8002 0000001F 0000012A"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000" // PW session
        "0000" // auth (param 1)
        "0000" // publicInfo (param 2, size = 0)
    );
    tpm.execute_command_separate(&mut global_state, &req_nv_def_zero_size, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "NV_DefineSpace with size == 0 publicInfo (param 2) must return TPM_RC_SIZE + P2"
    );

    // 2. TPM2_NV_DefineSpace (0x012A): publicInfo (param 2) with reserved bits in TPMA_NV -> TPM_RC_RESERVED_BITS + P2
    // Header: 8002, size = 10 + 4 + 4 + 9 + 2 (auth) + 16 (publicInfo) = 45 (0x2D)
    let req_nv_def_reserved_bits = hex!(
        "8002 0000002D 0000012A"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000" // PW session
        "0000" // auth (param 1)
        "000E 01000001 000B 00000100 0000 0000" // publicInfo (param 2, bit 8 reserved)
    );
    tpm.execute_command_separate(&mut global_state, &req_nv_def_reserved_bits, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::RESERVED_BITS.with(Position::parameter(2)).get(),
        "NV_DefineSpace with reserved TPMA_NV bits in publicInfo (param 2) must return TPM_RC_RESERVED_BITS + P2"
    );

    // 3. TPM2_NV_DefineSpace (0x012A): publicInfo (param 2) with invalid nameAlg (0x0001 RSA) -> TPM_RC_HASH + P2
    let req_nv_def_bad_hash = hex!(
        "8002 0000002D 0000012A"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000" // PW session
        "0000" // auth (param 1)
        "000E 01000001 0001 00020002 0000 0000" // publicInfo (param 2, nameAlg = 0x0001 RSA)
    );
    tpm.execute_command_separate(&mut global_state, &req_nv_def_bad_hash, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "NV_DefineSpace with invalid nameAlg in publicInfo (param 2) must return TPM_RC_HASH + P2"
    );

    // 3b. TPM2_NV_DefineSpace (0x012A): publicInfo (param 2) with invalid nvIndex (0x00000001) AND invalid nameAlg (0x0001 RSA) -> TPM_RC_VALUE + P2
    let req_nv_def_bad_idx_and_hash = hex!(
        "8002 0000002D 0000012A"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000" // PW session
        "0000" // auth (param 1)
        "000E 00000001 0001 00020002 0000 0000" // publicInfo (param 2, nvIndex = 0x00000001 invalid, nameAlg = 0x0001 RSA)
    );
    tpm.execute_command_separate(&mut global_state, &req_nv_def_bad_idx_and_hash, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "NV_DefineSpace with invalid nvIndex in publicInfo (param 2) must return TPM_RC_VALUE + P2 before checking nameAlg"
    );

    // 4. TPM2_CreatePrimary (0x0131): inPublic (param 2) with size == 0 -> TPM_RC_SIZE + P2
    // Header: 8002, size = 10 + 4 + 4 + 9 + 6 (inSensitive) + 2 (inPublic size=0) + 2 + 4 = 41 (0x29)
    let req_cp_zero_pub = hex!(
        "8002 00000029 00000131"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000" // PW session
        "0004 0000 0000" // inSensitive (param 1)
        "0000" // inPublic (param 2, size = 0)
        "0000" // outsideInfo (param 3)
        "00000000" // creationPCR (param 4)
    );
    tpm.execute_command_separate(&mut global_state, &req_cp_zero_pub, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "CreatePrimary with size == 0 inPublic (param 2) must return TPM_RC_SIZE + P2"
    );

    // 5. TPM2_CreateLoaded (0x0191): inPublic (param 2, TPM2B_TEMPLATE) with size == 0 -> TPM_RC_INSUFFICIENT + P2
    // Header: 8002, size = 10 + 4 + 4 + 9 + 6 (inSensitive) + 2 (inPublic size=0) = 35 (0x23)
    let req_cl_zero_pub = hex!(
        "8002 00000023 00000191"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000" // PW session
        "0004 0000 0000" // inSensitive (param 1)
        "0000" // inPublic (param 2, size = 0)
    );
    tpm.execute_command_separate(&mut global_state, &req_cl_zero_pub, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::INSUFFICIENT.with(Position::parameter(2)).get(),
        "CreateLoaded with size == 0 inPublic template (param 2) must return TPM_RC_INSUFFICIENT + P2"
    );

    // 6. TPM2_LoadExternal (0x0167): inPublic (param 2) with size == 0 -> TPM_RC_SIZE + P2
    // Header: 8001 (no sessions), size = 10 + 2 (inPrivate=0) + 2 (inPublic=0) + 4 (hierarchy=RH_NULL) = 18 (0x12)
    let req_le_zero_pub = hex!(
        "8001 00000012 00000167"
        "0000" // inPrivate (param 1, size = 0)
        "0000" // inPublic (param 2, size = 0)
        "40000007" // hierarchy (param 3, RH_NULL)
    );
    tpm.execute_command_separate(&mut global_state, &req_le_zero_pub, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "LoadExternal with size == 0 inPublic (param 2) must return TPM_RC_SIZE + P2"
    );

    // 6b. TPM2_LoadExternal with size == 0 inPublic and invalid hierarchy (param 3) -> still TPM_RC_SIZE + P2 (not VALUE + P3)
    let req_le_zero_pub_bad_hier = hex!(
        "8001 00000012 00000167"
        "0000" // inPrivate (param 1, size = 0)
        "0000" // inPublic (param 2, size = 0)
        "80000001" // invalid hierarchy (param 3)
    );
    tpm.execute_command_separate(&mut global_state, &req_le_zero_pub_bad_hier, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "LoadExternal with size == 0 inPublic and invalid hierarchy must fail at param 2 with TPM_RC_SIZE + P2"
    );

    // 6c. TPM2_LoadExternal with size == 0 inPublic and trailing bytes -> still TPM_RC_SIZE + P2 (not unadorned TPM_RC_SIZE)
    let req_le_zero_pub_trailing = hex!(
        "8001 00000013 00000167"
        "0000" // inPrivate (param 1, size = 0)
        "0000" // inPublic (param 2, size = 0)
        "40000007" // hierarchy (param 3, RH_NULL)
        "FF" // trailing byte
    );
    tpm.execute_command_separate(&mut global_state, &req_le_zero_pub_trailing, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::parameter(2)).get(),
        "LoadExternal with size == 0 inPublic and trailing bytes must fail at param 2 with TPM_RC_SIZE + P2"
    );
}

#[test]
fn test_engine_sensitive_rsa_key_bits_and_ecc_point_unmarshalling_errors() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let mut resp = [0u8; 256];

    // 1. TPM2_CreatePrimary (0x0131): inSensitive (param 1) with size == 0 -> TPM_RC_SIZE + P1
    // (Even when inPublic (param 2) also has size == 0, param 1 error takes precedence during unmarshalling)
    let req_cp_zero_sens = hex!(
        "8002 00000025 00000131"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000" // PW session
        "0000" // inSensitive (param 1, size = 0)
        "0000" // inPublic (param 2, size = 0)
        "0000" // outsideInfo (param 3)
        "00000000" // creationPCR (param 4)
    );
    tpm.execute_command_separate(&mut global_state, &req_cp_zero_sens, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "CreatePrimary with size == 0 inSensitive (param 1) must return TPM_RC_SIZE + P1"
    );

    // 2. TPM2_LoadExternal (0x0167): inPrivate (param 1) with invalid sensitiveType (0x0099) -> TPM_RC_TYPE + P1
    let req_le_bad_priv = hex!(
        "8001 00000014 00000167"
        "0002 0099" // inPrivate (param 1, size = 2, sensitiveType = 0x0099 invalid)
        "0000" // inPublic (param 2, size = 0)
        "40000007" // hierarchy (param 3, RH_NULL)
    );
    tpm.execute_command_separate(&mut global_state, &req_le_bad_priv, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::TYPE.with(Position::parameter(1)).get(),
        "LoadExternal with invalid sensitiveType in inPrivate (param 1) must return TPM_RC_TYPE + P1"
    );

    // 3. TPM2_TestParms (0x018A): parameters (param 1) with RSA key_bits = 512 (0x0200) -> TPM_RC_VALUE + P1
    let req_test_parms_bad_rsa_bits = hex!(
        "8001 00000016 0000018A"
        "0001" // type = TPM_ALG_RSA
        "0010" // symmetric = TPM_ALG_NULL
        "0010" // scheme = TPM_ALG_NULL
        "0200" // keyBits = 512 (invalid RSA key bits)
        "00000000" // exponent = 0
    );
    tpm.execute_command_separate(&mut global_state, &req_test_parms_bad_rsa_bits, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "TestParms with unsupported RSA keyBits (512) must return TPM_RC_VALUE + P1"
    );

    // 4. TPM2_ECDH_ZGen (0x0163): inPoint (param 1) with size == 0 or malformed TpmsEccPoint -> TPM_RC_SIZE + P1
    let key_handle = 0x80000002;
    let public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::DECRYPT | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: Some(tpm2::TpmtEccScheme::Ecdh(tpm2::TpmiAlgHash::Sha256)),
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint::default(),
        ),
    };
    global_state.transient_objects[0] = Some(tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: tpm2::Tpm2bName::default().into(),
        auth: tpm2::Tpm2bAuth::default().into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: tpm2::Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    });

    let req_ecdh_zero_point = hex!(
        "8002 0000001D 00000154"
        "80000002"
        "00000009" "40000009 0000 01 0000"
        "0000" // inPoint (param 1, size = 0)
    );
    tpm.execute_command_separate(&mut global_state, &req_ecdh_zero_point, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "ECDH_ZGen with size == 0 inPoint (param 1) must return TPM_RC_SIZE + P1"
    );

    let req_ecdh_truncated_point = hex!(
        "8002 0000001F 00000154"
        "80000002"
        "00000009" "40000009 0000 01 0000"
        "0002 0000" // inPoint (param 1, size = 2, x.size = 0, missing y coordinate)
    );
    tpm.execute_command_separate(&mut global_state, &req_ecdh_truncated_point, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
        "ECDH_ZGen with truncated TpmsEccPoint in inPoint (param 1) must return TPM_RC_INSUFFICIENT + P1"
    );

    let req_ecdh_mismatched_size_point = hex!(
        "8002 00000021 00000154"
        "80000002"
        "00000009" "40000009 0000 01 0000"
        "0002 0000 0000" // inPoint (param 1, size = 2, x.size = 0, y.size = 0 -> consumed 4 != size 2)
    );
    tpm.execute_command_separate(
        &mut global_state,
        &req_ecdh_mismatched_size_point,
        &mut resp,
    );
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "ECDH_ZGen with size-mismatched TpmsEccPoint in inPoint (param 1) must return TPM_RC_SIZE + P1"
    );

    // 5. TPM2_CreateLoaded (0x0191): inPublic (param 2, TPM2B_TEMPLATE) with size == 0 -> TPM_RC_INSUFFICIENT + P2
    // Total size: 10 (hdr) + 4 (parentHandle) + 4 (auth size) + 9 (PW session) + 6 (inSensitive default) + 2 (inPublic size=0) = 35 (0x23)
    let req_create_loaded_zero_template = hex!(
        "8002 00000023 00000191"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000"
        "0004 0000 0000" // inSensitive (param 1, size = 4, valid empty TpmsSensitiveCreate)
        "0000" // inPublic (param 2, size = 0)
    );
    tpm.execute_command_separate(
        &mut global_state,
        &req_create_loaded_zero_template,
        &mut resp,
    );
    assert_eq!(
        response_rc(&resp),
        TpmRc::INSUFFICIENT.with(Position::parameter(2)).get(),
        "CreateLoaded with size == 0 inPublic (param 2) must return TPM_RC_INSUFFICIENT + P2"
    );

    // 6. TPM2_CreateLoaded (0x0191): inPublic (param 2, TPM2B_TEMPLATE) with invalid type -> TPM_RC_TYPE + P2
    // Total size: 10 + 4 + 4 + 9 + 6 + 4 = 37 (0x25)
    let req_create_loaded_bad_template_type = hex!(
        "8002 00000025 00000191"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000"
        "0004 0000 0000" // inSensitive (param 1)
        "0002 FFFF" // inPublic (param 2, size = 2, type = 0xFFFF invalid)
    );
    tpm.execute_command_separate(
        &mut global_state,
        &req_create_loaded_bad_template_type,
        &mut resp,
    );
    assert_eq!(
        response_rc(&resp),
        TpmRc::TYPE.with(Position::parameter(2)).get(),
        "CreateLoaded with invalid type in inPublic (param 2) must return TPM_RC_TYPE + P2"
    );

    // 7. TPM2_Commit (0x018B): P1 (param 1, TPM2B_ECC_POINT) with size == 0 -> TPM_RC_SIZE + P1
    // First populate a signing ECC key at 0x80000003
    let commit_key_handle = 0x80000003;
    let commit_public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::SIGN_ENCRYPT | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: Some(tpm2::TpmtEccScheme::Ecdaa(tpm2::TpmsSchemeEcdaa {
                    hash_alg: tpm2::TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint::default(),
        ),
    };
    global_state.transient_objects[1] = Some(tpm2_impl::handler::TransientObject {
        handle: commit_key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: tpm2::Tpm2bName::default().into(),
        auth: tpm2::Tpm2bAuth::default().into(),
        public: commit_public.into(),
        private: [0xcc; 1536],
        private_len: 32,
        qualified_name: tpm2::Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    });

    // Total size: 10 (hdr) + 4 (signHandle) + 4 (auth size) + 9 (PW session) + 2 (P1 size=0) + 2 (s2 size=0) + 2 (y2 size=0) = 33 (0x21)
    let req_commit_zero_p1 = hex!(
        "8002 00000021 0000018B"
        "80000003"
        "00000009" "40000009 0000 01 0000"
        "0000" // P1 (param 1, size = 0 -> invalid for TPM2B_ECC_POINT)
        "0000" // s2 (param 2, size = 0)
        "0000" // y2 (param 3, size = 0)
    );
    tpm.execute_command_separate(&mut global_state, &req_commit_zero_p1, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "Commit with size == 0 P1 (param 1) must return TPM_RC_SIZE + P1"
    );
}

#[test]
fn test_non_null_schemes_with_tpm_alg_null_inner_hash_and_kdf_in_commands() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let mut resp = [0u8; 256];

    // 1. TPM2_TestParms (0x018A) with RSA (0x0001), symmetric=NULL (0x0010), scheme=RSASSA (0x0014), hash=NULL (0x0010), keyBits=2048 (0x0800), exponent=0 (0x00000000)
    // Total size: 10 (hdr) + 2 (RSA) + 2 (sym) + 2 (RSASSA) + 2 (hash) + 2 (keyBits) + 4 (exponent) = 24 (0x18)
    let req_test_parms_rsa_null_hash = hex!(
        "8001 00000018 0000018A"
        "0001 0010 0014 0010 0800 00000000"
    );
    tpm.execute_command_separate(&mut global_state, &req_test_parms_rsa_null_hash, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "TestParms RSA RSASSA with TPM_ALG_NULL inner hash must return TPM_RC_HASH + P1"
    );

    // 2. TPM2_TestParms (0x018A) with ECC (0x0023), symmetric=NULL (0x0010), scheme=ECDSA (0x0018), hash=NULL (0x0010), curve=NIST_P256 (0x0003), kdf=NULL (0x0010)
    // Total size: 10 + 2 + 2 + 2 + 2 + 2 + 2 = 22 (0x16)
    let req_test_parms_ecc_null_hash = hex!(
        "8001 00000016 0000018A"
        "0023 0010 0018 0010 0003 0010"
    );
    tpm.execute_command_separate(&mut global_state, &req_test_parms_ecc_null_hash, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "TestParms ECC ECDSA with TPM_ALG_NULL inner hash must return TPM_RC_HASH + P1"
    );

    // 3. TPM2_TestParms (0x018A) with KeyedHash (0x0008), scheme=XOR (0x000A), hash=SHA256 (0x000B), kdf=NULL (0x0010)
    // Total size: 10 + 2 + 2 + 2 + 2 = 18 (0x12)
    // The C reference accepts it: TPMS_SCHEME_XOR_Unmarshal reads the KDF as TPMI_ALG_KDF+
    // (flag = 1, Marshal.c:3439), so TPM_ALG_NULL is allowed and TestParms succeeds.
    let req_test_parms_xor_null_kdf = hex!(
        "8001 00000012 0000018A"
        "0008 000A 000B 0010"
    );
    tpm.execute_command_separate(&mut global_state, &req_test_parms_xor_null_kdf, &mut resp);
    assert_eq!(
        response_rc(&resp),
        0,
        "TestParms KeyedHash XOR with TPM_ALG_NULL inner KDF must succeed (C TPMI_ALG_KDF+)"
    );

    // 4. TPM2_TestParms (0x018A) with KeyedHash (0x0008), scheme=XOR (0x000A), hash=NULL (0x0010), kdf=NULL (0x0010)
    // Total size: 18 (0x12)
    let req_test_parms_xor_null_hash = hex!(
        "8001 00000012 0000018A"
        "0008 000A 0010 0010"
    );
    tpm.execute_command_separate(&mut global_state, &req_test_parms_xor_null_hash, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "TestParms KeyedHash XOR with TPM_ALG_NULL inner hash must return TPM_RC_HASH + P1"
    );

    // 5. TPM2_TestParms (0x018A) with KeyedHash (0x0008), scheme=XOR (0x000A), hash=SHA256 (0x000B), kdf=SHA256 (0x000B, invalid KDF)
    // Total size: 18 (0x12)
    let req_test_parms_xor_invalid_kdf = hex!(
        "8001 00000012 0000018A"
        "0008 000A 000B 000B"
    );
    tpm.execute_command_separate(
        &mut global_state,
        &req_test_parms_xor_invalid_kdf,
        &mut resp,
    );
    assert_eq!(
        response_rc(&resp),
        TpmRc::KDF.with(Position::parameter(1)).get(),
        "TestParms KeyedHash XOR with invalid inner KDF must return TPM_RC_KDF + P1"
    );
}

#[test]
fn test_verify_signature_and_policy_signed_reject_null_signature() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let mut resp = [0u8; 256];

    // Populate a loaded signing key at handle 0x80000001
    let key_handle = 0x80000001;
    let public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::SIGN_ENCRYPT | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: Some(tpm2::TpmtRsaScheme::Rsassa(tpm2::TpmiAlgHash::Sha256)),
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    global_state.transient_objects[0] = Some(tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: tpm2::Tpm2bName::default().into(),
        auth: tpm2::Tpm2bAuth::default().into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: tpm2::Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    });

    // Start a Trial Policy Session (handle 0x03000000) via StartAuthSession (0x0176)
    let start_session_req = hex!(
        "8001 0000002B 00000176"
        "40000007" // tpmKey = RH_NULL
        "40000007" // bind = RH_NULL
        "00100102030405060708090a0b0c0d0e0f10" // nonceCaller (16 bytes)
        "0000"     // encryptedSalt (size 0)
        "03"       // sessionType = Trial (0x03)
        "0010"     // symmetric = NULL
        "000b"     // authHash = SHA256
    );
    tpm.execute_command_separate(&mut global_state, &start_session_req, &mut resp);
    assert_eq!(response_rc(&resp), 0, "StartAuthSession should succeed");

    // 1. TPM2_VerifySignature (0x0177) with signature.sigAlg == TPM_ALG_NULL (0x0010)
    // Header: tag = 0x8001 (ST_NO_SESSIONS), size = 10 + 4 (keyHandle) + 2 (digest size=0) + 2 (sigAlg=0x0010) = 18 (0x12)
    let req_verify_sig_null = hex!(
        "8001 00000012 00000177"
        "80000001" // keyHandle
        "0000"     // digest (param 1, size = 0)
        "0010"     // signature (param 2, sigAlg = TPM_ALG_NULL)
    );
    tpm.execute_command_separate(&mut global_state, &req_verify_sig_null, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SCHEME.with(Position::parameter(2)).get(),
        "VerifySignature with TPM_ALG_NULL signature must return TPM_RC_SCHEME + P2"
    );

    // 2. TPM2_PolicySigned (0x0160) with auth.sigAlg == TPM_ALG_NULL (0x0010)
    // Header: tag = 0x8001 (ST_NO_SESSIONS), size = 10 + 8 (handles) + 2 (nonceTPM) + 2 (cpHashA) + 2 (policyRef) + 4 (expiration) + 2 (auth=0x0010) = 30 (0x1E)
    let req_policy_signed_null = hex!(
        "8001 0000001E 00000160"
        "80000001" // authObject
        "03000000" // policySession
        "0000"     // nonceTPM (param 1)
        "0000"     // cpHashA (param 2)
        "0000"     // policyRef (param 3)
        "00000000" // expiration (param 4)
        "0010"     // auth (param 5, sigAlg = TPM_ALG_NULL)
    );
    tpm.execute_command_separate(&mut global_state, &req_policy_signed_null, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::SCHEME.with(Position::parameter(5)).get(),
        "PolicySigned with TPM_ALG_NULL auth signature must return TPM_RC_SCHEME + P5"
    );
}

#[test]
fn test_incremental_self_test_reserved_alg_error_codes() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let mut resp = [0u8; 256];

    for reserved_id in [0x0000u16, 0x00C1, 0x8000, 0xFFFF] {
        let alg_bytes = reserved_id.to_be_bytes();

        // 1. Trailing bytes after toTest containing reserved algorithm ID -> TPM_RC_SIZE
        // Header: tag = 0x8001, size = 17 (0x11), cmd = 0x00000142 (IncrementalSelfTest)
        // toTest: count = 1 (0x00000001), algorithms[0] = reserved_id
        // Trailing byte: 0xAA
        let mut req_trailing = [0u8; 17];
        req_trailing[0..14].copy_from_slice(&hex!("8001 00000011 00000142 00000001"));
        req_trailing[14..16].copy_from_slice(&alg_bytes);
        req_trailing[16] = 0xAA;
        tpm.execute_command_separate(&mut global_state, &req_trailing, &mut resp);
        assert_eq!(
            response_rc(&resp),
            TpmRc::SIZE.get(),
            "IncrementalSelfTest with reserved alg {reserved_id:#06x} and trailing byte must return TPM_RC_SIZE"
        );

        // 2. Truncated buffer after reserved algorithm ID (count = 2, only 1 byte of 2nd alg) -> TPM_RC_INSUFFICIENT + P1
        let mut req_truncated = [0u8; 17];
        req_truncated[0..14].copy_from_slice(&hex!("8001 00000011 00000142 00000002"));
        req_truncated[14..16].copy_from_slice(&alg_bytes);
        req_truncated[16] = 0x00;
        tpm.execute_command_separate(&mut global_state, &req_truncated, &mut resp);
        assert_eq!(
            response_rc(&resp),
            TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
            "IncrementalSelfTest with reserved alg {reserved_id:#06x} and truncated 2nd alg must return TPM_RC_INSUFFICIENT + P1"
        );

        // 3. Exact buffer with reserved algorithm ID -> TPM_RC_VALUE + P1 during execution
        let mut req_exact = [0u8; 16];
        req_exact[0..14].copy_from_slice(&hex!("8001 00000010 00000142 00000001"));
        req_exact[14..16].copy_from_slice(&alg_bytes);
        tpm.execute_command_separate(&mut global_state, &req_exact, &mut resp);
        assert_eq!(
            response_rc(&resp),
            TpmRc::VALUE.with(Position::parameter(1)).get(),
            "IncrementalSelfTest with reserved alg {reserved_id:#06x} must return TPM_RC_VALUE + P1 during execution"
        );
    }
}

#[test]
fn test_engine_object_public_null_name_alg_validation() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let mut resp = [0u8; 512];

    // Populate a loaded parent key at handle 0x80000000 so handle resolution and session validation pass
    let parent_public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::RESTRICTED
            | tpm2::TpmaObject::DECRYPT
            | tpm2::TpmaObject::FIXED_TPM
            | tpm2::TpmaObject::FIXED_PARENT
            | tpm2::TpmaObject::SENSITIVE_DATA_ORIGIN
            | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: Some(tpm2::TpmtSymDefObject::aes_cfb(128).unwrap()),
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    global_state.transient_objects[0] = Some(tpm2_impl::handler::TransientObject {
        handle: 0x80000000,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: tpm2::Tpm2bName::default().into(),
        auth: tpm2::Tpm2bAuth::default().into(),
        public: parent_public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: tpm2::Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    });

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
    let req_cp_null_name_alg = hex!(
        "8002 00000037 00000131"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000" // PW session
        "0004 0000 0000" // inSensitive (param 1)
        "000E 0008 0010 00040040 0000 0010 0000" // inPublic (param 2, nameAlg = NULL)
        "0000" // outsideInfo (param 3)
        "00000000" // creationPCR (param 4)
    );
    tpm.execute_command_separate(&mut global_state, &req_cp_null_name_alg, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "CreatePrimary with nameAlg == TPM_ALG_NULL must return TPM_RC_HASH + P2 (0x2C3)"
    );

    // 2. TPM2_Create (0x0153) with nameAlg = TPM_ALG_NULL -> TPM_RC_HASH + P2 (0x2C3)
    // Note: command parameter unmarshalling occurs before handle resolution!
    let req_create_null_name_alg = hex!(
        "8002 00000037 00000153"
        "80000000" // parentHandle
        "00000009" "40000009 0000 01 0000" // PW session
        "0004 0000 0000" // inSensitive (param 1)
        "000E 0008 0010 00040040 0000 0010 0000" // inPublic (param 2, nameAlg = NULL)
        "0000" // outsideInfo (param 3)
        "00000000" // creationPCR (param 4)
    );
    tpm.execute_command_separate(&mut global_state, &req_create_null_name_alg, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Create with nameAlg == TPM_ALG_NULL must return TPM_RC_HASH + P2 (0x2C3)"
    );

    // 3. TPM2_Load (0x0157) with nameAlg = TPM_ALG_NULL -> TPM_RC_HASH + P2 (0x2C3)
    // Header: 8002, size = 10 + 4 + 4 + 9 + 2 (inPrivate size=0) + 16 (inPublic) = 45 (0x2D)
    let req_load_null_name_alg = hex!(
        "8002 0000002D 00000157"
        "80000000" // parentHandle
        "00000009" "40000009 0000 01 0000" // PW session
        "0000" // inPrivate (param 1)
        "000E 0008 0010 00040040 0000 0010 0000" // inPublic (param 2, nameAlg = NULL)
    );
    tpm.execute_command_separate(&mut global_state, &req_load_null_name_alg, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Load with nameAlg == TPM_ALG_NULL must return TPM_RC_HASH + P2 (0x2C3)"
    );

    // 4. TPM2_Import (0x0156) with nameAlg = TPM_ALG_NULL -> TPM_RC_HASH + P2 (0x2C3)
    // Header: 8002, size = 10 + 4 + 4 + 9 + 2 (encryptionKey) + 16 (objectPublic) + 2 (duplicate) + 2 (inSymSeed) + 2 (symmetricAlg=NULL) = 51 (0x33)
    let req_import_null_name_alg = hex!(
        "8002 00000033 00000156"
        "80000000" // parentHandle
        "00000009" "40000009 0000 01 0000" // PW session
        "0000" // encryptionKey (param 1)
        "000E 0008 0010 00040040 0000 0010 0000" // objectPublic (param 2, nameAlg = NULL)
        "0000" // duplicate (param 3)
        "0000" // inSymSeed (param 4)
        "0010" // symmetricAlg (param 5)
    );
    tpm.execute_command_separate(&mut global_state, &req_import_null_name_alg, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Import with nameAlg == TPM_ALG_NULL must return TPM_RC_HASH + P2 (0x2C3)"
    );

    // 4b. TPM2_CreateLoaded (0x0191) with nameAlg = TPM_ALG_NULL -> TPM_RC_HASH + P2 (0x2C3)
    // Header: 8002, size = 10 + 4 + 4 + 9 + 6 (inSensitive) + 16 (inPublic) = 49 (0x31)
    let req_create_loaded_null_name_alg = hex!(
        "8002 00000031 00000191"
        "40000001" // RH_OWNER
        "00000009" "40000009 0000 01 0000" // PW session
        "0004 0000 0000" // inSensitive (param 1)
        "000E 0008 0010 00040040 0000 0010 0000" // inPublic template (param 2, nameAlg = NULL)
    );
    tpm.execute_command_separate(
        &mut global_state,
        &req_create_loaded_null_name_alg,
        &mut resp,
    );
    assert_eq!(
        response_rc(&resp),
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
    let req_load_external_null_name_alg = hex!(
        "8001 0000002E 00000167"
        "000C 0008 0000 0000 0004 deadbeef"
        "0010 0008 0010 00040040 0000 0005 000B 0000"
        "40000007"
    );
    tpm.execute_command_separate(
        &mut global_state,
        &req_load_external_null_name_alg,
        &mut resp,
    );
    assert_eq!(
        response_rc(&resp),
        0,
        "LoadExternal with nameAlg == TPM_ALG_NULL must succeed"
    );
    let loaded_handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);

    // 6. TPM2_ReadPublic (0x0173) on the loaded null-nameAlg object -> SUCCEEDS and returns nameAlg = NULL
    let mut req_read_public = [0u8; 14];
    req_read_public[0..10].copy_from_slice(&hex!("8001 0000000E 00000173"));
    req_read_public[10..14].copy_from_slice(&loaded_handle.to_be_bytes());
    tpm.execute_command_separate(&mut global_state, &req_read_public, &mut resp);
    assert_eq!(
        response_rc(&resp),
        0,
        "ReadPublic on object with null nameAlg must succeed"
    );
    // Parse ReadPublicRsp using tpm2::commands::responses::ReadPublic
    let resp_len = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
    let mut resp_body = &resp[10..resp_len];
    let parsed_rsp = tpm2::Unmarshal::unmarshal(&mut resp_body)
        .expect("ReadPublicRsp unmarshal must succeed for null nameAlg object");
    let parsed_rsp: tpm2::commands::responses::ReadPublic = parsed_rsp;
    assert_eq!(
        parsed_rsp.out_public.to_struct_nullable().unwrap().name_alg,
        None
    );
}

#[test]
fn test_engine_rsa_encrypt_and_decrypt_reject_signature_schemes_on_unmarshal() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let mut resp = [0u8; 256];

    let key_handle = 0x80000001;
    let public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::DECRYPT | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    global_state.transient_objects[0] = Some(tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: tpm2::Tpm2bName::default().into(),
        auth: tpm2::Tpm2bAuth::default().into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: tpm2::Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    });

    // 1. TPM2_RSA_Encrypt (0x0174) with RSASSA (0x0014) in inScheme (param 2) -> TPM_RC_VALUE + P2
    // Header (10) + keyHandle (4) + message (2) + inScheme (4) + label (2) = 22 (0x16)
    let req_enc_rsassa = hex!(
        "8001 00000016 00000174"
        "80000001"
        "0000"
        "0014 000B"
        "0000"
    );
    tpm.execute_command_separate(&mut global_state, &req_enc_rsassa, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "RSA_Encrypt with RSASSA in inScheme (param 2) must return TPM_RC_VALUE + P2"
    );

    // 2. TPM2_RSA_Encrypt (0x0174) with RSAPSS (0x0016) in inScheme (param 2) -> TPM_RC_VALUE + P2
    let req_enc_rsapss = hex!(
        "8001 00000016 00000174"
        "80000001"
        "0000"
        "0016 000B"
        "0000"
    );
    tpm.execute_command_separate(&mut global_state, &req_enc_rsapss, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "RSA_Encrypt with RSAPSS in inScheme (param 2) must return TPM_RC_VALUE + P2"
    );

    // 3. TPM2_RSA_Encrypt (0x0174) with OAEP (0x0017) + NULL hash (0x0010) in inScheme (param 2) -> TPM_RC_HASH + P2
    let req_enc_oaep_null_hash = hex!(
        "8001 00000016 00000174"
        "80000001"
        "0000"
        "0017 0010"
        "0000"
    );
    tpm.execute_command_separate(&mut global_state, &req_enc_oaep_null_hash, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "RSA_Encrypt with OAEP and NULL inner hash in inScheme (param 2) must return TPM_RC_HASH + P2"
    );

    // 4. TPM2_RSA_Decrypt (0x0159) with RSASSA (0x0014) in inScheme (param 2) -> TPM_RC_VALUE + P2
    // Header (10) + keyHandle (4) + authSize (4) + PW session (9) + cipherText (2) + inScheme (4) + label (2) = 35 (0x23)
    let req_dec_rsassa = hex!(
        "8002 00000023 00000159"
        "80000001"
        "00000009" "40000009 0000 01 0000"
        "0000"
        "0014 000B"
        "0000"
    );
    tpm.execute_command_separate(&mut global_state, &req_dec_rsassa, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "RSA_Decrypt with RSASSA in inScheme (param 2) must return TPM_RC_VALUE + P2"
    );

    // 5. TPM2_RSA_Decrypt (0x0159) with RSAPSS (0x0016) in inScheme (param 2) -> TPM_RC_VALUE + P2
    let req_dec_rsapss = hex!(
        "8002 00000023 00000159"
        "80000001"
        "00000009" "40000009 0000 01 0000"
        "0000"
        "0016 000B"
        "0000"
    );
    tpm.execute_command_separate(&mut global_state, &req_dec_rsapss, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "RSA_Decrypt with RSAPSS in inScheme (param 2) must return TPM_RC_VALUE + P2"
    );

    // 6. TPM2_RSA_Decrypt (0x0159) with OAEP (0x0017) + NULL hash (0x0010) in inScheme (param 2) -> TPM_RC_HASH + P2
    let req_dec_oaep_null_hash = hex!(
        "8002 00000023 00000159"
        "80000001"
        "00000009" "40000009 0000 01 0000"
        "0000"
        "0017 0010"
        "0000"
    );
    tpm.execute_command_separate(&mut global_state, &req_dec_oaep_null_hash, &mut resp);
    assert_eq!(
        response_rc(&resp),
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "RSA_Decrypt with OAEP and NULL inner hash in inScheme (param 2) must return TPM_RC_HASH + P2"
    );
}
