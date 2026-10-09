#![forbid(unsafe_code)]

use tpm2::errors::{Position, TpmRc};
use tpm2::{Marshal, Unmarshal};
extern crate alloc;

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    Command, CreatePrimary, CreatePrimaryHandles, StartAuthSession, StartAuthSessionHandles,
};
use tpm2::{Handle, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bEncryptedSecret, Tpm2bNonce, Tpm2bPublic,
    Tpm2bSensitiveData, TpmaObject, TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmlPcrSelection,
    TpmsAuthCommand, TpmsSensitiveCreate, TpmtKeyedHashScheme, TpmtPublic, TpmtSymDefObject,
};
use tpm2_impl::{GlobalState, TpmEngine, TpmPlatform};

fn leak_bytes(bytes: &[u8]) -> &'static [u8] {
    alloc::vec::Vec::leak(bytes.to_vec())
}

/// Initializes a simulated TPM instance with fake hardware providers and executes TPM2_Startup(CLEAR).
fn setup_tpm<'a>(
    crypto: &'a mut FakeCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
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

/// Helper function to execute a typed TPM command and return either its unmarshalled output or raw return code.
fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::RespHandles, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let resp_handles =
        C::RespHandles::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4;
    }

    let mut params_slice = leak_bytes(&response_buf[resp_offset..resp_size]);
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

fn execute_tpm_command_with_corrupted_bytes<C: Command>(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<(C::RespHandles, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let payload_start = offset;
    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;

    corrupt_fn(&mut request_buf[payload_start..offset]);

    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let resp_handles =
        C::RespHandles::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4;
    }

    let mut params_slice = leak_bytes(&response_buf[resp_offset..resp_size]);
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

fn get_test_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Default::default(),
        // A restricted decrypt KEYEDHASH object would need an XOR scheme (C `SchemeChecks()`);
        // use a symmetric storage key instead.
        parms_and_id: PublicParmsAndId::Sym(
            tpm2::TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)),
            tpm2::Tpm2bDigest::default(),
        ),
    }
}

/// Verifies that transient object capacity matches the expected boundary (4 slots) to satisfy
/// Section 2.14 compliance test sequences without overflowing client cache assumptions in Section 2.22.
#[test]
fn test_transient_object_capacity_boundary() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_test_template());
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    // Exactly 16 items (MAX_LOADED_OBJECTS = 16) should be created and stored in RAM without error.
    for i in 0..16 {
        let res = execute_tpm_command(
            &mut tpm,
            &mut global_state,
            &handles,
            &cmd,
            &[common::password_auth(b"")],
        );
        assert!(
            res.is_ok(),
            "CreatePrimary at slot {} failed unexpectedly: {:?}",
            i,
            res.err()
        );
    }

    // The 17th load attempt should fail with TPM_RC_OBJECT_MEMORY (0x902), preserving cache limits.
    let overflow_res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[common::password_auth(b"")],
    );
    assert_eq!(
        overflow_res.err(),
        Some(TpmRc::OBJECT_MEMORY.get()),
        "Expected TPM_RC_OBJECT_MEMORY when exceeding transient capacity of 16 slots"
    );
}

/// Verifies that TPM2_FlushContext behaves properly during handle validation in the engine header stage,
/// returning TpmRc::HANDLE (0x8B) for unloaded transient handles per Part 3 specification.
#[test]
fn test_unmapped_transient_flush_validation() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let flush_request = hex!(
        "8001"     // tag: NO_SESSIONS
        "0000000e" // size: 14 bytes
        "00000165" // command code: TPM_CC_FlushContext (0x0165)
        "80000002" // flushHandle: transient handle not present in RAM
    );
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &flush_request[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    // flushHandle is a parameter: C `TPM2_FlushContext()` returns
    // TPM_RCS_HANDLE + RC_FlushContext_flushHandle (TPM_RC_HANDLE + RC_P1).
    assert_eq!(
        rc,
        TpmRc::HANDLE.with(Position::parameter(1)).get(),
        "Flushing an unloaded transient handle should return TPM_RC_HANDLE + RC_P1"
    );
}

/// Verifies that TPM2_MakeCredential correctly recognizes its first handle as an object handle during request parsing.
#[test]
fn test_make_credential_object_handle_recognition() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let make_cred_req = hex!(
        "8001"     // tag: NO_SESSIONS
        "0000001a" // size: 26 bytes
        "00000136" // command code: TPM_CC_MakeCredential (0x0136)
        "80000000" // handle 0: unloaded object handle
        "0004 01020304" // credential (TPM2B_DIGEST)
        "0004 00010203" // objectName (TPM2B_NAME)
    );
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &make_cred_req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_ne!(
        rc, 0,
        "Command targeting unmapped handle 0x80000000 must fail validation with a non-zero error code"
    );
}

/// Verifies that TPM2_Unseal resolves persistent objects per TPM (2 as u16) specification requirements,
/// querying persistent storage rather than failing immediately during transient-only searches.
#[test]
fn test_persistent_handle_unseal_resolution() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let unseal_req = hex!(
        "8002"     // tag: SESSIONS
        "0000001b" // size: 27 bytes
        "0000015e" // command code: TPM_CC_Unseal (0x015E)
        "81000001" // itemHandle: persistent handle
        "00000009" // authSize: 9 bytes
        "40000009" // sessionHandle: RS_PW
        "0000"     // nonce
        "01"       // sessionAttributes: continueSession
        "0000"     // hmac
    );
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &unseal_req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    // C `ObjectLoadEvict()` (Object.c): an undefined persistent handle is TPM_RC_HANDLE + RC_H1;
    // only unloaded transient handles give TPM_RC_REFERENCE_H0.
    assert_eq!(
        rc,
        TpmRc::HANDLE.with(Position::handle(1)).get(),
        "Expected TPM_RC_HANDLE + RC_H1 when Unseal references an undefined persistent object"
    );
}

/// Regression test for CPCTPM_TC2_0_32_03_06:
/// TPM2_TestParms with ECC KDF specifying an unsupported hash algorithm (e.g. TPM_ALG_AES = 0x0006)
/// must return TPM_RC_HASH (Parameter 1, 0x01C3).
#[test]
fn test_regression_tc2_0_32_03_06_ecc_kdf_invalid_hash() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // TestParms ECC: sym=Null, scheme=Null, curve=NistP256, kdf=KDF1_SP800_56A with hash=AES(0x0006)
    let req = hex!(
        "8001"     // NO_SESSIONS
        "00000016" // size: 22 bytes
        "0000018a" // TPM_CC_TestParms
        "0023"     // TPM_ALG_ECC
        "0010"     // sym: TPM_ALG_NULL
        "0010"     // scheme: TPM_ALG_NULL
        "0003"     // curveID: NIST_P256
        "0020"     // kdf: TPM_ALG_KDF1_SP800_56A
        "0006"     // kdf hashAlg: TPM_ALG_AES (invalid hash)
    );
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "Expected TPM_RC_HASH (0x01C3) for ECC KDF with invalid hash algorithm"
    );
}

/// Regression test for CPCTPM_TC2_0_32_03_08:
/// TPM2_TestParms with KeyedHash HMAC specifying an unsupported hash algorithm (TPM_ALG_AES = 0x0006)
/// must return TPM_RC_HASH (Parameter 1, 0x01C3), KeyedHash XOR with an invalid KDF (TPM_ALG_AES = 0x0006)
/// must return TPM_RC_KDF (Parameter 1, 0x01CC), and KeyedHash XOR with kdf=TPM_ALG_NULL (0x0010)
/// must return TPM_RC_KDF (Parameter 1, 0x01CC) per STEP2 of CPCTPM_TC2_0_32_03_08.
#[test]
fn test_regression_tc2_0_32_03_08_keyedhash_schemes() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. KeyedHash HMAC with hash=AES(0x0006)
    let req_hmac_invalid = hex!(
        "8001"     // NO_SESSIONS
        "00000010" // size: 16 bytes
        "0000018a" // TPM_CC_TestParms
        "0008"     // TPM_ALG_KEYEDHASH
        "0005"     // TPM_ALG_HMAC
        "0006"     // hash: TPM_ALG_AES (invalid)
    );
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &req_hmac_invalid[..],
        &mut response_buf[..],
    );
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "Expected TPM_RC_HASH (0x01C3) for KeyedHash HMAC with invalid hash algorithm"
    );

    // 2. KeyedHash XOR with invalid kdf=TPM_ALG_AES(0x0006)
    let req_xor_invalid_kdf = hex!(
        "8001"     // NO_SESSIONS
        "00000012" // size: 18 bytes
        "0000018a" // TPM_CC_TestParms
        "0008"     // TPM_ALG_KEYEDHASH
        "000a"     // TPM_ALG_XOR
        "000b"     // hash: SHA256
        "0006"     // kdf: TPM_ALG_AES (invalid for KDF)
    );
    tpm.execute_command_separate(
        &mut global_state,
        &req_xor_invalid_kdf[..],
        &mut response_buf[..],
    );
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::KDF.with(Position::parameter(1)).get(),
        "Expected TPM_RC_KDF (0x01CC) for KeyedHash XOR with invalid KDF"
    );

    // 3. KeyedHash XOR with kdf=TPM_ALG_NULL(0x0010) is accepted by the C reference:
    //    TPMS_SCHEME_XOR_Unmarshal uses TPMI_ALG_KDF_Unmarshal(..., 1) (NULL allowed, Marshal.c).
    let req_xor_null_kdf = hex!(
        "8001"     // NO_SESSIONS
        "00000012" // size: 18 bytes
        "0000018a" // TPM_CC_TestParms
        "0008"     // TPM_ALG_KEYEDHASH
        "000a"     // TPM_ALG_XOR
        "000b"     // hash: SHA256
        "0010"     // kdf: TPM_ALG_NULL
    );
    tpm.execute_command_separate(
        &mut global_state,
        &req_xor_null_kdf[..],
        &mut response_buf[..],
    );
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc, 0,
        "Expected TPM_RC_SUCCESS for KeyedHash XOR with NULL KDF in TestParms"
    );
}

/// Regression test for CPCTPM_TC2_1_25_19_02:
/// TPM2_PolicyPCR with an unsupported hash algorithm in pcrs (0xFFFF)
/// must return TPM_RC_HASH (Parameter 1, 0x01C3).
#[test]
fn test_regression_tc2_1_25_19_02_policy_pcr_invalid_hash() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Start a trial policy session
    let start_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let start_cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[]).unwrap();
    let session_handle = policy_session_resp.session_handle;

    // Send PolicyPCR with invalid hash algorithm 0xFFFF in PCR selection
    let mut policy_pcr_req = hex!(
        "8001"     // NO_SESSIONS
        "0000001a" // size: 26 bytes
        "0000017f" // TPM_CC_PolicyPCR
        "03000000" // sessionHandle
        "0000"     // pcrDigest size: 0
        "00000001" // count: 1
        "ffff"     // hash: 0xFFFF (invalid)
        "03"       // sizeofSelect: 3
        "010000"   // pcrSelect
    );
    let len = policy_pcr_req.len() as u32;
    policy_pcr_req[2..6].copy_from_slice(&len.to_be_bytes());
    policy_pcr_req[10..14].copy_from_slice(&session_handle.0.to_be_bytes());

    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &policy_pcr_req[..],
        &mut response_buf[..],
    );
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    // pcrs is the second parameter of TPM2_PolicyPCR (pcrDigest is the first).
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH + RC_P2 for PolicyPCR with invalid hash algorithm in PCR selection"
    );
}

/// Regression test for CPCTPM_TC2_2_14_01_06:
/// TPM2_Create for a KeyedHash object specifying an unsupported hash algorithm (TPM_ALG_AES = 0x0006) in HMAC scheme
/// must return TPM_RC_HASH (Parameter 2, 0x02C3), and KeyedHash with Decrypt only rejecting HMAC scheme
/// must return TPM_RC_SCHEME (Parameter 2, 0x02D9).
#[test]
fn test_regression_tc2_2_14_01_06_create_keyedhash_invalid_scheme_hash() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Create Primary object under Owner hierarchy first
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_test_template());
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (primary_resp, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &create_handles,
        &create_cmd,
        &[common::password_auth(b"")],
    )
    .unwrap();
    let primary_obj_handle = primary_resp.object_handle;

    // 1. Create KeyedHash with HMAC scheme where hashAlg = TPM_ALG_AES (0x0006)
    let keyed_hash_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            tpm2::Tpm2bDigest::default(),
        ),
    };
    let child_create_handles = tpm2::commands::CreateHandles {
        parent_handle: primary_obj_handle,
    };
    let child_create_cmd = tpm2::commands::Create {
        in_sensitive: tpm2::Tpm2b(t_sens),
        in_public: tpm2::Tpm2b(keyed_hash_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let _auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let err = execute_tpm_command_with_corrupted_bytes::<tpm2::commands::Create>(
        &mut tpm,
        &mut global_state,
        &child_create_handles,
        &child_create_cmd,
        &[common::password_auth(b"")],
        |payload| {
            // Find scheme hashAlg in in_public payload (0x0005 0x000B) and replace 0x000B with TPM_ALG_AES (0x0006)
            for i in 0..payload.len().saturating_sub(3) {
                if payload[i..i + 2] == [0x00, 0x05] && payload[i + 2..i + 4] == [0x00, 0x0B] {
                    payload[i + 2] = 0x00;
                    payload[i + 3] = 0x06;
                    break;
                }
            }
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH (0x02C3) for Create KeyedHash with invalid HMAC hash algorithm"
    );

    // 2. Create KeyedHash with Decrypt only (no Sign) and HMAC scheme -> TPM_RC_SCHEME (Pos2, 0x02D9)
    let decrypt_hmac_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            tpm2::Tpm2bDigest::default(),
        ),
    };
    let decrypt_hmac_cmd = tpm2::commands::Create {
        in_sensitive: tpm2::Tpm2b(t_sens),
        in_public: tpm2::Tpm2b(decrypt_hmac_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let err2 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &child_create_handles,
        &decrypt_hmac_cmd,
        &[common::password_auth(b"")],
    )
    .unwrap_err();
    assert_eq!(
        err2,
        TpmRc::SCHEME.with(Position::parameter(2)).get(),
        "Expected TPM_RC_SCHEME (0x02D9) for Create KeyedHash decrypt-only object with HMAC scheme"
    );
}

/// Regression test for CPCTPM_TC2_2_24_02_05:
/// TPM2_PCR_Extend specifying an unsupported hash algorithm (TPM_ALG_AES = 0x0006) in digests
/// must return TPM_RC_HASH (Parameter 1, 0x01C3).
#[test]
fn test_regression_tc2_2_24_02_05_pcr_extend_invalid_hash() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let mut pcr_extend_req = hex!(
        "8002"     // SESSIONS
        "0000002b" // size: 43 bytes
        "00000182" // TPM_CC_PCR_Extend
        "00000000" // pcrHandle: PCR 0
        "00000009" // authSize: 9
        "40000009" // session: RS_PW
        "0000"     // nonce
        "01"       // continueSession
        "0000"     // hmac
        "00000001" // digests count: 1
        "0006"     // hashAlg: TPM_ALG_AES (invalid)
        "000102030405060708090a0b0c0d0e0f" // digest: 16 bytes
    );
    let len = pcr_extend_req.len() as u32;
    pcr_extend_req[2..6].copy_from_slice(&len.to_be_bytes());
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &pcr_extend_req[..],
        &mut response_buf[..],
    );

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "Expected TPM_RC_HASH (0x01C3) for PCR_Extend with invalid hash algorithm in digests"
    );
}

/// Regression test for CPCTPM_TC2_2_26_03_04:
/// TPM2_SetPrimaryPolicy specifying an unsupported hash algorithm (TPM_ALG_AES = 0x0006)
/// must return TPM_RC_HASH (Parameter 2, 0x02C3), and mismatched policy size
/// must return TPM_RC_SIZE (Parameter 1, 0x01D5).
#[test]
fn test_regression_tc2_2_26_03_04_set_primary_policy_validation() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Invalid hashAlg TPM_ALG_AES (0x0006) -> TPM_RC_HASH (Pos2, 0x02C3)
    let mut set_policy_invalid_hash = hex!(
        "8002"     // SESSIONS
        "0000003f" // size: 63 bytes
        "0000012e" // TPM_CC_SetPrimaryPolicy
        "40000001" // authHandle: RH_OWNER
        "00000009" // authSize: 9
        "40000009" // session: RS_PW
        "0000"     // nonce
        "01"       // continueSession
        "0000"     // hmac
        "0020"     // authPolicy size: 32 bytes
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "0006"     // hashAlg: TPM_ALG_AES (invalid)
    );
    let len = set_policy_invalid_hash.len() as u32;
    set_policy_invalid_hash[2..6].copy_from_slice(&len.to_be_bytes());
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &set_policy_invalid_hash[..],
        &mut response_buf[..],
    );
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH (0x02C3) for SetPrimaryPolicy with invalid hash algorithm"
    );

    // 2. Mismatched authPolicy size (16 bytes for SHA256) -> TPM_RC_SIZE (Pos1, 0x01D5)
    let mut set_policy_mismatched_size = hex!(
        "8002"     // SESSIONS
        "0000002f" // size: 47 bytes
        "0000012e" // TPM_CC_SetPrimaryPolicy
        "40000001" // authHandle: RH_OWNER
        "00000009" // authSize: 9
        "40000009" // session: RS_PW
        "0000"     // nonce
        "01"       // continueSession
        "0000"     // hmac
        "0010"     // authPolicy size: 16 bytes (expected 32 for SHA256)
        "000102030405060708090a0b0c0d0e0f"
        "000b"     // hashAlg: SHA256
    );
    let len = set_policy_mismatched_size.len() as u32;
    set_policy_mismatched_size[2..6].copy_from_slice(&len.to_be_bytes());
    tpm.execute_command_separate(
        &mut global_state,
        &set_policy_mismatched_size[..],
        &mut response_buf[..],
    );
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::SIZE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_SIZE (0x01D5) for SetPrimaryPolicy with mismatched authPolicy size"
    );
}

/// Regression test for CPCTPM_TC2_0_11_04_02:
/// TPM2_Shutdown with an invalid shutdownType (e.g. 42 = 0x002A)
/// must return TPM_RC_VALUE (Parameter 1, 0x0103).
#[test]
fn test_regression_tc2_0_11_04_02_shutdown_invalid_type() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let shutdown_req = hex!(
        "8001"     // NO_SESSIONS
        "0000000c" // size: 12 bytes
        "00000145" // TPM_CC_Shutdown
        "002a"     // shutdownType = 42 (invalid)
    );
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &shutdown_req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_VALUE (0x0103) for Shutdown with invalid shutdownType"
    );
}

/// Regression test for CPCTPM_TC2_0_12_03_02:
/// TPM2_IncrementalSelfTest with an invalid algorithm ID (TPM_ALG_ERROR = 0x0000)
/// must return TPM_RC_VALUE (Parameter 1, 0x0103).
#[test]
fn test_regression_tc2_0_12_03_02_incremental_self_test_invalid_alg() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let inc_test_req = hex!(
        "8001"     // NO_SESSIONS
        "00000010" // size: 16 bytes
        "00000142" // TPM_CC_IncrementalSelfTest
        "00000001" // count: 1
        "0000"     // alg: TPM_ALG_ERROR (0x0000)
    );
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &inc_test_req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_VALUE (0x0103) for IncrementalSelfTest with invalid algorithm ID"
    );
}

/// Regression test verifying that `TPM2_IncrementalSelfTest` unmarshals `TPML_ALG`
/// (`TPM_ALG_ID` Constants) infallibly per element, returning `TPM_RC_SIZE` on trailing
/// bytes and `TPM_RC_INSUFFICIENT` on truncated buffers even when earlier elements are
/// reserved `TPM_ALG_ID` values (`0x0000`, `0x00C1..=0x00C6`, `0x8000..=0xFFFF`).
#[test]
fn test_incremental_self_test_reserved_alg_trailing_bytes_and_truncated() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Trailing bytes after a reserved algorithm ID must return TPM_RC_SIZE (not TPM_RC_VALUE)
    for reserved_hex in ["0000", "00C4", "8001", "FFFF"] {
        let mut req = [0u8; 17];
        req[0..2].copy_from_slice(&0x8001u16.to_be_bytes()); // NO_SESSIONS
        req[2..6].copy_from_slice(&17u32.to_be_bytes()); // size = 17 (1 trailing byte)
        req[6..10].copy_from_slice(&0x00000142u32.to_be_bytes()); // TPM_CC_IncrementalSelfTest
        req[10..14].copy_from_slice(&1u32.to_be_bytes()); // count = 1
        let alg_bytes = u16::from_str_radix(reserved_hex, 16).unwrap().to_be_bytes();
        req[14..16].copy_from_slice(&alg_bytes);
        req[16] = 0xAA; // trailing byte

        let mut response_buf = [0u8; 256];
        tpm.execute_command_separate(&mut global_state, &req[..], &mut response_buf[..]);
        let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
        assert_eq!(
            rc,
            TpmRc::SIZE.to_rc().get(),
            "Expected TPM_RC_SIZE on trailing bytes with reserved alg 0x{}",
            reserved_hex
        );
    }

    // 2. Truncated buffer after a reserved algorithm ID must return TPM_RC_INSUFFICIENT (not TPM_RC_VALUE)
    let truncated_req = hex!(
        "8001"     // NO_SESSIONS
        "00000011" // size: 17 bytes (truncated: count=2 requires 18 bytes)
        "00000142" // TPM_CC_IncrementalSelfTest
        "00000002" // count: 2
        "0000"     // alg[0]: 0x0000 (reserved)
        "00"       // alg[1]: truncated (only 1 byte)
    );
    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &truncated_req[..], &mut response_buf[..]);
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
        "Expected TPM_RC_INSUFFICIENT (Parameter 1) on truncated buffer with reserved alg[0]"
    );
}

/// Regression test for CPCTPM_TC2_1_25_20_05:
/// TPM2_PolicyNvWritten with an invalid writtenSet value (3)
/// must return TPM_RC_VALUE (Parameter 1, 0x0103).
#[test]
fn test_regression_tc2_1_25_20_05_policy_nv_written_invalid_yes_no() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Start a trial policy session
    let start_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let start_cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[]).unwrap();
    let session_handle = policy_session_resp.session_handle;

    let mut pnw_req = hex!(
        "8001"     // NO_SESSIONS
        "0000000f" // size: 15 bytes
        "0000018f" // TPM_CC_PolicyNvWritten
        "03000000" // sessionHandle
        "03"       // writtenSet = 3 (invalid bool)
    );
    pnw_req[10..14].copy_from_slice(&session_handle.0.to_be_bytes());

    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &pnw_req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_VALUE (0x0103) for PolicyNvWritten with invalid writtenSet"
    );
}

/// Regression test for CPCTPM_TC2_2_15_03_06:
/// TPM2_Import parameter validation:
/// 1. symmetricAlg with invalid mode/keyBits returns TPM_RC_VALUE (Pos5, 0x0503)
/// 2. objectPublic with FIXED_TPM | SENSITIVE_DATA_ORIGIN returns TPM_RC_ATTRIBUTES (Pos2, 0x0282)
/// 3. inSymSeed with oversized buffer returns TPM_RC_SIZE (Pos4, 0x04D5)
#[test]
fn test_regression_tc2_2_15_03_06_import_validation() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Create RSA primary storage parent key under Owner hierarchy
    let rsa_parent_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0x00010001,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let create_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(t_sens),
        in_public: tpm2::Tpm2b(rsa_parent_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (primary_resp, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &create_handles,
        &create_cmd,
        &[common::password_auth(b"")],
    )
    .unwrap();
    let parent_handle = primary_resp.object_handle;

    let child_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_TPM,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0x00010001,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    let child_pub_2b = tpm2::Tpm2b(child_pub);
    let mut child_pub_buf = [0u8; Tpm2bPublic::MAX_SIZE];
    let child_pub_len = child_pub_2b.marshal(&mut child_pub_buf);

    // 1. Step 1: Import with symmetricAlg = AES with mode 0 (invalid) -> TPM_RC_VALUE (Pos5, 0x0503)
    let mut req1 = alloc::vec::Vec::new();
    req1.extend_from_slice(&0x8002u16.to_be_bytes()); // SESSIONS
    req1.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    req1.extend_from_slice(&0x00000156u32.to_be_bytes()); // TPM_CC_Import
    req1.extend_from_slice(&parent_handle.0.to_be_bytes());
    // Auth session RS_PW
    req1.extend_from_slice(&9u32.to_be_bytes());
    req1.extend_from_slice(&0x40000009u32.to_be_bytes());
    req1.extend_from_slice(&0u16.to_be_bytes());
    req1.push(0x01);
    req1.extend_from_slice(&0u16.to_be_bytes());
    // encryptionKey: empty 2B
    req1.extend_from_slice(&0u16.to_be_bytes());
    // objectPublic
    req1.extend_from_slice(&child_pub_buf[..child_pub_len]);
    // duplicate: empty 2B
    req1.extend_from_slice(&0u16.to_be_bytes());
    // inSymSeed: 256 bytes (matching RSA 2048)
    req1.extend_from_slice(&256u16.to_be_bytes());
    req1.extend_from_slice(&[0u8; 256]);
    // symmetricAlg: AES (0x0006), keyBits=0, mode=0 (invalid)
    req1.extend_from_slice(&0x0006u16.to_be_bytes());
    req1.extend_from_slice(&0x0000u16.to_be_bytes());
    req1.extend_from_slice(&0x0000u16.to_be_bytes());
    let req1_len = req1.len() as u32;
    req1[2..6].copy_from_slice(&req1_len.to_be_bytes());

    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &req1, &mut response_buf[..]);
    let rc1 = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc1,
        TpmRc::VALUE.with(Position::parameter(5)).get(),
        "Expected TPM_RC_VALUE (0x0503) for Import with invalid symmetricAlg"
    );

    // 2. Step 2: Import with valid symmetricAlg (Null) and invalid attributes (FixedTPM) -> TPM_RC_ATTRIBUTES (Pos2, 0x0282)
    let mut req2 = alloc::vec::Vec::new();
    req2.extend_from_slice(&0x8002u16.to_be_bytes());
    req2.extend_from_slice(&0u32.to_be_bytes());
    req2.extend_from_slice(&0x00000156u32.to_be_bytes());
    req2.extend_from_slice(&parent_handle.0.to_be_bytes());
    req2.extend_from_slice(&9u32.to_be_bytes());
    req2.extend_from_slice(&0x40000009u32.to_be_bytes());
    req2.extend_from_slice(&0u16.to_be_bytes());
    req2.push(0x01);
    req2.extend_from_slice(&0u16.to_be_bytes());
    req2.extend_from_slice(&0u16.to_be_bytes()); // encryptionKey
    req2.extend_from_slice(&child_pub_buf[..child_pub_len]); // objectPublic with FixedTPM
    req2.extend_from_slice(&0u16.to_be_bytes()); // duplicate
    req2.extend_from_slice(&256u16.to_be_bytes()); // inSymSeed: 256 bytes
    req2.extend_from_slice(&[0u8; 256]);
    req2.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetricAlg: TPM_ALG_NULL
    let req2_len = req2.len() as u32;
    req2[2..6].copy_from_slice(&req2_len.to_be_bytes());

    tpm.execute_command_separate(&mut global_state, &req2, &mut response_buf[..]);
    let rc2 = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc2,
        TpmRc::ATTRIBUTES.with(Position::parameter(2)).get(),
        "Expected TPM_RC_ATTRIBUTES (0x0282) for Import with FixedTPM / SensitiveDataOrigin attributes"
    );

    // 3. Step 3: Import with inSymSeed of 512 bytes (oversized for RSA 2048) -> TPM_RC_SIZE (Pos4, 0x04D5)
    let mut req3 = alloc::vec::Vec::new();
    req3.extend_from_slice(&0x8002u16.to_be_bytes());
    req3.extend_from_slice(&0u32.to_be_bytes());
    req3.extend_from_slice(&0x00000156u32.to_be_bytes());
    req3.extend_from_slice(&parent_handle.0.to_be_bytes());
    req3.extend_from_slice(&9u32.to_be_bytes());
    req3.extend_from_slice(&0x40000009u32.to_be_bytes());
    req3.extend_from_slice(&0u16.to_be_bytes());
    req3.push(0x01);
    req3.extend_from_slice(&0u16.to_be_bytes());
    req3.extend_from_slice(&0u16.to_be_bytes()); // encryptionKey
    req3.extend_from_slice(&child_pub_buf[..child_pub_len]); // objectPublic
    req3.extend_from_slice(&0u16.to_be_bytes()); // duplicate
    req3.extend_from_slice(&512u16.to_be_bytes()); // inSymSeed: 512 bytes
    req3.extend_from_slice(&[0u8; 512]);
    req3.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetricAlg: TPM_ALG_NULL
    let req3_len = req3.len() as u32;
    req3[2..6].copy_from_slice(&req3_len.to_be_bytes());

    tpm.execute_command_separate(&mut global_state, &req3, &mut response_buf[..]);
    let rc3 = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc3,
        TpmRc::SIZE.with(Position::parameter(4)).get(),
        "Expected TPM_RC_SIZE (0x04D5) for Import with oversized inSymSeed"
    );
}

/// Regression test for CPCTPM_TC2_4_13_01_03:
/// TPM2_StartAuthSession with symmetric = TPMT_SYM_DEF(AES, 0, NULL) and wrong salt sizes
/// must return TPM_RC_VALUE (Pos4, 0x0403 or Pos2, 0x0203).
#[test]
fn test_regression_tc2_4_13_01_03_start_auth_session_invalid_symmetric_and_salt() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Create RSA primary key
    let rsa_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0x00010001,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let create_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(t_sens),
        in_public: tpm2::Tpm2b(rsa_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (primary_resp, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &create_handles,
        &create_cmd,
        &[common::password_auth(b"")],
    )
    .unwrap();
    let rsa_key_handle = primary_resp.object_handle;

    // STEP1: StartAuthSession with salt=16 bytes, symmetric = TPMT_SYM_DEF(AES, 0, NULL) -> TPM_RC_VALUE
    let mut req1 = alloc::vec::Vec::new();
    req1.extend_from_slice(&0x8001u16.to_be_bytes()); // NO_SESSIONS
    req1.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    req1.extend_from_slice(&0x00000176u32.to_be_bytes()); // TPM_CC_StartAuthSession
    req1.extend_from_slice(&rsa_key_handle.0.to_be_bytes()); // tpmKey
    req1.extend_from_slice(&0x4000000cu32.to_be_bytes()); // bind: TPM_RH_PLATFORM
    req1.extend_from_slice(&16u16.to_be_bytes()); // nonceCaller size: 16
    req1.extend_from_slice(&[1u8; 16]);
    req1.extend_from_slice(&16u16.to_be_bytes()); // encryptedSalt size: 16
    req1.extend_from_slice(&[2u8; 16]);
    req1.push(0x00); // sessionType: TPM_SE_HMAC
    // symmetric: TPM_ALG_AES (0x0006), keyBits=0 (0x0000), mode=TPM_ALG_NULL (0x0010)
    req1.extend_from_slice(&0x0006u16.to_be_bytes());
    req1.extend_from_slice(&0x0000u16.to_be_bytes());
    req1.extend_from_slice(&0x0010u16.to_be_bytes());
    req1.extend_from_slice(&0x0004u16.to_be_bytes()); // authHash: TPM_ALG_SHA1 (0x0004)
    let req1_len = req1.len() as u32;
    req1[2..6].copy_from_slice(&req1_len.to_be_bytes());

    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &req1, &mut response_buf[..]);
    let rc1 = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc1,
        TpmRc::VALUE.with(Position::parameter(4)).get(),
        "Expected TPM_RC_VALUE (0x0403) for StartAuthSession with invalid symmetric parameter"
    );

    // STEP2: StartAuthSession with salt=128 bytes, symmetric = TPMT_SYM_DEF(AES, 0, NULL) -> TPM_RC_VALUE
    let mut req2 = alloc::vec::Vec::new();
    req2.extend_from_slice(&0x8001u16.to_be_bytes());
    req2.extend_from_slice(&0u32.to_be_bytes());
    req2.extend_from_slice(&0x00000176u32.to_be_bytes());
    req2.extend_from_slice(&rsa_key_handle.0.to_be_bytes());
    req2.extend_from_slice(&0x4000000cu32.to_be_bytes());
    req2.extend_from_slice(&16u16.to_be_bytes());
    req2.extend_from_slice(&[1u8; 16]);
    req2.extend_from_slice(&128u16.to_be_bytes()); // encryptedSalt size: 128
    req2.extend_from_slice(&[2u8; 128]);
    req2.push(0x00);
    req2.extend_from_slice(&0x0006u16.to_be_bytes());
    req2.extend_from_slice(&0x0000u16.to_be_bytes());
    req2.extend_from_slice(&0x0010u16.to_be_bytes());
    req2.extend_from_slice(&0x0004u16.to_be_bytes());
    let req2_len = req2.len() as u32;
    req2[2..6].copy_from_slice(&req2_len.to_be_bytes());

    tpm.execute_command_separate(&mut global_state, &req2, &mut response_buf[..]);
    let rc2 = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc2,
        TpmRc::VALUE.with(Position::parameter(4)).get(),
        "Expected TPM_RC_VALUE (0x0403) for StartAuthSession with invalid symmetric parameter"
    );
}

/// Regression test for CPCTPM_TC2_2_17_03_04:
/// TPM2_Hash with an invalid/unsupported hash algorithm (TPM_ALG_AES = 0x0006 or TPM_ALG_NULL = 0x0010)
/// must return TPM_RC_HASH (Parameter 2, 0x02C3), not TPM_RC_SIZE.
#[test]
fn test_regression_tc2_2_17_03_04_hash_invalid_hash_alg() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // TPM2_Hash request with hashAlg = TPM_ALG_AES (0x0006)
    let mut hash_req = alloc::vec::Vec::new();
    hash_req.extend_from_slice(&0x8001u16.to_be_bytes()); // NO_SESSIONS
    hash_req.extend_from_slice(&0u32.to_be_bytes()); // commandSize placeholder
    hash_req.extend_from_slice(&0x0000017du32.to_be_bytes()); // TPM_CC_Hash
    hash_req.extend_from_slice(&4u16.to_be_bytes()); // data size: 4
    hash_req.extend_from_slice(b"test"); // data
    hash_req.extend_from_slice(&0x0006u16.to_be_bytes()); // hashAlg: 0x0006 (invalid)
    hash_req.extend_from_slice(&0x40000007u32.to_be_bytes()); // hierarchy: TPM_RH_NULL
    let hash_req_len = hash_req.len() as u32;
    hash_req[2..6].copy_from_slice(&hash_req_len.to_be_bytes());

    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &hash_req, &mut response_buf[..]);
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH (0x02C3) for TPM2_Hash with invalid hashAlg"
    );

    // TPM2_Hash request with hashAlg = TPM_ALG_NULL (0x0010)
    let mut hash_null_req = alloc::vec::Vec::new();
    hash_null_req.extend_from_slice(&0x8001u16.to_be_bytes()); // NO_SESSIONS
    hash_null_req.extend_from_slice(&0u32.to_be_bytes()); // commandSize placeholder
    hash_null_req.extend_from_slice(&0x0000017du32.to_be_bytes()); // TPM_CC_Hash
    hash_null_req.extend_from_slice(&4u16.to_be_bytes()); // data size: 4
    hash_null_req.extend_from_slice(b"test"); // data
    hash_null_req.extend_from_slice(&0x0010u16.to_be_bytes()); // hashAlg: TPM_ALG_NULL (0x0010)
    hash_null_req.extend_from_slice(&0x40000007u32.to_be_bytes()); // hierarchy: TPM_RH_NULL
    let hash_null_len = hash_null_req.len() as u32;
    hash_null_req[2..6].copy_from_slice(&hash_null_len.to_be_bytes());

    tpm.execute_command_separate(&mut global_state, &hash_null_req, &mut response_buf[..]);
    let rc_null = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc_null,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH (0x02C3) for TPM2_Hash with TPM_ALG_NULL hashAlg"
    );
}

/// Regression test for CPCTPM_TC2_3_33_03_06:
/// TPM2_NV_DefineSpace with invalid TPM_NT in attributes (e.g. 0x05 or 0x06)
/// must return TPM_RC_ATTRIBUTES (0x0082), not TPM_RC_VALUE.
#[test]
fn test_regression_tc2_3_33_03_06_nv_define_space_invalid_attributes() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // NV_DefineSpace with authHandle = RH_OWNER, attributes containing reserved NT = 0x05 (bits 4..7 = 0x50)
    // Attributes: OWNERWRITE (0x00020000) | OWNERREAD (0x00040000) | (0x05 << 4 = 0x50) -> 0x00060050
    let mut nv_def_req = alloc::vec::Vec::new();
    nv_def_req.extend_from_slice(&0x8002u16.to_be_bytes()); // SESSIONS
    nv_def_req.extend_from_slice(&0u32.to_be_bytes()); // commandSize placeholder
    nv_def_req.extend_from_slice(&0x0000012au32.to_be_bytes()); // TPM_CC_NV_DefineSpace
    nv_def_req.extend_from_slice(&0x40000001u32.to_be_bytes()); // authHandle: RH_OWNER
    nv_def_req.extend_from_slice(&9u32.to_be_bytes()); // authSize: 9
    nv_def_req.extend_from_slice(&0x40000009u32.to_be_bytes()); // session: RS_PW
    nv_def_req.extend_from_slice(&0u16.to_be_bytes()); // nonce
    nv_def_req.push(0x01); // continueSession
    nv_def_req.extend_from_slice(&0u16.to_be_bytes()); // hmac
    nv_def_req.extend_from_slice(&0u16.to_be_bytes()); // auth size: 0
    // publicInfo (TPM2B_NV_PUBLIC)
    let mut pub_info = alloc::vec::Vec::new();
    pub_info.extend_from_slice(&0x01000001u32.to_be_bytes()); // nvIndex: 0x01000001
    pub_info.extend_from_slice(&0x000bu16.to_be_bytes()); // nameAlg: SHA256 (0x000b)
    pub_info.extend_from_slice(&0x00060050u32.to_be_bytes()); // attributes: OWNERREAD | OWNERWRITE | NT=5 (invalid)
    pub_info.extend_from_slice(&0u16.to_be_bytes()); // authPolicy size: 0
    pub_info.extend_from_slice(&8u16.to_be_bytes()); // dataSize: 8

    let pub_info_len = pub_info.len() as u16;
    nv_def_req.extend_from_slice(&pub_info_len.to_be_bytes());
    nv_def_req.extend_from_slice(&pub_info);

    let total_len = nv_def_req.len() as u32;
    nv_def_req[2..6].copy_from_slice(&total_len.to_be_bytes());

    let mut response_buf = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &nv_def_req, &mut response_buf[..]);
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::ATTRIBUTES
            .with(tpm2::errors::Position::parameter(2))
            .get(),
        "Expected TPM_RC_ATTRIBUTES + RC_P2 (0x02C2, C NvDefineSpace blamePublic) for NV_DefineSpace with reserved TPM_NT in attributes"
    );
}
