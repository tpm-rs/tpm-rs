use common::marshal_to_slice;

use tpm2::{Marshal, Unmarshal};
extern crate alloc;

mod common;

use alloc::vec::Vec;
use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    Command, Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, Load, LoadHandles,
    PolicyCounterTimer, PolicyCounterTimerHandles, PolicyGetDigest, PolicyGetDigestHandles,
    PolicyLocality, PolicyLocalityHandles, PolicyNameHash, PolicyNameHashHandles, PolicyPCR,
    PolicyPCRHandles, PolicyPassword, PolicyPasswordHandles, ReadClock, StartAuthSession,
    StartAuthSessionHandles, Unseal, UnsealHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmEo, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bNonce, Tpm2bOperand,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaLocality, TpmaObject, TpmaSession, TpmiAlgHash,
    TpmiAlgSymMode, TpmiRsaKeyBits, TpmlPcrSelection, TpmsAuthCommand, TpmsPcrSelection,
    TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic, TpmtSymDefObject,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn hash_bytes<const N: usize>(alg: TpmiAlgHash, data: &[u8]) -> [u8; N] {
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(&TestCryptoProvider, alg, data, &mut out)
        .unwrap()
        .digest()
        .try_into()
        .unwrap()
}

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup(CLEAR)
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
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
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

#[test]
fn test_policy_name_hash_success() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Start a SHA256 trial policy session via StartAuthSession
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // Send TPM2_PolicyNameHash with a test 32-byte nameHash
    let name_hash_bytes = [0x42u8; 32];
    let name_hash = Tpm2bDigest::from_bytes(&name_hash_bytes).unwrap();
    let pnh_handles = PolicyNameHashHandles {
        policy_session: policy_session_handle,
    };
    let pnh_cmd = PolicyNameHash { name_hash };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pnh_handles, &pnh_cmd, &[]);
    assert!(
        res.is_ok(),
        "Expected TPM2_PolicyNameHash to succeed, but failed with rc: {:?}",
        res.err()
    );

    // Invoke PolicyGetDigest to verify the resulting digest
    let pgd_handles = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let pgd_cmd = PolicyGetDigest {};
    let (_, pgd_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &pgd_handles, &pgd_cmd, &[]).unwrap();

    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&[0u8; 32]);
    data_to_hash.extend_from_slice(&(TpmCc::PolicyNameHash.code()).to_be_bytes());
    data_to_hash.extend_from_slice(&name_hash_bytes);

    let digest = hash_bytes::<32>(TpmiAlgHash::Sha256, &data_to_hash);

    assert_eq!(pgd_rsp.policy_digest.get_buffer(), &digest[..]);
}

#[test]
fn test_policy_name_hash_hmac_session_fails() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Start an HMAC session via StartAuthSession
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let session_handle = session_resp.session_handle;

    let name_hash = Tpm2bDigest::from_bytes(&[0x42u8; 32]).unwrap();
    let pnh_handles = PolicyNameHashHandles {
        policy_session: session_handle,
    };
    let pnh_cmd = PolicyNameHash { name_hash };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pnh_handles, &pnh_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}

#[test]
fn test_policy_locality_match_success() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    global_state.locality = 0;

    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = session_resp.session_handle;

    let loc_handles = PolicyLocalityHandles {
        policy_session: policy_session_handle,
    };
    let loc_cmd = PolicyLocality {
        locality: TpmaLocality(1), // LOC_ZERO (bit 0 set)
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &loc_handles, &loc_cmd, &[]);
    assert!(
        res.is_ok(),
        "Expected PolicyLocality(LOC_ZERO) to succeed when locality=0, got {:?}",
        res.err()
    );

    let pgd_handles = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let pgd_cmd = PolicyGetDigest {};
    let (_, pgd_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &pgd_handles, &pgd_cmd, &[]).unwrap();

    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&[0u8; 32]);
    data_to_hash.extend_from_slice(&(TpmCc::PolicyLocality.code()).to_be_bytes());
    data_to_hash.extend_from_slice(&[1u8]);

    let digest = hash_bytes::<32>(TpmiAlgHash::Sha256, &data_to_hash);
    assert_eq!(pgd_rsp.policy_digest.get_buffer(), &digest[..]);
}

#[test]
fn test_policy_locality_mismatch_fails() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    global_state.locality = 0;

    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = session_resp.session_handle;

    let loc_handles = PolicyLocalityHandles {
        policy_session: policy_session_handle,
    };
    let loc_cmd = PolicyLocality {
        locality: TpmaLocality(8), // LOC_THREE (bit 3 set)
    };
    let _ = execute_tpm_command(&mut tpm, &mut global_state, &loc_handles, &loc_cmd, &[]).unwrap();

    let loc_cmd2 = PolicyLocality {
        locality: TpmaLocality(1), // LOC_ZERO (bit 0 set, intersection with bit 3 is 0)
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &loc_handles, &loc_cmd2, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::RANGE.with(Position::parameter(1)).get())
    );
}

#[test]
fn test_policy_password_enforcement() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    // Compute expected policy digest after PolicyPassword:
    // SHA256(32 zero bytes || TPM_CC_PolicyAuthValue)
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(&[0u8; 32]);
    to_hash.extend_from_slice(&(TpmCc::PolicyAuthValue.code()).to_be_bytes());
    let expected_policy = hash_bytes::<32>(TpmiAlgHash::Sha256, &to_hash);

    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a primary storage parent under Owner hierarchy
    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle(0x40000001),
    };
    let parent_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let parent_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        in_sensitive: parent_sensitive,
        in_public: tpm2::Tpm2b(parent_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    // CreatePrimary/Create/Load need a session for their auth-role handle even with an empty
    // authValue (C: TPM_RC_AUTH_MISSING otherwise, SessionProcess.c CheckAuthNoSession).
    let (cp_resp, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &cp_handles,
        &cp_cmd,
        &[common::password_auth(b"")],
    )
    .unwrap();
    let parent_handle = cp_resp.object_handle;

    // 2. Create a KeyedHash sealed data object under parent_handle
    let secret_data = b"secret_unsealed_data";
    let user_auth = b"secret_password";
    let create_handles = CreateHandles { parent_handle };
    let item_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::from_bytes(&expected_policy).unwrap(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };
    let item_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(user_auth).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(secret_data).unwrap(),
    });
    let create_cmd = Create {
        in_sensitive: item_sensitive,
        in_public: tpm2::Tpm2b(item_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (_, create_resp) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &create_handles,
        &create_cmd,
        &[common::password_auth(b"")],
    )
    .unwrap();

    // 3. Load the sealed data object
    let load_handles = LoadHandles { parent_handle };
    let load_cmd = Load {
        in_private: create_resp.out_private,
        in_public: create_resp.out_public,
    };
    let (load_resp, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &load_handles,
        &load_cmd,
        &[common::password_auth(b"")],
    )
    .unwrap();
    let item_handle = load_resp.object_handle;

    // Start a policy session
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = session_resp.session_handle;

    // Execute PolicyPassword
    let pp_handles = PolicyPasswordHandles {
        policy_session: policy_session_handle,
    };
    let pp_cmd = PolicyPassword {};
    execute_tpm_command(&mut tpm, &mut global_state, &pp_handles, &pp_cmd, &[]).unwrap();

    // Verify PolicyGetDigest matches expected_policy
    let pgd_handles = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let pgd_cmd = PolicyGetDigest {};
    let (_, pgd_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &pgd_handles, &pgd_cmd, &[]).unwrap();
    assert_eq!(pgd_rsp.policy_digest.get_buffer(), &expected_policy[..]);

    // Attempt unsealing using this policy session, but without satisfying is_password_needed (bad/empty password auth)
    let unseal_handles = UnsealHandles { item_handle };
    let unseal_cmd = Unseal {};
    let bad_auth = TpmsAuthCommand {
        session_handle: Handle(policy_session_handle.0),
        nonce: Tpm2bNonce::from_bytes(&[2; 32]).unwrap(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::default(), // empty password/hmac when password is required
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &unseal_handles,
        &unseal_cmd,
        &[bad_auth],
    );
    // The sealed object is NO_DA (DA-exempt), so C IncrementLockout returns
    // TPM_RC_BAD_AUTH + S1 rather than AUTH_FAIL (SessionProcess.c:105-118).
    assert_eq!(
        res.err(),
        Some(TpmRc::BAD_AUTH.with(Position::session(1)).get())
    );

    // Now provide valid password auth along with policy session and verify success
    let good_auth = TpmsAuthCommand {
        session_handle: Handle(policy_session_handle.0),
        nonce: Tpm2bNonce::from_bytes(&[3; 32]).unwrap(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::from_bytes(user_auth).unwrap(),
    };
    let (_, unseal_rsp) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &unseal_handles,
        &unseal_cmd,
        &[good_auth],
    )
    .unwrap();
    assert_eq!(unseal_rsp.out_data.get_buffer(), secret_data);
}

#[test]
fn test_policy_counter_timer_success() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Start policy session via StartAuthSession
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = session_resp.session_handle;

    // Call ReadClock to obtain the current clock value
    let (_, rc_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &ReadClock {}, &[]).unwrap();
    let clock_val = rc_rsp.current_time.clock_info.clock;

    // Call TPM2_PolicyCounterTimer with operation=EQ against clock value (offset = 8)
    let pct_handles = PolicyCounterTimerHandles {
        policy_session: policy_session_handle,
    };
    let clock_bytes = clock_val.to_be_bytes();
    let operand_b = Tpm2bOperand::from_bytes(&clock_bytes).unwrap();
    let pct_cmd = PolicyCounterTimer {
        operand_b,
        offset: 8,
        operation: TpmEo::Eq,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &pct_handles, &pct_cmd, &[]);
    assert!(
        res.is_ok(),
        "Expected TPM2_PolicyCounterTimer to succeed, but failed with rc: {:?}",
        res.err()
    );

    // Verify PolicyGetDigest matches expected policy digest accumulation
    let pgd_handles = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let pgd_cmd = PolicyGetDigest {};
    let (_, pgd_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &pgd_handles, &pgd_cmd, &[]).unwrap();

    let mut arg_data = Vec::new();
    arg_data.extend_from_slice(pct_cmd.operand_b.get_buffer());
    arg_data.extend_from_slice(&8u16.to_be_bytes());
    arg_data.extend_from_slice(&u16::from(TpmEo::Eq).to_be_bytes());
    let arg_hash = hash_bytes::<32>(TpmiAlgHash::Sha256, &arg_data);

    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&[0u8; 32]);
    data_to_hash.extend_from_slice(&(TpmCc::PolicyCounterTimer.code()).to_be_bytes());
    data_to_hash.extend_from_slice(&arg_hash[..]);
    let expected_digest = hash_bytes::<32>(TpmiAlgHash::Sha256, &data_to_hash);

    assert_eq!(pgd_rsp.policy_digest.get_buffer(), &expected_digest[..]);
}

#[test]
fn test_policy_pcr_trial_empty_sha1() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Test SHA1 trial session with empty pcr_digest. Like C (PolicyPCR.c: the trial branch
    // only overrides pcrDigest when one is provided), the digest of the current PCR values
    // (PCRComputeCurrentDigest) is used.
    let start_auth_cmd_sha1 = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 20]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha1,
    };
    let (sas_resp_sha1, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        &start_auth_cmd_sha1,
        &[],
    )
    .expect("StartAuthSession SHA1 should succeed");

    let pcr_selection_sha1 = TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::Sha1, &[0x00, 0x00, 0x01]).unwrap(), // PCR 16
    ])
    .unwrap();

    let policy_pcr_cmd_sha1 = PolicyPCR {
        pcr_digest: Tpm2bDigest::default(),
        pcrs: pcr_selection_sha1,
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PolicyPCRHandles {
            policy_session: sas_resp_sha1.session_handle,
        },
        &policy_pcr_cmd_sha1,
        &[],
    )
    .expect("PolicyPCR SHA1 on trial session should succeed");

    let (_, pgd_rsp_sha1) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PolicyGetDigestHandles {
            policy_session: sas_resp_sha1.session_handle,
        },
        &PolicyGetDigest {},
        &[],
    )
    .expect("PolicyGetDigest SHA1 should succeed");

    // Expected for SHA1: H_SHA1(zeros_20 || TPM_CC_PolicyPCR || pcrs || digestTPM), where
    // digestTPM = H_SHA1(PCR16 in the SHA1 bank, which is all zeros after Startup).
    let digest_tpm_sha1 = hash_bytes::<20>(TpmiAlgHash::Sha1, &[0u8; 20]);
    let mut data_to_hash_sha1 = Vec::new();
    data_to_hash_sha1.extend_from_slice(&[0u8; 20]);
    data_to_hash_sha1.extend_from_slice(&(TpmCc::PolicyPCR.code()).to_be_bytes());
    let mut pcr_sel_buf_sha1 = [0u8; 64];
    let pcr_sel_len_sha1 = marshal_to_slice(&(pcr_selection_sha1), &mut pcr_sel_buf_sha1[..]);
    data_to_hash_sha1.extend_from_slice(&pcr_sel_buf_sha1[..pcr_sel_len_sha1]);
    data_to_hash_sha1.extend_from_slice(&digest_tpm_sha1[..]);
    let expected_digest_sha1 = hash_bytes::<20>(TpmiAlgHash::Sha1, &data_to_hash_sha1);

    assert_eq!(
        pgd_rsp_sha1.policy_digest.get_buffer(),
        &expected_digest_sha1[..],
        "SHA1 trial session with empty pcr_digest must substitute digestTPM"
    );
}

#[test]
fn test_policy_pcr_trial_empty_sha256() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 2. Test SHA256 trial session with empty pcr_digest (must substitute digestTPM)
    let start_auth_cmd_sha256 = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (sas_resp_sha256, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        &start_auth_cmd_sha256,
        &[],
    )
    .expect("StartAuthSession SHA256 should succeed");

    let pcr_selection_sha256 = TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x8F, 0x00, 0x00]).unwrap(), // PCRs 0, 1, 2, 3, 7
    ])
    .unwrap();

    let policy_pcr_cmd_sha256 = PolicyPCR {
        pcr_digest: Tpm2bDigest::default(),
        pcrs: pcr_selection_sha256,
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PolicyPCRHandles {
            policy_session: sas_resp_sha256.session_handle,
        },
        &policy_pcr_cmd_sha256,
        &[],
    )
    .expect("PolicyPCR SHA256 on trial session should succeed");

    let (_, pgd_rsp_sha256) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PolicyGetDigestHandles {
            policy_session: sas_resp_sha256.session_handle,
        },
        &PolicyGetDigest {},
        &[],
    )
    .expect("PolicyGetDigest SHA256 should succeed");

    // Expected for SHA256: H_SHA256(zeros_32 || TPM_CC_PolicyPCR || pcrs || digestTPM)
    let mut pcr_data_sha256 = Vec::new();
    for _ in 0..5 {
        pcr_data_sha256.extend_from_slice(&[0u8; 32]);
    }
    let digest_tpm_sha256 = hash_bytes::<32>(TpmiAlgHash::Sha256, &pcr_data_sha256);

    let mut data_to_hash_sha256 = Vec::new();
    data_to_hash_sha256.extend_from_slice(&[0u8; 32]);
    data_to_hash_sha256.extend_from_slice(&(TpmCc::PolicyPCR.code()).to_be_bytes());
    let mut pcr_sel_buf_sha256 = [0u8; 64];
    let pcr_sel_len_sha256 = marshal_to_slice(&(pcr_selection_sha256), &mut pcr_sel_buf_sha256[..]);
    data_to_hash_sha256.extend_from_slice(&pcr_sel_buf_sha256[..pcr_sel_len_sha256]);
    data_to_hash_sha256.extend_from_slice(&digest_tpm_sha256[..]);

    let expected_digest_sha256 = hash_bytes::<32>(TpmiAlgHash::Sha256, &data_to_hash_sha256);

    assert_eq!(
        pgd_rsp_sha256.policy_digest.get_buffer(),
        &expected_digest_sha256[..],
        "SHA256 trial session with empty pcr_digest must substitute digestTPM"
    );
}
