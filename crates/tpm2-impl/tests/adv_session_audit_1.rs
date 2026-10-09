extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{Command, GetCapability, GetSessionAuditDigest, GetSessionAuditDigestHandles};
use tpm2::crypto::Rng;
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{CryptoError, CryptoProvider};
use tpm2::{Handle, Marshal, TpmCap, TpmPt};
use tpm2::{Tpm2bAuth, Tpm2bData, TpmaSession, TpmiAlgHash, TpmsAuthCommand};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::SessionState;

struct StressTestCrypto;

impl_fake_hash!(StressTestCrypto);

impl AsymmetricSign for StressTestCrypto {
    fn sign_inner(
        &self,
        sign_alg: tpm2::Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = match sign_alg {
            tpm2::Alg::ECDSA => {
                if signature_out.len() < 64 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..64].fill(0xee);
                64
            }
            _ => {
                if signature_out.len() < 256 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..256].fill(0xee);
                256
            }
        };
        Ok(len)
    }
}

impl Asymmetric for StressTestCrypto {
    fn verify_inner(
        &self,
        _sign_alg: tpm2::Alg,
        _public_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }
    fn encrypt(
        &self,
        _scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        _public_key: &[u8],
        _data: &[u8],
        _ciphertext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        Ok(0)
    }
    fn decrypt(
        &self,
        _scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        if private_key.is_empty() {
            return Err(CryptoError::HardwareFailure);
        }
        let len = ciphertext.len();
        if plaintext.len() < len {
            return Err(CryptoError::BufferTooSmall);
        }
        plaintext[..len].copy_from_slice(ciphertext);
        Ok(len)
    }
    fn generate_key(
        &self,
        scheme: tpm2::Alg,
        _params: Option<tpm2::crypto::asymmetric::KeyParams>,
        public_key: &mut [u8],
        private_key: &mut [u8],
        _seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        match scheme {
            tpm2::Alg::RSA => {
                public_key[..256].fill(0xcc);
                private_key[..256].fill(0xdd);
                Ok((256, 256))
            }
            tpm2::Alg::ECC => {
                public_key[..64].fill(0xcc);
                private_key[..32].fill(0xdd);
                Ok((64, 32))
            }
            _ => Err(CryptoError::HardwareFailure),
        }
    }
}

impl Rng for StressTestCrypto {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        dest.fill(0xaa);
        Ok(())
    }
}

impl CryptoProvider for StressTestCrypto {}

fn setup_tpm<'a>(
    crypto: &'a mut StressTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup
    let startup_request = hex_literal::hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command_with_auths<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    // Tag
    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    // Command code
    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    // Marshal auth area if tag is 0x8002
    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4; // place holder for auth size
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

    // Fill in total Size
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    Ok(())
}

fn compute_mock_hmac(attributes: u8, nonce_tpm: &[u8]) -> Tpm2bAuth<'_> {
    let mut hmac = [0u8; 32];
    let mut digest = [0u8; 32];
    let input = [0, 0, 1, 0x7a, 0, 0, 0, 6, 0, 0, 1, 0, 0, 0, 0, 1];
    for (i, &b) in input.iter().enumerate() {
        digest[i % 32] ^= b;
    }

    // state = key (32) + digest (32) + nonce_tpm (len) + attributes (1)
    let state_len = 32 + 32 + nonce_tpm.len() + 1;

    for i in 0..32 {
        hmac[i] ^= digest[i];
    }
    for (i, &b) in nonce_tpm.iter().enumerate() {
        hmac[i % 32] ^= b;
    }
    hmac[(32 + 32 + nonce_tpm.len()) % 32] ^= attributes;
    hmac[1] ^= state_len as u8;

    Tpm2bAuth::from_bytes(std::vec::Vec::leak(hmac.to_vec())).unwrap()
}

// Case 1: Exclusivity Loss on Command without Sessions (Tag 0x8001)
#[test]
fn test_exclusivity_loss_on_non_audit_command_without_sessions() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x02000001;
    global_state.exclusive_audit_session = Some(session_handle);

    // Command without session (Tag 0x8001), cc is GetCapability
    let request = hex_literal::hex!("8001 00000016 0000017a 00000006 00000100 00000001");
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);

    // Exclusivity must be lost
    assert_eq!(global_state.exclusive_audit_session, None);
}

// Case 2: Preservation of Exclusivity on Excluded Commands without Sessions
#[test]
fn test_exclusivity_preserved_on_excluded_commands_without_sessions() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x02000001;

    // 2A. FlushContext without sessions (Tag 0x8001)
    global_state.exclusive_audit_session = Some(session_handle);
    // FlushContext for non-existent transient handle 0x80000000
    // Request layout: tag (8001), size (0000000e), CC (00000165), handle (80000000)
    let request_flush = hex_literal::hex!("8001 0000000e 00000165 80000000");
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request_flush[..], &mut response[..]);

    // Exclusivity must be preserved because FlushContext is excluded
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle));

    // 2B. ContextSave without sessions
    global_state.exclusive_audit_session = Some(session_handle);
    // ContextSave for non-existent handle 0x80000000
    let request_save = hex_literal::hex!("8001 0000000e 00000162 80000000");
    tpm.execute_command_separate(&mut global_state, &request_save[..], &mut response[..]);
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle));
}

// Case 3: Audit Digest Accumulation / Multi-Command Auditing
#[test]
fn test_audit_digest_accumulation_multiple_commands() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x02000001;

    // Session: Audit session
    let s = SessionState {
        session_handle,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xab; 64]), // initial non-zero audit digest
        audit_digest_len: 32,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(s).unwrap();

    // Command 1: GetCapability, session with AUDIT_RESET and AUDIT (attributes 0x85)
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    let nonce_tpm_before_1 = global_state.session(session_handle).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x85, nonce_tpm_before_1.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x85), // AUDIT_RESET | AUDIT
        hmac: hmac_1,
    };

    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth_1])
        .expect("First command failed");

    // Retrieve audit digest after Command 1
    let digest_1 = global_state
        .session(session_handle)
        .unwrap()
        .audit_digest
        .unwrap();

    // Command 2: GetCapability, session with AUDIT but NO AUDIT_RESET (attributes 0x81)
    let nonce_tpm_before_2 = global_state.session(session_handle).unwrap().nonce_tpm;
    let hmac_2 = compute_mock_hmac(0x81, nonce_tpm_before_2.get_buffer());
    let auth_2 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x81), // AUDIT
        hmac: hmac_2,
    };

    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth_2])
        .expect("Second command failed");

    // Retrieve audit digest after Command 2
    let digest_2 = global_state
        .session(session_handle)
        .unwrap()
        .audit_digest
        .unwrap();

    // Verify it is not the same as digest_1 (since it should have accumulated)
    assert_ne!(digest_2, digest_1);
}

// Case 4: Attribute validation error: AUDIT_EXCLUSIVE or AUDIT_RESET without AUDIT
#[test]
fn test_attributes_error_audit_exclusive_without_audit() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x02000001;
    let s = SessionState {
        session_handle,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xab; 64]),
        audit_digest_len: 32,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(s).unwrap();

    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };

    // Case 4A: session_attributes = 0x02 (AUDIT_EXCLUSIVE, but no AUDIT 0x80)
    let nonce_tpm = global_state.session(session_handle).unwrap().nonce_tpm;
    let hmac_a = compute_mock_hmac(0x02, nonce_tpm.get_buffer());
    let auth_a = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x02),
        hmac: hmac_a,
    };
    let res_a = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth_a]);
    assert_eq!(res_a.err(), Some(0x982)); // attributes_for(Session, Pos1)

    // Case 4B: session_attributes = 0x04 (AUDIT_RESET, but no AUDIT 0x80)
    let hmac_b = compute_mock_hmac(0x04, nonce_tpm.get_buffer());
    let auth_b = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x04),
        hmac: hmac_b,
    };
    let res_b = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth_b]);
    assert_eq!(res_b.err(), Some(0x982)); // attributes_for(Session, Pos1)
}

// Case 5: GetSessionAuditDigest Command Errors
#[test]
fn test_get_session_audit_digest_invalid_privacy_admin() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x02000001;
    let s = SessionState {
        session_handle,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xab; 64]),
        audit_digest_len: 32,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(s).unwrap();

    let cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // 5A: privacy_admin_handle is RHPlatform instead of RHEndorsement or RHNull
    let handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_PLATFORM,
        sign_handle: Handle(0x40000007), // RHNull
        session_handle: Handle(session_handle),
    };

    let auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    };

    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[auth]);
    assert!(res.is_err());
}

#[test]
fn test_get_session_audit_digest_on_non_audit_session() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x02000001;
    let s = SessionState {
        session_handle,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: None, // NOT an audit session!
        audit_digest_len: 0,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(s).unwrap();

    let cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle(0x40000007), // RHNull
        session_handle: Handle(session_handle),
    };

    let auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    };

    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[auth]);
    assert!(res.is_err());
}
