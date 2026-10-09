extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{Command, GetCapability};
use tpm2::crypto::Rng;
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{CryptoError, CryptoProvider};
use tpm2::{Marshal, Tpm2bAuth, TpmaSession, TpmiAlgHash, TpmsAuthCommand};
use tpm2::{TpmCap, TpmPt};
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

// 1. Audit Reset Handover with Existing Exclusive Session
#[test]
fn test_audit_reset_handover_with_existing_exclusive_session() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle_1 = 0x02000001;
    let session_handle_2 = 0x02000002;

    // Session 1: Exclusive, initialized (first-use done)
    let s1 = SessionState {
        session_handle: session_handle_1,
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
    global_state.add_session(s1).unwrap();
    global_state.exclusive_audit_session = Some(session_handle_1);

    // Session 2: Audit session, initialized (first-use done)
    let s2 = SessionState {
        session_handle: session_handle_2,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xcd; 64]),
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
    global_state.add_session(s2).unwrap();

    // Command with Session 2, AUDIT_RESET set
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    let nonce_tpm_2 = global_state.session(session_handle_2).unwrap().nonce_tpm;
    let hmac = compute_mock_hmac(0x85, nonce_tpm_2.get_buffer()); // continueSession | audit | auditReset
    let auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_2),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x85),
        hmac,
    };

    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth])
        .expect("Command failed");

    // Verify exclusivity successfully hands over to Session 2
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_2));

    // Verify Session 2's audit digest is reset
    let s2_after = global_state.session(session_handle_2).unwrap();
    let mut expected_reset = [0u8; 64];
    expected_reset[..24].copy_from_slice(&[
        0, 0, 1, 122, 0, 0, 1, 124, 1, 0, 1, 0, 6, 0, 0, 1, 1, 0, 0, 1, 0, 50, 46, 48,
    ]);
    assert_eq!(s2_after.audit_digest.unwrap(), expected_reset);
}

// 2. Exclusivity Loss when using a Non-Exclusive Session
#[test]
fn test_exclusivity_loss_when_using_non_exclusive_session() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle_1 = 0x02000001;
    let session_handle_2 = 0x02000002;

    // Session 1: Audit session, initialized (first-use done)
    let s1 = SessionState {
        session_handle: session_handle_1,
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
    global_state.add_session(s1).unwrap();

    // Session 2: Exclusive, initialized (first-use done)
    let s2 = SessionState {
        session_handle: session_handle_2,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xcd; 64]),
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
    global_state.add_session(s2).unwrap();
    global_state.exclusive_audit_session = Some(session_handle_2);

    // Command with Session 1, no first-use, no auditReset (attribute 0x81)
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac = compute_mock_hmac(0x81, nonce_tpm_1.get_buffer()); // continueSession | audit
    let auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x81),
        hmac,
    };

    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth])
        .expect("Command failed");

    // Verify exclusivity is lost (cleared to None)
    assert_eq!(global_state.exclusive_audit_session, None);
}

// 3. Exclusivity Gating
#[test]
fn test_exclusivity_gating() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle_1 = 0x02000001;
    let session_handle_2 = 0x02000002;

    // Session 1: Audit session, initialized (first-use done)
    let s1 = SessionState {
        session_handle: session_handle_1,
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
    global_state.add_session(s1).unwrap();

    // Session 2: Exclusive, initialized (first-use done)
    let s2 = SessionState {
        session_handle: session_handle_2,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xcd; 64]),
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
    global_state.add_session(s2).unwrap();
    global_state.exclusive_audit_session = Some(session_handle_2);

    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };

    // A. Command with Session 1 (AUDIT_EXCLUSIVE set -> continueSession | audit | auditExclusive = 0x83)
    // Should fail with TPM_RC_EXCLUSIVE (0x121)
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x83, nonce_tpm_1.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x83),
        hmac: hmac_1,
    };

    let res_1 = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth_1]);
    assert_eq!(res_1.err(), Some(0x121)); // TPM_RC_EXCLUSIVE

    // B. Command with Session 2 (AUDIT_EXCLUSIVE set)
    // Should succeed
    let nonce_tpm_2 = global_state.session(session_handle_2).unwrap().nonce_tpm;
    let hmac_2 = compute_mock_hmac(0x83, nonce_tpm_2.get_buffer());
    let auth_2 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_2),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x83),
        hmac: hmac_2,
    };

    let res_2 = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth_2]);
    assert!(res_2.is_ok());
}

// 4. Exclusivity Loss when using a Non-Audit Session
#[test]
fn test_exclusivity_loss_when_using_non_audit_session() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle_1 = 0x02000001;
    let session_handle_2 = 0x02000002;

    // Session 1: Non-audit session (standard HMAC)
    let s1 = SessionState {
        session_handle: session_handle_1,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: None,
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
    global_state.add_session(s1).unwrap();

    // Session 2: Exclusive, initialized (first-use done)
    let s2 = SessionState {
        session_handle: session_handle_2,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xcd; 64]),
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
    global_state.add_session(s2).unwrap();
    global_state.exclusive_audit_session = Some(session_handle_2);

    // Command with a non-audit authorization session. In C a session that authorizes no handle
    // must be an audit/encrypt/decrypt session (TPM_RC_ATTRIBUTES + S1 otherwise,
    // SessionProcess.c:1705-1712), so a plain HMAC session can't be sent with GetCapability.
    // Use HierarchyChangeAuth(RH_OWNER, unchanged empty auth) authorized by a password session
    // instead: the command carries sessions but no audit session, which clears the exclusive
    // audit session (C UpdateAuditSessionStatus, SessionProcess.c:1993-1996).
    let cmd = tpm2::commands::HierarchyChangeAuth {
        new_auth: Tpm2bAuth::default(),
    };
    let handles = tpm2::commands::HierarchyChangeAuthHandles {
        auth_handle: tpm2::Handle::RH_OWNER,
    };
    let auth = common::password_auth(b"");

    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[auth])
        .expect("Command failed");

    // Verify exclusivity is lost (cleared to None)
    assert_eq!(global_state.exclusive_audit_session, None);
}
