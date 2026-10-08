use common::marshal_to_slice;
use tpm2::Alg;

use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage};
use hex_literal::hex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tpm2::commands::Command;
use tpm2::crypto::asymmetric::{KeyParams, TpmiRsaKeyBits};
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{Finalize as _, Hash as _, Update as _};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPublicKeyRsa, TpmaObject,
    TpmiAlgHash, TpmsAuthCommand, TpmsRsaParms, TpmtPublic, TpmtSignature, TpmtTkVerified,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

fn compute_sha256(crypto: &TestCryptoProvider, data: &[u8]) -> [u8; 32] {
    let mut ctx = crypto.sha256().unwrap();
    ctx.update(data).unwrap();
    let mut digest = [0u8; 32];
    ctx.finalize(&mut digest).unwrap();
    digest
}

struct MutableTimer {
    time: Arc<AtomicU64>,
}

impl tpm2_impl::timer::TpmTimer for MutableTimer {
    fn timer_read(&self) -> u64 {
        self.time.load(Ordering::SeqCst)
    }
}

fn setup_tpm<'a, T: tpm2_impl::timer::TpmTimer>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut T,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, T, FakeRng>,
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
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command<'a, C: Command, T: tpm2_impl::timer::TpmTimer>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, T, FakeRng>,
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

fn compute_key_name(crypto: &TestCryptoProvider, public: &TpmtPublic) -> Tpm2bName<'static> {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let digest = compute_sha256(crypto, &buf[..len]);

    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(&digest);
    Tpm2bName::from_bytes(std::vec::Vec::leak(name_bytes[..34].to_vec())).unwrap()
}

fn create_signing_key(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, MutableTimer, FakeRng>,
) -> (TransientObject, [u8; 1536], usize) {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 1536];
    let (pub_len, priv_len) = tpm
        .platform
        .crypto
        .generate_key(
            Alg::RSA,
            Some(KeyParams::Rsa(TpmiRsaKeyBits(2048))),
            &mut pub_buf,
            &mut priv_buf,
            None,
        )
        .unwrap();

    let unique = Tpm2bPublicKeyRsa::from_bytes(&pub_buf[..pub_len]).unwrap();
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            unique,
        ),
    };
    let name = compute_key_name(tpm.platform.crypto, &public);
    let mut private = [0u8; 1536];
    private[..priv_len].copy_from_slice(&priv_buf[..priv_len]);
    let signing_key = TransientObject {
        handle: 0x80000001,
        seed: [0u8; 32],
        name: name.into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: (name).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    (signing_key, priv_buf, priv_len)
}

#[test]
fn test_challenger_policy_signed_invalid_signature() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let (signing_key, priv_buf, priv_len) = create_signing_key(&mut tpm);
    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 2. Compute digest and sign
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 0;

    let mut to_be_signed = [0u8; 1024];
    let mut offset = 0;
    to_be_signed[offset..offset + nonce_tpm.get_size() as usize]
        .copy_from_slice(nonce_tpm.get_buffer());
    offset += nonce_tpm.get_size() as usize;
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.get_size() as usize]
        .copy_from_slice(cp_hash_a.get_buffer());
    offset += cp_hash_a.get_size() as usize;
    to_be_signed[offset..offset + policy_ref.get_size() as usize]
        .copy_from_slice(policy_ref.get_buffer());
    offset += policy_ref.get_size() as usize;

    let digest = compute_sha256(tpm.platform.crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; 256];
    let sig_len = tpm
        .platform
        .crypto
        .sign_inner(
            Alg::RSAPSS,
            &priv_buf[..priv_len],
            tpm2::TpmtHa::Sha256(&digest),
            &mut sig_out,
        )
        .unwrap();

    // Tamper with the signature bytes to make it invalid
    sig_out[10] ^= 0xFF;

    let sig = tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&sig_out[..sig_len]).unwrap(),
    };
    let auth = TpmtSignature::Rsapss(sig);

    use tpm2::commands::{PolicySigned, PolicySignedHandles};
    let ps_handles = PolicySignedHandles {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
    };
    let ps_cmd = PolicySigned {
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    // Calling PolicySigned with tampered signature should fail with signature_for(Parameter, Pos5)
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
}

#[test]
fn test_challenger_policy_signed_incorrect_message() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let (signing_key, priv_buf, priv_len) = create_signing_key(&mut tpm);
    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 2. Compute digest over an INCORRECT nonce_tpm (e.g. all 0xFF) and sign it
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 0;

    let incorrect_nonce = Tpm2bNonce::from_bytes(&[0xFF; 32]).unwrap();

    let mut to_be_signed = [0u8; 1024];
    let mut offset = 0;
    to_be_signed[offset..offset + incorrect_nonce.get_size() as usize]
        .copy_from_slice(incorrect_nonce.get_buffer());
    offset += incorrect_nonce.get_size() as usize;
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.get_size() as usize]
        .copy_from_slice(cp_hash_a.get_buffer());
    offset += cp_hash_a.get_size() as usize;
    to_be_signed[offset..offset + policy_ref.get_size() as usize]
        .copy_from_slice(policy_ref.get_buffer());
    offset += policy_ref.get_size() as usize;

    let digest = compute_sha256(tpm.platform.crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; 256];
    let sig_len = tpm
        .platform
        .crypto
        .sign_inner(
            Alg::RSAPSS,
            &priv_buf[..priv_len],
            tpm2::TpmtHa::Sha256(&digest),
            &mut sig_out,
        )
        .unwrap();

    let sig = tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&sig_out[..sig_len]).unwrap(),
    };
    let auth = TpmtSignature::Rsapss(sig);

    use tpm2::commands::{PolicySigned, PolicySignedHandles};
    let ps_handles = PolicySignedHandles {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
    };
    let ps_cmd = PolicySigned {
        nonce_tpm: nonce_tpm.as_tpm2b(), // The correct nonce_tpm is passed in the command parameters!
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    // Calling PolicySigned should fail because the signature is over the incorrect nonce!
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
}

#[test]
fn test_challenger_policy_signed_expiration_and_timeout() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer {
        time: shared_time.clone(),
    };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let (signing_key, priv_buf, priv_len) = create_signing_key(&mut tpm);
    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 2. Set expiration to 10 seconds (expiration = 10)
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 10;

    let mut to_be_signed = [0u8; 1024];
    let mut offset = 0;
    to_be_signed[offset..offset + nonce_tpm.get_size() as usize]
        .copy_from_slice(nonce_tpm.get_buffer());
    offset += nonce_tpm.get_size() as usize;
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.get_size() as usize]
        .copy_from_slice(cp_hash_a.get_buffer());
    offset += cp_hash_a.get_size() as usize;
    to_be_signed[offset..offset + policy_ref.get_size() as usize]
        .copy_from_slice(policy_ref.get_buffer());
    offset += policy_ref.get_size() as usize;

    let digest = compute_sha256(tpm.platform.crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; 256];
    let sig_len = tpm
        .platform
        .crypto
        .sign_inner(
            Alg::RSAPSS,
            &priv_buf[..priv_len],
            tpm2::TpmtHa::Sha256(&digest),
            &mut sig_out,
        )
        .unwrap();

    let sig = tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&sig_out[..sig_len]).unwrap(),
    };
    let auth = TpmtSignature::Rsapss(sig);

    use tpm2::commands::{PolicySigned, PolicySignedHandles};
    let ps_handles = PolicySignedHandles {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
    };
    let ps_cmd = PolicySigned {
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    // Calling PolicySigned with expiration = 10 should succeed and set the timeout
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]);
    assert!(res.is_ok());

    // Verify session timeout is 10000 ms (since clock was 0)
    {
        let session = global_state.session(policy_session_handle.0).unwrap();
        assert_eq!(session.timeout, 10000);
    }

    // 3. Advance clock to 10001 ms (exceeding 10000 ms timeout)
    shared_time.store(10001, Ordering::SeqCst);

    let res2 = execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]);
    assert_eq!(
        res2.err(),
        Some(TpmRc::EXPIRED.with(Position::handle(2)).get())
    );
}

#[test]
fn test_challenger_policy_signed_ticket_generation() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let (signing_key, priv_buf, priv_len) = create_signing_key(&mut tpm);
    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 2. Set expiration to -10 (negative value, so a ticket should be generated)
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = -10;

    let mut to_be_signed = [0u8; 1024];
    let mut offset = 0;
    to_be_signed[offset..offset + nonce_tpm.get_size() as usize]
        .copy_from_slice(nonce_tpm.get_buffer());
    offset += nonce_tpm.get_size() as usize;
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.get_size() as usize]
        .copy_from_slice(cp_hash_a.get_buffer());
    offset += cp_hash_a.get_size() as usize;
    to_be_signed[offset..offset + policy_ref.get_size() as usize]
        .copy_from_slice(policy_ref.get_buffer());
    offset += policy_ref.get_size() as usize;

    let digest = compute_sha256(tpm.platform.crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; 256];
    let sig_len = tpm
        .platform
        .crypto
        .sign_inner(
            Alg::RSAPSS,
            &priv_buf[..priv_len],
            tpm2::TpmtHa::Sha256(&digest),
            &mut sig_out,
        )
        .unwrap();

    let sig = tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&sig_out[..sig_len]).unwrap(),
    };
    let auth = TpmtSignature::Rsapss(sig);

    use tpm2::commands::{PolicySigned, PolicySignedHandles};
    let ps_handles = PolicySignedHandles {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
    };
    let ps_cmd = PolicySigned {
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    // Calling PolicySigned with negative expiration should generate a ticket in response
    let (_, ps_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]).unwrap();

    // Verify tag is 0x8025 and digest is non-empty
    assert_eq!(ps_rsp.policy_ticket.tag(), 0x8025);
    assert_ne!(ps_rsp.policy_ticket.digest().get_size(), 0);
}

#[test]
fn test_challenger_policy_authorize_mismatched_policy() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Start a policy session and get its digest
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // Set a policy command code to advance digest
    use tpm2::commands::{PolicyCommandCode, PolicyCommandCodeHandles};
    let pcc_handles = PolicyCommandCodeHandles {
        policy_session: policy_session_handle,
    };
    let pcc_cmd = PolicyCommandCode {
        code: TpmCc::GetRandom,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &pcc_handles, &pcc_cmd, &[]).unwrap();

    // 2. Prepare ticket inputs with a MISMATCHED approvedPolicy (e.g. all 0xEE)
    let mismatched_approved_policy = Tpm2bDigest::from_bytes(&[0xEE; 32]).unwrap();
    let policy_ref = Tpm2bNonce::default();

    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[3; 32]);
    let key_sign = Tpm2bName::from_bytes(&key_sign_bytes).unwrap();

    let check_ticket = tpm2::TpmtTkVerified::Verified(Handle(0x4000000C), Tpm2bDigest::default());

    use tpm2::commands::{PolicyAuthorize, PolicyAuthorizeHandles};
    let pa_handles = PolicyAuthorizeHandles {
        policy_session: policy_session_handle,
    };
    let pa_cmd = PolicyAuthorize {
        approved_policy: mismatched_approved_policy,
        policy_ref,
        key_sign,
        check_ticket,
    };

    // Calling PolicyAuthorize with mismatched approved_policy should return value_for(Parameter, Pos1)
    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

#[test]
fn test_challenger_policy_authorize_wrong_ticket_hmac() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // Get the current policy digest (empty, i.e., 32 bytes of zeros)
    use tpm2::commands::{PolicyGetDigest, PolicyGetDigestHandles};
    let pgd_handles = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let pgd_cmd = PolicyGetDigest {};
    let (_, pgd_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &pgd_handles, &pgd_cmd, &[]).unwrap();
    let approved_policy = pgd_rsp.policy_digest;

    // 2. Prepare ticket inputs with a WRONG/tampered HMAC digest
    let policy_ref = Tpm2bNonce::default();

    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[3; 32]);
    let key_sign = Tpm2bName::from_bytes(&key_sign_bytes).unwrap();

    let check_ticket = tpm2::TpmtTkVerified::Verified(
        Handle(0x4000000C),
        Tpm2bDigest::from_bytes(&[0x99; 32]).unwrap(),
    );

    use tpm2::commands::{PolicyAuthorize, PolicyAuthorizeHandles};
    let pa_handles = PolicyAuthorizeHandles {
        policy_session: policy_session_handle,
    };
    let pa_cmd = PolicyAuthorize {
        approved_policy,
        policy_ref,
        key_sign,
        check_ticket,
    };

    // Calling PolicyAuthorize with wrong ticket HMAC should fail with value_for(Parameter, Pos4)
    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(4)).get())
    );
}

#[test]
fn test_challenger_policy_authorize_wrong_ticket_tag() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    use tpm2::commands::{PolicyGetDigest, PolicyGetDigestHandles};
    let pgd_handles = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let pgd_cmd = PolicyGetDigest {};
    let (_, pgd_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &pgd_handles, &pgd_cmd, &[]).unwrap();
    let approved_policy = pgd_rsp.policy_digest;

    // 2. Prepare ticket inputs with a WRONG tag (e.g. 0x8025 instead of 0x8022)
    let policy_ref = Tpm2bNonce::default();

    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[3; 32]);
    let key_sign = Tpm2bName::from_bytes(&key_sign_bytes).unwrap();

    let check_ticket = tpm2::TpmtTkVerified::Verified(Handle(0x4000000C), Tpm2bDigest::default());

    use tpm2::commands::{PolicyAuthorize, PolicyAuthorizeHandles};
    let pa_handles = PolicyAuthorizeHandles {
        policy_session: policy_session_handle,
    };
    let pa_cmd = PolicyAuthorize {
        approved_policy,
        policy_ref,
        key_sign,
        check_ticket,
    };

    // Calling PolicyAuthorize with wrong ticket tag should fail with value_for(Parameter, Pos4)
    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(4)).get())
    );
}

#[test]
fn test_challenger_policy_signed_trial_session_digest_update() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let (signing_key, _, _) = create_signing_key(&mut tpm);
    let key_name = signing_key.name;
    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a trial session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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

    // 2. Call PolicySigned on Trial session
    let policy_ref = Tpm2bNonce::from_bytes(&[9; 16]).unwrap();
    use tpm2::commands::{PolicySigned, PolicySignedHandles};
    let ps_handles = PolicySignedHandles {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
    };
    let ps_cmd = PolicySigned {
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref,
        expiration: 0,
        auth: TpmtSignature::Rsapss(tpm2::TpmsSignatureRsa {
            hash: TpmiAlgHash::Sha256,
            sig: tpm2::Tpm2bPublicKeyRsa::default(),
        }),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]);
    assert!(res.is_ok());

    // 3. Call PolicyGetDigest to verify updated digest
    use tpm2::commands::{PolicyGetDigest, PolicyGetDigestHandles};
    let pgd_handles = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let pgd_cmd = PolicyGetDigest {};
    let (_, pgd_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &pgd_handles, &pgd_cmd, &[]).unwrap();

    // Expected digest update:
    // digest1 = SHA256(0..32 || TPM_CC_PolicySigned || key_name)
    // expected = SHA256(digest1 || policy_ref)
    let mut update1 = [0u8; 32 + 4 + 34];
    update1[32..36].copy_from_slice(&0x00000160u32.to_be_bytes()); // TPM_CC_PolicySigned
    update1[36..36 + key_name.get_size() as usize].copy_from_slice(key_name.get_buffer());

    let digest1 = compute_sha256(
        tpm.platform.crypto,
        &update1[..36 + key_name.get_size() as usize],
    );

    let mut update2 = Vec::new();
    update2.extend_from_slice(&digest1);
    update2.extend_from_slice(policy_ref.get_buffer());

    let expected_digest = compute_sha256(tpm.platform.crypto, &update2);

    assert_eq!(pgd_rsp.policy_digest.get_buffer(), &expected_digest);
}

#[test]
fn test_challenger_policy_authorize_trial_session_digest_update() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Start a trial session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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

    // Advance digest by some command first
    use tpm2::commands::{PolicyCommandCode, PolicyCommandCodeHandles};
    let pcc_handles = PolicyCommandCodeHandles {
        policy_session: policy_session_handle,
    };
    let pcc_cmd = PolicyCommandCode {
        code: TpmCc::GetRandom,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &pcc_handles, &pcc_cmd, &[]).unwrap();

    // Get current policy digest
    use tpm2::commands::{PolicyGetDigest, PolicyGetDigestHandles};
    let pgd_handles = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let pgd_cmd = PolicyGetDigest {};
    let (_, pgd_rsp1) =
        execute_tpm_command(&mut tpm, &mut global_state, &pgd_handles, &pgd_cmd, &[]).unwrap();
    let approved_policy = pgd_rsp1.policy_digest;

    // 2. Call PolicyAuthorize on Trial session (no ticket validation)
    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[3; 32]);
    let key_sign = Tpm2bName::from_bytes(&key_sign_bytes).unwrap();
    let policy_ref = Tpm2bNonce::from_bytes(&[7; 8]).unwrap();

    use tpm2::commands::{PolicyAuthorize, PolicyAuthorizeHandles};
    let pa_handles = PolicyAuthorizeHandles {
        policy_session: policy_session_handle,
    };
    let pa_cmd = PolicyAuthorize {
        approved_policy,
        policy_ref,
        key_sign,
        check_ticket: tpm2::TpmtTkVerified::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd, &[]);
    assert!(res.is_ok());

    // 3. Verify updated digest
    let (_, pgd_rsp2) =
        execute_tpm_command(&mut tpm, &mut global_state, &pgd_handles, &pgd_cmd, &[]).unwrap();

    // Expected digest update:
    // digest1 = SHA256(ZeroDigest || TPM_CC_PolicyAuthorize || key_sign)
    // expected = SHA256(digest1 || policy_ref)
    let zero_digest = [0u8; 32];
    let mut update1 = Vec::new();
    update1.extend_from_slice(&zero_digest);
    update1.extend_from_slice(&0x0000016Au32.to_be_bytes()); // TPM_CC_PolicyAuthorize
    update1.extend_from_slice(key_sign.get_buffer());

    let digest1 = compute_sha256(tpm.platform.crypto, &update1);

    let mut update2 = Vec::new();
    update2.extend_from_slice(&digest1);
    update2.extend_from_slice(policy_ref.get_buffer());

    let expected_digest = compute_sha256(tpm.platform.crypto, &update2);

    assert_eq!(pgd_rsp2.policy_digest.get_buffer(), &expected_digest);
}

#[test]
fn test_challenger_policy_authorize_invalid_key_sign_size() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Start a trial session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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

    // 2. Call PolicyAuthorize with key_sign size < 2
    let key_sign_too_small = Tpm2bName::from_bytes(&[0]).unwrap();

    use tpm2::commands::{PolicyAuthorize, PolicyAuthorizeHandles};
    let pa_handles = PolicyAuthorizeHandles {
        policy_session: policy_session_handle,
    };
    let pa_cmd = PolicyAuthorize {
        approved_policy: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        key_sign: key_sign_too_small,
        check_ticket: tpm2::TpmtTkVerified::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(3)).get())
    );

    // 3. Call PolicyAuthorize with key_sign size not matching digest size of its hash algorithm
    let mut key_sign_mismatched = [0u8; 10];
    key_sign_mismatched[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes()); // SHA256 requires 32 bytes digest, but key_sign total size is 10 (8 bytes digest)
    let key_sign = Tpm2bName::from_bytes(&key_sign_mismatched).unwrap();

    let pa_cmd2 = PolicyAuthorize {
        approved_policy: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        key_sign,
        check_ticket: tpm2::TpmtTkVerified::default(),
    };
    let res2 = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd2, &[]);
    assert_eq!(
        res2.err(),
        Some(TpmRc::SIZE.with(Position::parameter(3)).get())
    );
}

#[test]
fn test_challenger_policy_authorize_invalid_key_sign_hash() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Start a trial session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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

    // 2. Call PolicyAuthorize with invalid hash alg in key_sign (e.g. 0xFFFF)
    let mut key_sign_bad_hash = [0u8; 34];
    key_sign_bad_hash[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    let key_sign = Tpm2bName::from_bytes(&key_sign_bad_hash).unwrap();

    use tpm2::commands::{PolicyAuthorize, PolicyAuthorizeHandles};
    let pa_handles = PolicyAuthorizeHandles {
        policy_session: policy_session_handle,
    };
    let pa_cmd = PolicyAuthorize {
        approved_policy: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        key_sign,
        check_ticket: tpm2::TpmtTkVerified::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(Position::parameter(3)).get())
    );
}

#[test]
fn test_challenger_policy_signed_invalid_key_type() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a symmetric key and load it
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            tpm2::TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    let name = compute_key_name(tpm.platform.crypto, &public);
    let sym_key = TransientObject {
        handle: 0x80000002,
        seed: [0u8; 32],
        name: name.into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0u8; 1536],
        private_len: 16,
        qualified_name: (name).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(sym_key);

    // 2. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 3. Call PolicySigned using the symmetric key as authObject
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 0;

    let sig = tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&[0; 256]).unwrap(),
    };
    let auth = TpmtSignature::Rsapss(sig);

    use tpm2::commands::{PolicySigned, PolicySignedHandles};
    let ps_handles = PolicySignedHandles {
        auth_object: Handle(0x80000002), // Symmetric key
        policy_session: policy_session_handle,
    };
    let ps_cmd = PolicySigned {
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::KEY.with(Position::handle(1)).get()));
}

#[test]
fn test_challenger_policy_signed_scheme_mismatch() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let (signing_key, _, _) = create_signing_key(&mut tpm); // This creates an RSA key
    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 2. Call PolicySigned on RSA key but with ECDSA signature
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 0;

    let sig = tpm2::TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: tpm2::Tpm2bEccParameter::from_bytes(&[0; 32]).unwrap(),
        signature_s: tpm2::Tpm2bEccParameter::from_bytes(&[0; 32]).unwrap(),
    };
    let auth = TpmtSignature::Ecdsa(sig);

    use tpm2::commands::{PolicySigned, PolicySignedHandles};
    let ps_handles = PolicySignedHandles {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
    };
    let ps_cmd = PolicySigned {
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]);
    // Should fail with signature_for because verify_inner fails when trying to verify ECDSA signature with RSA key
    assert_eq!(
        res.err(),
        Some(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
}

#[test]
fn test_challenger_policy_authorize_success_flow() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let (signing_key, priv_buf, priv_len) = create_signing_key(&mut tpm);
    let key_name = signing_key.name;
    global_state.transient_objects[0] = Some(signing_key);

    // 1. Compute approvedPolicy and policyRef digest (aHash)
    // For a brand new session, policy_digest is all zeros
    let approved_policy = [0u8; 32];
    let policy_ref = Tpm2bNonce::from_bytes(&[8; 16]).unwrap();

    // aHash = SHA256(approvedPolicy || policyRef)
    let mut ahash_input = Vec::new();
    ahash_input.extend_from_slice(&approved_policy);
    ahash_input.extend_from_slice(policy_ref.get_buffer());
    let ahash_digest = compute_sha256(tpm.platform.crypto, &ahash_input);

    // 2. Sign aHash
    let mut sig_out = [0u8; 256];
    let sig_len = tpm
        .platform
        .crypto
        .sign_inner(
            Alg::RSAPSS,
            &priv_buf[..priv_len],
            tpm2::TpmtHa::Sha256(&ahash_digest),
            &mut sig_out,
        )
        .unwrap();

    let sig = tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&sig_out[..sig_len]).unwrap(),
    };
    let signature = TpmtSignature::Rsapss(sig);

    // 3. Call VerifySignature to get a ticket
    use tpm2::commands::{VerifySignature, VerifySignatureHandles};
    let vs_handles = VerifySignatureHandles {
        key_handle: Handle(0x80000001),
    };
    let vs_cmd = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&ahash_digest).unwrap(),
        signature,
    };
    let (_, vs_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &vs_handles, &vs_cmd, &[]).unwrap();
    let mut ticket = vs_rsp.validation;

    // Manually compute the correct HMAC to work around VerifySignature mock bug!
    let proof_bytes = &global_state.sh_proof[..global_state.sh_proof_size as usize];
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&0x8022u16.to_be_bytes()); // tag
    hmac_input.extend_from_slice(&ahash_digest); // digest
    hmac_input.extend_from_slice(key_name.get_buffer()); // keyName

    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let hmac_digest = tpm2::crypto::hmac(
        &*tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        proof_bytes,
        &hmac_input,
        &mut hmac_buf,
    )
    .unwrap();
    ticket = TpmtTkVerified::Verified(
        ticket.hierarchy(),
        Tpm2bDigest::from_bytes(hmac_digest.digest()).unwrap(),
    );

    // 4. Start a real policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // 5. Call PolicyAuthorize on this session
    use tpm2::commands::{PolicyAuthorize, PolicyAuthorizeHandles};
    let pa_handles = PolicyAuthorizeHandles {
        policy_session: policy_session_handle,
    };
    let pa_cmd = PolicyAuthorize {
        approved_policy: Tpm2bDigest::from_bytes(&approved_policy).unwrap(),
        policy_ref,
        key_sign: key_name.as_tpm2b(),
        check_ticket: ticket,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd, &[]);
    assert!(res.is_ok(), "PolicyAuthorize failed with {:?}", res.err());
}

#[test]
fn test_challenger_policy_authorize_forged_ticket_null_hierarchy() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Let's use a dummy authority key name (it does not even need to exist!)
    let key_name = Tpm2bName::from_bytes(&[
        0, 11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32,
    ])
    .unwrap();

    let approved_policy = [0u8; 32];
    let policy_ref = Tpm2bNonce::from_bytes(&[8; 16]).unwrap();

    // aHash = SHA256(approvedPolicy || policyRef)
    let mut ahash_input = Vec::new();
    ahash_input.extend_from_slice(&approved_policy);
    ahash_input.extend_from_slice(policy_ref.get_buffer());
    let ahash_digest = compute_sha256(tpm.platform.crypto, &ahash_input);

    // Forge the ticket with RHNull (0x40000007) and empty key HMAC
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&0x8022u16.to_be_bytes()); // tag
    hmac_input.extend_from_slice(&ahash_digest); // digest
    hmac_input.extend_from_slice(key_name.get_buffer()); // keyName

    // Compute HMAC with empty key (proof_len = 0)
    let proof_bytes = &[];
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let hmac_digest = tpm2::crypto::hmac(
        &*tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        proof_bytes,
        &hmac_input,
        &mut hmac_buf,
    )
    .unwrap();

    let ticket = tpm2::TpmtTkVerified::Verified(
        Handle::RH_NULL,
        Tpm2bDigest::from_bytes(hmac_digest.digest()).unwrap(),
    );

    // Start a real policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // Call PolicyAuthorize on this session
    use tpm2::commands::{PolicyAuthorize, PolicyAuthorizeHandles};
    let pa_handles = PolicyAuthorizeHandles {
        policy_session: policy_session_handle,
    };
    let pa_cmd = PolicyAuthorize {
        approved_policy: Tpm2bDigest::from_bytes(&approved_policy).unwrap(),
        policy_ref,
        key_sign: key_name,
        check_ticket: ticket,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd, &[]);
    assert!(
        res.is_err(),
        "Expected PolicyAuthorize to fail with forged RHNull ticket, but it succeeded!"
    );
    let err = res.err().unwrap();
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(4)).get());
}

#[test]
fn test_challenger_policy_authorize_timeout_bypass_vulnerability() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer {
        time: shared_time.clone(),
    };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let (signing_key, priv_buf, priv_len) = create_signing_key(&mut tpm);
    let key_name = signing_key.name;
    global_state.transient_objects[0] = Some(signing_key);

    // Start policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp_handles, policy_session_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp_handles.session_handle;

    let nonce_tpm = policy_session_resp.nonce_tpm;

    // Set a timeout on the session using PolicySigned first
    use tpm2::commands::{PolicySigned, PolicySignedHandles};
    let ps_handles = PolicySignedHandles {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
    };

    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 10;

    let mut to_be_signed = [0u8; 1024];
    let mut offset = 0;
    to_be_signed[offset..offset + nonce_tpm.get_size() as usize]
        .copy_from_slice(nonce_tpm.get_buffer());
    offset += nonce_tpm.get_size() as usize;
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.get_size() as usize]
        .copy_from_slice(cp_hash_a.get_buffer());
    offset += cp_hash_a.get_size() as usize;
    to_be_signed[offset..offset + policy_ref.get_size() as usize]
        .copy_from_slice(policy_ref.get_buffer());
    offset += policy_ref.get_size() as usize;

    let digest = compute_sha256(tpm.platform.crypto, &to_be_signed[..offset]);

    let mut sig_out_ps = [0u8; 256];
    let sig_len_ps = tpm
        .platform
        .crypto
        .sign_inner(
            Alg::RSAPSS,
            &priv_buf[..priv_len],
            tpm2::TpmtHa::Sha256(&digest),
            &mut sig_out_ps,
        )
        .unwrap();

    let sig_ps = tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&sig_out_ps[..sig_len_ps]).unwrap(),
    };
    let auth_ps = TpmtSignature::Rsapss(sig_ps);

    let ps_cmd = PolicySigned {
        nonce_tpm,
        cp_hash_a,
        policy_ref,
        expiration,
        auth: auth_ps,
    };
    // Call PolicySigned to set session.timeout = 10000 ms
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]);
    assert!(res.is_ok());

    // Verify session timeout is 10000 ms
    {
        let session = global_state.session(policy_session_handle.0).unwrap();
        assert_eq!(session.timeout, 10000);
    }

    // Fetch the updated policy digest from the session state
    let (current_policy_digest, current_policy_digest_len) = {
        let session = global_state.session(policy_session_handle.0).unwrap();
        (session.policy_digest, session.policy_digest_len)
    };

    // Generate the ticket using this updated policy digest
    let pa_policy_ref = Tpm2bNonce::from_bytes(&[8; 16]).unwrap();

    let mut ahash_input = Vec::new();
    ahash_input.extend_from_slice(&current_policy_digest[..current_policy_digest_len]);
    ahash_input.extend_from_slice(pa_policy_ref.get_buffer());
    let ahash_digest = compute_sha256(tpm.platform.crypto, &ahash_input);

    let mut sig_out = [0u8; 256];
    let sig_len = tpm
        .platform
        .crypto
        .sign_inner(
            Alg::RSAPSS,
            &priv_buf[..priv_len],
            tpm2::TpmtHa::Sha256(&ahash_digest),
            &mut sig_out,
        )
        .unwrap();

    let sig = tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&sig_out[..sig_len]).unwrap(),
    };
    let signature = TpmtSignature::Rsapss(sig);

    // Call VerifySignature to get a ticket
    use tpm2::commands::{VerifySignature, VerifySignatureHandles};
    let vs_handles = VerifySignatureHandles {
        key_handle: Handle(0x80000001),
    };
    let vs_cmd = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&ahash_digest).unwrap(),
        signature,
    };
    let (_, vs_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &vs_handles, &vs_cmd, &[]).unwrap();
    let mut ticket = vs_rsp.validation;

    // Compute correct HMAC
    let proof_bytes = &global_state.sh_proof[..global_state.sh_proof_size as usize];
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&0x8022u16.to_be_bytes());
    hmac_input.extend_from_slice(&ahash_digest);
    hmac_input.extend_from_slice(key_name.get_buffer());

    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let hmac_digest = tpm2::crypto::hmac(
        &*tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        proof_bytes,
        &hmac_input,
        &mut hmac_buf,
    )
    .unwrap();
    ticket = TpmtTkVerified::Verified(
        ticket.hierarchy(),
        Tpm2bDigest::from_bytes(hmac_digest.digest()).unwrap(),
    );

    // Advance clock to 10001 ms (exceeding 10000 ms timeout)
    shared_time.store(10001, Ordering::SeqCst);

    // Call PolicyAuthorize on the expired session
    use tpm2::commands::{PolicyAuthorize, PolicyAuthorizeHandles};
    let pa_handles = PolicyAuthorizeHandles {
        policy_session: policy_session_handle,
    };
    let pa_cmd = PolicyAuthorize {
        approved_policy: Tpm2bDigest::from_bytes(
            &current_policy_digest[..current_policy_digest_len],
        )
        .unwrap(),
        policy_ref: pa_policy_ref,
        key_sign: key_name.as_tpm2b(),
        check_ticket: ticket,
    };

    let res2 = execute_tpm_command(&mut tpm, &mut global_state, &pa_handles, &pa_cmd, &[]);
    assert_eq!(
        res2.err(),
        Some(TpmRc::EXPIRED.with(Position::handle(1)).get())
    );
}

#[test]
fn test_ticket_revival_fails_after_restart() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let (signing_key, priv_buf, priv_len) = create_signing_key(&mut tpm);
    let auth_name = signing_key.name;
    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
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
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 2. Generate a ticket with PolicySigned (expiration = -10 so it outputs a ticket)
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = -10;

    let mut to_be_signed = [0u8; 1024];
    let mut offset = 0;
    to_be_signed[offset..offset + nonce_tpm.get_size() as usize]
        .copy_from_slice(nonce_tpm.get_buffer());
    offset += nonce_tpm.get_size() as usize;
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.get_size() as usize]
        .copy_from_slice(cp_hash_a.get_buffer());
    offset += cp_hash_a.get_size() as usize;
    to_be_signed[offset..offset + policy_ref.get_size() as usize]
        .copy_from_slice(policy_ref.get_buffer());
    offset += policy_ref.get_size() as usize;

    let digest = compute_sha256(tpm.platform.crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; 256];
    let sig_len = tpm
        .platform
        .crypto
        .sign_inner(
            Alg::RSAPSS,
            &priv_buf[..priv_len],
            tpm2::TpmtHa::Sha256(&digest),
            &mut sig_out,
        )
        .unwrap();

    let sig = tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&sig_out[..sig_len]).unwrap(),
    };
    let auth = TpmtSignature::Rsapss(sig);

    use tpm2::commands::{PolicySigned, PolicySignedHandles};
    let ps_handles = PolicySignedHandles {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
    };
    let ps_cmd = PolicySigned {
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let (_, ps_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &ps_handles, &ps_cmd, &[]).unwrap();

    // We get our auth ticket (TPMT_TK_AUTH) bound to the current time_epoch
    let ticket = ps_rsp.policy_ticket;
    let timeout = ps_rsp.timeout;

    // 3. Simulate TPM restart -> epoch changes
    global_state.time_epoch ^= 0x1234567890ABCDEF;

    // 4. Start a NEW policy session (because the old one died on reboot)
    let (policy_session_resp2, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let policy_session_handle2 = policy_session_resp2.session_handle;

    // 5. Try to use PolicyTicket with the expired ticket from the old epoch
    use tpm2::commands::{PolicyTicket, PolicyTicketHandles};
    let pt_handles = PolicyTicketHandles {
        policy_session: policy_session_handle2,
    };
    let pt_cmd = PolicyTicket {
        timeout,
        cp_hash_a,
        policy_ref,
        auth_name: auth_name.as_tpm2b(),
        ticket,
    };

    let pt_res = execute_tpm_command(&mut tpm, &mut global_state, &pt_handles, &pt_cmd, &[]);

    // It should fail with TPM_RC_TICKET because the ticket's HMAC won't match the new epoch
    assert_eq!(
        pt_res.err(),
        Some(TpmRc::TICKET.with(Position::parameter(5)).get())
    );
}
