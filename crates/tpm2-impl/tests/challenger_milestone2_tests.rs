#![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

mod common;

use common::TestCryptoProvider;
use common::marshal_to_slice;
use common::{FakeRng, FakeStorage};
use hex_literal::hex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tpm2::commands::{
    Command, Message, PolicyAuthorize, PolicyCommandCode, PolicyGetDigest, PolicySigned,
    PolicyTicket, StartAuthSession, UnmarshalMessage, VerifySignature,
};
use tpm2::crypto::{
    Finalize as _, Hash as _, Random as _, Rsa, RsaPrivateKey as _, RsaPublicKey as _,
    RsaSigScheme, Signing as _, Update as _,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, AlgSym, Handle, Marshal, PublicParmsAndId, ResponseHeader, Ticket, Tpm2bAuth, Tpm2bDigest,
    Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce, Tpm2bPublicKeyRsa, TpmCc,
    TpmSe, TpmaObject, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits,
    TpmiStCommandTag, TpmsAuthCommand, TpmsRsaParms, TpmsSignatureEcc, TpmsSignatureRsa, TpmtHa,
    TpmtPublic, TpmtSignature, TpmtSymDefObject, TpmtTkVerified, Unmarshal,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{OwnedName, OwnedPrivateKeyRsa, OwnedSensitiveComposite, OwnedSymKey};
use tpm2_rustcrypto::RsaPrivateKey;

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
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut T,
    _rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, T>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(&[0u8; 32]).unwrap();
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

fn execute_tpm_command<C: Command, T: tpm2_impl::timer::TpmTimer>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, T>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::Response<'static>, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static> + Copy,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for h in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let mut auth_slice = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_slice);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_slice[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);
    assert!(resp_size >= ResponseHeader::MAX_SIZE);

    let mut resp_slice: &'static [u8] = std::vec::Vec::leak(response_buf[..resp_size].to_vec());
    let resp_header = ResponseHeader::unmarshal(&mut resp_slice).unwrap();
    if let Err(rc) = resp_header.rc {
        return Err(rc.get());
    }

    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut resp_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let resp_params = if resp_header.tag == TpmiStCommandTag::Sessions {
        let param_size = usize::try_from(u32::unmarshal(&mut resp_slice).unwrap()).unwrap();
        let mut param_slice = &resp_slice[..param_size];
        C::Response::unmarshal_with_handles(resp_handles, &mut param_slice)
            .map_err(|_| TpmRc::FAILURE.get())?
    } else {
        C::Response::unmarshal_with_handles(resp_handles, &mut resp_slice)
            .map_err(|_| TpmRc::FAILURE.get())?
    };

    Ok((resp_params, resp_params))
}

fn compute_key_name(crypto: &TestCryptoProvider, public: &TpmtPublic) -> OwnedName {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let digest = compute_sha256(crypto, &buf[..len]);

    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(&digest);
    OwnedName::from_bytes(&name_bytes[..34]).unwrap()
}

fn create_signing_key(crypto: &TestCryptoProvider) -> (TransientObject, RsaPrivateKey) {
    let mut rng = crypto.rng_seeded(&[0x55; 32]).unwrap();
    let rsa_key = Rsa::generate_key(crypto, &mut rng, TpmiRsaKeyBits::Rsa2048, 0).unwrap();
    let mut n = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let unique = rsa_key.public_key().modulus(&mut n).unwrap();
    let mut p = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let prime_p = rsa_key.prime_p(&mut p).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            unique,
        ),
    };
    let name = compute_key_name(crypto, &public);
    let signing_key = TransientObject {
        handle: 0x80000001,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::from(prime_p)),
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    };
    (signing_key, rsa_key)
}

fn sign_rsapss<'a>(
    crypto: &TestCryptoProvider,
    rsa_key: &RsaPrivateKey,
    digest: &[u8; 32],
    out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
) -> Tpm2bPublicKeyRsa<'a> {
    let mut rng = crypto.rng_seeded(&[0x33; 32]).unwrap();
    crypto
        .rsa_sign(
            &mut rng,
            rsa_key,
            RsaSigScheme::Rsapss,
            TpmtHa::Sha256(digest),
            out,
        )
        .unwrap()
}

#[test]
fn test_challenger_policy_signed_invalid_signature() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (signing_key, rsa_key) = create_signing_key(&crypto);
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
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
    let nonce_slice = nonce_tpm.get_buffer();
    to_be_signed[offset..offset + nonce_slice.len()].copy_from_slice(nonce_slice);
    offset += nonce_slice.len();
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.as_slice().len()].copy_from_slice(cp_hash_a.as_slice());
    offset += cp_hash_a.as_slice().len();
    to_be_signed[offset..offset + policy_ref.as_slice().len()]
        .copy_from_slice(policy_ref.as_slice());
    offset += policy_ref.as_slice().len();

    let digest = compute_sha256(&crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig_len = sign_rsapss(&crypto, &rsa_key, &digest, &mut sig_out)
        .as_slice()
        .len();

    // Tamper with the signature bytes to make it invalid
    sig_out[10] ^= 0xFF;

    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::new(&sig_out[..sig_len]).unwrap(),
    };
    let auth = TpmtSignature::Rsapss(sig);

    let ps_cmd = PolicySigned {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    // Calling PolicySigned with tampered signature should fail with signature_for(Parameter, Pos5)
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
}

#[test]
fn test_challenger_policy_signed_incorrect_message() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (signing_key, rsa_key) = create_signing_key(&crypto);
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 2. Compute digest over an INCORRECT nonce_tpm (e.g. all 0xFF) and sign it
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 0;

    let incorrect_nonce = Tpm2bNonce::new(&[0xFF; 32]).unwrap();

    let mut to_be_signed = [0u8; 1024];
    let mut offset = 0;
    to_be_signed[offset..offset + incorrect_nonce.as_slice().len()]
        .copy_from_slice(incorrect_nonce.as_slice());
    offset += incorrect_nonce.as_slice().len();
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.as_slice().len()].copy_from_slice(cp_hash_a.as_slice());
    offset += cp_hash_a.as_slice().len();
    to_be_signed[offset..offset + policy_ref.as_slice().len()]
        .copy_from_slice(policy_ref.as_slice());
    offset += policy_ref.as_slice().len();

    let digest = compute_sha256(&crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig_tpm2b = sign_rsapss(&crypto, &rsa_key, &digest, &mut sig_out);

    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: sig_tpm2b,
    };
    let auth = TpmtSignature::Rsapss(sig);

    let ps_cmd = PolicySigned {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    // Calling PolicySigned should fail because the signature is over the incorrect nonce!
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
}

#[test]
fn test_challenger_policy_signed_expiration_and_timeout() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer {
        time: shared_time.clone(),
    };
    let rng = FakeRng::new();
    let (signing_key, rsa_key) = create_signing_key(&crypto);
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
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
    let nonce_slice = nonce_tpm.get_buffer();
    to_be_signed[offset..offset + nonce_slice.len()].copy_from_slice(nonce_slice);
    offset += nonce_slice.len();
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.as_slice().len()].copy_from_slice(cp_hash_a.as_slice());
    offset += cp_hash_a.as_slice().len();
    to_be_signed[offset..offset + policy_ref.as_slice().len()]
        .copy_from_slice(policy_ref.as_slice());
    offset += policy_ref.as_slice().len();

    let digest = compute_sha256(&crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig_tpm2b = sign_rsapss(&crypto, &rsa_key, &digest, &mut sig_out);

    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: sig_tpm2b,
    };
    let auth = TpmtSignature::Rsapss(sig);

    let ps_cmd = PolicySigned {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    // Calling PolicySigned with expiration = 10 should succeed and set the timeout
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]);
    assert!(res.is_ok());

    {
        let session = global_state.session(policy_session_handle.0).unwrap();
        assert_eq!(session.timeout, 10000);
    }

    // 3. Advance clock to 10001 ms (exceeding 10000 ms timeout)
    shared_time.store(10001, Ordering::SeqCst);

    let res2 = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]);
    assert_eq!(
        res2.err(),
        Some(TpmRc::EXPIRED.with(Position::handle(2)).get())
    );
}

#[test]
fn test_challenger_policy_signed_ticket_generation() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (signing_key, rsa_key) = create_signing_key(&crypto);
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
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
    let nonce_slice = nonce_tpm.get_buffer();
    to_be_signed[offset..offset + nonce_slice.len()].copy_from_slice(nonce_slice);
    offset += nonce_slice.len();
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.as_slice().len()].copy_from_slice(cp_hash_a.as_slice());
    offset += cp_hash_a.as_slice().len();
    to_be_signed[offset..offset + policy_ref.as_slice().len()]
        .copy_from_slice(policy_ref.as_slice());
    offset += policy_ref.as_slice().len();

    let digest = compute_sha256(&crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig_tpm2b = sign_rsapss(&crypto, &rsa_key, &digest, &mut sig_out);

    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: sig_tpm2b,
    };
    let auth = TpmtSignature::Rsapss(sig);

    let ps_cmd = PolicySigned {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    // Calling PolicySigned with negative expiration should generate a ticket in response
    let (_, ps_rsp) = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]).unwrap();

    // Verify tag is 0x8025 and digest is non-empty
    assert_eq!(ps_rsp.policy_ticket.tag().id(), 0x8025);
    assert!(!ps_rsp.policy_ticket.digest().as_slice().is_empty());
}

#[test]
fn test_challenger_policy_authorize_mismatched_policy() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Start a policy session and get its digest
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // Set a policy command code to advance digest
    let pcc_cmd = PolicyCommandCode {
        policy_session: policy_session_handle,
        code: TpmCc::GetRandom,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &pcc_cmd, &[]).unwrap();

    // 2. Prepare ticket inputs with a MISMATCHED approvedPolicy (e.g. all 0xEE)
    let mismatched_approved_policy = Tpm2bDigest::new(&[0xEE; 32]).unwrap();
    let policy_ref = Tpm2bNonce::default();

    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[3; 32]);
    let key_sign = Tpm2bName::new(&key_sign_bytes).unwrap();

    let check_ticket = TpmtTkVerified::Verified(Handle(0x4000000C), Tpm2bDigest::default());

    let pa_cmd = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy: mismatched_approved_policy,
        policy_ref,
        key_sign,
        check_ticket,
    };

    // Calling PolicyAuthorize with mismatched approved_policy should return value_for(Parameter, Pos1)
    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

#[test]
fn test_challenger_policy_authorize_wrong_ticket_hmac() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Start a policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // Get the current policy digest (empty, i.e., 32 bytes of zeros)
    let pgd_cmd = PolicyGetDigest {
        policy_session: policy_session_handle,
    };
    let (_, pgd_rsp) = execute_tpm_command(&mut tpm, &mut global_state, &pgd_cmd, &[]).unwrap();
    let approved_policy = pgd_rsp.policy_digest;

    // 2. Prepare ticket inputs with a WRONG/tampered HMAC digest
    let policy_ref = Tpm2bNonce::default();

    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[3; 32]);
    let key_sign = Tpm2bName::new(&key_sign_bytes).unwrap();

    let check_ticket =
        TpmtTkVerified::Verified(Handle(0x4000000C), Tpm2bDigest::new(&[0x99; 32]).unwrap());

    let pa_cmd = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy,
        policy_ref,
        key_sign,
        check_ticket,
    };

    // Calling PolicyAuthorize with wrong ticket HMAC should fail with value_for(Parameter, Pos4)
    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(4)).get())
    );
}

#[test]
fn test_challenger_policy_authorize_wrong_ticket_tag() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Start a policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let pgd_cmd = PolicyGetDigest {
        policy_session: policy_session_handle,
    };
    let (_, pgd_rsp) = execute_tpm_command(&mut tpm, &mut global_state, &pgd_cmd, &[]).unwrap();
    let approved_policy = pgd_rsp.policy_digest;

    let policy_ref = Tpm2bNonce::default();

    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[3; 32]);
    let key_sign = Tpm2bName::new(&key_sign_bytes).unwrap();

    let check_ticket = TpmtTkVerified::Verified(Handle(0x4000000C), Tpm2bDigest::default());

    let pa_cmd = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy,
        policy_ref,
        key_sign,
        check_ticket,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(4)).get())
    );
}

#[test]
fn test_challenger_policy_signed_trial_session_digest_update() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (signing_key, _) = create_signing_key(&crypto);
    let key_name = signing_key.name;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a trial session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // 2. Call PolicySigned on Trial session
    let policy_ref = Tpm2bNonce::new(&[9; 16]).unwrap();
    let ps_cmd = PolicySigned {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref,
        expiration: 0,
        auth: TpmtSignature::Rsapss(TpmsSignatureRsa {
            hash: TpmiAlgHash::Sha256,
            sig: Tpm2bPublicKeyRsa::default(),
        }),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]);
    assert!(res.is_ok());

    // 3. Call PolicyGetDigest to verify updated digest
    let pgd_cmd = PolicyGetDigest {
        policy_session: policy_session_handle,
    };
    let (_, pgd_rsp) = execute_tpm_command(&mut tpm, &mut global_state, &pgd_cmd, &[]).unwrap();

    let mut update1 = [0u8; 32 + 4 + 34];
    update1[32..36].copy_from_slice(&0x00000160u32.to_be_bytes());
    let key_name_slice = key_name.get_buffer();
    update1[36..36 + key_name_slice.len()].copy_from_slice(key_name_slice);

    let digest1 = compute_sha256(&crypto, &update1[..36 + key_name_slice.len()]);

    let mut update2 = Vec::new();
    update2.extend_from_slice(&digest1);
    update2.extend_from_slice(policy_ref.as_slice());

    let expected_digest = compute_sha256(&crypto, &update2);

    assert_eq!(pgd_rsp.policy_digest.as_slice(), &expected_digest);
}

#[test]
fn test_challenger_policy_authorize_trial_session_digest_update() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Start a trial session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // Advance digest by some command first
    let pcc_cmd = PolicyCommandCode {
        policy_session: policy_session_handle,
        code: TpmCc::GetRandom,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &pcc_cmd, &[]).unwrap();

    // Get current policy digest
    let pgd_cmd = PolicyGetDigest {
        policy_session: policy_session_handle,
    };
    let (_, pgd_rsp1) = execute_tpm_command(&mut tpm, &mut global_state, &pgd_cmd, &[]).unwrap();
    let approved_policy = pgd_rsp1.policy_digest;

    // 2. Call PolicyAuthorize on Trial session (no ticket validation)
    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[3; 32]);
    let key_sign = Tpm2bName::new(&key_sign_bytes).unwrap();
    let policy_ref = Tpm2bNonce::new(&[7; 8]).unwrap();

    let pa_cmd = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy,
        policy_ref,
        key_sign,
        check_ticket: TpmtTkVerified::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd, &[]);
    assert!(res.is_ok());

    // 3. Verify updated digest
    let (_, pgd_rsp2) = execute_tpm_command(&mut tpm, &mut global_state, &pgd_cmd, &[]).unwrap();

    let zero_digest = [0u8; 32];
    let mut update1 = Vec::new();
    update1.extend_from_slice(&zero_digest);
    update1.extend_from_slice(&0x0000016Au32.to_be_bytes());
    update1.extend_from_slice(key_sign.as_slice());

    let digest1 = compute_sha256(&crypto, &update1);

    let mut update2 = Vec::new();
    update2.extend_from_slice(&digest1);
    update2.extend_from_slice(policy_ref.as_slice());

    let expected_digest = compute_sha256(&crypto, &update2);

    assert_eq!(pgd_rsp2.policy_digest.as_slice(), &expected_digest);
}

#[test]
fn test_challenger_policy_authorize_invalid_key_sign_size() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Start a trial session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // 2. Call PolicyAuthorize with key_sign size < 2
    let key_sign_too_small = Tpm2bName::new(&[0]).unwrap();

    let pa_cmd = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        key_sign: key_sign_too_small,
        check_ticket: TpmtTkVerified::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(3)).get())
    );

    // 3. Call PolicyAuthorize with key_sign size not matching digest size of its hash algorithm
    let mut key_sign_mismatched = [0u8; 10];
    key_sign_mismatched[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    let key_sign = Tpm2bName::new(&key_sign_mismatched).unwrap();

    let pa_cmd2 = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        key_sign,
        check_ticket: TpmtTkVerified::default(),
    };
    let res2 = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd2, &[]);
    assert_eq!(
        res2.err(),
        Some(TpmRc::SIZE.with(Position::parameter(3)).get())
    );
}

#[test]
fn test_challenger_policy_authorize_invalid_key_sign_hash() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Start a trial session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // 2. Call PolicyAuthorize with invalid hash alg in key_sign (e.g. 0xFFFF)
    let mut key_sign_bad_hash = [0u8; 34];
    key_sign_bad_hash[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    let key_sign = Tpm2bName::new(&key_sign_bad_hash).unwrap();

    let pa_cmd = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        key_sign,
        check_ticket: TpmtTkVerified::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(Position::parameter(3)).get())
    );
}

#[test]
fn test_challenger_policy_signed_invalid_key_type() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Create a symmetric key and load it
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
            },
            Tpm2bDigest::default(),
        ),
    };
    let name = compute_key_name(&crypto, &public);
    let sym_key = TransientObject {
        handle: 0x80000002,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Sym(OwnedSymKey::from_bytes(&[0u8; 16]).unwrap()),
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(sym_key);

    // 2. Start a policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 3. Call PolicySigned using the symmetric key as authObject
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 0;

    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::new(&[0; 256]).unwrap(),
    };
    let auth = TpmtSignature::Rsapss(sig);

    let ps_cmd = PolicySigned {
        auth_object: Handle(0x80000002),
        policy_session: policy_session_handle,
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::KEY.with(Position::handle(1)).get()));
}

#[test]
fn test_challenger_policy_signed_scheme_mismatch() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (signing_key, _) = create_signing_key(&crypto);
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    let nonce_tpm = global_state
        .session(policy_session_handle.0)
        .unwrap()
        .nonce_tpm;

    // 2. Call PolicySigned on RSA key but with ECDSA signature
    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 0;

    let sig = TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: Tpm2bEccParameter::new(&[0; 32]).unwrap(),
        signature_s: Tpm2bEccParameter::new(&[0; 32]).unwrap(),
    };
    let auth = TpmtSignature::Ecdsa(sig);

    let ps_cmd = PolicySigned {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
}

#[test]
fn test_challenger_policy_authorize_success_flow() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (signing_key, rsa_key) = create_signing_key(&crypto);
    let key_name = signing_key.name;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    global_state.transient_objects[0] = Some(signing_key);

    // 1. Compute approvedPolicy and policyRef digest (aHash)
    let approved_policy = [0u8; 32];
    let policy_ref = Tpm2bNonce::new(&[8; 16]).unwrap();

    // aHash = SHA256(approvedPolicy || policyRef)
    let mut ahash_input = Vec::new();
    ahash_input.extend_from_slice(&approved_policy);
    ahash_input.extend_from_slice(policy_ref.as_slice());
    let ahash_digest = compute_sha256(&crypto, &ahash_input);

    // 2. Sign aHash
    let mut sig_out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig_tpm2b = sign_rsapss(&crypto, &rsa_key, &ahash_digest, &mut sig_out);

    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: sig_tpm2b,
    };
    let signature = TpmtSignature::Rsapss(sig);

    // 3. Call VerifySignature to get a ticket
    #[allow(deprecated)]
    let vs_cmd = VerifySignature {
        key_handle: Handle(0x80000001),
        digest: Tpm2bDigest::new(&ahash_digest).unwrap(),
        signature,
    };
    #[allow(deprecated)]
    let (_, vs_rsp) = execute_tpm_command(&mut tpm, &mut global_state, &vs_cmd, &[]).unwrap();
    #[allow(deprecated)]
    let mut ticket = vs_rsp.validation;

    let proof_bytes = &global_state.sh_proof[..usize::from(global_state.sh_proof_size)];
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&0x8022u16.to_be_bytes());
    hmac_input.extend_from_slice(&ahash_digest);
    hmac_input.extend_from_slice(key_name.get_buffer());

    let mut hmac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let hmac_digest = tpm2::crypto::hmac(
        &crypto,
        TpmiAlgHash::Sha256,
        proof_bytes,
        &hmac_input,
        &mut hmac_buf,
    )
    .unwrap();
    ticket = TpmtTkVerified::Verified(
        ticket.hierarchy(),
        Tpm2bDigest::new(hmac_digest.digest()).unwrap(),
    );

    // 4. Start a real policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // 5. Call PolicyAuthorize on this session
    let pa_cmd = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy: Tpm2bDigest::new(&approved_policy).unwrap(),
        policy_ref,
        key_sign: key_name.as_tpm2b(),
        check_ticket: ticket,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd, &[]);
    assert!(res.is_ok(), "PolicyAuthorize failed with {:?}", res.err());
}

#[test]
fn test_challenger_policy_authorize_forged_ticket_null_hierarchy() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let key_name = Tpm2bName::new(&[
        0, 11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32,
    ])
    .unwrap();

    let approved_policy = [0u8; 32];
    let policy_ref = Tpm2bNonce::new(&[8; 16]).unwrap();

    let mut ahash_input = Vec::new();
    ahash_input.extend_from_slice(&approved_policy);
    ahash_input.extend_from_slice(policy_ref.as_slice());
    let ahash_digest = compute_sha256(&crypto, &ahash_input);

    // Forge the ticket with RHNull (0x40000007) and empty key HMAC
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&0x8022u16.to_be_bytes());
    hmac_input.extend_from_slice(&ahash_digest);
    hmac_input.extend_from_slice(key_name.as_slice());

    let proof_bytes = &[];
    let mut hmac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let hmac_digest = tpm2::crypto::hmac(
        &crypto,
        TpmiAlgHash::Sha256,
        proof_bytes,
        &hmac_input,
        &mut hmac_buf,
    )
    .unwrap();

    let ticket = TpmtTkVerified::Verified(
        Handle::RH_NULL,
        Tpm2bDigest::new(hmac_digest.digest()).unwrap(),
    );

    // Start a real policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp.session_handle;

    // Call PolicyAuthorize on this session
    let pa_cmd = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy: Tpm2bDigest::new(&approved_policy).unwrap(),
        policy_ref,
        key_sign: key_name,
        check_ticket: ticket,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd, &[]);
    assert!(
        res.is_err(),
        "Expected PolicyAuthorize to fail with forged RHNull ticket, but it succeeded!"
    );
    let err = res.err().unwrap();
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(4)).get());
}

#[test]
fn test_challenger_policy_authorize_timeout_bypass_vulnerability() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer {
        time: shared_time.clone(),
    };
    let rng = FakeRng::new();
    let (signing_key, rsa_key) = create_signing_key(&crypto);
    let key_name = signing_key.name;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    global_state.transient_objects[0] = Some(signing_key);

    // Start policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp_handles, policy_session_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle = policy_session_resp_handles.session_handle;

    let nonce_tpm = policy_session_resp.nonce_tpm;

    let cp_hash_a = Tpm2bDigest::default();
    let policy_ref = Tpm2bNonce::default();
    let expiration: i32 = 10;

    let mut to_be_signed = [0u8; 1024];
    let mut offset = 0;
    to_be_signed[offset..offset + nonce_tpm.as_slice().len()].copy_from_slice(nonce_tpm.as_slice());
    offset += nonce_tpm.as_slice().len();
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.as_slice().len()].copy_from_slice(cp_hash_a.as_slice());
    offset += cp_hash_a.as_slice().len();
    to_be_signed[offset..offset + policy_ref.as_slice().len()]
        .copy_from_slice(policy_ref.as_slice());
    offset += policy_ref.as_slice().len();

    let digest = compute_sha256(&crypto, &to_be_signed[..offset]);

    let mut sig_out_ps = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig_ps_tpm2b = sign_rsapss(&crypto, &rsa_key, &digest, &mut sig_out_ps);

    let sig_ps = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: sig_ps_tpm2b,
    };
    let auth_ps = TpmtSignature::Rsapss(sig_ps);

    let ps_cmd = PolicySigned {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
        nonce_tpm,
        cp_hash_a,
        policy_ref,
        expiration,
        auth: auth_ps,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]);
    assert!(res.is_ok());

    {
        let session = global_state.session(policy_session_handle.0).unwrap();
        assert_eq!(session.timeout, 10000);
    }

    let (current_policy_digest, current_policy_digest_len) = {
        let session = global_state.session(policy_session_handle.0).unwrap();
        (session.policy_digest, session.policy_digest_len)
    };

    let pa_policy_ref = Tpm2bNonce::new(&[8; 16]).unwrap();

    let mut ahash_input = Vec::new();
    ahash_input.extend_from_slice(&current_policy_digest[..current_policy_digest_len]);
    ahash_input.extend_from_slice(pa_policy_ref.as_slice());
    let ahash_digest = compute_sha256(&crypto, &ahash_input);

    let mut sig_out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig_tpm2b = sign_rsapss(&crypto, &rsa_key, &ahash_digest, &mut sig_out);

    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: sig_tpm2b,
    };
    let signature = TpmtSignature::Rsapss(sig);

    #[allow(deprecated)]
    let vs_cmd = VerifySignature {
        key_handle: Handle(0x80000001),
        digest: Tpm2bDigest::new(&ahash_digest).unwrap(),
        signature,
    };
    #[allow(deprecated)]
    let (_, vs_rsp) = execute_tpm_command(&mut tpm, &mut global_state, &vs_cmd, &[]).unwrap();
    #[allow(deprecated)]
    let mut ticket = vs_rsp.validation;

    let proof_bytes = &global_state.sh_proof[..usize::from(global_state.sh_proof_size)];
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&0x8022u16.to_be_bytes());
    hmac_input.extend_from_slice(&ahash_digest);
    hmac_input.extend_from_slice(key_name.get_buffer());

    let mut hmac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let hmac_digest = tpm2::crypto::hmac(
        &crypto,
        TpmiAlgHash::Sha256,
        proof_bytes,
        &hmac_input,
        &mut hmac_buf,
    )
    .unwrap();
    ticket = TpmtTkVerified::Verified(
        ticket.hierarchy(),
        Tpm2bDigest::new(hmac_digest.digest()).unwrap(),
    );

    // Advance clock to 10001 ms (exceeding 10000 ms timeout)
    shared_time.store(10001, Ordering::SeqCst);

    let pa_cmd = PolicyAuthorize {
        policy_session: policy_session_handle,
        approved_policy: Tpm2bDigest::new(&current_policy_digest[..current_policy_digest_len])
            .unwrap(),
        policy_ref: pa_policy_ref,
        key_sign: key_name.as_tpm2b(),
        check_ticket: ticket,
    };

    let res2 = execute_tpm_command(&mut tpm, &mut global_state, &pa_cmd, &[]);
    assert_eq!(
        res2.err(),
        Some(TpmRc::EXPIRED.with(Position::handle(1)).get())
    );
}

#[test]
fn test_ticket_revival_fails_after_restart() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let shared_time = Arc::new(AtomicU64::new(0));
    let mut timer = MutableTimer { time: shared_time };
    let rng = FakeRng::new();
    let (signing_key, rsa_key) = create_signing_key(&crypto);
    let auth_name = signing_key.name;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    global_state.transient_objects[0] = Some(signing_key);

    // 1. Start a policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (policy_session_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
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
    let nonce_slice = nonce_tpm.get_buffer();
    to_be_signed[offset..offset + nonce_slice.len()].copy_from_slice(nonce_slice);
    offset += nonce_slice.len();
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.as_slice().len()].copy_from_slice(cp_hash_a.as_slice());
    offset += cp_hash_a.as_slice().len();
    to_be_signed[offset..offset + policy_ref.as_slice().len()]
        .copy_from_slice(policy_ref.as_slice());
    offset += policy_ref.as_slice().len();

    let digest = compute_sha256(&crypto, &to_be_signed[..offset]);

    let mut sig_out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig_tpm2b = sign_rsapss(&crypto, &rsa_key, &digest, &mut sig_out);

    let sig = TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: sig_tpm2b,
    };
    let auth = TpmtSignature::Rsapss(sig);

    let ps_cmd = PolicySigned {
        auth_object: Handle(0x80000001),
        policy_session: policy_session_handle,
        nonce_tpm: nonce_tpm.as_tpm2b(),
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let (_, ps_rsp) = execute_tpm_command(&mut tpm, &mut global_state, &ps_cmd, &[]).unwrap();

    let ticket = ps_rsp.policy_ticket;
    let timeout = ps_rsp.timeout;

    // 3. Simulate TPM restart -> epoch changes
    global_state.time_epoch ^= 0x1234567890ABCDEF;

    // 4. Start a NEW policy session
    let (policy_session_resp2, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session_handle2 = policy_session_resp2.session_handle;

    // 5. Try to use PolicyTicket with the expired ticket from the old epoch
    let pt_cmd = PolicyTicket {
        policy_session: policy_session_handle2,
        timeout,
        cp_hash_a,
        policy_ref,
        auth_name: auth_name.as_tpm2b(),
        ticket,
    };

    let pt_res = execute_tpm_command(&mut tpm, &mut global_state, &pt_cmd, &[]);

    assert_eq!(
        pt_res.err(),
        Some(TpmRc::TICKET.with(Position::parameter(5)).get())
    );
}
