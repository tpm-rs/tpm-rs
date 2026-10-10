#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

mod common;

use alloc::vec::Vec;
use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider, marshal_to_slice};
use hex_literal::hex;
use tpm2::commands::{
    ActivateCredential, Command, Create, CreatePrimary, Duplicate, Import, Load, MakeCredential,
    Message, PolicyCommandCode, PolicyGetDigest, StartAuthSession, UnmarshalMessage,
};
use tpm2::crypto::{Ecc, EccPrivateKey, EccPublicKey, Random, Rsa, RsaPrivateKey, RsaPublicKey};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Handle, Marshal, PublicParmsAndId, ResponseHeader, Tpm2bAuth, Tpm2bData, Tpm2bDigest,
    Tpm2bEncryptedSecret, Tpm2bIdObject, Tpm2bName, Tpm2bNonce, Tpm2bPrivate, Tpm2bPublic,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmCc, TpmEccCurve, TpmSe, TpmaObject, TpmaSession,
    TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmiStCommandTag,
    TpmlPcrSelection, TpmsAuthCommand, TpmsEccParms, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic,
    TpmtSymDefObject, Unmarshal,
};
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{
    OwnedEccParameter, OwnedName, OwnedPrivateKeyRsa, OwnedPublicParmsAndId,
    OwnedSensitiveComposite, OwnedSensitiveData, OwnedSymKey,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

struct StartAuthSessionHandles {
    pub tpm_key: Handle,
    pub bind: Handle,
}
struct PolicyCommandCodeHandles {
    pub policy_session: Handle,
}
struct PolicyGetDigestHandles {
    pub policy_session: Handle,
}
struct DuplicateHandles {
    pub object_handle: Handle,
    pub new_parent_handle: Handle,
}
struct ImportHandles {
    pub parent_handle: Handle,
}
struct LoadHandles {
    pub parent_handle: Handle,
}
struct CreatePrimaryHandles {
    pub primary_handle: Handle,
}
struct MakeCredentialHandles {
    pub handle: Handle,
}
struct ActivateCredentialHandles {
    pub activate_handle: Handle,
    pub key_handle: Handle,
}
struct CreateHandles {
    pub parent_handle: Handle,
}

trait TestHandles {
    fn to_vec(&self) -> Vec<Handle>;
}

impl TestHandles for StartAuthSessionHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.tpm_key, self.bind]
    }
}
impl TestHandles for PolicyCommandCodeHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.policy_session]
    }
}
impl TestHandles for PolicyGetDigestHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.policy_session]
    }
}
impl TestHandles for DuplicateHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.object_handle, self.new_parent_handle]
    }
}
impl TestHandles for ImportHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.parent_handle]
    }
}
impl TestHandles for LoadHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.parent_handle]
    }
}
impl TestHandles for CreatePrimaryHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.primary_handle]
    }
}
impl TestHandles for MakeCredentialHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.handle]
    }
}
impl TestHandles for ActivateCredentialHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.activate_handle, self.key_handle]
    }
}
impl TestHandles for CreateHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.parent_handle]
    }
}

fn leak_bytes(bytes: &[u8]) -> &'static [u8] {
    std::vec::Vec::leak(bytes.to_vec())
}

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    _rng: &FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
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

fn execute_tpm_command<C: Command, H: TestHandles>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &H,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::Response<'static>, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static> + Copy,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    request_buf[0..2].copy_from_slice(&tag.to_be_bytes());
    request_buf[6..10].copy_from_slice(&C::CMD_CODE.code().to_be_bytes());

    for h in handles.to_vec() {
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

    let cmd_len = marshal_to_slice(cmd, &mut request_buf[offset..]);
    offset += cmd_len;
    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);
    assert!(resp_size >= ResponseHeader::MAX_SIZE);

    let mut resp_slice: &'static [u8] = leak_bytes(&response_buf[..resp_size]);
    let resp_header = ResponseHeader::unmarshal(&mut resp_slice).unwrap();
    if let Err(rc) = resp_header.rc {
        return Err(rc.get());
    }

    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut resp_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    if resp_header.tag == TpmiStCommandTag::Sessions {
        let param_size = usize::try_from(u32::unmarshal(&mut resp_slice).unwrap()).unwrap();
        let mut param_slice = &resp_slice[..param_size];
        let resp_params = C::Response::unmarshal_with_handles(resp_handles, &mut param_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;
        Ok((resp_params, resp_params))
    } else {
        let resp_params = C::Response::unmarshal_with_handles(resp_handles, &mut resp_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;
        Ok((resp_params, resp_params))
    }
}

fn compute_key_name(crypto: &TestCryptoProvider, public: &TpmtPublic) -> OwnedName {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let alg = public.name_alg.unwrap_or(TpmiAlgHash::Sha256);
    let mut name_bytes = [0u8; 66];
    name_bytes[0..2].copy_from_slice(&u16::from(tpm2::Alg::from(alg)).to_be_bytes());
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash(crypto, alg, &buf[..len], &mut out)
        .unwrap()
        .digest();
    name_bytes[2..2 + digest.len()].copy_from_slice(digest);
    OwnedName::from_bytes(&name_bytes[..2 + digest.len()]).unwrap()
}

fn create_transient_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
) -> TransientObject {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&handle.to_be_bytes());
    let mut rng = crypto.rng_seeded(&seed).unwrap();
    let rsa_key = Rsa::generate_key(crypto, &mut rng, TpmiRsaKeyBits::Rsa2048, 0).unwrap();
    let mut n = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let unique = rsa_key.public_key().modulus(&mut n).unwrap();
    let mut p = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let prime_p = rsa_key.prime_p(&mut p).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
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
    TransientObject {
        handle,
        seed: [0u8; 32],
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::from(prime_p)),
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_policy_command_code_success() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Start a policy session
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (resp_handles, _) = execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[])
        .expect("StartAuthSession failed");

    let session_handle = resp_handles.session_handle;

    // 2. Call PolicyCommandCode with TpmCc::Load (supported command)
    let policy_handles = PolicyCommandCodeHandles {
        policy_session: session_handle,
    };
    let policy_cmd = PolicyCommandCode {
        policy_session: session_handle,
        code: TpmCc::Load,
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    )
    .expect("PolicyCommandCode failed");

    // 3. Call PolicyGetDigest to verify the updated digest
    let digest_handles = PolicyGetDigestHandles {
        policy_session: session_handle,
    };
    let digest_cmd = PolicyGetDigest {
        policy_session: session_handle,
    };
    let (_, digest_resp) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &digest_handles,
        &digest_cmd,
        &[],
    )
    .expect("PolicyGetDigest failed");

    let mut expected_update = [0u8; 40];
    expected_update[32..36].copy_from_slice(&TpmCc::PolicyCommandCode.code().to_be_bytes());
    expected_update[36..40].copy_from_slice(&TpmCc::Load.code().to_be_bytes());

    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected_digest = tpm2::crypto::hash(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        &expected_update,
        &mut out,
    )
    .unwrap()
    .digest();
    assert_eq!(digest_resp.policy_digest.as_slice(), expected_digest);
}

#[test]
fn test_policy_command_code_failures() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // Start a policy session
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let session_handle = resp_handles.session_handle;

    // 1. Call PolicyCommandCode with unsupported code (TpmCc::PPCommands)
    let policy_handles = PolicyCommandCodeHandles {
        policy_session: session_handle,
    };
    let mut policy_cmd = PolicyCommandCode {
        policy_session: session_handle,
        code: TpmCc::PPCommands,
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::POLICY_CC.get()));

    // 2. Call PolicyCommandCode with supported code (TpmCc::Load) -> should succeed
    policy_cmd.code = TpmCc::Load;
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    )
    .unwrap();

    // 3. Call PolicyCommandCode with a different code (TpmCc::Import) -> should fail with Value (132)
    policy_cmd.code = TpmCc::Import;
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::VALUE.get()));
}

#[test]
fn test_policy_command_code_trial_session_mismatch() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Create a transient target key to use for a command
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(target);

    // 2. Start a trial policy session
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let session_handle = resp_handles.session_handle;

    // 3. Execute PolicyCommandCode on Trial session (should succeed now!)
    let policy_handles = PolicyCommandCodeHandles {
        policy_session: session_handle,
    };
    let policy_cmd = PolicyCommandCode {
        policy_session: session_handle,
        code: TpmCc::Duplicate,
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    );
    assert!(res.is_ok());

    // 4. Try to use the trial session to authorize a Duplicate command (should fail with AuthType)
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle::RH_NULL,
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle::RH_NULL,
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let auth = TpmsAuthCommand {
        session_handle: Handle(session_handle.0),
        nonce: Tpm2bNonce::new(&[2; 32]).unwrap(),
        session_attributes: TpmaSession(1), // continueSession
        hmac: Tpm2bAuth::default(),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[auth]);
    assert_eq!(res.err(), Some(TpmRc::AUTH_TYPE.get()));
}

#[test]
fn test_policy_get_digest_non_policy_session() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // Start an HMAC session
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let session_handle = resp_handles.session_handle;

    // PolicyGetDigest on HMAC session should fail with Value at H1
    let digest_handles = PolicyGetDigestHandles {
        policy_session: session_handle,
    };
    let digest_cmd = PolicyGetDigest {
        policy_session: session_handle,
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &digest_handles,
        &digest_cmd,
        &[],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}

#[test]
fn test_duplicate_fixed_parent() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent storage key (handle 0x80000001)
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // 2. Create a target signing key with FIXED_PARENT attribute (handle 0x80000002)
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH | TpmaObject::FIXED_PARENT,
    );
    global_state.transient_objects[1] = Some(target);

    // 3. Call Duplicate on fixedParent key -> should fail with Attributes (130)
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );
}

#[test]
fn test_duplicate_invalid_parent() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Create parent key that is NOT asymmetric (e.g. parent is symmetric/keyed hash)
    let mut parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    parent.public.parms_and_id = OwnedPublicParmsAndId::KeyedHash(None, Default::default());
    global_state.transient_objects[0] = Some(parent);

    // 2. Create target key
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target);

    // 3. Call Duplicate with invalid parent type -> should fail with Type (138)
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(2)).get()));
}

#[test]
fn test_import_fixed_tpm_or_parent() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // Create parent storage key
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // Create target key public struct with FIXED_TPM attribute set
    let target_public_struct = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let object_public = tpm2::Tpm2b(target_public_struct);

    // Call Import -> should fail with Attributes (130)
    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        parent_handle: Handle(0x80000001),
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: None,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get())
    );
}

#[test]
fn test_load_parent_not_decrypt_restricted() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent key that is NOT restricted (e.g. decrypt only)
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // 2. Create target key public struct
    let target_public_struct = TpmtPublic {
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
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_public = tpm2::Tpm2b(target_public_struct);

    // 3. Call Load under this parent -> should fail with Type at H1
    let load_handles = LoadHandles {
        parent_handle: Handle(0x80000001),
    };
    let load_cmd = Load {
        parent_handle: Handle(0x80000001),
        in_private: Tpm2bPrivate::new(&[1, 2, 3]).unwrap(),
        in_public,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(1)).get()));
}

#[test]
fn test_load_unsupported_name_alg() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // Create a parent storage key
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // Create key public area with empty RSA unique -> KEY at P2
    let target_public_struct = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha1),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_public = tpm2::Tpm2b(target_public_struct);

    let load_handles = LoadHandles {
        parent_handle: Handle(0x80000001),
    };
    let load_cmd = Load {
        parent_handle: Handle(0x80000001),
        in_private: Tpm2bPrivate::new(&[1, 2, 3]).unwrap(),
        in_public,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::KEY.with(Position::parameter(2)).get())
    );
}

#[test]
fn test_duplicate_import_load_integration_flow() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Setup a valid storage key (parent) at 0x80000001
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent.clone());

    // 2. Setup a target signing key at 0x80000002
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    // 3. Execute Duplicate on target under parent
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let (_, dup_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[])
            .expect("Duplicate failed in integration flow");

    // 4. Execute Import under parent using duplicate output
    let object_public = tpm2::Tpm2b(target.public.as_tpmt());

    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        parent_handle: Handle(0x80000001),
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: None,
    };
    let (_, imp_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[])
            .expect("Import failed in integration flow");

    // 5. Execute Load under parent using import output
    let load_handles = LoadHandles {
        parent_handle: Handle(0x80000001),
    };
    let load_cmd = Load {
        parent_handle: Handle(0x80000001),
        in_private: imp_resp.out_private,
        in_public: object_public,
    };
    let (load_resp_handles, load_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[])
            .expect("Load failed in integration flow");

    // Loaded object name should match target name
    assert_eq!(load_resp.name.as_slice(), target.name.get_buffer());
    // Verify that the new handle is a transient handle (starts with 0x80)
    assert_eq!(load_resp_handles.object_handle.0 >> 24, 0x80);
}

#[test]
fn test_duplicate_import_load_exhaustive_algos() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();

    let parent_base = create_transient_key(
        &crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    let target_base = create_transient_key(
        &crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );

    let hash_algos = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ];

    let aes128_cfb = TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    };
    let aes256_cfb = TpmtSymDefObject {
        alg: AlgSym::Aes256,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    };

    let sym_algos = [None, Some(aes128_cfb), Some(aes256_cfb)];

    for &parent_hash in &hash_algos {
        for &target_hash in &[TpmiAlgHash::Sha1, TpmiAlgHash::Sha256] {
            for &sym_alg in &sym_algos {
                for &parent_sym in &[None, Some(aes128_cfb)] {
                    let (mut tpm, mut global_state) =
                        setup_tpm(&crypto, &mut storage, &mut timer, &rng);

                    // 1. Create a parent storage key (handle 0x80000001) with parent_hash and parent_sym
                    let mut parent = parent_base.clone();
                    parent.public.name_alg = Some(parent_hash);
                    if let OwnedPublicParmsAndId::Rsa(ref mut parms, _) = parent.public.parms_and_id
                    {
                        parms.symmetric = parent_sym;
                    }
                    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
                    parent.qualified_name = parent.name;
                    global_state.transient_objects[0] = Some(parent);

                    // 2. Create target signing key (handle 0x80000002) with target_hash
                    let mut target = target_base.clone();
                    target.public.name_alg = Some(target_hash);
                    target.name = compute_key_name(tpm.platform.crypto, &target.public.as_tpmt());
                    target.qualified_name = target.name;
                    global_state.transient_objects[1] = Some(target.clone());

                    // 3. Execute Duplicate on target under parent
                    let dup_handles = DuplicateHandles {
                        object_handle: Handle(0x80000002),
                        new_parent_handle: Handle(0x80000001),
                    };

                    let encryption_key_in = match sym_alg {
                        Some(TpmtSymDefObject {
                            alg: AlgSym::Aes128,
                            ..
                        }) => {
                            let mut key_data = vec![0u8; 16];
                            tpm.fill_random(&mut key_data).unwrap();
                            Tpm2bData::new(leak_bytes(&key_data)).unwrap()
                        }
                        Some(TpmtSymDefObject {
                            alg: AlgSym::Aes256,
                            ..
                        }) => {
                            let mut key_data = vec![0u8; 32];
                            tpm.fill_random(&mut key_data).unwrap();
                            Tpm2bData::new(leak_bytes(&key_data)).unwrap()
                        }
                        _ => Tpm2bData::default(),
                    };

                    let dup_cmd = Duplicate {
                        object_handle: Handle(0x80000002),
                        new_parent_handle: Handle(0x80000001),
                        encryption_key_in,
                        symmetric_alg: sym_alg,
                    };
                    let (_, dup_resp) = execute_tpm_command(
                        &mut tpm,
                        &mut global_state,
                        &dup_handles,
                        &dup_cmd,
                        &[],
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "Duplicate failed for parent_hash={:?}, sym_alg={:?}, error={:08X}",
                            parent_hash, sym_alg, e
                        )
                    });

                    // 4. Execute Import under parent using duplicate output
                    let object_public = tpm2::Tpm2b(target.public.as_tpmt());

                    let imp_handles = ImportHandles {
                        parent_handle: Handle(0x80000001),
                    };
                    let imp_cmd = Import {
                        parent_handle: Handle(0x80000001),
                        encryption_key: encryption_key_in,
                        object_public,
                        duplicate: dup_resp.duplicate,
                        in_sym_seed: dup_resp.out_sym_seed,
                        symmetric_alg: sym_alg,
                    };
                    let (_, imp_resp) = execute_tpm_command(
                        &mut tpm,
                        &mut global_state,
                        &imp_handles,
                        &imp_cmd,
                        &[],
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "Import failed for parent_hash={:?}, sym_alg={:?}, error={:08X}",
                            parent_hash, sym_alg, e
                        )
                    });

                    // 5. Execute Load under parent using import output
                    let load_handles = LoadHandles {
                        parent_handle: Handle(0x80000001),
                    };
                    let load_cmd = Load {
                        parent_handle: Handle(0x80000001),
                        in_private: imp_resp.out_private,
                        in_public: object_public,
                    };
                    let (load_resp_handles, load_resp) = execute_tpm_command(
                        &mut tpm,
                        &mut global_state,
                        &load_handles,
                        &load_cmd,
                        &[],
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "Load failed for parent_hash={:?}, sym_alg={:?}, error={:08X}",
                            parent_hash, sym_alg, e
                        )
                    });

                    assert_eq!(load_resp.name.as_slice(), target.name.get_buffer());
                    assert_eq!(load_resp_handles.object_handle.0 >> 24, 0x80);
                }
            }
        }
    }
}

fn create_transient_keyed_hash(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
    secret: &[u8],
) -> TransientObject {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let unique_digest = tpm2::crypto::hash(crypto, TpmiAlgHash::Sha256, secret, &mut out)
        .unwrap()
        .digest();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::new(unique_digest).unwrap()),
    };
    let name = compute_key_name(crypto, &public);
    TransientObject {
        handle,
        seed: [0u8; 32],
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::KeyedHash(
            OwnedSensitiveData::from_bytes(secret).unwrap(),
        ),
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_sw_duplicate_import_debug() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_keyed_hash(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        b"hello, unseal",
    );
    global_state.transient_objects[1] = Some(target);

    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let (_, dup_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]).unwrap();

    assert!(!dup_resp.duplicate.as_slice().is_empty());
}

#[test]
fn test_create_primary_debug() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle(0x40000001),
    };
    let primary_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                }),
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive,
        in_public: tpm2::Tpm2b(primary_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let (_, _cp_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &cp_handles, &cp_cmd, &[]).unwrap();
}

fn create_transient_ecc_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
    curve: TpmEccCurve,
) -> TransientObject {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&handle.to_be_bytes());
    let mut rng = crypto.rng_seeded(&seed).unwrap();
    let ecc_key = Ecc::generate_key(crypto, &mut rng, curve).unwrap();
    let mut x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let unique = ecc_key.public_key().point(&mut x, &mut y).unwrap();
    let mut d = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let scalar = ecc_key.scalar(&mut d).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: curve,
                kdf: None,
            },
            unique,
        ),
    };
    let name = compute_key_name(crypto, &public);
    TransientObject {
        handle,
        seed: [0u8; 32],
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Ecc(OwnedEccParameter::from(scalar)),
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_duplicate_import_load_exhaustive_parent_and_target_types() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();

    let parent_rsa = create_transient_key(
        &crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    let parent_p256 = create_transient_ecc_key(
        &crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        TpmEccCurve::NistP256,
    );
    let parent_p384 = create_transient_ecc_key(
        &crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        TpmEccCurve::NistP384,
    );

    let target_rsa = create_transient_key(
        &crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    let target_p256 = create_transient_ecc_key(
        &crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        TpmEccCurve::NistP256,
    );

    #[derive(Clone, Copy, Debug)]
    enum KeyGenType {
        Rsa,
        Ecc(TpmEccCurve),
    }

    let parent_types = [
        KeyGenType::Rsa,
        KeyGenType::Ecc(TpmEccCurve::NistP256),
        KeyGenType::Ecc(TpmEccCurve::NistP384),
    ];

    let target_types = [KeyGenType::Rsa, KeyGenType::Ecc(TpmEccCurve::NistP256)];

    let hash_algos = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ];

    for &parent_type in &parent_types {
        for &target_type in &target_types {
            for &parent_hash in &hash_algos {
                let (mut tpm, mut global_state) =
                    setup_tpm(&crypto, &mut storage, &mut timer, &rng);

                // 1. Create parent storage key
                let mut parent = match parent_type {
                    KeyGenType::Rsa => parent_rsa.clone(),
                    KeyGenType::Ecc(curve) => {
                        if curve == TpmEccCurve::NistP256 {
                            parent_p256.clone()
                        } else {
                            parent_p384.clone()
                        }
                    }
                };
                parent.public.name_alg = Some(parent_hash);
                parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
                parent.qualified_name = parent.name;
                global_state.transient_objects[0] = Some(parent);

                // 2. Create target signing key
                let target = match target_type {
                    KeyGenType::Rsa => target_rsa.clone(),
                    KeyGenType::Ecc(_) => target_p256.clone(),
                };
                global_state.transient_objects[1] = Some(target.clone());

                // 3. Execute Duplicate on target under parent
                let dup_handles = DuplicateHandles {
                    object_handle: Handle(0x80000002),
                    new_parent_handle: Handle(0x80000001),
                };
                let dup_cmd = Duplicate {
                    object_handle: Handle(0x80000002),
                    new_parent_handle: Handle(0x80000001),
                    encryption_key_in: Tpm2bData::default(),
                    symmetric_alg: None,
                };
                let (_, dup_resp) = execute_tpm_command(
                    &mut tpm,
                    &mut global_state,
                    &dup_handles,
                    &dup_cmd,
                    &[],
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "Exhaustive parent/target keygen failed: Duplicate failed for parent_type={:?}, target_type={:?}, parent_hash={:?}, error={:08X}",
                        parent_type, target_type, parent_hash, e
                    )
                });

                // 4. Execute Import under parent using duplicate output
                let object_public = tpm2::Tpm2b(target.public.as_tpmt());

                let imp_handles = ImportHandles {
                    parent_handle: Handle(0x80000001),
                };
                let imp_cmd = Import {
                    parent_handle: Handle(0x80000001),
                    encryption_key: Tpm2bData::default(),
                    object_public,
                    duplicate: dup_resp.duplicate,
                    in_sym_seed: dup_resp.out_sym_seed,
                    symmetric_alg: None,
                };
                let (_, imp_resp) = execute_tpm_command(
                    &mut tpm,
                    &mut global_state,
                    &imp_handles,
                    &imp_cmd,
                    &[],
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "Exhaustive parent/target keygen failed: Import failed for parent_type={:?}, target_type={:?}, parent_hash={:?}, error={:08X}",
                        parent_type, target_type, parent_hash, e
                    )
                });

                // 5. Execute Load under parent using import output
                let load_handles = LoadHandles {
                    parent_handle: Handle(0x80000001),
                };
                let load_cmd = Load {
                    parent_handle: Handle(0x80000001),
                    in_private: imp_resp.out_private,
                    in_public: object_public,
                };
                let (load_resp_handles, load_resp) = execute_tpm_command(
                    &mut tpm,
                    &mut global_state,
                    &load_handles,
                    &load_cmd,
                    &[],
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "Exhaustive parent/target keygen failed: Load failed for parent_type={:?}, target_type={:?}, parent_hash={:?}, error={:08X}",
                        parent_type, target_type, parent_hash, e
                    )
                });

                assert_eq!(load_resp.name.as_slice(), target.name.get_buffer());
                assert_eq!(load_resp_handles.object_handle.0 >> 24, 0x80);
            }
        }
    }
}

#[test]
fn test_duplicate_encrypted_duplication_attributes() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH | TpmaObject::ENCRYPTED_DUPLICATION,
    );
    global_state.transient_objects[1] = Some(target);

    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert!(
        res.is_err(),
        "Expected Duplicate command to fail because ENCRYPTED_DUPLICATION is set but symmetricAlg is Null"
    );

    let dup_handles_null_parent = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle::RH_NULL,
    };
    let dup_cmd_aes = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle::RH_NULL,
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        }),
    };
    let res_null_parent = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &dup_handles_null_parent,
        &dup_cmd_aes,
        &[],
    );
    assert!(
        res_null_parent.is_err(),
        "Expected Duplicate command to fail because ENCRYPTED_DUPLICATION is set but newParentHandle is RHNull"
    );
}

#[test]
fn test_import_encrypted_duplication_attributes() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH | TpmaObject::ENCRYPTED_DUPLICATION,
    );

    let object_public = tpm2::Tpm2b(target.public.as_tpmt());

    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        parent_handle: Handle(0x80000001),
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(1)).get())
    );
}

#[test]
fn test_duplicate_invalid_encryption_key_size() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target);

    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let bad_encryption_key = Tpm2bData::new(&[0u8; 8]).unwrap();
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: bad_encryption_key,
        symmetric_alg: Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        }),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(1)).get())
    );
}

#[test]
fn test_import_panic_vulnerability_oversized_ecc_point() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        TpmEccCurve::NistP256,
    );
    if let OwnedPublicParmsAndId::Ecc(ref mut parms, _) = parent.public.parms_and_id {
        parms.symmetric = Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        });
    }
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );

    let object_public: Tpm2bPublic = tpm2::Tpm2b(target.public.as_tpmt());

    let mut bad_seed_bytes = Vec::new();
    bad_seed_bytes.extend_from_slice(&33u16.to_be_bytes());
    bad_seed_bytes.extend_from_slice(&[0u8; 33]);
    bad_seed_bytes.extend_from_slice(&32u16.to_be_bytes());
    bad_seed_bytes.extend_from_slice(&[0u8; 32]);

    let in_sym_seed = Tpm2bEncryptedSecret::new(&bad_seed_bytes).unwrap();

    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        parent_handle: Handle(0x80000001),
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed,
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ECC_POINT.with(Position::parameter(4)).get())
    );
}

#[test]
fn test_import_empty_seed_with_symmetric_parent() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        TpmEccCurve::NistP256,
    );
    if let OwnedPublicParmsAndId::Ecc(ref mut parms, _) = parent.public.parms_and_id {
        parms.symmetric = Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        });
    }
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );

    let object_public: Tpm2bPublic = tpm2::Tpm2b(target.public.as_tpmt());

    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        parent_handle: Handle(0x80000001),
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    assert!(
        res.is_err(),
        "Expected Import to fail because in_sym_seed is empty but parent symmetric is not Null"
    );
}

#[test]
fn test_import_valid_dup_empty_seed_with_symmetric_parent() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        TpmEccCurve::NistP256,
    );
    if let OwnedPublicParmsAndId::Ecc(ref mut parms, _) = parent.public.parms_and_id {
        parms.symmetric = Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        });
    }
    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
    parent.qualified_name = parent.name;
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let (_, dup_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[])
            .expect("Duplicate failed");

    let object_public: Tpm2bPublic = tpm2::Tpm2b(target.public.as_tpmt());

    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        parent_handle: Handle(0x80000001),
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: dup_resp.duplicate,
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    assert!(
        res.is_err(),
        "Expected Import to fail because in_sym_seed is empty but parent symmetric is not Null"
    );
}

#[test]
fn test_duplicate_unsupported_curve() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        TpmEccCurve::NistP256,
    );
    if let OwnedPublicParmsAndId::Ecc(ref mut parms, _) = parent.public.parms_and_id {
        parms.curve_id = TpmEccCurve::NistP224;
    }
    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
    parent.qualified_name = parent.name;
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target);

    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(res.as_ref().err().copied(), Some(TpmRc::VALUE.get()));
}

#[test]
fn test_make_credential_panic_vulnerability_oversized_ecc_point() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let mut protector = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        TpmEccCurve::NistP256,
    );
    if let OwnedPublicParmsAndId::Ecc(ref mut parms, _) = protector.public.parms_and_id {
        parms.symmetric = Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        });
    }

    if let OwnedPublicParmsAndId::Ecc(_, ref mut point) = protector.public.parms_and_id {
        point.x = OwnedEccParameter::from_bytes(&[0u8; 33]).unwrap();
    }
    global_state.transient_objects[0] = Some(protector);

    let mc_handles = MakeCredentialHandles {
        handle: Handle(0x80000001),
    };
    let mc_cmd = MakeCredential {
        handle: Handle(0x80000001),
        credential: Tpm2bDigest::new(b"credential").unwrap(),
        object_name: Tpm2bName::new(&[1, 2, 3]).unwrap(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &mc_handles, &mc_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}

fn create_transient_sym_key(handle: u32, attrs: TpmaObject) -> TransientObject {
    let name = OwnedName::from_bytes(&[7, 8, 9]).unwrap();
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
            },
            Tpm2bDigest::default(),
        ),
    };
    TransientObject {
        handle,
        seed: [0u8; 32],
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Sym(OwnedSymKey::from_bytes(&[0u8; 16]).unwrap()),
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_activate_credential_symmetric_key_error() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target);

    let protector_sym = create_transient_sym_key(
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(protector_sym);

    let ac_handles = ActivateCredentialHandles {
        activate_handle: Handle(0x80000002),
        key_handle: Handle(0x80000001),
    };
    let ac_cmd = ActivateCredential {
        activate_handle: Handle(0x80000002),
        key_handle: Handle(0x80000001),
        credential_blob: Tpm2bIdObject::default(),
        secret: Tpm2bEncryptedSecret::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &ac_handles, &ac_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(2)).get()));
}

#[test]
fn test_cpc_2_14_01_01_create_sym_under_null_parent() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let mut parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    if let OwnedPublicParmsAndId::Rsa(ref mut parms, _) = parent.public.parms_and_id {
        parms.symmetric = None;
    }
    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
    parent.qualified_name = parent.name;
    global_state.transient_objects[0] = Some(parent);

    let handles = CreateHandles {
        parent_handle: Handle(0x80000001),
    };
    let data_buf = [0xAAu8; 16];
    let data = Tpm2bSensitiveData::new(&data_buf).unwrap();
    let cmd = Create {
        parent_handle: Handle(0x80000001),
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::new(&[1, 2, 3]).unwrap(),
            data,
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha1),
            object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                },
                Tpm2bDigest::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(res.is_ok(), "Create failed: {:?}", res.err());
}
