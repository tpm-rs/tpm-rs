use common::marshal_to_slice;

use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{Command, Message, UnmarshalMessage};
use tpm2::crypto::Asymmetric;
use tpm2::errors::TpmRc;
use tpm2::{
    AlgSym, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName,
    Tpm2bNonce, Tpm2bPublicKeyRsa, TpmaObject, TpmaSession, TpmiAlgCipherMode, TpmiAlgHash,
    TpmiAlgSymMode, TpmsAuthCommand, TpmsRsaParms, TpmtPublic, TpmtSymDefObject,
};
use tpm2::{Handle, TpmCc, TpmSe};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

fn leak_bytes(bytes: &[u8]) -> &'static [u8] {
    std::vec::Vec::leak(bytes.to_vec())
}

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a mut FakeRng,
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

/// `TPM2_PolicyCommandCode(TPM_CC_Duplicate)` policy digest (SHA-256), used as the authPolicy of
/// the test objects: the DUP role of `TPM2_Duplicate` always requires a policy session in the C
/// reference (`IsPolicySessionRequired`), so the objects must carry a satisfiable policy.
const DUP_POLICY_DIGEST: [u8; 32] =
    hex!("bef56b8c1cc84e11edd717528d2cd99356bd2bbf8f015209c3f84aeeaba8e8a2");

/// Starts a policy session with `auth_hash`, runs `PolicyCommandCode(TPM_CC_Duplicate)` on it,
/// and returns the authorization that uses it for `TPM2_Duplicate`.
///
/// This is a separate, non-generic function so that the generic bounds of
/// [`execute_tpm_command`] do not interfere with resolving the bounds for these commands.
fn start_duplicate_policy_session(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    auth_hash: TpmiAlgHash,
) -> Result<TpmsAuthCommand<'static>, u32> {
    use tpm2::commands::{PolicyCommandCode, StartAuthSession};
    let session = execute_tpm_command_raw(
        tpm,
        global_state,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[0x5A; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Policy,
            symmetric: None,
            auth_hash,
        },
        &[],
    )?;
    execute_tpm_command_raw(
        tpm,
        global_state,
        &PolicyCommandCode {
            policy_session: session.session_handle,
            code: TpmCc::Duplicate,
        },
        &[],
    )?;
    Ok(TpmsAuthCommand {
        session_handle: session.session_handle,
        nonce: Tpm2bNonce::from_bytes(&[0xA5; 16]).unwrap(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    })
}

/// Executes `cmd`. When `auths` is empty, the authorizations the C reference requires for the
/// command's authorization handles are supplied automatically (it returns
/// `TPM_RC_AUTH_MISSING` otherwise): empty password sessions for USER/ADMIN handles, and for
/// `TPM2_Duplicate` a policy session that satisfied `PolicyCommandCode(TPM_CC_Duplicate)`.
fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    if !auths.is_empty() {
        return execute_tpm_command_raw(tpm, global_state, cmd, auths);
    }
    let password = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    match C::CMD_CODE {
        TpmCc::Duplicate => {
            // The policy session's hash must be the object's nameAlg (objectHandle comes first).
            let object_handle = cmd.handles().as_ref()[0].0;
            let auth_hash = global_state
                .transient_objects
                .iter()
                .flatten()
                .find(|o| o.handle == object_handle)
                .and_then(|o| o.public.name_alg)
                .unwrap_or(TpmiAlgHash::Sha256);
            let policy = start_duplicate_policy_session(tpm, global_state, auth_hash)?;
            execute_tpm_command_raw(tpm, global_state, cmd, &[policy])
        }
        TpmCc::ActivateCredential => {
            execute_tpm_command_raw(tpm, global_state, cmd, &[password, password])
        }
        TpmCc::Load | TpmCc::Import | TpmCc::Create | TpmCc::CreatePrimary => {
            execute_tpm_command_raw(tpm, global_state, cmd, &[password])
        }
        _ => execute_tpm_command_raw(tpm, global_state, cmd, &[]),
    }
}

fn execute_tpm_command_raw<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for handle in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&handle.0.to_be_bytes());
        offset += 4;
    }

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
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for handle in resp_handles.as_mut() {
        *handle = Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice = leak_bytes(&response_buf[resp_offset..resp_size]);
    let resp = <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut params_slice)
        .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp)
}

fn compute_key_name(
    crypto: &TestCryptoProvider,
    public: &TpmtPublic,
) -> tpm2_impl::owned::OwnedTpm2b<66> {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let alg = public.name_alg.unwrap_or(TpmiAlgHash::Sha256);
    let mut name_bytes = [0u8; 66];
    name_bytes[0..2].copy_from_slice(&tpm2::Alg::from(alg).id().to_be_bytes());
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash(crypto, alg, &buf[..len], &mut out)
        .unwrap()
        .digest();
    name_bytes[2..2 + digest.len()].copy_from_slice(digest);
    tpm2_impl::owned::OwnedTpm2b::new(&name_bytes[..2 + digest.len()]).unwrap()
}

fn create_transient_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
) -> TransientObject {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 2048];
    use tpm2::Alg;
    use tpm2::crypto::asymmetric::KeyParams;
    use tpm2::crypto::asymmetric::TpmiRsaKeyBits;

    let (pub_len, priv_len) = crypto
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
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::from_bytes(&DUP_POLICY_DIGEST).unwrap(),
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
    let name = compute_key_name(crypto, &public);
    let mut private = [0u8; 1536];
    private[..priv_len].copy_from_slice(&priv_buf[..priv_len]);
    TransientObject {
        handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

fn create_transient_ecc_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
    curve: tpm2::TpmEccCurve,
) -> TransientObject {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 2048];
    use tpm2::Alg;
    use tpm2::TpmEccCurve;
    use tpm2::crypto::asymmetric::KeyParams;

    let ecc_curve = if (curve as u16) == u16::from(tpm2::TpmEccCurve::NistP256) {
        TpmEccCurve::NistP256
    } else if (curve as u16) == u16::from(tpm2::TpmEccCurve::BNP256) {
        TpmEccCurve::BNP256
    } else {
        panic!("unsupported curve: {:?}", curve);
    };

    let (pub_len, priv_len) = crypto
        .generate_key(
            Alg::ECC,
            Some(KeyParams::Ecc(ecc_curve)),
            &mut pub_buf,
            &mut priv_buf,
            None,
        )
        .unwrap();

    let unique = tpm2::TpmsEccPoint {
        x: tpm2::Tpm2bEccParameter::from_bytes(&pub_buf[..pub_len / 2]).unwrap(),
        y: tpm2::Tpm2bEccParameter::from_bytes(&pub_buf[pub_len / 2..pub_len]).unwrap(),
    };

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::from_bytes(&DUP_POLICY_DIGEST).unwrap(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::try_from(curve as u16).unwrap(),
                kdf: None,
            },
            unique,
        ),
    };
    let name = compute_key_name(crypto, &public);
    let mut private = [0u8; 1536];
    private[..priv_len].copy_from_slice(&priv_buf[..priv_len]);
    TransientObject {
        handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_duplicate_unsupported_curve() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    // 1. Create parent key with an unsupported curve (e.g. 999)
    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Ecc(ref mut parms, _) =
        parent.public.parms_and_id
    {
        parms.curve_id = tpm2::TpmEccCurve::NistP224;
    }
    // Update name
    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
    parent.qualified_name = parent.name;
    global_state.transient_objects[0] = Some(parent);

    // 2. Create target signing key
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    // 3. Execute Duplicate on target under parent -> should fail with Value error (132)
    use tpm2::commands::Duplicate;
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_cmd, &[]);
    assert_eq!(res.as_ref().err().copied(), Some(TpmRc::VALUE.get()));
    println!("Duplicate with unsupported curve result: {:?}", res);
}

#[test]
fn test_make_credential_panic_vulnerability_oversized_ecc_point() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    // 1. Create a protector ECC key at 0x80000001
    let mut protector = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Ecc(ref mut parms, _) =
        protector.public.parms_and_id
    {
        parms.symmetric = Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        });
    }

    // Modify its public unique coordinates to be oversized (33 bytes)
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Ecc(_, ref mut point) =
        protector.public.parms_and_id
    {
        point.x = tpm2_impl::owned::OwnedTpm2b::new(&[0u8; 33]).unwrap();
    }
    global_state.transient_objects[0] = Some(protector);

    // 2. MakeCredential
    use tpm2::commands::MakeCredential;
    let mc_cmd = MakeCredential {
        handle: Handle(0x80000001),
        credential: Tpm2bDigest::from_bytes(b"credential").unwrap(),
        object_name: Tpm2bName::from_bytes(&[1, 2, 3]).unwrap(),
    };

    // This should NOT panic. C CryptSecretEncrypt returns a bare TPM_RC_KEY when the ECDH point
    // multiplication with the (invalid) protector public key fails (CryptUtil.c).
    let res = execute_tpm_command(&mut tpm, &mut global_state, &mc_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::KEY.get()));
}

#[test]
fn test_cpc_2_14_01_01_create_sym_under_null_parent() {
    use tpm2::TpmsSensitiveCreate;
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    // 1. Create parent RSA key with symmetric: Null
    let mut parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Rsa(ref mut parms, _) =
        parent.public.parms_and_id
    {
        parms.symmetric = None;
    }
    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
    parent.qualified_name = parent.name;
    global_state.transient_objects[0] = Some(parent);

    // 2. Execute Create for a SymCipher object with SHA1 name_alg
    use tpm2::commands::Create;
    let data_buf = [0xAAu8; 16];
    let data = tpm2::Tpm2bSensitiveData::from_bytes(&data_buf).unwrap();
    let cmd = Create {
        parent_handle: Handle(0x80000001),
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(&[1, 2, 3]).unwrap(),
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
        outside_info: tpm2::Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]);
    assert!(res.is_ok(), "Create failed: {:?}", res.err());
}
