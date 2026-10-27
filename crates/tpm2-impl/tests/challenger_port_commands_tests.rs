use common::marshal_to_slice;
use tpm2::errors::{Position, TpmRc};

use tpm2::Unmarshal;
extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{Command, Message, UnmarshalMessage};
use tpm2::{
    AlgSym, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bPrivate,
    Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgCipherMode, TpmiAlgHash, TpmsAuthCommand, TpmtPublic,
    TpmtSymDefObject,
};
use tpm2::{Handle, Marshal};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

use hex_literal::hex;
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{CryptoError, CryptoProvider};

struct StressTestCrypto;

impl_fake_hash!(StressTestCrypto);

impl AsymmetricSign for StressTestCrypto {
    fn sign_inner(
        &self,
        sign_alg: tpm2::Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let len = match sign_alg {
            tpm2::Alg::ECDSA => {
                if signature_out.len() < 64 {
                    return Err(CryptoError::Internal);
                }
                signature_out[..64].fill(0xee);
                64
            }
            _ => {
                if signature_out.len() < 256 {
                    return Err(CryptoError::Internal);
                }
                signature_out[..256].fill(0xee);
                256
            }
        };
        Ok(Some(len))
    }
}

impl Asymmetric for StressTestCrypto {
    fn verify_inner(
        &self,
        _sign_alg: tpm2::Alg,
        _public_key: &[u8],
        _rsa_exponent: u32,
        _digest: tpm2::TpmtHa<'_>,
        _signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Ok(true)
    }
    fn encrypt(
        &self,
        scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        public_key: &[u8],
        _rsa_exponent: u32,
        data: &[u8],
        ciphertext: &mut [u8],
        _label: &[u8],
    ) -> Result<Option<usize>, CryptoError> {
        let len = data.len();
        let out_len = if scheme == tpm2::Alg::OAEP && !public_key.is_empty() {
            public_key.len()
        } else {
            len
        };
        if ciphertext.len() < out_len {
            return Err(CryptoError::Internal);
        }
        ciphertext[..len].copy_from_slice(data);
        if out_len > len {
            ciphertext[len..out_len].fill(0);
        }
        Ok(Some(out_len))
    }
    fn decrypt(
        &self,
        scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        _label: &[u8],
    ) -> Result<Option<usize>, CryptoError> {
        if private_key.is_empty() {
            return Err(CryptoError::Internal);
        }
        let len = if scheme == tpm2::Alg::OAEP && ciphertext.len() > 32 {
            32
        } else {
            ciphertext.len()
        };
        if plaintext.len() < len {
            return Err(CryptoError::Internal);
        }
        plaintext[..len].copy_from_slice(&ciphertext[..len]);
        Ok(Some(len))
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
            _ => Err(CryptoError::Internal),
        }
    }
    fn rsa_import_private_key(
        &self,
        modulus: &[u8],
        prime_p: &[u8],
        exponent: u32,
        private_key_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let _ = modulus;
        let _ = exponent;
        if private_key_out.len() < prime_p.len() * 2 {
            return Err(CryptoError::Internal);
        }
        private_key_out[..prime_p.len()].copy_from_slice(prime_p);
        private_key_out[prime_p.len()..prime_p.len() * 2].copy_from_slice(prime_p);
        Ok(Some(prime_p.len() * 2))
    }
    fn rsa_private_key_to_prime_p(
        &self,
        private_key: &[u8],
        prime_p_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let half_len = private_key.len() / 2;
        if prime_p_out.len() < half_len {
            return Err(CryptoError::Internal);
        }
        prime_p_out[..half_len].copy_from_slice(&private_key[..half_len]);
        Ok(Some(half_len))
    }
}

impl CryptoProvider for StressTestCrypto {
    /// Its algorithms are fakes, which fail the known-answer self tests.
    const KNOWN_ANSWER_TESTS: bool = false;

    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        dest.fill(0xaa);
        Ok(())
    }
}

fn setup_tpm<'a>(
    crypto: &'a mut StressTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a mut FakeRng,
) -> TpmEngine<'a, StressTestCrypto, FakeStorage, FakeTimer, FakeRng> {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();
    tpm.state.nv_available = true;
    tpm.state.locality = 0;
    tpm.state.g_nv_ok = true;

    // Startup
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(&startup_request[..], &mut startup_response[..]);
    tpm
}

fn execute_tpm_command_with_auths<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_tpm_command_with_patched_parameters(tpm, cmd, auths, |_| {})
}

/// Like [`execute_tpm_command_with_auths`], but `patch` may modify the marshaled parameter area
/// before the command is sent (e.g. to send a value the `tpm2` types cannot represent).
fn execute_tpm_command_with_patched_parameters<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    cmd: &C,
    auths: &[TpmsAuthCommand],
    patch: impl FnOnce(&mut [u8]),
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
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

    for handle in cmd.handles().as_ref() {
        let handle_slice: &mut [u8; Handle::MAX_SIZE] = (&mut request_buf
            [offset..offset + Handle::MAX_SIZE])
            .try_into()
            .map_err(|_| ())
            .unwrap();
        offset += handle.marshal(handle_slice);
    }

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
    patch(&mut request_buf[offset..offset + cmd_len]);
    offset += cmd_len;

    // Fill in total Size
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size = tpm.execute_command_separate(&request_buf[..offset], &mut response_buf[..]);
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    // Skip the header (10), then read the response handles.
    let mut unmarshal_buf: &'static [u8] =
        std::vec::Vec::leak(response_buf[10..resp_size].to_vec());
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for handle in resp_handles.as_mut() {
        *handle = Handle::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    }
    if resp_tag == 0x8002 {
        // Skip the parameter size (4).
        unmarshal_buf = &unmarshal_buf[4..];
    }
    let resp = <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut unmarshal_buf)
        .map_err(|_| TpmRc::FAILURE.get())?;
    Ok(resp)
}

/// `TPM2_Duplicate` requires the DUP role, which always needs a policy session whose
/// `commandCode` is `TPM2_Duplicate` (C `IsPolicySessionRequired()` / `CheckPolicyAuthSession()`).
/// Installs such a session (its policyDigest equals the object's empty authPolicy) and returns the
/// authorization that uses it.
fn dup_policy_auth(global_state: &mut tpm2_impl::GlobalState) -> TpmsAuthCommand<'static> {
    const SESSION: u32 = 0x0300_0000;
    let _ = global_state.flush_session(SESSION);
    let mut session = common::make_test_session_state(
        SESSION,
        tpm2::TpmSe::Policy,
        TpmiAlgHash::Sha256,
        Default::default(),
        Default::default(),
        &[],
        None,
        Handle::RH_NULL,
    );
    session.command_code = u32::from(tpm2::TpmCc::Duplicate);
    global_state.add_session(session).unwrap();
    TpmsAuthCommand {
        session_handle: Handle(SESSION),
        nonce: Default::default(),
        session_attributes: tpm2::TpmaSession(0),
        hmac: Default::default(),
    }
}

#[test]
#[cfg_attr(
    feature = "reference-rng",
    ignore = "checks the default random sources; `reference-rng` draws from the reference DRBG"
)]
fn test_duplicate_import_load_roundtrip() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let mut tpm = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    // 1. Setup target object (the key to duplicate)
    let target_handle = 0x80000001;
    let target_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH, // fixedParent and fixedTPM are clear
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            // The modulus MSB must be set for a valid RSA public key (C `CryptValidateKeys()`).
            Tpm2bPublicKeyRsa::from_bytes(&[0x91; 256]).unwrap(),
        ),
    };
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target_public, &mut pub_buf);
    let handler = tpm2_impl::handler::CommandHandler::new(&mut tpm);
    let target_name = handler
        .compute_name(target_public.name_alg, &pub_buf[..pub_len])
        .unwrap();

    let target_obj = TransientObject {
        handle: target_handle,
        seed: {
            let mut s = [0u8; 64];
            s[..32].copy_from_slice(&[2u8; 32]);
            s
        },
        seed_len: 32,
        external: false,
        public_only: false,
        name: target_name,
        auth: (Tpm2bAuth::default()).into(),
        public: (target_public).into(),
        // The prime derived from this fake private key must have its MSB set (C
        // `CryptValidateKeys()`), or loading the imported object fails with TPM_RC_KEY_SIZE.
        private: [0xb3; 1536],
        private_len: 256,
        qualified_name: target_name,
        hierarchy: 0x40000001,
        st_clear: false,
    };
    tpm.state.transient_objects[0] = Some(target_obj.clone());

    // 2. Setup parent key P
    let parent_handle = 0x80000002;
    let parent_obj = TransientObject {
        handle: parent_handle,
        seed: {
            let mut s = [0u8; 64];
            s[..32].copy_from_slice(&[3u8; 32]);
            s
        },
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            // Restricted storage key attributes: DECRYPT | RESTRICTED | USER_WITH_AUTH
            object_attributes: TpmaObject::DECRYPT
                | TpmaObject::RESTRICTED
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                tpm2::TpmsRsaParms {
                    symmetric: Some(TpmtSymDefObject {
                        alg: AlgSym::Aes128,
                        mode: Some(TpmiAlgCipherMode::Cfb.into()),
                    }),
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::from_bytes(&[0xbb; 256]).unwrap(), // unique parent modulus
            ),
        })
        .into(),
        private: [0x55; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    tpm.state.transient_objects[1] = Some(parent_obj);

    // 3. Test Duplicate Edge Cases:
    // A. Invalid target object handle -> returns TpmRc::HANDLE.with(Position::handle(1))
    let dup_cmd = tpm2::commands::Duplicate {
        object_handle: Handle(target_handle),
        new_parent_handle: Handle(parent_handle),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    // An in-range transient handle that references no loaded object (with
    // `MAX_LOADED_OBJECTS = 3`, a handle beyond `TRANSIENT_LAST` would be `TPM_RC_VALUE`).
    let dup_cmd_bad = tpm2::commands::Duplicate {
        object_handle: Handle(0x80000000),
        ..dup_cmd
    };
    let res = execute_tpm_command_with_auths(&mut tpm, &dup_cmd_bad, &[]);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // B. Target object has fixedParent attribute -> returns TpmRc::ATTRIBUTES.with(Position::handle(1))
    tpm.state.transient_objects[0]
        .as_mut()
        .unwrap()
        .public
        .object_attributes
        .insert(TpmaObject::FIXED_PARENT);
    let dup_auth = dup_policy_auth(&mut tpm.state);
    let res = execute_tpm_command_with_auths(&mut tpm, &dup_cmd, &[dup_auth]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );
    // restore FIXED_PARENT
    tpm.state.transient_objects[0]
        .as_mut()
        .unwrap()
        .public
        .object_attributes
        .remove(TpmaObject::FIXED_PARENT);

    // C. New parent handle not found -> returns TpmRc::HANDLE.with(Position::handle(2))
    let dup_cmd_bad_parent = tpm2::commands::Duplicate {
        new_parent_handle: Handle(0x80000000),
        ..dup_cmd
    };
    let res = execute_tpm_command_with_auths(&mut tpm, &dup_cmd_bad_parent, &[]);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H1.get()));

    // D. New parent is not asymmetric -> returns TpmRc::TYPE.with(Position::handle(2))
    let bad_parent_obj = TransientObject {
        handle: 0x80000000,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgCipherMode::Cfb.into()),
                },
                Tpm2bDigest::default(),
            ),
        })
        .into(),
        private: [0; 1536],
        private_len: 16,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    tpm.state.transient_objects[2] = Some(bad_parent_obj);
    let dup_cmd_bad_type = tpm2::commands::Duplicate {
        new_parent_handle: Handle(0x80000000),
        ..dup_cmd
    };
    let dup_auth = dup_policy_auth(&mut tpm.state);
    let res = execute_tpm_command_with_auths(&mut tpm, &dup_cmd_bad_type, &[dup_auth]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(2)).get()));
    tpm.state.transient_objects[2] = None;

    // 4. Success Duplicate with inner wrapper (AES-128 CFB)
    let sym_alg = TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgCipherMode::Cfb.into()),
    };
    let dup_cmd_sym = tpm2::commands::Duplicate {
        object_handle: Handle(target_handle),
        new_parent_handle: Handle(parent_handle),
        encryption_key_in: Tpm2bData::default(), // TPM should generate one
        symmetric_alg: Some(sym_alg),
    };
    let dup_auth = dup_policy_auth(&mut tpm.state);
    let dup_resp = execute_tpm_command_with_auths(&mut tpm, &dup_cmd_sym, &[dup_auth])
        .expect("Duplicate failed");
    assert!(dup_resp.encryption_key_out.get_size() > 0);
    assert!(dup_resp.duplicate.get_size() > 0);
    assert!(dup_resp.out_sym_seed.get_size() > 0);

    // 5. Test Import Edge Cases:
    let object_public_2b = tpm2::Tpm2b(target_public);
    // A. Object attributes contains fixedTPM or fixedParent -> returns TpmRc::ATTRIBUTES.with(Position::parameter(2))
    let mut bad_target_public = target_public;
    bad_target_public
        .object_attributes
        .insert(TpmaObject::FIXED_TPM);
    let bad_object_public_2b = tpm2::Tpm2b(bad_target_public);
    let import_cmd_bad = tpm2::commands::Import {
        parent_handle: Handle(parent_handle),
        encryption_key: dup_resp.encryption_key_out,
        object_public: bad_object_public_2b,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: Some(sym_alg),
    };
    let res =
        execute_tpm_command_with_auths(&mut tpm, &import_cmd_bad, &[common::password_auth(b"")]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get())
    );

    // B. Encryption key size mismatch -> returns TpmRc::SIZE.with(Position::parameter(1))
    let import_cmd_bad_key = tpm2::commands::Import {
        parent_handle: Handle(parent_handle),
        encryption_key: Tpm2bData::from_bytes(&[0u8; 32]).unwrap(), // 32 bytes instead of 16
        object_public: object_public_2b,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: Some(sym_alg),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &import_cmd_bad_key,
        &[common::password_auth(b"")],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(1)).get())
    );

    // C. Outer integrity HMAC mismatch -> returns TpmRc::INTEGRITY
    let mut tampered_bytes = dup_resp.duplicate.get_buffer().to_vec();
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] ^= 1; // Tamper with the duplicate bytes
    let tampered_duplicate = Tpm2bPrivate::from_bytes(&tampered_bytes).unwrap();
    let import_cmd_bad_hmac = tpm2::commands::Import {
        parent_handle: Handle(parent_handle),
        encryption_key: dup_resp.encryption_key_out,
        object_public: object_public_2b,
        duplicate: tampered_duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: Some(sym_alg),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &import_cmd_bad_hmac,
        &[common::password_auth(b"")],
    );
    // C TPM2_Import: DuplicateToSensitive's TPM_RC_INTEGRITY is reported against `duplicate`
    // (RcSafeAddToResult(result, RC_Import_duplicate), +P3).
    assert_eq!(
        res.err(),
        Some(TpmRc::INTEGRITY.with(Position::parameter(3)).get())
    );

    // 6. Success Import
    let import_cmd = tpm2::commands::Import {
        parent_handle: Handle(parent_handle),
        encryption_key: dup_resp.encryption_key_out,
        object_public: object_public_2b,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: Some(sym_alg),
    };
    let import_resp =
        execute_tpm_command_with_auths(&mut tpm, &import_cmd, &[common::password_auth(b"")])
            .expect("Import failed");
    assert!(import_resp.out_private.get_size() > 0);

    // 7. Test Load Edge Cases:
    // A. Parent transient object not found -> returns TpmRc::HANDLE
    let load_cmd = tpm2::commands::Load {
        parent_handle: Handle(parent_handle),
        in_private: import_resp.out_private,
        in_public: object_public_2b,
    };
    let load_cmd_bad = tpm2::commands::Load {
        parent_handle: Handle(0x80000000),
        ..load_cmd
    };
    let res =
        execute_tpm_command_with_auths(&mut tpm, &load_cmd_bad, &[common::password_auth(b"")]);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // B. Parent key does not have DECRYPT and RESTRICTED -> returns TpmRc::TYPE.with(Position::handle(1))
    // Modify parent's attributes to remove RESTRICTED
    tpm.state.transient_objects[1]
        .as_mut()
        .unwrap()
        .public
        .object_attributes
        .remove(TpmaObject::RESTRICTED);
    let res = execute_tpm_command_with_auths(&mut tpm, &load_cmd, &[common::password_auth(b"")]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(1)).get()));
    // restore attributes
    tpm.state.transient_objects[1]
        .as_mut()
        .unwrap()
        .public
        .object_attributes
        .insert(TpmaObject::RESTRICTED);

    // C. Integrity HMAC verification failed for load -> returns TpmRc::INTEGRITY
    let mut tampered_bytes = import_resp.out_private.get_buffer().to_vec();
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] ^= 1; // Tamper with the private bytes
    let tampered_private = Tpm2bPrivate::from_bytes(&tampered_bytes).unwrap();
    let load_cmd_bad_hmac = tpm2::commands::Load {
        parent_handle: Handle(parent_handle),
        in_private: tampered_private,
        in_public: object_public_2b,
    };
    let res =
        execute_tpm_command_with_auths(&mut tpm, &load_cmd_bad_hmac, &[common::password_auth(b"")]);
    // C TPM2_Load: PrivateToSensitive's TPM_RC_INTEGRITY is reported against `inPrivate`
    // (RcSafeAddToResult(result, RC_Load_inPrivate), +P1).
    assert_eq!(
        res.err(),
        Some(TpmRc::INTEGRITY.with(Position::parameter(1)).get())
    );

    // D. Name alg is not implemented (SM3_256, which the `tpm2` types of this TPM cannot represent,
    // so it is patched into the marshaled `inPublic`).
    let load_cmd_bad_alg = tpm2::commands::Load {
        parent_handle: Handle(parent_handle),
        in_private: import_resp.out_private,
        in_public: tpm2::Tpm2b(target_public),
    };
    let res = execute_tpm_command_with_patched_parameters(
        &mut tpm,
        &load_cmd_bad_alg,
        &[common::password_auth(b"")],
        |params| {
            // inPrivate (UINT16 size and buffer), then inPublic: UINT16 size, type, nameAlg.
            let private_size = usize::from(u16::from_be_bytes([params[0], params[1]]));
            let name_alg = 2 + private_size + 2 + 2;
            params[name_alg..name_alg + 2].copy_from_slice(&tpm2::Alg::SM3_256.id().to_be_bytes());
        },
    );
    // SM3_256 is not implemented: TPMT_PUBLIC unmarshal of nameAlg fails with TPM_RC_HASH,
    // reported against inPublic (+P2).
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(Position::parameter(2)).get())
    );

    // 8. Success Load
    let load_resp =
        execute_tpm_command_with_auths(&mut tpm, &load_cmd, &[common::password_auth(b"")])
            .expect("Load failed");
    assert!(load_resp.name.get_size() > 0);

    // Verify loaded object is now in transient storage and matches target
    let loaded_obj = tpm
        .state
        .transient_objects
        .iter()
        .flatten()
        .find(|obj| obj.name == load_resp.name)
        .expect("Loaded object not found in transient objects");
    assert_eq!(loaded_obj.auth.get_buffer(), target_obj.auth.get_buffer());
    assert_eq!(
        &loaded_obj.private[..loaded_obj.private_len],
        &target_obj.private[..target_obj.private_len]
    );
}
