//! Shared helpers for the `objects` findings tests.
//!
//! Everything goes through the simulator's command interface (`testing::test_utils`); no
//! `tpm2-impl` internals are used.

#![allow(dead_code)]

pub use crate::test_utils::*;
pub use tpm2::commands::*;
pub use tpm2::errors::{Position, TpmRc};
pub use tpm2::*;
pub use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

/// Decodes a hex string (test fixtures only).
pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Response code of a format-one error at handle position `h`.
pub fn rc_h(rc: tpm2::errors::Fmt1, h: u8) -> u32 {
    rc.with(Position::handle(h)).get()
}

/// Response code of a format-one error at parameter position `p`.
pub fn rc_p(rc: tpm2::errors::Fmt1, p: u8) -> u32 {
    rc.with(Position::parameter(p)).get()
}

/// Response code of a format-one error without a position.
pub fn rc1(rc: tpm2::errors::Fmt1) -> u32 {
    rc.to_rc().get()
}

/// Response code of a format-zero error.
pub fn rc0(rc: TpmRc) -> u32 {
    rc.get()
}

/// Executes `cmd` (which carries its handles) with `sessions` empty password sessions (no
/// session area if 0). The response carries the response handles.
pub fn run<C: Command>(
    sim: &mut Simulator<'_>,
    cmd: &C,
    sessions: usize,
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_password_sessions(sim, cmd, sessions, &[])
}

/// Returns the response code of executing `cmd` (0 on success).
pub fn rc_of<C: Command>(sim: &mut Simulator<'_>, cmd: &C, sessions: usize) -> u32
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    match run(sim, cmd, sessions) {
        Ok(_) => 0,
        Err(rc) => rc,
    }
}

/// Owned copy of a public area (so that tests can keep it beyond a response buffer).
pub fn sensitive_create(auth: &[u8], data: &[u8]) -> Tpm2bSensitiveCreate<'static> {
    Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(leak_bytes(data)).unwrap(),
    })
}

/// RSA-2048 storage key template (restricted decrypt, AES-128-CFB).
pub fn rsa_storage_template(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgCipherMode::Cfb.into()),
                }),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// Fixed (fixedTPM | fixedParent) RSA-2048 storage key template.
pub fn fixed_rsa_storage() -> TpmtPublic<'static> {
    rsa_storage_template(
        TpmiAlgHash::Sha256,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    )
}

/// ECC P-256 storage key template (restricted decrypt, AES-128-CFB).
pub fn ecc_storage_template(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgCipherMode::Cfb.into()),
                }),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    }
}

/// ECC P-256 ECDSA signing key template.
pub fn ecc_sign_template(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    }
}

/// Sealed data object template (KEYEDHASH, sign = decrypt = CLEAR, NULL scheme).
pub fn sealed_template(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    }
}

/// SYMCIPHER AES-128-CFB decryption key template.
pub fn sym_template(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgCipherMode::Cfb.into()),
            },
            Tpm2bDigest::default(),
        ),
    }
}

/// Derivation parent template (restricted decrypt KEYEDHASH, XOR/SP800-108 with `hash`).
pub fn derivation_parent_template(hash: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
                hash_alg: hash,
                kdf: Some(TpmiAlgKdf::Kdf1Sp800_108),
            })),
            Tpm2bDigest::default(),
        ),
    }
}

/// `TPM2_CreatePrimary` under `hierarchy`; returns (handle, response).
pub fn create_primary(
    sim: &mut Simulator<'_>,
    hierarchy: Handle,
    template: TpmtPublic<'static>,
    data: &[u8],
) -> Result<(Handle, responses::CreatePrimary<'static>), u32> {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: sensitive_create(&[], data),
        in_public: Tpm2b(template),
        ..Default::default()
    };
    run(sim, &cmd, 1).map(|rsp| (rsp.object_handle, rsp))
}

/// Creates the default fixed RSA storage primary key under the owner hierarchy.
pub fn owner_srk(sim: &mut Simulator<'_>) -> Handle {
    create_primary(sim, Handle::RH_OWNER, fixed_rsa_storage(), &[])
        .expect("CreatePrimary")
        .0
}

/// `TPM2_Create` under `parent`.
pub fn create(
    sim: &mut Simulator<'_>,
    parent: Handle,
    template: TpmtPublic<'static>,
    auth: &[u8],
    data: &[u8],
) -> Result<responses::Create<'static>, u32> {
    let cmd = Create {
        parent_handle: parent,
        in_sensitive: sensitive_create(auth, data),
        in_public: Tpm2b(template),
        ..Default::default()
    };
    run(sim, &cmd, 1)
}

/// `TPM2_Load` under `parent`.
pub fn load(
    sim: &mut Simulator<'_>,
    parent: Handle,
    private: Tpm2bPrivate<'static>,
    public: Tpm2bPublic<'static>,
) -> Result<Handle, u32> {
    let cmd = Load {
        parent_handle: parent,
        in_private: private,
        in_public: public,
    };
    run(sim, &cmd, 1).map(|rsp| rsp.object_handle)
}

/// Creates and loads a child of `parent`; returns (handle, create response).
pub fn create_and_load(
    sim: &mut Simulator<'_>,
    parent: Handle,
    template: TpmtPublic<'static>,
    auth: &[u8],
    data: &[u8],
) -> (Handle, responses::Create<'static>) {
    let rsp = create(sim, parent, template, auth, data).expect("Create");
    let handle = load(sim, parent, rsp.out_private, rsp.out_public).expect("Load");
    (handle, rsp)
}

/// `TPM2_LoadExternal` of a public area (and optional sensitive area) into `hierarchy`.
pub fn load_external(
    sim: &mut Simulator<'_>,
    public: TpmtPublic<'static>,
    sensitive: Option<TpmtSensitive<'static>>,
    hierarchy: Handle,
) -> Result<Handle, u32> {
    let cmd = LoadExternal {
        in_private: sensitive.map(Tpm2b),
        in_public: Tpm2b(public),
        hierarchy,
    };
    run(sim, &cmd, 0).map(|rsp| rsp.object_handle)
}

/// `TPM2_HashSequenceStart` (SHA-256, empty auth); returns the sequence handle.
pub fn hash_sequence_start(sim: &mut Simulator<'_>) -> Handle {
    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    run(sim, &cmd, 0)
        .expect("HashSequenceStart")
        .sequence_handle
}

/// `TPM2_EvictControl` with an empty password for `auth`.
pub fn evict_control(
    sim: &mut Simulator<'_>,
    auth: Handle,
    object: Handle,
    persistent: Handle,
) -> Result<(), u32> {
    let cmd = EvictControl {
        auth,
        object_handle: object,
        persistent_handle: persistent,
    };
    run(sim, &cmd, 1).map(|_| ())
}

/// `TPM2_ReadPublic`.
pub fn read_public(
    sim: &mut Simulator<'_>,
    handle: Handle,
) -> Result<responses::ReadPublic<'static>, u32> {
    run(
        sim,
        &ReadPublic {
            object_handle: handle,
        },
        0,
    )
}

/// Digest of a policy consisting only of `TPM2_PolicyCommandCode(Duplicate)` (SHA-256).
pub fn dup_policy_digest() -> Tpm2bDigest<'static> {
    dup_policy_digest_for(TpmiAlgHash::Sha256)
}

/// Digest of a policy consisting only of `TPM2_PolicyCommandCode(Duplicate)` with `alg`.
pub fn dup_policy_digest_for(alg: TpmiAlgHash) -> Tpm2bDigest<'static> {
    let mut data = vec![0u8; alg.digest_size()];
    data.extend_from_slice(&u32::from(TpmCc::PolicyCommandCode).to_be_bytes());
    data.extend_from_slice(&u32::from(TpmCc::Duplicate).to_be_bytes());
    let digest = hash(alg, &[&data]);
    Tpm2bDigest::from_bytes(leak_bytes(&digest)).unwrap()
}

/// Duplicates `object` to TPM_RH_NULL (no wrappers) with an `alg` policy session.
pub fn duplicate_with_policy(
    sim: &mut Simulator<'_>,
    object: Handle,
    alg: TpmiAlgHash,
) -> responses::Duplicate<'static> {
    let sess = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();
    run(
        sim,
        &PolicyCommandCode {
            policy_session: sess.session_handle,
            code: TpmCc::Duplicate,
        },
        0,
    )
    .unwrap();
    execute_with_hmac_sessions(
        sim,
        &Duplicate {
            object_handle: object,
            new_parent_handle: Handle::RH_NULL,
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
        },
        &[],
        &mut [sess],
        &[&[]],
    )
    .expect("Duplicate")
}

/// Hashes the concatenation of `parts` with `alg` on the client.
pub fn hash(alg: TpmiAlgHash, parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, alg).unwrap();
    for p in parts {
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; 64];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

/// Starts an `alg` policy session that satisfies `dup_policy_digest_for(alg)`.
pub fn dup_policy_session_alg(sim: &mut Simulator<'_>, alg: TpmiAlgHash) -> ActiveSession {
    let sess = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();
    run(
        sim,
        &PolicyCommandCode {
            policy_session: sess.session_handle,
            code: TpmCc::Duplicate,
        },
        0,
    )
    .expect("PolicyCommandCode");
    sess
}

/// `TPM2_Duplicate` authorized with a SHA-256 `PolicyCommandCode(Duplicate)` policy session.
pub fn duplicate(
    sim: &mut Simulator<'_>,
    object: Handle,
    new_parent: Handle,
    symmetric: Option<TpmtSymDefObject>,
) -> Result<responses::Duplicate<'static>, u32> {
    duplicate_alg(sim, object, new_parent, symmetric, TpmiAlgHash::Sha256)
}

/// `TPM2_Duplicate` authorized with an `alg` `PolicyCommandCode(Duplicate)` policy session.
pub fn duplicate_alg(
    sim: &mut Simulator<'_>,
    object: Handle,
    new_parent: Handle,
    symmetric: Option<TpmtSymDefObject>,
    alg: TpmiAlgHash,
) -> Result<responses::Duplicate<'static>, u32> {
    let sess = dup_policy_session_alg(sim, alg);
    let cmd = Duplicate {
        object_handle: object,
        new_parent_handle: new_parent,
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: symmetric,
    };
    let rsp = execute_with_hmac_sessions(sim, &cmd, &[], &mut [sess.clone()], &[&[]]);
    let _ = flush_context(sim, sess.session_handle);
    rsp
}

/// `TPM2_Import` under `parent` (no inner wrapper).
pub fn import(
    sim: &mut Simulator<'_>,
    parent: Handle,
    public: Tpm2bPublic<'static>,
    duplicate: Tpm2bPrivate<'static>,
    seed: Tpm2bEncryptedSecret<'static>,
) -> Result<Tpm2bPrivate<'static>, u32> {
    let cmd = Import {
        parent_handle: parent,
        encryption_key: Tpm2bData::default(),
        object_public: public,
        duplicate,
        in_sym_seed: seed,
        symmetric_alg: None,
    };
    run(sim, &cmd, 1).map(|rsp| rsp.out_private)
}

/// `TPM2_Rewrap` (oldParent authorized with an empty password).
pub fn rewrap(
    sim: &mut Simulator<'_>,
    old_parent: Handle,
    new_parent: Handle,
    in_duplicate: Tpm2bPrivate<'static>,
    name: Tpm2bName<'static>,
    in_sym_seed: Tpm2bEncryptedSecret<'static>,
) -> Result<responses::Rewrap<'static>, u32> {
    let cmd = Rewrap {
        old_parent,
        new_parent,
        in_duplicate,
        name,
        in_sym_seed,
    };
    run(sim, &cmd, 1)
}

/// Returns the public area carried in a `TPM2B_PUBLIC`.
pub fn public_of(public: &Tpm2bPublic<'static>) -> TpmtPublic<'static> {
    public.0
}

/// Returns the ECC public point (x, y) of a public area.
pub fn ecc_point(public: &TpmtPublic<'static>) -> (Vec<u8>, Vec<u8>) {
    match &public.parms_and_id {
        PublicParmsAndId::Ecc(_, p) => (p.x.get_buffer().to_vec(), p.y.get_buffer().to_vec()),
        _ => panic!("not an ECC key"),
    }
}

/// Parses a plaintext (unwrapped) duplication blob: `UINT16 size || TPMT_SENSITIVE`.
pub fn parse_plain_duplicate(blob: &[u8]) -> TpmtSensitive<'static> {
    let size = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    assert_eq!(
        size + 2,
        blob.len(),
        "TPM2B_SENSITIVE size must cover the blob"
    );
    let mut slice: &'static [u8] = leak_bytes(&blob[2..]);
    let sensitive = TpmtSensitive::unmarshal(&mut slice).unwrap();
    assert!(slice.is_empty());
    sensitive
}

/// Digest of a policy consisting only of `TPM2_PolicyCommandCode(code)` with `alg`.
pub fn policy_command_code_digest(alg: TpmiAlgHash, code: TpmCc) -> Tpm2bDigest<'static> {
    let mut data = vec![0u8; alg.digest_size()];
    data.extend_from_slice(&u32::from(TpmCc::PolicyCommandCode).to_be_bytes());
    data.extend_from_slice(&u32::from(code).to_be_bytes());
    Tpm2bDigest::from_bytes(leak_bytes(&hash(alg, &[&data]))).unwrap()
}

/// Starts an `alg` policy session and applies `TPM2_PolicyCommandCode(code)`.
pub fn policy_command_code_session(
    sim: &mut Simulator<'_>,
    alg: TpmiAlgHash,
    code: TpmCc,
) -> ActiveSession {
    let sess = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();
    run(
        sim,
        &PolicyCommandCode {
            policy_session: sess.session_handle,
            code,
        },
        0,
    )
    .expect("PolicyCommandCode");
    sess
}
