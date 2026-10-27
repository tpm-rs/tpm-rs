//! The RSA private key in sensitive areas: under a fixedTPM parent, `TPM2_Create`,
//! `TPM2_CreateLoaded`, `TPM2_Import` and `TPM2_ObjectChangeAuth` store the full CRT form (P, Q,
//! dP, dQ, qInv: five times the prime size, TPM 2.0 Part 2 `TPM2B_PRIVATE_KEY_RSA`:
//! `RSA_PRIVATE_SIZE` "would only apply to keys that have *fixedTPM* parents"), every other
//! sensitive area holds only the prime; `TPM2_Load` accepts the CRT form only under a fixedTPM
//! parent, `TPM2_LoadExternal` and `TPM2_Import` take only the prime.

use crate::_common::{
    RSA_N, RSA_P, RSA_Q, context_load, context_save, create, create_and_load,
    dup_policy_digest_for, duplicate_with_policy, ecc_storage_template_with, evict, exec_command,
    import, leak_bytes, load, load_external, make_template, marshal_to_vec, owner_srk,
    parse_plain_duplicate, rc_p, run, sign, verify_signature,
};
use testing::tpm::Tpm;
#[allow(deprecated)] // `TPM2_CreateLoaded` is deprecated upstream.
use tpm2::commands::{CreateLoaded, ObjectChangeAuth};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bPrivate,
    Tpm2bPrivateKeyRsa, Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject,
    TpmiAlgHash, TpmiRsaKeyBits, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic, TpmtRsaScheme,
    TpmtSensitive, TpmuSensitiveComposite,
};

/// The digest every test signs.
const DIGEST: &[u8; 32] = &[0x5a; 32];

/// An RSASSA-SHA256 signing key template of `key_bits` bits with `attrs` (plus
/// sensitiveDataOrigin and userWithAuth, and the `PolicyCommandCode(Duplicate)` policy).
fn rsa_sign_template(key_bits: u16, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: dup_policy_digest_for(TpmiAlgHash::Sha256),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(key_bits),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// A non-fixedTPM signing key template (fixedTPM and fixedParent CLEAR, so that it may be
/// created under any parent and duplicated).
fn duplicable_rsa_sign_template(key_bits: u16) -> TpmtPublic<'static> {
    rsa_sign_template(key_bits, TpmaObject::empty())
}

/// The public area of the fixed test key [`RSA_N`] as a duplicable signing key.
fn fixed_key_public() -> TpmtPublic<'static> {
    let mut public = duplicable_rsa_sign_template(2048);
    public.object_attributes = TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH;
    if let PublicParmsAndId::Rsa(_, unique) = &mut public.parms_and_id {
        *unique = Tpm2bPublicKeyRsa::from_bytes(RSA_N).unwrap();
    }
    public
}

/// A plaintext (unwrapped) duplicate of the fixed test key with sensitive value `value`.
fn plain_duplicate(value: &'static [u8]) -> Tpm2bPrivate<'static> {
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(value).unwrap()),
    };
    let marshaled = marshal_to_vec(&sensitive);
    let mut blob = (marshaled.len() as u16).to_be_bytes().to_vec();
    blob.extend(marshaled);
    Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap()
}

/// A storage key with fixedTPM CLEAR (and the same nameAlg and symmetric key size as
/// [`owner_srk`], so that private areas under both parents have the same overhead).
fn non_fixed_tpm_parent(sim: &mut Tpm, srk: Handle) -> Handle {
    create_and_load(
        sim,
        srk,
        ecc_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    )
    .0
}

/// Signs [`DIGEST`] with `key` (empty authValue unless `auth`) and verifies the signature with
/// the key's public area, which shows that the private key matches the modulus.
fn assert_signs(sim: &mut Tpm, key: Handle, auth: &[u8]) {
    let signature = sign(sim, key, auth, DIGEST, None).expect("Sign");
    verify_signature(sim, key, DIGEST, signature).expect("VerifySignature");
}

/// `TPM2_Create` under a fixedTPM parent returns the CRT form: the private area is four primes
/// longer than that of the same key under a parent that is not fixedTPM, and it loads and signs.
#[test]
fn create_under_fixed_tpm_parent_stores_crt_form() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let other = non_fixed_tpm_parent(&mut sim, srk);
    for key_bits in [1024u16, 2048] {
        let prime_size = usize::from(key_bits) / 16;
        let template = duplicable_rsa_sign_template(key_bits);
        let crt = create(&mut sim, srk, template, &[], &[]).expect("Create (fixedTPM)");
        let prime = create(&mut sim, other, template, &[], &[]).expect("Create (non-fixedTPM)");
        assert_eq!(
            usize::from(crt.out_private.get_size()),
            usize::from(prime.out_private.get_size()) + 4 * prime_size,
            "{key_bits}-bit key"
        );
        for (parent, rsp) in [(srk, crt), (other, prime)] {
            let key = load(&mut sim, parent, rsp.out_private, rsp.out_public).expect("Load");
            assert_signs(&mut sim, key, &[]);
            run(
                &mut sim,
                &tpm2::commands::FlushContext { flush_handle: key },
                0,
            )
            .unwrap();
        }
    }
}

/// A fixedTPM key (whose parent is always fixedTPM) also gets the CRT form.
#[test]
fn create_fixed_tpm_key_stores_crt_form() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let fixed = rsa_sign_template(2048, TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT);
    let crt = create(&mut sim, srk, fixed, &[], &[]).expect("Create (fixedTPM key)");
    let other = create(&mut sim, srk, duplicable_rsa_sign_template(2048), &[], &[])
        .expect("Create (duplicable key)");
    assert_eq!(crt.out_private.get_size(), other.out_private.get_size());
    let key = load(&mut sim, srk, crt.out_private, crt.out_public).expect("Load");
    assert_signs(&mut sim, key, &[]);
}

/// `TPM2_CreateLoaded` of an ordinary object under a fixedTPM parent returns the same CRT-form
/// private area size as `TPM2_Create`, and the private area loads again.
#[test]
#[allow(deprecated)] // `TPM2_CreateLoaded` is deprecated upstream.
fn create_loaded_under_fixed_tpm_parent_stores_crt_form() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let template = duplicable_rsa_sign_template(2048);
    let created = create(&mut sim, srk, template, &[], &[]).expect("Create");
    let rsp = exec_command(
        &mut sim,
        &CreateLoaded {
            parent_handle: srk,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: make_template(&template),
        },
        &[crate::_common::pw()],
    )
    .expect("CreateLoaded");
    assert_eq!(rsp.out_private.get_size(), created.out_private.get_size());
    assert_signs(&mut sim, rsp.object_handle, &[]);
    let again = load(&mut sim, srk, rsp.out_private, rsp.out_public).expect("Load");
    assert_signs(&mut sim, again, &[]);
}

/// `TPM2_Import` under a fixedTPM parent validates the prime and returns the CRT form; under a
/// parent that is not fixedTPM, the prime is passed through. Either prime of the key may be
/// given, and every private area loads and signs.
#[test]
fn import_under_fixed_tpm_parent_expands_to_crt_form() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let other = non_fixed_tpm_parent(&mut sim, srk);
    let public = fixed_key_public();
    for prime in [RSA_P, RSA_Q] {
        let crt = import(
            &mut sim,
            srk,
            Tpm2b(public),
            plain_duplicate(prime),
            Tpm2bEncryptedSecret::default(),
        )
        .expect("Import (fixedTPM)");
        let plain = import(
            &mut sim,
            other,
            Tpm2b(public),
            plain_duplicate(prime),
            Tpm2bEncryptedSecret::default(),
        )
        .expect("Import (non-fixedTPM)");
        assert_eq!(
            usize::from(crt.get_size()),
            usize::from(plain.get_size()) + 4 * prime.len()
        );
        for (parent, private) in [(srk, crt), (other, plain)] {
            let key = load(&mut sim, parent, private, Tpm2b(public)).expect("Load");
            assert_signs(&mut sim, key, &[]);
            run(
                &mut sim,
                &tpm2::commands::FlushContext { flush_handle: key },
                0,
            )
            .unwrap();
        }
    }
}

/// The CRT form of the fixed test key: the sensitive value of the right size that a duplicate
/// cannot carry.
fn crt_sized_value() -> &'static [u8] {
    let mut value = RSA_P.to_vec();
    value.extend_from_slice(RSA_Q);
    value.resize(5 * RSA_P.len(), 0x11);
    leak_bytes(&value)
}

/// A CRT-sized sensitive value is rejected by `TPM2_Import` under a fixedTPM parent (validated
/// as if loaded: `TPM_RC_KEY_SIZE` for `duplicate`); under a parent that is not fixedTPM it is
/// not validated on import, and `TPM2_Load` rejects it with `TPM_RC_KEY_SIZE` for `inPrivate`.
#[test]
fn import_rejects_crt_sized_sensitive_value() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let other = non_fixed_tpm_parent(&mut sim, srk);
    let public = fixed_key_public();
    assert_eq!(
        import(
            &mut sim,
            srk,
            Tpm2b(public),
            plain_duplicate(crt_sized_value()),
            Tpm2bEncryptedSecret::default(),
        ),
        Err(rc_p(TpmRc::KEY_SIZE, 3))
    );
    let private = import(
        &mut sim,
        other,
        Tpm2b(public),
        plain_duplicate(crt_sized_value()),
        Tpm2bEncryptedSecret::default(),
    )
    .expect("Import (non-fixedTPM)");
    assert_eq!(
        load(&mut sim, other, private, Tpm2b(public)),
        Err(rc_p(TpmRc::KEY_SIZE, 1))
    );
}

/// `TPM2_LoadExternal` takes only the prime: a CRT-sized sensitive value is `TPM_RC_KEY_SIZE`
/// for `inPrivate`, the prime loads.
#[test]
fn load_external_rejects_crt_sized_sensitive_value() {
    let mut sim = Tpm::new();
    let public = fixed_key_public();
    let sensitive = |value: &'static [u8]| TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(value).unwrap()),
    };
    assert_eq!(
        load_external(
            &mut sim,
            public,
            Some(sensitive(crt_sized_value())),
            Handle::RH_NULL
        ),
        Err(rc_p(TpmRc::KEY_SIZE, 1))
    );
    let key = load_external(&mut sim, public, Some(sensitive(RSA_P)), Handle::RH_NULL)
        .expect("LoadExternal");
    assert_signs(&mut sim, key, &[]);
}

/// `TPM2_ObjectChangeAuth` returns the CRT form under a fixedTPM parent and the prime under any
/// other parent; the new private areas load with the new authValue.
#[test]
fn object_change_auth_follows_the_parent() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let other = non_fixed_tpm_parent(&mut sim, srk);
    let template = duplicable_rsa_sign_template(2048);
    let mut sizes = Vec::new();
    for parent in [srk, other] {
        let (key, created) = create_and_load(&mut sim, parent, template, &[], &[]);
        let rsp = exec_command(
            &mut sim,
            &ObjectChangeAuth {
                object_handle: key,
                parent_handle: parent,
                new_auth: Tpm2bAuth::from_bytes(b"new").unwrap(),
            },
            &[crate::_common::pw()],
        )
        .expect("ObjectChangeAuth");
        assert_eq!(rsp.out_private.get_size(), created.out_private.get_size());
        sizes.push(rsp.out_private.get_size());
        run(
            &mut sim,
            &tpm2::commands::FlushContext { flush_handle: key },
            0,
        )
        .unwrap();
        let changed = load(&mut sim, parent, rsp.out_private, created.out_public).expect("Load");
        assert_signs(&mut sim, changed, b"new");
        run(
            &mut sim,
            &tpm2::commands::FlushContext {
                flush_handle: changed,
            },
            0,
        )
        .unwrap();
    }
    assert_eq!(usize::from(sizes[0]), usize::from(sizes[1]) + 4 * 128);
}

/// `TPM2_Duplicate` of a key whose private area under its fixedTPM parent is the CRT form
/// exports only the prime, a factor of the modulus.
#[test]
fn duplicate_exports_only_the_prime() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let (key, created) =
        create_and_load(&mut sim, srk, duplicable_rsa_sign_template(2048), &[], &[]);
    let dup = duplicate_with_policy(&mut sim, key, TpmiAlgHash::Sha256);
    let sensitive = parse_plain_duplicate(dup.duplicate.get_buffer());
    let TpmuSensitiveComposite::Rsa(prime) = sensitive.sensitive else {
        panic!("not an RSA sensitive area");
    };
    assert_eq!(prime.get_size(), 128);
    let PublicParmsAndId::Rsa(_, modulus) = created.out_public.0.parms_and_id else {
        unreachable!()
    };
    let n = rsa::BigUint::from_bytes_be(modulus.get_buffer());
    let p = rsa::BigUint::from_bytes_be(prime.get_buffer());
    assert_eq!(
        &n % &p,
        rsa::BigUint::from(0u32),
        "the prime does not divide the modulus"
    );
}

/// A key loaded from a CRT-form private area keeps working after `TPM2_ContextSave` /
/// `TPM2_ContextLoad` and after `TPM2_EvictControl` makes it persistent.
#[test]
fn crt_form_key_survives_context_save_and_persistence() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let created =
        create(&mut sim, srk, duplicable_rsa_sign_template(2048), &[], &[]).expect("Create");
    let public: Tpm2bPublic<'static> = created.out_public;
    let key = load(&mut sim, srk, created.out_private, public).expect("Load");
    let context = context_save(&mut sim, key);
    run(
        &mut sim,
        &tpm2::commands::FlushContext { flush_handle: key },
        0,
    )
    .unwrap();
    let restored = context_load(&mut sim, context).expect("ContextLoad");
    assert_signs(&mut sim, restored, &[]);
    evict(&mut sim, Handle::RH_OWNER, restored, 0x8100_0123);
    assert_signs(&mut sim, Handle(0x8100_0123), &[]);
    evict(&mut sim, Handle::RH_OWNER, Handle(0x8100_0123), 0x8100_0123);
}
