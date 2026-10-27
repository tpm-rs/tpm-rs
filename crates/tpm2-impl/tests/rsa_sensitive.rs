//! White-box tests of the RSA sensitive value in private areas (`handler::rsa_sensitive`): the
//! CRT form that `TPM2_Create` stores under a fixedTPM parent is decrypted with the parent's
//! internal seed and checked value by value, and private areas that only the TPM itself could
//! produce (the prime-only form, corrupted CRT values, wrong sizes) are forged with that seed to
//! exercise `TPM2_Load` under a fixedTPM parent.

mod common;

use common::{
    FakeRng, FakeStorage, FakeTimer, RealCryptoEngine, TestCryptoProvider, execute_command,
    marshal_to_slice, password_auth, setup_real_crypto_tpm,
};
use num_bigint::BigUint;
#[allow(deprecated)] // `TPM2_Sign` is deprecated upstream.
use tpm2::commands::{Create, CreatePrimary, FlushContext, Load, Sign};
use tpm2::crypto::kdf::kdfa_bits;
use tpm2::crypto::{HmacStream, ModeIv, SymmetricKey};
use tpm2::errors::TpmRc;
use tpm2::{
    AlgSym, Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bDigest, Tpm2bPrivate,
    Tpm2bPrivateKeyRsa, Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmEccCurve,
    TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsEccParms, TpmsRsaParms, TpmsSensitiveCreate,
    TpmtPublic, TpmtRsaScheme, TpmtSensitive, TpmtSymDefObject, TpmtTkHashcheck,
    TpmuSensitiveComposite, Unmarshal,
};

macro_rules! setup {
    ($tpm:ident) => {
        let mut crypto = TestCryptoProvider;
        let mut storage = FakeStorage::default();
        let mut timer = FakeTimer;
        let mut rng = FakeRng::new();
        let mut $tpm = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);
    };
}

/// A fixedTPM NIST P-256 storage primary key (SHA-256, AES-128-CFB) under the owner hierarchy.
fn storage_primary(tpm: &mut RealCryptoEngine<'_>) -> Handle {
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::RESTRICTED
                | TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                    scheme: None,
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                tpm2::TpmsEccPoint::default(),
            ),
        }),
        ..Default::default()
    };
    execute_command(tpm, &create, &[password_auth(b"")])
        .expect("CreatePrimary")
        .object_handle
}

/// The `seedValue` of the loaded object `handle` (white-box).
fn seed_of(tpm: &RealCryptoEngine<'_>, handle: Handle) -> Vec<u8> {
    tpm.state
        .transient_objects
        .iter()
        .flatten()
        .find(|o| o.handle == handle.0)
        .expect("loaded object")
        .seed_bytes()
        .to_vec()
}

/// Creates an RSA-1024 RSASSA-SHA256 signing key (fixedTPM and fixedParent CLEAR) under
/// `parent`.
fn create_rsa_key(
    tpm: &mut RealCryptoEngine<'_>,
    parent: Handle,
) -> (Tpm2bPrivate<'static>, Tpm2bPublic<'static>) {
    let cmd = Create {
        parent_handle: parent,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits(1024),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        }),
        ..Default::default()
    };
    let rsp = execute_command(tpm, &cmd, &[password_auth(b"")]).expect("Create");
    (rsp.out_private, rsp.out_public)
}

/// The Name (`nameAlg || H(public)`, SHA-256) and the modulus of `public`.
fn name_and_modulus(public: &Tpm2bPublic<'_>) -> (Vec<u8>, Vec<u8>) {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&public.0, &mut buf);
    let mut digest = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash(
        &TestCryptoProvider,
        TpmiAlgHash::Sha256,
        &buf[..len],
        &mut digest,
    )
    .unwrap();
    let mut name = vec![0x00, 0x0b];
    name.extend_from_slice(digest.digest());
    let PublicParmsAndId::Rsa(_, modulus) = &public.0.parms_and_id else {
        panic!("not an RSA key");
    };
    (name, modulus.get_buffer().to_vec())
}

/// The AES-128 key that protects the children of a SHA-256 parent with `seed` (`KDFa(STORAGE)`).
fn storage_key(seed: &[u8], name: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    kdfa_bits(
        &TestCryptoProvider,
        TpmiAlgHash::Sha256,
        seed,
        b"STORAGE",
        name,
        &[],
        128,
        &mut key,
    )
    .unwrap();
    key
}

/// The outer HMAC (`KDFa(INTEGRITY)`) over `iv_and_enc || name`.
fn integrity(seed: &[u8], iv_and_enc: &[u8], name: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 32];
    kdfa_bits(
        &TestCryptoProvider,
        TpmiAlgHash::Sha256,
        seed,
        b"INTEGRITY",
        &[],
        &[],
        256,
        &mut key,
    )
    .unwrap();
    let mut hmac = HmacStream::new(&TestCryptoProvider, TpmiAlgHash::Sha256, &key).unwrap();
    hmac.update(iv_and_enc).unwrap();
    hmac.update(name).unwrap();
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    hmac.finalize(&mut out).unwrap().digest().to_vec()
}

/// Decrypts the private area `private` of the object `name` protected by a parent with `seed`
/// and returns its sensitive area (marshaled `TPMT_SENSITIVE`).
fn unwrap_private(seed: &[u8], name: &[u8], private: &[u8]) -> Vec<u8> {
    assert_eq!(&private[..2], &[0, 32]);
    let iv_and_enc = &private[34..];
    assert_eq!(integrity(seed, iv_and_enc, name), &private[2..34]);
    assert_eq!(&iv_and_enc[..2], &[0, 16]);
    let mut iv: [u8; 16] = iv_and_enc[2..18].try_into().unwrap();
    let mut plain = iv_and_enc[18..].to_vec();
    let key = storage_key(seed, name);
    tpm2::crypto::decrypt(
        &TestCryptoProvider,
        SymmetricKey::new(AlgSym::Aes128, &key).unwrap(),
        ModeIv::Cfb(&mut iv),
        &mut plain,
    )
    .unwrap();
    let size = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
    assert_eq!(size + 2, plain.len());
    plain[2..].to_vec()
}

/// Encrypts the marshaled `TPMT_SENSITIVE` `sensitive` into a private area of the object `name`
/// under a parent with `seed`.
fn wrap_private(seed: &[u8], name: &[u8], sensitive: &[u8]) -> Tpm2bPrivate<'static> {
    let mut plain = (sensitive.len() as u16).to_be_bytes().to_vec();
    plain.extend_from_slice(sensitive);
    let mut iv = [0x42u8; 16];
    let key = storage_key(seed, name);
    tpm2::crypto::encrypt(
        &TestCryptoProvider,
        SymmetricKey::new(AlgSym::Aes128, &key).unwrap(),
        ModeIv::Cfb(&mut iv),
        &mut plain,
    )
    .unwrap();
    let mut iv_and_enc = vec![0, 16];
    iv_and_enc.extend_from_slice(&[0x42u8; 16]);
    iv_and_enc.extend_from_slice(&plain);
    let mut private = vec![0, 32];
    private.extend(integrity(seed, &iv_and_enc, name));
    private.extend(iv_and_enc);
    Tpm2bPrivate::from_bytes(Vec::leak(private)).unwrap()
}

/// `sensitive` (a marshaled `TPMT_SENSITIVE` of an RSA key) with the RSA value replaced by
/// `value`.
fn with_rsa_value(sensitive: &[u8], value: &[u8]) -> Vec<u8> {
    let mut slice = sensitive;
    let mut parsed = TpmtSensitive::unmarshal(&mut slice).unwrap();
    parsed.sensitive = TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(value).unwrap());
    let mut buf = [0u8; 2048];
    let len = marshal_to_slice(&parsed, &mut buf);
    buf[..len].to_vec()
}

/// The RSA value of a marshaled `TPMT_SENSITIVE`.
fn rsa_value(sensitive: &[u8]) -> Vec<u8> {
    let mut slice = sensitive;
    match TpmtSensitive::unmarshal(&mut slice).unwrap().sensitive {
        TpmuSensitiveComposite::Rsa(value) => value.get_buffer().to_vec(),
        _ => panic!("not an RSA sensitive area"),
    }
}

fn load(
    tpm: &mut RealCryptoEngine<'_>,
    parent: Handle,
    private: Tpm2bPrivate<'static>,
    public: Tpm2bPublic<'static>,
) -> Result<Handle, u32> {
    execute_command(
        tpm,
        &Load {
            parent_handle: parent,
            in_private: private,
            in_public: public,
        },
        &[password_auth(b"")],
    )
    .map(|rsp| rsp.object_handle)
}

#[allow(deprecated)] // `TPM2_Sign` is deprecated upstream.
fn sign_and_flush(tpm: &mut RealCryptoEngine<'_>, key: Handle) {
    let cmd = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(&[0x33; 32]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::new(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    execute_command(tpm, &cmd, &[password_auth(b"")]).expect("Sign");
    execute_command(tpm, &FlushContext { flush_handle: key }, &[]).expect("FlushContext");
}

/// `TPM2_Create` under a fixedTPM parent stores `P | Q | dP | dQ | qInv` (each the size of a
/// prime) where `P` is a factor of the modulus, `Q = N / P`, and `dP`, `dQ`, `qInv` are computed
/// with the larger prime as "p" (the reference's `TpmRsaUtil_PackExponent()` layout).
#[test]
fn create_stores_the_reference_crt_layout() {
    setup!(tpm);
    let parent = storage_primary(&mut tpm);
    let seed = seed_of(&tpm, parent);
    for _ in 0..4 {
        let (private, public) = create_rsa_key(&mut tpm, parent);
        let (name, modulus) = name_and_modulus(&public);
        let value = rsa_value(&unwrap_private(&seed, &name, private.get_buffer()));
        assert_eq!(value.len(), 5 * 64);
        let v: Vec<BigUint> = value.chunks(64).map(BigUint::from_bytes_be).collect();
        let (p, q) = (&v[0], &v[1]);
        assert_eq!(p * q, BigUint::from_bytes_be(&modulus));
        let (max, min) = if p > q { (p, q) } else { (q, p) };
        let one = BigUint::from(1u32);
        let e = BigUint::from(65537u32);
        assert_eq!((&e * &v[2]) % (max - &one), one, "dP");
        assert_eq!((&e * &v[3]) % (min - &one), one, "dQ");
        assert_eq!((min * &v[4]) % max, one, "qInv");
    }
}

/// `TPM2_Load` under a fixedTPM parent accepts the prime-only form (which this TPM no longer
/// writes there), and the CRT form only if every value belongs to the key rebuilt from the
/// prime and the size is five primes; otherwise `TPM_RC_BINDING`.
#[test]
fn load_under_fixed_tpm_parent_checks_the_stored_form() {
    setup!(tpm);
    let parent = storage_primary(&mut tpm);
    let seed = seed_of(&tpm, parent);
    let (private, public) = create_rsa_key(&mut tpm, parent);
    let (name, _) = name_and_modulus(&public);
    let sensitive = unwrap_private(&seed, &name, private.get_buffer());
    let value = rsa_value(&sensitive);

    // The unmodified CRT form and its re-wrapped copy load and sign.
    let key = load(&mut tpm, parent, private, public).expect("Load (CRT form)");
    sign_and_flush(&mut tpm, key);
    let rewrapped = wrap_private(&seed, &name, &sensitive);
    let key = load(&mut tpm, parent, rewrapped, public).expect("Load (re-wrapped)");
    sign_and_flush(&mut tpm, key);

    // The prime-only form loads and signs.
    let prime_only = wrap_private(&seed, &name, &with_rsa_value(&sensitive, &value[..64]));
    let key = load(&mut tpm, parent, prime_only, public).expect("Load (prime only)");
    sign_and_flush(&mut tpm, key);

    // Each corrupted CRT value, and the other sizes, are binding errors.
    let binding = TpmRc::BINDING.to_rc().get();
    for slot in 1..5 {
        let mut corrupted = value.clone();
        corrupted[slot * 64 + 63] ^= 1;
        let private = wrap_private(&seed, &name, &with_rsa_value(&sensitive, &corrupted));
        assert_eq!(
            load(&mut tpm, parent, private, public),
            Err(binding),
            "slot {slot}"
        );
    }
    for len in [4 * 64, 5 * 64 - 1, 5 * 64 + 5, 2 * 64] {
        let mut resized = value.clone();
        resized.resize(len, 0);
        let private = wrap_private(&seed, &name, &with_rsa_value(&sensitive, &resized));
        assert_eq!(
            load(&mut tpm, parent, private, public),
            Err(binding),
            "{len} bytes"
        );
    }
}
