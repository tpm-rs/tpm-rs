//! Client-side crypto fixtures for the `objects` findings tests: fixed ECC points and a
//! `TPM2B_PRIVATE` round trip under a parent whose protection seed is known to the client.

use super::helpers::*;

/// Order `n` of NIST P-256.
pub fn p256_order() -> Vec<u8> {
    unhex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
}

/// Generator `G` of NIST P-256 (the public key of the private scalar `d = 1`).
pub fn p256_generator() -> TpmsEccPoint<'static> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::from_bytes(leak_bytes(&unhex(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        )))
        .unwrap(),
        y: Tpm2bEccParameter::from_bytes(leak_bytes(&unhex(
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        )))
        .unwrap(),
    }
}

/// `[379]G` on NIST P-256, whose x coordinate starts with a zero byte. The point is returned
/// with that leading zero stripped (31-byte x), as TPM 2.0 encodings allow.
pub fn p256_point_with_stripped_x() -> TpmsEccPoint<'static> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::from_bytes(leak_bytes(&unhex(
            "5543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00a",
        )))
        .unwrap(),
        y: Tpm2bEccParameter::from_bytes(leak_bytes(&unhex(
            "bb4c85a3d8ea29efaafa24406912dd84d5b14dc32bf656ef6c6bd58a5d943f92",
        )))
        .unwrap(),
    }
}

/// Imports (plaintext duplicate) and loads under `srk` an ECC P-256 storage key with private
/// scalar 379 whose public point is [`p256_point_with_stripped_x`] (31-byte x).
pub fn load_stripped_ecc_storage_key(sim: &mut Simulator<'_>, srk: Handle) -> Handle {
    let mut public = ecc_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    if let PublicParmsAndId::Ecc(_, point) = &mut public.parms_and_id {
        *point = p256_point_with_stripped_x();
    }
    let mut d = [0u8; 32];
    d[30..].copy_from_slice(&379u16.to_be_bytes());
    import_and_load(sim, srk, public, &d, &[0x11; 32])
}

/// Imports a plaintext duplicate of an ECC key (`d`, `seed`) under `srk` and loads it.
fn import_and_load(
    sim: &mut Simulator<'_>,
    srk: Handle,
    public: TpmtPublic<'static>,
    d: &[u8],
    seed: &[u8],
) -> Handle {
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(leak_bytes(seed)).unwrap(),
        sensitive: TpmuSensitiveComposite::Ecc(
            Tpm2bEccParameter::from_bytes(leak_bytes(d)).unwrap(),
        ),
    };
    let sens = marshal_to_vec(&sensitive);
    let mut blob = (sens.len() as u16).to_be_bytes().to_vec();
    blob.extend(sens);
    let private = import(
        sim,
        srk,
        Tpm2b(public),
        Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
        Tpm2bEncryptedSecret::default(),
    )
    .expect("Import");
    load(sim, srk, private, Tpm2b(public)).expect("Load of the imported key")
}

/// Computes `nameAlg || H(marshal(public))` (SHA-256).
fn object_name(public: &TpmtPublic<'_>) -> Vec<u8> {
    let mut name = vec![0x00, 0x0b];
    name.extend(hash(TpmiAlgHash::Sha256, &[&marshal_to_vec(public)]));
    name
}

/// `KDFa(SHA-256, key, label, context, NULL, bits)`.
fn kdfa256(key: &[u8], label: &[u8], context: &[u8], bits: u32) -> Vec<u8> {
    let mut out = vec![0u8; bits.div_ceil(8) as usize];
    kdfa_by_alg(
        CLIENT_CRYPTO,
        TpmiAlgHash::Sha256,
        key,
        label,
        context,
        &[],
        bits,
        &mut out,
    );
    out
}

/// HMAC-SHA-256 of the concatenation of `parts`.
fn hmac256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HmacCtx::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256, key).unwrap();
    for p in parts {
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; 64];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

/// AES-128-CFB encryption in place with a zero IV (duplication inner wrapper).
pub fn aes128_cfb_zero_iv_encrypt(key: &[u8], data: &mut [u8]) {
    aes_cfb(key, &[0u8; 16], data, true);
}

/// AES-128-CFB in place.
fn aes_cfb(key: &[u8], iv: &[u8; 16], data: &mut [u8], encrypt: bool) {
    let alg = TpmtSymDefObject::aes_cfb(128).unwrap();
    let mut iv = *iv;
    if encrypt {
        tpm2::crypto::encrypt(CLIENT_CRYPTO, alg, key, &mut iv, data).unwrap();
    } else {
        tpm2::crypto::decrypt(CLIENT_CRYPTO, alg, key, &mut iv, data).unwrap();
    }
}

/// Imports an ECC P-256 storage key with private scalar 1 and protection seed `seed` under
/// `srk` (plaintext duplicate) and loads it; returns its handle.
fn load_known_seed_parent(sim: &mut Simulator<'_>, srk: Handle, seed: &[u8]) -> Handle {
    let mut public = ecc_storage_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    if let PublicParmsAndId::Ecc(_, point) = &mut public.parms_and_id {
        *point = p256_generator();
    }
    let mut d = [0u8; 32];
    d[31] = 1;
    import_and_load(sim, srk, public, &d, seed)
}

/// Checks the `TPM2B_PRIVATE` format of ordinary objects in both directions:
/// - `TPM2_Create` output decrypts (with the known parent seed) to `UINT16 size ||
///   TPMT_SENSITIVE` with the authValue padded to the nameAlg digest size;
/// - a C-format blob built by the client loads with `TPM2_Load` and unseals.
pub fn private_area_format_round_trip() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let parent_seed = [0xa5u8; 32];
    let parent = load_known_seed_parent(&mut sim, srk, &parent_seed);
    let integrity_key = kdfa256(&parent_seed, b"INTEGRITY", &[], 256);

    // TPM -> client.
    let created = create(
        &mut sim,
        parent,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        b"ab",
        b"hello",
    )
    .unwrap();
    let name = object_name(&created.out_public.0);
    let blob = created.out_private.get_buffer();
    assert_eq!(u16::from_be_bytes([blob[0], blob[1]]), 32);
    let integrity = &blob[2..34];
    assert_eq!(u16::from_be_bytes([blob[34], blob[35]]), 16);
    let iv: [u8; 16] = blob[36..52].try_into().unwrap();
    assert_eq!(
        hmac256(&integrity_key, &[&blob[34..], &name]),
        integrity.to_vec(),
        "outer integrity"
    );
    let mut plain = blob[52..].to_vec();
    let sym_key = kdfa256(&parent_seed, b"STORAGE", &name, 128);
    aes_cfb(&sym_key, &iv, &mut plain, false);
    let sensitive = parse_plain_duplicate(&plain);
    assert_eq!(
        sensitive.auth_value.get_buffer(),
        {
            let mut a = [0u8; 32];
            a[..2].copy_from_slice(b"ab");
            a
        }
        .as_slice(),
        "authValue must be zero-padded to the nameAlg digest size"
    );
    match sensitive.sensitive {
        TpmuSensitiveComposite::KeyedHash(d) => assert_eq!(d.get_buffer(), b"hello"),
        _ => panic!("not a KEYEDHASH sensitive area"),
    }

    // Client -> TPM.
    let seed = [0x3cu8; 32];
    let mut public = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    public.parms_and_id = PublicParmsAndId::KeyedHash(
        None,
        Tpm2bDigest::from_bytes(leak_bytes(&hash(TpmiAlgHash::Sha256, &[&seed, b"world"])))
            .unwrap(),
    );
    let name = object_name(&public);
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(leak_bytes(&seed)).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"world").unwrap(),
        ),
    };
    let sens = marshal_to_vec(&sensitive);
    let mut enc = (sens.len() as u16).to_be_bytes().to_vec();
    enc.extend(sens);
    let iv = [7u8; 16];
    aes_cfb(
        &kdfa256(&parent_seed, b"STORAGE", &name, 128),
        &iv,
        &mut enc,
        true,
    );
    let mut iv_and_enc = 16u16.to_be_bytes().to_vec();
    iv_and_enc.extend(iv);
    iv_and_enc.extend(enc);
    let mut private = 32u16.to_be_bytes().to_vec();
    private.extend(hmac256(&integrity_key, &[&iv_and_enc, &name]));
    private.extend(iv_and_enc);
    let handle = load(
        &mut sim,
        parent,
        Tpm2bPrivate::from_bytes(leak_bytes(&private)).unwrap(),
        Tpm2b(public),
    )
    .expect("C-format TPM2B_PRIVATE must load");
    let (unsealed, _) = run(
        &mut sim,
        &Unseal {},
        UnsealHandles {
            item_handle: handle,
        },
        1,
    )
    .unwrap();
    assert_eq!(unsealed.out_data.get_buffer(), b"world");
}
