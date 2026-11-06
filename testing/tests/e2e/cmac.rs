//! `TPM_ALG_CMAC` (the `cmac` profile feature): `TPM2_MAC` and `TPM2_MAC_Start`, which a TPM
//! with CMAC implements in place of `TPM2_HMAC`/`TPM2_HMAC_Start` (same command codes). CMAC
//! results of SYMCIPHER signing keys (against the SP 800-38B examples and a client-side CMAC),
//! HMAC results of KEYEDHASH keys through `TPM2_MAC`, MAC sequences (split updates, context
//! save/load), the MAC selection rules of `inScheme` against the key's mode or scheme, the key
//! checks, CMAC keys in object creation, `TPM2_TestParms` and `TPM_CAP_ALGS`, and the self test
//! of the block cipher before a CMAC. Without the feature, `TPM_ALG_CMAC` is not a hash for
//! `TPM2_HMAC`.
#![cfg_attr(not(feature = "cmac"), allow(unused_imports, dead_code))]

use crate::_common::{
    exec_pw, flush_context, get_bound_unique, incremental_self_test, leak_bytes, load_with_private,
    make_keyed_hash_public_area_with_sensitive, rc_at,
};
use testing::tpm::Tpm;
use tpm2::commands::{
    ContextLoad, ContextSave, CreatePrimary, LoadExternal, MAC, MACStart, SequenceComplete,
    SequenceUpdate, TestParms,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, AlgSym, Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest,
    Tpm2bMaxBuffer, Tpm2bSensitiveData, Tpm2bSymKey, TpmCap, TpmaAlgorithm, TpmaObject,
    TpmiAlgHash, TpmiAlgMacScheme, TpmiAlgSymMode, TpmlPcrSelection, TpmsCapabilityData,
    TpmsSensitiveCreate, TpmtPublic, TpmtPublicParms, TpmtSensitive, TpmtSymDefObject,
    TpmuSensitiveComposite,
};

/// The 64-octet message of the SP 800-38B / RFC 4493 examples.
const MESSAGE: [u8; 64] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
];

/// The AES-128 key of the SP 800-38B examples (D.1).
const AES128_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

/// The AES-128 CMACs of the first 0, 16, 40 and 64 octets of [`MESSAGE`] (SP 800-38B D.1).
const AES128_CMACS: [(usize, [u8; 16]); 4] = [
    (
        0,
        [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ],
    ),
    (
        16,
        [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ],
    ),
    (
        40,
        [
            0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97,
            0xc8, 0x27,
        ],
    ),
    (
        64,
        [
            0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36,
            0x3c, 0xfe,
        ],
    ),
];

/// The AES-256 key of the SP 800-38B examples (D.3).
const AES256_KEY: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];

/// The AES-256 CMAC of [`MESSAGE`] (SP 800-38B D.3, example 12).
const AES256_CMAC_64: [u8; 16] = [
    0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5, 0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10,
];

/// `TPM_ALG_CMAC` as the mode (`TPMI_ALG_SYM_MODE`) of a SYMCIPHER key.
#[cfg(feature = "cmac")]
const CMAC_MODE: Option<TpmiAlgSymMode> = Some(TpmiAlgSymMode::Cmac);

/// Loads (`TPM2_LoadExternal`, NULL hierarchy) a SYMCIPHER key `key` of `alg` with `mode` and
/// `attributes` (plus `userWithAuth`).
fn load_sym_key(
    sim: &mut Tpm,
    alg: AlgSym,
    mode: Option<TpmiAlgSymMode>,
    attributes: TpmaObject,
    key: &[u8],
) -> Handle {
    let key: &'static [u8] = leak_bytes(key);
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attributes | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(TpmtSymDefObject { alg, mode }, get_bound_unique(key)),
    };
    load_with_private(
        sim,
        public,
        TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(key).unwrap()),
        &[0x02; 32],
    )
}

/// Loads a KEYEDHASH key with the NULL scheme (`sign` and `decrypt`), whose sensitive data is
/// `key`.
fn load_keyed_hash_key(sim: &mut Tpm, key: &'static [u8]) -> Handle {
    let cmd = LoadExternal {
        in_private: Some(Tpm2b(TpmtSensitive {
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
            sensitive: TpmuSensitiveComposite::KeyedHash(
                Tpm2bSensitiveData::from_bytes(key).unwrap(),
            ),
        })),
        // `[0x01; 32]`: the helper binds `unique` to the seed and `key`.
        in_public: Tpm2b(make_keyed_hash_public_area_with_sensitive(
            &[0x01; 32],
            TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
            key,
        )),
        hierarchy: Handle::RH_NULL,
    };
    sim.execute(cmd).unwrap().object_handle
}

/// `TPM2_MAC(handle, data, in_scheme)`: the MAC or the response code.
fn mac(
    sim: &mut Tpm,
    handle: Handle,
    data: &[u8],
    in_scheme: Option<TpmiAlgMacScheme>,
) -> Result<Vec<u8>, u32> {
    exec_pw(
        sim,
        MAC {
            handle,
            buffer: Tpm2bMaxBuffer::from_bytes(leak_bytes(data)).unwrap(),
            in_scheme,
        },
    )
    .map(|rsp| rsp.out_hmac.get_buffer().to_vec())
    .map_err(|rc| rc.0)
}

/// `TPM2_MAC_Start(handle, auth = "", in_scheme)`: the sequence handle or the response code.
fn mac_start(
    sim: &mut Tpm,
    handle: Handle,
    in_scheme: Option<TpmiAlgMacScheme>,
) -> Result<Handle, u32> {
    exec_pw(
        sim,
        MACStart {
            handle,
            auth: Tpm2bAuth::default(),
            in_scheme,
        },
    )
    .map(|rsp| rsp.sequence_handle)
    .map_err(|rc| rc.0)
}

/// `TPM2_SequenceUpdate(sequence, data)`.
fn sequence_update(sim: &mut Tpm, sequence: Handle, data: &[u8]) {
    exec_pw(
        sim,
        SequenceUpdate {
            sequence_handle: sequence,
            buffer: Tpm2bMaxBuffer::from_bytes(leak_bytes(data)).unwrap(),
        },
    )
    .expect("TPM2_SequenceUpdate");
}

/// `TPM2_SequenceComplete(sequence, data, TPM_RH_NULL)`: the result, after checking that the
/// ticket is the NULL ticket of a MAC sequence.
fn sequence_complete(sim: &mut Tpm, sequence: Handle, data: &[u8]) -> Vec<u8> {
    let rsp = exec_pw(
        sim,
        SequenceComplete {
            sequence_handle: sequence,
            buffer: Tpm2bMaxBuffer::from_bytes(leak_bytes(data)).unwrap(),
            hierarchy: Handle::RH_NULL,
        },
    )
    .expect("TPM2_SequenceComplete");
    assert_eq!(
        rsp.validation,
        tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default())
    );
    rsp.result.get_buffer().to_vec()
}

/// Without CMAC the TPM implements `TPM2_HMAC`, whose `hashAlg` is a `TPMI_ALG_HASH+`:
/// `TPM_ALG_CMAC` in it is `TPM_RC_HASH + RC_P2`.
#[cfg(not(feature = "cmac"))]
#[test]
fn hmac_rejects_cmac_as_hash() {
    let mut sim = Tpm::new();
    let key = load_keyed_hash_key(&mut sim, b"hmac key");
    let cmd = tpm2::commands::HMAC {
        handle: key,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = crate::_common::execute_with_corrupted_bytes_status(&mut sim, &cmd, 1, &[], |p| {
        crate::_common::put_u16(p, crate::_common::tpm2b_end(p, 0), Alg::CMAC.id());
    });
    assert_eq!(res.err(), Some(rc_at(TpmRc::HASH, Position::parameter(2))));
}

/// `TPM2_MAC` of an AES-128 SYMCIPHER signing key computes the CMAC of SP 800-38B (the
/// examples D.1: 0, 16, 40 and 64 octets), with `inScheme` `TPM_ALG_CMAC` or `TPM_ALG_NULL`
/// for a key whose mode is CMAC, and with `inScheme` `TPM_ALG_CMAC` for a key whose mode is NULL.
#[cfg(feature = "cmac")]
#[test]
fn mac_of_aes128_key_matches_sp800_38b() {
    let mut sim = Tpm::new();
    let cmac_key = load_sym_key(
        &mut sim,
        AlgSym::Aes128,
        CMAC_MODE,
        TpmaObject::SIGN_ENCRYPT,
        &AES128_KEY,
    );
    let null_key = load_sym_key(
        &mut sim,
        AlgSym::Aes128,
        None,
        TpmaObject::SIGN_ENCRYPT,
        &AES128_KEY,
    );
    for (len, expected) in AES128_CMACS {
        for (key, scheme) in [
            (cmac_key, Some(TpmiAlgMacScheme::Cmac)),
            (cmac_key, None),
            (null_key, Some(TpmiAlgMacScheme::Cmac)),
        ] {
            assert_eq!(
                mac(&mut sim, key, &MESSAGE[..len], scheme).unwrap(),
                expected,
                "len {len}, scheme {scheme:?}"
            );
        }
    }
}

/// `TPM2_MAC` of an AES-256 SYMCIPHER signing key computes the CMAC of SP 800-38B (D.3).
#[cfg(feature = "cmac")]
#[test]
fn mac_of_aes256_key_matches_sp800_38b() {
    let mut sim = Tpm::new();
    let key = load_sym_key(
        &mut sim,
        AlgSym::Aes256,
        CMAC_MODE,
        TpmaObject::SIGN_ENCRYPT,
        &AES256_KEY,
    );
    assert_eq!(mac(&mut sim, key, &MESSAGE, None).unwrap(), AES256_CMAC_64);
}

/// `TPM2_MAC` of a Camellia SYMCIPHER signing key computes the Camellia-CMAC (compared with a
/// client-side CMAC) for message lengths around the block size.
#[cfg(all(feature = "cmac", feature = "camellia128"))]
#[test]
fn mac_of_camellia_key_matches_client_cmac() {
    use tpm2::crypto::{Block, CmacContext, SymmetricKey};
    let mut sim = Tpm::new();
    let key_bytes = [0x5au8; 16];
    let key = load_sym_key(
        &mut sim,
        AlgSym::Camellia128,
        CMAC_MODE,
        TpmaObject::SIGN_ENCRYPT,
        &key_bytes,
    );
    for len in [0, 1, 15, 16, 17, 32, 40, 64] {
        let client_key = SymmetricKey::new(AlgSym::Camellia128, &key_bytes).unwrap();
        let mut ctx = CmacContext::<crate::_common::ClientCrypto>::new(client_key).unwrap();
        ctx.update(&MESSAGE[..len]).unwrap();
        let mut expected: Block = [0u8; 16];
        ctx.finalize(&mut expected).unwrap();
        assert_eq!(
            mac(&mut sim, key, &MESSAGE[..len], None).unwrap(),
            expected,
            "len {len}"
        );
    }
}

/// `TPM2_MAC` of a KEYEDHASH key computes the HMAC with the hash `inScheme` (RFC 2104,
/// compared with a client-side HMAC).
#[cfg(feature = "cmac")]
#[test]
fn mac_of_keyed_hash_key_is_hmac() {
    use hmac::{Hmac, Mac};
    let mut sim = Tpm::new();
    let key = load_keyed_hash_key(&mut sim, b"hmac key");
    let mut expected = Hmac::<sha2::Sha256>::new_from_slice(b"hmac key").unwrap();
    expected.update(&MESSAGE);
    assert_eq!(
        mac(&mut sim, key, &MESSAGE, Some(TpmiAlgMacScheme::Sha256)).unwrap(),
        expected.finalize().into_bytes().to_vec()
    );
}

/// A MAC sequence (`TPM2_MAC_Start`, `TPM2_SequenceUpdate`s of 17, 0 and 16 octets,
/// `TPM2_SequenceComplete` with the rest) returns the CMAC of the whole message and a NULL
/// ticket, also when the message ends on a block boundary.
#[cfg(feature = "cmac")]
#[test]
fn mac_sequence_matches_one_shot_cmac() {
    let mut sim = Tpm::new();
    let key = load_sym_key(
        &mut sim,
        AlgSym::Aes128,
        CMAC_MODE,
        TpmaObject::SIGN_ENCRYPT,
        &AES128_KEY,
    );
    for (len, expected) in AES128_CMACS {
        let sequence = mac_start(&mut sim, key, Some(TpmiAlgMacScheme::Cmac)).unwrap();
        let mut offset = 0;
        for chunk in [17, 0, 16] {
            let end = (offset + chunk).min(len);
            sequence_update(&mut sim, sequence, &MESSAGE[offset..end]);
            offset = end;
        }
        assert_eq!(
            sequence_complete(&mut sim, sequence, &MESSAGE[offset..len]),
            expected,
            "len {len}"
        );
    }
}

/// A MAC sequence of a KEYEDHASH key (`TPM2_MAC_Start` with a hash) is an HMAC sequence.
#[cfg(feature = "cmac")]
#[test]
fn mac_sequence_of_keyed_hash_key_is_hmac() {
    let mut sim = Tpm::new();
    let key = load_keyed_hash_key(&mut sim, b"hmac key");
    let one_shot = mac(&mut sim, key, &MESSAGE, Some(TpmiAlgMacScheme::Sha256)).unwrap();
    let sequence = mac_start(&mut sim, key, Some(TpmiAlgMacScheme::Sha256)).unwrap();
    sequence_update(&mut sim, sequence, &MESSAGE[..20]);
    assert_eq!(
        sequence_complete(&mut sim, sequence, &MESSAGE[20..]),
        one_shot
    );
}

/// A CMAC sequence keeps its state across `TPM2_ContextSave`/`TPM2_ContextLoad` (saved in the
/// middle of a block).
#[cfg(feature = "cmac")]
#[test]
fn mac_sequence_survives_context_save_and_load() {
    let mut sim = Tpm::new();
    let key = load_sym_key(
        &mut sim,
        AlgSym::Aes256,
        CMAC_MODE,
        TpmaObject::SIGN_ENCRYPT,
        &AES256_KEY,
    );
    let sequence = mac_start(&mut sim, key, None).unwrap();
    sequence_update(&mut sim, sequence, &MESSAGE[..23]);
    let context = sim
        .execute(ContextSave {
            save_handle: sequence,
        })
        .expect("TPM2_ContextSave")
        .context;
    let sequence = sim
        .execute(ContextLoad { context })
        .expect("TPM2_ContextLoad")
        .loaded_handle;
    sequence_update(&mut sim, sequence, &MESSAGE[23..50]);
    assert_eq!(
        sequence_complete(&mut sim, sequence, &MESSAGE[50..]),
        AES256_CMAC_64
    );
}

/// The MAC selection of `TPM2_MAC` and `TPM2_MAC_Start` (Part 3, "Algorithm Selection
/// Matrix"): a non-NULL `inScheme` that differs from the key's mode or scheme is
/// `TPM_RC_VALUE + RC_P2`, a NULL `inScheme` with a NULL key mode or scheme is
/// `TPM_RC_VALUE + RC_P2`, and an algorithm the key type cannot use (a hash for a SYMCIPHER key,
/// a cipher mode instead of CMAC, CMAC for a KEYEDHASH key) is `TPM_RC_SCHEME + RC_P2`.
#[cfg(feature = "cmac")]
#[test]
fn mac_scheme_selection_errors() {
    let mut sim = Tpm::new();
    let value = rc_at(TpmRc::VALUE, Position::parameter(2));
    let scheme = rc_at(TpmRc::SCHEME, Position::parameter(2));
    let cfb = Some(TpmiAlgSymMode::Cipher(tpm2::TpmiAlgCipherMode::Cfb));
    // (key mode, `sign`/`decrypt` attributes, `inScheme` and the expected error of each row);
    // a `None` key mode is the KEYEDHASH key (NULL scheme).
    let sign = TpmaObject::SIGN_ENCRYPT;
    let cases: [(Option<Option<TpmiAlgSymMode>>, TpmaObject, Vec<_>); 4] = [
        (
            Some(CMAC_MODE),
            sign,
            vec![(Some(TpmiAlgMacScheme::Sha256), value)],
        ),
        (
            Some(None),
            sign,
            vec![(None, value), (Some(TpmiAlgMacScheme::Sha256), scheme)],
        ),
        (
            Some(cfb),
            sign | TpmaObject::DECRYPT,
            vec![(None, scheme), (Some(TpmiAlgMacScheme::Cmac), value)],
        ),
        (
            None,
            sign,
            vec![(None, value), (Some(TpmiAlgMacScheme::Cmac), scheme)],
        ),
    ];
    for (mode, attributes, rows) in cases {
        // At most three objects fit (the TCG reference profile), so one key at a time.
        let key = match mode {
            Some(mode) => load_sym_key(&mut sim, AlgSym::Aes128, mode, attributes, &AES128_KEY),
            None => load_keyed_hash_key(&mut sim, b"hmac key"),
        };
        for (in_scheme, expected) in rows {
            assert_eq!(
                mac(&mut sim, key, b"data", in_scheme),
                Err(expected),
                "TPM2_MAC {mode:?} {in_scheme:?}"
            );
            assert_eq!(
                mac_start(&mut sim, key, in_scheme),
                Err(expected),
                "TPM2_MAC_Start {mode:?} {in_scheme:?}"
            );
        }
        flush_context(&mut sim, key).unwrap();
    }
}

/// `TPM2_MAC` and `TPM2_MAC_Start` need a signing key (`TPM_RC_KEY + RC_H1`), checked after the
/// MAC selection, and reject a key that is neither KEYEDHASH nor SYMCIPHER (`TPM_RC_TYPE +
/// RC_H1`) and a sequence object (`TPM_RC_TYPE + RC_H1`).
#[cfg(feature = "cmac")]
#[test]
fn mac_key_checks() {
    let mut sim = Tpm::new();
    let decrypt_key = load_sym_key(
        &mut sim,
        AlgSym::Aes128,
        None,
        TpmaObject::DECRYPT,
        &AES128_KEY,
    );
    let key = rc_at(TpmRc::KEY, Position::handle(1));
    assert_eq!(
        mac(&mut sim, decrypt_key, b"data", Some(TpmiAlgMacScheme::Cmac)),
        Err(key)
    );
    assert_eq!(
        mac_start(&mut sim, decrypt_key, Some(TpmiAlgMacScheme::Cmac)),
        Err(key)
    );
    // The MAC selection comes first: a mismatching scheme is reported for a non-signing key.
    assert_eq!(
        mac(
            &mut sim,
            decrypt_key,
            b"data",
            Some(TpmiAlgMacScheme::Sha256)
        ),
        Err(rc_at(TpmRc::SCHEME, Position::parameter(2)))
    );

    let rsa_key = crate::_common::create_primary_returning_public(
        &mut sim,
        crate::_common::rsa_public_with_symmetric(
            TpmaObject::SIGN_ENCRYPT | crate::_common::sdo_user(),
            None,
        ),
        &[],
    )
    .0;
    let type_h1 = rc_at(TpmRc::TYPE, Position::handle(1));
    assert_eq!(
        mac(&mut sim, rsa_key, b"data", Some(TpmiAlgMacScheme::Cmac)),
        Err(type_h1)
    );
    assert_eq!(
        mac_start(&mut sim, rsa_key, Some(TpmiAlgMacScheme::Cmac)),
        Err(type_h1)
    );

    // At most three objects fit (the TCG reference profile): make room for the sequence.
    flush_context(&mut sim, decrypt_key).unwrap();
    flush_context(&mut sim, rsa_key).unwrap();
    let cmac_key = load_sym_key(
        &mut sim,
        AlgSym::Aes128,
        CMAC_MODE,
        TpmaObject::SIGN_ENCRYPT,
        &AES128_KEY,
    );
    let sequence = mac_start(&mut sim, cmac_key, None).unwrap();
    assert_eq!(mac(&mut sim, sequence, b"data", None), Err(type_h1));
    assert_eq!(mac_start(&mut sim, sequence, None), Err(type_h1));
    flush_context(&mut sim, sequence).unwrap();
}

/// A SYMCIPHER key with mode CMAC can be created as a signing key, but not as a decryption key
/// (`TPM_RC_SCHEME`: only block cipher modes encrypt), and `TPM2_TestParms` accepts CMAC as the
/// mode of a SYMCIPHER definition.
#[cfg(feature = "cmac")]
#[test]
fn cmac_keys_are_signing_keys() {
    let mut sim = Tpm::new();
    let create = |attributes: TpmaObject| CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate::default()),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: attributes
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: CMAC_MODE,
                },
                Tpm2bDigest::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let key = exec_pw(&mut sim, create(TpmaObject::SIGN_ENCRYPT))
        .expect("CMAC signing key")
        .object_handle;
    assert_eq!(mac(&mut sim, key, b"data", None).unwrap().len(), 16);
    assert_eq!(
        exec_pw(
            &mut sim,
            create(TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT)
        )
        .err()
        .map(|rc| rc.0),
        Some(rc_at(TpmRc::SCHEME, Position::parameter(2)))
    );
    sim.execute(TestParms {
        parameters: TpmtPublicParms::Sym(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: CMAC_MODE,
        }),
    })
    .expect("TPM2_TestParms(SYMCIPHER, AES-128, CMAC)");
}

/// Without CMAC, `TPM_CAP_ALGS` does not list `TPM_ALG_CMAC` (the next algorithm reported from
/// it on is a block cipher mode).
#[cfg(not(feature = "cmac"))]
#[test]
fn capability_omits_cmac() {
    let mut sim = Tpm::new();
    let rsp = sim
        .execute(tpm2::commands::GetCapability {
            capability: TpmCap::Algs,
            property: u32::from(Alg::CMAC.id()),
            property_count: 1,
        })
        .expect("TPM2_GetCapability");
    let TpmsCapabilityData::Algorithms(algs) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    assert!(algs.as_ref().iter().all(|a| a.alg != Alg::CMAC));
}

/// `TPM_CAP_ALGS` lists `TPM_ALG_CMAC` as a symmetric signing algorithm.
#[cfg(feature = "cmac")]
#[test]
fn capability_lists_cmac() {
    let mut sim = Tpm::new();
    let rsp = sim
        .execute(tpm2::commands::GetCapability {
            capability: TpmCap::Algs,
            property: u32::from(Alg::CMAC.id()),
            property_count: 1,
        })
        .expect("TPM2_GetCapability");
    let TpmsCapabilityData::Algorithms(algs) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    let first = algs.as_ref()[0];
    assert_eq!(first.alg, Alg::CMAC);
    assert_eq!(
        first.alg_properties,
        TpmaAlgorithm::SYMMETRIC | TpmaAlgorithm::SIGNING
    );
}

/// The block cipher of a CMAC is self-tested before the CMAC is computed (Part 1, "Self-Test
/// Modes"): after `TPM2_MAC` (and after `TPM2_MAC_Start`) of an AES key on a TPM where AES is
/// untested, AES is no longer in the `toDoList` of `TPM2_IncrementalSelfTest`.
#[cfg(feature = "cmac")]
#[test]
fn cmac_tests_its_block_cipher_first() {
    for start_sequence in [false, true] {
        let mut sim = Tpm::new();
        let key = load_sym_key(
            &mut sim,
            AlgSym::Aes128,
            CMAC_MODE,
            TpmaObject::SIGN_ENCRYPT,
            &AES128_KEY,
        );
        assert!(
            incremental_self_test(&mut sim, &[])
                .unwrap()
                .contains(&Alg::AES)
        );
        if start_sequence {
            mac_start(&mut sim, key, None).unwrap();
        } else {
            mac(&mut sim, key, b"data", None).unwrap();
        }
        assert!(
            !incremental_self_test(&mut sim, &[])
                .unwrap()
                .contains(&Alg::AES),
            "sequence: {start_sequence}"
        );
    }
}
