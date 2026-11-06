//! ML-KEM keys (`TPM_ALG_MLKEM`, TPM 2.0 v185): capabilities, TPM2_TestParms, primary and
//! ordinary key creation (encapsulation key sizes, determinism of primary keys), the attribute
//! and symmetric-definition checks, TPM2_LoadExternal validation (seed size, encapsulation key
//! size, binding) and context save/load.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{ContextLoad, GetCapability};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Handle, TpmCap, TpmPt, TpmaAlgorithm, TpmaObject, TpmiMlkemParms, TpmsCapabilityData,
    TpmsMlkemParms, TpmtPublic, TpmtPublicParms,
};

/// Attributes of a key loaded with its private part by TPM2_LoadExternal (no fixedTPM,
/// fixedParent or sensitiveDataOrigin).
fn external_attrs() -> TpmaObject {
    TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT
}

/// The encapsulation key of a primary ML-KEM key created from `template` under `hierarchy`.
fn primary_encapsulation_key(
    sim: &mut Tpm,
    hierarchy: Handle,
    template: TpmtPublic<'static>,
) -> Vec<u8> {
    let handle = create_primary_in(sim, hierarchy, template);
    let public = read_public(sim, handle).unwrap().out_public.0;
    flush_context(sim, handle).unwrap();
    mlkem_public_key(&public).1
}

/// TPM_CAP_ALGS reports TPM_ALG_MLKEM as an asymmetric object algorithm.
#[test]
fn algorithm_capability_reports_mlkem() {
    let mut sim = Tpm::new();
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::Algs,
            property: u32::from(Alg::MLKEM.id()),
            property_count: 1,
        })
        .unwrap();
    let TpmsCapabilityData::Algorithms(list) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    let entry = list.as_ref()[0];
    assert_eq!(entry.alg, Alg::MLKEM);
    assert_eq!(
        entry.alg_properties,
        TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::OBJECT
    );
}

/// TPM_PT_ML_PARAMETER_SETS reports every ML-KEM parameter set (0x07), and with ML-DSA also
/// every ML-DSA parameter set and extMu (0x7F).
#[test]
fn ml_parameter_sets_property_reports_every_parameter_set() {
    let mut sim = Tpm::new();
    let expected = if cfg!(feature = "mldsa") { 0x7F } else { 0x07 };
    assert_eq!(
        get_tpm_property(&mut sim, TpmPt::ML_PARAMETER_SETS),
        expected
    );
}

/// TPM2_TestParms accepts every ML-KEM parameter set, with and without a symmetric definition.
#[test]
fn test_parms_accepts_every_parameter_set() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        for symmetric in [None, Some(AES128_CFB)] {
            assert_eq!(
                execute_test_parms(
                    &mut sim,
                    TpmtPublicParms::Mlkem(TpmsMlkemParms {
                        symmetric,
                        parameter_set,
                    }),
                ),
                Ok(()),
                "{parameter_set:?} {symmetric:?}"
            );
        }
    }
}

/// TPM2_TestParms rejects undefined ML-KEM parameter sets (0 and 4) with TPM_RC_PARMS + P1.
#[test]
fn test_parms_rejects_undefined_parameter_sets() {
    let mut sim = Tpm::new();
    for value in [0u16, 4, 0xFFFF] {
        let rc = execute_test_parms_corrupted(
            &mut sim,
            TpmtPublicParms::Mlkem(TpmsMlkemParms {
                symmetric: None,
                parameter_set: TpmiMlkemParms::Mlkem768,
            }),
            |buf| {
                // type (2) | symmetric TPM_ALG_NULL (2) | parameterSet (2)
                buf[4..6].copy_from_slice(&value.to_be_bytes());
            },
        );
        assert_eq!(
            rc,
            Err(TpmRc::PARMS.with(Position::parameter(1)).get()),
            "parameterSet {value:#x}"
        );
    }
}

/// A primary ML-KEM key has the encapsulation key of its parameter set (800, 1184 or 1568
/// bytes) and is deterministic: the same template gives the same key in the same hierarchy,
/// and another key in another hierarchy.
#[test]
fn primary_keys_are_deterministic_per_hierarchy() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let template = mlkem_decryption_public(parameter_set);
        let first = primary_encapsulation_key(&mut sim, Handle::RH_OWNER, template);
        assert_eq!(
            first.len(),
            parameter_set.pub_key_bytes(),
            "{parameter_set:?}"
        );
        let second = primary_encapsulation_key(&mut sim, Handle::RH_OWNER, template);
        assert_eq!(
            first, second,
            "{parameter_set:?}: primary key not deterministic"
        );
        let endorsement = primary_encapsulation_key(&mut sim, Handle::RH_ENDORSEMENT, template);
        assert_ne!(
            first, endorsement,
            "{parameter_set:?}: same key in two hierarchies"
        );
    }
}

/// Primary ML-KEM keys from templates that differ only in an attribute (noDA) are different
/// keys: the template is part of the key derivation.
#[test]
fn primary_key_depends_on_template() {
    let mut sim = Tpm::new();
    let template = mlkem_decryption_public(TpmiMlkemParms::Mlkem512);
    let mut other = template;
    other.object_attributes |= TpmaObject::NO_DA;
    let a = primary_encapsulation_key(&mut sim, Handle::RH_OWNER, template);
    let b = primary_encapsulation_key(&mut sim, Handle::RH_OWNER, other);
    assert_ne!(a, b);
}

/// Ordinary ML-KEM keys of every parameter set are created under a storage parent, load, and
/// keep their encapsulation key; two keys from the same template differ.
#[test]
fn ordinary_keys_create_and_load() {
    let mut sim = Tpm::new();
    let srk = create_srk(&mut sim);
    for parameter_set in MLKEM_PARAMETER_SETS {
        let template = mlkem_decryption_public(parameter_set);
        let (private, public) = create_child(&mut sim, srk, template, b"");
        let (_, other_public) = create_child(&mut sim, srk, template, b"");
        let (_, key) = mlkem_public_key(&public.0);
        assert_eq!(key.len(), parameter_set.pub_key_bytes());
        assert_ne!(key, mlkem_public_key(&other_public.0).1);
        let (handle, name) = load_child(&mut sim, srk, private, public);
        let read = read_public(&mut sim, handle).unwrap();
        assert_eq!(read.name.get_buffer(), name.as_slice());
        assert_eq!(mlkem_public_key(&read.out_public.0).1, key);
        flush_context(&mut sim, handle).unwrap();
    }
}

/// An ML-KEM key must be a decryption key and not a signing key: sign, sign + decrypt and
/// neither fail with TPM_RC_ATTRIBUTES + P2 (inPublic of TPM2_CreatePrimary).
#[test]
fn key_must_be_decrypt_only() {
    let mut sim = Tpm::new();
    for attributes in [
        base_attrs() | TpmaObject::SIGN_ENCRYPT,
        base_attrs() | TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        base_attrs(),
    ] {
        let rc = try_create_primary(
            &mut sim,
            mlkem_public(TpmiMlkemParms::Mlkem768, attributes, None),
            &[],
        )
        .map(|_| ());
        assert_eq!(
            rc,
            Err(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()),
            "{attributes:?}"
        );
    }
}

/// The symmetric definition of an ML-KEM key is NULL unless the key is restricted: an
/// unrestricted key with AES-128-CFB, and a restricted key without one, fail with
/// TPM_RC_SYMMETRIC + P2.
#[test]
fn symmetric_definition_only_for_restricted_keys() {
    let mut sim = Tpm::new();
    let rc = try_create_primary(
        &mut sim,
        mlkem_public(
            TpmiMlkemParms::Mlkem512,
            base_attrs() | TpmaObject::DECRYPT,
            Some(AES128_CFB),
        ),
        &[],
    )
    .map(|_| ());
    assert_eq!(rc, Err(TpmRc::SYMMETRIC.with(Position::parameter(2)).get()));
    let rc = try_create_primary(
        &mut sim,
        mlkem_public(TpmiMlkemParms::Mlkem512, storage_attrs(), None),
        &[],
    )
    .map(|_| ());
    assert_eq!(rc, Err(TpmRc::SYMMETRIC.with(Position::parameter(2)).get()));
}

/// TPM2_LoadExternal loads an ML-KEM key pair generated client-side for every parameter set;
/// the TPM keeps the given encapsulation key, and a public-only copy has the same Name.
#[test]
fn load_external_accepts_client_key_pairs() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (seed, public_key) = mlkem_client_key(parameter_set);
        let public = mlkem_public_with_key(parameter_set, external_attrs(), None, &public_key);
        let pair = load_external(
            &mut sim,
            public,
            Some(mlkem_sensitive(&seed)),
            Handle::RH_NULL,
        )
        .unwrap_or_else(|rc| panic!("{parameter_set:?}: LoadExternal failed: {rc:#x}"));
        let public_only = load_external(&mut sim, public, None, Handle::RH_OWNER).unwrap();
        let read = read_public(&mut sim, pair).unwrap();
        assert_eq!(mlkem_public_key(&read.out_public.0).1, public_key);
        assert_eq!(read.name, read_public(&mut sim, public_only).unwrap().name);
        flush_context(&mut sim, pair).unwrap();
        flush_context(&mut sim, public_only).unwrap();
    }
}

/// TPM2_LoadExternal rejects an ML-KEM seed that is not 64 bytes with TPM_RC_SIZE + P1: the
/// size of a `TPM2B_PRIVATE_KEY_MLKEM` "shall be 64" (TPM 2.0 Part 2), so another size fails to unmarshal.
#[test]
fn load_external_rejects_seed_of_wrong_size() {
    let mut sim = Tpm::new();
    let (seed, public_key) = mlkem_client_key(TpmiMlkemParms::Mlkem512);
    let public = mlkem_public_with_key(
        TpmiMlkemParms::Mlkem512,
        external_attrs(),
        None,
        &public_key,
    );
    for size in [0, 32, 63] {
        let rc = load_external(
            &mut sim,
            public,
            Some(mlkem_sensitive(&seed[..size])),
            Handle::RH_NULL,
        );
        assert_eq!(
            rc,
            Err(TpmRc::SIZE.with(Position::parameter(1)).get()),
            "seed of {size} bytes"
        );
    }
}

/// TPM2_LoadExternal rejects an ML-KEM encapsulation key that does not have the size of the
/// parameter set with TPM_RC_KEY + P2, with and without a private part.
#[test]
fn load_external_rejects_encapsulation_key_of_wrong_size() {
    let mut sim = Tpm::new();
    let (seed, public_key) = mlkem_client_key(TpmiMlkemParms::Mlkem768);
    // An ML-KEM-768 key declared as ML-KEM-512 or ML-KEM-1024.
    for parameter_set in [TpmiMlkemParms::Mlkem512, TpmiMlkemParms::Mlkem1024] {
        let public = mlkem_public_with_key(parameter_set, external_attrs(), None, &public_key);
        assert_eq!(
            load_external(&mut sim, public, None, Handle::RH_OWNER),
            Err(TpmRc::KEY.with(Position::parameter(2)).get()),
            "public only, {parameter_set:?}"
        );
        assert_eq!(
            load_external(
                &mut sim,
                public,
                Some(mlkem_sensitive(&seed)),
                Handle::RH_NULL
            ),
            Err(TpmRc::KEY.with(Position::parameter(2)).get()),
            "key pair, {parameter_set:?}"
        );
    }
    // A truncated encapsulation key.
    let public = mlkem_public_with_key(
        TpmiMlkemParms::Mlkem768,
        external_attrs(),
        None,
        &public_key[..public_key.len() - 1],
    );
    assert_eq!(
        load_external(&mut sim, public, None, Handle::RH_OWNER),
        Err(TpmRc::KEY.with(Position::parameter(2)).get())
    );
}

/// TPM2_LoadExternal rejects an ML-KEM seed that does not generate the given encapsulation key
/// with a bare TPM_RC_BINDING.
#[test]
fn load_external_rejects_mismatched_seed() {
    let mut sim = Tpm::new();
    let (_, public_key) = mlkem_client_key(TpmiMlkemParms::Mlkem1024);
    let (other_seed, _) = mlkem_client_key(TpmiMlkemParms::Mlkem1024);
    let public = mlkem_public_with_key(
        TpmiMlkemParms::Mlkem1024,
        external_attrs(),
        None,
        &public_key,
    );
    assert_eq!(
        load_external(
            &mut sim,
            public,
            Some(mlkem_sensitive(&other_seed)),
            Handle::RH_NULL
        ),
        Err(rc_bare(TpmRc::BINDING))
    );
}

/// TPM2_LoadExternal of an ML-KEM key whose sensitive area has another type fails with
/// TPM_RC_TYPE + P1.
#[cfg(feature = "mldsa")]
#[test]
fn load_external_rejects_sensitive_of_other_type() {
    use tpm2::Tpm2b;
    use tpm2::commands::LoadExternal;
    let mut sim = Tpm::new();
    let (_, public_key) = mlkem_client_key(TpmiMlkemParms::Mlkem512);
    let public = mlkem_public_with_key(
        TpmiMlkemParms::Mlkem512,
        external_attrs(),
        None,
        &public_key,
    );
    let rc = execute_with_password_sessions(
        &mut sim,
        &LoadExternal {
            in_private: Some(Tpm2b(mldsa_sensitive(&[7; 32]))),
            in_public: Tpm2b(public),
            hierarchy: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .map(|_| ());
    assert_eq!(rc, Err(TpmRc::TYPE.with(Position::parameter(1)).get()));
}

/// An ML-KEM-1024 key survives TPM2_ContextSave / TPM2_FlushContext / TPM2_ContextLoad with
/// the same Name.
#[test]
fn context_save_and_load_round_trip() {
    let mut sim = Tpm::new();
    let srk = create_srk(&mut sim);
    let (private, public) = create_child(
        &mut sim,
        srk,
        mlkem_decryption_public(TpmiMlkemParms::Mlkem1024),
        b"",
    );
    let (handle, name) = load_child(&mut sim, srk, private, public);
    let context = context_save(&mut sim, handle);
    flush_context(&mut sim, handle).unwrap();
    let loaded = execute_with_password_sessions(&mut sim, &ContextLoad { context }, 0, &[])
        .unwrap()
        .loaded_handle;
    assert_eq!(
        read_public(&mut sim, loaded).unwrap().name.get_buffer(),
        name.as_slice()
    );
}
