//! ML-DSA keys (`TPM_ALG_MLDSA`, TPM 2.0 v185): capabilities, TPM2_TestParms, primary and
//! ordinary key creation (verification key sizes, determinism of primary keys), the attribute
//! checks (sign-only, *allowExternalMu* only on unrestricted non-x509sign keys),
//! TPM2_LoadExternal validation (seed size, verification key size, binding), the rejection of
//! ML-DSA keys by TPM2_Sign and TPM2_VerifySignature, and context save/load. HashML-DSA keys
//! (`TPM_ALG_HASH_MLDSA`, implemented by no C reference) are tested with the `hash_mldsa`
//! feature only.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{ContextLoad, GetCapability};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Handle, TpmCap, TpmaAlgorithm, TpmaObject, TpmiMldsaParms, TpmsCapabilityData,
    TpmsMldsaParms, TpmtPublic, TpmtPublicParms, TpmtSigScheme,
};

/// Attributes of a signing key loaded with its private part by TPM2_LoadExternal.
fn external_attrs() -> TpmaObject {
    TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT
}

/// The verification key of a primary ML-DSA key created from `template` under `hierarchy`.
fn primary_verification_key(
    sim: &mut Tpm,
    hierarchy: Handle,
    template: TpmtPublic<'static>,
) -> Vec<u8> {
    let handle = create_primary_in(sim, hierarchy, template);
    let public = read_public(sim, handle).unwrap().out_public.0;
    flush_context(sim, handle).unwrap();
    mldsa_public_key(&public).1
}

/// TPM_CAP_ALGS reports TPM_ALG_MLDSA as an asymmetric signing object algorithm.
#[test]
fn algorithm_capability_reports_mldsa() {
    let mut sim = Tpm::new();
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::Algs,
            property: u32::from(Alg::MLDSA.id()),
            property_count: 1,
        })
        .unwrap();
    let TpmsCapabilityData::Algorithms(list) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    let entry = list.as_ref()[0];
    assert_eq!(entry.alg, Alg::MLDSA);
    assert_eq!(
        entry.alg_properties,
        TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::OBJECT | TpmaAlgorithm::SIGNING
    );
}

/// TPM2_TestParms accepts every ML-DSA parameter set, with and without *allowExternalMu*.
#[test]
fn test_parms_accepts_every_parameter_set() {
    let mut sim = Tpm::new();
    for parameter_set in MLDSA_PARAMETER_SETS {
        for allow_external_mu in [false, true] {
            assert_eq!(
                execute_test_parms(
                    &mut sim,
                    TpmtPublicParms::Mldsa(TpmsMldsaParms {
                        parameter_set,
                        allow_external_mu,
                    }),
                ),
                Ok(()),
                "{parameter_set:?} allowExternalMu={allow_external_mu}"
            );
        }
    }
}

/// TPM2_TestParms rejects undefined ML-DSA parameter sets (0 and 4) with TPM_RC_PARMS + P1,
/// and an *allowExternalMu* that is not a TPMI_YES_NO with TPM_RC_VALUE + P1.
#[test]
fn test_parms_rejects_undefined_values() {
    let mut sim = Tpm::new();
    let parms = TpmtPublicParms::Mldsa(TpmsMldsaParms {
        parameter_set: TpmiMldsaParms::Mldsa65,
        allow_external_mu: false,
    });
    // type (2) | parameterSet (2) | allowExternalMu (1)
    for value in [0u16, 4, 0xFFFF] {
        assert_eq!(
            execute_test_parms_corrupted(&mut sim, parms, |buf| {
                buf[2..4].copy_from_slice(&value.to_be_bytes());
            }),
            Err(TpmRc::PARMS.with(Position::parameter(1)).get()),
            "parameterSet {value:#x}"
        );
    }
    assert_eq!(
        execute_test_parms_corrupted(&mut sim, parms, |buf| buf[4] = 2),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

/// A primary ML-DSA key has the verification key of its parameter set (1312, 1952 or 2592
/// bytes) and is deterministic: the same template gives the same key in the same hierarchy,
/// and another key in another hierarchy.
#[test]
fn primary_keys_are_deterministic_per_hierarchy() {
    let mut sim = Tpm::new();
    for parameter_set in MLDSA_PARAMETER_SETS {
        let template = mldsa_signing_public(parameter_set);
        let first = primary_verification_key(&mut sim, Handle::RH_OWNER, template);
        assert_eq!(
            first.len(),
            parameter_set.public_key_bytes(),
            "{parameter_set:?}"
        );
        let second = primary_verification_key(&mut sim, Handle::RH_OWNER, template);
        assert_eq!(
            first, second,
            "{parameter_set:?}: primary key not deterministic"
        );
        let endorsement = primary_verification_key(&mut sim, Handle::RH_ENDORSEMENT, template);
        assert_ne!(
            first, endorsement,
            "{parameter_set:?}: same key in two hierarchies"
        );
    }
}

/// Ordinary ML-DSA keys of every parameter set, restricted or not, are created under a
/// storage parent, load and keep their verification key.
#[test]
fn ordinary_keys_create_and_load() {
    let mut sim = Tpm::new();
    let srk = create_srk(&mut sim);
    for parameter_set in MLDSA_PARAMETER_SETS {
        for template in [
            mldsa_signing_public(parameter_set),
            mldsa_attestation_public(parameter_set),
        ] {
            let (private, public) = create_child(&mut sim, srk, template, b"");
            let (_, key) = mldsa_public_key(&public.0);
            assert_eq!(key.len(), parameter_set.public_key_bytes());
            let (handle, name) = load_child(&mut sim, srk, private, public);
            let read = read_public(&mut sim, handle).unwrap();
            assert_eq!(read.name.get_buffer(), name.as_slice());
            assert_eq!(mldsa_public_key(&read.out_public.0).1, key);
            flush_context(&mut sim, handle).unwrap();
        }
    }
}

/// An ML-DSA key must be a signing key and not a decryption key: decrypt, sign + decrypt and
/// neither fail with TPM_RC_ATTRIBUTES + P2 (inPublic of TPM2_CreatePrimary).
#[test]
fn key_must_be_sign_only() {
    let mut sim = Tpm::new();
    for attributes in [
        base_attrs() | TpmaObject::DECRYPT,
        base_attrs() | TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        base_attrs(),
    ] {
        let rc = try_create_primary(
            &mut sim,
            mldsa_public(TpmiMldsaParms::Mldsa44, attributes, false),
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

/// *allowExternalMu* is allowed on an unrestricted signing key, and rejected with
/// TPM_RC_ATTRIBUTES + P2 on a restricted key or an x509sign key.
#[test]
fn allow_external_mu_only_on_unrestricted_keys() {
    let mut sim = Tpm::new();
    let signing = base_attrs() | TpmaObject::SIGN_ENCRYPT;
    let (handle, _) = try_create_primary(
        &mut sim,
        mldsa_public(TpmiMldsaParms::Mldsa44, signing, true),
        &[],
    )
    .expect("unrestricted key with allowExternalMu");
    flush_context(&mut sim, handle).unwrap();
    for attributes in [
        signing | TpmaObject::RESTRICTED,
        signing | TpmaObject::X509_SIGN,
    ] {
        let rc = try_create_primary(
            &mut sim,
            mldsa_public(TpmiMldsaParms::Mldsa44, attributes, true),
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

/// TPM2_LoadExternal loads an ML-DSA key pair generated client-side for every parameter set
/// and keeps the given verification key.
#[test]
fn load_external_accepts_client_key_pairs() {
    let mut sim = Tpm::new();
    for parameter_set in MLDSA_PARAMETER_SETS {
        let (seed, public_key) = mldsa_client_key(parameter_set);
        let public = mldsa_public_with_key(parameter_set, external_attrs(), false, &public_key);
        let handle = load_external(
            &mut sim,
            public,
            Some(mldsa_sensitive(&seed)),
            Handle::RH_NULL,
        )
        .unwrap_or_else(|rc| panic!("{parameter_set:?}: LoadExternal failed: {rc:#x}"));
        let read = read_public(&mut sim, handle).unwrap();
        assert_eq!(mldsa_public_key(&read.out_public.0).1, public_key);
        flush_context(&mut sim, handle).unwrap();
    }
}

/// TPM2_LoadExternal rejects an ML-DSA seed that is not 32 bytes with TPM_RC_SIZE + P1: the
/// size of a `TPM2B_PRIVATE_KEY_MLDSA` "shall be 32" (TPM 2.0 Part 2), so another size fails to unmarshal.
#[test]
fn load_external_rejects_seed_of_wrong_size() {
    let mut sim = Tpm::new();
    let (seed, public_key) = mldsa_client_key(TpmiMldsaParms::Mldsa44);
    let public = mldsa_public_with_key(
        TpmiMldsaParms::Mldsa44,
        external_attrs(),
        false,
        &public_key,
    );
    for size in [0, 16, 31] {
        assert_eq!(
            load_external(
                &mut sim,
                public,
                Some(mldsa_sensitive(&seed[..size])),
                Handle::RH_NULL,
            ),
            Err(TpmRc::SIZE.with(Position::parameter(1)).get()),
            "seed of {size} bytes"
        );
    }
}

/// TPM2_LoadExternal rejects an ML-DSA verification key that does not have the size of the
/// parameter set with TPM_RC_KEY + P2, with and without a private part.
#[test]
fn load_external_rejects_verification_key_of_wrong_size() {
    let mut sim = Tpm::new();
    let (seed, public_key) = mldsa_client_key(TpmiMldsaParms::Mldsa65);
    for parameter_set in [TpmiMldsaParms::Mldsa44, TpmiMldsaParms::Mldsa87] {
        let public = mldsa_public_with_key(parameter_set, external_attrs(), false, &public_key);
        assert_eq!(
            load_external(&mut sim, public, None, Handle::RH_OWNER),
            Err(TpmRc::KEY.with(Position::parameter(2)).get()),
            "public only, {parameter_set:?}"
        );
        assert_eq!(
            load_external(
                &mut sim,
                public,
                Some(mldsa_sensitive(&seed)),
                Handle::RH_NULL
            ),
            Err(TpmRc::KEY.with(Position::parameter(2)).get()),
            "key pair, {parameter_set:?}"
        );
    }
}

/// TPM2_LoadExternal rejects an ML-DSA seed that does not generate the given verification key
/// with a bare TPM_RC_BINDING.
#[test]
fn load_external_rejects_mismatched_seed() {
    let mut sim = Tpm::new();
    let (_, public_key) = mldsa_client_key(TpmiMldsaParms::Mldsa87);
    let (other_seed, _) = mldsa_client_key(TpmiMldsaParms::Mldsa87);
    let public = mldsa_public_with_key(
        TpmiMldsaParms::Mldsa87,
        external_attrs(),
        false,
        &public_key,
    );
    assert_eq!(
        load_external(
            &mut sim,
            public,
            Some(mldsa_sensitive(&other_seed)),
            Handle::RH_NULL
        ),
        Err(rc_bare(TpmRc::BINDING))
    );
}

/// TPM2_Sign does not support ML-DSA keys (TPM 2.0 Part 3, signing commands overview): with a
/// NULL or an ML-DSA scheme it fails with TPM_RC_SCHEME + P2.
#[test]
fn sign_rejects_mldsa_keys() {
    let mut sim = Tpm::new();
    for parameter_set in MLDSA_PARAMETER_SETS {
        let (key, _) =
            create_primary_returning_public(&mut sim, mldsa_signing_public(parameter_set), &[]);
        for scheme in [None, Some(TpmtSigScheme::Mldsa)] {
            assert_eq!(
                sign(&mut sim, key, &[], &[0x11; 32], scheme).map(|_| ()),
                Err(TpmRc::SCHEME.with(Position::parameter(2)).get()),
                "{parameter_set:?} {scheme:?}"
            );
        }
        flush_context(&mut sim, key).unwrap();
    }
}

/// TPM2_VerifySignature does not support ML-DSA keys: a valid pure ML-DSA signature of the
/// digest fails with TPM_RC_SCHEME + P2.
#[test]
fn verify_signature_rejects_mldsa_keys() {
    let mut sim = Tpm::new();
    let parameter_set = TpmiMldsaParms::Mldsa44;
    let (seed, public_key) = mldsa_client_key(parameter_set);
    let public = mldsa_public_with_key(parameter_set, external_attrs(), false, &public_key);
    let key = load_external(&mut sim, public, None, Handle::RH_OWNER).unwrap();
    let digest = [0x22u8; 32];
    let signature = mldsa_client_sign(parameter_set, &seed, &[], &digest);
    assert_eq!(
        verify_signature(
            &mut sim,
            key,
            leak_bytes(&digest),
            mldsa_signature(&signature)
        )
        .map(|_| ()),
        Err(TpmRc::SCHEME.with(Position::parameter(2)).get())
    );
}

/// An ML-DSA-87 key survives TPM2_ContextSave / TPM2_FlushContext / TPM2_ContextLoad with the
/// same Name.
#[test]
fn context_save_and_load_round_trip() {
    let mut sim = Tpm::new();
    let srk = create_srk(&mut sim);
    let (private, public) = create_child(
        &mut sim,
        srk,
        mldsa_signing_public(TpmiMldsaParms::Mldsa87),
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

/// HashML-DSA keys (`TPM_ALG_HASH_MLDSA`): TPM2_TestParms accepts every parameter set with
/// SHA-256 and SHA-384, and primary keys are created with the verification key size of their
/// parameter set.
#[cfg(feature = "hash_mldsa")]
#[test]
fn hash_mldsa_keys_create() {
    use tpm2::{
        PublicParmsAndId, Tpm2bDigest, Tpm2bPublicKeyMldsa, TpmiAlgHash, TpmsHashMldsaParms,
    };
    let mut sim = Tpm::new();
    for parameter_set in MLDSA_PARAMETER_SETS {
        for hash_alg in [TpmiAlgHash::Sha256, TpmiAlgHash::Sha384] {
            let parms = TpmsHashMldsaParms {
                parameter_set,
                hash_alg,
            };
            assert_eq!(
                execute_test_parms(&mut sim, TpmtPublicParms::HashMldsa(parms)),
                Ok(())
            );
            let template = TpmtPublic {
                name_alg: Some(TpmiAlgHash::Sha256),
                object_attributes: base_attrs() | TpmaObject::SIGN_ENCRYPT,
                auth_policy: Tpm2bDigest::default(),
                parms_and_id: PublicParmsAndId::HashMldsa(parms, Tpm2bPublicKeyMldsa::default()),
            };
            let (handle, public) = create_primary_returning_public(&mut sim, template, &[]);
            assert_eq!(
                mldsa_public_key(&public).1.len(),
                parameter_set.public_key_bytes()
            );
            flush_context(&mut sim, handle).unwrap();
        }
    }
}
