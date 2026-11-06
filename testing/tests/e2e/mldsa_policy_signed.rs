//! TPM2_PolicySigned with ML-DSA authorization keys (TPM 2.0 v185): a pure ML-DSA authObject
//! verifies a signature of the message *toBeSigned* = nonceTPM || expiration || cpHashA ||
//! policyRef itself (not a digest of it) with an empty context, for every parameter set; bad,
//! truncated, other-context and digest signatures fail with TPM_RC_SIGNATURE + P5 and
//! signatures of another algorithm with TPM_RC_SCHEME + P5. HashML-DSA authorizations are
//! tested with the `hash_mldsa` feature only.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::PolicySigned;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bDigest, Tpm2bNonce, TpmCc, TpmSt, TpmaObject, TpmiAlgHash, TpmiMldsaParms,
    TpmsSignatureEcc, TpmtSignature,
};

/// The policyRef of every authorization in this file.
const POLICY_REF: &[u8] = b"pqc-policy";

/// An ML-DSA authorization key generated client-side: its seed, verification key and the
/// handle of its public part loaded with TPM2_LoadExternal.
struct AuthKey {
    parameter_set: TpmiMldsaParms,
    seed: Vec<u8>,
    handle: Handle,
}

/// Loads the public part of a fresh client-side ML-DSA key of `parameter_set`.
fn load_auth_key(sim: &mut Tpm, parameter_set: TpmiMldsaParms) -> AuthKey {
    let (seed, public_key) = mldsa_client_key(parameter_set);
    let public = mldsa_public_with_key(
        parameter_set,
        TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
        false,
        &public_key,
    );
    let handle = load_external(sim, public, None, Handle::RH_OWNER).unwrap();
    AuthKey {
        parameter_set,
        seed,
        handle,
    }
}

/// *toBeSigned* of TPM2_PolicySigned with an empty cpHashA and [`POLICY_REF`].
fn to_be_signed(nonce_tpm: &[u8], expiration: i32) -> Vec<u8> {
    [nonce_tpm, &expiration.to_be_bytes(), POLICY_REF].concat()
}

/// Runs TPM2_PolicySigned with `auth_object`, `auth` and an empty cpHashA on `session`.
fn policy_signed_ml(
    sim: &mut Tpm,
    auth_object: Handle,
    session: &ActiveSession,
    expiration: i32,
    auth: TpmtSignature<'static>,
) -> Result<tpm2::commands::responses::PolicySigned<'static>, u32> {
    run_command(
        sim,
        PolicySigned {
            auth_object,
            policy_session: session.session_handle,
            nonce_tpm: session.nonce_tpm,
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::from_bytes(POLICY_REF).unwrap(),
            expiration,
            auth,
        },
    )
}

/// The policy digest after TPM2_PolicySigned with the key of Name `auth_name` and
/// [`POLICY_REF`] on a fresh SHA-256 session.
fn expected_policy_digest(auth_name: &[u8]) -> Vec<u8> {
    let first = sha256(&[
        &[0u8; 32],
        &TpmCc::PolicySigned.code().to_be_bytes(),
        auth_name,
    ]);
    sha256(&[&first, POLICY_REF])
}

/// A pure ML-DSA signature of *toBeSigned* (empty context) authorizes TPM2_PolicySigned for
/// every parameter set and extends the policy digest with the key's Name and policyRef.
#[test]
fn pure_mldsa_signature_authorizes() {
    let mut sim = Tpm::new();
    for parameter_set in MLDSA_PARAMETER_SETS {
        let key = load_auth_key(&mut sim, parameter_set);
        let session = start_policy_session(&mut sim);
        let message = to_be_signed(session.nonce_tpm.get_buffer(), 0);
        let signature = mldsa_client_sign(parameter_set, &key.seed, &[], &message);
        policy_signed_ml(
            &mut sim,
            key.handle,
            &session,
            0,
            mldsa_signature(&signature),
        )
        .unwrap_or_else(|rc| panic!("{parameter_set:?}: PolicySigned failed: {rc:#x}"));
        let auth_name = read_public_name(&mut sim, key.handle);
        assert_eq!(
            policy_digest(&mut sim, session.session_handle),
            expected_policy_digest(auth_name.get_buffer()),
            "{parameter_set:?}"
        );
        flush_context(&mut sim, session.session_handle).unwrap();
        flush_context(&mut sim, key.handle).unwrap();
    }
}

/// An ML-DSA key pair loaded with its private part verifies like a public-only key, and a
/// negative expiration returns a TPM_ST_AUTH_SIGNED ticket.
#[test]
fn key_pair_authorizes_and_returns_ticket() {
    let mut sim = Tpm::new();
    let parameter_set = TpmiMldsaParms::Mldsa65;
    let (seed, public_key) = mldsa_client_key(parameter_set);
    let public = mldsa_public_with_key(
        parameter_set,
        TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
        false,
        &public_key,
    );
    let key = load_external(
        &mut sim,
        public,
        Some(mldsa_sensitive(&seed)),
        Handle::RH_NULL,
    )
    .unwrap();
    let session = start_policy_session(&mut sim);
    let expiration = -60;
    let message = to_be_signed(session.nonce_tpm.get_buffer(), expiration);
    let signature = mldsa_client_sign(parameter_set, &seed, &[], &message);
    let rsp = policy_signed_ml(
        &mut sim,
        key,
        &session,
        expiration,
        mldsa_signature(&signature),
    )
    .unwrap();
    assert_eq!(rsp.policy_ticket.tag(), TpmSt::AUTH_SIGNED.into());
    assert_ne!(rsp.policy_ticket.digest().get_size(), 0);
}

/// Signatures that do not verify fail with TPM_RC_SIGNATURE + P5: a modified signature, a
/// truncated one, one with a non-empty context, one of the SHA-256 digest of *toBeSigned*
/// (as ECDSA keys sign), and one of a stale nonce.
#[test]
fn invalid_signatures_rejected() {
    let mut sim = Tpm::new();
    let key = load_auth_key(&mut sim, TpmiMldsaParms::Mldsa44);
    let session = start_policy_session(&mut sim);
    let message = to_be_signed(session.nonce_tpm.get_buffer(), 0);
    let good = mldsa_client_sign(key.parameter_set, &key.seed, &[], &message);
    let mut modified = good.clone();
    modified[100] ^= 0x40;
    let invalid = [
        modified,
        good[..good.len() - 1].to_vec(),
        mldsa_client_sign(key.parameter_set, &key.seed, b"ctx", &message),
        mldsa_client_sign(key.parameter_set, &key.seed, &[], &sha256(&[&message])),
        mldsa_client_sign(
            key.parameter_set,
            &key.seed,
            &[],
            &to_be_signed(&[0x55; 16], 0),
        ),
    ];
    for (i, signature) in invalid.into_iter().enumerate() {
        assert_eq!(
            policy_signed_ml(
                &mut sim,
                key.handle,
                &session,
                0,
                mldsa_signature(&signature)
            )
            .map(|_| ()),
            Err(TpmRc::SIGNATURE.with(Position::parameter(5)).get()),
            "invalid signature {i}"
        );
    }
    // The session is unchanged and the valid signature still authorizes.
    assert_eq!(policy_digest(&mut sim, session.session_handle), [0u8; 32]);
    policy_signed_ml(&mut sim, key.handle, &session, 0, mldsa_signature(&good)).unwrap();
}

/// An ECDSA signature with an ML-DSA authObject, and an ML-DSA signature with an ECC
/// authObject, fail with TPM_RC_SCHEME + P5.
#[test]
fn signature_of_other_algorithm_rejected() {
    let mut sim = Tpm::new();
    let key = load_auth_key(&mut sim, TpmiMldsaParms::Mldsa44);
    let session = start_policy_session(&mut sim);
    let ecdsa = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: tpm2::Tpm2bEccParameter::from_bytes(&[1; 32]).unwrap(),
        signature_s: tpm2::Tpm2bEccParameter::from_bytes(&[2; 32]).unwrap(),
    });
    assert_eq!(
        policy_signed_ml(&mut sim, key.handle, &session, 0, ecdsa).map(|_| ()),
        Err(TpmRc::SCHEME.with(Position::parameter(5)).get())
    );

    let ecc = load_ecc_with_private(
        &mut sim,
        TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
    );
    let message = to_be_signed(session.nonce_tpm.get_buffer(), 0);
    let signature = mldsa_client_sign(key.parameter_set, &key.seed, &[], &message);
    assert_eq!(
        policy_signed_ml(&mut sim, ecc, &session, 0, mldsa_signature(&signature)).map(|_| ()),
        Err(TpmRc::SCHEME.with(Position::parameter(5)).get())
    );
}

/// A HashML-DSA signature of the digest of *toBeSigned* (computed with the signature's hash
/// algorithm, empty context) authorizes TPM2_PolicySigned with a HashML-DSA authObject.
#[cfg(feature = "hash_mldsa")]
#[test]
fn hash_mldsa_signature_authorizes() {
    use tpm2::{
        PublicParmsAndId, Tpm2bPublicKeyMldsa, Tpm2bSignatureMldsa, TpmsHashMldsaParms,
        TpmsSignatureHashMldsa, TpmtPublic,
    };
    let mut sim = Tpm::new();
    let parameter_set = TpmiMldsaParms::Mldsa44;
    let hash_alg = TpmiAlgHash::Sha384;
    let (seed, public_key) = mldsa_client_key(parameter_set);
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::HashMldsa(
            TpmsHashMldsaParms {
                parameter_set,
                hash_alg,
            },
            Tpm2bPublicKeyMldsa::from_bytes(leak_bytes(&public_key)).unwrap(),
        ),
    };
    let key = load_external(&mut sim, public, None, Handle::RH_OWNER).unwrap();
    let session = start_policy_session(&mut sim);
    let message = to_be_signed(session.nonce_tpm.get_buffer(), 0);
    let digest = compute_hash(hash_alg, &[&message]);
    let mu = hash_mldsa_mu(&public_key, hash_alg, &digest);
    let signature = mldsa_client_sign_mu(parameter_set, &seed, &mu);
    let auth = TpmtSignature::HashMldsa(TpmsSignatureHashMldsa {
        hash: hash_alg,
        signature: Tpm2bSignatureMldsa::from_bytes(leak_bytes(&signature)).unwrap(),
    });
    policy_signed_ml(&mut sim, key, &session, 0, auth).unwrap();
    let auth_name = read_public_name(&mut sim, key);
    assert_eq!(
        policy_digest(&mut sim, session.session_handle),
        expected_policy_digest(auth_name.get_buffer())
    );
}
