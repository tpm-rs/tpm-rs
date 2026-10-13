//! Signing key and signing scheme checks (with response-code positions) shared by the attestation
//! commands (Certify, Quote, ...).

use crate::_common::{
    RC_KEY, RC_KEY_H1, RC_KEY_H2, RC_SCHEME, RC_SCHEME_P2, certify, create_primary_in,
    ecc_sign_template_with_scheme, execute_with_password_sessions_status, quote,
    rsa_decrypt_template, rsa_sign_template,
};
use tpm2::commands::GetCommandAuditDigest;
use tpm2::{
    Handle, Tpm2bData, TpmiAlgHash, TpmsSchemeEcdaa, TpmtEccScheme, TpmtRsaScheme, TpmtSigScheme,
};
use tpm2_simulator::create_simulator;

/// Certify with a non-signing key fails with KEY+H2.
///
/// `TPM2_Certify` with a non-signing key: `TPM_RC_KEY + RC_Certify_signHandle` (H2).
#[test]
fn certify_non_signing_key_position() {
    let mut sim = create_simulator!();
    let object = create_primary_in(&mut sim, Handle::RH_OWNER, rsa_sign_template(None));
    let decrypt_key = create_primary_in(&mut sim, Handle::RH_OWNER, rsa_decrypt_template());
    assert_eq!(
        certify(&mut sim, object, decrypt_key, None).err(),
        Some(RC_KEY_H2)
    );
}

/// A key with ECDAA default scheme requires an explicit inScheme: SCHEME+P2 on Certify.
///
/// A key whose default scheme is the split-signing ECDAA scheme requires an explicit
/// `inScheme`: `TPM_RC_SCHEME + RC_Certify_inScheme`.
#[test]
fn ecdaa_default_scheme_needs_explicit_scheme() {
    let mut sim = create_simulator!();
    let object = create_primary_in(&mut sim, Handle::RH_OWNER, rsa_sign_template(None));
    let ecdaa_key = create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template_with_scheme(Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: 0,
        }))),
    );
    assert_eq!(
        certify(&mut sim, object, ecdaa_key, None).err(),
        Some(RC_SCHEME_P2)
    );
}

/// Quote with a non-signing key is KEY+H1, with a scheme mismatch SCHEME+P2.
///
/// A non-signing key fails with `TPM_RC_KEY + RC_Quote_signHandle` (H1), a scheme mismatch with
/// `TPM_RC_SCHEME + RC_Quote_inScheme` (P2).
#[test]
fn quote_key_and_scheme_positions() {
    let mut sim = create_simulator!();
    let decrypt_key = create_primary_in(&mut sim, Handle::RH_OWNER, rsa_decrypt_template());
    let err = quote(&mut sim, decrypt_key, None).err();
    assert_eq!(err, Some(RC_KEY_H1));
    assert_ne!(err, Some(RC_KEY));

    let sign_key = create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    let err = quote(
        &mut sim,
        sign_key,
        Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256)),
    )
    .err();
    assert_eq!(err, Some(RC_SCHEME_P2));
    assert_ne!(err, Some(RC_SCHEME));
}

/// Every attestation command reports scheme errors at its inScheme position.
///
/// Every attestation command reports the scheme error at its `inScheme` position.
#[test]
fn scheme_error_at_in_scheme_position() {
    let mut sim = create_simulator!();
    let key = create_primary_in(
        &mut sim,
        Handle::RH_ENDORSEMENT,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    let wrong = Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256));
    assert_eq!(certify(&mut sim, key, key, wrong).err(), Some(RC_SCHEME_P2));
    assert_eq!(quote(&mut sim, key, wrong).err(), Some(RC_SCHEME_P2));

    let cmd = GetCommandAuditDigest {
        privacy_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key,
        qualifying_data: Tpm2bData::default(),
        in_scheme: wrong,
    };
    assert_eq!(
        execute_with_password_sessions_status(&mut sim, &cmd, 2, &[]).err(),
        Some(RC_SCHEME_P2)
    );

    // A scheme-less key with a non-signing input scheme is equally a scheme error.
    let schemeless = create_primary_in(&mut sim, Handle::RH_OWNER, rsa_sign_template(None));
    assert_eq!(
        certify(
            &mut sim,
            key,
            schemeless,
            Some(TpmtSigScheme::Hmac(TpmiAlgHash::Sha256))
        )
        .err(),
        Some(RC_SCHEME_P2)
    );
}
