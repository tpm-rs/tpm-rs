//! TPM2_Quote: signing key and scheme checks, HMAC signers and NULL signer.

use crate::_common::*;
use tpm2::commands::{PCREvent, PCRRead, Quote, ReadPublic};
use tpm2::crypto::Asymmetric;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Handle, Tpm2bData, Tpm2bEvent, TpmaObject, TpmiAlgHash, TpmlPcrSelection, TpmtHa,
    TpmtSigScheme, TpmtSignature, TpmuAttest,
};
use tpm2_simulator::create_simulator;

/// Quote with a decrypt-only (non-signing) key fails with KEY/SCHEME.
#[test]
fn decrypt_key_rejected() {
    let mut sim = create_simulator!();
    let (decrypt_handle, _) = create_rsa_primary(&mut sim, TpmaObject::DECRYPT, None);

    let cmd = Quote {
        sign_handle: decrypt_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        pcr_select: pcr0_sha256_selection(),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err == TpmRc::KEY.get()
            || err == TpmRc::SCHEME.get()
            || err == (TpmRc::KEY.get() + 0x100)
            || err == (TpmRc::SCHEME.get() + 0x100),
        "Expected Key or Scheme error, got 0x{:x}",
        err
    );
}

/// A keyed-hash (HMAC) signing key can sign a Quote.
///
/// Keyed-hash (HMAC) signing keys can sign quotes.
#[test]
fn hmac_key_signs_quote() {
    let mut sim = create_simulator!();
    let (_, key) = create_primary_full(
        &mut sim,
        Handle::RH_OWNER,
        hmac_sign_template(),
        b"quote-hmac-key-bits",
    );
    let rsp = quote(&mut sim, key, None).expect("Quote with an HMAC key failed");
    assert!(matches!(rsp.signature, Some(TpmtSignature::Hmac(_))));
}

/// Quote with signHandle TPM_RH_NULL has no hash for the PCR digest: SCHEME+P2.
///
/// With `signHandle == TPM_RH_NULL` the selected scheme is NULL, so `TPM2_Quote` has no hash
/// algorithm for the PCR digest: `TPM_RC_SCHEME + RC_Quote_inScheme` (Quote.c), not success.
#[test]
fn null_sign_handle_is_scheme_error() {
    let mut sim = create_simulator!();
    assert_eq!(
        quote(&mut sim, Handle::RH_NULL, None).err(),
        Some(RC_SCHEME_P2)
    );
    assert_eq!(
        quote(
            &mut sim,
            Handle::RH_NULL,
            Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256))
        )
        .err(),
        Some(RC_SCHEME_P2)
    );
}

/// Quote with signHandle TPM_RH_NULL passes handle validation and fails with TPM_RC_SCHEME + RC_P2
#[test]
fn null_sign_handle_rejected_by_scheme() {
    let mut sim = create_simulator!();
    let cmd = Quote {
        sign_handle: Handle::RH_NULL,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        pcr_select: TpmlPcrSelection::default(),
    };
    // `signHandle` is a `TPMI_DH_OBJECT+`, so TPM_RH_NULL passes handle validation (it used to
    // fail with TPM_RC_VALUE + RC_H1). The C command action then rejects the NULL scheme's
    // TPM_ALG_NULL hash with TPM_RC_SCHEME + RC_P2 (`Quote.c`).
    assert_eq!(
        exec_with_empty_passwords(&mut sim, &cmd, 1).unwrap_err(),
        TpmRc::SCHEME.with(Position::parameter(2)).get()
    );
}

/// The attestation's qualifiedSigner equals the signer's Qualified Name from ReadPublic.
///
/// The attestation's `qualifiedSigner` is the signing key's Qualified Name (as reported by
/// `TPM2_ReadPublic`).
#[test]
fn qualified_signer_matches_read_public() {
    let mut sim = create_simulator!();
    let (signer_handle, _) = create_restricted_signer(&mut sim);

    let rp_cmd = ReadPublic {
        object_handle: signer_handle,
    };
    let rp = execute_with_password_sessions(&mut sim, &rp_cmd, 0, &[]).unwrap();
    let signer_qn = rp.qualified_name;

    let cmd = Quote {
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::from_bytes(&[10, 20]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        pcr_select: pcr0_sha256_selection(),
    };

    let resp = execute_with_password_sessions(&mut sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("Quote failed: {rc:#x}"));
    let attest = resp.quoted.0;
    assert_eq!(attest.qualified_signer.get_buffer(), signer_qn.get_buffer());
}

/// An RSASSA quote attests the expected PCR 0 digest and verifies with the signer's public key.
#[test]
fn rsassa_quote_attests_pcr_digest() {
    let mut sim = create_simulator!();
    let (signer_handle, modulus) = create_restricted_signer(&mut sim);

    // Extend PCR 0 with a test event and read back its value.
    let event = PCREvent {
        pcr_handle: Handle(0),
        event_data: Tpm2bEvent::from_bytes(b"quote test event").unwrap(),
    };
    let mut event_rsp = [0u8; 4096];
    execute_pcr_event(&mut sim, &event, 1, &[], &mut event_rsp)
        .unwrap_or_else(|rc| panic!("PCR_Event failed: {rc:#x}"));
    let pcr_read = execute_with_password_sessions(
        &mut sim,
        &PCRRead {
            pcr_selection_in: pcr0_sha256_selection(),
        },
        0,
        &[],
    )
    .unwrap();
    let pcr0 = pcr_read.pcr_values.digests()[0].get_buffer().to_vec();
    assert_ne!(pcr0, [0u8; 32]);

    let cmd = Quote {
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::from_bytes(&[10, 20, 30]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        pcr_select: pcr0_sha256_selection(),
    };

    let resp = execute_with_password_sessions(&mut sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("Quote failed: {rc:#x}"));

    let attest = resp.quoted.0;
    assert_eq!(attest.extra_data.get_buffer(), &[10, 20, 30]);

    match attest.attested {
        TpmuAttest::Quote(quote_info) => {
            assert_eq!(quote_info.pcr_select, cmd.pcr_select);
            // pcrDigest = H(PCR 0) for a single selected PCR.
            assert_eq!(quote_info.pcr_digest.get_buffer(), sha256_single(&pcr0));
        }
        _ => panic!("Expected Quote attested info"),
    }

    let quoted_bytes = marshal_to_vec(&attest);
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let digest =
        tpm2::crypto::hash(CLIENT_CRYPTO, TpmiAlgHash::Sha256, &quoted_bytes, &mut out).unwrap();
    match resp.signature {
        Some(TpmtSignature::Rsassa(sig)) => {
            assert_eq!(
                CLIENT_CRYPTO.verify_inner(Alg::RSASSA, &modulus, digest, sig.sig.get_buffer()),
                Ok(true),
                "Cryptographic signature verification failed"
            );
        }
        _ => panic!("Expected RSASSA signature"),
    }
}
