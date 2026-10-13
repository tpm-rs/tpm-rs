//! End-to-end regression tests for the `crypto` findings in command-handlers.toml.
//!
//! Owned by the `fix-crypto` worker; add submodules under `findings_crypto/` if this grows.
//!
//! Every test is named after the finding id it guards (dashes replaced by underscores) and is
//! strictly black-box: all TPM interaction goes through the simulator's command interface.

#![allow(unused_imports)]

use crate::test_utils::*;
use tpm2::commands::{
    Command, Commit, CreatePrimary, ECDHKeyGen, ECDHZGen, EventSequenceComplete, EvictControl,
    HMAC, HMACStart, HashSequenceStart, LoadExternal, PCRRead, PolicyAuthorize, RSADecrypt,
    RSAEncrypt, SequenceComplete, SequenceUpdate,
};
#[allow(deprecated)]
use tpm2::commands::{EncryptDecrypt, Sign, VerifySignature};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::{Simulator, create_simulator};

// ----------------------------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------------------------

/// Returns the raw response code of a positioned format-one error.
fn rc_at(rc: tpm2::errors::Fmt1, pos: Position) -> u32 {
    rc.with(pos).get()
}

/// Returns the raw response code of a bare format-one error.
fn rc_bare(rc: tpm2::errors::Fmt1) -> u32 {
    rc.to_rc().get()
}

/// Creates a primary object from `public` in `hierarchy` (empty hierarchy auth) and returns its
/// handle.
fn create_primary(
    sim: &mut Simulator<'_>,
    hierarchy: Handle,
    public: TpmtPublic<'static>,
    user_auth: &'static [u8],
) -> Handle {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(user_auth).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(public),
        ..Default::default()
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("CreatePrimary failed");
    rsp.object_handle
}

/// Default attributes of a TPM-generated key with password (userWithAuth) authorization.
fn base_attrs() -> TpmaObject {
    TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
}

/// An ECC NIST P-256 key template.
fn ecc_template(attrs: TpmaObject, scheme: Option<TpmtEccScheme>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// An ECC P-256 restricted decryption (storage) key template.
fn ecc_storage_template() -> TpmtPublic<'static> {
    let mut t = ecc_template(
        base_attrs() | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
        None,
    );
    if let PublicParmsAndId::Ecc(parms, _) = &mut t.parms_and_id {
        parms.symmetric = Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgCipherMode::Cfb.into()),
        });
    }
    t
}

/// An ECDAA (SHA-256) NIST P-256 signing key template.
fn ecdaa_template(attrs: TpmaObject) -> TpmtPublic<'static> {
    ecc_template(
        attrs,
        Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: 0,
        })),
    )
}

/// An RSA-2048 key template.
fn rsa_template(
    attrs: TpmaObject,
    scheme: Option<TpmtRsaScheme>,
    symmetric: Option<TpmtSymDefObject>,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric,
                scheme,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// A keyed-hash (HMAC) key template.
fn hmac_template(attrs: TpmaObject, scheme: Option<TpmtKeyedHashScheme>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(scheme, Tpm2bDigest::default()),
    }
}

/// An AES-128-CFB symmetric cipher key template.
fn sym_template(attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
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

/// Marshals `num_sessions` password sessions carrying `auth` (the authorization area without
/// its size field).
fn password_sessions(num_sessions: usize, auth: &[u8]) -> Vec<u8> {
    let auth_cmd = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
    };
    marshal_to_vec(&auth_cmd).repeat(num_sessions)
}

/// Sends `cmd` (with its handles) with optional password sessions, appending `trailing` bytes
/// after the parameters (the command size covers them), and returns the response code.
fn send_with_trailing<CmdT: Command>(
    sim: &mut Simulator<'_>,
    cmd: &CmdT,
    num_sessions: usize,
    auth: &[u8],
    trailing: &[u8],
) -> u32
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut buf = vec![0u8; 10];
    for handle in cmd.handles().as_ref() {
        buf.extend_from_slice(&handle.0.to_be_bytes());
    }
    if num_sessions > 0 {
        let area = password_sessions(num_sessions, auth);
        buf.extend_from_slice(&(area.len() as u32).to_be_bytes());
        buf.extend_from_slice(&area);
    }
    buf.extend_from_slice(&marshal_to_vec(cmd));
    buf.extend_from_slice(trailing);
    let header = CmdHeader {
        tag: if num_sessions > 0 {
            TpmiStCommandTag::Sessions
        } else {
            TpmiStCommandTag::NoSessions
        },
        size: buf.len() as u32,
        code: CmdT::CMD_CODE,
    };
    let mut header_buf = [0u8; 10];
    header.marshal((&mut header_buf[..]).try_into().unwrap());
    buf[..10].copy_from_slice(&header_buf);
    let mut rsp = [0u8; 4096];
    sim.transact(&buf, &mut rsp).unwrap();
    let mut slice = &rsp[..];
    RespHeader::unmarshal(&mut slice).unwrap().rc
}

/// Computes a SHA-256 digest client-side.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut state = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    state.update(data).unwrap();
    out.copy_from_slice(state.finalize(&mut [0u8; 64]).unwrap().digest());
    out
}

/// Runs TPM2_Sign with one password session.
#[allow(deprecated)]
fn sign(
    sim: &mut Simulator<'_>,
    key: Handle,
    auth: &[u8],
    digest: &'static [u8],
    in_scheme: Option<TpmtSigScheme>,
) -> Result<TpmtSignature<'static>, u32> {
    let cmd = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(digest).unwrap(),
        in_scheme,
        validation: TpmtTkHashcheck::new(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    execute_with_password_sessions(sim, &cmd, 1, auth).map(|rsp| rsp.signature)
}

/// Runs TPM2_VerifySignature (no sessions).
#[allow(deprecated)]
fn verify_signature(
    sim: &mut Simulator<'_>,
    key: Handle,
    digest: &'static [u8],
    signature: TpmtSignature<'static>,
) -> Result<TpmtTkVerified<'static>, u32> {
    let cmd = VerifySignature {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(digest).unwrap(),
        signature,
    };
    execute_with_password_sessions(sim, &cmd, 0, &[]).map(|rsp| rsp.validation)
}

/// Runs TPM2_Commit without P1/P2 and returns the commit counter.
fn commit(sim: &mut Simulator<'_>, key: Handle, auth: &[u8]) -> Result<u16, u32> {
    let cmd = Commit {
        sign_handle: key,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    execute_with_password_sessions(sim, &cmd, 1, auth).map(|rsp| rsp.counter)
}

/// The ECDAA signing scheme for commit `count`.
fn ecdaa_scheme(count: u16) -> Option<TpmtSigScheme> {
    Some(TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
        hash_alg: TpmiAlgHash::Sha256,
        count,
    }))
}

/// Starts a hash (or event, for `None`) sequence with an empty auth value.
fn start_hash_sequence(sim: &mut Simulator<'_>, alg: Option<TpmiAlgHash>) -> Handle {
    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: alg,
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 0, &[]).unwrap();
    rsp.sequence_handle
}

/// Feeds `data` into a sequence.
fn sequence_update(sim: &mut Simulator<'_>, seq: Handle, data: &'static [u8]) -> Result<(), u32> {
    let cmd = SequenceUpdate {
        sequence_handle: seq,
        buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map(|_| ())
}

/// Completes a hash sequence for `hierarchy`.
fn sequence_complete(
    sim: &mut Simulator<'_>,
    seq: Handle,
    data: &'static [u8],
    hierarchy: Handle,
) -> Result<TpmtTkHashcheck<'static>, u32> {
    let cmd = SequenceComplete {
        sequence_handle: seq,
        buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hierarchy,
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map(|rsp| rsp.validation)
}

/// Completes an event sequence, extending `pcr` (or `TPM_RH_NULL`).
fn event_sequence_complete(
    sim: &mut Simulator<'_>,
    pcr: Handle,
    seq: Handle,
    data: &'static [u8],
) -> Result<usize, u32> {
    let cmd = EventSequenceComplete {
        pcr_handle: pcr,
        sequence_handle: seq,
        buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
    };
    execute_with_password_sessions(sim, &cmd, 2, &[]).map(|rsp| rsp.results.digests().count())
}

/// Reads the PCR update counter.
fn pcr_update_counter(sim: &mut Simulator<'_>) -> u32 {
    sim.execute(PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    })
    .unwrap()
    .pcr_update_counter
}

/// Returns the number of PCR banks in which `pcr` is allocated (`TPM_CAP_PCRS`).
fn allocated_banks_for_pcr(sim: &mut Simulator<'_>, pcr: usize) -> u32 {
    let cmd = tpm2::commands::GetCapability {
        capability: TpmCap::PCRs,
        property: 0,
        property_count: 16,
    };
    let mut buf = [0u8; 4096];
    let rsp = execute_get_capability(sim, &cmd, 0, &[], &mut buf).unwrap();
    match rsp.capability_data {
        TpmsCapabilityData::AssignedPcr(sel) => sel
            .pcr_selections()
            .filter(|s| {
                s.pcr_select()
                    .get(pcr / 8)
                    .is_some_and(|b| b & (1 << (pcr % 8)) != 0)
            })
            .count() as u32,
        _ => panic!("unexpected capability data"),
    }
}

/// Returns `true` if `ticket` is the NULL hashcheck ticket.
fn is_null_hashcheck(ticket: &TpmtTkHashcheck<'_>) -> bool {
    ticket.hierarchy() == Handle::RH_NULL && ticket.digest().get_size() == 0
}

// ----------------------------------------------------------------------------------------------
// TPM2_VerifySignature
// ----------------------------------------------------------------------------------------------

/// Signs `digest` with a new HMAC key in `hierarchy` and returns the key and signature.
fn hmac_key_and_signature(
    sim: &mut Simulator<'_>,
    hierarchy: Handle,
    digest: &'static [u8],
) -> (Handle, TpmtSignature<'static>) {
    let key = create_primary(
        sim,
        hierarchy,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let signature = sign(sim, key, b"", digest, None).expect("HMAC sign failed");
    (key, signature)
}

/// HMAC-key tickets must be real `TicketComputeVerified` tickets: one produced over
/// `aHash = H(approvedPolicy || policyRef)` is accepted by TPM2_PolicyAuthorize.
#[test]
fn tpm2_verifysignature_accepts_tpm_alg_null_produces_hmac_ticket_validates() {
    let mut sim = create_simulator!();

    // Fresh policy session: policyDigest is all zeros; approve exactly that digest.
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let approved: &'static [u8] = leak_bytes(&[0u8; 32]);
    let a_hash: &'static [u8] = leak_bytes(&sha256(approved));

    let (key, signature) = hmac_key_and_signature(&mut sim, Handle::RH_OWNER, a_hash);
    let ticket = verify_signature(&mut sim, key, a_hash, signature).expect("verify failed");
    match &ticket {
        TpmtTkVerified::Verified(h, d) => {
            assert_eq!(*h, Handle::RH_OWNER);
            assert_eq!(d.get_size(), 32);
            assert_ne!(d.get_buffer(), a_hash, "ticket must not be the raw digest");
        }
        _ => panic!("unexpected ticket tag"),
    }

    let key_name = read_public_name(&mut sim, key);
    let cmd = PolicyAuthorize {
        policy_session: session.session_handle,
        approved_policy: Tpm2bDigest::from_bytes(approved).unwrap(),
        policy_ref: Tpm2bNonce::default(),
        key_sign: key_name,
        check_ticket: ticket,
    };
    execute_with_password_sessions(&mut sim, &cmd, 0, &[])
        .expect("PolicyAuthorize must accept the HMAC-key ticket");
}

/// An HMAC key in the NULL hierarchy yields the NULL ticket (empty digest).
#[test]
fn verify_signature_null_scheme_and_public_only_keyedhash_bypass_null_hierarchy_ticket() {
    let mut sim = create_simulator!();
    let digest: &'static [u8] = leak_bytes(&[0x11; 32]);
    let (key, signature) = hmac_key_and_signature(&mut sim, Handle::RH_NULL, digest);
    let ticket = verify_signature(&mut sim, key, digest, signature).unwrap();
    match ticket {
        TpmtTkVerified::Verified(h, d) => {
            assert_eq!(h, Handle::RH_NULL);
            assert_eq!(d.get_size(), 0);
        }
        _ => panic!("unexpected ticket tag"),
    }
}

/// Signature validation errors carry `RC_VerifySignature_signature` (parameter 2); a key
/// without `sign` is `TPM_RC_ATTRIBUTES + RC_H1`.
#[test]
fn verify_signature_null_scheme_and_public_only_keyedhash_bypass_error_positions() {
    let mut sim = create_simulator!();
    let digest: &'static [u8] = leak_bytes(&[0x22; 32]);
    let (key, signature) = hmac_key_and_signature(&mut sim, Handle::RH_OWNER, digest);

    // Wrong HMAC value -> TPM_RC_SIGNATURE + RC_P2.
    let bad_sig = match signature {
        TpmtSignature::Hmac(ha) => {
            let mut bytes = ha.digest().to_vec();
            bytes[0] ^= 1;
            TpmtSignature::Hmac(TpmtHa::new(ha.hash_alg(), leak_bytes(&bytes)).unwrap())
        }
        _ => unreachable!(),
    };
    assert_eq!(
        verify_signature(&mut sim, key, digest, bad_sig).unwrap_err(),
        rc_at(TpmRc::SIGNATURE, Position::parameter(2))
    );

    // ECDSA signature for an HMAC key -> TPM_RC_SCHEME + RC_P2.
    let ecdsa = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
        signature_s: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
    });
    assert_eq!(
        verify_signature(&mut sim, key, digest, ecdsa).unwrap_err(),
        rc_at(TpmRc::SCHEME, Position::parameter(2))
    );

    // A decrypt-only key is not a signing key -> TPM_RC_ATTRIBUTES + RC_H1.
    let storage = create_primary(&mut sim, Handle::RH_OWNER, ecc_storage_template(), b"");
    let ecdsa = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
        signature_s: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
    });
    assert_eq!(
        verify_signature(&mut sim, storage, digest, ecdsa).unwrap_err(),
        rc_at(TpmRc::ATTRIBUTES, Position::handle(1))
    );
}

/// ECC signature errors: invalid ECDSA values are `TPM_RC_SIGNATURE + RC_P2`, and an ECDAA
/// signature can't be verified (`TPM_RC_SCHEME + RC_P2`, as in `CryptEccValidateSignature`).
#[test]
fn verify_signature_and_sign_ecschnorr_sm2_omission_and_ecdaa_verification_bug() {
    let mut sim = create_simulator!();
    let key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let digest: &'static [u8] = leak_bytes(&[0x33; 32]);
    let good = sign(&mut sim, key, b"", digest, None).expect("ECDSA sign failed");
    verify_signature(&mut sim, key, digest, good).expect("valid ECDSA must verify");

    // The same (r, s) presented as an ECDAA signature must be rejected with SCHEME + P2.
    let (r, s) = match &good {
        TpmtSignature::Ecdsa(sig) => (sig.signature_r, sig.signature_s),
        _ => unreachable!(),
    };
    let ecdaa = TpmtSignature::Ecdaa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: r,
        signature_s: s,
    });
    assert_eq!(
        verify_signature(&mut sim, key, digest, ecdaa).unwrap_err(),
        rc_at(TpmRc::SCHEME, Position::parameter(2))
    );

    // r == 0 -> TPM_RC_SIGNATURE + RC_P2 (not RC_H2).
    let zero_r = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: Tpm2bEccParameter::default(),
        signature_s: s,
    });
    assert_eq!(
        verify_signature(&mut sim, key, digest, zero_r).unwrap_err(),
        rc_at(TpmRc::SIGNATURE, Position::parameter(2))
    );
}

// ----------------------------------------------------------------------------------------------
// Trailing bytes (crypt_ops handlers)
// ----------------------------------------------------------------------------------------------

/// Trailing parameter bytes are a `TPM_RC_SIZE` error that wins over execution errors.
#[test]
#[allow(deprecated)]
fn crypt_ops_and_startup_unmarshal_trailing_bytes_and_validation_order() {
    let mut sim = create_simulator!();
    let key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let size = rc_bare(TpmRc::SIZE);

    // VerifySignature with an invalid signature + 1 trailing byte.
    let verify = VerifySignature {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(&[0x44; 32]).unwrap(),
        signature: TpmtSignature::Ecdsa(TpmsSignatureEcc {
            hash: TpmiAlgHash::Sha256,
            signature_r: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
            signature_s: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
        }),
    };
    assert_eq!(send_with_trailing(&mut sim, &verify, 0, &[], &[0]), size);

    // Sign with a wrong digest size + trailing byte.
    let sign_cmd = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(&[0x44; 7]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::new(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    assert_eq!(send_with_trailing(&mut sim, &sign_cmd, 1, &[], &[0]), size);

    // RSA_Encrypt / RSA_Decrypt on an ECC key (TPM_RC_KEY) + trailing byte.
    let enc = RSAEncrypt {
        key_handle: key,
        message: Tpm2bPublicKeyRsa::from_bytes(b"msg").unwrap(),
        in_scheme: None,
        label: Tpm2bData::default(),
    };
    assert_eq!(send_with_trailing(&mut sim, &enc, 0, &[], &[0]), size);
    let dec = RSADecrypt {
        key_handle: key,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(b"msg").unwrap(),
        in_scheme: None,
        label: Tpm2bData::default(),
    };
    assert_eq!(send_with_trailing(&mut sim, &dec, 1, &[], &[0]), size);
}

// ----------------------------------------------------------------------------------------------
// TPM2_Commit / ECDAA TPM2_Sign
// ----------------------------------------------------------------------------------------------

/// The counter returned by TPM2_Commit signs exactly once; reusing it fails with
/// `TPM_RC_VALUE` (no ECDAA nonce reuse).
#[test]
#[cfg_attr(
    feature = "crux",
    ignore = "crux backend has no ECDAA sign (ecdaa_sign is unsupported)"
)]
fn tpm2_commit_and_sign_ecdaa_counter_mismatch_and_nonce_reuse() {
    let mut sim = create_simulator!();
    let key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecdaa_template(base_attrs() | TpmaObject::SIGN_ENCRYPT),
        b"pw",
    );
    let count = commit(&mut sim, key, b"pw").expect("commit failed");

    let d1: &'static [u8] = leak_bytes(&[0x55; 32]);
    let d2: &'static [u8] = leak_bytes(&[0x66; 32]);
    let sig = sign(&mut sim, key, b"pw", d1, ecdaa_scheme(count))
        .expect("signing with the committed counter must succeed");
    assert!(matches!(sig, TpmtSignature::Ecdaa(_)));

    // Second signature with the same commitment (same r) must be refused.
    assert_eq!(
        sign(&mut sim, key, b"pw", d2, ecdaa_scheme(count)).unwrap_err(),
        rc_bare(TpmRc::VALUE)
    );
    // A counter that was never committed is refused as well.
    assert_eq!(
        sign(
            &mut sim,
            key,
            b"pw",
            d2,
            ecdaa_scheme(count.wrapping_add(1))
        )
        .unwrap_err(),
        rc_bare(TpmRc::VALUE)
    );

    // A new commitment can be used once.
    let count2 = commit(&mut sim, key, b"pw").unwrap();
    assert_eq!(count2, count.wrapping_add(1));
    sign(&mut sim, key, b"pw", d2, ecdaa_scheme(count2)).expect("fresh commit must sign");
}

/// ECDAA default scheme with a NULL `inScheme`, invalid hashes and scheme mismatches are
/// `TPM_RC_SCHEME + RC_P2`; non-signing (symmetric) keys are `TPM_RC_KEY + RC_H1`.
#[test]
fn tpm2_sign_ecdaa_commit_reuse_and_scheme_validation_bugs() {
    let mut sim = create_simulator!();
    let ecdaa_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecdaa_template(base_attrs() | TpmaObject::SIGN_ENCRYPT),
        b"",
    );
    let digest: &'static [u8] = leak_bytes(&[0x77; 32]);
    let scheme_p2 = rc_at(TpmRc::SCHEME, Position::parameter(2));

    // Split-signing default scheme requires an explicit inScheme.
    assert_eq!(
        sign(&mut sim, ecdaa_key, b"", digest, None).unwrap_err(),
        scheme_p2
    );
    // Mismatching scheme.
    assert_eq!(
        sign(
            &mut sim,
            ecdaa_key,
            b"",
            digest,
            Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256))
        )
        .unwrap_err(),
        scheme_p2
    );

    // Scheme-less ECC key with an RSA scheme -> SCHEME + P2.
    let ecc_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(base_attrs() | TpmaObject::SIGN_ENCRYPT, None),
        b"",
    );
    assert_eq!(
        sign(
            &mut sim,
            ecc_key,
            b"",
            digest,
            Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256))
        )
        .unwrap_err(),
        scheme_p2
    );

    // Symmetric cipher key with `sign` set is not a signing object.
    let sym_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        sym_template(base_attrs() | TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT),
        b"",
    );
    assert_eq!(
        sign(
            &mut sim,
            sym_key,
            b"",
            digest,
            Some(TpmtSigScheme::Hmac(TpmiAlgHash::Sha256))
        )
        .unwrap_err(),
        rc_at(TpmRc::KEY, Position::handle(1))
    );

    // A decrypt-only key is not a signing object either.
    let storage = create_primary(&mut sim, Handle::RH_OWNER, ecc_storage_template(), b"");
    assert_eq!(
        sign(&mut sim, storage, b"", digest, None).unwrap_err(),
        rc_at(TpmRc::KEY, Position::handle(1))
    );
}

/// TPM2_Commit accepts persistent keys, policy-authorized keys with `userWithAuth` clear, and
/// requires an anonymous (ECDAA) scheme (`TPM_RC_SCHEME + RC_H1`).
#[test]
fn tpm2_commit_rejects_persistent_ecc_keys_rejects() {
    let mut sim = create_simulator!();

    // Persistent ECDAA key.
    let key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecdaa_template(base_attrs() | TpmaObject::SIGN_ENCRYPT),
        b"pw",
    );
    let persistent = Handle(0x8100_0A01);
    execute_with_password_sessions(
        &mut sim,
        &EvictControl {
            auth: Handle::RH_OWNER,
            object_handle: key,
            persistent_handle: persistent,
        },
        1,
        &[],
    )
    .expect("EvictControl failed");
    commit(&mut sim, persistent, b"pw").expect("Commit must accept a persistent ECDAA key");

    // ECDSA key: not an anonymous scheme.
    let ecdsa_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    assert_eq!(
        commit(&mut sim, ecdsa_key, b"").unwrap_err(),
        rc_at(TpmRc::SCHEME, Position::handle(1))
    );

    // Policy-only ECDAA key (userWithAuth clear) authorized with a policy session whose
    // (initial, all-zero) digest matches the key's authPolicy.
    let mut template = ecdaa_template(
        TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
    );
    template.auth_policy = Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap();
    let policy_key = create_primary(&mut sim, Handle::RH_OWNER, template, b"");
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let cmd = Commit {
        sign_handle: policy_key,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    execute_with_hmac_sessions(&mut sim, &cmd, &[], &mut [session], &[b""])
        .expect("Commit must accept a policy-authorized key with userWithAuth clear");
}

/// An unloaded transient `signHandle` is reported as `TPM_RC_REFERENCE_H0`.
#[test]
fn validate_command_handles_off_by_one_position_and_missing_commands_commit() {
    let mut sim = create_simulator!();
    assert_eq!(
        commit(&mut sim, Handle(0x8000_00F0), b"").unwrap_err(),
        TpmRc::REFERENCE_H0.get()
    );
}

// ----------------------------------------------------------------------------------------------
// TPM2_ECDH_KeyGen / TPM2_ECDH_ZGen
// ----------------------------------------------------------------------------------------------

/// ECDH_KeyGen only needs a loaded ECC key: signing / restricted keys are accepted and a
/// non-ECC key is `TPM_RC_KEY + RC_H1`.
#[test]
fn tpm2_ecdh_keygen_erroneously_enforces_restricted_and() {
    let mut sim = create_simulator!();
    let sign_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    sim.execute(ECDHKeyGen {
        key_handle: sign_key,
    })
    .expect("ECDH_KeyGen must accept an ECC signing key");

    let storage = create_primary(&mut sim, Handle::RH_OWNER, ecc_storage_template(), b"");
    sim.execute(ECDHKeyGen {
        key_handle: storage,
    })
    .expect("ECDH_KeyGen must accept a restricted ECC key");
}

/// A non-ECC key without `decrypt` is `TPM_RC_KEY + RC_H1` (type checked first).
#[test]
fn tpm2_ecdh_keygen_attribute_order_and_curve_support_bugs() {
    let mut sim = create_simulator!();
    let hmac_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let err = sim
        .execute(ECDHKeyGen {
            key_handle: hmac_key,
        })
        .unwrap_err();
    assert_eq!(err.get(), rc_at(TpmRc::KEY, Position::handle(1)));
}

/// ECDH_ZGen checks the key type before its attributes and rejects trailing bytes.
#[test]
fn tpm2_hmac_mac_and_ecdh_zgen_validation_order_bugs() {
    let mut sim = create_simulator!();

    // A restricted keyed-hash key: type (KEY) is checked before restricted/decrypt.
    let hmac_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT | TpmaObject::RESTRICTED,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let zgen = ECDHZGen {
        key_handle: hmac_key,
        in_point: Tpm2b(TpmsEccPoint {
            x: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
            y: Tpm2bEccParameter::from_bytes(&[2]).unwrap(),
        }),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &zgen, 1, &[]).unwrap_err(),
        rc_at(TpmRc::KEY, Position::handle(1))
    );

    // TPM2_HMAC: restricted is checked before the hash algorithm selection.
    let hmac = HMAC {
        handle: hmac_key,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha1),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &hmac, 1, &[]).unwrap_err(),
        rc_at(TpmRc::ATTRIBUTES, Position::handle(1))
    );
}

/// ECDH_ZGen rejects trailing parameter bytes with `TPM_RC_SIZE`, and checks the type of a
/// restricted RSA key before its attributes.
#[test]
fn tpm2_evictcontrol_and_ecdh_zgen_mac_validation_and_error_bugs() {
    let mut sim = create_simulator!();
    let storage = create_primary(&mut sim, Handle::RH_OWNER, ecc_storage_template(), b"");
    let zgen = ECDHZGen {
        key_handle: storage,
        in_point: Tpm2b(TpmsEccPoint {
            x: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
            y: Tpm2bEccParameter::from_bytes(&[2]).unwrap(),
        }),
    };
    assert_eq!(
        send_with_trailing(&mut sim, &zgen, 1, &[], &[0]),
        rc_bare(TpmRc::SIZE)
    );
}

// ----------------------------------------------------------------------------------------------
// TPM2_RSA_Encrypt / TPM2_RSA_Decrypt
// ----------------------------------------------------------------------------------------------

/// RSA_Encrypt accepts restricted decryption keys; RSA_Decrypt checks the type first, the
/// ciphertext size, and reports label / scheme errors at parameter positions.
#[test]
fn tpm2_rsa_encrypt_and_tpm2_rsa_decrypt_attribute_and_error_position_bugs() {
    let mut sim = create_simulator!();

    // Restricted RSA storage key: RSA_Encrypt only uses the public part.
    let srk = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        rsa_template(
            base_attrs() | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
            None,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgCipherMode::Cfb.into()),
            }),
        ),
        b"",
    );
    let enc = RSAEncrypt {
        key_handle: srk,
        message: Tpm2bPublicKeyRsa::from_bytes(b"secret").unwrap(),
        in_scheme: Some(TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256)),
        label: Tpm2bData::default(),
    };
    execute_with_password_sessions(&mut sim, &enc, 0, &[])
        .expect("RSA_Encrypt must accept a restricted decryption key");

    // Unterminated label -> TPM_RC_VALUE + RC_P3.
    let enc_bad_label = RSAEncrypt {
        key_handle: srk,
        message: Tpm2bPublicKeyRsa::from_bytes(b"secret").unwrap(),
        in_scheme: Some(TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256)),
        label: Tpm2bData::from_bytes(b"abc").unwrap(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &enc_bad_label, 0, &[]).unwrap_err(),
        rc_at(TpmRc::VALUE, Position::parameter(3))
    );

    // Unrestricted RSA decryption key with an OAEP-SHA256 scheme.
    let dec_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        rsa_template(
            base_attrs() | TpmaObject::DECRYPT,
            Some(TpmtRsaScheme::Oaep(TpmiAlgHash::Sha256)),
            None,
        ),
        b"",
    );
    // Scheme mismatch -> TPM_RC_SCHEME + RC_P2.
    let dec_bad_scheme = RSADecrypt {
        key_handle: dec_key,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[1u8; 256]).unwrap(),
        in_scheme: Some(TpmtRsaDecrypt::Rsaes),
        label: Tpm2bData::default(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &dec_bad_scheme, 1, &[]).unwrap_err(),
        rc_at(TpmRc::SCHEME, Position::parameter(2))
    );
    // Ciphertext not the size of the modulus -> bare TPM_RC_SIZE.
    let dec_short = RSADecrypt {
        key_handle: dec_key,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[1u8; 16]).unwrap(),
        in_scheme: None,
        label: Tpm2bData::default(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &dec_short, 1, &[]).unwrap_err(),
        rc_bare(TpmRc::SIZE)
    );

    // Restricted ECC key: not an RSA key -> TPM_RC_KEY + RC_H1 (type before attributes).
    let ecc_srk = create_primary(&mut sim, Handle::RH_OWNER, ecc_storage_template(), b"");
    let dec = RSADecrypt {
        key_handle: ecc_srk,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[1u8; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bData::default(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &dec, 1, &[]).unwrap_err(),
        rc_at(TpmRc::KEY, Position::handle(1))
    );
    // Restricted RSA key -> TPM_RC_ATTRIBUTES + RC_H1.
    assert_eq!(
        execute_with_password_sessions(
            &mut sim,
            &RSADecrypt {
                key_handle: srk,
                ..dec
            },
            1,
            &[]
        )
        .unwrap_err(),
        rc_at(TpmRc::ATTRIBUTES, Position::handle(1))
    );
}

// ----------------------------------------------------------------------------------------------
// Hash / HMAC / event sequences
// ----------------------------------------------------------------------------------------------

/// `TicketIsSafe` is applied to the first data block only: a short first block (or a short
/// total) yields the NULL ticket; a safe first block yields a real ticket.
#[test]
fn tpm2_sequenceupdate_and_tpm2_sequencecomplete_fail_to() {
    let mut sim = create_simulator!();

    // First block shorter than 4 bytes.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    sequence_update(&mut sim, seq, b"ab").unwrap();
    let ticket = sequence_complete(&mut sim, seq, b"cdefgh", Handle::RH_OWNER).unwrap();
    assert!(
        is_null_hashcheck(&ticket),
        "short first block must not get a ticket"
    );

    // Total data shorter than 4 bytes, no SequenceUpdate.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    let ticket = sequence_complete(&mut sim, seq, b"abc", Handle::RH_OWNER).unwrap();
    assert!(is_null_hashcheck(&ticket));

    // Empty first block.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    sequence_update(&mut sim, seq, b"").unwrap();
    let ticket = sequence_complete(&mut sim, seq, b"abcdefgh", Handle::RH_OWNER).unwrap();
    assert!(is_null_hashcheck(&ticket));

    // Safe first block -> real ticket.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    sequence_update(&mut sim, seq, b"abcd").unwrap();
    let ticket = sequence_complete(&mut sim, seq, b"\xffTCG", Handle::RH_OWNER).unwrap();
    assert_eq!(ticket.hierarchy(), Handle::RH_OWNER);
    assert_eq!(ticket.digest().get_size(), 32);

    // SequenceComplete on an event sequence -> TPM_RC_MODE + RC_H1.
    let ev = start_hash_sequence(&mut sim, None);
    assert_eq!(
        sequence_complete(&mut sim, ev, b"", Handle::RH_NULL).unwrap_err(),
        rc_at(TpmRc::MODE, Position::handle(1))
    );
}

/// Sequences are not limited to 4096 bytes, event sequences report every implemented hash,
/// HMAC_Start checks `restricted` before `sign`, and HashSequenceStart reports RC_P2.
#[test]
fn tpm2_sequence_commands_buffer_limit_sha512_and_macstart_bugs() {
    let mut sim = create_simulator!();

    // > 4096 bytes across SequenceUpdate calls.
    let chunk: &'static [u8] = leak_bytes(&[0x5a; 1024]);
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    for _ in 0..6 {
        sequence_update(&mut sim, seq, chunk).expect("long sequences must be accepted");
    }
    sequence_complete(&mut sim, seq, b"", Handle::RH_NULL).unwrap();

    // Event sequence: SHA-1, SHA-256, SHA-384 and SHA-512 digests.
    let ev = start_hash_sequence(&mut sim, None);
    assert_eq!(
        event_sequence_complete(&mut sim, Handle::RH_NULL, ev, b"event").unwrap(),
        4
    );

    // HMAC_Start with a restricted, non-signing key -> ATTRIBUTES (restricted first).
    let key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
                hash_alg: TpmiAlgHash::Sha256,
                kdf: Some(TpmiAlgKdf::Kdf1Sp800_108),
            })),
        ),
        b"",
    );
    let start = HMACStart {
        handle: key,
        auth: Tpm2bAuth::default(),
        hash_alg: None,
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &start, 1, &[]).unwrap_err(),
        rc_at(TpmRc::ATTRIBUTES, Position::handle(1))
    );
}

/// HMAC_Start / MAC_Start runs the scheme selection before the attribute checks
/// (`MAC_Start.c`): a non-signing key with an incompatible `inScheme` reports
/// `TPM_RC_VALUE + RC_P2`.
#[test]
fn tpm2_mac_start_symcipher_cmac_rejection_and_validation_order_bugs() {
    let mut sim = create_simulator!();
    let key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    // Restricted + mismatching hash: scheme error first.
    let restricted = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT | TpmaObject::RESTRICTED,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    for handle in [key, restricted] {
        let start = HMACStart {
            handle,
            auth: Tpm2bAuth::default(),
            hash_alg: Some(TpmiAlgHash::Sha1),
        };
        assert_eq!(
            execute_with_password_sessions(&mut sim, &start, 1, &[]).unwrap_err(),
            rc_at(TpmRc::VALUE, Position::parameter(2))
        );
    }
}

/// Same ordering requirement as above, from the second MAC_Start finding.
#[test]
fn mac_start_and_hash_sequence_start_validation_order_and_error_code_bugs() {
    let mut sim = create_simulator!();
    // Restricted and non-signing: ATTRIBUTES (restricted) before KEY (sign).
    let key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
                hash_alg: TpmiAlgHash::Sha256,
                kdf: Some(TpmiAlgKdf::Kdf1Sp800_108),
            })),
        ),
        b"",
    );
    let start = HMACStart {
        handle: key,
        auth: Tpm2bAuth::default(),
        hash_alg: None,
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &start, 1, &[]).unwrap_err(),
        rc_at(TpmRc::ATTRIBUTES, Position::handle(1))
    );
}

/// HashSequenceStart with an unimplemented hash (SM3-256) is `TPM_RC_HASH + RC_P2`.
#[test]
fn tpm2_hash_and_hashsequencestart_sm3_and_unmarshal_error_bugs() {
    let mut sim = create_simulator!();
    // Raw parameters: auth (empty TPM2B) || hashAlg = TPM_ALG_SM3_256 (0x0012).
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x8001u16.to_be_bytes()); // TPM_ST_NO_SESSIONS
    buf.extend_from_slice(&14u32.to_be_bytes());
    buf.extend_from_slice(&0x0000_0186u32.to_be_bytes()); // TPM_CC_HashSequenceStart
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0x0012u16.to_be_bytes());
    let mut rsp = [0u8; 64];
    sim.transact(&buf, &mut rsp).unwrap();
    let mut slice = &rsp[..];
    let rc = RespHeader::unmarshal(&mut slice).unwrap().rc;
    assert_eq!(rc, rc_at(TpmRc::HASH, Position::parameter(2)));
}

/// EventSequenceComplete validates `sequenceHandle` (Handle 2) first, extends only allocated
/// banks and counts like PCR_Event.
#[test]
fn tpm2_eventsequencecomplete_premature_orderly_clear_and_validation_order() {
    let mut sim = create_simulator!();

    // A hash (non-event) sequence -> TPM_RC_MODE + RC_H2.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    assert_eq!(
        event_sequence_complete(&mut sim, Handle(16), seq, b"").unwrap_err(),
        rc_at(TpmRc::MODE, Position::handle(2))
    );

    // PCRExtend() changes (and counts) every *allocated* bank of PCR 16 once.
    let allocated_banks = allocated_banks_for_pcr(&mut sim, 16);
    assert!(
        allocated_banks >= 2,
        "default allocation has SHA-1 and SHA-256"
    );

    let ev = start_hash_sequence(&mut sim, None);
    let before = pcr_update_counter(&mut sim);
    event_sequence_complete(&mut sim, Handle(16), ev, b"event").unwrap();
    assert_eq!(pcr_update_counter(&mut sim) - before, allocated_banks);
}

// ----------------------------------------------------------------------------------------------
// Public-only keys
// ----------------------------------------------------------------------------------------------

/// Gives a symmetric / keyed-hash public area a (nameAlg-sized) `unique` value, as required
/// for objects loaded without their sensitive area.
fn with_unique(mut public: TpmtPublic<'static>) -> TpmtPublic<'static> {
    let unique = Tpm2bDigest::from_bytes(leak_bytes(&[0xA5; 32])).unwrap();
    match &mut public.parms_and_id {
        PublicParmsAndId::Sym(_, u) | PublicParmsAndId::KeyedHash(_, u) => *u = unique,
        _ => unreachable!(),
    }
    public
}

/// Loads a public-only AES key (no sensitive area) in the NULL hierarchy.
fn load_public_only_sym_key(sim: &mut Simulator<'_>) -> Handle {
    let cmd = LoadExternal {
        in_private: None,
        in_public: Tpm2b(with_unique(sym_template(
            TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        ))),
        hierarchy: Handle::RH_NULL,
    };
    let rsp = sim.execute(cmd).unwrap();
    rsp.object_handle
}

/// EncryptDecrypt with a public-only key never runs the cipher with an empty key: C rejects the
/// authorization with `TPM_RC_AUTH_UNAVAILABLE` (the handler additionally refuses an empty key
/// with `TPM_RC_KEY + RC_H1`) instead of returning `TPM_RC_FAILURE`.
#[test]
#[allow(deprecated)]
fn tpm2_encryptdecrypt_cmac_mode_and_public_only_key_bugs() {
    let mut sim = create_simulator!();
    let key = load_public_only_sym_key(&mut sim);
    let cmd = EncryptDecrypt {
        key_handle: key,
        decrypt: false,
        mode: None,
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
        in_data: Tpm2bMaxBuffer::from_bytes(&[0u8; 16]).unwrap(),
    };
    let rc = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
    // C IsAuthValueAvailable: a public-only object can't be authorized (bare, fmt-0 RC).
    assert_eq!(rc, TpmRc::AUTH_UNAVAILABLE.get());
}

/// Sign with a public-only HMAC key must not produce an HMAC under an empty key.
#[test]
fn sign_public_only_keyedhash_zero_byte_key_and_asymmetric_error_code_bugs() {
    let mut sim = create_simulator!();
    let cmd = LoadExternal {
        in_private: None,
        in_public: Tpm2b(with_unique(hmac_template(
            TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ))),
        hierarchy: Handle::RH_NULL,
    };
    let rsp = sim.execute(cmd).unwrap();
    let digest: &'static [u8] = leak_bytes(&[0x88; 32]);
    assert_eq!(
        sign(&mut sim, rsp.object_handle, b"", digest, None).unwrap_err(),
        TpmRc::AUTH_UNAVAILABLE.get()
    );
}
