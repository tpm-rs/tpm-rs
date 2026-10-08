//! Rust port of `ek_test.go`.
//!
//! Values for the various EK Policies and Templates are specified in:
//! TCG EK Credential Profile For TPM Family 2.0; Level 0, Version 2.7

use crate::test_utils::*;
use tpm2::commands::PolicySecretHandles;
use tpm2::commands::{Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, PolicySecret};
use tpm2::{Handle, TpmSe, TpmaSession};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmaNv, TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmsNvPublic,
    TpmsSensitiveCreate, TpmtPublic, TpmtSymDefObject,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

/// Decodes the provided hex strings into a byte vector. Panics on non-hex chars.
fn hex_to_bytes(hex_strings: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    for s in hex_strings {
        assert!(s.len() % 2 == 0, "odd-length hex string: {s}");
        for i in (0..s.len()).step_by(2) {
            buf.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
        }
    }
    buf
}

/// Digest size of the given hash algorithm (`hash.Size()` in Go).
fn hash_size(alg: TpmiAlgHash) -> usize {
    match alg {
        TpmiAlgHash::Sha256 => 32,
        TpmiAlgHash::Sha384 => 48,
        TpmiAlgHash::Sha512 => 64,
        _ => panic!("unsupported hash"),
    }
}

/// PolicyA values from "Computing PolicyA" section.
fn policy_a(alg: TpmiAlgHash) -> Vec<u8> {
    match alg {
        TpmiAlgHash::Sha256 => hex_to_bytes(&[
            "837197674484b3f81a90cc8d46a5d724",
            "fd52d76e06520b64f2a1da1b331469aa",
        ]),
        TpmiAlgHash::Sha384 => hex_to_bytes(&[
            "8bbf2266537c171cb56e403c4dc1d4b6",
            "4f432611dc386e6f532050c3278c930e",
            "143e8bb1133824ccb431053871c6db53",
        ]),
        TpmiAlgHash::Sha512 => hex_to_bytes(&[
            "1e3b76502c8a1425aa0b7b3fc646a1b0",
            "fae063b03b5368f9c4cddecaff0891dd",
            "682bac1a85d4d832b781ea451915de5f",
            "c5bf0dc4a1917cd42fa041e3f998e0ee",
        ]),
        _ => panic!("no PolicyA for {alg:?}"),
    }
}

/// Policy NV Indices from "Handle Values" section.
fn policy_index(alg: TpmiAlgHash) -> Handle {
    match alg {
        TpmiAlgHash::Sha256 => Handle(0x01C07F01),
        TpmiAlgHash::Sha384 => Handle(0x01C07F02),
        TpmiAlgHash::Sha512 => Handle(0x01C07F03),
        _ => panic!("no PolicyIndex for {alg:?}"),
    }
}

/// Policy Index Names from "Computing Policy Index Names" section.
fn policy_index_name(alg: TpmiAlgHash) -> Vec<u8> {
    match alg {
        TpmiAlgHash::Sha256 => hex_to_bytes(&[
            "000b", // TPM_ALG_SHA256
            "0c9d717e9c3fe69fda41769450bb1459",
            "57f8b3610e084dbf65591a5d11ecd83f",
        ]),
        TpmiAlgHash::Sha384 => hex_to_bytes(&[
            "000c", // TPM_ALG_SHA384
            "db62fca346612c976732ff4e8621fb4e",
            "858be82586486504f7d02e621f8d7d61",
            "ae32cfc60c4d120609ed6768afcf090c",
        ]),
        TpmiAlgHash::Sha512 => hex_to_bytes(&[
            "000d", // TPM_ALG_SHA512
            "1c47c0bbcbd3cf7d7cae6987d31937c1",
            "71015dde3b7f0d3c869bca1f7e8a223b",
            "9acfadb49b7c9cf14d450f41e9327de3",
            "4d9291eece2c58ab1dc10e9059cce560",
        ]),
        _ => panic!("no PolicyIndexName for {alg:?}"),
    }
}

/// PolicyC values from "Computing PolicyC" section.
fn policy_c(alg: TpmiAlgHash) -> Vec<u8> {
    match alg {
        TpmiAlgHash::Sha256 => hex_to_bytes(&[
            "3767e2edd43ff45a3a7e1eaefcef7864",
            "3dca964632e7aad82c673a30d8633fde",
        ]),
        TpmiAlgHash::Sha384 => hex_to_bytes(&[
            "d6032ce61f2fb3c240eb3cf6a33237ef",
            "2b6a16f4293c22b455e261cffd217ad5",
            "b4947c2d73e63005eed2dc2b3593d165",
        ]),
        TpmiAlgHash::Sha512 => hex_to_bytes(&[
            "589ee1e146544716e8deafe6db247b01",
            "b81e9f9c7dd16b814aa159138749105f",
            "ba5388dd1dea702f35240c184933121e",
            "2c61b8f50d3ef91393a49a38c3f73fc8",
        ]),
        _ => panic!("no PolicyC for {alg:?}"),
    }
}

/// PolicyB values from "Computing PolicyB" section.
fn policy_b(alg: TpmiAlgHash) -> Vec<u8> {
    match alg {
        TpmiAlgHash::Sha256 => hex_to_bytes(&[
            "ca3d0a99a2b93906f7a3342414efcfb3",
            "a385d44cd1fd459089d19b5071c0b7a0",
        ]),
        TpmiAlgHash::Sha384 => hex_to_bytes(&[
            "b26e7d28d11a50bc53d882bcf5fd3a1a",
            "074148bb35d3b4e4cb1c0ad9bde419ca",
            "cb47ba09699646150f9fc000f3f80e12",
        ]),
        TpmiAlgHash::Sha512 => hex_to_bytes(&[
            "b8221ca69e8550a4914de3faa6a18c07",
            "2cc01208073a928d5d66d59ef79e49a4",
            "29c41a6b269571d57edb25fbdb183842",
            "5608b413cd616a5f6db5b6071af99bea",
        ]),
        _ => panic!("no PolicyB for {alg:?}"),
    }
}

// ---------------------------------------------------------------------------
// TestCalculatePolicyA
// ---------------------------------------------------------------------------

/// Test that PolicyCalculator correctly computes PolicyA for `alg`.
fn calculate_policy_a(alg: TpmiAlgHash) {
    // PolicyA only makes use of TPM2_PolicySecret(TPM_RH_ENDORSEMENT).
    let mut pol = PolicyCalculator::new(alg);
    pol.policy_secret(&Handle::RH_ENDORSEMENT.0.to_be_bytes(), &[]);
    assert_eq!(pol.policy_digest, policy_a(alg), "PolicyA mismatch");
}

// Original Go test: ek_test.go - TestCalculatePolicyA/SHA-256
#[test]
fn test_calculate_policy_a_sha_256() {
    calculate_policy_a(TpmiAlgHash::Sha256);
}

// Original Go test: ek_test.go - TestCalculatePolicyA/SHA-384
#[test]
fn test_calculate_policy_a_sha_384() {
    calculate_policy_a(TpmiAlgHash::Sha384);
}

// Original Go test: ek_test.go - TestCalculatePolicyA/SHA-512
#[test]
fn test_calculate_policy_a_sha_512() {
    calculate_policy_a(TpmiAlgHash::Sha512);
}

// ---------------------------------------------------------------------------
// TestCalculatePolicyIndexName
// ---------------------------------------------------------------------------

/// Test our Name calculation for the Policy NV Index (part of PolicyC).
fn calculate_policy_index_name(alg: TpmiAlgHash) {
    let policy = policy_a(alg);
    let nv_pub = TpmsNvPublic {
        nv_index: policy_index(alg),
        name_alg: alg,
        attributes: TpmaNv::POLICYWRITE
            | TpmaNv::WRITEALL
            | TpmaNv::PPREAD
            | TpmaNv::OWNERREAD
            | TpmaNv::AUTHREAD
            | TpmaNv::POLICYREAD
            | TpmaNv::NO_DA
            | TpmaNv::WRITTEN,
        auth_policy: Tpm2bDigest::from_bytes(&policy).unwrap(),
        data_size: (hash_size(alg) + 2) as u16,
    };
    let computed = nv_name(&nv_pub);
    assert_eq!(
        computed.get_buffer(),
        policy_index_name(alg).as_slice(),
        "NVName mismatch"
    );
}

// Original Go test: ek_test.go - TestCalculatePolicyIndexName/SHA-256
#[test]
fn test_calculate_policy_index_name_sha_256() {
    calculate_policy_index_name(TpmiAlgHash::Sha256);
}

// Original Go test: ek_test.go - TestCalculatePolicyIndexName/SHA-384
#[test]
fn test_calculate_policy_index_name_sha_384() {
    calculate_policy_index_name(TpmiAlgHash::Sha384);
}

// Original Go test: ek_test.go - TestCalculatePolicyIndexName/SHA-512
#[test]
fn test_calculate_policy_index_name_sha_512() {
    calculate_policy_index_name(TpmiAlgHash::Sha512);
}

// ---------------------------------------------------------------------------
// TestCalculatePolicyC
// ---------------------------------------------------------------------------

/// Test that PolicyCalculator correctly computes PolicyC for `alg`.
fn calculate_policy_c(alg: TpmiAlgHash) {
    let mut pol = PolicyCalculator::new(alg);
    // PolicyC uses TPM2_PolicyAuthorizeNV(idx) to delegate policy.
    let name_bytes = policy_index_name(alg);
    let name = Tpm2bName::from_bytes(&name_bytes).unwrap();
    pol.policy_authorize_nv(&name);
    assert_eq!(pol.policy_digest, policy_c(alg), "PolicyC mismatch");
}

// Original Go test: ek_test.go - TestCalculatePolicyC/SHA-256
#[test]
fn test_calculate_policy_c_sha_256() {
    calculate_policy_c(TpmiAlgHash::Sha256);
}

// Original Go test: ek_test.go - TestCalculatePolicyC/SHA-384
#[test]
fn test_calculate_policy_c_sha_384() {
    calculate_policy_c(TpmiAlgHash::Sha384);
}

// Original Go test: ek_test.go - TestCalculatePolicyC/SHA-512
#[test]
fn test_calculate_policy_c_sha_512() {
    calculate_policy_c(TpmiAlgHash::Sha512);
}

// ---------------------------------------------------------------------------
// TestCalculatePolicyB
// ---------------------------------------------------------------------------

/// Test that PolicyCalculator correctly computes PolicyB for `alg`.
fn calculate_policy_b(alg: TpmiAlgHash) {
    let mut pol = PolicyCalculator::new(alg);
    // PolicyB is just the TPM2_PolicyOR of PolicyA and PolicyC.
    let a = policy_a(alg);
    let c = policy_c(alg);
    let digests = [
        Tpm2bDigest::from_bytes(&a).unwrap(),
        Tpm2bDigest::from_bytes(&c).unwrap(),
    ];
    pol.policy_or(&digests);
    // (The Go test's error message says "PolicyC" here; it checks PolicyB.)
    assert_eq!(pol.policy_digest, policy_b(alg), "PolicyB mismatch");
}

// Original Go test: ek_test.go - TestCalculatePolicyB/SHA-256
#[test]
fn test_calculate_policy_b_sha_256() {
    calculate_policy_b(TpmiAlgHash::Sha256);
}

// Original Go test: ek_test.go - TestCalculatePolicyB/SHA-384
#[test]
fn test_calculate_policy_b_sha_384() {
    calculate_policy_b(TpmiAlgHash::Sha384);
}

// Original Go test: ek_test.go - TestCalculatePolicyB/SHA-512
#[test]
fn test_calculate_policy_b_sha_512() {
    calculate_policy_b(TpmiAlgHash::Sha512);
}

// ---------------------------------------------------------------------------
// TestEKPolicy
// ---------------------------------------------------------------------------

/// go-tpm's `RSAEKTemplate` (the shared `rsa_ek_template()` with go-tpm's
/// 256-byte zero `unique` field).
fn go_rsa_ek_template() -> TpmtPublic<'static> {
    let mut template = rsa_ek_template();
    match &mut template.parms_and_id {
        PublicParmsAndId::Rsa(_, unique) => {
            *unique = Tpm2bPublicKeyRsa::from_bytes(&[0u8; 256]).unwrap();
        }
        _ => unreachable!(),
    }
    template
}

/// go-tpm's `ECCEKTemplate` (the shared `ecc_ek_template()` with go-tpm's
/// 32-byte zero X/Y `unique` field).
fn go_ecc_ek_template() -> TpmtPublic<'static> {
    let mut template = ecc_ek_template();
    match &mut template.parms_and_id {
        PublicParmsAndId::Ecc(_, unique) => {
            unique.x = tpm2::Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap();
            unique.y = tpm2::Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap();
        }
        _ => unreachable!(),
    }
    template
}

/// Port of Go's `ekPolicy` callback: TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
/// on the given policy session.
fn ek_policy(sim: &mut Simulator<'_>, handle: Handle, nonce_tpm: Tpm2bNonce<'static>) {
    let cmd = PolicySecret {
        nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: handle,
    };
    execute_with_password_sessions(sim, &cmd, handles, 1, &[]).expect("executing EK policy");
}

/// Starts an auth session like go-tpm's `Init`: 16-byte nonceCaller,
/// optionally salted with `salt_key` (whose public area is `salt_pub`) and
/// optionally bound to `bind` (with empty bind auth).
///
/// The session key is `KDFa(hash, bindAuth || salt, "ATH", nonceTPM,
/// nonceCaller, hash bits)` (Part 1, 19.6), computed only when bound or
/// salted.
fn start_session(
    tpm: &mut Simulator<'_>,
    session_type: TpmSe,
    auth_hash: TpmiAlgHash,
    symmetric: Option<TpmtSymDefObject>,
    bind: Handle,
    salt: Option<(Handle, &TpmtPublic)>,
) -> ActiveSession {
    use tpm2::crypto::Rng;

    let mut nonce_bytes = [0u8; 16];
    tpm.context
        .platform
        .crypto
        .get_random(&mut nonce_bytes)
        .unwrap();
    let nonce_caller = Tpm2bNonce::from_bytes(leak_bytes(&nonce_bytes)).unwrap();

    let mut encrypted_salt = tpm2::Tpm2bEncryptedSecret::default();
    let mut salt_value: Vec<u8> = Vec::new();
    let tpm_key = match salt {
        None => Handle::RH_NULL,
        Some((handle, pub_area)) => {
            let mut rng = rand::rngs::OsRng;
            match &pub_area.parms_and_id {
                PublicParmsAndId::Rsa(rsa_parms, rsa_unique) => {
                    // RSA-OAEP(nameAlg, label "SECRET\0") of a nameAlg-sized salt.
                    let mut salt = [0u8; 32];
                    tpm.context.platform.crypto.get_random(&mut salt).unwrap();
                    let exponent = if rsa_parms.exponent == 0 {
                        65537
                    } else {
                        rsa_parms.exponent
                    };
                    use rsa::{Oaep, RsaPublicKey};
                    let rsa_key = RsaPublicKey::new(
                        rsa::BigUint::from_bytes_be(rsa_unique.get_buffer()),
                        rsa::BigUint::from(exponent),
                    )
                    .unwrap();
                    let enc_salt = rsa_key
                        .encrypt(
                            &mut rng,
                            Oaep::new_with_label::<sha2::Sha256, _>("SECRET\0"),
                            &salt,
                        )
                        .unwrap();
                    encrypted_salt =
                        tpm2::Tpm2bEncryptedSecret::from_bytes(leak_bytes(&enc_salt)).unwrap();
                    salt_value = salt.to_vec();
                }
                PublicParmsAndId::Ecc(_, ecc_unique) => {
                    // Ephemeral ECDH + KDFe(nameAlg, Z, "SECRET", ephX, ekX).
                    use p256::elliptic_curve::sec1::ToEncodedPoint;
                    let eph_private = p256::SecretKey::random(&mut rng);
                    let eph_encoded = eph_private.public_key().to_encoded_point(false);
                    let eph_xy = eph_encoded.as_bytes();
                    assert_eq!(eph_xy[0], 0x04);
                    let eph_point = tpm2::TpmsEccPoint {
                        x: tpm2::Tpm2bEccParameter::from_bytes(&eph_xy[1..33]).unwrap(),
                        y: tpm2::Tpm2bEccParameter::from_bytes(&eph_xy[33..65]).unwrap(),
                    };
                    let enc = marshal_to_vec(&eph_point);
                    encrypted_salt =
                        tpm2::Tpm2bEncryptedSecret::from_bytes(leak_bytes(&enc)).unwrap();

                    let ek_x = ecc_unique.x.get_buffer();
                    let ek_y = ecc_unique.y.get_buffer();
                    let mut ek_xy = [0u8; 65];
                    ek_xy[0] = 0x04;
                    ek_xy[33 - ek_x.len()..33].copy_from_slice(ek_x);
                    ek_xy[65 - ek_y.len()..65].copy_from_slice(ek_y);
                    let ek_public = p256::PublicKey::from_sec1_bytes(&ek_xy).unwrap();
                    let shared = p256::ecdh::diffie_hellman(
                        eph_private.to_nonzero_scalar(),
                        ek_public.as_affine(),
                    );
                    let mut derived = [0u8; 32];
                    tpm2::crypto::kdf::kdfe(
                        tpm.context.platform.crypto,
                        TpmiAlgHash::Sha256,
                        shared.raw_secret_bytes(),
                        b"SECRET",
                        &eph_xy[1..33],
                        &ek_xy[1..33],
                        256,
                        &mut derived,
                    )
                    .unwrap();
                    salt_value = derived.to_vec();
                }
                _ => panic!("unsupported key type for salting"),
            }
            handle
        }
    };

    let cmd = tpm2::commands::StartAuthSession {
        nonce_caller,
        encrypted_salt,
        session_type,
        symmetric: symmetric.map(tpm2::TpmtSymDef::from),
        auth_hash,
    };
    let handles = tpm2::commands::StartAuthSessionHandles { tpm_key, bind };
    let (resp, resp_handles) = execute_with_password_sessions(tpm, &cmd, handles, 0, &[])
        .expect("creating session (TPM2_StartAuthSession)");

    let session_key = if bind != Handle::RH_NULL || !salt_value.is_empty() {
        // bindAuth is empty for every session in this test.
        let bits = (hash_size_any(auth_hash) * 8) as u32;
        let mut derived = vec![0u8; bits as usize / 8];
        kdfa_by_alg(
            tpm.context.platform.crypto,
            auth_hash,
            &salt_value,
            b"ATH",
            resp.nonce_tpm.get_buffer(),
            nonce_caller.get_buffer(),
            bits,
            &mut derived,
        );
        derived
    } else {
        Vec::new()
    };

    ActiveSession {
        session_handle: resp_handles.session_handle,
        nonce_caller,
        nonce_tpm: resp.nonce_tpm,
        session_key,
        auth_hash,
        symmetric,
        attributes: TpmaSession::from_bits_retain(0),
        bind_auth: Vec::new(),
        bind_entity: bind,
    }
}

/// Digest size of any hash algorithm used for sessions (SHA-1 included).
fn hash_size_any(alg: TpmiAlgHash) -> usize {
    match alg {
        TpmiAlgHash::Sha1 => 20,
        other => hash_size(other),
    }
}

/// Port of Go's `ekTestCase`.
#[derive(Clone, Copy)]
struct EkTestCase {
    /// Use Policy instead of PolicySession, passing the callback instead of
    /// managing it ourselves?
    jit_policy_session: bool,
    /// Use the policy session for decrypt? (Incompatible with decryptAnotherSession)
    decrypt_policy_session: bool,
    /// Use another session for decrypt? (Incompatible with decryptPolicySession)
    decrypt_another_session: bool,
    /// Use a bound session?
    bound: bool,
    /// Use a salted session?
    salted: bool,
}

/// Context needed to (re)start the policy session for a test case.
struct PolicySessionParams<'a> {
    symmetric: Option<TpmtSymDefObject>,
    attributes: TpmaSession,
    bind: Handle,
    salt: Option<(Handle, &'a TpmtPublic<'static>)>,
}

/// Executes `createBlobCmd.Execute(thetpm, sessions...)` with go-tpm session
/// semantics:
/// - JIT policy session (`Policy(...)`): started (and the EK policy callback
///   run) just in time, used once without continueSession.
/// - Standalone policy session: `policy` is reused (continueSession set).
/// - The extra decrypt session (`HMAC(SHA1, 16, AESEncryption(128, EncryptIn))`)
///   is started just in time and used once without continueSession.
///
/// On failure, one-shot sessions are flushed (go-tpm's `CleanupFailure`).
#[allow(clippy::too_many_arguments)]
fn execute_create_blob(
    sim: &mut Simulator<'_>,
    create_cmd: &Create<'_>,
    ek_handle: Handle,
    ek_name: &Tpm2bName<'_>,
    case: EkTestCase,
    params: &PolicySessionParams<'_>,
    policy: &mut Option<ActiveSession>,
) -> Result<(), u32> {
    // Init: auth (policy) session first, then extra sessions.
    let mut sessions = Vec::new();
    if case.jit_policy_session {
        let mut s = start_session(
            sim,
            TpmSe::Policy,
            TpmiAlgHash::Sha256,
            params.symmetric,
            params.bind,
            params.salt,
        );
        s.attributes = params.attributes;
        ek_policy(sim, s.session_handle, s.nonce_tpm);
        sessions.push(s);
    } else {
        sessions.push(policy.clone().expect("standalone policy session"));
    }
    if case.decrypt_another_session {
        let mut s = start_session(
            sim,
            TpmSe::HMAC,
            TpmiAlgHash::Sha1,
            Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
            Handle::RH_NULL,
            None,
        );
        s.attributes = TpmaSession::DECRYPT;
        sessions.push(s);
    }

    let entity_auths: Vec<&[u8]> = vec![&[]; sessions.len()];
    let res = execute_with_hmac_sessions(
        sim,
        create_cmd,
        CreateHandles {
            parent_handle: ek_handle,
        },
        &[ek_name.get_buffer()],
        &mut sessions,
        &entity_auths,
    );
    match res {
        Ok(_) => {
            if !case.jit_policy_session {
                *policy = Some(sessions[0].clone());
            }
            Ok(())
        }
        Err(rc) => {
            for (i, s) in sessions.iter().enumerate() {
                let one_shot = i > 0 || case.jit_policy_session;
                if one_shot {
                    flush_context(sim, s.session_handle).expect("CleanupFailure flush");
                }
            }
            Err(rc)
        }
    }
}

/// Port of Go's `ekTest` for a single test case: tests a combination of
/// authorizing the EK policy.
fn ek_test(ek_template: TpmtPublic<'static>, case: EkTestCase) {
    // Before using the EK, ensure it has the expected policy.
    let name_alg = ek_template.name_alg.expect("EK template nameAlg");
    assert_eq!(
        ek_template.auth_policy.get_buffer(),
        policy_a(name_alg).as_slice(),
        "AuthPolicy mismatch"
    );

    let mut sim = create_simulator!();

    // Create the EK
    let create_ek_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(ek_template),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let (create_ek_rsp, create_ek_rsp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_ek_cmd,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_ENDORSEMENT,
        },
        1,
        &[],
    )
    .expect("CreatePrimary (EK)");
    let ek_handle = create_ek_rsp_handles.object_handle;
    let ek_name = create_ek_rsp.name;
    let out_pub = create_ek_rsp
        .out_public
        .to_struct()
        .expect("EK outPublic contents");
    match &out_pub.parms_and_id {
        PublicParmsAndId::Rsa(_, rsa) => println!("EK pub:\n{:02x?}", rsa.get_buffer()),
        PublicParmsAndId::Ecc(_, ecc) => println!(
            "EK pub:\n{:02x?}\n{:02x?}",
            ecc.x.get_buffer(),
            ecc.y.get_buffer()
        ),
        _ => {}
    }
    println!("EK name: {:02x?}", ek_name.get_buffer());

    // Exercise the EK's auth policy (PolicySecret[RH_ENDORSEMENT])
    // by creating an object under it
    let data: &[u8] = b"secrets";
    let create_blob_cmd = Create {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };

    // Policy session options.
    let mut params = PolicySessionParams {
        symmetric: None,
        attributes: TpmaSession::from_bits_retain(0),
        bind: Handle::RH_NULL,
        salt: None,
    };
    if case.decrypt_policy_session {
        params.symmetric = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
        params.attributes |= TpmaSession::DECRYPT;
    }
    if case.bound {
        params.bind = ek_handle;
    }
    if case.salted {
        params.salt = Some((ek_handle, &out_pub));
    }

    let mut policy: Option<ActiveSession> = None;
    if !case.jit_policy_session {
        // Set up a session we have to execute and clean up ourselves.
        let mut s = start_session(
            &mut sim,
            TpmSe::Policy,
            TpmiAlgHash::Sha256,
            params.symmetric,
            params.bind,
            params.salt,
        );
        s.attributes = params.attributes | TpmaSession::CONTINUE_SESSION;
        // Execute the same callback ourselves.
        ek_policy(&mut sim, s.session_handle, s.nonce_tpm);
        policy = Some(s);
    }

    execute_create_blob(
        &mut sim,
        &create_blob_cmd,
        ek_handle,
        &ek_name,
        case,
        &params,
        &mut policy,
    )
    .expect("first Create under EK");

    if !case.jit_policy_session {
        // If we're not using a "just-in-time" session with a callback,
        // we have to re-initialize the session.
        let s = policy.as_ref().unwrap();
        ek_policy(&mut sim, s.session_handle, s.nonce_tpm);
    }

    // Try again and make sure it succeeds again.
    execute_create_blob(
        &mut sim,
        &create_blob_cmd,
        ek_handle,
        &ek_name,
        case,
        &params,
        &mut policy,
    )
    .expect("second Create under EK");

    if !case.jit_policy_session {
        // Finally, for non-JIT policy sessions, make sure we fail if
        // we don't re-initialize the session.
        // This is because after using a policy session, it's as if
        // PolicyRestart was called.
        let rc = execute_create_blob(
            &mut sim,
            &create_blob_cmd,
            ek_handle,
            &ek_name,
            case,
            &params,
            &mut policy,
        )
        .expect_err("want TPM_RC_POLICY_FAIL, got success");
        // TPM_RC_POLICY_FAIL is format-one (0x080 | 0x01D).
        assert_eq!(rc & 0x0BF, 0x09D, "want TPM_RC_POLICY_FAIL, got {rc:#x}");
        // Session-relative error (TPM_RC_S) on session 1.
        assert!(rc & 0x080 != 0, "want a Fmt1Error, got {rc:#x}");
        assert!(
            rc & 0x800 != 0 && (rc >> 8) & 0x7 == 1,
            "want TPM_RC_POLICY_FAIL on session 1, got {rc:#x}"
        );
    }

    // Deferred cleanups run in LIFO order: the standalone policy session
    // first, then the EK.
    if let Some(s) = policy {
        flush_context(&mut sim, s.session_handle).expect("cleaning up policy session");
    }
    flush_context(&mut sim, ek_handle).expect("flushing EK");
}

/// Shorthand constructor for [`EkTestCase`].
const fn case(
    jit: bool,
    decrypt_same: bool,
    decrypt_another: bool,
    bound: bool,
    salted: bool,
) -> EkTestCase {
    EkTestCase {
        jit_policy_session: jit,
        decrypt_policy_session: decrypt_same,
        decrypt_another_session: decrypt_another,
        bound,
        salted,
    }
}

// Case order and names follow Go's generation loops:
// jit x decryptPol x decryptAnother (not both) x bound x salted.

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone
#[test]
fn test_ek_policy_rsa_test_standalone() {
    ek_test(
        go_rsa_ek_template(),
        case(false, false, false, false, false),
    );
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-salted
#[test]
fn test_ek_policy_rsa_test_standalone_salted() {
    ek_test(go_rsa_ek_template(), case(false, false, false, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-bound
#[test]
fn test_ek_policy_rsa_test_standalone_bound() {
    ek_test(go_rsa_ek_template(), case(false, false, false, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-bound-salted
#[test]
fn test_ek_policy_rsa_test_standalone_bound_salted() {
    ek_test(go_rsa_ek_template(), case(false, false, false, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-decrypt-another
#[test]
fn test_ek_policy_rsa_test_standalone_decrypt_another() {
    ek_test(go_rsa_ek_template(), case(false, false, true, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-decrypt-another-salted
#[test]
fn test_ek_policy_rsa_test_standalone_decrypt_another_salted() {
    ek_test(go_rsa_ek_template(), case(false, false, true, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-decrypt-another-bound
#[test]
fn test_ek_policy_rsa_test_standalone_decrypt_another_bound() {
    ek_test(go_rsa_ek_template(), case(false, false, true, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-decrypt-another-bound-salted
#[test]
fn test_ek_policy_rsa_test_standalone_decrypt_another_bound_salted() {
    ek_test(go_rsa_ek_template(), case(false, false, true, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-decrypt-same
#[test]
fn test_ek_policy_rsa_test_standalone_decrypt_same() {
    ek_test(go_rsa_ek_template(), case(false, true, false, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-decrypt-same-salted
#[test]
fn test_ek_policy_rsa_test_standalone_decrypt_same_salted() {
    ek_test(go_rsa_ek_template(), case(false, true, false, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-decrypt-same-bound
#[test]
fn test_ek_policy_rsa_test_standalone_decrypt_same_bound() {
    ek_test(go_rsa_ek_template(), case(false, true, false, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-standalone-decrypt-same-bound-salted
#[test]
fn test_ek_policy_rsa_test_standalone_decrypt_same_bound_salted() {
    ek_test(go_rsa_ek_template(), case(false, true, false, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit
#[test]
fn test_ek_policy_rsa_test_jit() {
    ek_test(go_rsa_ek_template(), case(true, false, false, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-salted
#[test]
fn test_ek_policy_rsa_test_jit_salted() {
    ek_test(go_rsa_ek_template(), case(true, false, false, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-bound
#[test]
fn test_ek_policy_rsa_test_jit_bound() {
    ek_test(go_rsa_ek_template(), case(true, false, false, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-bound-salted
#[test]
fn test_ek_policy_rsa_test_jit_bound_salted() {
    ek_test(go_rsa_ek_template(), case(true, false, false, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-decrypt-another
#[test]
fn test_ek_policy_rsa_test_jit_decrypt_another() {
    ek_test(go_rsa_ek_template(), case(true, false, true, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-decrypt-another-salted
#[test]
fn test_ek_policy_rsa_test_jit_decrypt_another_salted() {
    ek_test(go_rsa_ek_template(), case(true, false, true, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-decrypt-another-bound
#[test]
fn test_ek_policy_rsa_test_jit_decrypt_another_bound() {
    ek_test(go_rsa_ek_template(), case(true, false, true, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-decrypt-another-bound-salted
#[test]
fn test_ek_policy_rsa_test_jit_decrypt_another_bound_salted() {
    ek_test(go_rsa_ek_template(), case(true, false, true, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-decrypt-same
#[test]
fn test_ek_policy_rsa_test_jit_decrypt_same() {
    ek_test(go_rsa_ek_template(), case(true, true, false, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-decrypt-same-salted
#[test]
fn test_ek_policy_rsa_test_jit_decrypt_same_salted() {
    ek_test(go_rsa_ek_template(), case(true, true, false, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-decrypt-same-bound
#[test]
fn test_ek_policy_rsa_test_jit_decrypt_same_bound() {
    ek_test(go_rsa_ek_template(), case(true, true, false, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/RSA/test-jit-decrypt-same-bound-salted
#[test]
fn test_ek_policy_rsa_test_jit_decrypt_same_bound_salted() {
    ek_test(go_rsa_ek_template(), case(true, true, false, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone
#[test]
fn test_ek_policy_ecc_test_standalone() {
    ek_test(
        go_ecc_ek_template(),
        case(false, false, false, false, false),
    );
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-salted
#[test]
fn test_ek_policy_ecc_test_standalone_salted() {
    ek_test(go_ecc_ek_template(), case(false, false, false, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-bound
#[test]
fn test_ek_policy_ecc_test_standalone_bound() {
    ek_test(go_ecc_ek_template(), case(false, false, false, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-bound-salted
#[test]
fn test_ek_policy_ecc_test_standalone_bound_salted() {
    ek_test(go_ecc_ek_template(), case(false, false, false, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-decrypt-another
#[test]
fn test_ek_policy_ecc_test_standalone_decrypt_another() {
    ek_test(go_ecc_ek_template(), case(false, false, true, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-decrypt-another-salted
#[test]
fn test_ek_policy_ecc_test_standalone_decrypt_another_salted() {
    ek_test(go_ecc_ek_template(), case(false, false, true, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-decrypt-another-bound
#[test]
fn test_ek_policy_ecc_test_standalone_decrypt_another_bound() {
    ek_test(go_ecc_ek_template(), case(false, false, true, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-decrypt-another-bound-salted
#[test]
fn test_ek_policy_ecc_test_standalone_decrypt_another_bound_salted() {
    ek_test(go_ecc_ek_template(), case(false, false, true, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-decrypt-same
#[test]
fn test_ek_policy_ecc_test_standalone_decrypt_same() {
    ek_test(go_ecc_ek_template(), case(false, true, false, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-decrypt-same-salted
#[test]
fn test_ek_policy_ecc_test_standalone_decrypt_same_salted() {
    ek_test(go_ecc_ek_template(), case(false, true, false, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-decrypt-same-bound
#[test]
fn test_ek_policy_ecc_test_standalone_decrypt_same_bound() {
    ek_test(go_ecc_ek_template(), case(false, true, false, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-standalone-decrypt-same-bound-salted
#[test]
fn test_ek_policy_ecc_test_standalone_decrypt_same_bound_salted() {
    ek_test(go_ecc_ek_template(), case(false, true, false, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit
#[test]
fn test_ek_policy_ecc_test_jit() {
    ek_test(go_ecc_ek_template(), case(true, false, false, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-salted
#[test]
fn test_ek_policy_ecc_test_jit_salted() {
    ek_test(go_ecc_ek_template(), case(true, false, false, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-bound
#[test]
fn test_ek_policy_ecc_test_jit_bound() {
    ek_test(go_ecc_ek_template(), case(true, false, false, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-bound-salted
#[test]
fn test_ek_policy_ecc_test_jit_bound_salted() {
    ek_test(go_ecc_ek_template(), case(true, false, false, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-decrypt-another
#[test]
fn test_ek_policy_ecc_test_jit_decrypt_another() {
    ek_test(go_ecc_ek_template(), case(true, false, true, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-decrypt-another-salted
#[test]
fn test_ek_policy_ecc_test_jit_decrypt_another_salted() {
    ek_test(go_ecc_ek_template(), case(true, false, true, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-decrypt-another-bound
#[test]
fn test_ek_policy_ecc_test_jit_decrypt_another_bound() {
    ek_test(go_ecc_ek_template(), case(true, false, true, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-decrypt-another-bound-salted
#[test]
fn test_ek_policy_ecc_test_jit_decrypt_another_bound_salted() {
    ek_test(go_ecc_ek_template(), case(true, false, true, true, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-decrypt-same
#[test]
fn test_ek_policy_ecc_test_jit_decrypt_same() {
    ek_test(go_ecc_ek_template(), case(true, true, false, false, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-decrypt-same-salted
#[test]
fn test_ek_policy_ecc_test_jit_decrypt_same_salted() {
    ek_test(go_ecc_ek_template(), case(true, true, false, false, true));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-decrypt-same-bound
#[test]
fn test_ek_policy_ecc_test_jit_decrypt_same_bound() {
    ek_test(go_ecc_ek_template(), case(true, true, false, true, false));
}

// Original Go test: ek_test.go - TestEKPolicy/ECC/test-jit-decrypt-same-bound-salted
#[test]
fn test_ek_policy_ecc_test_jit_decrypt_same_bound_salted() {
    ek_test(go_ecc_ek_template(), case(true, true, false, true, true));
}
