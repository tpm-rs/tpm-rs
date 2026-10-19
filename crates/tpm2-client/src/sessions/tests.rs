use tpm2::crypto::{HashStream, HmacStream};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmCc, TpmaSession,
    TpmiAlgHash, TpmsAuthResponse,
};
use tpm2_rustcrypto::RustCrypto;

use super::*;
use crate::nv_name;

const SESSION_HANDLE: Handle = Handle(0x02000000);
const NV_INDEX: Handle = Handle(0x01422224);
const ALG: TpmiAlgHash = TpmiAlgHash::Sha256;
const CODE: TpmCc = TpmCc::NVWrite;
const NONCE_CALLER: [u8; 32] = [0x11; 32];
const NONCE_TPM: [u8; 32] = [0x22; 32];

fn new_hmac_session() -> HmacSession<RustCrypto> {
    HmacSession::new(
        RustCrypto,
        SESSION_HANDLE,
        ALG,
        Tpm2bNonce::new(&NONCE_CALLER).unwrap(),
        Tpm2bNonce::new(&NONCE_TPM).unwrap(),
    )
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut stream = HashStream::new(&RustCrypto, ALG).unwrap();
    for part in parts {
        stream.update(part).unwrap();
    }
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    stream
        .finalize(&mut out)
        .unwrap()
        .digest()
        .try_into()
        .unwrap()
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut stream = HmacStream::new(&RustCrypto, ALG, key).unwrap();
    for part in parts {
        stream.update(part).unwrap();
    }
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    stream
        .finalize(&mut out)
        .unwrap()
        .digest()
        .try_into()
        .unwrap()
}

/// Returns the response the TPM would send for `nonce_caller`, with the HMAC
/// key `key`.
fn tpm_response<'a>(
    rsp: &ResponseData,
    key: &[u8],
    nonce_tpm: &'a [u8; 32],
    nonce_caller: &[u8],
    hmac_out: &'a mut [u8; 32],
) -> TpmsAuthResponse<'a> {
    let rp_hash = sha256(&[&0u32.to_be_bytes(), &CODE.code().to_be_bytes(), rsp.params]);
    *hmac_out = hmac_sha256(
        key,
        &[
            &rp_hash,
            nonce_tpm,
            nonce_caller,
            &[TpmaSession::CONTINUE_SESSION.0],
        ],
    );
    TpmsAuthResponse {
        nonce: Tpm2bNonce::new(nonce_tpm).unwrap(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bData::new(hmac_out).unwrap(),
    }
}

#[test]
fn test_hmac_session_command_hmac() {
    let mut session = new_hmac_session();
    session.set_auth_value(Tpm2bAuth::new(b"auth\0\0").unwrap());

    let name = [0xAB; 34];
    let names = [None, Some(Tpm2bName::new(&name).unwrap())];
    let cmd = CommandData {
        code: CODE,
        handles: &[Handle::RH_OWNER, NV_INDEX],
        names: &names,
        params: b"params",
    };
    let auth = session.auth_command(&cmd).unwrap();
    assert_eq!(auth.session_handle, SESSION_HANDLE);
    assert_eq!(auth.session_attributes, TpmaSession::CONTINUE_SESSION);
    // A fresh nonceCaller is generated for each command.
    assert_eq!(auth.nonce.as_slice().len(), ALG.digest_size());
    assert_ne!(auth.nonce.as_slice(), NONCE_CALLER);

    // RH_OWNER's Name is its handle; the NV index's Name is provided.
    let cp_hash = sha256(&[
        &CODE.code().to_be_bytes(),
        &Handle::RH_OWNER.0.to_be_bytes(),
        &name,
        b"params",
    ]);
    // Unbound/unsalted: hmacKey is the authValue with trailing zeros removed.
    let expected = hmac_sha256(
        b"auth",
        &[
            &cp_hash,
            auth.nonce.as_slice(),
            &NONCE_TPM,
            &[TpmaSession::CONTINUE_SESSION.0],
        ],
    );
    assert_eq!(auth.hmac.as_slice(), expected);
}

#[test]
fn test_hmac_session_rolls_nonces() {
    let mut session = new_hmac_session();
    session.set_auth_value(Tpm2bAuth::new(b"auth").unwrap());
    let cmd = CommandData {
        code: CODE,
        handles: &[Handle::RH_OWNER],
        names: &[],
        params: b"params",
    };
    let rsp = ResponseData {
        code: CODE,
        params: b"response",
    };

    // First command.
    let mut nonce_caller = [0u8; 32];
    nonce_caller.copy_from_slice(session.auth_command(&cmd).unwrap().nonce.as_slice());

    let new_nonce_tpm = [0x33; 32];
    let mut hmac_buf = [0u8; 32];
    let mut response = tpm_response(&rsp, b"auth", &new_nonce_tpm, &nonce_caller, &mut hmac_buf);

    // A tampered HMAC is rejected, and nonceTPM is not updated.
    let good_hmac = response.hmac;
    let mut bad_hmac = [0u8; 32];
    bad_hmac.copy_from_slice(good_hmac.as_slice());
    bad_hmac[0] ^= 1;
    response.hmac = Tpm2bData::new(&bad_hmac).unwrap();
    assert_eq!(
        session.validate_auth_response(&rsp, &response),
        Err(AuthError::InvalidResponse)
    );
    assert_eq!(session.nonce_tpm().as_slice(), NONCE_TPM);

    // The correct HMAC is accepted, and nonceTPM rolls forward.
    response.hmac = good_hmac;
    assert_eq!(session.validate_auth_response(&rsp, &response), Ok(()));
    assert_eq!(session.nonce_tpm().as_slice(), new_nonce_tpm);

    // The second command's HMAC uses the new nonceTPM.
    let auth = session.auth_command(&cmd).unwrap();
    assert_ne!(auth.nonce.as_slice(), nonce_caller);
    let cp_hash = sha256(&[
        &CODE.code().to_be_bytes(),
        &Handle::RH_OWNER.0.to_be_bytes(),
        b"params",
    ]);
    let expected = hmac_sha256(
        b"auth",
        &[
            &cp_hash,
            auth.nonce.as_slice(),
            &new_nonce_tpm,
            &[TpmaSession::CONTINUE_SESSION.0],
        ],
    );
    assert_eq!(auth.hmac.as_slice(), expected);
}

#[test]
fn test_hmac_session_missing_name() {
    let mut session = new_hmac_session();
    // With an empty HMAC key, no cpHash (and so no Name) is needed.
    session.set_auth_value(Tpm2bAuth::new(b"auth").unwrap());
    let cmd = CommandData {
        code: CODE,
        handles: &[Handle::RH_OWNER, NV_INDEX],
        names: &[],
        params: &[],
    };
    assert_eq!(
        session.auth_command(&cmd).err(),
        Some(AuthError::MissingName)
    );
}

#[test]
fn test_hmac_session_empty_key() {
    // Unbound, unsalted, and an empty authValue: the HMAC key is empty, so
    // the HMACs are empty (and no Names are needed).
    let mut session = new_hmac_session();
    let cmd = CommandData {
        code: CODE,
        handles: &[Handle::RH_OWNER, NV_INDEX],
        names: &[],
        params: b"params",
    };
    let rsp = ResponseData {
        code: CODE,
        params: b"response",
    };

    let auth = session.auth_command(&cmd).unwrap();
    assert!(auth.hmac.as_slice().is_empty());
    // The nonce still rolls.
    assert_eq!(auth.nonce.as_slice().len(), ALG.digest_size());
    assert_ne!(auth.nonce.as_slice(), NONCE_CALLER);
    let mut nonce_caller = [0u8; 32];
    nonce_caller.copy_from_slice(auth.nonce.as_slice());

    let new_nonce_tpm = [0x33; 32];
    let mut hmac_buf = [0u8; 32];
    let mut response = tpm_response(&rsp, &[], &new_nonce_tpm, &nonce_caller, &mut hmac_buf);

    // A non-empty response HMAC is rejected, and nonceTPM is not updated.
    assert_eq!(
        session.validate_auth_response(&rsp, &response),
        Err(AuthError::InvalidResponse)
    );
    assert_eq!(session.nonce_tpm().as_slice(), NONCE_TPM);

    // An empty response HMAC is accepted, and nonceTPM rolls forward.
    response.hmac = Tpm2bData::default();
    assert_eq!(session.validate_auth_response(&rsp, &response), Ok(()));
    assert_eq!(session.nonce_tpm().as_slice(), new_nonce_tpm);
}

#[test]
fn test_password_auth_command() {
    let mut session = PasswordSession::new("hello").unwrap();
    let cmd = CommandData {
        code: CODE,
        handles: &[NV_INDEX],
        names: &[],
        params: &[],
    };
    // Password sessions don't need Names.
    let tpm_auth = session.auth_command(&cmd).unwrap();
    assert_eq!(tpm_auth.session_handle, Handle::RS_PW);
    assert_eq!(tpm_auth.hmac.as_slice().len(), 5);
    assert_eq!(tpm_auth.hmac.as_slice(), b"hello");
}

#[test]
fn test_nv_name() {
    let mut public = tpm2::TpmsNvPublic {
        nv_index: NV_INDEX,
        name_alg: ALG,
        attributes: tpm2::TpmaNv::from(tpm2::TpmNt::Ordinary)
            | tpm2::TpmaNv::OWNERREAD
            | tpm2::TpmaNv::OWNERWRITE,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 16,
    };
    let mut name_buf = [0u8; Tpm2bName::CAP];
    let name = nv_name(&RustCrypto, &public, &mut name_buf).unwrap();

    // Name := nameAlg || H(nvIndex || nameAlg || attributes || authPolicy || dataSize)
    let digest = sha256(&[
        &NV_INDEX.0.to_be_bytes(),
        &0x000Bu16.to_be_bytes(), // TPM_ALG_SHA256
        &public.attributes.0.to_be_bytes(),
        &0u16.to_be_bytes(), // empty authPolicy
        &16u16.to_be_bytes(),
    ]);
    assert_eq!(name.as_slice().len(), 2 + 32);
    assert_eq!(name.as_slice()[..2], 0x000Bu16.to_be_bytes());
    assert_eq!(name.as_slice()[2..], digest);

    // Setting TPMA_NV_WRITTEN changes the Name.
    public.attributes |= tpm2::TpmaNv::WRITTEN;
    let mut written_buf = [0u8; Tpm2bName::CAP];
    let written_name = nv_name(&RustCrypto, &public, &mut written_buf).unwrap();
    assert_ne!(written_name, name);
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// policyDigest after `TPM2_PolicyAuthValue` (or `TPM2_PolicyPassword`) on a
/// new SHA-256 session.
const POLICY_AUTH_VALUE: &str = "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e";

#[test]
fn test_policy_digest_known_values() {
    let mut policy = PolicyDigest::new(RustCrypto, ALG);
    assert_eq!(policy.digest().as_slice(), [0u8; 32]);

    policy.policy_auth_value().unwrap();
    assert_eq!(policy.digest().as_slice(), hex32(POLICY_AUTH_VALUE));

    policy.reset();
    assert_eq!(policy.digest().as_slice(), [0u8; 32]);
    policy.policy_password().unwrap();
    assert_eq!(policy.digest().as_slice(), hex32(POLICY_AUTH_VALUE));

    // The policy of the default EK templates (TPM 2.0 EK Credential Profile):
    // PolicySecret(TPM_RH_ENDORSEMENT) with an empty policyRef.
    let mut policy = PolicyDigest::new(RustCrypto, ALG);
    let name = Handle::RH_ENDORSEMENT.0.to_be_bytes();
    policy
        .policy_secret(Tpm2bName::new(&name).unwrap(), Tpm2bNonce::default())
        .unwrap();
    assert_eq!(
        policy.digest().as_slice(),
        hex32("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa")
    );
}

#[test]
fn test_policy_digest_updates() {
    let cc = |code: TpmCc| code.code().to_be_bytes();

    // PolicyCommandCode extends the current digest.
    let mut policy = PolicyDigest::new(RustCrypto, ALG);
    policy.policy_command_code(TpmCc::NVRead).unwrap();
    let expected = sha256(&[&[0u8; 32], &cc(TpmCc::PolicyCommandCode), &cc(TpmCc::NVRead)]);
    assert_eq!(policy.digest().as_slice(), expected);

    // PolicyNV hashes its arguments first.
    let nv_name = [0xAB; 34];
    policy
        .policy_nv(
            tpm2::Tpm2bOperand::new(b"operand").unwrap(),
            3,
            tpm2::TpmEo::UnsignedLT,
            Tpm2bName::new(&nv_name).unwrap(),
        )
        .unwrap();
    let args = sha256(&[b"operand", &3u16.to_be_bytes(), &5u16.to_be_bytes()]);
    let expected = sha256(&[&expected, &cc(TpmCc::PolicyNV), &args, &nv_name]);
    assert_eq!(policy.digest().as_slice(), expected);

    // PolicyOR replaces the digest, regardless of its current value.
    let a = [0x01; 32];
    let b = [0x02; 32];
    policy
        .policy_or(&[Tpm2bDigest::new(&a).unwrap(), Tpm2bDigest::new(&b).unwrap()])
        .unwrap();
    let expected = sha256(&[&[0u8; 32], &cc(TpmCc::PolicyOR), &a, &b]);
    assert_eq!(policy.digest().as_slice(), expected);

    // PolicyAuthorize also replaces the digest, and always does the second
    // (policyRef) update.
    let key_name = [0xCD; 34];
    policy
        .policy_authorize(Tpm2bName::new(&key_name).unwrap(), Tpm2bNonce::default())
        .unwrap();
    let expected = sha256(&[&[0u8; 32], &cc(TpmCc::PolicyAuthorize), &key_name]);
    let expected = sha256(&[&expected]);
    assert_eq!(policy.digest().as_slice(), expected);

    // PolicyDuplicationSelect only includes objectName if includeObject.
    let mut policy = PolicyDigest::new(RustCrypto, ALG);
    let object_name = [0x11; 34];
    let parent_name = [0x22; 34];
    policy
        .policy_duplication_select(
            Tpm2bName::new(&object_name).unwrap(),
            Tpm2bName::new(&parent_name).unwrap(),
            false,
        )
        .unwrap();
    let expected = sha256(&[
        &[0u8; 32],
        &cc(TpmCc::PolicyDuplicationSelect),
        &parent_name,
        &[0],
    ]);
    assert_eq!(policy.digest().as_slice(), expected);

    // PolicyPCR includes the marshaled TPML_PCR_SELECTION.
    let mut policy = PolicyDigest::new(RustCrypto, ALG);
    let pcr_digest = [0x33; 32];
    policy
        .policy_pcr(
            Tpm2bDigest::new(&pcr_digest).unwrap(),
            &tpm2::TpmlPcrSelection::default(),
        )
        .unwrap();
    let expected = sha256(&[
        &[0u8; 32],
        &cc(TpmCc::PolicyPCR),
        &0u32.to_be_bytes(), // empty list
        &pcr_digest,
    ]);
    assert_eq!(policy.digest().as_slice(), expected);
}

const POLICY_SESSION_HANDLE: Handle = Handle(0x03000000);

fn new_policy_session() -> PolicySession<RustCrypto> {
    PolicySession::new(
        RustCrypto,
        POLICY_SESSION_HANDLE,
        ALG,
        Tpm2bNonce::new(&NONCE_CALLER).unwrap(),
        Tpm2bNonce::new(&NONCE_TPM).unwrap(),
    )
}

#[test]
fn test_policy_session_policy_only() {
    // Without PolicyAuthValue/PolicyPassword, an unbound, unsalted policy
    // session has an empty HMAC key, so the HMACs are empty, even if an
    // authValue is set.
    let mut session = new_policy_session();
    session.set_auth_value(Tpm2bAuth::new(b"auth").unwrap());
    session
        .policy_mut()
        .policy_command_code(TpmCc::NVRead)
        .unwrap();
    assert_ne!(session.policy().digest().as_slice(), [0u8; 32]);

    let cmd = CommandData {
        code: CODE,
        handles: &[NV_INDEX, NV_INDEX],
        names: &[],
        params: b"params",
    };
    let rsp = ResponseData {
        code: CODE,
        params: b"response",
    };
    let auth = session.auth_command(&cmd).unwrap();
    assert_eq!(auth.session_handle, POLICY_SESSION_HANDLE);
    assert!(auth.hmac.as_slice().is_empty());
    let mut nonce_caller = [0u8; 32];
    nonce_caller.copy_from_slice(auth.nonce.as_slice());

    let new_nonce_tpm = [0x33; 32];
    let response = TpmsAuthResponse {
        nonce: Tpm2bNonce::new(&new_nonce_tpm).unwrap(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bData::default(),
    };
    assert_eq!(session.validate_auth_response(&rsp, &response), Ok(()));
    assert_eq!(session.nonce_tpm().as_slice(), new_nonce_tpm);

    // A successful use resets the policy.
    assert_eq!(session.policy().digest().as_slice(), [0u8; 32]);
}

#[test]
fn test_policy_session_auth_value() {
    let mut session = new_policy_session();
    session
        .policy_auth_value(Tpm2bAuth::new(b"auth\0\0").unwrap())
        .unwrap();
    assert_eq!(
        session.policy().digest().as_slice(),
        hex32(POLICY_AUTH_VALUE)
    );

    let name = [0xAB; 34];
    let names = [Some(Tpm2bName::new(&name).unwrap())];
    let cmd = CommandData {
        code: CODE,
        handles: &[NV_INDEX],
        names: &names,
        params: b"params",
    };
    let rsp = ResponseData {
        code: CODE,
        params: b"response",
    };

    // The HMAC key is the authValue, with trailing zeros removed.
    let auth = session.auth_command(&cmd).unwrap();
    let cp_hash = sha256(&[&CODE.code().to_be_bytes(), &name, b"params"]);
    let expected = hmac_sha256(
        b"auth",
        &[
            &cp_hash,
            auth.nonce.as_slice(),
            &NONCE_TPM,
            &[TpmaSession::CONTINUE_SESSION.0],
        ],
    );
    assert_eq!(auth.hmac.as_slice(), expected);
    let mut nonce_caller = [0u8; 32];
    nonce_caller.copy_from_slice(auth.nonce.as_slice());

    // So is the response HMAC key.
    let new_nonce_tpm = [0x33; 32];
    let mut hmac_buf = [0u8; 32];
    let response = tpm_response(&rsp, &[], &new_nonce_tpm, &nonce_caller, &mut hmac_buf);
    assert_eq!(
        session.validate_auth_response(&rsp, &response),
        Err(AuthError::InvalidResponse)
    );
    // A failed validation doesn't reset the policy.
    assert_eq!(
        session.policy().digest().as_slice(),
        hex32(POLICY_AUTH_VALUE)
    );
    let response = tpm_response(&rsp, b"auth", &new_nonce_tpm, &nonce_caller, &mut hmac_buf);
    assert_eq!(session.validate_auth_response(&rsp, &response), Ok(()));

    // A successful use resets the policy, so the authValue is no longer used.
    assert_eq!(session.policy().digest().as_slice(), [0u8; 32]);
    let auth = session.auth_command(&cmd).unwrap();
    assert!(auth.hmac.as_slice().is_empty());
}

#[test]
fn test_policy_session_password() {
    let mut session = new_policy_session();
    session
        .policy_password(Tpm2bAuth::new(b"password").unwrap())
        .unwrap();
    assert_eq!(
        session.policy().digest().as_slice(),
        hex32(POLICY_AUTH_VALUE)
    );

    // No Names are needed, as there is no cpHash.
    let cmd = CommandData {
        code: CODE,
        handles: &[NV_INDEX],
        names: &[],
        params: b"params",
    };
    let rsp = ResponseData {
        code: CODE,
        params: b"response",
    };

    // The authValue is sent in place of the HMAC, but the nonce still rolls.
    let auth = session.auth_command(&cmd).unwrap();
    assert_eq!(auth.session_handle, POLICY_SESSION_HANDLE);
    assert_eq!(auth.hmac.as_slice(), b"password");
    assert_eq!(auth.nonce.as_slice().len(), ALG.digest_size());
    assert_ne!(auth.nonce.as_slice(), NONCE_CALLER);
    let mut nonce_caller = [0u8; 32];
    nonce_caller.copy_from_slice(auth.nonce.as_slice());

    // The response HMAC must be empty.
    let new_nonce_tpm = [0x33; 32];
    let mut hmac_buf = [0u8; 32];
    let mut response = tpm_response(&rsp, &[], &new_nonce_tpm, &nonce_caller, &mut hmac_buf);
    assert_eq!(
        session.validate_auth_response(&rsp, &response),
        Err(AuthError::InvalidResponse)
    );
    assert_eq!(session.nonce_tpm().as_slice(), NONCE_TPM);

    response.hmac = Tpm2bData::default();
    assert_eq!(session.validate_auth_response(&rsp, &response), Ok(()));
    assert_eq!(session.nonce_tpm().as_slice(), new_nonce_tpm);

    // A successful use resets the policy.
    assert_eq!(session.policy().digest().as_slice(), [0u8; 32]);
    let auth = session.auth_command(&cmd).unwrap();
    assert!(auth.hmac.as_slice().is_empty());
}

#[test]
fn test_policy_session_restart() {
    let mut session = new_policy_session();
    session
        .policy_password(Tpm2bAuth::new(b"password").unwrap())
        .unwrap();
    session.policy_restart();
    assert_eq!(session.policy().digest().as_slice(), [0u8; 32]);

    let cmd = CommandData {
        code: CODE,
        handles: &[NV_INDEX],
        names: &[],
        params: b"params",
    };
    let auth = session.auth_command(&cmd).unwrap();
    assert!(auth.hmac.as_slice().is_empty());
}
