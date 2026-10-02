use tpm2::crypto::{HashStream, HmacStream};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bData, Tpm2bName, Tpm2bNonce, TpmCc, TpmaSession, TpmiAlgHash,
    TpmsAuthResponse,
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

/// Returns the response the TPM would send for `nonce_caller`, with an empty
/// HMAC key.
fn tpm_response<'a>(
    rsp: &ResponseData,
    nonce_tpm: &'a [u8; 32],
    nonce_caller: &[u8],
    hmac_out: &'a mut [u8; 32],
) -> TpmsAuthResponse<'a> {
    let rp_hash = sha256(&[&0u32.to_be_bytes(), &CODE.code().to_be_bytes(), rsp.params]);
    *hmac_out = hmac_sha256(
        &[],
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
    let mut response = tpm_response(&rsp, &new_nonce_tpm, &nonce_caller, &mut hmac_buf);

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
        &[],
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
