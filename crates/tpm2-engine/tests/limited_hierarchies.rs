//! White-box tests of the firmware-limited and SVN-limited hierarchies: the derivation of their
//! proofs (checked through hash-check tickets against an independent KDFa computation over the
//! engine's base proofs), their availability with and without a platform firmware, and their
//! `TPM2_GetCapability` listings.

mod common;

use common::{
    FakeRng, FakeStorage, FakeTimer, TestCryptoProvider, execute_command, password_auth,
    setup_real_crypto_tpm,
};
use tpm2::commands::{CreatePrimary, GetCapability, Hash};
use tpm2::crypto::kdf::kdfa_bits;
use tpm2::errors::{Position, TpmRc};
use tpm2::platform::SimulatedFirmware;
use tpm2::{
    Handle, Tpm2b, Tpm2bMaxBuffer, TpmCap, TpmEccCurve, TpmPt, TpmaObject, TpmiAlgHash,
    TpmsCapabilityData, TpmsEccParms, TpmsEccPoint, TpmtPublic,
};

/// The context integrity hash of this build (SHA-512, or SHA-384 without SHA-512).
fn context_hash() -> TpmiAlgHash {
    TpmiAlgHash::try_from(tpm2::Alg::SHA512).unwrap_or(TpmiAlgHash::Sha384)
}

/// The proof of a limited hierarchy (TPM 2.0 Part 1, Equation "seed-proof-limited-hierarchy"):
/// `KDFa(hashAlg, baseProof, "H_PROOF_SECRET", aSecret, aSecretLabel, bits)` with the labels of
/// the TCG reference (including their terminating NUL).
fn limited_proof(base_proof: &[u8], secret: &[u8], secret_label: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; base_proof.len()];
    kdfa_bits(
        &TestCryptoProvider,
        context_hash(),
        base_proof,
        b"H_PROOF_SECRET\0",
        secret,
        secret_label,
        (base_proof.len() * 8) as u32,
        &mut out,
    )
    .unwrap();
    out
}

/// The hash-check ticket digest `HMAC(proof, TPM_ST_HASHCHECK || hashAlg || digest)`.
fn hashcheck_ticket(proof: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut input = 0x8024u16.to_be_bytes().to_vec();
    input.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA-256
    input.extend_from_slice(digest);
    let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    tpm2::crypto::hmac(&TestCryptoProvider, context_hash(), proof, &input, &mut buf)
        .unwrap()
        .digest()
        .to_vec()
}

/// `TPM2_Hash("data", SHA-256, hierarchy)`: the digest and the ticket's digest, or the response
/// code.
fn hash_ticket(
    tpm: &mut common::RealCryptoEngine<'_>,
    hierarchy: Handle,
) -> Result<(Vec<u8>, Vec<u8>), u32> {
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy,
    };
    execute_command(tpm, &cmd, &[]).map(|rsp| {
        assert_eq!(rsp.validation.hierarchy(), hierarchy);
        (
            rsp.out_hash.get_buffer().to_vec(),
            rsp.validation.digest().get_buffer().to_vec(),
        )
    })
}

/// An ECC P-256 signing key template with fixedTPM and fixedParent.
fn signing_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Default::default(),
        parms_and_id: tpm2::PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    }
}

/// `TPM2_CreatePrimary(hierarchy)`; the response code on failure.
fn create_primary(
    tpm: &mut common::RealCryptoEngine<'_>,
    hierarchy: Handle,
) -> Result<Handle, u32> {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_public: Tpm2b(signing_template()),
        ..Default::default()
    };
    execute_command(tpm, &cmd, &[password_auth(b"")]).map(|rsp| rsp.object_handle)
}

/// The permanent handles of `TPM_CAP_HANDLES` from `from`.
fn permanent_handles(tpm: &mut common::RealCryptoEngine<'_>, from: u32) -> Vec<u32> {
    let cmd = GetCapability {
        capability: TpmCap::Handles,
        property: from,
        property_count: 64,
    };
    match execute_command(tpm, &cmd, &[]).unwrap().capability_data {
        TpmsCapabilityData::Handles(list) => list.as_ref().iter().map(|h| h.0).collect(),
        other => panic!("{other:?}"),
    }
}

/// `TPM_PT_FIRMWARE_SVN` and `TPM_PT_FIRMWARE_MAX_SVN`.
fn firmware_svn_properties(tpm: &mut common::RealCryptoEngine<'_>) -> (u32, u32) {
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: TpmPt::FIRMWARE_SVN.0,
        property_count: 2,
    };
    match execute_command(tpm, &cmd, &[]).unwrap().capability_data {
        TpmsCapabilityData::TpmProperties(list) => {
            let props: Vec<(TpmPt, u32)> = list
                .as_ref()
                .iter()
                .map(|p| (p.property, p.value))
                .collect();
            assert_eq!(props[0].0, TpmPt::FIRMWARE_SVN);
            assert_eq!(props[1].0, TpmPt::FIRMWARE_MAX_SVN);
            (props[0].1, props[1].1)
        }
        other => panic!("{other:?}"),
    }
}

/// The proofs of the firmware-limited and SVN-limited hierarchies are the KDFa of their base
/// hierarchy's proof and the Firmware Secret (the reference platform's dummy: the firmware hash
/// repeated, little-endian) or the Firmware SVN Secret (the SVN repeated, little-endian), and a
/// base hierarchy keeps its own proof.
#[test]
fn limited_proofs_are_derived_from_the_base_proofs() {
    let firmware = SimulatedFirmware::new(0x1122_3344, 10, 255);
    let (mut crypto, mut storage, mut timer, mut rng) = (
        TestCryptoProvider,
        FakeStorage::default(),
        FakeTimer,
        FakeRng::new(),
    );
    let mut tpm = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);
    tpm.platform.firmware = Some(&firmware);

    let sh_proof = tpm.state.sh_proof[..tpm.state.sh_proof_size as usize].to_vec();
    let eh_proof = tpm.state.eh_proof[..tpm.state.eh_proof_size as usize].to_vec();
    let null_proof = tpm.state.null_proof[..tpm.state.null_proof_size as usize].to_vec();
    let fw_secret: Vec<u8> = (0..64).map(|i| [0x44, 0x33, 0x22, 0x11][i % 4]).collect();
    let svn_secret = |svn: u16| -> Vec<u8> { (0..64).map(|i| svn.to_le_bytes()[i % 2]).collect() };

    for (hierarchy, proof) in [
        (Handle::RH_OWNER, sh_proof.clone()),
        (
            Handle::RH_FW_OWNER,
            limited_proof(&sh_proof, &fw_secret, b"H_FW_SECRET\0"),
        ),
        (
            Handle::RH_FW_NULL,
            limited_proof(&null_proof, &fw_secret, b"H_FW_SECRET\0"),
        ),
        (
            Handle(Handle::RH_SVN_ENDORSEMENT_BASE.0 + 7),
            limited_proof(&eh_proof, &svn_secret(7), b"H_SVN_SECRET\0"),
        ),
        (
            Handle(Handle::RH_SVN_OWNER_BASE.0),
            limited_proof(&sh_proof, &svn_secret(0), b"H_SVN_SECRET\0"),
        ),
    ] {
        let (digest, ticket) = hash_ticket(&mut tpm, hierarchy).unwrap();
        assert_eq!(ticket, hashcheck_ticket(&proof, &digest), "{hierarchy:?}");
    }
}

/// Without a platform firmware the limited hierarchies are not supported: their handles fail
/// with `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED` (at the handle, or where a ticket needs the
/// proof), they are not listed by `TPM_CAP_HANDLES`, and the firmware SVN properties are 0.
#[test]
fn limited_hierarchies_need_a_platform_firmware() {
    let (mut crypto, mut storage, mut timer, mut rng) = (
        TestCryptoProvider,
        FakeStorage::default(),
        FakeTimer,
        FakeRng::new(),
    );
    let mut tpm = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);
    assert!(tpm.platform.firmware.is_none());

    assert_eq!(
        create_primary(&mut tpm, Handle::RH_FW_OWNER),
        Err(TpmRc::FW_LIMITED.with(Position::handle(1)).get())
    );
    assert_eq!(
        create_primary(&mut tpm, Handle(Handle::RH_SVN_OWNER_BASE.0)),
        Err(TpmRc::SVN_LIMITED.with(Position::handle(1)).get())
    );
    assert_eq!(
        hash_ticket(&mut tpm, Handle::RH_FW_NULL),
        Err(TpmRc::FW_LIMITED.to_rc().get())
    );
    assert_eq!(
        hash_ticket(&mut tpm, Handle(Handle::RH_SVN_NULL_BASE.0)),
        Err(TpmRc::SVN_LIMITED.to_rc().get())
    );
    assert!(
        permanent_handles(&mut tpm, 0x4000_0000)
            .iter()
            .all(|&h| h < 0x4000_0140)
    );
    assert_eq!(firmware_svn_properties(&mut tpm), (0, 0));
}

/// With a platform firmware the limited hierarchies are listed, an SVN-limited hierarchy is
/// available up to the firmware's current SVN, and a firmware SVN change (a firmware update) moves
/// that limit.
#[test]
fn svn_limit_follows_the_platform_firmware() {
    let firmware = SimulatedFirmware::default();
    let (mut crypto, mut storage, mut timer, mut rng) = (
        TestCryptoProvider,
        FakeStorage::default(),
        FakeTimer,
        FakeRng::new(),
    );
    let mut tpm = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);
    tpm.platform.firmware = Some(&firmware);

    assert_eq!(
        permanent_handles(&mut tpm, 0x4000_0140),
        [
            0x4000_0140,
            0x4000_0141,
            0x4000_0142,
            0x4000_0143,
            0x4001_0000,
            0x4002_0000,
            0x4003_0000,
            0x4004_0000
        ]
    );
    assert_eq!(firmware_svn_properties(&mut tpm), (10, 255));
    let svn = |s: u32| Handle(Handle::RH_SVN_PLATFORM_BASE.0 + s);
    let handle = create_primary(&mut tpm, svn(10)).unwrap();
    let flush = tpm2::commands::FlushContext {
        flush_handle: handle,
    };
    execute_command(&mut tpm, &flush, &[]).unwrap();
    assert_eq!(
        create_primary(&mut tpm, svn(11)),
        Err(TpmRc::SVN_LIMITED.with(Position::handle(1)).get())
    );
    firmware.set_firmware_svn(11);
    let handle = create_primary(&mut tpm, svn(11)).unwrap();
    let flush = tpm2::commands::FlushContext {
        flush_handle: handle,
    };
    execute_command(&mut tpm, &flush, &[]).unwrap();
    assert_eq!(firmware_svn_properties(&mut tpm), (11, 255));
    firmware.set_firmware_svn(3);
    assert_eq!(
        create_primary(&mut tpm, svn(4)),
        Err(TpmRc::SVN_LIMITED.with(Position::handle(1)).get())
    );
    assert_eq!(
        hash_ticket(&mut tpm, svn(4)),
        Err(TpmRc::SVN_LIMITED.to_rc().get())
    );
}
