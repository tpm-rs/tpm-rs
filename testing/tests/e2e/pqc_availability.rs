//! Availability of the post-quantum features by profile: TPM2_Encapsulate and TPM2_Decapsulate
//! in `TPM_CAP_COMMANDS` (with their `TPMA_CC`) when `cc-encapsulate`/`cc-decapsulate`
//! implements them and `TPM_RC_COMMAND_CODE` when not; TPM_ALG_MLKEM, TPM_ALG_MLDSA and
//! TPM_ALG_HASH_MLDSA in `TPM_CAP_ALGS` (with their `TPMA_ALGORITHM`) when `mlkem`/`mldsa`/
//! `hash_mldsa` implements them, and rejected by TPM2_TestParms when not; and
//! TPM_PT_ML_PARAMETER_SETS reporting exactly the implemented parameter sets.

use crate::_common::{CAP_ALGS, CAP_COMMANDS, build_raw_cmd, get_cap, send_with_rc};
use testing::tpm::Tpm;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, TpmCc, TpmPt, TpmaAlgorithm};

/// Raw `TPM_CAP_TPM_PROPERTIES` capability.
const CAP_TPM_PROPERTIES: u32 = 6;

/// Each command, whether its profile feature implements it, and its expected `TPMA_CC` bits
/// above `commandIndex` (one command handle, no *rHandle*).
fn commands() -> [(TpmCc, bool, u32); 2] {
    [
        (
            TpmCc::Encapsulate,
            cfg!(feature = "cc-encapsulate"),
            1 << 25,
        ),
        (
            TpmCc::Decapsulate,
            cfg!(feature = "cc-decapsulate"),
            1 << 25,
        ),
    ]
}

/// Each algorithm, whether its feature implements it, its expected `TPMA_ALGORITHM` and the
/// parameter bytes of a `TPMT_PUBLIC_PARMS` of that type after the type.
fn algorithms() -> [(Alg, bool, TpmaAlgorithm, &'static [u8]); 3] {
    let signing = TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::OBJECT | TpmaAlgorithm::SIGNING;
    [
        (
            Alg::MLKEM,
            cfg!(feature = "mlkem"),
            TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::OBJECT,
            // symmetric TPM_ALG_NULL, TPM_MLKEM_768
            &[0x00, 0x10, 0x00, 0x02],
        ),
        (
            Alg::MLDSA,
            cfg!(feature = "mldsa"),
            signing,
            // TPM_MLDSA_65, allowExternalMu NO
            &[0x00, 0x02, 0x00],
        ),
        (
            Alg::HASH_MLDSA,
            cfg!(feature = "hash_mldsa"),
            signing,
            // TPM_MLDSA_65, TPM_ALG_SHA256
            &[0x00, 0x02, 0x00, 0x0B],
        ),
    ]
}

/// An implemented command is listed in `TPM_CAP_COMMANDS` with its `TPMA_CC`; an
/// unimplemented one is not listed.
#[test]
fn commands_listed_in_capability_when_implemented() {
    let mut sim = Tpm::new();
    for (cc, implemented, bits) in commands() {
        let (_, data) = get_cap(&mut sim, CAP_COMMANDS, cc.code(), 1).unwrap();
        let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let first = (count > 0).then(|| u32::from_be_bytes(data[4..8].try_into().unwrap()));
        let listed = first.filter(|attr| attr & 0xFFFF == cc.code());
        if implemented {
            let attr = listed.unwrap_or_else(|| panic!("{cc:?} not in TPM_CAP_COMMANDS"));
            assert_eq!(attr & !0xFFFF, bits, "TPMA_CC of {cc:?}: {attr:#010x}");
        } else {
            assert_eq!(listed, None, "{cc:?} listed but not implemented");
        }
    }
}

/// An unimplemented command is rejected with `TPM_RC_COMMAND_CODE`.
#[test]
fn unimplemented_commands_rejected() {
    let mut sim = Tpm::new();
    for (cc, implemented, _) in commands() {
        if implemented {
            continue;
        }
        let cmd = build_raw_cmd(0x8001, cc.code(), &[0x8000_0000], None, &[]);
        let (rc, _) = send_with_rc(&mut sim, &cmd);
        assert_eq!(rc, TpmRc::COMMAND_CODE.get(), "{cc:?}");
    }
}

/// An implemented algorithm is listed in `TPM_CAP_ALGS` with its `TPMA_ALGORITHM`; an
/// unimplemented one is not listed.
#[test]
fn algorithms_listed_in_capability_when_implemented() {
    let mut sim = Tpm::new();
    for (alg, implemented, properties, _) in algorithms() {
        let (_, data) = get_cap(&mut sim, CAP_ALGS, u32::from(alg.id()), 1).unwrap();
        let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let first = (count > 0).then(|| {
            (
                u16::from_be_bytes(data[4..6].try_into().unwrap()),
                u32::from_be_bytes(data[6..10].try_into().unwrap()),
            )
        });
        let listed = first.filter(|(id, _)| *id == alg.id());
        if implemented {
            let (_, attr) = listed.unwrap_or_else(|| panic!("{alg:?} not in TPM_CAP_ALGS"));
            assert_eq!(attr, properties.0, "TPMA_ALGORITHM of {alg:?}");
        } else {
            assert_eq!(listed, None, "{alg:?} listed but not implemented");
        }
    }
}

/// TPM2_TestParms accepts the parameters of an implemented algorithm and rejects those of an
/// unimplemented one with TPM_RC_TYPE + P1 (its `TPMI_ALG_PUBLIC` does not unmarshal).
#[test]
fn test_parms_follows_implemented_algorithms() {
    let mut sim = Tpm::new();
    for (alg, implemented, _, parms) in algorithms() {
        let mut params = alg.id().to_be_bytes().to_vec();
        params.extend_from_slice(parms);
        let cmd = build_raw_cmd(0x8001, TpmCc::TestParms.code(), &[], None, &params);
        let (rc, _) = send_with_rc(&mut sim, &cmd);
        let rc = if rc == 0 { Ok(()) } else { Err(rc) };
        let expected = if implemented {
            Ok(())
        } else {
            Err(TpmRc::TYPE.with(Position::parameter(1)).get())
        };
        assert_eq!(rc, expected, "{alg:?}");
    }
}

/// TPM_PT_ML_PARAMETER_SETS reports the three ML-KEM parameter sets with `mlkem`, the three
/// ML-DSA parameter sets and extMu with `mldsa`, and is not reported without either.
#[test]
fn ml_parameter_sets_follow_implemented_algorithms() {
    let mut sim = Tpm::new();
    let property = u32::from(TpmPt::ML_PARAMETER_SETS);
    let (_, data) = get_cap(&mut sim, CAP_TPM_PROPERTIES, property, 1).unwrap();
    let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let reported = (count > 0)
        .then(|| {
            (
                u32::from_be_bytes(data[4..8].try_into().unwrap()),
                u32::from_be_bytes(data[8..12].try_into().unwrap()),
            )
        })
        .filter(|(p, _)| *p == property)
        .map(|(_, value)| value);
    let mut expected = 0;
    if cfg!(feature = "mlkem") {
        expected |= 0x07;
    }
    if cfg!(feature = "mldsa") {
        expected |= 0x78;
    }
    assert_eq!(reported, (expected != 0).then_some(expected));
}
