//! TPM2_TestParms parsing and cross-checks: unknown selectors, truncation, NULL hashes and
//! randomized comparison with a reference oracle.

use crate::_common::{
    CC_ECC_PARAMETERS, ST_NO_SESSIONS, SimpleRng, build_raw_cmd, gen_random_parms, hex,
    mssim_rc_of, oracle_validate_parms, rc_p, symcipher_parms, test_parms, transact_rc_of,
};
use tpm2::commands::TestParms;
use tpm2::errors::{Position, TpmRc};
use tpm2_simulator::{ExecuteError, create_simulator};

/// Differential fuzzing of `TPM2_TestParms` against a reference oracle with a fixed seed.
#[test]
fn differential_fuzz_against_oracle() {
    let mut sim = create_simulator!();

    // Use a fixed seed for reproducible fuzzing
    let mut fuzzer_rng = SimpleRng::new(13372026);

    let num_iterations = 2000;
    let mut passed_count = 0;

    for i in 0..num_iterations {
        let parms = gen_random_parms(&mut fuzzer_rng);
        let expected = oracle_validate_parms(&parms);

        let cmd = TestParms { parameters: parms };
        let res = sim.execute(cmd).map_err(|e| e.get());

        match (expected, res) {
            (Ok(()), Ok(_)) => {
                passed_count += 1;
            }
            (Err(exp_err), Err(act_err)) => {
                assert_eq!(
                    exp_err.get(),
                    act_err,
                    "Mismatch on iteration {}. Parms: {:?}",
                    i,
                    parms
                );
                passed_count += 1;
            }
            (Ok(()), Err(act_err)) => {
                panic!(
                    "Iteration {} mismatch! Oracle expected SUCCESS, but TPM returned error code: 0x{:08X}. Parms: {:?}",
                    i, act_err, parms
                );
            }
            (Err(exp_err), Ok(_)) => {
                panic!(
                    "Iteration {} mismatch! Oracle expected error code 0x{:08X}, but TPM returned SUCCESS. Parms: {:?}",
                    i,
                    exp_err.get(),
                    parms
                );
            }
        }
    }

    println!(
        "Passed {} differential fuzz test cases successfully.",
        passed_count
    );
}

/// Fuzzes `TPM2_TestParms` with 1000 random (valid and invalid) parameter sets and compares
/// every response code against an oracle of the C reference behaviour.
#[test]
fn random_parms_match_reference_oracle() {
    let mut sim = create_simulator!();

    let mut rng = SimpleRng::new(42);
    let mut passed = 0;

    for i in 0..1000 {
        let parms = gen_random_parms(&mut rng);
        let expected = oracle_validate_parms(&parms);
        let res = sim
            .execute(TestParms { parameters: parms })
            .map_err(|e| match e {
                ExecuteError::Tpm(rc) => rc.get(),
                other => panic!("Unexpected execution error on case {i}: {other}"),
            });

        match (expected, res) {
            (Ok(()), Ok(_)) => {
                passed += 1;
            }
            (Err(exp_err), Err(act_err)) => {
                assert_eq!(
                    exp_err.get(),
                    act_err,
                    "Mismatch on case {}: expected error code {:X}, got {:X}. Parameters: {:?}",
                    i,
                    exp_err.get(),
                    act_err,
                    parms
                );
                passed += 1;
            }
            (Ok(()), Err(act_err)) => {
                panic!(
                    "Mismatch on case {}: expected SUCCESS, but got error {:X}. Parameters: {:?}",
                    i, act_err, parms
                );
            }
            (Err(exp_err), Ok(_)) => {
                panic!(
                    "Mismatch on case {}: expected error {:X}, but got SUCCESS. Parameters: {:?}",
                    i,
                    exp_err.get(),
                    parms
                );
            }
        }
    }
    println!("Fuzz stress test passed {} iterations", passed);
}

/// TestParms with a non-NULL RSA/ECC/keyedHash scheme but a NULL hash or KDF fails with TPM_RC_HASH / TPM_RC_KDF.
#[test]
fn scheme_with_null_hash_or_kdf_rejected() {
    let mut sim = create_simulator!();

    // 1. TPM2_TestParms (0x018A) with RSA (0x0001), symmetric=NULL (0x0010), scheme=RSASSA (0x0014), hash=NULL (0x0010), keyBits=2048 (0x0800), exponent=0 (0x00000000)
    // Total size: 10 (hdr) + 2 (RSA) + 2 (sym) + 2 (RSASSA) + 2 (hash) + 2 (keyBits) + 4 (exponent) = 24 (0x18)
    let req_test_parms_rsa_null_hash =
        hex("8001 00000018 0000018A 0001 0010 0014 0010 0800 00000000");
    assert_eq!(
        transact_rc_of(&mut sim, &req_test_parms_rsa_null_hash),
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "TestParms RSA RSASSA with TPM_ALG_NULL inner hash must return TPM_RC_HASH + P1"
    );

    // 2. TPM2_TestParms (0x018A) with ECC (0x0023), symmetric=NULL (0x0010), scheme=ECDSA (0x0018), hash=NULL (0x0010), curve=NIST_P256 (0x0003), kdf=NULL (0x0010)
    // Total size: 10 + 2 + 2 + 2 + 2 + 2 + 2 = 22 (0x16)
    let req_test_parms_ecc_null_hash = hex("8001 00000016 0000018A 0023 0010 0018 0010 0003 0010");
    assert_eq!(
        transact_rc_of(&mut sim, &req_test_parms_ecc_null_hash),
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "TestParms ECC ECDSA with TPM_ALG_NULL inner hash must return TPM_RC_HASH + P1"
    );

    // 3. TPM2_TestParms (0x018A) with KeyedHash (0x0008), scheme=XOR (0x000A), hash=SHA256 (0x000B), kdf=NULL (0x0010)
    // Total size: 10 + 2 + 2 + 2 + 2 = 18 (0x12)
    // The C reference accepts it: TPMS_SCHEME_XOR_Unmarshal reads the KDF as TPMI_ALG_KDF+
    // (flag = 1, Marshal.c:3439), so TPM_ALG_NULL is allowed and TestParms succeeds.
    let req_test_parms_xor_null_kdf = hex("8001 00000012 0000018A 0008 000A 000B 0010");
    assert_eq!(
        transact_rc_of(&mut sim, &req_test_parms_xor_null_kdf),
        0,
        "TestParms KeyedHash XOR with TPM_ALG_NULL inner KDF must succeed (C TPMI_ALG_KDF+)"
    );

    // 4. TPM2_TestParms (0x018A) with KeyedHash (0x0008), scheme=XOR (0x000A), hash=NULL (0x0010), kdf=NULL (0x0010)
    // Total size: 18 (0x12)
    let req_test_parms_xor_null_hash = hex("8001 00000012 0000018A 0008 000A 0010 0010");
    assert_eq!(
        transact_rc_of(&mut sim, &req_test_parms_xor_null_hash),
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "TestParms KeyedHash XOR with TPM_ALG_NULL inner hash must return TPM_RC_HASH + P1"
    );

    // 5. TPM2_TestParms (0x018A) with KeyedHash (0x0008), scheme=XOR (0x000A), hash=SHA256 (0x000B), kdf=SHA256 (0x000B, invalid KDF)
    // Total size: 18 (0x12)
    let req_test_parms_xor_invalid_kdf = hex("8001 00000012 0000018A 0008 000A 000B 000B");
    assert_eq!(
        transact_rc_of(&mut sim, &req_test_parms_xor_invalid_kdf),
        TpmRc::KDF.with(Position::parameter(1)).get(),
        "TestParms KeyedHash XOR with invalid inner KDF must return TPM_RC_KDF + P1"
    );
}

/// Truncated `TPM2_TestParms` input reports the unmarshal error; `TPM2_ECC_Parameters` rejects an
/// unimplemented curve before checking for trailing bytes.
#[test]
fn truncated_input_and_unsupported_curve() {
    let mut sim = create_simulator!();
    let mut trailing = symcipher_parms(0x0043);
    trailing.push(0xAA);
    assert_eq!(test_parms(&mut sim, &trailing), TpmRc::SIZE.get());

    // SYMCIPHER / AES without keyBits and mode.
    let mut truncated = 0x0025u16.to_be_bytes().to_vec();
    truncated.extend_from_slice(&0x0006u16.to_be_bytes());
    assert_eq!(
        test_parms(&mut sim, &truncated),
        rc_p(TpmRc::INSUFFICIENT, 1)
    );

    // NIST P-192 unmarshals as a curve ID but is not implemented.
    let mut params = 0x0001u16.to_be_bytes().to_vec();
    params.push(0);
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_ECC_PARAMETERS, &[], None, &params);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_p(TpmRc::CURVE, 1));
    // An implemented curve with trailing bytes is a size error.
    let mut params = 0x0003u16.to_be_bytes().to_vec();
    params.push(0);
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_ECC_PARAMETERS, &[], None, &params);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::SIZE.get());
}

/// Malformed `TPM2_TestParms` parameter buffers: unknown selector and truncated parameters.
#[test]
fn unknown_selector_and_truncated_parameters() {
    let mut sim = create_simulator!();
    let mut response = [0u8; 256];

    // 1. Unknown selector in TpmtPublicParms (e.g. 0x0004 which is SHA1, not a valid public parms algorithm)
    // Header: Tag (8001), Size (0000000C), CmdCode (0000018A), Discriminant (0004)
    let request_unknown_selector = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x8a, 0x00, 0x04,
    ];
    let resp = sim
        .transact(&request_unknown_selector, &mut response)
        .unwrap();
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    // C TPMI_ALG_PUBLIC_Unmarshal rejects an unknown selector with TPM_RC_TYPE (+ RC_P1).
    assert_eq!(rc, TpmRc::TYPE.with(Position::parameter(1)).get());

    // 2. Truncated buffer
    // Discriminant is RSA (0001), but nothing else is provided.
    // TpmsRsaParms needs symmetric, scheme, key_bits, exponent.
    let request_truncated = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x8a, 0x00, 0x01,
    ];
    let resp = sim.transact(&request_truncated, &mut response).unwrap();
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    // C: the parameter buffer runs out while unmarshaling -> TPM_RC_INSUFFICIENT + RC_P1.
    assert_eq!(rc, TpmRc::INSUFFICIENT.with(Position::parameter(1)).get());
}

/// `TPM2_TestParms` accepts a NULL KDF in `TPMS_SCHEME_XOR` and reports trailing bytes as
/// `TPM_RC_SIZE`.
#[test]
fn xor_null_kdf_and_trailing_bytes() {
    let mut sim = create_simulator!();
    let mut xor = 0x0008u16.to_be_bytes().to_vec();
    xor.extend_from_slice(&0x000Au16.to_be_bytes()); // XOR
    xor.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
    xor.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf NULL
    assert_eq!(test_parms(&mut sim, &xor), 0);

    let mut trailing = symcipher_parms(0x0043);
    trailing.push(0);
    assert_eq!(test_parms(&mut sim, &trailing), TpmRc::SIZE.get());
}
