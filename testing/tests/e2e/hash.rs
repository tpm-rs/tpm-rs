//! TPM2_Hash: digests and hashcheck tickets for every hash algorithm and hierarchy, plus parameter
//! validation.

use crate::_common::{
    CONTEXT_INTEGRITY_DIGEST_SIZE, execute_tpm_command_via_run, execute_tpm_command_via_send,
    execute_tpm_command_with_corrupted_bytes_via_send, execute_tpm_command_with_extra_bytes, hash,
    hash_request, raw_rc,
};
use sha1::Sha1;
use sha2::{Digest, Sha384, Sha512};
use tpm2::commands::Hash;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bMaxBuffer, TpmiAlgHash};
use tpm2_simulator::create_simulator;

/// TPM2_Hash digests for all banks, rejects an unsupported hash (HASH) and an invalid hierarchy (VALUE).
#[test]
fn algorithms_and_hierarchy_validation() {
    let mut sim = create_simulator!();

    let test_cases = [
        (TpmiAlgHash::Sha1, 20),
        (TpmiAlgHash::Sha256, 32),
        (TpmiAlgHash::Sha384, 48),
        (TpmiAlgHash::Sha512, 64),
    ];

    let hierarchies = [
        Handle::RH_OWNER,
        Handle::RH_ENDORSEMENT,
        Handle::RH_PLATFORM,
        Handle::RH_NULL,
    ];

    let data_inputs: &[&[u8]] = &[
        b"",
        b"Hello, World!",
        &[0u8; 1024], // Max buffer size representation
    ];

    // Test happy paths
    for &(alg, expected_len) in &test_cases {
        for &hierarchy in &hierarchies {
            for &data in data_inputs {
                let hash_cmd = Hash {
                    data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
                    hash_alg: alg,
                    hierarchy,
                };
                let resp = execute_tpm_command_via_send(&mut sim, &hash_cmd, &[]).unwrap();
                assert_eq!(resp.out_hash.get_size() as usize, expected_len);
                assert_eq!(resp.validation.tag(), 0x8024);
                assert_eq!(resp.validation.hierarchy(), hierarchy);
                if hierarchy == Handle::RH_NULL {
                    assert_eq!(resp.validation.digest().get_size() as usize, 0);
                    assert_eq!(resp.validation.digest().get_buffer(), &[] as &[u8]);
                } else {
                    assert_eq!(
                        resp.validation.digest().get_size() as usize,
                        CONTEXT_INTEGRITY_DIGEST_SIZE
                    );
                }
            }
        }
    }

    // Test error: unsupported hash algorithm
    let invalid_hash_cmd = Hash {
        data: Tpm2bMaxBuffer::default(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_tpm_command_with_corrupted_bytes_via_send(
        &mut sim,
        &invalid_hash_cmd,
        &[],
        |buf| {
            buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        },
    );
    assert_eq!(
        res.unwrap_err(),
        TpmRc::HASH.with(Position::parameter(2)).get()
    );

    // Test error: invalid hierarchy
    let invalid_hier_cmd = Hash {
        data: Tpm2bMaxBuffer::default(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle(1), // Invalid hierarchy handle (e.g. PCR1)
    };
    let res2 = execute_tpm_command_via_send(&mut sim, &invalid_hier_cmd, &[]);
    assert!(res2.is_err());
    let rc2 = res2.unwrap_err();
    assert_eq!(rc2, TpmRc::VALUE.with(Position::parameter(3)).get());
}

/// TPM2_Hash returns correct digests and tickets for every hash alg and hierarchy
#[test]
fn hash_every_alg_and_hierarchy() {
    let mut sim = create_simulator!();

    let test_data = b"Multialg data check";

    let scenarios = [
        (TpmiAlgHash::Sha1, Handle::RH_OWNER),
        (TpmiAlgHash::Sha256, Handle::RH_ENDORSEMENT),
        (TpmiAlgHash::Sha384, Handle::RH_PLATFORM),
        (TpmiAlgHash::Sha512, Handle::RH_NULL),
    ];

    for (alg, hierarchy) in scenarios {
        let cmd = Hash {
            data: Tpm2bMaxBuffer::from_bytes(test_data).unwrap(),
            hash_alg: alg,
            hierarchy,
        };

        let resp = execute_tpm_command_via_run(&mut sim, &cmd, &[]).unwrap();
        let expected_digest = hash(alg, test_data);

        assert_eq!(resp.out_hash.get_buffer(), &expected_digest[..]);
        assert_eq!(resp.validation.hierarchy(), hierarchy);
        if hierarchy == Handle::RH_NULL {
            assert_eq!(resp.validation.digest().get_buffer(), &[] as &[u8]);
        } else {
            assert_eq!(
                resp.validation.digest().get_size() as usize,
                CONTEXT_INTEGRITY_DIGEST_SIZE
            );
        }
    }
}

/// TPM2_Hash with an invalid hierarchy fails with TPM_RC_VALUE
#[test]
fn hash_rejects_invalid_hierarchy() {
    let mut sim = create_simulator!();

    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle(0x80000000), // invalid hierarchy handle
    };

    let res = execute_tpm_command_via_run(&mut sim, &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(3)).get())
    );
}

/// TPM2_Hash with trailing bytes after its parameters fails with TPM_RC_SIZE
#[test]
fn hash_rejects_trailing_bytes() {
    let mut sim = create_simulator!();

    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };

    let res = execute_tpm_command_with_extra_bytes(&mut sim, &cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
}

/// TPM2_Hash with an unimplemented hashAlg fails with TPM_RC_HASH
#[test]
fn hash_rejects_unsupported_alg() {
    let mut sim = create_simulator!();

    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sm3_256, // invalid/unsupported alg for Hash command
        hierarchy: Handle::RH_NULL,
    };

    let res = execute_tpm_command_via_run(&mut sim, &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(Position::parameter(2)).get())
    );
}

/// TPM2_Hash with SHA-256 returns the correct digest and a hashcheck ticket
#[test]
fn hash_sha256_returns_digest_and_ticket() {
    let mut sim = create_simulator!();

    let test_data = b"Hello Adversary Hash!";
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(test_data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };

    let resp = execute_tpm_command_via_run(&mut sim, &cmd, &[]).unwrap();
    let expected_digest = hash(TpmiAlgHash::Sha256, test_data);
    assert_eq!(resp.out_hash.get_buffer(), &expected_digest[..]);

    // Verify ticket
    assert_eq!(resp.validation.tag(), 0x8024);
    assert_eq!(resp.validation.hierarchy(), Handle::RH_NULL);
    assert_eq!(resp.validation.digest().get_buffer(), &[] as &[u8]);
}

/// Regression test for CPCTPM_TC2_2_17_03_04:
/// TPM2_Hash with an invalid/unsupported hash algorithm (TPM_ALG_AES = 0x0006 or TPM_ALG_NULL = 0x0010)
/// must return TPM_RC_HASH (Parameter 2, 0x02C3), not TPM_RC_SIZE.
#[test]
fn invalid_hash_alg_rejected() {
    let mut sim = create_simulator!();

    // TPM2_Hash request with hashAlg = TPM_ALG_AES (0x0006)
    let rc = raw_rc(&mut sim, &hash_request(0x0006));
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH (0x02C3) for TPM2_Hash with invalid hashAlg"
    );

    // TPM2_Hash request with hashAlg = TPM_ALG_NULL (0x0010)
    let rc_null = raw_rc(&mut sim, &hash_request(0x0010));
    assert_eq!(
        rc_null,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH (0x02C3) for TPM2_Hash with TPM_ALG_NULL hashAlg"
    );
}

/// TPM2_Hash with SHA-1/SHA-384/SHA-512, and rejection of an unsupported
/// hash algorithm (SM3-256). The Go test only covers SHA-256.
#[test]
fn sha1_sha384_sha512_and_unsupported() {
    let mut sim = create_simulator!();

    let data = b"fiona";

    // Test SHA-1
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha1,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).unwrap();
    let expected = Sha1::digest(data);
    assert_eq!(resp.out_hash.as_ref(), expected.as_slice());

    // Test SHA-384
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha384,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).unwrap();
    let expected = Sha384::digest(data);
    assert_eq!(resp.out_hash.as_ref(), expected.as_slice());

    // Test SHA-512
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha512,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).unwrap();
    let expected = Sha512::digest(data);
    assert_eq!(resp.out_hash.as_ref(), expected.as_slice());

    // Test invalid hash algorithm
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sm3_256,
        hierarchy: Handle::RH_NULL,
    };
    assert!(sim.execute(cmd).is_err());
}
