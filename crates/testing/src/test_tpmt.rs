use crate::test_utils::marshal_to_slice;
use tpm2::Unmarshal;
use tpm2::*;
#[test]
fn test_tpmt() {
    let tpms_derive = TpmsDerive {
        label: Tpm2bLabel::from_bytes(b"label").unwrap(),
        context: Tpm2bLabel::from_bytes(b"context").unwrap(),
    };
    let mut derive_buf = [0u8; 1024];
    let derive_len = marshal_to_slice(&tpms_derive, &mut derive_buf);

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"p@ssw0rd").unwrap(),
        data: Tpm2bSensitiveData::from_bytes(&derive_buf[..derive_len]).unwrap(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);
    println!(
        "in_sensitive size: {}",
        crate::test_utils::marshal_to_vec(&in_sensitive.0).len()
    );
    let mut serialized = [0u8; 1024];
    let len = marshal_to_slice(&in_sensitive, &mut serialized);
    println!("Serialized length: {}", len);

    // Test unmarshal
    let mut unmarshal_buf = &serialized[..len];
    let unmarshaled = Tpm2bSensitiveCreate::unmarshal(&mut unmarshal_buf).unwrap();
    let _ = unmarshaled.0;
}

#[test]
fn test_incremental_self_test_reserved_alg_error_codes() {
    use tpm2::errors::{Position, TpmRc};
    use tpm2_platform_linux::LinuxRng;
    use tpm2_simulator::{Simulator, create_simulator};

    let mut sim = create_simulator!();

    let expected_size = TpmRc::SIZE.get();
    let expected_val_p1 = TpmRc::VALUE.with(Position::parameter(1)).get();
    let expected_insufficient = TpmRc::INSUFFICIENT.with(Position::parameter(1)).get();

    for reserved_id in [0x0000u16, 0x00C1, 0x00C4, 0x00C6, 0x8000, 0x8021, 0xFFFF] {
        // 1. Trailing bytes after reserved TPM_ALG_ID -> must return TPM_RC_SIZE (0x00000095)
        // Header: tag = TPM_ST_NO_SESSIONS (0x8001), size = 17, cc = TPM_CC_IncrementalSelfTest (0x00000142)
        // Payload: count = 1 (0x00000001), alg[0] = reserved_id, trailing byte = 0xFF
        let mut cmd_trailing = Vec::new();
        cmd_trailing.extend_from_slice(&0x8001u16.to_be_bytes());
        cmd_trailing.extend_from_slice(&17u32.to_be_bytes());
        cmd_trailing.extend_from_slice(&0x00000142u32.to_be_bytes());
        cmd_trailing.extend_from_slice(&1u32.to_be_bytes());
        cmd_trailing.extend_from_slice(&reserved_id.to_be_bytes());
        cmd_trailing.push(0xFF);

        let mut rsp = [0u8; 64];
        let out = sim.transact(&cmd_trailing, &mut rsp).unwrap();
        let rc = u32::from_be_bytes(out[6..10].try_into().unwrap());
        assert_eq!(
            rc, expected_size,
            "Expected TPM_RC_SIZE (0x{:08X}) on trailing bytes with reserved alg 0x{:04X}, got 0x{:08X}",
            expected_size, reserved_id, rc
        );

        // 2. Exact buffer with reserved TPM_ALG_ID -> must return TPM_RC_VALUE | TPM_RC_P | TPM_RC_1 (0x000001C4)
        let mut cmd_exact = Vec::new();
        cmd_exact.extend_from_slice(&0x8001u16.to_be_bytes());
        cmd_exact.extend_from_slice(&16u32.to_be_bytes());
        cmd_exact.extend_from_slice(&0x00000142u32.to_be_bytes());
        cmd_exact.extend_from_slice(&1u32.to_be_bytes());
        cmd_exact.extend_from_slice(&reserved_id.to_be_bytes());

        let out_exact = sim.transact(&cmd_exact, &mut rsp).unwrap();
        let rc_exact = u32::from_be_bytes(out_exact[6..10].try_into().unwrap());
        assert_eq!(
            rc_exact, expected_val_p1,
            "Expected TPM_RC_VALUE | TPM_RC_P | TPM_RC_1 (0x{:08X}) for reserved alg 0x{:04X}, got 0x{:08X}",
            expected_val_p1, reserved_id, rc_exact
        );

        // 3. Truncated buffer after reserved TPM_ALG_ID (count = 2, only 1 byte of 2nd alg) -> TPM_RC_INSUFFICIENT (0x0000009A)
        let mut cmd_trunc = Vec::new();
        cmd_trunc.extend_from_slice(&0x8001u16.to_be_bytes());
        cmd_trunc.extend_from_slice(&17u32.to_be_bytes());
        cmd_trunc.extend_from_slice(&0x00000142u32.to_be_bytes());
        cmd_trunc.extend_from_slice(&2u32.to_be_bytes());
        cmd_trunc.extend_from_slice(&reserved_id.to_be_bytes());
        cmd_trunc.push(0x00);

        let out_trunc = sim.transact(&cmd_trunc, &mut rsp).unwrap();
        let rc_trunc = u32::from_be_bytes(out_trunc[6..10].try_into().unwrap());
        assert_eq!(
            rc_trunc, expected_insufficient,
            "Expected TPM_RC_INSUFFICIENT (0x{:08X}) on truncated buffer after reserved alg 0x{:04X}, got 0x{:08X}",
            expected_insufficient, reserved_id, rc_trunc
        );
    }
}
