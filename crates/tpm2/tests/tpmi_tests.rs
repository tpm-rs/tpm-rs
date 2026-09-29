// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use tpm2::errors::UnmarshalError;
use tpm2::*;

#[test]
fn test_tpmi_rsa_key_bits_unmarshal_valid() {
    let valid_bits: &[u16] = &[
        #[cfg(feature = "rsa1024")]
        1024,
        #[cfg(feature = "rsa2048")]
        2048,
        #[cfg(feature = "rsa3072")]
        3072,
        #[cfg(feature = "rsa4096")]
        4096,
    ];
    for &bits in valid_bits {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&bits.to_be_bytes());
        buf[2..4].copy_from_slice(&[0xAA, 0xBB]);

        let mut slice: &[u8] = &buf;
        let unmarshalled = TpmiRsaKeyBits::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshalled, TpmiRsaKeyBits(bits));
        assert_eq!(u16::from(unmarshalled), bits);
        assert_eq!(slice, &[0xAA, 0xBB]);
    }

    #[cfg(not(feature = "rsa1024"))]
    assert_eq!(TpmiRsaKeyBits::try_from(1024), Err(UnmarshalError::VALUE));
    #[cfg(not(feature = "rsa2048"))]
    assert_eq!(TpmiRsaKeyBits::try_from(2048), Err(UnmarshalError::VALUE));
    #[cfg(not(feature = "rsa3072"))]
    assert_eq!(TpmiRsaKeyBits::try_from(3072), Err(UnmarshalError::VALUE));
    #[cfg(not(feature = "rsa4096"))]
    assert_eq!(TpmiRsaKeyBits::try_from(4096), Err(UnmarshalError::VALUE));
}

#[test]
fn test_feature_dependent_max_sizes_and_selectors() {
    assert_eq!(TpmiAlgHash::MAX_DIGEST_BYTES, TpmtHa::MAX_DIGEST_SIZE);
    assert_eq!(
        TPM2_MAX_SYM_KEY_BYTES as usize,
        TpmtSymDefObject::MAX_KEY_BYTES
    );
    assert_eq!(
        TPM2_MAX_RSA_KEY_BYTES as usize,
        TpmiRsaKeyBits::MAX_PUB_KEY_BYTES
    );
    assert_eq!(
        TpmEccCurve::MAX_ECC_KEY_BYTES,
        TpmEccCurve::MAX_ECC_KEY_BITS.div_ceil(8)
    );
    assert_eq!(
        <tags::EccParameter as tags::Tpm2bTag>::CAP,
        TpmEccCurve::MAX_ECC_KEY_BYTES
    );
    assert_eq!(
        <tags::Digest as tags::Tpm2bTag>::CAP,
        TpmiAlgHash::MAX_DIGEST_BYTES
    );
    assert_eq!(
        <tags::SymKey as tags::Tpm2bTag>::CAP,
        TpmtSymDefObject::MAX_KEY_BYTES
    );
    assert_eq!(
        <tags::PublicKeyRsa as tags::Tpm2bTag>::CAP,
        TpmiRsaKeyBits::MAX_PUB_KEY_BYTES
    );

    #[cfg(all(feature = "ecc_curve_nist_p521", not(feature = "ecc_curve_bn_p638")))]
    {
        assert_eq!(TpmEccCurve::MAX_ECC_KEY_BITS, 521);
        assert_eq!(TpmEccCurve::MAX_ECC_KEY_BYTES, 66);
    }

    #[cfg(not(feature = "rsa"))]
    {
        assert_eq!(TpmiAlgPublic::try_from(Alg::RSA), Err(UnmarshalError::TYPE));
        let mut src = &Alg::RSA.id().to_be_bytes()[..];
        assert_eq!(
            TpmtPublicParms::unmarshal(&mut src),
            Err(UnmarshalError::TYPE)
        );
        let mut empty = &[][..];
        assert_eq!(
            PublicParmsAndId::unmarshal_variant(Alg::RSA, &mut empty),
            Err(UnmarshalError::SELECTOR)
        );
        assert_eq!(
            TpmuPublicId::unmarshal_variant(Alg::RSA, &mut empty),
            Err(UnmarshalError::SELECTOR)
        );
        assert_eq!(
            TpmuSensitiveComposite::unmarshal_variant(Alg::RSA, &mut empty),
            Err(UnmarshalError::SELECTOR)
        );
    }

    #[cfg(not(feature = "ecc"))]
    {
        assert_eq!(TpmiAlgPublic::try_from(Alg::ECC), Err(UnmarshalError::TYPE));
        let mut src = &Alg::ECC.id().to_be_bytes()[..];
        assert_eq!(
            TpmtPublicParms::unmarshal(&mut src),
            Err(UnmarshalError::TYPE)
        );
        let mut empty = &[][..];
        assert_eq!(
            PublicParmsAndId::unmarshal_variant(Alg::ECC, &mut empty),
            Err(UnmarshalError::SELECTOR)
        );
        assert_eq!(
            TpmuPublicId::unmarshal_variant(Alg::ECC, &mut empty),
            Err(UnmarshalError::SELECTOR)
        );
        assert_eq!(
            TpmuSensitiveComposite::unmarshal_variant(Alg::ECC, &mut empty),
            Err(UnmarshalError::SELECTOR)
        );
    }
}

#[test]
fn test_tpmi_rsa_key_bits_unmarshal_invalid() {
    for invalid_bits in [
        0u16,
        1,
        512,
        1023,
        1025,
        2047,
        2049,
        4095,
        4097,
        8192,
        9999,
        u16::MAX,
    ] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&invalid_bits.to_be_bytes());
        buf[2..4].copy_from_slice(&[0xCC, 0xDD]);

        let mut slice: &[u8] = &buf;
        let res = TpmiRsaKeyBits::unmarshal(&mut slice);
        assert_eq!(res, Err(UnmarshalError::VALUE));
    }
}

#[test]
fn test_tpmi_rsa_key_bits_unmarshal_insufficient() {
    let buf = [0x08u8];
    let mut slice: &[u8] = &buf;
    let res = TpmiRsaKeyBits::unmarshal(&mut slice);
    assert_eq!(res, Err(UnmarshalError::INSUFFICIENT));
}

#[test]
fn test_tpms_rsa_parms_unmarshal_invalid_key_bits() {
    use tpm2::TpmsRsaParms;

    // Wire bytes for TpmsRsaParms:
    // - symmetric: TPM_ALG_NULL (0x0010)
    // - scheme: TPM_ALG_NULL (0x0010)
    // - key_bits: u16
    // - exponent: u32 (0)
    for invalid_bits in [0u16, 512, 9999] {
        let mut buf = [0u8; 10];
        buf[0..2].copy_from_slice(&0x0010u16.to_be_bytes());
        buf[2..4].copy_from_slice(&0x0010u16.to_be_bytes());
        buf[4..6].copy_from_slice(&invalid_bits.to_be_bytes());
        buf[6..10].copy_from_slice(&0u32.to_be_bytes());

        let mut slice: &[u8] = &buf;
        let res = TpmsRsaParms::unmarshal(&mut slice);
        assert_eq!(res, Err(UnmarshalError::VALUE));
    }
}

#[test]
fn test_tpmi_alg_cipher_mode_unmarshal_valid() {
    let valid_modes = [
        (0x0040u16, TpmiAlgCipherMode::CTR),
        (0x0041u16, TpmiAlgCipherMode::OFB),
        (0x0042u16, TpmiAlgCipherMode::CBC),
        (0x0043u16, TpmiAlgCipherMode::CFB),
        (0x0044u16, TpmiAlgCipherMode::ECB),
    ];
    for (alg_id, expected) in valid_modes {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&alg_id.to_be_bytes());
        buf[2..4].copy_from_slice(&[0xAA, 0xBB]);

        let mut slice: &[u8] = &buf;
        let unmarshalled = TpmiAlgCipherMode::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshalled, expected);
        assert_eq!(slice, &[0xAA, 0xBB]);

        let mut slice_opt: &[u8] = &buf;
        let unmarshalled_opt = Option::<TpmiAlgCipherMode>::unmarshal(&mut slice_opt).unwrap();
        assert_eq!(unmarshalled_opt, Some(expected));
        assert_eq!(slice_opt, &[0xAA, 0xBB]);
    }

    // TPM_ALG_NULL (0x0010) unmarshals to None for Option<TpmiAlgCipherMode>
    let mut buf = [0u8; 4];
    buf[0..2].copy_from_slice(&0x0010u16.to_be_bytes());
    buf[2..4].copy_from_slice(&[0xCC, 0xDD]);

    let mut slice_opt: &[u8] = &buf;
    let unmarshalled_opt = Option::<TpmiAlgCipherMode>::unmarshal(&mut slice_opt).unwrap();
    assert_eq!(unmarshalled_opt, None);
    assert_eq!(slice_opt, &[0xCC, 0xDD]);
}

#[test]
fn test_tpmi_alg_cipher_mode_rejects_cmac() {
    // TPM_ALG_CMAC (0x003F) is valid in TpmiAlgSymMode but invalid in TpmiAlgCipherMode
    let cmac_id: u16 = 0x003F;
    let mut buf = [0u8; 4];
    buf[0..2].copy_from_slice(&cmac_id.to_be_bytes());
    buf[2..4].copy_from_slice(&[0xAA, 0xBB]);

    let mut slice: &[u8] = &buf;
    assert_eq!(
        TpmiAlgCipherMode::unmarshal(&mut slice),
        Err(UnmarshalError::MODE)
    );

    let mut slice_opt: &[u8] = &buf;
    assert_eq!(
        Option::<TpmiAlgCipherMode>::unmarshal(&mut slice_opt),
        Err(UnmarshalError::MODE)
    );
}

#[test]
fn test_encrypt_decrypt_unmarshal_rejects_cmac_mode() {
    use tpm2::commands::{EncryptDecrypt, EncryptDecrypt2};

    // EncryptDecrypt parameters:
    // decrypt: u8 (0)
    // mode: u16 (0x003F = TPM_ALG_CMAC)
    // iv_in: TPM2B_IV (size = 16)
    // in_data: TPM2B_MAX_BUFFER (size = 0)
    let mut buf = [0u8; 23];
    buf[0] = 0; // decrypt = false
    buf[1..3].copy_from_slice(&0x003Fu16.to_be_bytes()); // TPM_ALG_CMAC
    buf[3..5].copy_from_slice(&16u16.to_be_bytes()); // iv_in size = 16
    // buf[5..21] is 16 bytes of 0
    buf[21..23].copy_from_slice(&0u16.to_be_bytes()); // in_data size = 0

    let mut slice: &[u8] = &buf;
    let res = EncryptDecrypt::unmarshal(&mut slice);
    assert_eq!(res, Err(UnmarshalError::MODE.in_parameter(2)));

    // EncryptDecrypt2 parameters:
    // in_data: TPM2B_MAX_BUFFER (size = 0)
    // decrypt: u8 (0)
    // mode: u16 (0x003F = TPM_ALG_CMAC)
    // iv_in: TPM2B_IV (size = 16)
    let mut buf2 = [0u8; 23];
    buf2[0..2].copy_from_slice(&0u16.to_be_bytes()); // in_data size = 0
    buf2[2] = 0; // decrypt = false
    buf2[3..5].copy_from_slice(&0x003Fu16.to_be_bytes()); // TPM_ALG_CMAC
    buf2[5..7].copy_from_slice(&16u16.to_be_bytes()); // iv_in size = 16

    let mut slice2: &[u8] = &buf2;
    let res2 = EncryptDecrypt2::unmarshal(&mut slice2);
    assert_eq!(res2, Err(UnmarshalError::MODE.in_parameter(3)));
}

#[test]
fn test_tpmi_alg_reserved_ids_return_specific_errors() {
    for reserved_id in [0x0000u16, 0x00C1, 0x00C4, 0x00C6, 0x8000, 0x8021, 0xFFFF] {
        let bytes = reserved_id.to_be_bytes();

        let mut s1 = &bytes[..];
        assert_eq!(TpmiAlgKdf::unmarshal(&mut s1), Err(UnmarshalError::KDF));
        let mut s1_opt = &bytes[..];
        assert_eq!(
            Option::<TpmiAlgKdf>::unmarshal(&mut s1_opt),
            Err(UnmarshalError::KDF)
        );

        let mut s2 = &bytes[..];
        assert_eq!(
            Option::<TpmiAlgSymMode>::unmarshal(&mut s2),
            Err(UnmarshalError::MODE)
        );

        let mut s3 = &bytes[..];
        assert_eq!(
            TpmiAlgCipherMode::unmarshal(&mut s3),
            Err(UnmarshalError::MODE)
        );
        let mut s3_opt = &bytes[..];
        assert_eq!(
            Option::<TpmiAlgCipherMode>::unmarshal(&mut s3_opt),
            Err(UnmarshalError::MODE)
        );

        let mut s4 = &bytes[..];
        assert_eq!(TpmiAlgHash::unmarshal(&mut s4), Err(UnmarshalError::HASH));
        let mut s4_opt = &bytes[..];
        assert_eq!(
            Option::<TpmiAlgHash>::unmarshal(&mut s4_opt),
            Err(UnmarshalError::HASH)
        );

        let mut s5 = &bytes[..];
        assert_eq!(
            TpmiAlgMacScheme::unmarshal(&mut s5),
            Err(UnmarshalError::SYMMETRIC)
        );
        let mut s5_opt = &bytes[..];
        assert_eq!(
            Option::<TpmiAlgMacScheme>::unmarshal(&mut s5_opt),
            Err(UnmarshalError::SYMMETRIC)
        );

        let mut s6 = &bytes[..];
        assert_eq!(
            TpmiEccKeyExchange::unmarshal(&mut s6),
            Err(UnmarshalError::SCHEME)
        );
        let mut s6_opt = &bytes[..];
        assert_eq!(
            Option::<TpmiEccKeyExchange>::unmarshal(&mut s6_opt),
            Err(UnmarshalError::SCHEME)
        );
    }
}

#[test]
fn test_tpmi_alg_mac_scheme_valid() {
    let mut buf = [0u8; 4];
    buf[0..2].copy_from_slice(&0x003Fu16.to_be_bytes()); // TPM_ALG_CMAC
    buf[2..4].copy_from_slice(&[0x11, 0x22]);

    let mut slice: &[u8] = &buf;
    let res = TpmiAlgMacScheme::unmarshal(&mut slice).unwrap();
    assert_eq!(res, TpmiAlgMacScheme::Cmac);
    assert_eq!(slice, &[0x11, 0x22]);

    let mut slice_opt: &[u8] = &buf;
    let res_opt = Option::<TpmiAlgMacScheme>::unmarshal(&mut slice_opt).unwrap();
    assert_eq!(res_opt, Some(TpmiAlgMacScheme::Cmac));

    // TPM_ALG_NULL unmarshals to None
    let mut null_buf = [0u8; 2];
    null_buf.copy_from_slice(&0x0010u16.to_be_bytes());
    let mut null_slice: &[u8] = &null_buf;
    assert_eq!(
        Option::<TpmiAlgMacScheme>::unmarshal(&mut null_slice).unwrap(),
        None
    );
}

#[test]
fn test_tpmi_dh_object_validation() {
    assert_eq!(
        TpmiDhObject::<false>::try_from(Handle(0x80000001)),
        Ok(TpmiDhObject(Handle(0x80000001)))
    );
    assert_eq!(
        TpmiDhObject::<false>::try_from(Handle(0x81000001)),
        Ok(TpmiDhObject(Handle(0x81000001)))
    );
    assert_eq!(
        TpmiDhObject::<false>::try_from(Handle::RH_NULL),
        Err(UnmarshalError::VALUE)
    );
    assert_eq!(
        TpmiDhObject::<true>::try_from(Handle::RH_NULL),
        Ok(TpmiDhObject(Handle::RH_NULL))
    );
    assert_eq!(
        TpmiDhObject::<true>::try_from(Handle(0x01000001)),
        Err(UnmarshalError::VALUE)
    );
}

#[test]
fn test_tpmi_ecc_key_exchange_valid() {
    let valid: &[(u16, TpmiEccKeyExchange)] = &[
        #[cfg(feature = "ecdh")]
        (0x0019u16, TpmiEccKeyExchange::Ecdh),
        #[cfg(feature = "sm2")]
        (0x001Bu16, TpmiEccKeyExchange::Sm2),
        #[cfg(feature = "ecmqv")]
        (0x001Du16, TpmiEccKeyExchange::Ecmqv),
    ];
    for &(alg_id, expected) in valid {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&alg_id.to_be_bytes());
        buf[2..4].copy_from_slice(&[0x33, 0x44]);

        let mut slice: &[u8] = &buf;
        let res = TpmiEccKeyExchange::unmarshal(&mut slice).unwrap();
        assert_eq!(res, expected);
        assert_eq!(slice, &[0x33, 0x44]);

        let mut slice_opt: &[u8] = &buf;
        let res_opt = Option::<TpmiEccKeyExchange>::unmarshal(&mut slice_opt).unwrap();
        assert_eq!(res_opt, Some(expected));
    }

    #[cfg(not(feature = "ecdh"))]
    assert_eq!(
        TpmiEccKeyExchange::try_from(Alg::ECDH),
        Err(UnmarshalError::SCHEME)
    );
    #[cfg(not(feature = "sm2"))]
    assert_eq!(
        TpmiEccKeyExchange::try_from(Alg::SM2),
        Err(UnmarshalError::SCHEME)
    );
    #[cfg(not(feature = "ecmqv"))]
    assert_eq!(
        TpmiEccKeyExchange::try_from(Alg::ECMQV),
        Err(UnmarshalError::SCHEME)
    );

    // TPM_ALG_NULL unmarshals to None
    let mut null_buf = [0u8; 2];
    null_buf.copy_from_slice(&0x0010u16.to_be_bytes());
    let mut null_slice: &[u8] = &null_buf;
    assert_eq!(
        Option::<TpmiEccKeyExchange>::unmarshal(&mut null_slice).unwrap(),
        None
    );
}

#[test]
fn test_tpmi_dh_parent_and_persistent() {
    assert!(TpmiDhParent::try_from(Handle(0x80000001)).is_ok());
    assert!(TpmiDhParent::try_from(Handle(0x81000001)).is_ok());
    assert!(TpmiDhParent::try_from(Handle::RH_OWNER).is_ok());
    assert!(TpmiDhParent::try_from(Handle::RH_NULL).is_ok());
    assert_eq!(
        TpmiDhParent::try_from(Handle(0x01000001)),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiDhPersistent::try_from(Handle(0x81000001)).is_ok());
    assert_eq!(
        TpmiDhPersistent::try_from(Handle(0x80000001)),
        Err(UnmarshalError::VALUE)
    );
}

#[test]
fn test_tpmi_dh_pcr_and_entity() {
    assert!(TpmiDhPcr::<false>::try_from(Handle(0)).is_ok());
    assert!(TpmiDhPcr::<false>::try_from(Handle(23)).is_ok());
    assert_eq!(
        TpmiDhPcr::<false>::try_from(Handle(24)),
        Err(UnmarshalError::VALUE)
    );
    assert_eq!(
        TpmiDhPcr::<false>::try_from(Handle::RH_NULL),
        Err(UnmarshalError::VALUE)
    );
    assert!(TpmiDhPcr::<true>::try_from(Handle::RH_NULL).is_ok());

    assert!(TpmiDhEntity::<false>::try_from(Handle::RH_OWNER).is_ok());
    assert!(TpmiDhEntity::<false>::try_from(Handle(0x80000001)).is_ok());
    assert!(TpmiDhEntity::<false>::try_from(Handle(0x01000001)).is_ok());
    assert!(TpmiDhEntity::<false>::try_from(Handle(0)).is_ok());
    assert_eq!(
        TpmiDhEntity::<false>::try_from(Handle::RH_NULL),
        Err(UnmarshalError::VALUE)
    );
    assert!(TpmiDhEntity::<true>::try_from(Handle::RH_NULL).is_ok());
}

#[test]
fn test_tpmi_sh_and_context_handles() {
    assert!(TpmiShAuthSession::<false>::try_from(Handle(0x02000000)).is_ok());
    assert!(TpmiShAuthSession::<false>::try_from(Handle(0x03000000)).is_ok());
    assert_eq!(
        TpmiShAuthSession::<false>::try_from(Handle::RS_PW),
        Err(UnmarshalError::VALUE)
    );
    assert!(TpmiShAuthSession::<true>::try_from(Handle::RS_PW).is_ok());

    assert!(TpmiShHmac::try_from(Handle(0x02000000)).is_ok());
    assert_eq!(
        TpmiShHmac::try_from(Handle(0x03000000)),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiShPolicy::try_from(Handle(0x03000000)).is_ok());
    assert_eq!(
        TpmiShPolicy::try_from(Handle(0x02000000)),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiDhContext::try_from(Handle(0x02000000)).is_ok());
    assert!(TpmiDhContext::try_from(Handle(0x03000000)).is_ok());
    assert!(TpmiDhContext::try_from(Handle(0x80000005)).is_ok());
    assert_eq!(
        TpmiDhContext::try_from(Handle(0x81000000)),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiDhSaved::try_from(Handle(0x80000002)).is_ok());
    assert_eq!(
        TpmiDhSaved::try_from(Handle(0x80000003)),
        Err(UnmarshalError::VALUE)
    );
}

#[test]
fn test_tpmi_rh_handles() {
    assert!(TpmiRhEnables::<false>::try_from(Handle::RH_OWNER).is_ok());
    assert!(TpmiRhEnables::<false>::try_from(Handle::RH_PLATFORM_NV).is_ok());
    assert_eq!(
        TpmiRhEnables::<false>::try_from(Handle::RH_LOCKOUT),
        Err(UnmarshalError::VALUE)
    );
    assert!(TpmiRhEnables::<true>::try_from(Handle::RH_NULL).is_ok());

    assert!(TpmiRhHierarchyAuth::<false>::try_from(Handle::RH_LOCKOUT).is_ok());
    assert_eq!(
        TpmiRhHierarchyAuth::<false>::try_from(Handle::RH_PLATFORM_NV),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiRhHierarchyPolicy::try_from(Handle::RH_OWNER).is_ok());
    assert!(TpmiRhHierarchyPolicy::try_from(Handle::RH_PLATFORM).is_ok());
    assert!(TpmiRhHierarchyPolicy::try_from(Handle::RH_ENDORSEMENT).is_ok());
    assert!(TpmiRhHierarchyPolicy::try_from(Handle::RH_LOCKOUT).is_ok());
    assert!(TpmiRhHierarchyPolicy::try_from(Handle(0x40000110)).is_ok());
    assert!(TpmiRhHierarchyPolicy::try_from(Handle(0x4000011F)).is_ok());
    assert_eq!(
        TpmiRhHierarchyPolicy::try_from(Handle::RH_NULL),
        Err(UnmarshalError::VALUE)
    );
    assert_eq!(
        TpmiRhHierarchyPolicy::try_from(Handle(0x40000120)),
        Err(UnmarshalError::VALUE)
    );
    assert!(TpmiRhBaseHierarchy::try_from(Handle::RH_ENDORSEMENT).is_ok());
    assert_eq!(
        TpmiRhBaseHierarchy::try_from(Handle::RH_LOCKOUT),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiRhPlatform::try_from(Handle::RH_PLATFORM).is_ok());
    assert_eq!(
        TpmiRhPlatform::try_from(Handle::RH_OWNER),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiRhOwner::<false>::try_from(Handle::RH_OWNER).is_ok());
    assert!(TpmiRhOwner::<true>::try_from(Handle::RH_NULL).is_ok());
    assert!(TpmiRhEndorsement::<false>::try_from(Handle::RH_ENDORSEMENT).is_ok());
    assert!(TpmiRhProvision::try_from(Handle::RH_OWNER).is_ok());
    assert!(TpmiRhProvision::try_from(Handle::RH_PLATFORM).is_ok());
    assert_eq!(
        TpmiRhProvision::try_from(Handle::RH_ENDORSEMENT),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiRhClear::try_from(Handle::RH_LOCKOUT).is_ok());
    assert!(TpmiRhClear::try_from(Handle::RH_PLATFORM).is_ok());
    assert_eq!(
        TpmiRhClear::try_from(Handle::RH_OWNER),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiRhNvAuth::try_from(Handle::RH_OWNER).is_ok());
    assert!(TpmiRhNvAuth::try_from(Handle(0x01000001)).is_ok());
    assert_eq!(
        TpmiRhNvAuth::try_from(Handle::RH_ENDORSEMENT),
        Err(UnmarshalError::VALUE)
    );

    assert!(TpmiRhLockout::try_from(Handle::RH_LOCKOUT).is_ok());
    assert!(TpmiRhNvIndex::try_from(Handle(0x01000001)).is_ok());
    assert!(TpmiRhNvDefinedIndex::try_from(Handle(0x11000001)).is_ok());
    assert!(TpmiRhNvLegacyIndex::try_from(Handle(0x01000001)).is_ok());
    assert!(TpmiRhNvExpIndex::try_from(Handle(0x11000001)).is_ok());
    assert!(TpmiRhAc::try_from(Handle(0x90000001)).is_ok());
    assert!(TpmiRhAct::try_from(Handle(0x40000115)).is_ok());
}

#[test]
fn test_tpmi_alg_sig_scheme() {
    let valid_schemes = [
        #[cfg(feature = "rsassa")]
        (Alg::RSASSA, TpmiAlgSigScheme::Rsassa),
        #[cfg(feature = "rsapss")]
        (Alg::RSAPSS, TpmiAlgSigScheme::Rsapss),
        #[cfg(feature = "ecdsa")]
        (Alg::ECDSA, TpmiAlgSigScheme::Ecdsa),
        #[cfg(feature = "ecdaa")]
        (Alg::ECDAA, TpmiAlgSigScheme::Ecdaa),
        #[cfg(feature = "sm2")]
        (Alg::SM2, TpmiAlgSigScheme::Sm2),
        #[cfg(feature = "ecschnorr")]
        (Alg::ECSCHNORR, TpmiAlgSigScheme::Ecschnorr),
        (Alg::EDDSA, TpmiAlgSigScheme::Eddsa),
        (Alg::HASH_EDDSA, TpmiAlgSigScheme::HashEddsa),
        (Alg::HMAC, TpmiAlgSigScheme::Hmac),
    ];

    for (alg, expected) in valid_schemes {
        assert_eq!(TpmiAlgSigScheme::try_from(alg), Ok(expected));
        assert_eq!(TpmiAlgSigScheme::try_from(alg.id()), Ok(expected));
        assert_eq!(Alg::from(expected), alg);
        assert_eq!(u16::from(expected), alg.id());
        assert_eq!(
            Option::<TpmiAlgSigScheme>::try_from(alg),
            Ok(Some(expected))
        );
        assert_eq!(Alg::from(Some(expected)), alg);

        let mut dst = [0u8; TpmiAlgSigScheme::MAX_SIZE];
        let len = expected.marshal(&mut dst);
        assert_eq!(len, 2);
        let mut src = &dst[..len];
        assert_eq!(TpmiAlgSigScheme::unmarshal(&mut src), Ok(expected));
        assert!(src.is_empty());

        let mut opt_dst = [0u8; Option::<TpmiAlgSigScheme>::MAX_SIZE];
        let opt_len = Some(expected).marshal(&mut opt_dst);
        assert_eq!(opt_len, 2);
        let mut opt_src = &opt_dst[..opt_len];
        assert_eq!(
            Option::<TpmiAlgSigScheme>::unmarshal(&mut opt_src),
            Ok(Some(expected))
        );
        assert!(opt_src.is_empty());
    }

    #[cfg(not(feature = "rsassa"))]
    assert_eq!(
        TpmiAlgSigScheme::try_from(Alg::RSASSA),
        Err(UnmarshalError::SCHEME)
    );
    #[cfg(not(feature = "rsapss"))]
    assert_eq!(
        TpmiAlgSigScheme::try_from(Alg::RSAPSS),
        Err(UnmarshalError::SCHEME)
    );
    #[cfg(not(feature = "ecdsa"))]
    assert_eq!(
        TpmiAlgSigScheme::try_from(Alg::ECDSA),
        Err(UnmarshalError::SCHEME)
    );
    #[cfg(not(feature = "ecdaa"))]
    assert_eq!(
        TpmiAlgSigScheme::try_from(Alg::ECDAA),
        Err(UnmarshalError::SCHEME)
    );
    #[cfg(not(feature = "sm2"))]
    assert_eq!(
        TpmiAlgSigScheme::try_from(Alg::SM2),
        Err(UnmarshalError::SCHEME)
    );
    #[cfg(not(feature = "ecschnorr"))]
    assert_eq!(
        TpmiAlgSigScheme::try_from(Alg::ECSCHNORR),
        Err(UnmarshalError::SCHEME)
    );

    // TPM_ALG_NULL is rejected for non-optional TpmiAlgSigScheme, accepted for Option<TpmiAlgSigScheme>
    assert_eq!(
        TpmiAlgSigScheme::try_from(Alg::NULL),
        Err(UnmarshalError::SCHEME)
    );
    assert_eq!(Option::<TpmiAlgSigScheme>::try_from(Alg::NULL), Ok(None));
    assert_eq!(Alg::from(None::<TpmiAlgSigScheme>), Alg::NULL);
    let mut null_dst = [0u8; Option::<TpmiAlgSigScheme>::MAX_SIZE];
    let null_len = None::<TpmiAlgSigScheme>.marshal(&mut null_dst);
    assert_eq!(null_len, 2);
    let mut null_src = &null_dst[..null_len];
    assert_eq!(
        Option::<TpmiAlgSigScheme>::unmarshal(&mut null_src),
        Ok(None)
    );

    // Non-signature schemes return UnmarshalError::SCHEME
    for invalid in [
        Alg::AES,
        Alg::RSA,
        Alg::ECC,
        Alg::OAEP,
        Alg::RSAES,
        Alg::ECDH,
        Alg::ECMQV,
        Alg::SHA256,
    ] {
        assert_eq!(
            TpmiAlgSigScheme::try_from(invalid),
            Err(UnmarshalError::SCHEME)
        );
        assert_eq!(
            Option::<TpmiAlgSigScheme>::try_from(invalid),
            Err(UnmarshalError::SCHEME)
        );
    }
}

#[test]
fn test_tpmi_dh_sh_handle_range_upper_bounds() {
    let transient_last = Handle::TRANSIENT_LAST;
    let transient_over = Handle(Handle::TRANSIENT_LAST.0 + 1);
    let transient_max_mso = Handle(0x80FF_FFFF);

    let hmac_last = Handle::HMAC_SESSION_LAST;
    let hmac_over = Handle(Handle::HMAC_SESSION_LAST.0 + 1);
    let hmac_max_mso = Handle(0x02FF_FFFF);

    let policy_last = Handle::POLICY_SESSION_LAST;
    let policy_over = Handle(Handle::POLICY_SESSION_LAST.0 + 1);
    let policy_max_mso = Handle(0x03FF_FFFF);

    // TPMI_DH_OBJECT
    assert!(TpmiDhObject::<false>::try_from(transient_last).is_ok());
    assert_eq!(
        TpmiDhObject::<false>::try_from(transient_over),
        Err(UnmarshalError::VALUE)
    );
    assert_eq!(
        TpmiDhObject::<false>::try_from(transient_max_mso),
        Err(UnmarshalError::VALUE)
    );

    // TPMI_DH_PARENT
    assert!(TpmiDhParent::try_from(transient_last).is_ok());
    assert_eq!(
        TpmiDhParent::try_from(transient_over),
        Err(UnmarshalError::VALUE)
    );
    assert_eq!(
        TpmiDhParent::try_from(transient_max_mso),
        Err(UnmarshalError::VALUE)
    );

    // TPMI_DH_ENTITY
    assert!(TpmiDhEntity::<false>::try_from(transient_last).is_ok());
    assert!(TpmiDhEntity::<false>::try_from(Handle::PCR_LAST).is_ok());
    for invalid in [
        transient_over,
        transient_max_mso,
        Handle(Handle::PCR_LAST.0 + 1),
        hmac_last,
        policy_last,
    ] {
        assert_eq!(
            TpmiDhEntity::<false>::try_from(invalid),
            Err(UnmarshalError::VALUE)
        );
    }

    // TPMI_SH_AUTH_SESSION
    assert!(TpmiShAuthSession::<false>::try_from(hmac_last).is_ok());
    assert!(TpmiShAuthSession::<false>::try_from(policy_last).is_ok());
    for invalid in [hmac_over, hmac_max_mso, policy_over, policy_max_mso] {
        assert_eq!(
            TpmiShAuthSession::<false>::try_from(invalid),
            Err(UnmarshalError::VALUE)
        );
    }

    // TPMI_SH_HMAC
    assert!(TpmiShHmac::try_from(hmac_last).is_ok());
    assert_eq!(TpmiShHmac::try_from(hmac_over), Err(UnmarshalError::VALUE));
    assert_eq!(
        TpmiShHmac::try_from(hmac_max_mso),
        Err(UnmarshalError::VALUE)
    );

    // TPMI_SH_POLICY
    assert!(TpmiShPolicy::try_from(policy_last).is_ok());
    assert_eq!(
        TpmiShPolicy::try_from(policy_over),
        Err(UnmarshalError::VALUE)
    );
    assert_eq!(
        TpmiShPolicy::try_from(policy_max_mso),
        Err(UnmarshalError::VALUE)
    );

    // TPMI_DH_CONTEXT
    assert!(TpmiDhContext::try_from(transient_last).is_ok());
    assert!(TpmiDhContext::try_from(hmac_last).is_ok());
    assert!(TpmiDhContext::try_from(policy_last).is_ok());
    for invalid in [
        transient_over,
        transient_max_mso,
        hmac_over,
        hmac_max_mso,
        policy_over,
        policy_max_mso,
    ] {
        assert_eq!(TpmiDhContext::try_from(invalid), Err(UnmarshalError::VALUE));
    }

    // TPMI_DH_SAVED
    assert!(TpmiDhSaved::try_from(Handle(0x8000_0002)).is_ok());
    assert!(TpmiDhSaved::try_from(hmac_last).is_ok());
    assert!(TpmiDhSaved::try_from(policy_last).is_ok());
    for invalid in [
        Handle(0x8000_0003),
        transient_over,
        transient_max_mso,
        hmac_over,
        hmac_max_mso,
        policy_over,
        policy_max_mso,
    ] {
        assert_eq!(TpmiDhSaved::try_from(invalid), Err(UnmarshalError::VALUE));
    }
}

#[test]
fn test_default_hash_and_ha_and_structure_defaults() {
    let expected_hash = TpmiAlgHash::DEFAULT_HASH;
    assert_eq!(TpmiAlgHash::default(), expected_hash);

    let default_ha = TpmtHa::DEFAULT_HA;
    assert_eq!(TpmtHa::default(), default_ha);
    assert_eq!(default_ha.hash_alg(), expected_hash);
    assert_eq!(default_ha.digest().len(), expected_hash.digest_size());
    assert!(default_ha.digest().iter().all(|&b| b == 0));

    assert_eq!(TpmsPcrSelection::default().hash(), expected_hash);
    assert_eq!(TpmsNvPublic::default().name_alg, expected_hash);
    assert_eq!(TpmsNvPublicExpAttr::default().name_alg, expected_hash);
    assert_eq!(
        <TpmsPcrSelection as TpmlElement>::DEFAULT.hash(),
        expected_hash
    );
    assert_eq!(<TpmtHa<'_> as TpmlElement>::DEFAULT, default_ha);
}
