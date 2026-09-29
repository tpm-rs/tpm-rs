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

use tpm2::commands::{PolicySigned, Sign, VerifySignature};
use tpm2::errors::UnmarshalError;
use tpm2::*;

#[test]
fn test_tpmt_unmarshal_reserved_alg_ids_return_specific_errors() {
    for reserved_id in [0x0000u16, 0x00C1, 0x00C4, 0x00C6, 0x8000, 0x8021, 0xFFFF] {
        let bytes = reserved_id.to_be_bytes();

        let mut s1 = &bytes[..];
        assert_eq!(
            Option::<TpmtKeyedHashScheme>::unmarshal(&mut s1),
            Err(UnmarshalError::VALUE)
        );

        let mut s1b = &bytes[..];
        assert_eq!(
            TpmtKeyedHashScheme::unmarshal(&mut s1b),
            Err(UnmarshalError::VALUE)
        );

        let mut s2 = &bytes[..];
        assert_eq!(
            TpmtSymDefObject::unmarshal(&mut s2),
            Err(UnmarshalError::SYMMETRIC)
        );

        let mut s3 = &bytes[..];
        assert_eq!(
            Option::<TpmtSymDefObject>::unmarshal(&mut s3),
            Err(UnmarshalError::SYMMETRIC)
        );

        let mut s4 = &bytes[..];
        assert_eq!(
            Option::<TpmtSymDef>::unmarshal(&mut s4),
            Err(UnmarshalError::SYMMETRIC)
        );

        let mut s5 = &bytes[..];
        assert_eq!(
            TpmtSignature::unmarshal(&mut s5),
            Err(UnmarshalError::SCHEME)
        );

        let mut s6 = &bytes[..];
        assert_eq!(
            Option::<TpmtSignature>::unmarshal(&mut s6),
            Err(UnmarshalError::SCHEME)
        );

        let mut s7 = &bytes[..];
        assert_eq!(
            Option::<TpmtSigScheme>::unmarshal(&mut s7),
            Err(UnmarshalError::SCHEME)
        );

        let mut s8 = &bytes[..];
        assert_eq!(
            Option::<TpmtRsaScheme>::unmarshal(&mut s8),
            Err(UnmarshalError::VALUE)
        );

        let mut s8b = &bytes[..];
        assert_eq!(
            TpmtRsaScheme::unmarshal(&mut s8b),
            Err(UnmarshalError::VALUE)
        );

        let mut s9 = &bytes[..];
        assert_eq!(
            Option::<TpmtEccScheme>::unmarshal(&mut s9),
            Err(UnmarshalError::SCHEME)
        );

        let mut s10 = &bytes[..];
        assert_eq!(
            TpmtPublicParms::unmarshal(&mut s10),
            Err(UnmarshalError::TYPE)
        );

        let mut s11 = &bytes[..];
        assert_eq!(TpmtPublic::unmarshal(&mut s11), Err(UnmarshalError::TYPE));

        let mut s12 = &bytes[..];
        assert_eq!(
            TpmtSensitive::unmarshal(&mut s12),
            Err(UnmarshalError::TYPE)
        );

        let mut s13 = &bytes[..];
        assert_eq!(
            TpmtRsaDecrypt::unmarshal(&mut s13),
            Err(UnmarshalError::VALUE)
        );

        let mut s14 = &bytes[..];
        assert_eq!(
            Option::<TpmtRsaDecrypt>::unmarshal(&mut s14),
            Err(UnmarshalError::VALUE)
        );
    }
}

#[test]
fn test_keyedhash_and_rsa_scheme_unmarshal_error_codes_and_feature_gates() {
    // 1. Option<TpmtKeyedHashScheme> and TpmtKeyedHashScheme return VALUE on invalid selectors
    for invalid_alg in [
        Alg::RSA,
        Alg::SHA256,
        Alg::AES,
        Alg::RSASSA,
        Alg::ECDSA,
        Alg::OAEP,
    ] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&invalid_alg.id().to_be_bytes());
        buf[2..4].copy_from_slice(&Alg::SHA256.id().to_be_bytes());
        let mut src = &buf[..];
        assert_eq!(
            Option::<TpmtKeyedHashScheme>::unmarshal(&mut src),
            Err(UnmarshalError::VALUE),
            "Option<TpmtKeyedHashScheme> must return VALUE for {:?}",
            invalid_alg
        );
        let mut src = &buf[..];
        assert_eq!(
            TpmtKeyedHashScheme::unmarshal(&mut src),
            Err(UnmarshalError::VALUE),
            "TpmtKeyedHashScheme must return VALUE for {:?}",
            invalid_alg
        );
    }
    // Non-optional TpmtKeyedHashScheme rejects Alg::NULL with VALUE
    let mut null_src = &Alg::NULL.id().to_be_bytes()[..];
    assert_eq!(
        TpmtKeyedHashScheme::unmarshal(&mut null_src),
        Err(UnmarshalError::VALUE)
    );

    // 2. Option<TpmtRsaScheme> and TpmtRsaScheme return VALUE on invalid selectors
    for invalid_alg in [
        Alg::RSA,
        Alg::SHA256,
        Alg::AES,
        Alg::HMAC,
        Alg::ECDSA,
        Alg::ECDH,
    ] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&invalid_alg.id().to_be_bytes());
        buf[2..4].copy_from_slice(&Alg::SHA256.id().to_be_bytes());
        let mut src = &buf[..];
        assert_eq!(
            Option::<TpmtRsaScheme>::unmarshal(&mut src),
            Err(UnmarshalError::VALUE),
            "Option<TpmtRsaScheme> must return VALUE for {:?}",
            invalid_alg
        );
        let mut src = &buf[..];
        assert_eq!(
            TpmtRsaScheme::unmarshal(&mut src),
            Err(UnmarshalError::VALUE),
            "TpmtRsaScheme must return VALUE for {:?}",
            invalid_alg
        );
    }
    // Non-optional TpmtRsaScheme rejects Alg::NULL with VALUE
    let mut null_src = &Alg::NULL.id().to_be_bytes()[..];
    assert_eq!(
        TpmtRsaScheme::unmarshal(&mut null_src),
        Err(UnmarshalError::VALUE)
    );

    // 3. Disabled scheme features (e.g. sm2, ecschnorr, ecmqv when not enabled) are rejected
    #[cfg(not(feature = "sm2"))]
    {
        let buf = [0x00u8, 0x1B, 0x00, 0x0B]; // SM2 + SHA256
        let mut s1 = &buf[..];
        assert_eq!(
            Option::<TpmtSigScheme>::unmarshal(&mut s1),
            Err(UnmarshalError::SCHEME)
        );
        let mut s2 = &buf[..];
        assert_eq!(
            Option::<TpmtEccScheme>::unmarshal(&mut s2),
            Err(UnmarshalError::SCHEME)
        );
        let mut s3 = &[0x00u8, 0x1B][..];
        assert_eq!(
            TpmiEccKeyExchange::unmarshal(&mut s3),
            Err(UnmarshalError::SCHEME)
        );
    }
    #[cfg(not(feature = "ecschnorr"))]
    {
        let buf = [0x00u8, 0x1C, 0x00, 0x0B]; // ECSCHNORR + SHA256
        let mut s1 = &buf[..];
        assert_eq!(
            Option::<TpmtSigScheme>::unmarshal(&mut s1),
            Err(UnmarshalError::SCHEME)
        );
        let mut s2 = &buf[..];
        assert_eq!(
            Option::<TpmtEccScheme>::unmarshal(&mut s2),
            Err(UnmarshalError::SCHEME)
        );
    }
    #[cfg(not(feature = "ecmqv"))]
    {
        let buf = [0x00u8, 0x1D, 0x00, 0x0B]; // ECMQV + SHA256
        let mut s1 = &buf[..];
        assert_eq!(
            Option::<TpmtEccScheme>::unmarshal(&mut s1),
            Err(UnmarshalError::SCHEME)
        );
        let mut s2 = &[0x00u8, 0x1D][..];
        assert_eq!(
            TpmiEccKeyExchange::unmarshal(&mut s2),
            Err(UnmarshalError::SCHEME)
        );
    }
}

#[test]
fn test_tpmt_rsa_decrypt_marshal_unmarshal() {
    // Valid: Alg::NULL -> None
    let mut dst = [0u8; Option::<TpmtRsaDecrypt>::MAX_SIZE];
    let len = Option::<TpmtRsaDecrypt>::None.marshal(&mut dst);
    assert_eq!(&dst[..len], &Alg::NULL.id().to_be_bytes());
    let mut src = &dst[..len];
    assert_eq!(Option::<TpmtRsaDecrypt>::unmarshal(&mut src), Ok(None));
    assert!(src.is_empty());

    // Non-optional TpmtRsaDecrypt rejects Alg::NULL with VALUE
    let mut src_null = &Alg::NULL.id().to_be_bytes()[..];
    assert_eq!(
        TpmtRsaDecrypt::unmarshal(&mut src_null),
        Err(UnmarshalError::VALUE)
    );

    let mut dst_non_opt = [0u8; TpmtRsaDecrypt::MAX_SIZE];

    #[cfg(feature = "rsaes")]
    {
        // Valid: Alg::RSAES
        let rsaes = Some(TpmtRsaDecrypt::Rsaes);
        let len = rsaes.marshal(&mut dst);
        assert_eq!(&dst[..len], &Alg::RSAES.id().to_be_bytes());
        let mut src = &dst[..len];
        assert_eq!(Option::<TpmtRsaDecrypt>::unmarshal(&mut src), Ok(rsaes));
        assert!(src.is_empty());

        // Non-optional TpmtRsaDecrypt::Rsaes roundtrip + methods
        assert_eq!(TpmtRsaDecrypt::Rsaes.scheme(), Alg::RSAES);
        assert_eq!(TpmtRsaDecrypt::Rsaes.hash_alg(), None);
        let len = TpmtRsaDecrypt::Rsaes.marshal(&mut dst_non_opt);
        let mut src = &dst_non_opt[..len];
        assert_eq!(
            TpmtRsaDecrypt::unmarshal(&mut src),
            Ok(TpmtRsaDecrypt::Rsaes)
        );
        assert!(src.is_empty());
    }

    #[cfg(feature = "oaep")]
    {
        // Valid: Alg::OAEP with SHA256
        let oaep_val = TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256);
        assert_eq!(oaep_val.scheme(), Alg::OAEP);
        assert_eq!(oaep_val.hash_alg(), Some(TpmiAlgHash::Sha256));
        let len = oaep_val.marshal(&mut dst_non_opt);
        assert_eq!(len, 4);
        let mut src = &dst_non_opt[..len];
        assert_eq!(TpmtRsaDecrypt::unmarshal(&mut src), Ok(oaep_val));
        assert!(src.is_empty());

        let oaep = Some(oaep_val);
        let len = oaep.marshal(&mut dst);
        assert_eq!(len, 4);
        let mut src = &dst[..len];
        assert_eq!(Option::<TpmtRsaDecrypt>::unmarshal(&mut src), Ok(oaep));
        assert!(src.is_empty());
    }

    // Reject signature schemes (RSASSA, RSAPSS) and other non-decrypt schemes with UnmarshalError::VALUE
    for invalid_alg in [
        Alg::RSASSA,
        Alg::RSAPSS,
        Alg::ECDSA,
        Alg::ECDAA,
        Alg::AES,
        Alg::HMAC,
    ] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&invalid_alg.id().to_be_bytes());
        buf[2..4].copy_from_slice(&Alg::SHA256.id().to_be_bytes());
        let mut src = &buf[..];
        assert_eq!(
            Option::<TpmtRsaDecrypt>::unmarshal(&mut src),
            Err(UnmarshalError::VALUE),
            "Expected UnmarshalError::VALUE for invalid scheme {:?}",
            invalid_alg
        );
        let mut src = &buf[..];
        assert_eq!(
            TpmtRsaDecrypt::unmarshal(&mut src),
            Err(UnmarshalError::VALUE)
        );
    }

    #[cfg(feature = "oaep")]
    {
        // OAEP with invalid hash alg (e.g. Alg::NULL) returns UnmarshalError::HASH
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&Alg::OAEP.id().to_be_bytes());
        buf[2..4].copy_from_slice(&Alg::NULL.id().to_be_bytes());
        let mut src = &buf[..];
        assert_eq!(
            Option::<TpmtRsaDecrypt>::unmarshal(&mut src),
            Err(UnmarshalError::HASH)
        );
        let mut src = &buf[..];
        assert_eq!(
            TpmtRsaDecrypt::unmarshal(&mut src),
            Err(UnmarshalError::HASH)
        );
    }
}

#[test]
fn test_eddsa_schemes_and_signatures() {
    // 1. TpmtSigScheme::Eddsa and TpmtSigScheme::HashEddsa
    for (scheme, expected_alg, expected_tpmi, expected_wire) in [
        (
            TpmtSigScheme::Eddsa,
            Alg::EDDSA,
            TpmiAlgSigScheme::Eddsa,
            [0x00u8, 0x60],
        ),
        (
            TpmtSigScheme::HashEddsa,
            Alg::HASH_EDDSA,
            TpmiAlgSigScheme::HashEddsa,
            [0x00u8, 0x61],
        ),
    ] {
        assert_eq!(scheme.algorithm(), expected_alg);
        assert_eq!(scheme.scheme(), expected_tpmi);
        assert_eq!(scheme.hash_alg(), None);

        let mut dst = [0u8; TpmtSigScheme::MAX_SIZE];
        let len = scheme.marshal(&mut dst);
        assert_eq!(len, 2);
        assert_eq!(&dst[..2], &expected_wire);

        let mut src = &dst[..len];
        assert_eq!(TpmtSigScheme::unmarshal(&mut src), Ok(scheme));
        assert!(src.is_empty());

        let mut opt_dst = [0u8; Option::<TpmtSigScheme>::MAX_SIZE];
        let opt_len = Some(scheme).marshal(&mut opt_dst);
        assert_eq!(opt_len, 2);
        assert_eq!(&opt_dst[..2], &expected_wire);

        let mut opt_src = &opt_dst[..opt_len];
        assert_eq!(
            Option::<TpmtSigScheme>::unmarshal(&mut opt_src),
            Ok(Some(scheme))
        );
        assert!(opt_src.is_empty());
    }

    // 2. TpmtEccScheme::Eddsa and TpmtEccScheme::HashEddsa
    for (ecc_scheme, expected_sig_scheme, expected_alg, expected_wire) in [
        (
            TpmtEccScheme::Eddsa,
            TpmtSigScheme::Eddsa,
            Alg::EDDSA,
            [0x00u8, 0x60],
        ),
        (
            TpmtEccScheme::HashEddsa,
            TpmtSigScheme::HashEddsa,
            Alg::HASH_EDDSA,
            [0x00u8, 0x61],
        ),
    ] {
        assert_eq!(ecc_scheme.scheme(), expected_alg);
        assert_eq!(ecc_scheme.hash_alg(), None);
        assert_eq!(TpmtSigScheme::try_from(ecc_scheme), Ok(expected_sig_scheme));

        let mut dst = [0u8; TpmtEccScheme::MAX_SIZE];
        let len = ecc_scheme.marshal(&mut dst);
        assert_eq!(len, 2);
        assert_eq!(&dst[..2], &expected_wire);

        let mut src = &dst[..len];
        assert_eq!(TpmtEccScheme::unmarshal(&mut src), Ok(ecc_scheme));
        assert!(src.is_empty());

        let mut opt_dst = [0u8; Option::<TpmtEccScheme>::MAX_SIZE];
        let opt_len = Some(ecc_scheme).marshal(&mut opt_dst);
        assert_eq!(opt_len, 2);
        assert_eq!(&opt_dst[..2], &expected_wire);

        let mut opt_src = &opt_dst[..opt_len];
        assert_eq!(
            Option::<TpmtEccScheme>::unmarshal(&mut opt_src),
            Ok(Some(ecc_scheme))
        );
        assert!(opt_src.is_empty());
    }

    // 3. TpmtSignature::Eddsa and TpmtSignature::HashEddsa
    let sig_bytes = [0xABu8; 64];
    let eddsa_buf = Tpm2bSignatureEddsa::from_bytes(&sig_bytes).unwrap();
    for (sig, expected_alg, expected_tag) in [
        (TpmtSignature::Eddsa(eddsa_buf), Alg::EDDSA, [0x00u8, 0x60]),
        (
            TpmtSignature::HashEddsa(eddsa_buf),
            Alg::HASH_EDDSA,
            [0x00u8, 0x61],
        ),
    ] {
        assert_eq!(sig.sig_alg(), expected_alg);
        let mut dst = [0u8; TpmtSignature::MAX_SIZE];
        let len = sig.marshal(&mut dst);
        assert_eq!(len, 2 + 2 + 64);
        assert_eq!(&dst[0..2], &expected_tag);
        assert_eq!(&dst[2..4], &64u16.to_be_bytes());
        assert_eq!(&dst[4..68], &sig_bytes);

        let mut src = &dst[..len];
        assert_eq!(TpmtSignature::unmarshal(&mut src), Ok(sig));
        assert!(src.is_empty());

        let mut opt_dst = [0u8; Option::<TpmtSignature>::MAX_SIZE];
        let opt_len = Some(sig).marshal(&mut opt_dst);
        assert_eq!(opt_len, len);
        let mut opt_src = &opt_dst[..opt_len];
        assert_eq!(
            Option::<TpmtSignature>::unmarshal(&mut opt_src),
            Ok(Some(sig))
        );
        assert!(opt_src.is_empty());
    }

    // 4. Command wire roundtrips: Sign, VerifySignature, PolicySigned
    let digest =
        Tpm2bDigest::from_bytes(&[0x11u8; 32][..TpmiAlgHash::MAX_DIGEST_BYTES.min(32)]).unwrap();
    let validation = TpmtTkHashcheck::new(Handle::RH_NULL, Tpm2bDigest::default());
    for scheme in [TpmtSigScheme::Eddsa, TpmtSigScheme::HashEddsa] {
        let sign_cmd = Sign {
            digest,
            in_scheme: Some(scheme),
            validation,
        };
        let mut dst = [0u8; Sign::MAX_SIZE];
        let len = sign_cmd.marshal(&mut dst);
        let mut src = &dst[..len];
        assert_eq!(Sign::unmarshal(&mut src), Ok(sign_cmd));
        assert!(src.is_empty());
    }

    for sig in [
        TpmtSignature::Eddsa(eddsa_buf),
        TpmtSignature::HashEddsa(eddsa_buf),
    ] {
        let verify_cmd = VerifySignature {
            digest,
            signature: sig,
        };
        let mut dst = [0u8; VerifySignature::MAX_SIZE];
        let len = verify_cmd.marshal(&mut dst);
        let mut src = &dst[..len];
        assert_eq!(VerifySignature::unmarshal(&mut src), Ok(verify_cmd));
        assert!(src.is_empty());

        let policy_signed_cmd = PolicySigned {
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
            auth: sig,
        };
        let mut dst = [0u8; PolicySigned::MAX_SIZE];
        let len = policy_signed_cmd.marshal(&mut dst);
        let mut src = &dst[..len];
        assert_eq!(PolicySigned::unmarshal(&mut src), Ok(policy_signed_cmd));
        assert!(src.is_empty());
    }
}

#[test]
fn test_pqc_tpmi_mldsa_mlkem_parms_and_alg_public() {
    // 1. TpmiMlkemParms
    let mlkem_cases = [
        (0x0001u16, TpmiMlkemParms::Mlkem512, 800usize, 768usize),
        (0x0002u16, TpmiMlkemParms::Mlkem768, 1184usize, 1088usize),
        (0x0003u16, TpmiMlkemParms::Mlkem1024, 1568usize, 1568usize),
    ];
    for (raw, expected, pub_bytes, ct_bytes) in mlkem_cases {
        let mut dst = [0u8; TpmiMlkemParms::MAX_SIZE];
        assert_eq!(expected.marshal(&mut dst), 2);
        assert_eq!(dst, raw.to_be_bytes());
        let mut src = &dst[..];
        assert_eq!(TpmiMlkemParms::unmarshal(&mut src), Ok(expected));
        assert!(src.is_empty());
        assert_eq!(expected.public_key_bytes(), pub_bytes);
        assert_eq!(expected.private_key_bytes(), 64);
        assert_eq!(expected.ciphertext_bytes(), ct_bytes);
        assert_eq!(expected.shared_secret_bytes(), 32);
    }
    for invalid in [0x0000u16, 0x0004, 0x0010, 0xFFFF] {
        let bytes = invalid.to_be_bytes();
        let mut src = &bytes[..];
        assert_eq!(
            TpmiMlkemParms::unmarshal(&mut src),
            Err(UnmarshalError::PARMS)
        );
    }

    // 2. TpmiMldsaParms
    let mldsa_cases = [
        (0x0001u16, TpmiMldsaParms::Mldsa44, 1312usize, 2420usize),
        (0x0002u16, TpmiMldsaParms::Mldsa65, 1952usize, 3309usize),
        (0x0003u16, TpmiMldsaParms::Mldsa87, 2592usize, 4627usize),
    ];
    for (raw, expected, pub_bytes, sig_bytes) in mldsa_cases {
        let mut dst = [0u8; TpmiMldsaParms::MAX_SIZE];
        assert_eq!(expected.marshal(&mut dst), 2);
        assert_eq!(dst, raw.to_be_bytes());
        let mut src = &dst[..];
        assert_eq!(TpmiMldsaParms::unmarshal(&mut src), Ok(expected));
        assert!(src.is_empty());
        assert_eq!(expected.public_key_bytes(), pub_bytes);
        assert_eq!(expected.private_key_bytes(), 32);
        assert_eq!(expected.signature_bytes(), sig_bytes);
    }
    for invalid in [0x0000u16, 0x0004, 0x0010, 0xFFFF] {
        let bytes = invalid.to_be_bytes();
        let mut src = &bytes[..];
        assert_eq!(
            TpmiMldsaParms::unmarshal(&mut src),
            Err(UnmarshalError::PARMS)
        );
    }

    // 3. TpmiAlgPublic
    let alg_cases = [
        #[cfg(feature = "rsa")]
        (Alg::RSA, TpmiAlgPublic::Rsa),
        (Alg::KEYEDHASH, TpmiAlgPublic::KeyedHash),
        #[cfg(feature = "ecc")]
        (Alg::ECC, TpmiAlgPublic::Ecc),
        (Alg::SYMCIPHER, TpmiAlgPublic::SymCipher),
        (Alg::MLKEM, TpmiAlgPublic::Mlkem),
        (Alg::MLDSA, TpmiAlgPublic::Mldsa),
        (Alg::HASH_MLDSA, TpmiAlgPublic::HashMldsa),
    ];
    for (alg, expected) in alg_cases {
        let mut dst = [0u8; TpmiAlgPublic::MAX_SIZE];
        assert_eq!(expected.marshal(&mut dst), 2);
        assert_eq!(dst, alg.id().to_be_bytes());
        let mut src = &dst[..];
        assert_eq!(TpmiAlgPublic::unmarshal(&mut src), Ok(expected));
        assert_eq!(Alg::from(expected), alg);
    }
    for invalid_alg in [Alg::NULL, Alg::SHA256, Alg::AES, Alg::HMAC] {
        let bytes = invalid_alg.id().to_be_bytes();
        let mut src = &bytes[..];
        assert_eq!(
            TpmiAlgPublic::unmarshal(&mut src),
            Err(UnmarshalError::TYPE)
        );
    }
}

#[test]
fn test_pqc_tpm2b_and_tpms_structures() {
    assert_eq!(Tpm2bPublicKeyMlkem::CAP, 1568);
    assert_eq!(Tpm2bPrivateKeyMlkem::CAP, 64);
    assert_eq!(Tpm2bPublicKeyMldsa::CAP, 2592);
    assert_eq!(Tpm2bPrivateKeyMldsa::CAP, 32);
    assert_eq!(Tpm2bSignatureMldsa::CAP, 4627);

    // TpmsMldsaParms roundtrip & validation
    let mldsa_parms = TpmsMldsaParms {
        parameter_set: TpmiMldsaParms::Mldsa87,
        allow_external_mu: true,
    };
    let mut buf = [0u8; TpmsMldsaParms::MAX_SIZE];
    let len = mldsa_parms.marshal(&mut buf);
    assert_eq!(len, 3);
    assert_eq!(&buf[..len], &[0x00, 0x03, 0x01]);
    let mut src = &buf[..len];
    assert_eq!(TpmsMldsaParms::unmarshal(&mut src), Ok(mldsa_parms));
    assert!(src.is_empty());

    // Invalid boolean in TpmsMldsaParms -> UnmarshalError::VALUE
    let bad_bool = [0x00u8, 0x01, 0x02];
    let mut src = &bad_bool[..];
    assert_eq!(
        TpmsMldsaParms::unmarshal(&mut src),
        Err(UnmarshalError::VALUE)
    );

    // TpmsHashMldsaParms roundtrip & validation
    let hash_mldsa_parms = TpmsHashMldsaParms {
        parameter_set: TpmiMldsaParms::Mldsa65,
        hash_alg: TpmiAlgHash::DEFAULT_HASH,
    };
    let mut buf = [0u8; TpmsHashMldsaParms::MAX_SIZE];
    let len = hash_mldsa_parms.marshal(&mut buf);
    assert_eq!(len, 4);
    let mut src = &buf[..len];
    assert_eq!(
        TpmsHashMldsaParms::unmarshal(&mut src),
        Ok(hash_mldsa_parms)
    );
    assert!(src.is_empty());

    // TpmsMlkemParms roundtrip (with NULL symmetric and AES-128 CFB symmetric)
    for sym in [
        None,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
    ] {
        let mlkem_parms = TpmsMlkemParms {
            symmetric: sym,
            parameter_set: TpmiMlkemParms::Mlkem768,
        };
        let mut buf = [0u8; TpmsMlkemParms::MAX_SIZE];
        let len = mlkem_parms.marshal(&mut buf);
        let mut src = &buf[..len];
        assert_eq!(TpmsMlkemParms::unmarshal(&mut src), Ok(mlkem_parms));
        assert!(src.is_empty());
    }
}

#[test]
fn test_pqc_tpmt_public_parms_public_and_sensitive_roundtrip() {
    let mldsa_key_bytes = [0x42u8; 1312];
    let mldsa_pub_key = Tpm2bPublicKeyMldsa::from_bytes(&mldsa_key_bytes).unwrap();
    let mlkem_key_bytes = [0x55u8; 800];
    let mlkem_pub_key = Tpm2bPublicKeyMlkem::from_bytes(&mlkem_key_bytes).unwrap();

    let public_cases = [
        PublicParmsAndId::Mldsa(
            TpmsMldsaParms {
                parameter_set: TpmiMldsaParms::Mldsa44,
                allow_external_mu: false,
            },
            mldsa_pub_key,
        ),
        PublicParmsAndId::HashMldsa(
            TpmsHashMldsaParms {
                parameter_set: TpmiMldsaParms::Mldsa44,
                hash_alg: TpmiAlgHash::DEFAULT_HASH,
            },
            mldsa_pub_key,
        ),
        PublicParmsAndId::Mlkem(
            TpmsMlkemParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                parameter_set: TpmiMlkemParms::Mlkem512,
            },
            mlkem_pub_key,
        ),
    ];

    for parms_and_id in public_cases {
        // 1. TpmtPublicParms roundtrip
        let parms = parms_and_id.parms();
        let mut p_buf = [0u8; TpmtPublicParms::MAX_SIZE];
        let p_len = parms.marshal(&mut p_buf);
        let mut p_src = &p_buf[..p_len];
        assert_eq!(TpmtPublicParms::unmarshal(&mut p_src), Ok(parms));
        assert!(p_src.is_empty());

        // 2. TpmtPublic roundtrip
        let pub_area = TpmtPublic {
            name_alg: Some(TpmiAlgHash::DEFAULT_HASH),
            object_attributes: TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id,
        };
        let mut pub_buf = [0u8; TpmtPublic::MAX_SIZE];
        let pub_len = pub_area.marshal(&mut pub_buf);
        let mut pub_src = &pub_buf[..pub_len];
        assert_eq!(TpmtPublic::unmarshal(&mut pub_src), Ok(pub_area));
        assert!(pub_src.is_empty());
    }

    // 3. TpmtSensitive roundtrip for MLDSA, HASH_MLDSA, and MLKEM
    let mldsa_seed = Tpm2bPrivateKeyMldsa::from_bytes(&[0xAAu8; 32]).unwrap();
    let mlkem_seed = Tpm2bPrivateKeyMlkem::from_bytes(&[0xBBu8; 64]).unwrap();

    let sensitive_cases = [
        (Alg::MLDSA, TpmuSensitiveComposite::Mldsa(mldsa_seed)),
        (
            Alg::HASH_MLDSA,
            TpmuSensitiveComposite::HashMldsa(mldsa_seed),
        ),
        (Alg::MLKEM, TpmuSensitiveComposite::Mlkem(mlkem_seed)),
    ];

    for (expected_alg, sensitive_comp) in sensitive_cases {
        let sens = TpmtSensitive {
            auth_value: Tpm2bAuth::from_bytes(&[1, 2, 3, 4]).unwrap(),
            seed_value: Tpm2bDigest::from_bytes(
                &[0x77u8; 32][..TpmiAlgHash::MAX_DIGEST_BYTES.min(32)],
            )
            .unwrap(),
            sensitive: sensitive_comp,
        };
        assert_eq!(sens.sensitive_type(), expected_alg);
        let mut s_buf = [0u8; TpmtSensitive::MAX_SIZE];
        let s_len = sens.marshal(&mut s_buf);
        let mut s_src = &s_buf[..s_len];
        let unmarshalled = TpmtSensitive::unmarshal(&mut s_src).unwrap();
        assert!(s_src.is_empty());
        assert_eq!(unmarshalled, sens);
        assert_eq!(unmarshalled.sensitive_type(), expected_alg);
    }
}

#[cfg(feature = "ecc_curve_nist_p256")]
#[test]
fn test_tpmt_public_unmarshal_for_template_derivation_rejects_trailing_bytes_and_preserves_context()
{
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    };
    let derive = TpmsDerive {
        label: Tpm2bLabel::from_bytes(b"orig_label").unwrap(),
        context: Tpm2bLabel::from_bytes(b"orig_context").unwrap(),
    };

    let mut valid_buf = [0u8; TpmtPublic::MAX_SIZE];
    let valid_tmpl =
        Tpm2bTemplate::from_derive_template_in(&pub_area, &derive, &mut valid_buf).unwrap();
    let valid_bytes = valid_tmpl.as_slice();

    // 1. Exact derivation template succeeds and preserves both label and context.
    let (decoded_pub, decoded_derive) = valid_tmpl.unmarshal_to_public(true).unwrap();
    assert_eq!(decoded_pub, pub_area);
    assert_eq!(decoded_derive, Some(derive));

    // 2. Trailing bytes of any form after TPMS_DERIVE must not be consumed by
    //    TpmtPublic::unmarshal_for_template, must not overwrite derive.context,
    //    and must be rejected by Tpm2bTemplate::unmarshal_to_public(true) with UnmarshalError::SIZE.
    let trailing_cases: &[&[u8]] = &[
        &[0x00],                               // 1 trailing byte
        &[0x00, 0x00],                         // empty trailing TPM2B_LABEL
        &[0x00, 0x05], // non-zero u16 size with 0 payload bytes (INSUFFICIENT if unmarshaled)
        &[0x00, 0x25], // u16 size > TPM2_LABEL_MAX_BUFFER (SIZE if unmarshaled)
        &[0xFF, 0xFF], // max u16 trailing garbage
        &[0x00, 0x04, b'e', b'v', b'i', b'l'], // valid non-empty trailing TPM2B_LABEL
    ];

    for trailing in trailing_cases {
        let mut buf = [0u8; TpmtPublic::MAX_SIZE];
        let total_len = valid_bytes.len() + trailing.len();
        buf[..valid_bytes.len()].copy_from_slice(valid_bytes);
        buf[valid_bytes.len()..total_len].copy_from_slice(trailing);

        let mut src = &buf[..total_len];
        let (_, parsed_derive) = TpmtPublic::unmarshal_for_template(&mut src, true).unwrap();
        assert_eq!(
            src, *trailing,
            "unmarshal_for_template must leave all trailing bytes unconsumed for {:?}",
            trailing
        );
        assert_eq!(
            parsed_derive,
            Some(derive),
            "unmarshal_for_template must not overwrite derive.context for {:?}",
            trailing
        );

        let tmpl = Tpm2bTemplate::from_bytes(&buf[..total_len]).unwrap();
        assert_eq!(
            tmpl.unmarshal_to_public(true),
            Err(UnmarshalError::SIZE),
            "unmarshal_to_public(true) must return UnmarshalError::SIZE for trailing {:?}",
            trailing
        );
    }
}
