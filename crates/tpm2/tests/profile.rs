//! The unmarshal profile (`tpm2::profile`): without an installed profile every value of the
//! enabled features unmarshals; once a profile is installed, algorithms, curves, RSA key sizes
//! profile-dependent buffer sizes and `HASH_COUNT` list lengths outside it are rejected with the types' usual errors. The
//! profile is process-global, so this test binary installs it in a single test that checks the
//! behavior before and after.

use tpm2::errors::UnmarshalError;
use tpm2::profile::{self, BufferLimits, InstallError, Profile};
use tpm2::{
    Alg, AlgSym, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPrivateKeyRsa,
    Tpm2bPublicKeyRsa, Tpm2bTemplate, TpmEccCurve, TpmiAlgHash, TpmiAlgPublic, TpmiAlgSigScheme,
    TpmiRsaKeyBits, TpmlPcrSelection, Unmarshal,
};

/// A small profile: SHA-256, RSA, ECC, AES, RSASSA; NIST P-256; RSA-2048.
static PROFILE: Profile = Profile {
    algorithms: &[Alg::SHA256, Alg::RSA, Alg::ECC, Alg::AES, Alg::RSASSA],
    curves: &[TpmEccCurve::NistP256],
    rsa_key_bits: &[2048],
    sym_key_bits: &[128, 256],
    buffer_limits: BufferLimits {
        public_key_rsa: 256,
        private_key_rsa: 640,
        encrypted_secret: 256,
        private: 910,
        template: 350,
        ecc_parameter: 32,
    },
    default_pcr_banks: &[Alg::SHA256],
};

/// An equal profile in another static (installing it again is a no-op).
static SAME_PROFILE: Profile = PROFILE;

/// A different profile.
static OTHER_PROFILE: Profile = Profile {
    rsa_key_bits: &[1024, 2048],
    ..PROFILE
};

/// A `TPM2B` of `len` zero bytes.
fn tpm2b(len: u16) -> Vec<u8> {
    let mut v = len.to_be_bytes().to_vec();
    v.resize(2 + usize::from(len), 0);
    v
}

/// A `TPML_PCR_SELECTION` of `count` SHA-256 selections of PCRs 0-23.
fn pcr_selection(count: u32) -> Vec<u8> {
    let mut v = count.to_be_bytes().to_vec();
    for _ in 0..count {
        v.extend_from_slice(&[0x00, 0x0B, 3, 0xFF, 0xFF, 0xFF]);
    }
    v
}

/// Unmarshals a whole `T` from `bytes`.
fn parse<'a, T: Unmarshal<'a>>(bytes: &'a [u8]) -> Result<T, UnmarshalError> {
    let mut src = bytes;
    T::unmarshal(&mut src)
}

/// Every gated conversion, before and after installing a profile.
#[test]
fn installed_profile_restricts_unmarshaling() {
    // Without a profile: everything the features enable.
    assert!(!profile::is_installed());
    assert_eq!(TpmiAlgHash::try_from(Alg::SHA384), Ok(TpmiAlgHash::Sha384));
    assert!(TpmiAlgHash::try_from(Alg::SM3_256).is_ok());
    assert!(TpmEccCurve::try_from(0x0004).is_ok());
    assert!(TpmiRsaKeyBits::try_from(4096).is_ok());
    assert!(TpmiAlgSigScheme::try_from(Alg::RSAPSS).is_ok());
    assert!(TpmiAlgPublic::try_from(Alg::KEYEDHASH).is_ok());
    assert!(parse::<Tpm2bPublicKeyRsa>(&tpm2b(512)).is_ok());
    assert!(parse::<AlgSym>(&[0x00, 0x06, 0x00, 0xC0]).is_ok());
    assert!(parse::<Tpm2bEncryptedSecret>(&tpm2b(400)).is_ok());
    assert!(parse::<Tpm2bPrivate>(&tpm2b(911)).is_ok());
    assert!(parse::<Tpm2bPrivateKeyRsa>(&tpm2b(641)).is_ok());
    assert!(parse::<Tpm2bTemplate>(&tpm2b(351)).is_ok());
    assert!(parse::<Tpm2bEccParameter>(&tpm2b(33)).is_ok());
    assert!(parse::<TpmlPcrSelection>(&pcr_selection(2)).is_ok());
    assert!(profile::allows_algorithm(Alg::SHA1));
    assert!(profile::is_default_pcr_bank(Alg::SHA384));
    assert!(!profile::is_default_pcr_bank(Alg::SHA1));

    profile::install(&PROFILE).unwrap();
    assert!(profile::is_installed());
    profile::install(&PROFILE).unwrap();
    profile::install(&SAME_PROFILE).unwrap();
    assert_eq!(
        profile::install(&OTHER_PROFILE),
        Err(InstallError::ProfileAlreadyInstalled)
    );
    // A profile that differs only in its default PCR banks is a different profile.
    static OTHER_BANKS: Profile = Profile {
        default_pcr_banks: &[],
        ..PROFILE
    };
    assert_eq!(
        profile::install(&OTHER_BANKS),
        Err(InstallError::ProfileAlreadyInstalled)
    );
    assert!(profile::is_default_pcr_bank(Alg::SHA256));
    assert!(!profile::is_default_pcr_bank(Alg::SHA384));

    // Algorithms outside the profile fail with the type's error; NULL stays NULL.
    assert_eq!(TpmiAlgHash::try_from(Alg::SHA256), Ok(TpmiAlgHash::Sha256));
    assert_eq!(
        TpmiAlgHash::try_from(Alg::SHA384),
        Err(UnmarshalError::HASH)
    );
    assert_eq!(
        TpmiAlgHash::try_from(Alg::SM3_256),
        Err(UnmarshalError::HASH)
    );
    assert_eq!(Option::<TpmiAlgHash>::try_from(Alg::NULL), Ok(None));
    assert!(TpmiAlgSigScheme::try_from(Alg::RSASSA).is_ok());
    assert_eq!(
        TpmiAlgSigScheme::try_from(Alg::RSAPSS),
        Err(UnmarshalError::SCHEME)
    );
    assert_eq!(
        TpmiAlgPublic::try_from(Alg::KEYEDHASH),
        Err(UnmarshalError::TYPE)
    );
    // Symmetric algorithms: AES only.
    assert!(parse::<AlgSym>(&[0x00, 0x06, 0x00, 0x80]).is_ok());
    assert_eq!(
        parse::<AlgSym>(&[0x00, 0x26, 0x00, 0x80]),
        Err(UnmarshalError::SYMMETRIC)
    );
    // Symmetric key sizes: AES-192 is not in the profile.
    assert!(parse::<AlgSym>(&[0x00, 0x06, 0x01, 0x00]).is_ok());
    assert_eq!(
        parse::<AlgSym>(&[0x00, 0x06, 0x00, 0xC0]),
        Err(UnmarshalError::VALUE)
    );
    // Curves and RSA key sizes.
    assert_eq!(TpmEccCurve::try_from(0x0003), Ok(TpmEccCurve::NistP256));
    assert_eq!(TpmEccCurve::try_from(0x0004), Err(UnmarshalError::CURVE));
    assert_eq!(TpmEccCurve::try_from(0x0000), Ok(TpmEccCurve::None));
    assert!(TpmiRsaKeyBits::try_from(2048).is_ok());
    assert_eq!(TpmiRsaKeyBits::try_from(4096), Err(UnmarshalError::VALUE));
    assert_eq!(TpmiRsaKeyBits::try_from(1024), Err(UnmarshalError::VALUE));
    // RSA-dependent buffers: the profile's sizes.
    assert!(parse::<Tpm2bPublicKeyRsa>(&tpm2b(256)).is_ok());
    assert_eq!(
        parse::<Tpm2bPublicKeyRsa>(&tpm2b(257)),
        Err(UnmarshalError::SIZE)
    );
    assert!(parse::<Tpm2bEncryptedSecret>(&tpm2b(256)).is_ok());
    assert_eq!(
        parse::<Tpm2bEncryptedSecret>(&tpm2b(257)),
        Err(UnmarshalError::SIZE)
    );
    assert!(parse::<Tpm2bPrivate>(&tpm2b(910)).is_ok());
    assert_eq!(
        parse::<Tpm2bPrivate>(&tpm2b(911)),
        Err(UnmarshalError::SIZE)
    );
    assert!(parse::<Tpm2bPrivateKeyRsa>(&tpm2b(640)).is_ok());
    assert_eq!(
        parse::<Tpm2bPrivateKeyRsa>(&tpm2b(641)),
        Err(UnmarshalError::SIZE)
    );
    assert!(parse::<Tpm2bTemplate>(&tpm2b(350)).is_ok());
    assert_eq!(
        parse::<Tpm2bTemplate>(&tpm2b(351)),
        Err(UnmarshalError::SIZE)
    );
    assert!(parse::<Tpm2bEccParameter>(&tpm2b(32)).is_ok());
    assert_eq!(
        parse::<Tpm2bEccParameter>(&tpm2b(33)),
        Err(UnmarshalError::SIZE)
    );
    // `HASH_COUNT` lists: one hash algorithm in the profile.
    assert!(parse::<TpmlPcrSelection>(&pcr_selection(1)).is_ok());
    assert_eq!(
        parse::<TpmlPcrSelection>(&pcr_selection(2)),
        Err(UnmarshalError::SIZE)
    );
    // An oversized buffer is SIZE even when truncated (the size is checked first).
    assert_eq!(
        parse::<Tpm2bEncryptedSecret>(&[0x01, 0x01]),
        Err(UnmarshalError::SIZE)
    );
}

/// A profile that cannot be represented is rejected without installing anything.
#[test]
fn unrepresentable_profiles_are_rejected() {
    static BAD_BITS: Profile = Profile {
        rsa_key_bits: &[1000],
        ..PROFILE
    };
    assert_eq!(
        profile::install(&BAD_BITS),
        Err(InstallError::Unrepresentable)
    );
    // A default PCR bank must be an implemented hash algorithm.
    static UNIMPLEMENTED_BANK: Profile = Profile {
        default_pcr_banks: &[Alg::SHA384],
        ..PROFILE
    };
    assert_eq!(
        profile::install(&UNIMPLEMENTED_BANK),
        Err(InstallError::InvalidDefaultPcrBank)
    );
    static NON_HASH_BANK: Profile = Profile {
        default_pcr_banks: &[Alg::RSA],
        ..PROFILE
    };
    assert_eq!(
        profile::install(&NON_HASH_BANK),
        Err(InstallError::InvalidDefaultPcrBank)
    );
}
