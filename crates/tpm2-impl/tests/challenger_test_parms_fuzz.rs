#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider, marshal_to_slice};
use hex_literal::hex;
use tpm2::commands::{Command, Message, TestParms, UnmarshalMessage};
use tpm2::crypto::Random;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Handle, Marshal, TpmEccCurve, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgKdf,
    TpmiAlgSymMode, TpmiRsaKeyBits, TpmsAuthCommand, TpmsEccParms, TpmsRsaParms, TpmsSchemeEcdaa,
    TpmsSchemeXor, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedHashScheme, TpmtPublicParms,
    TpmtRsaScheme, TpmtSymDefObject, Unmarshal,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

const fn sym_def(alg: AlgSym, mode: TpmiAlgCipherMode) -> TpmtSymDefObject {
    TpmtSymDefObject {
        alg,
        mode: Some(TpmiAlgSymMode::Cipher(mode)),
    }
}

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    _rng: FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(&[0u8; 32]).unwrap();
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<C::Response<'static>, u32>
where
    for<'a> &'a mut <C as Marshal>::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    request_buf[0..2].copy_from_slice(&tag.to_be_bytes());
    request_buf[6..10].copy_from_slice(&u32::from(C::CMD_CODE).to_be_bytes());

    for h in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let mut auth_buf = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_buf);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let response_buf = alloc::vec![0u8; 16384].leak();
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_slice: &'static [u8] = &response_buf[10..resp_size];
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut resp_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        let param_size = u32::unmarshal(&mut resp_slice).map_err(|_| TpmRc::FAILURE.get())?;
        let param_len = usize::try_from(param_size).unwrap();
        resp_slice = &resp_slice[..param_len];
    }

    let resp_params = C::Response::unmarshal_with_handles(resp_handles, &mut resp_slice)
        .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp_params)
}

struct SimpleRng(u64);
impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn choose<T: Clone>(&mut self, choices: &[T]) -> T {
        let len = u64::try_from(choices.len()).unwrap();
        let idx = usize::try_from(self.next_u64() % len).unwrap();
        choices[idx].clone()
    }
}

fn oracle_validate_parms(parms: &TpmtPublicParms) -> Result<(), TpmRc> {
    match parms {
        TpmtPublicParms::Rsa(parms) => {
            match parms.scheme {
                Some(TpmtRsaScheme::Rsapss(scheme)) => {
                    oracle_validate_hash_alg(scheme)?;
                }
                Some(TpmtRsaScheme::Rsassa(scheme)) => {
                    oracle_validate_hash_alg(scheme)?;
                }
                Some(TpmtRsaScheme::Oaep(scheme)) => {
                    oracle_validate_hash_alg(scheme)?;
                }
                Some(TpmtRsaScheme::Rsaes) | None => {}
            }
            oracle_validate_symmetric(parms.symmetric)?;
            if u16::from(parms.key_bits) != 1024 && u16::from(parms.key_bits) != 2048 {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            if parms.exponent != 0 && parms.exponent != 65537 {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        }
        TpmtPublicParms::Ecc(parms) => {
            match parms.scheme {
                Some(TpmtEccScheme::Ecdsa(scheme))
                | Some(TpmtEccScheme::Sm2(scheme))
                | Some(TpmtEccScheme::Ecschnorr(scheme)) => {
                    oracle_validate_hash_alg(scheme)?;
                }
                Some(TpmtEccScheme::Ecdaa(scheme)) => {
                    oracle_validate_hash_alg(scheme.hash_alg)?;
                }
                Some(_) => {
                    return Err(TpmRc::SCHEME.with(Position::parameter(1)));
                }
                None => {}
            }
            if let Some(kdf) = parms.kdf {
                match kdf {
                    TpmtKdfScheme::Kdf1Sp800_56a(scheme) => {
                        oracle_validate_hash_alg(scheme)?;
                    }
                    TpmtKdfScheme::Kdf2(scheme) => {
                        oracle_validate_hash_alg(scheme)?;
                    }
                    TpmtKdfScheme::Kdf1Sp800_108(scheme) => {
                        oracle_validate_hash_alg(scheme)?;
                    }
                    TpmtKdfScheme::Mgf1(_) | TpmtKdfScheme::Hkdf(_) => {
                        return Err(TpmRc::KDF.with(Position::parameter(1)));
                    }
                }
            }
            oracle_validate_symmetric(parms.symmetric)?;
            if parms.curve_id != TpmEccCurve::NistP256
                && parms.curve_id != TpmEccCurve::NistP384
                && parms.curve_id != TpmEccCurve::NistP521
                && parms.curve_id != TpmEccCurve::BNP256
            {
                return Err(TpmRc::CURVE.with(Position::parameter(1)));
            }
        }
        TpmtPublicParms::KeyedHash(scheme) => match scheme {
            Some(TpmtKeyedHashScheme::Hmac(h)) => {
                oracle_validate_hash_alg(*h)?;
            }
            Some(TpmtKeyedHashScheme::Xor(scheme)) => {
                oracle_validate_hash_alg(scheme.hash_alg)?;
                if scheme.kdf.is_none() || scheme.kdf == Some(TpmiAlgKdf::Hkdf) {
                    return Err(TpmRc::KDF.with(Position::parameter(1)));
                }
            }
            None => {}
        },
        TpmtPublicParms::Sym(sym) => {
            oracle_validate_symmetric(Some(*sym))?;
        }
        TpmtPublicParms::Mldsa(_) | TpmtPublicParms::HashMldsa(_) | TpmtPublicParms::Mlkem(_) => {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
    }
    Ok(())
}

fn oracle_validate_hash_alg(hash_alg: TpmiAlgHash) -> Result<(), TpmRc> {
    if hash_alg != TpmiAlgHash::Sha1
        && hash_alg != TpmiAlgHash::Sha256
        && hash_alg != TpmiAlgHash::Sha384
        && hash_alg != TpmiAlgHash::Sha512
    {
        return Err(TpmRc::HASH.with(Position::parameter(1)));
    }
    Ok(())
}

fn oracle_validate_symmetric(symmetric: Option<TpmtSymDefObject>) -> Result<(), TpmRc> {
    match symmetric {
        Some(TpmtSymDefObject {
            alg: AlgSym::Aes128 | AlgSym::Aes256,
            mode,
        }) => {
            if mode != Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)) {
                return Err(TpmRc::MODE.with(Position::parameter(1)));
            }
        }
        None => {}
        _ => {
            return Err(TpmRc::SYMMETRIC.with(Position::parameter(1)));
        }
    }
    Ok(())
}

fn gen_symmetric(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtSymDefObject> {
    if make_valid {
        rng.choose(&[
            Some(sym_def(AlgSym::Aes128, TpmiAlgCipherMode::Cfb)),
            Some(sym_def(AlgSym::Aes256, TpmiAlgCipherMode::Cfb)),
            None,
        ])
    } else {
        rng.choose(&[
            Some(sym_def(AlgSym::Aes192, TpmiAlgCipherMode::Cfb)),
            Some(sym_def(AlgSym::Aes128, TpmiAlgCipherMode::Cbc)),
            Some(sym_def(AlgSym::Aes256, TpmiAlgCipherMode::Ctr)),
            Some(sym_def(AlgSym::Sm4_128, TpmiAlgCipherMode::Cfb)),
            None,
        ])
    }
}

fn gen_hash_alg(rng: &mut SimpleRng, make_valid: bool) -> TpmiAlgHash {
    if make_valid {
        rng.choose(&[
            TpmiAlgHash::Sha1,
            TpmiAlgHash::Sha256,
            TpmiAlgHash::Sha384,
            TpmiAlgHash::Sha512,
        ])
    } else {
        rng.choose(&[
            TpmiAlgHash::Sm3_256,
            TpmiAlgHash::Sha3_256,
            TpmiAlgHash::Sha3_384,
            TpmiAlgHash::Sha3_512,
        ])
    }
}

fn gen_rsa_scheme(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtRsaScheme> {
    if make_valid {
        let hash_alg = gen_hash_alg(rng, true);
        rng.choose(&[
            Some(TpmtRsaScheme::Rsapss(hash_alg)),
            Some(TpmtRsaScheme::Rsassa(hash_alg)),
            Some(TpmtRsaScheme::Oaep(hash_alg)),
            Some(TpmtRsaScheme::Rsaes),
            None,
        ])
    } else {
        let hash_alg = gen_hash_alg(rng, false);
        rng.choose(&[
            Some(TpmtRsaScheme::Rsapss(hash_alg)),
            Some(TpmtRsaScheme::Rsassa(hash_alg)),
            Some(TpmtRsaScheme::Oaep(hash_alg)),
        ])
    }
}

fn gen_ecc_scheme(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtEccScheme> {
    if make_valid {
        let hash_alg = gen_hash_alg(rng, true);
        rng.choose(&[
            Some(TpmtEccScheme::Ecdsa(hash_alg)),
            Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa { hash_alg, count: 0 })),
            Some(TpmtEccScheme::Sm2(hash_alg)),
            Some(TpmtEccScheme::Ecschnorr(hash_alg)),
            None,
        ])
    } else {
        let hash_alg = gen_hash_alg(rng, false);
        rng.choose(&[
            Some(TpmtEccScheme::Ecdsa(hash_alg)),
            Some(TpmtEccScheme::Sm2(hash_alg)),
            Some(TpmtEccScheme::Ecschnorr(hash_alg)),
        ])
    }
}

fn gen_ecc_kdf(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtKdfScheme> {
    if make_valid {
        let hash_alg = gen_hash_alg(rng, true);
        rng.choose(&[
            Some(TpmtKdfScheme::Kdf1Sp800_56a(hash_alg)),
            Some(TpmtKdfScheme::Kdf2(hash_alg)),
            Some(TpmtKdfScheme::Kdf1Sp800_108(hash_alg)),
            None,
        ])
    } else {
        let hash_alg = gen_hash_alg(rng, false);
        rng.choose(&[
            Some(TpmtKdfScheme::Kdf1Sp800_56a(hash_alg)),
            Some(TpmtKdfScheme::Kdf2(hash_alg)),
            Some(TpmtKdfScheme::Kdf1Sp800_108(hash_alg)),
            Some(TpmtKdfScheme::Mgf1(hash_alg)),
        ])
    }
}

fn gen_keyed_hash_scheme(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtKeyedHashScheme> {
    if make_valid {
        let hash_alg = gen_hash_alg(rng, true);
        let kdf_val = rng.choose(&[
            Some(TpmiAlgKdf::Mgf1),
            Some(TpmiAlgKdf::Kdf1Sp800_56a),
            Some(TpmiAlgKdf::Kdf2),
            Some(TpmiAlgKdf::Kdf1Sp800_108),
            None,
        ]);
        rng.choose(&[
            Some(TpmtKeyedHashScheme::Hmac(hash_alg)),
            Some(TpmtKeyedHashScheme::Xor(TpmsSchemeXor {
                hash_alg,
                kdf: kdf_val,
            })),
            None,
        ])
    } else {
        let hash_alg = gen_hash_alg(rng, false);
        rng.choose(&[
            Some(TpmtKeyedHashScheme::Hmac(hash_alg)),
            Some(TpmtKeyedHashScheme::Xor(TpmsSchemeXor {
                hash_alg: TpmiAlgHash::Sm3_256,
                kdf: Some(TpmiAlgKdf::Mgf1),
            })),
            Some(TpmtKeyedHashScheme::Xor(TpmsSchemeXor {
                hash_alg: TpmiAlgHash::Sha3_256,
                kdf: None,
            })),
        ])
    }
}

fn gen_random_parms(rng: &mut SimpleRng) -> TpmtPublicParms {
    // 0: RSA, 1: ECC, 2: KeyedHash, 3: Sym
    let variant = rng.next_u64() % 4;
    let make_valid = rng.next_u64() % 10 < 4;

    match variant {
        0 => {
            let key_bits = if make_valid {
                rng.choose(&[TpmiRsaKeyBits::Rsa1024, TpmiRsaKeyBits::Rsa2048])
            } else {
                rng.choose(&[TpmiRsaKeyBits::Rsa3072, TpmiRsaKeyBits::Rsa4096])
            };
            let exponent = if make_valid {
                rng.choose(&[0, 65537])
            } else {
                rng.choose(&[3, 17, 65535])
            };
            let symmetric = gen_symmetric(rng, make_valid);
            let scheme = gen_rsa_scheme(rng, make_valid);

            TpmtPublicParms::Rsa(TpmsRsaParms {
                symmetric,
                scheme,
                key_bits,
                exponent,
            })
        }
        1 => {
            let curve_id = if make_valid {
                rng.choose(&[
                    TpmEccCurve::NistP256,
                    TpmEccCurve::NistP384,
                    TpmEccCurve::BNP256,
                ])
            } else {
                TpmEccCurve::NistP256
            };
            let symmetric = gen_symmetric(rng, make_valid);
            let scheme = gen_ecc_scheme(rng, make_valid);
            let kdf = gen_ecc_kdf(rng, make_valid);

            TpmtPublicParms::Ecc(TpmsEccParms {
                symmetric,
                scheme,
                curve_id,
                kdf,
            })
        }
        2 => {
            let scheme = gen_keyed_hash_scheme(rng, make_valid);
            TpmtPublicParms::KeyedHash(scheme)
        }
        _ => {
            let sym = if make_valid {
                rng.choose(&[
                    sym_def(AlgSym::Aes128, TpmiAlgCipherMode::Cfb),
                    sym_def(AlgSym::Aes256, TpmiAlgCipherMode::Cfb),
                ])
            } else {
                rng.choose(&[
                    sym_def(AlgSym::Aes192, TpmiAlgCipherMode::Cfb),
                    sym_def(AlgSym::Aes128, TpmiAlgCipherMode::Cbc),
                ])
            };
            TpmtPublicParms::Sym(sym)
        }
    }
}

#[test]
fn test_parms_stress_differential_fuzz() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // Use a fixed seed for reproducible fuzzing
    let mut fuzzer_rng = SimpleRng::new(13372026);

    let num_iterations = 2000;
    let mut passed_count = 0;

    for i in 0..num_iterations {
        let parms = gen_random_parms(&mut fuzzer_rng);
        let expected = oracle_validate_parms(&parms);

        let cmd = TestParms { parameters: parms };
        let res = execute_tpm_command::<TestParms>(&mut tpm, &mut global_state, &cmd, &[]);

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

#[test]
fn test_parms_malformed_buffers() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // 1. Unknown selector in TpmtPublicParms (e.g. 0x0004 which is SHA1, not a valid public parms algorithm)
    // Header: Tag (8001), Size (0000000E), CmdCode (0000018A), Discriminant (0004)
    let request_unknown_selector = hex!("8001 0000000c 0000018a 0004");
    let mut response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &request_unknown_selector[..],
        &mut response[..],
    );
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    // Should return unmarshal error TpmRc::VALUE.with(Position::parameter(1)) = 0x184
    assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(1)).get());

    // 2. Truncated buffer
    // Discriminant is RSA (0001), but nothing else is provided.
    // TpmsRsaParms needs symmetric, scheme, key_bits, exponent.
    let request_truncated = hex!("8001 0000000c 0000018a 0001");
    tpm.execute_command_separate(&mut global_state, &request_truncated[..], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    // Should return TpmRc::VALUE.with(Position::parameter(1)) = 0x184
    assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(1)).get());
}
