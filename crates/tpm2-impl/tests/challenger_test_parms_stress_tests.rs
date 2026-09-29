use tpm2::errors::{Position, TpmRc};
use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::TpmEccCurve;
use tpm2::commands::{Command, TestParms};
use tpm2::{
    TpmiAlgHash, TpmiAlgKdf, TpmiAlgSymMode, TpmiRsaKeyBits, TpmsAuthCommand, TpmsEccParms,
    TpmsRsaParms, TpmsSchemeEcdaa, TpmsSchemeXor, TpmtEccScheme, TpmtKdfScheme,
    TpmtKeyedHashScheme, TpmtPublicParms, TpmtRsaScheme, TpmtSymDefObject,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
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
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::RespHandles, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let resp_handles =
        C::RespHandles::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
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
        let idx = (self.next_u64() as usize) % choices.len();
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
            if parms.key_bits.0 != 1024 && parms.key_bits.0 != 2048 {
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
            Some(TpmtKeyedHashScheme::ExclusiveOr(scheme)) => {
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
        Some(TpmtSymDefObject::Aes128(mode)) | Some(TpmtSymDefObject::Aes256(mode)) => {
            if mode != Some(TpmiAlgSymMode::CFB) {
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
            Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
            Some(TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CFB))),
            None,
        ])
    } else {
        rng.choose(&[
            Some(TpmtSymDefObject::Aes192(Some(TpmiAlgSymMode::CFB))),
            Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CBC))),
            Some(TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CTR))),
            Some(TpmtSymDefObject::Sm4_128(Some(TpmiAlgSymMode::CFB))),
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
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
                hash_alg,
                kdf: kdf_val,
            })),
            None,
        ])
    } else {
        let hash_alg = gen_hash_alg(rng, false);
        rng.choose(&[
            Some(TpmtKeyedHashScheme::Hmac(hash_alg)),
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
                hash_alg: TpmiAlgHash::Sm3_256,
                kdf: Some(TpmiAlgKdf::Mgf1),
            })),
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
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
                rng.choose(&[TpmiRsaKeyBits(1024), TpmiRsaKeyBits(2048)])
            } else {
                rng.choose(&[
                    TpmiRsaKeyBits(512),
                    TpmiRsaKeyBits(3072),
                    TpmiRsaKeyBits(4096),
                    TpmiRsaKeyBits(9999),
                ])
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
                    TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
                    TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CFB)),
                ])
            } else {
                rng.choose(&[
                    TpmtSymDefObject::Aes192(Some(TpmiAlgSymMode::CFB)),
                    TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CBC)),
                ])
            };
            TpmtPublicParms::Sym(sym)
        }
    }
}

#[test]
fn test_test_parms_stress_fuzz() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng_fake = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng_fake);

    let mut rng = SimpleRng::new(42);
    let mut passed = 0;

    for i in 0..1000 {
        let parms = gen_random_parms(&mut rng);
        let expected = oracle_validate_parms(&parms);
        let cmd = TestParms { parameters: parms };
        let res = execute_tpm_command::<TestParms>(&mut tpm, &mut global_state, &(), &cmd, &[]);

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
