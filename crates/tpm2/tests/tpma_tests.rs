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
fn test_tpma_object_flags_and_reserved_bits() {
    assert_eq!(TpmaObject::FIRMWARE_LIMITED.bits(), 1 << 8);
    assert_eq!(TpmaObject::SVN_LIMITED.bits(), 1 << 9);
    assert_eq!(TpmaObject::RESERVED_BITS_MASK, 0xfff0_f009);
    assert_eq!(!TpmaObject::all().bits(), TpmaObject::RESERVED_BITS_MASK);

    // Bit 3 (0x0000_0008) is reserved (fixedFirmware was moved to bit 8 firmwareLimited in spec)
    assert_eq!(
        TpmaObject::unmarshal(&mut &0x0000_0008u32.to_be_bytes()[..]),
        Err(UnmarshalError::RESERVED_BITS)
    );

    // All valid bits should marshal/unmarshal cleanly
    let valid = TpmaObject::all();
    let mut buf = [0u8; 4];
    assert_eq!(valid.marshal(&mut buf), 4);
    let mut slice = &buf[..];
    assert_eq!(TpmaObject::unmarshal(&mut slice), Ok(valid));

    // Each reserved bit in 0xfff0_f009 must fail with RESERVED_BITS
    for bit in 0..32 {
        let mask = 1u32 << bit;
        if (mask & TpmaObject::RESERVED_BITS_MASK) != 0 {
            let bytes = mask.to_be_bytes();
            let mut s = &bytes[..];
            assert_eq!(
                TpmaObject::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS),
                "TpmaObject bit {bit} should be rejected as RESERVED_BITS"
            );
        } else {
            let bytes = mask.to_be_bytes();
            let mut s = &bytes[..];
            assert_eq!(
                TpmaObject::unmarshal(&mut s),
                Ok(TpmaObject(mask)),
                "TpmaObject bit {bit} should be accepted"
            );
        }
    }
}

#[test]
fn test_tpma_algorithm_reserved_bits() {
    assert_eq!(
        !TpmaAlgorithm::all().bits(),
        TpmaAlgorithm::RESERVED_BITS_MASK
    );
    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaAlgorithm::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaAlgorithm::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(TpmaAlgorithm::unmarshal(&mut s), Ok(TpmaAlgorithm(mask)));
        }
    }
}

#[test]
fn test_tpma_session_reserved_bits() {
    assert_eq!(!TpmaSession::all().bits(), TpmaSession::RESERVED_BITS_MASK);
    for bit in 0..8 {
        let mask = 1u8 << bit;
        let bytes = [mask];
        let mut s = &bytes[..];
        if (mask & TpmaSession::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaSession::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(TpmaSession::unmarshal(&mut s), Ok(TpmaSession(mask)));
        }
    }
}

#[test]
fn test_tpma_nv_reserved_bits() {
    assert_eq!(TpmaNv::RESERVED_BITS_MASK, 0x01f00300);
    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaNv::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaNv::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(TpmaNv::unmarshal(&mut s), Ok(TpmaNv(mask)));
        }
    }
}

#[test]
fn test_tpma_nv_exp_reserved_bits() {
    assert_eq!(TpmaNvExp::RESERVED_BITS_MASK, 0xffff_fff8_01f0_0300);
    for bit in 0..64 {
        let mask = 1u64 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaNvExp::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaNvExp::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS),
                "TpmaNvExp bit {bit} should be rejected as RESERVED_BITS"
            );
        } else {
            assert_eq!(
                TpmaNvExp::unmarshal(&mut s),
                Ok(TpmaNvExp(mask)),
                "TpmaNvExp bit {bit} should be accepted"
            );
        }
    }

    // Conversion between TpmaNv and TpmaNvExp
    let nv = TpmaNv::PPWRITE | TpmaNv::OWNERREAD | TpmaNv::from(TpmNt::Counter);
    let exp: TpmaNvExp = nv.into();
    assert_eq!(exp.get_index_type(), Ok(TpmNt::Counter));
    assert_eq!(TpmaNv::try_from(exp), Ok(nv));

    // Setting upper external NV bits should fail conversion back to legacy TpmaNv
    let exp_ext = exp | TpmaNvExp::EXTERNAL_NV_ENCRYPTION;
    assert!(TpmaNv::try_from(exp_ext).is_err());
}

#[test]
fn test_tpma_cc_reserved_bits() {
    assert_eq!(TpmaCc::RESERVED_BITS_MASK, 0xc03f0000);
    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaCc::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaCc::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(TpmaCc::unmarshal(&mut s), Ok(TpmaCc(mask)));
        }
    }
}

#[test]
fn test_new_tpma_bitfields_reserved_bits() {
    assert_eq!(
        !TpmaPermanent::all().bits(),
        TpmaPermanent::RESERVED_BITS_MASK
    );
    assert_eq!(
        !TpmaStartupClear::all().bits(),
        TpmaStartupClear::RESERVED_BITS_MASK
    );
    assert_eq!(!TpmaMemory::all().bits(), TpmaMemory::RESERVED_BITS_MASK);
    assert_eq!(!TpmaModes::all().bits(), TpmaModes::RESERVED_BITS_MASK);
    assert_eq!(
        !TpmaX509KeyUsage::all().bits(),
        TpmaX509KeyUsage::RESERVED_BITS_MASK
    );
    assert_eq!(!TpmaAct::all().bits(), TpmaAct::RESERVED_BITS_MASK);

    // TpmaPermanent
    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaPermanent::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaPermanent::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(TpmaPermanent::unmarshal(&mut s), Ok(TpmaPermanent(mask)));
        }
    }

    // TpmaStartupClear
    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaStartupClear::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaStartupClear::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(
                TpmaStartupClear::unmarshal(&mut s),
                Ok(TpmaStartupClear(mask))
            );
        }
    }

    // TpmaMemory
    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaMemory::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaMemory::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(TpmaMemory::unmarshal(&mut s), Ok(TpmaMemory(mask)));
        }
    }

    // TpmaModes
    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaModes::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaModes::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(TpmaModes::unmarshal(&mut s), Ok(TpmaModes(mask)));
        }
    }
    let mut modes = TpmaModes::FIPS_140_3;
    modes.set_fips_140_3_indicator(2);
    assert_eq!(modes.get_fips_140_3_indicator(), 2);

    // TpmaX509KeyUsage
    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaX509KeyUsage::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaX509KeyUsage::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(
                TpmaX509KeyUsage::unmarshal(&mut s),
                Ok(TpmaX509KeyUsage(mask))
            );
        }
    }

    // TpmaAct
    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaAct::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaAct::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS)
            );
        } else {
            assert_eq!(TpmaAct::unmarshal(&mut s), Ok(TpmaAct(mask)));
        }
    }

    // TpmaMlParameterSet
    assert_eq!(TpmaMlParameterSet::ML_KEM_512.bits(), 1 << 0);
    assert_eq!(TpmaMlParameterSet::ML_KEM_768.bits(), 1 << 1);
    assert_eq!(TpmaMlParameterSet::ML_KEM_1024.bits(), 1 << 2);
    assert_eq!(TpmaMlParameterSet::ML_DSA_44.bits(), 1 << 3);
    assert_eq!(TpmaMlParameterSet::ML_DSA_65.bits(), 1 << 4);
    assert_eq!(TpmaMlParameterSet::ML_DSA_87.bits(), 1 << 5);
    assert_eq!(TpmaMlParameterSet::EXT_MU.bits(), 1 << 6);
    assert_eq!(TpmaMlParameterSet::RESERVED_BITS_MASK, 0xffff_ff80);
    assert_eq!(
        !TpmaMlParameterSet::all().bits(),
        TpmaMlParameterSet::RESERVED_BITS_MASK
    );

    let all_ml = TpmaMlParameterSet::all();
    let mut buf = [0u8; 4];
    assert_eq!(all_ml.marshal(&mut buf), 4);
    let mut slice = &buf[..];
    assert_eq!(TpmaMlParameterSet::unmarshal(&mut slice), Ok(all_ml));

    for bit in 0..32 {
        let mask = 1u32 << bit;
        let bytes = mask.to_be_bytes();
        let mut s = &bytes[..];
        if (mask & TpmaMlParameterSet::RESERVED_BITS_MASK) != 0 {
            assert_eq!(
                TpmaMlParameterSet::unmarshal(&mut s),
                Err(UnmarshalError::RESERVED_BITS),
                "TpmaMlParameterSet bit {bit} should be rejected as RESERVED_BITS"
            );
        } else {
            assert_eq!(
                TpmaMlParameterSet::unmarshal(&mut s),
                Ok(TpmaMlParameterSet(mask)),
                "TpmaMlParameterSet bit {bit} should be accepted"
            );
        }
    }
}
