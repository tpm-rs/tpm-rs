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

use tpm2::platform::pcr::PcrState;
use tpm2::*;

#[test]
fn test_pcr_state_default_banks_and_allocation() {
    let pcr = PcrState::default();

    // PCR 0..=16 and 23 must be 0x00, PCR 17..=22 must be 0xFF
    for i in 0..=16 {
        #[cfg(feature = "sha1")]
        assert_eq!(pcr.sha1[i], [0x00; 20]);
        #[cfg(feature = "sha256")]
        assert_eq!(pcr.sha256[i], [0x00; 32]);
        #[cfg(feature = "sha384")]
        assert_eq!(pcr.sha384[i], [0x00; 48]);
        #[cfg(feature = "sha512")]
        assert_eq!(pcr.sha512[i], [0x00; 64]);
        #[cfg(feature = "sm3_256")]
        assert_eq!(pcr.sm3_256[i], [0x00; 32]);
        #[cfg(feature = "sha3_256")]
        assert_eq!(pcr.sha3_256[i], [0x00; 32]);
        #[cfg(feature = "sha3_384")]
        assert_eq!(pcr.sha3_384[i], [0x00; 48]);
        #[cfg(feature = "sha3_512")]
        assert_eq!(pcr.sha3_512[i], [0x00; 64]);
    }
    for i in 17..=22 {
        #[cfg(feature = "sha1")]
        assert_eq!(pcr.sha1[i], [0xFF; 20]);
        #[cfg(feature = "sha256")]
        assert_eq!(pcr.sha256[i], [0xFF; 32]);
        #[cfg(feature = "sha384")]
        assert_eq!(pcr.sha384[i], [0xFF; 48]);
        #[cfg(feature = "sha512")]
        assert_eq!(pcr.sha512[i], [0xFF; 64]);
        #[cfg(feature = "sm3_256")]
        assert_eq!(pcr.sm3_256[i], [0xFF; 32]);
        #[cfg(feature = "sha3_256")]
        assert_eq!(pcr.sha3_256[i], [0xFF; 32]);
        #[cfg(feature = "sha3_384")]
        assert_eq!(pcr.sha3_384[i], [0xFF; 48]);
        #[cfg(feature = "sha3_512")]
        assert_eq!(pcr.sha3_512[i], [0xFF; 64]);
    }
    #[cfg(feature = "sha1")]
    assert_eq!(pcr.sha1[23], [0x00; 20]);
    #[cfg(feature = "sha256")]
    assert_eq!(pcr.sha256[23], [0x00; 32]);
    #[cfg(feature = "sha384")]
    assert_eq!(pcr.sha384[23], [0x00; 48]);
    #[cfg(feature = "sha512")]
    assert_eq!(pcr.sha512[23], [0x00; 64]);
    #[cfg(feature = "sm3_256")]
    assert_eq!(pcr.sm3_256[23], [0x00; 32]);
    #[cfg(feature = "sha3_256")]
    assert_eq!(pcr.sha3_256[23], [0x00; 32]);
    #[cfg(feature = "sha3_384")]
    assert_eq!(pcr.sha3_384[23], [0x00; 48]);
    #[cfg(feature = "sha3_512")]
    assert_eq!(pcr.sha3_512[23], [0x00; 64]);

    assert_eq!(pcr.update_counter, 0);

    // Verify PCR allocation contains selections for supported algorithms
    let selections = pcr.pcr_allocation.pcr_selections();
    let hashes: Vec<TpmiAlgHash> = selections.map(|s| s.hash()).collect();

    #[cfg(feature = "sha1")]
    assert!(hashes.contains(&TpmiAlgHash::Sha1));
    #[cfg(feature = "sha256")]
    assert!(hashes.contains(&TpmiAlgHash::Sha256));
    #[cfg(feature = "sha384")]
    assert!(hashes.contains(&TpmiAlgHash::Sha384));
    #[cfg(feature = "sha512")]
    assert!(hashes.contains(&TpmiAlgHash::Sha512));
    #[cfg(feature = "sm3_256")]
    assert!(hashes.contains(&TpmiAlgHash::Sm3_256));
    #[cfg(feature = "sha3_256")]
    assert!(hashes.contains(&TpmiAlgHash::Sha3_256));
    #[cfg(feature = "sha3_384")]
    assert!(hashes.contains(&TpmiAlgHash::Sha3_384));
    #[cfg(feature = "sha3_512")]
    assert!(hashes.contains(&TpmiAlgHash::Sha3_512));
}

#[test]
fn test_pcr_state_reset_preserves_custom_pcr_allocation() {
    let mut pcr = PcrState::default();

    // Custom PCR allocation
    let custom_allocation = TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::DEFAULT_HASH, &[0x01, 0x02, 0x04]).unwrap(),
        #[cfg(all(feature = "sha384", feature = "sha256"))]
        TpmsPcrSelection::new(TpmiAlgHash::Sha384, &[0xFF, 0xFF, 0xFF]).unwrap(),
    ])
    .unwrap();

    pcr.pcr_allocation = custom_allocation;

    // Mutate register values and update counter
    #[cfg(feature = "sha1")]
    {
        pcr.sha1[0] = [0xAA; 20];
        pcr.sha1[18] = [0x00; 20];
    }
    #[cfg(feature = "sha256")]
    {
        pcr.sha256[0] = [0xBB; 32];
        pcr.sha256[18] = [0x00; 32];
    }
    #[cfg(feature = "sha384")]
    {
        pcr.sha384[0] = [0xCC; 48];
        pcr.sha384[18] = [0x00; 48];
    }
    #[cfg(feature = "sha512")]
    {
        pcr.sha512[0] = [0xDD; 64];
        pcr.sha512[18] = [0x00; 64];
    }
    #[cfg(feature = "sm3_256")]
    {
        pcr.sm3_256[0] = [0xEE; 32];
        pcr.sm3_256[18] = [0x00; 32];
    }
    #[cfg(feature = "sha3_256")]
    {
        pcr.sha3_256[0] = [0x11; 32];
        pcr.sha3_256[18] = [0x00; 32];
    }
    #[cfg(feature = "sha3_384")]
    {
        pcr.sha3_384[0] = [0x22; 48];
        pcr.sha3_384[18] = [0x00; 48];
    }
    #[cfg(feature = "sha3_512")]
    {
        pcr.sha3_512[0] = [0x33; 64];
        pcr.sha3_512[18] = [0x00; 64];
    }
    pcr.update_counter = 12345;

    // Reset PCR state
    pcr.reset();

    // 1. Allocation must be preserved
    assert_eq!(pcr.pcr_allocation, custom_allocation);

    // 2. Update counter must be 0
    assert_eq!(pcr.update_counter, 0);

    // 3. Registers must be reset to initial values
    #[cfg(feature = "sha1")]
    {
        assert_eq!(pcr.sha1[0], [0x00; 20]);
        assert_eq!(pcr.sha1[18], [0xFF; 20]);
    }
    #[cfg(feature = "sha256")]
    {
        assert_eq!(pcr.sha256[0], [0x00; 32]);
        assert_eq!(pcr.sha256[18], [0xFF; 32]);
    }
    #[cfg(feature = "sha384")]
    {
        assert_eq!(pcr.sha384[0], [0x00; 48]);
        assert_eq!(pcr.sha384[18], [0xFF; 48]);
    }
    #[cfg(feature = "sha512")]
    {
        assert_eq!(pcr.sha512[0], [0x00; 64]);
        assert_eq!(pcr.sha512[18], [0xFF; 64]);
    }
    #[cfg(feature = "sm3_256")]
    {
        assert_eq!(pcr.sm3_256[0], [0x00; 32]);
        assert_eq!(pcr.sm3_256[18], [0xFF; 32]);
    }
    #[cfg(feature = "sha3_256")]
    {
        assert_eq!(pcr.sha3_256[0], [0x00; 32]);
        assert_eq!(pcr.sha3_256[18], [0xFF; 32]);
    }
    #[cfg(feature = "sha3_384")]
    {
        assert_eq!(pcr.sha3_384[0], [0x00; 48]);
        assert_eq!(pcr.sha3_384[18], [0xFF; 48]);
    }
    #[cfg(feature = "sha3_512")]
    {
        assert_eq!(pcr.sha3_512[0], [0x00; 64]);
        assert_eq!(pcr.sha3_512[18], [0xFF; 64]);
    }
}
