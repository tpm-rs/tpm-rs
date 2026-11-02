//! Portable, backend-independent streaming SHAKE256 (FIPS 202) state.
//!
//! ML-DSA computes its message representative `mu` with SHAKE256 (FIPS 204, Algorithm 7 line 6),
//! over a message that a signing or verification sequence receives in parts. Like the SHA state
//! machine of [`crate::hash_state`], the state is explicit (the Keccak-f\[1600\] lanes and the
//! number of bytes absorbed into the current block), so that a running computation can be
//! exported as a fixed-size byte string ([`Shake256::to_bytes`]) and restored
//! ([`Shake256::from_bytes`]), e.g. by `TPM2_ContextSave`/`TPM2_ContextLoad`.

/// The SHAKE256 rate (block size) in bytes: `(1600 - 2 * 256) / 8`.
pub(crate) const SHAKE256_RATE: usize = 136;

/// The size of an exported state ([`Shake256::to_bytes`]): the 25 lanes (little-endian) and the
/// number of bytes absorbed into the current block (big-endian `u16`).
pub(crate) const SHAKE256_EXPORT_SIZE: usize = 25 * 8 + 2;

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// The rotation offsets of the rho step, in the order of the pi step's lane walk.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// The lane walk of the pi step (starting from lane 1).
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Keccak-f\[1600\] (FIPS 202, Section 3.3) on `lanes` (lane `(x, y)` at index `x + 5 * y`).
fn keccak_f1600(lanes: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        // theta
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                lanes[x + 5 * y] ^= d;
            }
        }
        // rho and pi
        let mut current = lanes[1];
        for (&target, &rotation) in PI.iter().zip(RHO.iter()) {
            let next = lanes[target];
            lanes[target] = current.rotate_left(rotation);
            current = next;
        }
        // chi
        for y in 0..5 {
            let row = [
                lanes[5 * y],
                lanes[5 * y + 1],
                lanes[5 * y + 2],
                lanes[5 * y + 3],
                lanes[5 * y + 4],
            ];
            for x in 0..5 {
                lanes[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        // iota
        lanes[0] ^= round_constant;
    }
}

/// A running SHAKE256 computation (absorbing phase).
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Shake256 {
    lanes: [u64; 25],
    /// The number of bytes absorbed into the current block (`< SHAKE256_RATE`).
    position: usize,
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256 {
    /// A new computation (nothing absorbed).
    pub(crate) const fn new() -> Self {
        Self {
            lanes: [0; 25],
            position: 0,
        }
    }

    /// XORs `byte` into the state at byte offset `index` (lanes are little-endian).
    fn xor_byte(&mut self, index: usize, byte: u8) {
        self.lanes[index / 8] ^= u64::from(byte) << (8 * (index % 8));
    }

    /// Absorbs `data`.
    pub(crate) fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.xor_byte(self.position, byte);
            self.position += 1;
            if self.position == SHAKE256_RATE {
                keccak_f1600(&mut self.lanes);
                self.position = 0;
            }
        }
    }

    /// Finishes the computation and squeezes `out.len()` bytes of output into `out`.
    pub(crate) fn finalize_into(mut self, out: &mut [u8]) {
        // The SHAKE domain separation and pad10*1 (FIPS 202, Sections 5.1 and 6.2).
        self.xor_byte(self.position, 0x1f);
        self.xor_byte(SHAKE256_RATE - 1, 0x80);
        for block in out.chunks_mut(SHAKE256_RATE) {
            keccak_f1600(&mut self.lanes);
            for (index, byte) in block.iter_mut().enumerate() {
                *byte = (self.lanes[index / 8] >> (8 * (index % 8))) as u8;
            }
        }
    }

    /// SHAKE256 of `data`, `out.len()` bytes long.
    pub(crate) fn digest(data: &[u8], out: &mut [u8]) {
        let mut shake = Self::new();
        shake.update(data);
        shake.finalize_into(out);
    }

    /// Exports the state (see [`SHAKE256_EXPORT_SIZE`]).
    pub(crate) fn to_bytes(&self) -> [u8; SHAKE256_EXPORT_SIZE] {
        let mut out = [0u8; SHAKE256_EXPORT_SIZE];
        for (i, lane) in self.lanes.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
        }
        out[25 * 8..].copy_from_slice(&(self.position as u16).to_be_bytes());
        out
    }

    /// Restores a state exported by [`Shake256::to_bytes`], or `None` if `bytes` is not a valid
    /// export (a block position outside the rate).
    pub(crate) fn from_bytes(bytes: &[u8; SHAKE256_EXPORT_SIZE]) -> Option<Self> {
        let position = usize::from(u16::from_be_bytes([bytes[200], bytes[201]]));
        if position >= SHAKE256_RATE {
            return None;
        }
        let mut lanes = [0u64; 25];
        for (i, lane) in lanes.iter_mut().enumerate() {
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            *lane = u64::from_le_bytes(le);
        }
        Some(Self { lanes, position })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// SHAKE256 of the empty string (FIPS 202 examples), 64 bytes.
    #[test]
    fn empty_message() {
        let mut out = [0u8; 64];
        Shake256::digest(&[], &mut out);
        assert_eq!(
            out,
            hex!(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            )
        );
    }

    /// SHAKE256("abc"), 32 bytes.
    #[test]
    fn abc() {
        let mut out = [0u8; 32];
        Shake256::digest(b"abc", &mut out);
        assert_eq!(
            out,
            hex!("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")
        );
    }

    /// Absorbing in parts, across block boundaries and through an export/import, and squeezing
    /// more than one block gives the same output as one-shot absorbing.
    #[test]
    fn streaming_and_export_match_one_shot() {
        let data: [u8; 700] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let mut expected = [0u8; 300];
        Shake256::digest(&data, &mut expected);

        let mut shake = Shake256::new();
        shake.update(&data[..1]);
        shake.update(&data[1..136]);
        shake.update(&data[136..300]);
        let exported = shake.to_bytes();
        let mut shake = Shake256::from_bytes(&exported).unwrap();
        shake.update(&data[300..]);
        let mut out = [0u8; 300];
        shake.finalize_into(&mut out);
        assert_eq!(out, expected);
    }

    /// An export with a block position outside the rate is rejected.
    #[test]
    fn invalid_export_rejected() {
        let mut bytes = Shake256::new().to_bytes();
        bytes[201] = SHAKE256_RATE as u8;
        assert!(Shake256::from_bytes(&bytes).is_none());
    }
}
