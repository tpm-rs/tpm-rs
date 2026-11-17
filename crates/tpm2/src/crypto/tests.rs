//! Unit tests for the dispatch functions, using a toy backend.

use super::{
    backend::{
        Cmac, Ecc, EccCurve, EdwardsCurve, Hash, HashState, Hmac, HmacState, Mldsa, MldsaKey,
        Mlkem, MlkemKey, MontgomeryCurve, PrivateKey, Rsa, RsaKey, Symmetric,
    },
    *,
};
use crate::{TpmiAlgHash, TpmtHa};

/// Deterministic xorshift64 RNG for tests.
struct TestRng(u64);

impl Rng for TestRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        for b in out.iter_mut() {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            *b = (x & 0xff) as u8;
        }
        Ok(())
    }

    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        for &b in data {
            self.0 = self.0.wrapping_mul(0x100_0000_01b3) ^ u64::from(b);
        }
        if self.0 == 0 {
            self.0 = 1;
        }
        Ok(())
    }
}

#[test]
fn test_crypto_error_display_and_error() {
    fn assert_error<T: core::error::Error>(_: &T) {}
    assert_error(&CryptoError::Unsupported);
    assert_error(&CryptoError::Internal);
    assert_eq!(
        format!("{}", CryptoError::Unsupported),
        "unsupported cryptographic algorithm, mode, or key size"
    );
    assert_eq!(
        format!("{}", CryptoError::Internal),
        "internal cryptographic error"
    );
}

/// Lightweight deterministic sponge hash for testing dispatch logic across
/// all digest sizes without external deps.
struct ToyHash<const N: usize> {
    state: [u8; N],
    pos: usize,
}

impl<const N: usize> HashState<N> for ToyHash<N> {
    fn init() -> Result<Self, CryptoError> {
        let mut state = [0u8; N];
        for (i, b) in state.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(0xa5);
        }
        Ok(Self { state, pos: 0 })
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        for &byte in data {
            let idx = self.pos % N;
            let prev = self.state[(idx + N - 1) % N];
            self.state[idx] = self.state[idx]
                .wrapping_add(byte ^ 0x5c)
                .rotate_left(3)
                .wrapping_add(prev);
            self.pos = self.pos.wrapping_add(1);
        }
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        let len_bytes = (self.pos as u64).to_be_bytes();
        self.update(&len_bytes)?;
        for round in 0..4u8 {
            self.update(&[round, 0xff ^ round])?;
        }
        out.copy_from_slice(&self.state);
        Ok(())
    }
}

struct ToyHmac<const N: usize>(ToyHash<N>);

impl<const N: usize> HmacState<N> for ToyHmac<N> {
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        let mut h = ToyHash::<N>::init()?;
        h.update(&(key.len() as u32).to_be_bytes())?;
        h.update(key)?;
        Ok(Self(h))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data)
    }

    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        self.0.finalize(out)
    }
}

#[derive(Clone)]
struct ToyRsa1024Pub {
    exponent: u32,
    modulus: [u8; 128],
}

/// Toy 1024-bit RSA key implementing an exact bijection on `[0, n)` via
/// modular addition `(x + secret) mod n` / `(y - secret) mod n`, with toy
/// padding for its own encryptions and signatures; its decryptions and its
/// RSASSA-PSS verification decode the standard encodings of RFC 8017, which
/// the dispatch functions produce ([`rsa_oaep_encode`],
/// [`rsa_pkcs1v15_encode`], [`rsa_pss_encode`]) before the raw operation.
struct ToyRsa1024 {
    public: ToyRsa1024Pub,
    prime_p: [u8; 64],
}

fn be_cmp<const N: usize>(a: &[u8; N], b: &[u8; N]) -> core::cmp::Ordering {
    a.cmp(b)
}

fn be_add_mod<const N: usize>(x: &[u8; N], delta: &[u8; N], m: &[u8; N]) -> [u8; N] {
    let mut sum = [0u8; N];
    let mut carry = 0u16;
    for i in (0..N).rev() {
        let v = u16::from(x[i]) + u16::from(delta[i]) + carry;
        sum[i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    if carry != 0 || be_cmp(&sum, m) != core::cmp::Ordering::Less {
        let mut borrow = 0i16;
        for i in (0..N).rev() {
            let v = i16::from(sum[i]) - i16::from(m[i]) - borrow;
            if v < 0 {
                sum[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                sum[i] = v as u8;
                borrow = 0;
            }
        }
    }
    sum
}

fn be_sub_mod<const N: usize>(y: &[u8; N], delta: &[u8; N], m: &[u8; N]) -> [u8; N] {
    let mut diff = [0u8; N];
    let mut borrow = 0i16;
    for i in (0..N).rev() {
        let v = i16::from(y[i]) - i16::from(delta[i]) - borrow;
        if v < 0 {
            diff[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            diff[i] = v as u8;
            borrow = 0;
        }
    }
    if borrow != 0 {
        let mut carry = 0u16;
        for i in (0..N).rev() {
            let v = u16::from(diff[i]) + u16::from(m[i]) + carry;
            diff[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
    }
    diff
}

impl ToyRsa1024 {
    fn secret_delta(pub_key: &ToyRsa1024Pub) -> [u8; 128] {
        let mut d = [0u8; 128];
        // Strictly `< modulus` because `modulus[0] & 0x80 != 0` and `d[0] = 0x13`.
        d[0] = 0x13;
        d[1..5].copy_from_slice(&pub_key.exponent.to_be_bytes());
        for i in 5..128 {
            d[i] = pub_key.modulus[i] ^ 0x3a;
        }
        d
    }

    fn expected_prime(modulus: &[u8; 128]) -> [u8; 64] {
        let mut p = [0u8; 64];
        p.copy_from_slice(&modulus[..64]);
        p[0] |= 0x80;
        p[63] |= 0x01;
        p
    }

    /// Toy public operation `(x + secret) mod n`, or `None` if `x >= n`.
    fn toy_public(public: &ToyRsa1024Pub, x: &[u8; 128]) -> Option<[u8; 128]> {
        if be_cmp(x, &public.modulus) != core::cmp::Ordering::Less {
            return None;
        }
        Some(be_add_mod(x, &Self::secret_delta(public), &public.modulus))
    }

    /// Toy private operation `(y - secret) mod n`, or `None` if `y >= n`.
    fn toy_private(public: &ToyRsa1024Pub, y: &[u8; 128]) -> Option<[u8; 128]> {
        if be_cmp(y, &public.modulus) != core::cmp::Ordering::Less {
            return None;
        }
        Some(be_sub_mod(y, &Self::secret_delta(public), &public.modulus))
    }

    /// Toy encryption padding header `0x00 || tag || len || label_tag`,
    /// followed by the (at most 117-byte) message (`tag` 2 for `RSAES`, 3
    /// for `OAEP`).
    fn toy_pad_header(tag: u8, label: &[u8]) -> Result<[u8; 11], CryptoError> {
        let mut header = [0u8; 11];
        header[1] = tag;
        if tag == 3 {
            let mut label_tag = [0u8; 32];
            ToyHash::<32>::hash(&[label], &mut label_tag)?;
            header[3..].copy_from_slice(&label_tag[..8]);
        }
        Ok(header)
    }

    fn toy_pad_encrypt(
        public: &ToyRsa1024Pub,
        mut header: [u8; 11],
        plaintext: &[u8],
        out: &mut [u8; 128],
    ) -> Result<Option<()>, CryptoError> {
        if plaintext.len() > 117 {
            return Ok(None);
        }
        header[2] = plaintext.len() as u8;
        let mut em = [0u8; 128];
        em[..11].copy_from_slice(&header);
        em[11..11 + plaintext.len()].copy_from_slice(plaintext);
        let Some(ct) = Self::toy_public(public, &em) else {
            return Ok(None);
        };
        *out = ct;
        Ok(Some(()))
    }

    /// Toy signature encoding `0x00 || 0x01 || tag || hash_alg || digest`
    /// (`tag` 1 for `RSASSA`, 2 for `RSAPSS`).
    fn toy_sig_encoding(tag: u8, digest: TpmtHa<'_>) -> [u8; 128] {
        let mut em = [0u8; 128];
        em[1] = 1;
        em[2] = tag;
        em[3..5].copy_from_slice(&(digest.hash_alg() as u16).to_be_bytes());
        em[5..5 + digest.digest().len()].copy_from_slice(digest.digest());
        em
    }

    fn toy_sign(
        &self,
        tag: u8,
        digest: TpmtHa<'_>,
        out: &mut [u8; 128],
    ) -> Result<(), CryptoError> {
        let em = Self::toy_sig_encoding(tag, digest);
        *out = Self::toy_private(&self.public, &em).ok_or(CryptoError::Internal)?;
        Ok(())
    }

    fn toy_verify(
        public: &ToyRsa1024Pub,
        tag: u8,
        digest: TpmtHa<'_>,
        sig: &[u8; 128],
    ) -> Result<bool, CryptoError> {
        let Some(em) = Self::toy_public(public, sig) else {
            return Ok(false);
        };
        Ok(em == Self::toy_sig_encoding(tag, digest))
    }
}

impl PrivateKey<128, 64, TestRng, u32> for ToyRsa1024 {
    type PublicKey = ToyRsa1024Pub;

    fn generate(rng: &mut TestRng, exponent: u32) -> Result<Self, CryptoError> {
        let mut modulus = [0u8; 128];
        rng.fill_bytes(&mut modulus)?;
        modulus[0] |= 0x80;
        modulus[127] |= 0x01;
        let prime_p = Self::expected_prime(&modulus);
        Ok(ToyRsa1024 {
            public: ToyRsa1024Pub { exponent, modulus },
            prime_p,
        })
    }

    fn load_public(
        exponent: u32,
        modulus: &[u8; 128],
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        if (modulus[0] & 0x80) == 0 || (modulus[127] & 1) == 0 {
            return Ok(None);
        }
        Ok(Some(ToyRsa1024Pub {
            exponent,
            modulus: *modulus,
        }))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; 128]) -> Result<(), CryptoError> {
        out.copy_from_slice(&public.modulus);
        Ok(())
    }

    fn load(public: Self::PublicKey, prime_p: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
        if *prime_p != Self::expected_prime(&public.modulus) {
            return Ok(None);
        }
        Ok(Some(ToyRsa1024 {
            public,
            prime_p: *prime_p,
        }))
    }

    fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.prime_p);
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl RsaKey<128, 64, TestRng> for ToyRsa1024 {
    fn exponent(public: &Self::PublicKey) -> u32 {
        public.exponent
    }

    fn raw_encrypt(
        public: &Self::PublicKey,
        m: &[u8; 128],
        out: &mut [u8; 128],
    ) -> Result<Option<()>, CryptoError> {
        let Some(ct) = Self::toy_public(public, m) else {
            return Ok(None);
        };
        *out = ct;
        Ok(Some(()))
    }

    fn raw_decrypt(
        &self,
        rng: &mut TestRng,
        c: &[u8; 128],
        out: &mut [u8; 128],
    ) -> Result<Option<()>, CryptoError> {
        let mut blind = [0u8; 4];
        rng.fill_bytes(&mut blind)?;
        let Some(m) = Self::toy_private(&self.public, c) else {
            return Ok(None);
        };
        *out = m;
        Ok(Some(()))
    }

    fn oaep_encrypt(
        public: &Self::PublicKey,
        _: &mut TestRng,
        _: TpmiAlgHash,
        label: &[u8],
        m: &[u8],
        out: &mut [u8; 128],
    ) -> Result<Option<()>, CryptoError> {
        Self::toy_pad_encrypt(public, Self::toy_pad_header(3, label)?, m, out)
    }

    fn oaep_decrypt(
        &self,
        rng: &mut TestRng,
        hash: TpmiAlgHash,
        label: &[u8],
        c: &[u8; 128],
        out: &mut [u8; 128],
    ) -> Result<Option<usize>, CryptoError> {
        let mut em = [0u8; 128];
        if self.raw_decrypt(rng, c, &mut em)?.is_none() {
            return Ok(None);
        }
        Ok(oaep_decode(hash, label, &em).map(|m| {
            out[..m.len()].copy_from_slice(&m);
            m.len()
        }))
    }

    fn rsaes_encrypt(
        public: &Self::PublicKey,
        _: &mut TestRng,
        m: &[u8],
        out: &mut [u8; 128],
    ) -> Result<Option<()>, CryptoError> {
        Self::toy_pad_encrypt(public, Self::toy_pad_header(2, &[])?, m, out)
    }

    fn rsaes_decrypt(
        &self,
        rng: &mut TestRng,
        c: &[u8; 128],
        out: &mut [u8; 128],
    ) -> Result<Option<usize>, CryptoError> {
        let mut em = [0u8; 128];
        if self.raw_decrypt(rng, c, &mut em)?.is_none() {
            return Ok(None);
        }
        Ok(pkcs1v15_decode(&em).map(|m| {
            out[..m.len()].copy_from_slice(m);
            m.len()
        }))
    }

    fn rsassa_sign(
        &self,
        _: &mut TestRng,
        digest: TpmtHa<'_>,
        out: &mut [u8; 128],
    ) -> Result<(), CryptoError> {
        self.toy_sign(1, digest, out)
    }

    fn rsassa_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; 128],
    ) -> Result<bool, CryptoError> {
        Self::toy_verify(public, 1, digest, sig)
    }

    fn rsapss_sign(
        &self,
        _: &mut TestRng,
        digest: TpmtHa<'_>,
        out: &mut [u8; 128],
    ) -> Result<(), CryptoError> {
        self.toy_sign(2, digest, out)
    }

    fn rsapss_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; 128],
    ) -> Result<bool, CryptoError> {
        Ok(Self::toy_public(public, sig)
            .is_some_and(|em| pss_verify(digest.hash_alg(), digest.digest(), &em)))
    }
}

/// `MGF1(seed, len)` with the toy hash `alg`.
fn toy_mgf1(alg: TpmiAlgHash, seed: &[u8], len: usize) -> std::vec::Vec<u8> {
    let mut out = std::vec::Vec::new();
    for counter in 0u32.. {
        if out.len() >= len {
            break;
        }
        let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let d = hash::<TestBackend>(alg, &[seed, &counter.to_be_bytes()], &mut buf).unwrap();
        out.extend_from_slice(d.digest());
    }
    out.truncate(len);
    out
}

/// EME-OAEP decoding (RFC 8017, 7.1.2 step 3) of `em` with the toy hash `alg`.
fn oaep_decode(alg: TpmiAlgHash, label: &[u8], em: &[u8]) -> Option<std::vec::Vec<u8>> {
    let h_len = alg.digest_size();
    let (y, rest) = em.split_first()?;
    let (masked_seed, masked_db) = rest.split_at(h_len);
    let seed: std::vec::Vec<u8> = masked_seed
        .iter()
        .zip(toy_mgf1(alg, masked_db, h_len))
        .map(|(a, b)| a ^ b)
        .collect();
    let db: std::vec::Vec<u8> = masked_db
        .iter()
        .zip(toy_mgf1(alg, &seed, masked_db.len()))
        .map(|(a, b)| a ^ b)
        .collect();
    let mut l_hash = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let l_hash = hash::<TestBackend>(alg, &[label], &mut l_hash).unwrap();
    let rest = &db[h_len..];
    let one = rest.iter().position(|&b| b != 0)?;
    (*y == 0 && db[..h_len] == *l_hash.digest() && rest[one] == 1).then(|| rest[one + 1..].to_vec())
}

/// RSAES-PKCS1-v1_5 decoding (RFC 8017, 7.2.2 step 3) of `em`.
fn pkcs1v15_decode(em: &[u8]) -> Option<&[u8]> {
    let zero = em[2..].iter().position(|&b| b == 0)? + 2;
    (em[..2] == [0, 2] && zero >= 10).then(|| &em[zero + 1..])
}

/// EMSA-PSS verification (RFC 8017, 9.1.2) of `em` (one leading bit cleared) for the message
/// digest `digest` with the toy hash `alg`, for any salt length.
fn pss_verify(alg: TpmiAlgHash, digest: &[u8], em: &[u8]) -> bool {
    let h_len = alg.digest_size();
    let m_len = em.len() - h_len - 1;
    let (masked_db, rest) = em.split_at(m_len);
    let (h, trailer) = rest.split_at(h_len);
    if trailer != [0xbc] || masked_db[0] & 0x80 != 0 {
        return false;
    }
    let mut db: std::vec::Vec<u8> = masked_db
        .iter()
        .zip(toy_mgf1(alg, h, m_len))
        .map(|(a, b)| a ^ b)
        .collect();
    db[0] &= 0x7f;
    let Some(one) = db.iter().position(|&b| b != 0) else {
        return false;
    };
    if db[one] != 1 {
        return false;
    }
    let salt = &db[one + 1..];
    let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected = hash::<TestBackend>(alg, &[&[0u8; 8], digest, salt], &mut buf).unwrap();
    expected.digest() == h
}

#[derive(Clone, PartialEq, Eq)]
struct ToyP256Pub {
    x: [u8; 32],
    y: [u8; 32],
}

/// Toy 256-bit Weierstrass curve (`y = x ^ 0x55`, non-zero `x < [0xff; 32]`).
struct ToyP256 {
    public: ToyP256Pub,
    scalar: [u8; 32],
}

impl ToyP256 {
    fn point_for_scalar(scalar: &[u8; 32]) -> Option<ToyP256Pub> {
        if scalar.iter().all(|&b| b == 0) || scalar.iter().all(|&b| b == 0xff) {
            return None;
        }
        let x = *scalar;
        let mut y = [0u8; 32];
        for i in 0..32 {
            y[i] = x[i] ^ 0x55;
        }
        Some(ToyP256Pub { x, y })
    }

    /// Toy signature `(r, s)` with `r` random and `s = H(tag || x || r ||
    /// digest)` (`tag` 1 for `ECDSA`, 2 for `SM2`).
    fn toy_sign(
        &self,
        rng: &mut TestRng,
        tag: u8,
        digest: &[u8],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        rng.fill_bytes(out_r)?;
        out_r[31] |= 1;
        ToyHash::<32>::hash(&[&[tag], &self.public.x, out_r, digest], out_s)?;
        out_s[31] |= 1;
        Ok(())
    }

    fn toy_verify(
        public: &ToyP256Pub,
        tag: u8,
        digest: &[u8],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        if sig_r.iter().all(|&b| b == 0) || sig_s.iter().all(|&b| b == 0) {
            return Ok(false);
        }
        let mut expected_s = [0u8; 32];
        ToyHash::<32>::hash(&[&[tag], &public.x, sig_r, digest], &mut expected_s)?;
        expected_s[31] |= 1;
        Ok(*sig_s == expected_s)
    }
}

impl PrivateKey<64, 32, TestRng> for ToyP256 {
    type PublicKey = ToyP256Pub;

    fn generate(rng: &mut TestRng, _: ()) -> Result<Self, CryptoError> {
        let mut scalar = [0u8; 32];
        rng.fill_bytes(&mut scalar)?;
        scalar[0] &= 0x7f;
        scalar[31] |= 0x01;
        let public = Self::point_for_scalar(&scalar).ok_or(CryptoError::Internal)?;
        Ok(ToyP256 { public, scalar })
    }

    fn load_public(_: (), point: &[u8; 64]) -> Result<Option<Self::PublicKey>, CryptoError> {
        let (x, y) = point.split_first_chunk::<32>().unwrap();
        let Some(expected) = Self::point_for_scalar(x) else {
            return Ok(None);
        };
        if expected.y != *y {
            return Ok(None);
        }
        Ok(Some(expected))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        out[..32].copy_from_slice(&public.x);
        out[32..].copy_from_slice(&public.y);
        Ok(())
    }

    fn load(public: Self::PublicKey, scalar: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
        if Self::point_for_scalar(scalar).as_ref() != Some(&public) {
            return Ok(None);
        }
        Ok(Some(ToyP256 {
            public,
            scalar: *scalar,
        }))
    }

    fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.scalar);
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl EccCurve<32, 64, TestRng> for ToyP256 {
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_x: &mut [u8; 32],
        out_y: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        // Equal X coordinates simulate `[d]([-d]G) = O` (infinity) when `x[31] == 0xfe`.
        if self.scalar == peer_public.x && peer_public.x[31] == 0xfe {
            return Ok(None);
        }
        for i in 0..32 {
            // Commutative toy shared point: `(d_a ^ d_b)` so `ecdh(a, B) == ecdh(b, A)`.
            out_x[i] = self.scalar[i] ^ peer_public.x[i] ^ 0x11;
            out_y[i] = out_x[i] ^ 0x55;
        }
        Ok(Some(()))
    }

    fn sign(
        &self,
        rng: &mut TestRng,
        digest: &[u8],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        self.toy_sign(rng, 1, digest, out_r, out_s)
    }

    fn verify(
        public: &Self::PublicKey,
        digest: &[u8],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        Self::toy_verify(public, 1, digest, sig_r, sig_s)
    }

    fn sm2_sign(
        &self,
        rng: &mut TestRng,
        e: &[u8],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        self.toy_sign(rng, 2, e, out_r, out_s)
    }

    fn sm2_verify(
        public: &Self::PublicKey,
        e: &[u8],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        Self::toy_verify(public, 2, e, sig_r, sig_s)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ToyEdwardsPub<const N: usize>([u8; N]);

/// Toy twisted Edwards curve (`Ed25519` for `N = 32`, `Ed448` for `N = 57`).
struct ToyEdwards<const N: usize> {
    public: ToyEdwardsPub<N>,
    secret: [u8; N],
}

impl<const N: usize> ToyEdwards<N> {
    fn derive_point(secret: &[u8; N]) -> [u8; N] {
        let mut pt = [0u8; N];
        for i in 0..N {
            pt[i] = secret[i] ^ 0xa3;
        }
        pt[0] |= 0x01;
        pt
    }
}

impl<const N: usize> PrivateKey<N, N, TestRng> for ToyEdwards<N> {
    type PublicKey = ToyEdwardsPub<N>;

    fn generate(rng: &mut TestRng, _: ()) -> Result<Self, CryptoError> {
        let mut secret = [0u8; N];
        rng.fill_bytes(&mut secret)?;
        secret[0] |= 0x01;
        Ok(ToyEdwards {
            public: ToyEdwardsPub(Self::derive_point(&secret)),
            secret,
        })
    }

    fn load_public(_: (), point: &[u8; N]) -> Result<Option<Self::PublicKey>, CryptoError> {
        if point.iter().all(|&b| b == 0) || point.iter().all(|&b| b == 0xff) {
            return Ok(None);
        }
        Ok(Some(ToyEdwardsPub(*point)))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.copy_from_slice(&public.0);
        Ok(())
    }

    fn load(public: Self::PublicKey, secret: &[u8; N]) -> Result<Option<Self>, CryptoError> {
        if secret.iter().all(|&b| b == 0) || Self::derive_point(secret) != public.0 {
            return Ok(None);
        }
        Ok(Some(ToyEdwards {
            public,
            secret: *secret,
        }))
    }

    fn store(&self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.secret);
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl<const N: usize> EdwardsCurve<N, TestRng> for ToyEdwards<N> {
    fn sign_message(
        &self,
        msg: &[&[u8]],
        out_r: &mut [u8; N],
        out_s: &mut [u8; N],
    ) -> Result<(), CryptoError> {
        let mut h_r = ToyHash::<N>::init()?;
        h_r.update(b"eddsa-msg-r")?;
        h_r.update(&self.public.0)?;
        for part in msg {
            h_r.update(part)?;
        }
        h_r.finalize(out_r)?;

        let mut h_s = ToyHash::<N>::init()?;
        h_s.update(b"eddsa-msg-s")?;
        h_s.update(&self.public.0)?;
        h_s.update(out_r)?;
        for part in msg {
            h_s.update(part)?;
        }
        h_s.finalize(out_s)?;
        Ok(())
    }

    fn sign_prehash(
        &self,
        prehash: &[u8; 64],
        out_r: &mut [u8; N],
        out_s: &mut [u8; N],
    ) -> Result<(), CryptoError> {
        ToyHash::<N>::hash(&[b"eddsa-ph-r", &self.public.0, prehash], out_r)?;
        ToyHash::<N>::hash(&[b"eddsa-ph-s", &self.public.0, out_r, prehash], out_s)?;
        Ok(())
    }

    fn verify_message(
        public: &Self::PublicKey,
        msg: &[&[u8]],
        sig_r: &[u8; N],
        sig_s: &[u8; N],
    ) -> Result<bool, CryptoError> {
        let mut h_s = ToyHash::<N>::init()?;
        h_s.update(b"eddsa-msg-s")?;
        h_s.update(&public.0)?;
        h_s.update(sig_r)?;
        for part in msg {
            h_s.update(part)?;
        }
        let mut expected_s = [0u8; N];
        h_s.finalize(&mut expected_s)?;
        Ok(*sig_s == expected_s)
    }

    fn verify_prehash(
        public: &Self::PublicKey,
        prehash: &[u8; 64],
        sig_r: &[u8; N],
        sig_s: &[u8; N],
    ) -> Result<bool, CryptoError> {
        let mut expected_s = [0u8; N];
        ToyHash::<N>::hash(&[b"eddsa-ph-s", &public.0, sig_r, prehash], &mut expected_s)?;
        Ok(*sig_s == expected_s)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ToyMontgomeryPub<const N: usize>([u8; N]);

/// Toy Montgomery curve (`X25519` for `N = 32`).
struct ToyMontgomery<const N: usize> {
    public: ToyMontgomeryPub<N>,
    scalar: [u8; N],
}

impl<const N: usize> ToyMontgomery<N> {
    fn derive_u(scalar: &[u8; N]) -> [u8; N] {
        let mut u = [0u8; N];
        for i in 0..N {
            u[i] = scalar[i] ^ 0x3c;
        }
        u
    }
}

impl<const N: usize> PrivateKey<N, N, TestRng> for ToyMontgomery<N> {
    type PublicKey = ToyMontgomeryPub<N>;

    fn generate(rng: &mut TestRng, _: ()) -> Result<Self, CryptoError> {
        let mut scalar = [0u8; N];
        rng.fill_bytes(&mut scalar)?;
        scalar[0] |= 0x01;
        Ok(ToyMontgomery {
            public: ToyMontgomeryPub(Self::derive_u(&scalar)),
            scalar,
        })
    }

    fn load_public(_: (), u: &[u8; N]) -> Result<Option<Self::PublicKey>, CryptoError> {
        if u.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        Ok(Some(ToyMontgomeryPub(*u)))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.copy_from_slice(&public.0);
        Ok(())
    }

    fn load(public: Self::PublicKey, scalar: &[u8; N]) -> Result<Option<Self>, CryptoError> {
        if scalar.iter().all(|&b| b == 0) || Self::derive_u(scalar) != public.0 {
            return Ok(None);
        }
        Ok(Some(ToyMontgomery {
            public,
            scalar: *scalar,
        }))
    }

    fn store(&self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.scalar);
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl<const N: usize> MontgomeryCurve<N, TestRng> for ToyMontgomery<N> {
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_u: &mut [u8; N],
    ) -> Result<Option<()>, CryptoError> {
        if peer_public.0.iter().all(|&b| b == 0xfe) {
            return Ok(None);
        }
        for i in 0..N {
            out_u[i] = self.scalar[i] ^ (peer_public.0[i] ^ 0x3c) ^ 0x77;
        }
        Ok(Some(()))
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ToyMldsa44Pub([u8; 32]);

/// Toy ML-DSA-44 (`PUB_SIZE = 1312`, `SIG_SIZE = 2420`).
struct ToyMldsa44 {
    public: ToyMldsa44Pub,
    seed: [u8; 32],
}

impl ToyMldsa44 {
    fn expand_public_bytes(tag: &[u8; 32], out: &mut [u8; 1312]) {
        out[..32].copy_from_slice(tag);
        for (i, b) in out[32..].iter_mut().enumerate() {
            *b = tag[i % 32].wrapping_add(i as u8);
        }
    }

    fn public_for_seed(seed: &[u8; 32]) -> Result<ToyMldsa44Pub, CryptoError> {
        let mut tag = [0u8; 32];
        ToyHash::<32>::hash(&[b"mldsa44-pk", seed], &mut tag)?;
        if tag[0] == 0xff && tag[1] == 0xff {
            tag[0] = 0xfe;
        }
        Ok(ToyMldsa44Pub(tag))
    }
}

impl PrivateKey<1312, 32, TestRng> for ToyMldsa44 {
    type PublicKey = ToyMldsa44Pub;

    fn generate(rng: &mut TestRng, _: ()) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed)?;
        seed[0] |= 1;
        Ok(ToyMldsa44 {
            public: Self::public_for_seed(&seed)?,
            seed,
        })
    }

    fn load_public(_: (), public: &[u8; 1312]) -> Result<Option<Self::PublicKey>, CryptoError> {
        if public[0] == 0xff && public[1] == 0xff {
            return Ok(None);
        }
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&public[..32]);
        let mut expected = [0u8; 1312];
        Self::expand_public_bytes(&tag, &mut expected);
        if *public != expected {
            return Ok(None);
        }
        Ok(Some(ToyMldsa44Pub(tag)))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; 1312]) -> Result<(), CryptoError> {
        Self::expand_public_bytes(&public.0, out);
        Ok(())
    }

    fn load(public: Self::PublicKey, seed: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
        if seed.iter().all(|&b| b == 0) || Self::public_for_seed(seed)? != public {
            return Ok(None);
        }
        Ok(Some(ToyMldsa44 {
            public,
            seed: *seed,
        }))
    }

    fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.seed);
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl MldsaKey<1312, 2420, TestRng> for ToyMldsa44 {
    fn sign_message(
        &self,
        rng: &mut TestRng,
        context: &[u8],
        msg: &[&[u8]],
        out_sig: &mut [u8; 2420],
    ) -> Result<(), CryptoError> {
        let mut rnd = [0u8; 4];
        rng.fill_bytes(&mut rnd)?;
        let ctx_len = u8::try_from(context.len()).map_err(|_| CryptoError::Internal)?;
        let mut h = ToyHash::<32>::init()?;
        h.update(b"mldsa44-msg")?;
        h.update(&self.public.0)?;
        h.update(&[ctx_len])?;
        h.update(context)?;
        for part in msg {
            h.update(part)?;
        }
        let mut tag = [0u8; 32];
        h.finalize(&mut tag)?;
        for (i, b) in out_sig.iter_mut().enumerate() {
            *b = tag[i % 32] ^ (i as u8);
        }
        Ok(())
    }

    fn verify_message(
        public: &Self::PublicKey,
        context: &[u8],
        msg: &[&[u8]],
        sig: &[u8; 2420],
    ) -> Result<bool, CryptoError> {
        let Ok(ctx_len) = u8::try_from(context.len()) else {
            return Ok(false);
        };
        let mut h = ToyHash::<32>::init()?;
        h.update(b"mldsa44-msg")?;
        h.update(&public.0)?;
        h.update(&[ctx_len])?;
        h.update(context)?;
        for part in msg {
            h.update(part)?;
        }
        let mut tag = [0u8; 32];
        h.finalize(&mut tag)?;
        Ok(sig
            .iter()
            .enumerate()
            .all(|(i, &b)| b == (tag[i % 32] ^ (i as u8))))
    }

    fn sign_mu(
        &self,
        rng: &mut TestRng,
        mu: &[u8; 64],
        out_sig: &mut [u8; 2420],
    ) -> Result<(), CryptoError> {
        let mut rnd = [0u8; 4];
        rng.fill_bytes(&mut rnd)?;
        let mut tag = [0u8; 32];
        ToyHash::<32>::hash(&[b"mldsa44-mu", &self.public.0, mu], &mut tag)?;
        for (i, b) in out_sig.iter_mut().enumerate() {
            *b = tag[i % 32] ^ (i as u8);
        }
        Ok(())
    }

    fn verify_mu(
        public: &Self::PublicKey,
        mu: &[u8; 64],
        sig: &[u8; 2420],
    ) -> Result<bool, CryptoError> {
        let mut tag = [0u8; 32];
        ToyHash::<32>::hash(&[b"mldsa44-mu", &public.0, mu], &mut tag)?;
        Ok(sig
            .iter()
            .enumerate()
            .all(|(i, &b)| b == (tag[i % 32] ^ (i as u8))))
    }

    fn sign_prehash(
        &self,
        rng: &mut TestRng,
        context: &[u8],
        digest: TpmtHa<'_>,
        out_sig: &mut [u8; 2420],
    ) -> Result<(), CryptoError> {
        let mut rnd = [0u8; 4];
        rng.fill_bytes(&mut rnd)?;
        let ctx_len = u8::try_from(context.len()).map_err(|_| CryptoError::Internal)?;
        let alg_bytes = (digest.hash_alg() as u16).to_be_bytes();
        let mut tag = [0u8; 32];
        ToyHash::<32>::hash(
            &[
                b"mldsa44-ph",
                &alg_bytes,
                &self.public.0,
                &[ctx_len],
                context,
                digest.digest(),
            ],
            &mut tag,
        )?;
        for (i, b) in out_sig.iter_mut().enumerate() {
            *b = tag[i % 32] ^ (i as u8);
        }
        Ok(())
    }

    fn verify_prehash(
        public: &Self::PublicKey,
        context: &[u8],
        digest: TpmtHa<'_>,
        sig: &[u8; 2420],
    ) -> Result<bool, CryptoError> {
        let Ok(ctx_len) = u8::try_from(context.len()) else {
            return Ok(false);
        };
        let alg_bytes = (digest.hash_alg() as u16).to_be_bytes();
        let mut tag = [0u8; 32];
        ToyHash::<32>::hash(
            &[
                b"mldsa44-ph",
                &alg_bytes,
                &public.0,
                &[ctx_len],
                context,
                digest.digest(),
            ],
            &mut tag,
        )?;
        Ok(sig
            .iter()
            .enumerate()
            .all(|(i, &b)| b == (tag[i % 32] ^ (i as u8))))
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ToyMlkem768Pub([u8; 32]);

/// Toy ML-KEM-768 (`PUB_SIZE = 1184`, `CT_SIZE = 1088`).
struct ToyMlkem768 {
    public: ToyMlkem768Pub,
    seed: [u8; 64],
}

impl ToyMlkem768 {
    fn expand_public_bytes(tag: &[u8; 32], out: &mut [u8; 1184]) {
        out[..32].copy_from_slice(tag);
        for (i, b) in out[32..].iter_mut().enumerate() {
            *b = tag[i % 32].wrapping_add((i as u8).wrapping_mul(3));
        }
    }

    fn public_for_seed(seed: &[u8; 64]) -> Result<ToyMlkem768Pub, CryptoError> {
        let mut tag = [0u8; 32];
        ToyHash::<32>::hash(&[b"mlkem768-ek", seed], &mut tag)?;
        if tag[0] == 0xff && tag[1] == 0xff {
            tag[0] = 0xfe;
        }
        Ok(ToyMlkem768Pub(tag))
    }
}

impl PrivateKey<1184, 64, TestRng> for ToyMlkem768 {
    type PublicKey = ToyMlkem768Pub;

    fn generate(rng: &mut TestRng, _: ()) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed)?;
        seed[0] |= 1;
        Ok(ToyMlkem768 {
            public: Self::public_for_seed(&seed)?,
            seed,
        })
    }

    fn load_public(_: (), public: &[u8; 1184]) -> Result<Option<Self::PublicKey>, CryptoError> {
        if public[0] == 0xff && public[1] == 0xff {
            return Ok(None);
        }
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&public[..32]);
        let mut expected = [0u8; 1184];
        Self::expand_public_bytes(&tag, &mut expected);
        if *public != expected {
            return Ok(None);
        }
        Ok(Some(ToyMlkem768Pub(tag)))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; 1184]) -> Result<(), CryptoError> {
        Self::expand_public_bytes(&public.0, out);
        Ok(())
    }

    fn load(public: Self::PublicKey, seed: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
        if seed.iter().all(|&b| b == 0) || Self::public_for_seed(seed)? != public {
            return Ok(None);
        }
        Ok(Some(ToyMlkem768 {
            public,
            seed: *seed,
        }))
    }

    fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.seed);
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl MlkemKey<1184, 1088, TestRng> for ToyMlkem768 {
    fn encapsulate(
        public: &Self::PublicKey,
        rng: &mut TestRng,
        out_ct: &mut [u8; 1088],
        out_ss: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m)?;
        for (i, b) in out_ct.iter_mut().enumerate() {
            *b = if i < 32 {
                m[i] ^ public.0[i]
            } else {
                public.0[i % 32] ^ (i as u8)
            };
        }
        ToyHash::<32>::hash(&[b"mlkem768-ss", &public.0, &m], out_ss)?;
        Ok(())
    }

    fn decapsulate(&self, ct: &[u8; 1088], out_ss: &mut [u8; 32]) -> Result<(), CryptoError> {
        let mut m = [0u8; 32];
        for i in 0..32 {
            m[i] = ct[i] ^ self.public.0[i];
        }
        ToyHash::<32>::hash(&[b"mlkem768-ss", &self.public.0, &m], out_ss)?;
        Ok(())
    }
}

struct TestBackend;

impl Hash for TestBackend {
    type Sha1 = ToyHash<20>;
    type Sha256 = ToyHash<32>;
    type Sha384 = ToyHash<48>;
    type Sha512 = ToyHash<64>;
    type Sm3_256 = ToyHash<32>;
    type Sha3_256 = ToyHash<32>;
    type Sha3_384 = ToyHash<48>;
    type Sha3_512 = ToyHash<64>;
}

impl Hmac for TestBackend {
    type Sha1 = ToyHmac<20>;
    type Sha256 = ToyHmac<32>;
    type Sha384 = ToyHmac<48>;
    type Sha512 = ToyHmac<64>;
    type Sm3_256 = ToyHmac<32>;
    type Sha3_256 = ToyHmac<32>;
    type Sha3_384 = ToyHmac<48>;
    type Sha3_512 = ToyHmac<64>;
}

impl Cmac for TestBackend {
    type Aes128 = !;
    type Aes192 = !;
    type Aes256 = !;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}

impl Symmetric for TestBackend {
    type Aes128 = !;
    type Aes192 = !;
    type Aes256 = !;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}

impl Rsa for TestBackend {
    type Rsa1024 = ToyRsa1024;
    type Rsa2048 = !;
    type Rsa3072 = !;
    type Rsa4096 = !;
}

impl Ecc for TestBackend {
    type NistP192 = !;
    type NistP224 = !;
    type NistP256 = ToyP256;
    type NistP384 = !;
    type NistP521 = !;
    type BNP256 = !;
    type BNP638 = !;
    type SM2P256 = !;
    type BpP256R1 = !;
    type BpP384R1 = !;
    type BpP512R1 = !;
    type Ed25519 = ToyEdwards<32>;
    type Ed448 = ToyEdwards<57>;
    type X25519 = ToyMontgomery<32>;
    type X448 = !;
}

impl Mldsa for TestBackend {
    type Mldsa44 = ToyMldsa44;
    type Mldsa65 = !;
    type Mldsa87 = !;
}

impl Mlkem for TestBackend {
    type Mlkem512 = !;
    type Mlkem768 = ToyMlkem768;
    type Mlkem1024 = !;
}

impl Random for TestBackend {
    type Rng = TestRng;

    fn from_entropy() -> Result<TestRng, CryptoError> {
        Self::from_seed(b"entropy")
    }

    fn from_seed(seed: &[u8]) -> Result<TestRng, CryptoError> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for &b in seed {
            state = state.rotate_left(7) ^ u64::from(b);
        }
        if state == 0 {
            state = 1;
        }
        Ok(TestRng(state))
    }
}

impl Crypto for TestBackend {
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        // Not constant time, which is fine for tests.
        a == b
    }
}

fn first_enabled_hash() -> TpmiAlgHash {
    // At least one hash algorithm is always enabled; prefer SHA-256.
    [
        #[cfg(feature = "sha256")]
        TpmiAlgHash::Sha256,
        #[cfg(feature = "sha1")]
        TpmiAlgHash::Sha1,
        #[cfg(feature = "sha384")]
        TpmiAlgHash::Sha384,
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512,
        #[cfg(feature = "sm3_256")]
        TpmiAlgHash::Sm3_256,
        #[cfg(feature = "sha3_256")]
        TpmiAlgHash::Sha3_256,
        #[cfg(feature = "sha3_384")]
        TpmiAlgHash::Sha3_384,
        #[cfg(feature = "sha3_512")]
        TpmiAlgHash::Sha3_512,
    ][0]
}

/// `HMAC` is not a [`RsaPrivateKey::sign`] / [`RsaPublicKey::verify`] scheme (use [`hmac`] instead).
#[cfg(feature = "rsa1024")]
#[test]
fn hmac_sign_and_verify_unsupported() {
    use crate::{TpmiRsaKeyBits, TpmtSigScheme, TpmtSignature};

    let alg = first_enabled_hash();
    let mut rng = TestBackend::from_seed(b"hmac-test").unwrap();
    let priv_key =
        RsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiRsaKeyBits::Rsa1024, 0).unwrap();
    let mut mod_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let modulus = priv_key.modulus(&mut mod_buf).unwrap();
    let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
        .unwrap()
        .unwrap();
    let digest = &[0x42u8; 64][..alg.digest_size()];

    let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
    assert_eq!(
        priv_key.sign(&mut rng, TpmtSigScheme::Hmac(alg), digest, &mut sig_buf),
        Err(CryptoError::Unsupported)
    );

    let mut tag_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let tag = hmac::<TestBackend>(alg, b"key", &[digest], &mut tag_buf).unwrap();
    assert_eq!(
        pub_key.verify(digest, TpmtSignature::Hmac(tag)),
        Err(CryptoError::Unsupported)
    );
}

#[test]
fn hmac_dispatch() {
    let alg = first_enabled_hash();
    let mut buf1 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let mut buf2 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let tag = hmac::<TestBackend>(alg, b"key", &[b"hello ", b"hmac"], &mut buf1).unwrap();
    assert_eq!(tag.hash_alg(), alg);
    assert_eq!(tag.digest().len(), alg.digest_size());
    let same = hmac::<TestBackend>(alg, b"key", &[b"hello hmac"], &mut buf2).unwrap();
    assert_eq!(tag, same);
    let mut buf3 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let other = hmac::<TestBackend>(alg, b"other", &[b"hello hmac"], &mut buf3).unwrap();
    assert_ne!(tag, other);
}

#[cfg(feature = "rsa1024")]
#[test]
fn rsa_key_roundtrip_and_encrypt_schemes() {
    use core::ffi::CStr;

    use crate::{Tpm2bPrivateKeyRsa, TpmiRsaKeyBits};

    let alg = first_enabled_hash();
    let mut rng = TestBackend::from_seed(b"rsa-seed").unwrap();

    // Exponent 0 normalizes to 65537; invalid exponents fail gracefully.
    let priv_key =
        RsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiRsaKeyBits::Rsa1024, 0).unwrap();
    assert_eq!(priv_key.bits(), TpmiRsaKeyBits::Rsa1024);
    assert_eq!(priv_key.exponent(), 65537);
    assert_eq!(
        RsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiRsaKeyBits::Rsa1024, 2).err(),
        Some(CryptoError::Unsupported)
    );

    let mut mod_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let mut p_buf: RsaPrimeBuffer = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let modulus = priv_key.modulus(&mut mod_buf).unwrap();
    let prime_p = priv_key.prime_p(&mut p_buf).unwrap();

    assert!(
        RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 4, modulus)
            .unwrap()
            .is_none()
    );
    let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
        .unwrap()
        .unwrap();
    assert_eq!(pub_key.exponent(), 65537);

    // Wrong prime_p is rejected with Ok(None) (TPM_RC_BINDING), not failure mode.
    let bad_p = Tpm2bPrivateKeyRsa::new(&[0xffu8; 64]).unwrap();
    assert!(
        RsaPrivateKey::<TestBackend>::load(pub_key, bad_p)
            .unwrap()
            .is_none()
    );

    let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
        .unwrap()
        .unwrap();
    let reloaded_priv = RsaPrivateKey::<TestBackend>::load(pub_key, prime_p)
        .unwrap()
        .unwrap();
    let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
        .unwrap()
        .unwrap();

    // 1. Raw (`TPM_ALG_NULL`): short input + extra leading zero bytes.
    let mut ct_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let mut pt_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let mut raw_in = [0u8; 132];
    raw_in[130] = 0xca;
    raw_in[131] = 0xfe;
    let ct = pub_key
        .encrypt(&mut rng, RsaEncryptScheme::Raw, &raw_in, &mut ct_buf)
        .unwrap()
        .unwrap();
    let pt = reloaded_priv
        .decrypt(&mut rng, RsaEncryptScheme::Raw, ct.as_slice(), &mut pt_buf)
        .unwrap()
        .unwrap();
    assert_eq!(pt.as_slice().len(), 128);
    assert_eq!(&pt.as_slice()[126..], &[0xca, 0xfe]);

    // Value >= modulus returns Ok(None).
    assert!(
        pub_key
            .encrypt(&mut rng, RsaEncryptScheme::Raw, &[0xff; 128], &mut ct_buf)
            .unwrap()
            .is_none()
    );

    // 2. RSAES-PKCS1-v1_5 (`TPM_ALG_RSAES`), or Unsupported if disabled.
    #[cfg(feature = "rsaes")]
    {
        let msg = b"hello pkcs1v1.5";
        let ct = pub_key
            .encrypt(&mut rng, RsaEncryptScheme::Rsaes, msg, &mut ct_buf)
            .unwrap()
            .unwrap();
        let pt = reloaded_priv
            .decrypt(
                &mut rng,
                RsaEncryptScheme::Rsaes,
                ct.as_slice(),
                &mut pt_buf,
            )
            .unwrap()
            .unwrap();
        assert_eq!(pt.as_slice(), msg);

        // Overlong RSAES message (> 128 - 11 = 117) returns Ok(None).
        assert!(
            pub_key
                .encrypt(&mut rng, RsaEncryptScheme::Rsaes, &[0x11; 118], &mut ct_buf)
                .unwrap()
                .is_none()
        );
    }
    #[cfg(not(feature = "rsaes"))]
    {
        assert_eq!(
            pub_key.encrypt(&mut rng, RsaEncryptScheme::Rsaes, b"msg", &mut ct_buf),
            Err(CryptoError::Unsupported)
        );
        assert_eq!(
            reloaded_priv.decrypt(&mut rng, RsaEncryptScheme::Rsaes, &[0u8; 128], &mut pt_buf),
            Err(CryptoError::Unsupported)
        );
    }

    // 3. RSAES-OAEP (`TPM_ALG_OAEP`) with non-UTF-8 label (if hash fits in 128B OAEP: 2*hLen + 2 <= 128, i.e. hLen <= 63).
    if alg.digest_size() <= 48 {
        let label = CStr::from_bytes_with_nul(&[0xff, 0x80, b'D', b'U', b'P', 0x00]).unwrap();
        let scheme = RsaEncryptScheme::Oaep {
            hash: alg,
            label: Some(label),
        };
        assert_eq!(scheme.label_bytes(), label.to_bytes_with_nul());
        let ct = pub_key
            .encrypt(&mut rng, scheme, b"oaep secret", &mut ct_buf)
            .unwrap()
            .unwrap();
        let pt = reloaded_priv
            .decrypt(&mut rng, scheme, ct.as_slice(), &mut pt_buf)
            .unwrap()
            .unwrap();
        assert_eq!(pt.as_slice(), b"oaep secret");

        // Mismatched OAEP label rejects cleanly with Ok(None).
        for label in [Some(c"WRONG"), Some(c""), None] {
            let wrong_label = RsaEncryptScheme::Oaep { hash: alg, label };
            assert!(
                reloaded_priv
                    .decrypt(&mut rng, wrong_label, ct.as_slice(), &mut pt_buf)
                    .unwrap()
                    .is_none()
            );
        }
    }

    // Unsupported RSA key size (`Rsa2048 = !` on TestBackend) returns CryptoError::Unsupported.
    #[cfg(feature = "rsa2048")]
    {
        let dummy_mod = crate::Tpm2bPublicKeyRsa::new(&[0x81; 128]).unwrap();
        assert_eq!(
            RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa2048, 0, dummy_mod).err(),
            Some(CryptoError::Unsupported)
        );
    }
}

#[cfg(all(feature = "rsa1024", any(feature = "rsassa", feature = "rsapss")))]
#[test]
fn rsa_sign_and_verify_rsassa_and_rsapss() {
    use crate::{TpmiRsaKeyBits, TpmtSigScheme};

    let alg = first_enabled_hash();
    let mut rng = TestBackend::from_seed(b"rsa-sig").unwrap();
    let priv_key =
        RsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiRsaKeyBits::Rsa1024, 0).unwrap();
    let mut mod_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let modulus = priv_key.modulus(&mut mod_buf).unwrap();
    let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
        .unwrap()
        .unwrap();

    let digest = &[0x5au8; 64][..alg.digest_size()];
    let mut check = |scheme| {
        let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        let sig = priv_key
            .sign(&mut rng, scheme, digest, &mut sig_buf)
            .unwrap();
        assert!(pub_key.verify(digest, sig).unwrap());

        let mut bad_digest = [0x5au8; 64];
        bad_digest[0] ^= 0x01;
        assert!(
            !pub_key
                .verify(&bad_digest[..alg.digest_size()], sig)
                .unwrap()
        );
    };
    #[cfg(feature = "rsassa")]
    check(TpmtSigScheme::Rsassa(alg));
    #[cfg(feature = "rsapss")]
    check(TpmtSigScheme::Rsapss(alg));
}

#[cfg(feature = "nist_p256")]
#[test]
fn ecc_padding_and_ecdh() {
    use crate::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint};

    let mut rng = TestBackend::from_seed(b"ecc-seed").unwrap();

    let alice =
        EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();
    let bob =
        EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();
    assert_eq!(alice.curve(), TpmEccCurve::NistP256);
    assert_eq!(alice.key_bytes(), 32);

    let (mut ax, mut ay) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let (mut bx, mut by) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let alice_pt = alice.point(&mut ax, &mut ay).unwrap();
    let bob_pt = bob.point(&mut bx, &mut by).unwrap();
    let alice_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, alice_pt)
        .unwrap()
        .unwrap();
    let bob_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, bob_pt)
        .unwrap()
        .unwrap();

    // ECDH symmetry: `[d_a]Q_b == [d_b]Q_a`.
    let (mut zx1, mut zy1) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let (mut zx2, mut zy2) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let z1 = alice.ecdh(&bob_pub, &mut zx1, &mut zy1).unwrap().unwrap();
    let z2 = bob.ecdh(&alice_pub, &mut zx2, &mut zy2).unwrap().unwrap();
    assert_eq!(z1, z2);

    // Short unpadded big-endian scalar & coordinates normalize cleanly.
    let short_scalar = Tpm2bEccParameter::new(&[0x07]).unwrap();
    let mut short_y = [0x55u8; 32];
    short_y[31] = 0x07 ^ 0x55;
    let unpadded_pt = TpmsEccPoint {
        x: short_scalar,
        y: Tpm2bEccParameter::new(&short_y).unwrap(),
    };
    let short_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, unpadded_pt)
        .unwrap()
        .unwrap();
    let (mut sx, mut sy) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let short_pt = short_pub.point(&mut sx, &mut sy).unwrap();
    assert_eq!(short_pt.x.as_slice().len(), 32);
    assert_eq!(short_pt.x.as_slice()[31], 0x07);
    assert_eq!(short_pt.y.as_slice(), &short_y);

    // `load` validates `[d]G == public`.
    let wrong_d = Tpm2bEccParameter::new(&[0x09]).unwrap();
    assert!(
        EccPrivateKey::<TestBackend>::load(short_pub, wrong_d)
            .unwrap()
            .is_none()
    );
    let short_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, unpadded_pt)
        .unwrap()
        .unwrap();
    let short_priv = EccPrivateKey::<TestBackend>::load(short_pub, short_scalar)
        .unwrap()
        .unwrap();
    let mut d_buf = [0u8; MAX_ECC_COORD_BYTES];
    assert_eq!(short_priv.scalar(&mut d_buf).unwrap().as_slice().len(), 32);
    assert_eq!(short_priv.scalar(&mut d_buf).unwrap().as_slice()[31], 0x07);

    // Empty or oversized coordinates return Ok(None).
    let empty_pt = TpmsEccPoint {
        x: Tpm2bEccParameter::new(&[]).unwrap(),
        y: unpadded_pt.y,
    };
    assert!(
        EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, empty_pt)
            .unwrap()
            .is_none()
    );
    // Only representable if a curve larger than P-256 is enabled.
    if let Some(x) = Tpm2bEccParameter::new(&[0x01; 33]) {
        let long_pt = TpmsEccPoint {
            x,
            y: unpadded_pt.y,
        };
        assert!(
            EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, long_pt)
                .unwrap()
                .is_none()
        );
    }

    // EdDSA scheme on Weierstrass curve and `!`-bound curves return Unsupported.
    #[cfg(feature = "eddsa")]
    assert_eq!(
        EccPublicKey::<TestBackend>::load(
            TpmEccCurve::NistP256,
            Some(crate::TpmtEccScheme::Eddsa),
            unpadded_pt
        )
        .err(),
        Some(CryptoError::Unsupported)
    );
    #[cfg(feature = "nist_p384")]
    assert_eq!(
        EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP384, None, unpadded_pt).err(),
        Some(CryptoError::Unsupported)
    );
}

#[cfg(all(feature = "nist_p256", any(feature = "ecdsa", feature = "sm2")))]
#[test]
fn ecc_signing() {
    use crate::{TpmEccCurve, TpmtSigScheme};

    let alg = first_enabled_hash();
    let mut rng = TestBackend::from_seed(b"ecc-sig").unwrap();
    let alice =
        EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();
    let (mut ax, mut ay) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let alice_pub = EccPublicKey::<TestBackend>::load(
        TpmEccCurve::NistP256,
        None,
        alice.point(&mut ax, &mut ay).unwrap(),
    )
    .unwrap()
    .unwrap();
    let digest = &[0x33u8; 64][..alg.digest_size()];

    // ECDSA and SM2 sign & verify (including short `(r, s)` padding on verify).
    let mut check = |scheme| {
        let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        let sig = alice.sign(&mut rng, scheme, digest, &mut sig_buf).unwrap();
        assert!(alice_pub.verify(digest, sig).unwrap());
    };
    #[cfg(feature = "ecdsa")]
    check(TpmtSigScheme::Ecdsa(alg));
    #[cfg(feature = "sm2")]
    check(TpmtSigScheme::Sm2(alg));
}

/// `ECSchnorr` is not yet supported by [`EccPrivateKey::sign`] / [`EccPublicKey::verify`].
#[cfg(all(feature = "nist_p256", feature = "ecschnorr"))]
#[test]
fn ecschnorr_sign_and_verify_unsupported() {
    use crate::{Tpm2bEccParameter, TpmEccCurve, TpmsSignatureEcc, TpmtSigScheme, TpmtSignature};

    let alg = first_enabled_hash();
    let mut rng = TestBackend::from_seed(b"ecschnorr").unwrap();
    let key =
        EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let point = key.point(&mut x, &mut y).unwrap();
    let pub_key = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, point)
        .unwrap()
        .unwrap();
    let digest = &[0x33u8; 64][..alg.digest_size()];

    let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
    assert_eq!(
        key.sign(
            &mut rng,
            TpmtSigScheme::Ecschnorr(alg),
            digest,
            &mut sig_buf
        ),
        Err(CryptoError::Unsupported)
    );
    let sig = TpmtSignature::Ecschnorr(TpmsSignatureEcc {
        hash: alg,
        signature_r: Tpm2bEccParameter::new(&[1; 32]).unwrap(),
        signature_s: Tpm2bEccParameter::new(&[1; 32]).unwrap(),
    });
    assert_eq!(pub_key.verify(digest, sig), Err(CryptoError::Unsupported));
}

/// `ECDAA` is not an [`EccPrivateKey::sign`] / [`EccPublicKey::verify`] scheme.
#[cfg(all(feature = "nist_p256", feature = "ecdaa"))]
#[test]
fn ecdaa_sign_and_verify_unsupported() {
    use crate::{
        Tpm2bEccParameter, TpmEccCurve, TpmsSchemeEcdaa, TpmsSignatureEcc, TpmtSigScheme,
        TpmtSignature,
    };

    let alg = first_enabled_hash();
    let mut rng = TestBackend::from_seed(b"ecdaa").unwrap();
    let key =
        EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let point = key.point(&mut x, &mut y).unwrap();
    let pub_key = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, point)
        .unwrap()
        .unwrap();
    let digest = &[0x33u8; 64][..alg.digest_size()];

    let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
    let scheme = TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
        hash_alg: alg,
        count: 1,
    });
    assert_eq!(
        key.sign(&mut rng, scheme, digest, &mut sig_buf),
        Err(CryptoError::Unsupported)
    );
    let sig = TpmtSignature::Ecdaa(TpmsSignatureEcc {
        hash: alg,
        signature_r: Tpm2bEccParameter::new(&[1; 32]).unwrap(),
        signature_s: Tpm2bEccParameter::new(&[1; 32]).unwrap(),
    });
    assert_eq!(pub_key.verify(digest, sig), Err(CryptoError::Unsupported));
}

#[cfg(feature = "curve25519")]
#[test]
fn x25519_key_roundtrip_and_ecdh() {
    use crate::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint};

    let mut rng = TestBackend::from_seed(b"x25519-seed").unwrap();
    let alice =
        EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::Curve25519, None).unwrap();
    let bob =
        EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::Curve25519, None).unwrap();
    assert!(matches!(alice, EccPrivateKey::X25519(_)));
    assert_eq!(alice.curve(), TpmEccCurve::Curve25519);
    assert_eq!(alice.key_bytes(), 32);

    let (mut ax, mut ay) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let (mut bx, mut by) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let alice_pt = alice.point(&mut ax, &mut ay).unwrap();
    assert_eq!(alice_pt.x.as_slice().len(), 32);
    assert!(alice_pt.y.as_slice().is_empty());
    let bob_pt = bob.point(&mut bx, &mut by).unwrap();

    let alice_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, alice_pt)
        .unwrap()
        .unwrap();
    let bob_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, bob_pt)
        .unwrap()
        .unwrap();

    // Non-empty `y` or wrong-length `x` on Curve25519 returns Ok(None).
    let bad_y_pt = TpmsEccPoint {
        x: alice_pt.x,
        y: Tpm2bEccParameter::new(&[1]).unwrap(),
    };
    assert!(
        EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, bad_y_pt)
            .unwrap()
            .is_none()
    );
    let short_x_pt = TpmsEccPoint {
        x: Tpm2bEccParameter::new(&[1; 31]).unwrap(),
        y: Tpm2bEccParameter::new(&[]).unwrap(),
    };
    assert!(
        EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, short_x_pt)
            .unwrap()
            .is_none()
    );

    // ECDH produces shared `u` in `x` with `y` empty.
    let (mut zx1, mut zy1) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let (mut zx2, mut zy2) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let z1 = alice.ecdh(&bob_pub, &mut zx1, &mut zy1).unwrap().unwrap();
    let z2 = bob.ecdh(&alice_pub, &mut zx2, &mut zy2).unwrap().unwrap();
    assert_eq!(z1, z2);
    assert_eq!(z1.x.as_slice().len(), 32);
    assert!(z1.y.as_slice().is_empty());

    // Reload private key and verify the `load` check.
    let mut s_buf = [0u8; MAX_ECC_COORD_BYTES];
    let scalar = alice.scalar(&mut s_buf).unwrap();
    let wrong_scalar = Tpm2bEccParameter::new(&[0x99; 32]).unwrap();
    assert!(
        EccPrivateKey::<TestBackend>::load(alice_pub, wrong_scalar)
            .unwrap()
            .is_none()
    );
    let alice_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, alice_pt)
        .unwrap()
        .unwrap();
    assert!(
        EccPrivateKey::<TestBackend>::load(alice_pub, scalar)
            .unwrap()
            .is_some()
    );

    // Weierstrass scheme (`Ecdsa`) on Curve25519 returns Unsupported.
    #[cfg(feature = "ecdsa")]
    {
        let alg = first_enabled_hash();
        assert_eq!(
            EccPrivateKey::<TestBackend>::generate(
                &mut rng,
                TpmEccCurve::Curve25519,
                Some(crate::TpmtEccScheme::Ecdsa(alg))
            )
            .err(),
            Some(CryptoError::Unsupported)
        );
    }
}

#[cfg(all(feature = "curve25519", feature = "eddsa"))]
#[test]
fn ed25519_sign_message_and_hash_eddsa() {
    use crate::{Tpm2bEccParameter, TpmEccCurve, TpmtEccScheme, TpmtSigScheme, TpmtSignature};

    let mut rng = TestBackend::from_seed(b"ed25519-seed").unwrap();
    let priv_key = EccPrivateKey::<TestBackend>::generate(
        &mut rng,
        TpmEccCurve::Curve25519,
        Some(TpmtEccScheme::Eddsa),
    )
    .unwrap();
    assert!(matches!(priv_key, EccPrivateKey::Ed25519(_)));
    assert_eq!(priv_key.curve(), TpmEccCurve::Curve25519);
    assert_eq!(priv_key.key_bytes(), 32);

    let (mut px, mut py) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let pt = priv_key.point(&mut px, &mut py).unwrap();
    assert_eq!(pt.x.as_slice().len(), 32);
    assert!(pt.y.as_slice().is_empty());

    let pub_key =
        EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, Some(TpmtEccScheme::Eddsa), pt)
            .unwrap()
            .unwrap();
    assert!(matches!(pub_key, EccPublicKey::Ed25519(_)));

    // ECDH on an Edwards signing key returns Unsupported.
    let (mut zx, mut zy) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    assert_eq!(
        priv_key.ecdh(&pub_key, &mut zx, &mut zy),
        Err(CryptoError::Unsupported)
    );

    // Reload private key and verify the `load` check.
    let mut s_buf = [0u8; MAX_ECC_COORD_BYTES];
    let secret = priv_key.scalar(&mut s_buf).unwrap();
    let wrong_secret = Tpm2bEccParameter::new(&[0x77; 32]).unwrap();
    assert!(
        EccPrivateKey::<TestBackend>::load(pub_key, wrong_secret)
            .unwrap()
            .is_none()
    );
    let pub_key =
        EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, Some(TpmtEccScheme::Eddsa), pt)
            .unwrap()
            .unwrap();
    assert!(
        EccPrivateKey::<TestBackend>::load(pub_key, secret)
            .unwrap()
            .is_some()
    );
    let pub_key =
        EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, Some(TpmtEccScheme::Eddsa), pt)
            .unwrap()
            .unwrap();

    // Pure EdDSA works via `sign_message` / `verify_message` and rejects digest `sign` / `verify`.
    let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
    assert_eq!(
        priv_key.sign(&mut rng, TpmtSigScheme::Eddsa, &[0x11; 32], &mut sig_buf),
        Err(CryptoError::Unsupported)
    );

    let sig = priv_key
        .sign_message(&[b"hello ", b"ed25519"], &mut sig_buf)
        .unwrap();
    assert!(matches!(sig, TpmtSignature::Eddsa(s) if s.as_slice().len() == 64));
    assert!(pub_key.verify_message(&[b"hello ed25519"], sig).unwrap());
    assert!(!pub_key.verify_message(&[b"wrong"], sig).unwrap());
    assert_eq!(
        pub_key.verify(&[0x11; 32], sig),
        Err(CryptoError::Unsupported)
    );

    // HashEdDSA works via digest `sign` / `verify` with a 64-byte prehash.
    #[cfg(feature = "hash_eddsa")]
    {
        let prehash = [0x42u8; 64];
        let mut ph_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        assert_eq!(
            priv_key.sign(
                &mut rng,
                TpmtSigScheme::HashEddsa,
                &prehash[..32],
                &mut ph_buf
            ),
            Err(CryptoError::Internal)
        );
        let ph_sig = priv_key
            .sign(&mut rng, TpmtSigScheme::HashEddsa, &prehash, &mut ph_buf)
            .unwrap();
        assert!(matches!(ph_sig, TpmtSignature::HashEddsa(s) if s.as_slice().len() == 64));
        assert!(pub_key.verify(&prehash, ph_sig).unwrap());
        assert!(!pub_key.verify(&[0x00; 64], ph_sig).unwrap());
        assert!(!pub_key.verify(&prehash[..32], ph_sig).unwrap());
    }
}

#[cfg(all(feature = "curve448", feature = "eddsa"))]
#[test]
fn ed448_sizing_and_sign_message() {
    use crate::{TpmEccCurve, TpmtEccScheme, TpmtSignature};

    // Curve448 is 448 bits (56 bytes for X448), while Ed448 keys are 57 bytes and signatures 114 bytes.
    assert_eq!(TpmEccCurve::Curve448.key_bytes(), 56);
    const {
        assert!(TpmEccCurve::MAX_ECC_KEY_BYTES >= 57);
        assert!(MAX_ECC_COORD_BYTES >= 57);
        assert!(MAX_SIGNATURE_BYTES >= 114);
    }

    let mut rng = TestBackend::from_seed(b"ed448-seed").unwrap();
    let priv_key = EccPrivateKey::<TestBackend>::generate(
        &mut rng,
        TpmEccCurve::Curve448,
        Some(TpmtEccScheme::Eddsa),
    )
    .unwrap();
    assert!(matches!(priv_key, EccPrivateKey::Ed448(_)));
    assert_eq!(priv_key.curve(), TpmEccCurve::Curve448);
    assert_eq!(priv_key.key_bytes(), 57);

    let (mut px, mut py) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let pt = priv_key.point(&mut px, &mut py).unwrap();
    assert_eq!(pt.x.as_slice().len(), 57);
    assert!(pt.y.as_slice().is_empty());

    let pub_key =
        EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve448, Some(TpmtEccScheme::Eddsa), pt)
            .unwrap()
            .unwrap();
    assert_eq!(pub_key.key_bytes(), 57);

    let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
    let sig = priv_key
        .sign_message(&[b"ed448 ", b"message"], &mut sig_buf)
        .unwrap();
    assert!(matches!(sig, TpmtSignature::Eddsa(s) if s.as_slice().len() == 114));
    assert!(pub_key.verify_message(&[b"ed448 message"], sig).unwrap());
    assert!(!pub_key.verify_message(&[b"tampered"], sig).unwrap());

    // `X448 = !` on TestBackend returns Unsupported.
    assert_eq!(
        EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::Curve448, None).err(),
        Some(CryptoError::Unsupported)
    );
}

#[cfg(feature = "mldsa_44")]
#[test]
fn mldsa_message_mu_and_hash_mldsa() {
    use crate::{Tpm2bPrivateKeyMldsa, Tpm2bPublicKeyMldsa, TpmiMldsaParms, TpmtSignature};

    let mut rng = TestBackend::from_seed(b"mldsa-seed").unwrap();
    let priv_key =
        MldsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiMldsaParms::Mldsa44).unwrap();
    assert_eq!(priv_key.parms(), TpmiMldsaParms::Mldsa44);

    let mut pk_buf: MldsaPubKeyBuffer = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
    let mut seed_buf: MldsaSeedBuffer = [0u8; 32];
    let pk_2b = priv_key.public(&mut pk_buf).unwrap();
    assert_eq!(pk_2b.as_slice().len(), 1312);
    let seed_2b = priv_key.seed(&mut seed_buf).unwrap();

    // Invalid public key length or encoding returns Ok(None).
    let short_pk = Tpm2bPublicKeyMldsa::new(&[0x11; 32]).unwrap();
    assert!(
        MldsaPublicKey::<TestBackend>::load(TpmiMldsaParms::Mldsa44, short_pk)
            .unwrap()
            .is_none()
    );
    let pub_key = MldsaPublicKey::<TestBackend>::load(TpmiMldsaParms::Mldsa44, pk_2b)
        .unwrap()
        .unwrap();
    assert_eq!(pub_key.parms(), TpmiMldsaParms::Mldsa44);

    // Wrong seed rejected with Ok(None) by `load`.
    assert!(
        MldsaPrivateKey::<TestBackend>::load(
            pub_key,
            Tpm2bPrivateKeyMldsa::new(&[0x99u8; 32]).unwrap()
        )
        .unwrap()
        .is_none()
    );
    let pub_key = MldsaPublicKey::<TestBackend>::load(TpmiMldsaParms::Mldsa44, pk_2b)
        .unwrap()
        .unwrap();
    assert!(
        MldsaPrivateKey::<TestBackend>::load(pub_key, seed_2b)
            .unwrap()
            .is_some()
    );
    let pub_key = MldsaPublicKey::<TestBackend>::load(TpmiMldsaParms::Mldsa44, pk_2b)
        .unwrap()
        .unwrap();

    // 1. Pure ML-DSA message signing (`sign_message` / `verify_message`) with context and >255 rejection.
    let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
    let ctx = b"tpm2-mldsa-context";
    let overlong_ctx = [0xaa; TpmtSignature::MAX_CTX_BYTES + 1];
    assert_eq!(
        priv_key.sign_message(&mut rng, &overlong_ctx, &[b"pure ", b"mldsa"], &mut sig_buf),
        Err(CryptoError::Internal)
    );
    let msg_sig = priv_key
        .sign_message(&mut rng, ctx, &[b"pure ", b"mldsa"], &mut sig_buf)
        .unwrap();
    assert!(matches!(msg_sig, TpmtSignature::Mldsa(s) if s.as_slice().len() == 2420));
    assert!(
        pub_key
            .verify_message(ctx, &[b"pure mldsa"], msg_sig)
            .unwrap()
    );
    assert!(
        !pub_key
            .verify_message(b"wrong-ctx", &[b"pure mldsa"], msg_sig)
            .unwrap()
    );
    assert!(
        !pub_key
            .verify_message(&overlong_ctx, &[b"pure mldsa"], msg_sig)
            .unwrap()
    );
    assert!(!pub_key.verify_message(ctx, &[b"wrong"], msg_sig).unwrap());

    // 2. External-mu 64-byte digest signing (`sign_mu` / `verify`; verification
    //    requires an empty context).
    let mu = [0x5au8; TpmiMldsaParms::MU_BYTES];
    let mut mu_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
    assert_eq!(
        priv_key.sign_mu(&mut rng, &mu[..32], &mut mu_buf),
        Err(CryptoError::Internal)
    );
    let mu_sig = priv_key.sign_mu(&mut rng, &mu, &mut mu_buf).unwrap();
    assert!(pub_key.verify(&[], &mu, mu_sig).unwrap());
    assert!(!pub_key.verify(b"non-empty", &mu, mu_sig).unwrap());
    assert!(!pub_key.verify(&[], &[0u8; 64], mu_sig).unwrap());
    assert!(!pub_key.verify(&[], &mu[..32], mu_sig).unwrap());

    // 3. HashML-DSA prehash signing (`sign` / `verify` with `TpmtSigScheme::HashMldsa`).
    #[cfg(feature = "hash_mldsa")]
    {
        let alg = first_enabled_hash();
        let digest = &[0x7bu8; 64][..alg.digest_size()];
        let mut ph_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        assert_eq!(
            priv_key.sign_prehash(&mut rng, alg, &overlong_ctx, digest, &mut ph_buf),
            Err(CryptoError::Internal)
        );
        let ph_sig = priv_key
            .sign_prehash(&mut rng, alg, ctx, digest, &mut ph_buf)
            .unwrap();
        assert!(
            matches!(ph_sig, TpmtSignature::HashMldsa(s) if s.hash == alg && s.signature.as_slice().len() == 2420)
        );
        assert!(pub_key.verify(ctx, digest, ph_sig).unwrap());
        assert!(!pub_key.verify(b"wrong-ctx", digest, ph_sig).unwrap());
        assert!(!pub_key.verify(&overlong_ctx, digest, ph_sig).unwrap());
        assert!(
            !pub_key
                .verify(ctx, &[0u8; 64][..alg.digest_size()], ph_sig)
                .unwrap()
        );
    }

    // `!`-bound parameter set (`Mldsa65 = !`) returns Unsupported.
    #[cfg(feature = "mldsa_65")]
    assert_eq!(
        MldsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiMldsaParms::Mldsa65).err(),
        Some(CryptoError::Unsupported)
    );
}

#[cfg(feature = "mlkem_768")]
#[test]
fn mlkem_encapsulate_and_decapsulate() {
    use crate::{Tpm2bKemCiphertext, Tpm2bPrivateKeyMlkem, Tpm2bPublicKeyMlkem, TpmiMlkemParms};

    let mut rng = TestBackend::from_seed(b"mlkem-seed").unwrap();
    let priv_key =
        MlkemPrivateKey::<TestBackend>::generate(&mut rng, TpmiMlkemParms::Mlkem768).unwrap();
    assert_eq!(priv_key.parms(), TpmiMlkemParms::Mlkem768);

    let mut pk_buf: MlkemPubKeyBuffer = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
    let mut seed_buf: MlkemSeedBuffer = [0u8; 64];
    let pk_2b = priv_key.public(&mut pk_buf).unwrap();
    assert_eq!(pk_2b.as_slice().len(), 1184);
    let seed_2b = priv_key.seed(&mut seed_buf).unwrap();

    // Wrong length or failed modulus check returns Ok(None).
    let short_pk = Tpm2bPublicKeyMlkem::new(&[0x22; 32]).unwrap();
    assert!(
        MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, short_pk)
            .unwrap()
            .is_none()
    );
    let bad_pk = Tpm2bPublicKeyMlkem::new(&[0xff; 1184]).unwrap();
    assert!(
        MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, bad_pk)
            .unwrap()
            .is_none()
    );

    let pub_key = MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, pk_2b)
        .unwrap()
        .unwrap();
    assert_eq!(pub_key.parms(), TpmiMlkemParms::Mlkem768);

    // Wrong seed rejected with Ok(None) by `load`.
    assert!(
        MlkemPrivateKey::<TestBackend>::load(
            pub_key,
            Tpm2bPrivateKeyMlkem::new(&[0x55u8; 64]).unwrap()
        )
        .unwrap()
        .is_none()
    );
    let pub_key = MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, pk_2b)
        .unwrap()
        .unwrap();
    let reloaded_priv = MlkemPrivateKey::<TestBackend>::load(pub_key, seed_2b)
        .unwrap()
        .unwrap();
    let pub_key = MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, pk_2b)
        .unwrap()
        .unwrap();

    // Encapsulate & decapsulate roundtrip.
    let mut ct_buf: MlkemCiphertextBuffer = [0u8; TpmiMlkemParms::MAX_CT_BYTES];
    let mut ss_enc_buf: MlkemSharedSecretBuffer = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
    let mut ss_dec_buf: MlkemSharedSecretBuffer = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
    let (ct, ss_enc) = pub_key
        .encapsulate(&mut rng, &mut ct_buf, &mut ss_enc_buf)
        .unwrap();
    assert_eq!(ct.as_slice().len(), 1088);
    assert_eq!(ss_enc.as_slice().len(), 32);

    let ss_dec = reloaded_priv
        .decapsulate(ct, &mut ss_dec_buf)
        .unwrap()
        .unwrap();
    assert_eq!(ss_enc, ss_dec);

    // Wrong ciphertext length returns Ok(None).
    let short_ct = Tpm2bKemCiphertext::new(&[0u8; 32]).unwrap();
    assert!(
        reloaded_priv
            .decapsulate(short_ct, &mut ss_dec_buf)
            .unwrap()
            .is_none()
    );

    // `!`-bound parameter set (`Mlkem512 = !`) returns Unsupported.
    #[cfg(feature = "mlkem_512")]
    assert_eq!(
        MlkemPrivateKey::<TestBackend>::generate(&mut rng, TpmiMlkemParms::Mlkem512).err(),
        Some(CryptoError::Unsupported)
    );
}

/// The default [`Random::instantiate_seeded`] is deterministic and separates its inputs.
#[test]
fn default_instantiate_seeded_is_deterministic_and_separates_inputs() {
    let draw = |seed: &[u8], purpose: &[u8], name: &[u8], additional: &[u8]| {
        let mut rng = TestBackend::instantiate_seeded(seed, purpose, name, additional).unwrap();
        let mut out = [0u8; 16];
        rng.fill_bytes(&mut out).unwrap();
        out
    };
    let a = draw(b"seed", b"purpose\0", b"name", b"data");
    assert_eq!(a, draw(b"seed", b"purpose\0", b"name", b"data"));
    assert_ne!(a, draw(b"seed", b"purpose\0", b"name", b"dat"));
    assert_ne!(a, draw(b"Seed", b"purpose\0", b"name", b"data"));
    // The inputs are not simply concatenated.
    assert_ne!(
        draw(b"seed", b"ab", b"c", b""),
        draw(b"seed", b"a", b"bc", b"")
    );
    // The default lifecycle and state hooks.
    let mut rng = TestBackend::from_entropy().unwrap();
    assert_eq!(rng.init(), Ok(()));
    assert_eq!(rng.startup(), Ok(()));
    assert_eq!(rng.self_test(), Ok(true));
    assert_eq!(<TestRng as Rng>::STATE_SIZE, 0);
    assert_eq!(rng.save_state(&mut []), Err(CryptoError::Unsupported));
    assert_eq!(rng.load_state(&[]), Err(CryptoError::Unsupported));
    assert!(!rng.is_system_rng());
}

/// An RNG that draws only zero octets (for the zero-replacement of RSAES-PKCS1-v1_5).
#[cfg(feature = "rsa")]
struct ZeroRng(usize);

#[cfg(feature = "rsa")]
impl Rng for ZeroRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        out.fill(0);
        self.0 += out.len();
        Ok(())
    }

    fn stir_bytes(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// The next 16 octets of `rng` (to compare the states of two RNGs).
#[cfg(feature = "rsa")]
fn next_octets(rng: &mut TestRng) -> [u8; 16] {
    let mut out = [0u8; 16];
    rng.fill_bytes(&mut out).unwrap();
    out
}

/// [`rsa_oaep_encode`] is RFC 8017's EME-OAEP with the label's octets, and its seed is the one
/// digest it draws (after which the RNG is where a draw of one digest leaves it); messages that
/// do not fit and moduli that cannot hold two digests are `Ok(None)` and draw nothing.
#[cfg(feature = "rsa")]
#[test]
fn rsa_oaep_encode_draws_one_seed_and_encodes_like_rfc_8017() {
    let alg = first_enabled_hash();
    let h_len = alg.digest_size();
    let (mut rng, mut twin) = (
        TestBackend::from_seed(b"oaep").unwrap(),
        TestBackend::from_seed(b"oaep").unwrap(),
    );
    let label = b"DUPLICATE\0";
    let mut padded = [0xaau8; 256];
    let max = 256 - 2 * h_len - 2;
    for message in [&b""[..], b"secret", &[0x5a; 256][..max]] {
        assert_eq!(
            rsa_oaep_encode::<TestBackend>(&mut rng, alg, label, message, &mut padded),
            Ok(Some(()))
        );
        let mut seed = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        twin.fill_bytes(&mut seed[..h_len]).unwrap();
        assert_eq!(
            oaep_decode(alg, label, &padded).as_deref(),
            Some(message),
            "{} octets",
            message.len()
        );
        // The masked seed is the drawn seed masked with MGF1(maskedDB).
        let mask = toy_mgf1(alg, &padded[1 + h_len..], h_len);
        let unmasked: std::vec::Vec<u8> = padded[1..=h_len]
            .iter()
            .zip(mask)
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(unmasked, seed[..h_len]);
    }
    assert_eq!(next_octets(&mut rng), next_octets(&mut twin));
    // Too long, or too small a modulus: nothing is drawn.
    let too_long = [0u8; 256];
    assert_eq!(
        rsa_oaep_encode::<TestBackend>(&mut rng, alg, b"", &too_long[..=max], &mut padded),
        Ok(None)
    );
    assert_eq!(
        rsa_oaep_encode::<TestBackend>(&mut rng, alg, b"", b"", &mut padded[..2 * h_len + 1]),
        Ok(None)
    );
    assert_eq!(
        rsa_oaep_encode::<TestBackend>(&mut rng, alg, b"", b"", &mut padded[..2 * h_len + 2]),
        Ok(Some(()))
    );
    twin.fill_bytes(&mut [0u8; TpmiAlgHash::MAX_DIGEST_BYTES][..h_len])
        .unwrap();
    assert_eq!(next_octets(&mut rng), next_octets(&mut twin));
}

/// [`rsa_pkcs1v15_encode`] is `00 02 PS 00 M` with the padding string drawn in one piece and
/// each of its zero octets replaced with `0x55`; a message longer than `k - 11` octets is
/// `Ok(None)` and draws nothing.
#[cfg(feature = "rsa")]
#[test]
fn rsa_pkcs1v15_encode_replaces_zero_padding_octets() {
    let mut zeros = ZeroRng(0);
    let mut padded = [0xaau8; 128];
    assert_eq!(
        rsa_pkcs1v15_encode(&mut zeros, &[1, 2, 3], &mut padded),
        Ok(Some(()))
    );
    assert_eq!(zeros.0, 128 - 3 - 3);
    assert_eq!(padded[..2], [0x00, 0x02]);
    assert!(padded[2..124].iter().all(|&b| b == 0x55));
    assert_eq!(padded[124..], [0x00, 1, 2, 3]);
    assert_eq!(pkcs1v15_decode(&padded), Some(&[1u8, 2, 3][..]));

    let (mut rng, mut twin) = (
        TestBackend::from_seed(b"pkcs1").unwrap(),
        TestBackend::from_seed(b"pkcs1").unwrap(),
    );
    assert_eq!(
        rsa_pkcs1v15_encode(&mut rng, &[7; 117], &mut padded),
        Ok(Some(()))
    );
    let mut ps = [0u8; 8];
    twin.fill_bytes(&mut ps).unwrap();
    for (&octet, &drawn) in padded[2..10].iter().zip(&ps) {
        assert_eq!(octet, if drawn == 0 { 0x55 } else { drawn });
    }
    assert_eq!(padded[10], 0);
    assert_eq!(padded[11..], [7; 117]);
    assert_eq!(
        rsa_pkcs1v15_encode(&mut rng, &[7; 118], &mut padded),
        Ok(None)
    );
    assert_eq!(
        rsa_pkcs1v15_encode(&mut rng, &[], &mut padded[..10]),
        Ok(None)
    );
    assert_eq!(next_octets(&mut rng), next_octets(&mut twin));
}

/// The salt length of the TPM's PSS signatures: the largest that fits, at most the digest size.
#[cfg(feature = "rsa")]
#[test]
fn rsa_pss_salt_size_is_the_largest_that_fits_up_to_the_digest_size() {
    assert_eq!(rsa_pss_salt_size(32, 256), 32);
    assert_eq!(rsa_pss_salt_size(64, 128), 62);
    assert_eq!(rsa_pss_salt_size(64, 100), 34);
    assert_eq!(rsa_pss_salt_size(20, 22), 0);
    assert_eq!(rsa_pss_salt_size(20, 21), 0);
    assert_eq!(rsa_pss_salt_size(20, 0), 0);
}

/// [`rsa_pss_encode`] is RFC 8017's EMSA-PSS with the salt it draws (one leading bit cleared,
/// the `0xbc` trailer), and an output that cannot hold a digest and two octets is an internal
/// error that draws nothing.
#[cfg(feature = "rsa")]
#[test]
fn rsa_pss_encode_draws_the_salt_and_encodes_like_rfc_8017() {
    let alg = first_enabled_hash();
    let h_len = alg.digest_size();
    let digest = &[0x44u8; 64][..h_len];
    let (mut rng, mut twin) = (
        TestBackend::from_seed(b"pss").unwrap(),
        TestBackend::from_seed(b"pss").unwrap(),
    );
    for k in [128usize, 2 * h_len + 2, h_len + 3, h_len + 2] {
        let mut out = [0xffu8; 128];
        let out = &mut out[..k];
        assert_eq!(
            rsa_pss_encode::<TestBackend>(&mut rng, alg, digest, out),
            Ok(()),
            "{k}"
        );
        let salt_size = rsa_pss_salt_size(h_len, k);
        let mut salt = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        twin.fill_bytes(&mut salt[..salt_size]).unwrap();
        assert_eq!(out[0] & 0x80, 0);
        assert_eq!(out[k - 1], 0xbc);
        assert!(pss_verify(alg, digest, out), "{k}");
        // The salt is the end of DB.
        let m_len = k - h_len - 1;
        let db: std::vec::Vec<u8> = out[..m_len]
            .iter()
            .zip(toy_mgf1(alg, &out[m_len..k - 1], m_len))
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(db[m_len - salt_size..], salt[..salt_size], "{k}");
    }
    assert_eq!(
        rsa_pss_encode::<TestBackend>(&mut rng, alg, digest, &mut [0; 64][..h_len + 1]),
        Err(CryptoError::Internal)
    );
    assert_eq!(next_octets(&mut rng), next_octets(&mut twin));
}
