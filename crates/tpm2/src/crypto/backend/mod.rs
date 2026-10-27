//! Cryptography Backend Traits
//!
//! Users of [`tpm2::crypto`](super) should not normally need this module. The
//! dispatch functions (and enums) use a runtime-specified algorithm to call
//! into a [`Crypto`](super::Crypto) backend rather than directly using the
//! family traits and state traits in this module.
//!
//! ## Structure
//!
//! Each algorithm family has a *family trait*:
//! - [`Hash`]
//! - [`Hmac`]
//! - [`Cmac`]
//! - [`Symmetric`]
//!
//! with one associated type per algorithm. Each associated type implements
//! the family's *state trait*:
//! - [`HashState`]
//! - [`HmacState`]
//! - [`CmacState`]
//! - [`SymmetricState`]
//!
//! whose digest or key size is a `const` generic parameter. Backends
//! never see a runtime algorithm identifier, and only ever receive
//! correctly sized input/output buffers (digests, keys, data blocks).
//!
//! A complete backend implements all the family traits,
//! [`Random`](super::Random), and the [`Crypto`](super::Crypto) supertrait.
//!
//! ## Unsupported Algorithms
//!
//! Algorithms a backend does not implement bind their associated type to
//! [`!`]. The `!` implementations of the state traits return
//! `Err(`[`CryptoError::Unsupported`](super::CryptoError::Unsupported)`)` from
//! `init`, so every operation on an unsupported algorithm returns that error.
//! A backend can leave out an entire family this way (see the example below).
//!
//! Random number generation ([`Random`](super::Random)) is not optional, so
//! there is no `!` implementation of [`Rng`](super::Rng).
//!
//! ## Default Methods
//!
//! Some state trait methods have default implementations built on the
//! required methods. Backends may override them for hardware acceleration,
//! compliance, or code-size reasons, but must preserve the documented
//! behavior. The defaults which implement complex TPM-specific behavior are
//! also available as public functions, so an override can handle the cases
//! it accelerates and fall back to the default for the rest:
//!
//! | Method | Default implementation |
//! |--------|------------------------|
//! | [`HashState::kdfe`] | [`default_kdfe`] |
//! | [`HmacState::kdfa`] | [`default_kdfa`] |
//! | [`HmacState::kdfa_xor`] | [`default_kdfa_xor`] |
//! | [`SymmetricState::crypt`] | [`default_crypt`] |
//!
//! ## Example
//!
//! A backend which only implements SHA-256 (and random number generation):
//!
//! ```
//! use tpm2::crypto::{
//!     Crypto, CryptoError, Random, Rng,
//!     backend::{Cmac, Hash, HashState, Hmac, Symmetric},
//! };
//!
//! struct MyBackend;
//! struct MySha256 { /* ... */ }
//!
//! impl HashState<32> for MySha256 {
//!     fn init() -> Result<Self, CryptoError> {
//!         todo!()
//!     }
//!     fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
//!         todo!()
//!     }
//!     fn finalize(&mut self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
//!         todo!()
//!     }
//! }
//!
//! impl Hash for MyBackend {
//!     type Sha256 = MySha256;
//!     type Sha1 = !;
//!     type Sha384 = !;
//!     type Sha512 = !;
//!     type Sm3_256 = !;
//!     type Sha3_256 = !;
//!     type Sha3_384 = !;
//!     type Sha3_512 = !;
//! }
//!
//! // Families which aren't implemented at all bind every type to `!`.
//! impl Hmac for MyBackend {
//!     type Sha1 = !;
//!     type Sha256 = !;
//!     type Sha384 = !;
//!     type Sha512 = !;
//!     type Sm3_256 = !;
//!     type Sha3_256 = !;
//!     type Sha3_384 = !;
//!     type Sha3_512 = !;
//! }
//! impl Cmac for MyBackend {
//!     type Aes128 = !;
//!     type Aes192 = !;
//!     type Aes256 = !;
//!     type Sm4_128 = !;
//!     type Camellia128 = !;
//!     type Camellia192 = !;
//!     type Camellia256 = !;
//! }
//! impl Symmetric for MyBackend {
//!     type Aes128 = !;
//!     type Aes192 = !;
//!     type Aes256 = !;
//!     type Sm4_128 = !;
//!     type Camellia128 = !;
//!     type Camellia192 = !;
//!     type Camellia256 = !;
//! }
//!
//! // Random number generation is always required.
//! struct MyRng { /* ... */ }
//!
//! impl Rng for MyRng {
//!     fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
//!         todo!()
//!     }
//!     fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
//!         todo!()
//!     }
//! }
//!
//! impl Random for MyBackend {
//!     type Rng = MyRng;
//!     fn from_entropy() -> Result<MyRng, CryptoError> {
//!         todo!()
//!     }
//!     fn from_seed(seed: &[u8]) -> Result<MyRng, CryptoError> {
//!         todo!()
//!     }
//! }
//!
//! impl Crypto for MyBackend {
//!     fn ct_eq(a: &[u8], b: &[u8]) -> bool {
//!         todo!()
//!     }
//! }
//! ```
//!
//! ## Optimization Notes
//!
//! ### Using the dispatch functions and enums
//!
//! - **Prefer one-shot functions.** One-shot functions (e.g.
//!   [`hash`](super::hash) or [`SymmetricKey::crypt`](super::SymmetricKey::crypt))
//!   select the algorithm once and then use only that algorithm's state, in
//!   place. Pass multi-part input as `&[a, b, ..]` (e.g. `cpHash`, session
//!   HMACs) rather than building a local context. The dispatch enums (e.g.
//!   [`HashContext`](super::HashContext)) are sized for the largest enabled
//!   algorithm, and constructing, returning, or consuming one can move the
//!   backend state (returning one in a `Result` can take 2–3× its size in
//!   stack). Operating on an already-stored enum (e.g. `&mut HashContext`)
//!   copies nothing.
//! - **Disable unused [algorithm features](crate#algorithm-feature-flags).**
//!   Dropping `sha384`, `sha512`, `aes256`, or unused cipher modes shrinks the
//!   dispatch enums and removes those algorithms from runtime dispatch.
//! - **Use `opt-level = "s"` (or higher), not `"z"`.** `"z"` suppresses
//!   inlining of small helpers, which increases peak stack and leaves slice
//!   bounds-check panics that higher levels eliminate.
//!
//! ### Implementing the backend traits
//!
//! - **Keep stack-heavy setup out of line.** Mark stack-heavy setup (key
//!   expansion, long HMAC key hashing) `#[inline(never)]`, so its temporaries
//!   are freed before data is processed.
//! - **Don't move states out of a `Result`.** Use them in place (e.g.
//!   `match &mut Self::init(key) { Ok(state) => .., Err(e) => .. }`), as
//!   moving a state out copies it.
//! - **Override one-shot methods.** Hardware, ROM, or C backends can override
//!   the one-shot methods (e.g. [`HashState::hash`],
//!   [`SymmetricState::crypt_once`], or
//!   [`Random::rand_bytes`](super::Random::rand_bytes)) to skip software state
//!   entirely.
//!
//! ### Dispatch design notes
//!
//! These were measured with the RustCrypto backend on `thumbv7m` and
//! `riscv32imc` at `opt-level = "s"`, for a context which is constructed and
//! used in the same function.
//!
//! - **Only [`SymmetricContext::new`](super::SymmetricContext::new) is
//!   `#[inline]`.** This saves 192–392 bytes of peak stack. `#[inline]` on
//!   [`HashContext::new`](super::HashContext::new) instead costs 152 bytes,
//!   and had no measurable effect on the other dispatch methods.
//! - **Contexts are constructed directly** (`Ok(Self::V(State::init()?))`).
//!   Constructing them in an `#[inline(never)]` helper saved ~192 bytes when
//!   `HashContext::new` was `#[inline]`, but had mixed effects at
//!   `opt-level = 3` (±100–250 bytes), so the helper was removed for
//!   simplicity.

mod cmac;
mod hash;
mod hmac;
mod kdf;
mod symmetric;
pub use {cmac::*, hash::*, hmac::*, kdf::*, symmetric::*};
