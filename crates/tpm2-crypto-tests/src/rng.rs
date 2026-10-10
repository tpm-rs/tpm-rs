//! Tests for [`Random`] and [`Rng`].

use tpm2::crypto::{Random, Rng};

use crate::{
    Caps, Check,
    util::{fill, seeded_rng},
};

/// Output sizes requested from an RNG, in order.
const REQUESTS: [usize; 5] = [1, 7, 32, 64, 1000];

/// Returns the concatenated output of [`REQUESTS`].
fn outputs<R: Rng>(rng: &mut R) -> Vec<u8> {
    REQUESTS.iter().flat_map(|&len| fill(rng, len)).collect()
}

/// The entropy-seeded RNG produces distinct, non-zero output (and two
/// instances differ), and handles empty and large requests.
pub fn rng_system<C: Random>(c: &C, _caps: &Caps) {
    let mut rng = c.rng().check("Random::rng");
    let a = fill(&mut rng, 32);
    let b = fill(&mut rng, 32);
    assert_ne!(a, b, "consecutive outputs are identical");
    assert_ne!(a, [0u8; 32], "output is all zeros");
    rng.fill_bytes(&mut []).check("empty fill_bytes");
    let large = fill(&mut rng, 1 << 20);
    assert!(
        large.iter().any(|&x| x != 0),
        "1 MiB of output is all zeros"
    );

    let mut other = c.rng().check("Random::rng");
    assert_ne!(
        fill(&mut other, 32),
        a,
        "two instances produce the same output"
    );
}

/// Seeded RNGs are deterministic: the same seed gives the same output for the
/// same sequence of requests.
pub fn rng_seeded_deterministic<C: Random>(c: &C, _caps: &Caps) {
    for seed in [&[0x11; 32][..], &[0x22; 64], b"tpm2-crypto-tests"] {
        let mut a = c.rng_seeded(seed).check("Random::rng_seeded");
        let mut b = c.rng_seeded(seed).check("Random::rng_seeded");
        assert_eq!(
            outputs(&mut a),
            outputs(&mut b),
            "same seed, different output"
        );
        // ... and they stay in sync.
        assert_eq!(fill(&mut a, 48), fill(&mut b, 48), "seeded RNGs diverged");
    }
}

/// Changing any part of the seed changes the output.
pub fn rng_seeded_seed_sensitivity<C: Random>(c: &C, _caps: &Caps) {
    let seed = [0x33u8; 48];
    let output = |seed: &[u8]| {
        let mut rng = c.rng_seeded(seed).check("Random::rng_seeded");
        fill(&mut rng, 64)
    };
    let base = output(&seed);
    for index in [0, seed.len() / 2, seed.len() - 1] {
        let mut changed = seed;
        changed[index] ^= 0x80;
        assert_ne!(
            output(&changed),
            base,
            "changing seed byte {index} doesn't change the output"
        );
    }
    assert_ne!(
        output(&[0x44; 48]),
        base,
        "different seeds give the same output"
    );
}

/// Reseeding is deterministic, and changes the output depending on the data.
pub fn rng_reseed<C: Random>(c: &C, _caps: &Caps) {
    let seed = b"rng_reseed";
    let reseeded = |data: &[&[u8]]| {
        let mut rng = c.rng_seeded(seed).check("Random::rng_seeded");
        fill(&mut rng, 16);
        for data in data {
            rng.reseed(data).check("Rng::reseed");
        }
        fill(&mut rng, 64)
    };
    let plain = reseeded(&[]);
    let once = reseeded(&[b"additional data"]);
    assert_eq!(
        once,
        reseeded(&[b"additional data"]),
        "reseeding isn't deterministic"
    );
    assert_ne!(once, plain, "reseeding doesn't change the output");
    assert_ne!(
        once,
        reseeded(&[b"additional datA"]),
        "reseed data is ignored"
    );
    assert_ne!(
        once,
        reseeded(&[b"additional data", b"more"]),
        "second reseed is ignored"
    );

    // Reseeding the entropy-seeded RNG works too.
    let mut rng = c.rng().check("Random::rng");
    rng.reseed(b"stir").check("Rng::reseed");
    assert_ne!(fill(&mut rng, 32), [0u8; 32]);
}

/// The byte distribution of 100,000 output bytes is roughly uniform (each
/// value occurs within about 7 standard deviations of the mean).
pub fn rng_byte_distribution<C: Random>(c: &C, _caps: &Caps) {
    let check = |name: &str, data: Vec<u8>| {
        let mut counts = [0usize; 256];
        for byte in data {
            counts[usize::from(byte)] += 1;
        }
        for (value, count) in counts.iter().enumerate() {
            assert!(
                (250..=530).contains(count),
                "{name}: byte {value:#04x} occurs {count} times (expected ~390)"
            );
        }
    };
    check(
        "Random::rng",
        fill(&mut c.rng().check("Random::rng"), 100_000),
    );
    check(
        "Random::rng_seeded",
        fill(&mut seeded_rng(c, "distribution"), 100_000),
    );
}
