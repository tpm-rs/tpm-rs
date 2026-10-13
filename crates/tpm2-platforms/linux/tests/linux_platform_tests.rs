use tpm2::crypto::Rng;
use tpm2_impl::timer::TpmTimer;
use tpm2_platform_linux::{LinuxRng, LinuxTimer};

#[test]
fn test_linux_timer() {
    let timer = LinuxTimer::new();
    let t1 = timer.timer_read();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let t2 = timer.timer_read();
    assert!(t2 > t1);
}

#[test]
fn test_linux_rng() {
    let mut rng = LinuxRng::new();
    let mut buf1 = [0u8; 16];
    let mut buf2 = [0u8; 16];
    assert!(rng.fill_bytes(&mut buf1).is_ok());
    assert!(rng.fill_bytes(&mut buf2).is_ok());
    // Probability of two 16-byte random buffers being exactly the same is negligible.
    assert_ne!(buf1, buf2);
}

#[test]
fn test_linux_rng_reseed_is_ignored() {
    // The OS entropy source cannot be stirred: reseeding succeeds and the RNG
    // keeps producing random bytes.
    let mut rng = LinuxRng::new();
    assert_eq!(rng.reseed(b"additional entropy"), Ok(()));
    assert_eq!(rng.reseed(&[]), Ok(()));
    let mut buf1 = [0u8; 16];
    let mut buf2 = [0u8; 16];
    assert_eq!(rng.fill_bytes(&mut buf1), Ok(()));
    assert_eq!(rng.fill_bytes(&mut buf2), Ok(()));
    assert_ne!(buf1, buf2);
    // An empty request is trivially satisfied.
    assert_eq!(rng.fill_bytes(&mut []), Ok(()));
}
