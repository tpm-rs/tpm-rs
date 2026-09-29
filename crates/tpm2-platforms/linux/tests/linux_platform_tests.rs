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
    let rng = LinuxRng::new();
    let mut buf1 = [0u8; 16];
    let mut buf2 = [0u8; 16];
    assert!(rng.get_random(&mut buf1).is_ok());
    assert!(rng.get_random(&mut buf2).is_ok());
    // Probability of two 16-byte random buffers being exactly the same is negligible.
    assert_ne!(buf1, buf2);
}
