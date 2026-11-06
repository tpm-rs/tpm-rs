//! Tests of the platform interface of the engine (tpm-rs#299): a custom [`Platform`] whose
//! immutable [`Info`] the TPM reports, whose NV hooks ([`Platform::load_nv`],
//! [`Platform::store_nv`]) the engine calls at `_TPM_Init`, manufacture and after every
//! command, and whose NV data structure ([`Platform::IndexState`]) lives in the TPM state; and
//! the state hierarchy ([`State`], [`tpm2_engine::Nv`]).

mod common;

use common::FakePlatform;
use common::{FakeCrypto, FakeRng, FakeTimer};
use tpm2::{TpmCap, TpmPt};
use tpm2_engine::storage::IndexState;
use tpm2_engine::storage::ram_storage_mock::RamStorageMock;
use tpm2_engine::{Info, Nv, Platform, State, TpmEngine};

/// The size of the NV memory of the test platforms.
const NV_SIZE: usize = 2 * tpm2_engine::storage::nv_capacity::NV_MEMORY_SIZE as usize;

/// The NV data structure of the test platforms: an owned RAM medium.
type Ram = RamStorageMock<NV_SIZE>;

/// A platform that owns its components, reports `info`, counts the NV hooks and keeps an
/// "external" copy of the NV data, which `load_nv` reads into the TPM state and `store_nv`
/// writes back (like a platform that keeps NV in RAM and syncs it to a file).
struct CountingPlatform {
    timer: FakeTimer,
    rng: FakeRng,
    info: Info,
    loads: usize,
    stores: usize,
    external: Option<Box<Ram>>,
}

impl CountingPlatform {
    fn new(info: Info) -> Self {
        Self {
            timer: FakeTimer,
            rng: FakeRng::new(),
            info,
            loads: 0,
            stores: 0,
            external: None,
        }
    }
}

impl Platform for CountingPlatform {
    type Crypto = FakeCrypto;
    type Timer = FakeTimer;
    type Rng = FakeRng;
    type IndexState = Ram;

    fn info(&self) -> &Info {
        &self.info
    }

    fn timer(&self) -> &FakeTimer {
        &self.timer
    }

    fn rng(&mut self) -> &mut FakeRng {
        &mut self.rng
    }

    fn load_nv(&mut self, nv: &mut Nv<Self>) {
        self.loads += 1;
        if let Some(external) = &self.external {
            nv.index.as_mut_slice().copy_from_slice(external.as_slice());
        }
    }

    fn store_nv(&mut self, nv: &Nv<Self>) {
        self.stores += 1;
        if let Some(external) = &mut self.external {
            external.as_mut_slice().copy_from_slice(nv.index.as_slice());
        }
    }
}

/// A new engine over `platform` with a fresh NV medium, manufactured.
fn manufactured(platform: CountingPlatform) -> Box<TpmEngine<CountingPlatform>> {
    let mut tpm = Box::new(TpmEngine::new(platform, Ram::new()).unwrap());
    tpm.init_storage();
    tpm
}

/// Powers `tpm` on (`_TPM_Init`) and runs `TPM2_Startup(TPM_SU_CLEAR)`.
fn power_on_start_up<P: Platform>(tpm: &mut TpmEngine<P>) {
    tpm.reset();
    tpm.set_nv_available(true);
    let startup = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0];
    let mut rsp = [0u8; 64];
    let len = tpm.execute_command_separate(&startup, &mut rsp);
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0], "TPM2_Startup failed");
    assert_eq!(len, 10);
}

/// The vendor and firmware properties of `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)`, from
/// `TPM_PT_MANUFACTURER` to `TPM_PT_FIRMWARE_VERSION_2`.
fn vendor_properties<P: Platform>(tpm: &mut TpmEngine<P>) -> Vec<(TpmPt, u32)> {
    let mut cmd = vec![0x80, 0x01, 0, 0, 0, 22, 0, 0, 0x01, 0x7A];
    cmd.extend_from_slice(&(TpmCap::TPMProperties as u32).to_be_bytes());
    cmd.extend_from_slice(&TpmPt::MANUFACTURER.0.to_be_bytes());
    cmd.extend_from_slice(&8u32.to_be_bytes());
    let mut rsp = [0u8; 1024];
    let len = tpm.execute_command_separate(&cmd, &mut rsp);
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0], "TPM2_GetCapability failed");
    // moreData (1), capability (4), count (4), then (property, value) pairs.
    let count = u32::from_be_bytes(rsp[15..19].try_into().unwrap()) as usize;
    assert_eq!(len, 19 + 8 * count);
    rsp[19..len]
        .chunks(8)
        .map(|p| {
            (
                TpmPt(u32::from_be_bytes(p[..4].try_into().unwrap())),
                u32::from_be_bytes(p[4..].try_into().unwrap()),
            )
        })
        .collect()
}

/// The expected vendor properties for `info`.
fn expected_properties(info: &Info) -> Vec<(TpmPt, u32)> {
    vec![
        (TpmPt::MANUFACTURER, info.manufacturer),
        (TpmPt::VENDOR_STRING_1, info.vendor_strings[0]),
        (TpmPt::VENDOR_STRING_2, info.vendor_strings[1]),
        (TpmPt::VENDOR_STRING_3, info.vendor_strings[2]),
        (TpmPt::VENDOR_STRING_4, info.vendor_strings[3]),
        (TpmPt::VENDOR_TPM_TYPE, info.vendor_tpm_type),
        (TpmPt::FIRMWARE_VERSION_1, info.firmware_version_1),
        (TpmPt::FIRMWARE_VERSION_2, info.firmware_version_2),
    ]
}

/// `FakePlatform` reports `Info::DEFAULT` ("GOOG", "TPM-RUST", firmware version 1.0) unless it
/// is given other information.
#[test]
fn default_platform_reports_default_info() {
    assert_eq!(Info::default(), Info::DEFAULT);
    assert_eq!(Info::DEFAULT.manufacturer, u32::from_be_bytes(*b"GOOG"));
    assert_eq!(Info::DEFAULT.attest_firmware_version(), 1 << 32);

    let (mut crypto, mut timer, mut rng) = (FakeCrypto, FakeTimer, FakeRng::new());
    let mut storage = Box::new(Ram::new());
    let platform = FakePlatform::new(&mut crypto, &mut timer, &mut rng);
    let mut tpm = Box::new(TpmEngine::new(platform, &mut *storage).unwrap());
    tpm.init_storage();
    power_on_start_up(&mut *tpm);
    assert_eq!(
        vendor_properties(&mut *tpm),
        expected_properties(&Info::DEFAULT)
    );

    let info = Info {
        vendor_strings: [
            u32::from_be_bytes(*b"ABCD"),
            u32::from_be_bytes(*b"EFGH"),
            0,
            0,
        ],
        ..Info::DEFAULT
    };
    tpm.platform = tpm.platform.with_info(info);
    assert_eq!(vendor_properties(&mut *tpm), expected_properties(&info));
}

/// A custom platform's `Info` is reported by `TPM2_GetCapability`, and its firmware version
/// in attestation structures follows it (`(V1 << 32) | V2`).
#[test]
fn custom_platform_info_is_reported() {
    let info = Info {
        manufacturer: u32::from_be_bytes(*b"TEST"),
        vendor_strings: [1, 2, 3, 4],
        vendor_tpm_type: 7,
        firmware_version_1: 0x0102_0304,
        firmware_version_2: 0x0506_0708,
    };
    assert_eq!(info.attest_firmware_version(), 0x0102_0304_0506_0708);
    let mut tpm = manufactured(CountingPlatform::new(info));
    power_on_start_up(&mut *tpm);
    assert_eq!(vendor_properties(&mut *tpm), expected_properties(&info));
}

/// The engine reads the NV data from external storage once per `_TPM_Init` and syncs it back
/// after manufacture, `_TPM_Init` and every command (also a failing one).
#[test]
fn nv_hooks_are_called_at_init_and_after_every_command() {
    let mut tpm = manufactured(CountingPlatform::new(Info::DEFAULT));
    assert_eq!((tpm.platform.loads, tpm.platform.stores), (0, 1));

    tpm.reset();
    tpm.set_nv_available(true);
    assert_eq!((tpm.platform.loads, tpm.platform.stores), (1, 2));

    let startup = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0];
    let mut rsp = [0u8; 64];
    tpm.execute_command_separate(&startup, &mut rsp);
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0]);
    assert_eq!((tpm.platform.loads, tpm.platform.stores), (1, 3));

    // A second TPM2_Startup fails (TPM_RC_INITIALIZE) and still syncs.
    tpm.execute_command_separate(&startup, &mut rsp);
    assert_ne!(&rsp[6..10], &[0, 0, 0, 0]);
    assert_eq!((tpm.platform.loads, tpm.platform.stores), (1, 4));

    // A malformed command too.
    tpm.execute_command_separate(&[0x80], &mut rsp);
    assert_eq!((tpm.platform.loads, tpm.platform.stores), (1, 5));
}

/// A platform that keeps the NV data externally gets every NV write in `store_nv`, and the NV
/// data it supplies in `load_nv` is the one the TPM reloads at `_TPM_Init`: a TPM over a fresh
/// medium that loads the external copy of another TPM continues with its Primary Seeds.
#[test]
fn load_nv_supplies_and_store_nv_receives_the_nv_data() {
    let mut first = CountingPlatform::new(Info::DEFAULT);
    first.external = Some(Box::new(Ram::new()));
    let mut first = manufactured(first);
    power_on_start_up(&mut *first);
    let external = first.platform.external.take().unwrap();
    assert_eq!(external.as_slice(), first.state.nv.index.as_slice());
    let seed = first.state.nv.persistent.sp_seed;
    assert_ne!(seed, [0; 64]);

    let mut second = CountingPlatform::new(Info::DEFAULT);
    second.external = Some(external);
    let mut second = Box::new(TpmEngine::new(second, Ram::new()).unwrap());
    assert_eq!(second.state.nv.persistent.sp_seed_size, 0);
    power_on_start_up(&mut *second);
    assert_eq!(second.state.nv.persistent.sp_seed, seed);
    assert_eq!(second.state.nv.persistent.sp_seed_size, 64);
    assert_eq!(
        second.state.nv.index.as_slice(),
        second.platform.external.as_ref().unwrap().as_slice()
    );
}

/// `State::reinitialize` returns every value to that of a new TPM but keeps the NV data.
#[test]
fn reinitialize_keeps_only_the_nv_data() {
    let mut tpm = manufactured(CountingPlatform::new(Info::DEFAULT));
    power_on_start_up(&mut *tpm);
    let nv = tpm.state.nv.index.as_slice().to_vec();
    assert!(tpm.state.initialized);
    assert_eq!(tpm.state.nv.persistent.sp_seed_size, 64);
    tpm.state.locality = 3;
    tpm.state.nv.reset.restart_count = 9;
    tpm.state.nv.clear.sh_enable = false;
    tpm.state.nv.orderly.clock_safe = false;

    tpm.state.reinitialize();
    let new = Box::new(State::<CountingPlatform>::new(Ram::new()));
    assert!(!tpm.state.initialized);
    assert_eq!(tpm.state.locality, new.locality);
    assert_eq!(tpm.state.nv.persistent.sp_seed_size, 0);
    assert_eq!(tpm.state.nv.reset.restart_count, new.nv.reset.restart_count);
    assert_eq!(tpm.state.nv.clear.sh_enable, new.nv.clear.sh_enable);
    assert_eq!(tpm.state.nv.orderly.clock_safe, new.nv.orderly.clock_safe);
    assert_eq!(tpm.state.nv.index.as_slice(), &nv[..]);

    // The NV data still holds the manufactured TPM: `_TPM_Init` reloads its seeds.
    power_on_start_up(&mut *tpm);
    assert_eq!(tpm.state.nv.persistent.sp_seed_size, 64);
}

/// A state over an owned NV medium has a `Default` (a new TPM with an empty medium), and every
/// NV medium is an `IndexState` in the storage manager's layout.
#[test]
fn state_default_and_index_state_of_a_medium() {
    let mut state = Box::<State<CountingPlatform>>::default();
    assert_eq!(state.nv.index.nv_capacity(), NV_SIZE);
    assert!(
        state
            .nv
            .index
            .items()
            .unwrap()
            .iter()
            .all(|i| i.in_use == 0)
    );
    state.nv.index.define_space(0x0150_0000, 4, 0).unwrap();
    state.nv.index.write_item(0x0150_0000, 0, b"data").unwrap();
    state.nv.index.write_reserved(0, &[1, 2]).unwrap();
    let mut buf = [0u8; 4];
    state.nv.index.read_item(0x0150_0000, 0, &mut buf).unwrap();
    assert_eq!(&buf, b"data");
    // The reserved header is limited to its 128 octets.
    assert!(state.nv.index.write_reserved(127, &[0, 0]).is_err());
    assert!(state.nv.index.read_reserved(120, &mut [0; 9]).is_err());
}
