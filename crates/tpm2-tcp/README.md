# tpm2-tcp

A connection to the [TCG TPM 2.0 Simulator] over TCP.

This crate provides:

- `TcpConnection`, which talks to a running simulator and implements the
  `tpm2::Connection` trait. It also exposes the simulator's platform controls
  (power, NV, physical presence, etc.).
- `TcpSimulator`, which starts a simulator binary, connects to it, powers on
  its TPM, and stops it when dropped.

## Examples

Start a simulator, and send it a command:

```rust
use std::path::Path;

use tpm2::Connection;
use tpm2_tcp::TcpSimulator;

fn startup() -> std::io::Result<Vec<u8>> {
    let bin = Path::new("/path/to/Simulator");
    let dir = Path::new("/path/to/state");
    let mut simulator = TcpSimulator::launch_in(bin, dir)?;

    // TPM2_Startup(TPM_SU_CLEAR)
    let command = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0];
    let mut response = [0u8; 4096];
    let response = simulator.connection.transact(&command, &mut response)?;
    Ok(response.to_vec())
}
```

Connect to a simulator that is already running:

```rust
use tpm2_tcp::{DEFAULT_PLATFORM_PORT, DEFAULT_TPM_PORT, TcpConnection};

fn power_cycle() -> std::io::Result<()> {
    let mut tpm = TcpConnection::connect(
        ("127.0.0.1", DEFAULT_TPM_PORT),
        ("127.0.0.1", DEFAULT_PLATFORM_PORT),
    )?;
    tpm.reinit()
}
```

## Feature flags

- `tempfile` (on by default): adds `TcpSimulator::launch` and
  `TcpSimulator::launch_from_env`, which run the simulator in a temporary
  directory made with the [`tempfile`] crate.

[TCG TPM 2.0 Simulator]: https://github.com/TrustedComputingGroup/TPM
[`tempfile`]: https://crates.io/crates/tempfile
