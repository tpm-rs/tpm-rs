# tpm2-tcp

A connection to the [TCG TPM 2.0 Simulator] over TCP.

This crate provides:

- `TcpConnection`, which talks to a running simulator and implements the
  `tpm2::Connection` trait. It also exposes the simulator's platform controls
  (power, NV, physical presence, etc.).
- `TcpSimulator`, which starts a simulator binary, connects to it, and stops it
  when dropped.

## Example

```rust,no_run
use tpm2::Connection;
use tpm2_tcp::TcpConnection;

# fn main() -> std::io::Result<()> {
let mut tpm = TcpConnection::connect("127.0.0.1", None, None)?;
let mut response = [0u8; 4096];
// TPM2_GetRandom(8)
let command = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x7b, 0, 0x08];
let response = tpm.transact(&command, &mut response)?;
# Ok(())
# }
```

## Feature flags

This crate has no feature flags.

[TCG TPM 2.0 Simulator]: https://github.com/TrustedComputingGroup/TPM
