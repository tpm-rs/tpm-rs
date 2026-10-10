#![forbid(unsafe_code)]

//! A TPM 2.0 Simulator that runs a TCP server accepting TPM commands over the MSSIM protocol.

use clap::Parser;

use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;
use tpm2_simulator::{Args, Simulator};

use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
use tpm2_platform_linux::{LinuxTimer, PlatformCryptoProvider};

/// Process a single command server client connection.
pub fn handle_client(simulator: &Mutex<Simulator>, mut stream: TcpStream) {
    loop {
        let mut cmd_buf = [0u8; 4];
        use std::io::Read;
        if stream.read_exact(&mut cmd_buf).is_err() {
            break;
        }
        let command = u32::from_be_bytes(cmd_buf);

        let mut sim = simulator.lock().unwrap();
        match sim.handle_regular_command_raw(command, &mut stream) {
            Ok(should_break) => {
                if should_break {
                    break;
                }
            }
            Err(e) => {
                eprintln!("Command connection error: {}. Disconnecting client.", e);
                break;
            }
        }
    }
}

/// Process a single platform server client connection.
pub fn handle_platform_client(simulator: &Mutex<Simulator>, mut stream: TcpStream) {
    loop {
        let mut cmd_buf = [0u8; 4];
        use std::io::Read;
        if stream.read_exact(&mut cmd_buf).is_err() {
            break;
        }
        let command = u32::from_be_bytes(cmd_buf);

        let mut sim = simulator.lock().unwrap();

        match sim.handle_platform_command_raw(command, &mut stream) {
            Ok(should_break) => {
                if should_break {
                    break;
                }
            }
            Err(e) => {
                eprintln!("Platform connection error: {}. Disconnecting client.", e);
                break;
            }
        }
    }
}

/// Starts the servers, optionally picking ports if they are in use.
pub fn start_servers(pick_ports: bool) -> std::io::Result<(TcpListener, u16, TcpListener, u16)> {
    let mut base_port = 2321;
    loop {
        match TcpListener::bind(("127.0.0.1", base_port)) {
            Ok(tpm_listener) => {
                let plat_port = base_port + 1;
                match TcpListener::bind(("127.0.0.1", plat_port)) {
                    Ok(plat_listener) => {
                        return Ok((tpm_listener, base_port, plat_listener, plat_port));
                    }
                    Err(e) if pick_ports && e.kind() == std::io::ErrorKind::AddrInUse => {
                        base_port += 2;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) if pick_ports && e.kind() == std::io::ErrorKind::AddrInUse => {
                base_port += 2;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

fn main() {
    let args = Args::parse();
    let (tpm_listener, tpm_port, plat_listener, plat_port) =
        start_servers(args.pick_ports).expect("Failed to start servers");

    // Write ports to files for tpm2-client compatibility
    let write_atomic = |name: &str, port: u16| {
        let tmp = format!("{name}.tmp");
        let _ = std::fs::write(&tmp, port.to_string());
        let _ = std::fs::rename(&tmp, name);
    };
    write_atomic("platform.port", plat_port);
    write_atomic("command.port", tpm_port);

    println!("TPM Command Server listening on port {}", tpm_port);
    println!("Platform Server listening on port {}", plat_port);

    // PORTING: exp also created the platform RNG (`LinuxRng`) here; the TPM's global RNG is now
    // created from the crypto backend by `Simulator::new`.
    let crypto: PlatformCryptoProvider = PlatformCryptoProvider;
    let mut storage: RamStorageMock<4096> = RamStorageMock::new();
    let mut timer: LinuxTimer = LinuxTimer::new();
    let sim = Mutex::new(Simulator::new(&crypto, &mut storage, &mut timer).unwrap());

    thread::scope(|s| {
        s.spawn(|| {
            for stream in plat_listener.incoming() {
                match stream {
                    Ok(stream) => {
                        handle_platform_client(&sim, stream);
                    }
                    Err(e) => eprintln!("Platform connection failed: {}", e),
                }
            }
        });
        s.spawn(|| {
            for stream in tpm_listener.incoming() {
                match stream {
                    Ok(stream) => {
                        handle_client(&sim, stream);
                    }
                    Err(e) => eprintln!("Command connection failed: {}", e),
                }
            }
        });
    });
}
