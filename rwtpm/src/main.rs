mod args;
mod helpers;
mod logging;
mod platform;
mod stream;

use args::Cli;
use clap::Parser;
use helpers::slice_to_hex_string;
use logging::init_tracing;
use platform::SwDeps;
use std::process::exit;
use stream::open_stream;
use tpm2_rs_server::TpmContext;
use tracing::{debug, error, trace};

const MAX_COMMAND_SIZE: usize = 64 * 1024;

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbosity, cli.logfile.as_deref(), !cli.no_color);
    let mut stream = match open_stream(&cli.command) {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to open stream: {e}");
            exit(-1);
        }
    };
    let mut tpm: TpmContext<SwDeps> = match TpmContext::new() {
        Ok(tpm) => tpm,
        Err(e) => {
            error!("Failed to initialize tpm: {e}");
            return;
        }
    };
    let mut buffer = vec![0u8; MAX_COMMAND_SIZE];
    loop {
        let size_in = match stream.read(buffer.as_mut()) {
            Err(e) => {
                error!("Failed to read socket data: {e}");
                break;
            }
            Ok(size) => size,
        };
        trace!("Data in = {}", slice_to_hex_string(&buffer[..size_in]));
        let size_out = tpm.execute_command_in_place(buffer.as_mut(), size_in);
        trace!("Data out = {}", slice_to_hex_string(&buffer[..size_out]));
        if let Err(e) = stream.write_all(&buffer[..size_out]) {
            error!("Failed to write TCP data: {e}");
            break;
        }
    }
    debug!("Shutting down");
}
