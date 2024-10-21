mod args;
mod logging;
mod platform;

use args::Cli;
use clap::Parser;
use logging::init_tracing;
use tracing::error;

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbosity, cli.logfile.as_deref(), !cli.no_color);
    error!("Hello, world!");
}
