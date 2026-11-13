//! Repository automation tasks (`cargo xtask`) for `tpm-rs`.

#![forbid(unsafe_code)]
#![forbid(unreachable_pub)]

mod cli;
mod elf;
mod report;
mod runner;
mod vcs;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

fn main() -> ExitCode {
    match try_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn try_main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse_args(&args)? {
        cli::Command::Help => {
            print!("{}", cli::HELP_TEXT);
            Ok(())
        }
        cli::Command::Size(opts) => runner::run_size(&opts),
    }
}
