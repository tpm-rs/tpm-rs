use std::{
    fs::{File, OpenOptions},
    process::exit,
};
use tracing::{error, level_filters::LevelFilter};
use tracing_subscriber::{fmt, EnvFilter};

/// This function initializes logging or exit with code -1 if
/// tracing initialization fails. Note that this function may
/// not return.
pub fn init_tracing(verbosity: u8, logfile: Option<&str>, ansi: bool) {
    let Err(err) = init_tracing_inner(verbosity, logfile, ansi) else {
        security_banner();
        return;
    };
    fmt().with_max_level(tracing::Level::WARN).init();
    error!("{err}");
    exit(-1);
}

/// This function initializes logging and return an error when failing to do so
pub fn init_tracing_inner(verbosity: u8, logfile: Option<&str>, ansi: bool) -> Result<(), String> {
    let filter = verbosity_to_filter(verbosity)?;
    let logger = fmt().with_env_filter(filter).with_ansi(ansi);
    if let Some(path) = logfile {
        let file = prepare_log_file(path)?;
        logger.with_writer(file).init();
    } else {
        logger.init();
    }
    Ok(())
}

/// This function converts verbosity count to a filter or returns error on failure
fn verbosity_to_filter(verbosity: u8) -> Result<EnvFilter, String> {
    let level = match verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        3 => LevelFilter::TRACE,
        _ => return Err("Maximum verbosity level supported is 3".to_owned()),
    };
    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env()
        .map_err(|e| format!("Failed to prepare filter: {e}"))?;
    Ok(filter)
}

fn prepare_log_file(path: &str) -> Result<File, String> {
    OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("Failed to open {path}: {e}"))
}

/// Sadly there may be ways for a user to hide this message without disabling
/// tracing at build time. But at least it will not be "accidental".
/// TODO: move to server but that can only be done after we have debugging
/// infrastructure: <https://github.com/tpm-rs/tpm-rs/issues/99>
fn security_banner() {
    error!("+==================================================+");
    error!("|         DANGER: DO NOT USE IN PRODUCTION         |");
    error!("+--------------------------------------------------+");
    error!("| This build is debug build. It is no meant to run |");
    error!("| in production environment. You may accidentally  |");
    error!("| leak critial traces even if you cannot see them  |");
    error!("| in this log.                                     |");
    error!("+==================================================+");
}
