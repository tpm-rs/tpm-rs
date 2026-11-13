//! Command-line argument parser for `cargo xtask`.

pub(crate) const HELP_TEXT: &str = "\
Usage:
  cargo xtask size [OPTIONS]

Subcommands:
  size                  Measure freestanding binary-size deltas across bare-metal targets

Options for `size`:
  --base <REV>          Base Git/Jujutsu revision to compare against [default: HEAD^1]
  --head <REV>          Head revision (or WORKDIR for live tree) [default: HEAD]
  --fail-on-bytes <N>   Exit 1 if any row's Total VM grows by more than N bytes
  -h, --help            Print help
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Help,
    Size(SizeArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SizeArgs {
    pub(crate) base: String,
    pub(crate) head: String,
    pub(crate) fail_on_bytes: Option<u64>,
}

pub(crate) fn parse_args(args: &[String]) -> Result<Command, String> {
    let Some(first) = args.first().map(String::as_str) else {
        return Ok(Command::Help);
    };
    match first {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "size" => parse_size_args(&args[1..]),
        other => Err(format!(
            "unknown subcommand `{other}` (expected `size`; pass `--help` for usage)"
        )),
    }
}

fn parse_size_args(args: &[String]) -> Result<Command, String> {
    let mut base = String::from("HEAD^1");
    let mut head = String::from("HEAD");
    let mut fail_on_bytes = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--base" => {
                base = next_value(&mut iter, "--base")?;
            }
            "--head" => {
                head = next_value(&mut iter, "--head")?;
            }
            "--fail-on-bytes" => {
                let raw = next_value(&mut iter, "--fail-on-bytes")?;
                let parsed = raw.parse::<u64>().map_err(|_| {
                    format!(
                        "invalid `--fail-on-bytes` value `{raw}`: expected non-negative integer"
                    )
                })?;
                fail_on_bytes = Some(parsed);
            }
            other if other.starts_with("--base=") => {
                base = value_after_eq(other, "--base")?;
            }
            other if other.starts_with("--head=") => {
                head = value_after_eq(other, "--head")?;
            }
            other if other.starts_with("--fail-on-bytes=") => {
                let raw = value_after_eq(other, "--fail-on-bytes")?;
                let parsed = raw.parse::<u64>().map_err(|_| {
                    format!(
                        "invalid `--fail-on-bytes` value `{raw}`: expected non-negative integer"
                    )
                })?;
                fail_on_bytes = Some(parsed);
            }
            other => {
                return Err(format!(
                    "unknown argument `{other}` for `cargo xtask size` (pass `--help` for usage)"
                ));
            }
        }
    }

    Ok(Command::Size(SizeArgs {
        base,
        head,
        fail_on_bytes,
    }))
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, String> {
    let val = iter
        .next()
        .ok_or_else(|| format!("missing value for `{flag}`"))?;
    if val.is_empty() {
        return Err(format!("empty value for `{flag}`"));
    }
    Ok(val.clone())
}

fn value_after_eq(arg: &str, flag: &str) -> Result<String, String> {
    let (_, val) = arg.split_once('=').unwrap_or(("", ""));
    if val.is_empty() {
        return Err(format!("empty value for `{flag}`"));
    }
    Ok(val.to_owned())
}
