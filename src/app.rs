use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    OpenProcess,
    ExistingHandle,
}

impl ConnectionMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::OpenProcess => "OpenProcess (read-only)",
            Self::ExistingHandle => "Existing handle (explicitly supplied)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub connection: ConnectionMode,
    pub pid: u32,
    pub existing_handle: Option<u64>,
    pub output: PathBuf,
    pub make_jar: bool,
}

pub fn prompt_config() -> Result<AppConfig> {
    println!("\n  JVM External Dumper · HotSpot 8\n");
    println!("Connection:");
    println!("  1) OpenProcess (recommended, read-only)");
    println!("  2) Existing handle (only a handle explicitly supplied by the operator)");

    let connection = match prompt("Select [1]: ")?.as_str() {
        "" | "1" => ConnectionMode::OpenProcess,
        "2" => ConnectionMode::ExistingHandle,
        _ => bail!("unknown connection mode"),
    };
    let pid = prompt("Target PID: ")?
        .parse::<u32>()
        .context("PID must be an unsigned integer")?;
    let existing_handle = if connection == ConnectionMode::ExistingHandle {
        Some(parse_handle(&prompt(
            "Inherited HANDLE (decimal or 0x...): ",
        )?)?)
    } else {
        None
    };
    let output_text = prompt("Output directory [./dump]: ")?;
    let output = if output_text.is_empty() {
        PathBuf::from("dump")
    } else {
        output_text.into()
    };
    let make_jar = prompt_yes_no("Create classes.jar", true)?;

    Ok(AppConfig {
        connection,
        pid,
        existing_handle,
        output,
        make_jar,
    })
}

fn parse_handle(value: &str) -> Result<u64> {
    let value = value.trim();
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).context("HANDLE must contain hexadecimal digits")?
    } else {
        value
            .parse::<u64>()
            .context("HANDLE must be an unsigned integer or 0x-prefixed hexadecimal value")?
    };
    if parsed == 0 || parsed == u64::MAX {
        bail!("HANDLE cannot be NULL or INVALID_HANDLE_VALUE")
    }
    Ok(parsed)
}

fn prompt_yes_no(label: &str, default: bool) -> Result<bool> {
    let suffix = if default { "Y/n" } else { "y/N" };
    match prompt(&format!("{label} [{suffix}]: "))?
        .to_ascii_lowercase()
        .as_str()
    {
        "" => Ok(default),
        "y" | "yes" | "1" => Ok(true),
        "n" | "no" | "0" => Ok(false),
        _ => bail!("expected yes or no"),
    }
}

fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    io::stdout().flush().context("failed to flush stdout")?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .context("failed to read stdin")?;
    Ok(value.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::parse_handle;

    #[test]
    fn handle_accepts_decimal_and_hexadecimal() {
        assert_eq!(parse_handle("4660").unwrap(), 0x1234);
        assert_eq!(parse_handle("0x1234").unwrap(), 0x1234);
        assert!(parse_handle("0").is_err());
    }
}
