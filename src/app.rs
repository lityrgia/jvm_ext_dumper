use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub pid: u32,
    pub output: PathBuf,
}

pub fn prompt_config() -> Result<AppConfig> {
    println!("\n  JVM External Dumper · HotSpot 8\n");
    let pid = prompt("Target PID: ")?
        .parse::<u32>()
        .context("PID must be an unsigned integer")?;
    let output_text = prompt("Output directory [./dump]: ")?;
    let output = if output_text.is_empty() {
        PathBuf::from("dump")
    } else {
        output_text.into()
    };
    Ok(AppConfig { pid, output })
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
