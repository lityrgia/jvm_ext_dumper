pub mod dictionary;
pub mod discovery;
pub mod heuristic;
pub mod pe;
pub mod reconstruct;
pub mod structural;
pub mod vmstructs;
pub mod vmtypes;

use crate::{app::AppConfig, platform::TargetProcess};
use anyhow::Result;
use discovery::{DiscoveryReport, locate_hotspot};

pub fn inspect(process: &TargetProcess, config: &AppConfig) -> Result<DiscoveryReport> {
    let report = locate_hotspot(process, &config.output)?;
    if config.make_jar && report.classfiles_written > 0 {
        reconstruct::make_jar(&config.output)?;
    }
    Ok(report)
}
