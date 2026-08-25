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
    locate_hotspot(process, &config.output)
}
