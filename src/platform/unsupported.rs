use super::{MemoryRegion, ModuleInfo, RemoteMemory};
use anyhow::{Result, bail};

pub struct TargetProcess;
impl TargetProcess {
    pub fn open_read_only(_pid: u32) -> Result<Self> {
        bail!("Windows is required")
    }
    pub fn from_existing_handle(_pid: u32, _raw_handle: u64) -> Result<Self> {
        bail!("Windows is required")
    }
    pub fn pid(&self) -> u32 {
        0
    }
    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        bail!("Windows is required")
    }
    pub fn readable_regions(&self) -> Result<Vec<MemoryRegion>> {
        bail!("Windows is required")
    }
}
impl RemoteMemory for TargetProcess {
    fn read_exact(&self, _address: u64, _destination: &mut [u8]) -> Result<()> {
        bail!("Windows is required")
    }
}
