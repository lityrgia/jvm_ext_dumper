#[cfg(not(windows))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub use unsupported::TargetProcess;
#[cfg(windows)]
pub use windows::TargetProcess;

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: usize,
}

pub trait RemoteMemory {
    fn read_exact(&self, address: u64, destination: &mut [u8]) -> anyhow::Result<()>;
    fn read_u16(&self, address: u64) -> anyhow::Result<u16> {
        let mut bytes = [0; 2];
        self.read_exact(address, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }
    fn read_u32(&self, address: u64) -> anyhow::Result<u32> {
        let mut bytes = [0; 4];
        self.read_exact(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn read_u64(&self, address: u64) -> anyhow::Result<u64> {
        let mut bytes = [0; 8];
        self.read_exact(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_c_string(&self, address: u64, max_length: usize) -> anyhow::Result<String> {
        let mut value = Vec::new();
        for offset in 0..max_length {
            let mut byte = [0];
            self.read_exact(address + offset as u64, &mut byte)?;
            if byte[0] == 0 {
                return String::from_utf8(value).map_err(Into::into);
            }
            value.push(byte[0]);
        }
        anyhow::bail!("unterminated string at 0x{address:016x}")
    }
}

pub fn ensure_elevated() -> anyhow::Result<()> {
    imp_ensure_elevated()
}

#[cfg(windows)]
fn imp_ensure_elevated() -> anyhow::Result<()> {
    windows::ensure_elevated()
}

#[cfg(not(windows))]
fn imp_ensure_elevated() -> anyhow::Result<()> {
    anyhow::bail!("jvm_ext_dumper runs only on Windows")
}
