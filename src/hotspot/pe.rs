use std::collections::HashMap;

use anyhow::{Context, Result, bail};

use crate::platform::RemoteMemory;

const DOS_MAGIC: u16 = 0x5a4d;
const PE_MAGIC: u32 = 0x0000_4550;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const MAX_EXPORTS: usize = 100_000;

pub struct RemotePe<'a, M> {
    memory: &'a M,
    base: u64,
}

impl<'a, M: RemoteMemory> RemotePe<'a, M> {
    pub const fn new(memory: &'a M, base: u64) -> Self {
        Self { memory, base }
    }

    pub fn exports(&self) -> Result<HashMap<String, u64>> {
        if self.memory.read_u16(self.base)? != DOS_MAGIC {
            bail!("jvm.dll has an invalid DOS header");
        }
        let nt = self.base + self.memory.read_u32(self.base + 0x3c)? as u64;
        if self.memory.read_u32(nt)? != PE_MAGIC {
            bail!("jvm.dll has an invalid PE signature");
        }

        let optional = nt + 24;
        if self.memory.read_u16(optional)? != PE32_PLUS_MAGIC {
            bail!("target jvm.dll is not PE32+; only x64 HotSpot is currently supported");
        }
        let export_rva = self.memory.read_u32(optional + 112)?;
        if export_rva == 0 {
            bail!("jvm.dll has no PE export directory");
        }
        let directory = self.base + export_rva as u64;
        let function_count = self.memory.read_u32(directory + 20)? as usize;
        let name_count = self.memory.read_u32(directory + 24)? as usize;
        if name_count > MAX_EXPORTS || function_count > MAX_EXPORTS {
            bail!("unreasonable PE export count");
        }

        let functions = self.base + self.memory.read_u32(directory + 28)? as u64;
        let names = self.base + self.memory.read_u32(directory + 32)? as u64;
        let ordinals = self.base + self.memory.read_u32(directory + 36)? as u64;
        let mut result = HashMap::with_capacity(name_count);

        for index in 0..name_count {
            let name_rva = self.memory.read_u32(names + (index * 4) as u64)?;
            let name = self
                .memory
                .read_c_string(self.base + name_rva as u64, 512)
                .with_context(|| format!("invalid PE export name #{index}"))?;
            let ordinal = self.memory.read_u16(ordinals + (index * 2) as u64)? as usize;
            if ordinal >= function_count {
                bail!("invalid PE export ordinal for {name}");
            }
            let function_rva = self.memory.read_u32(functions + (ordinal * 4) as u64)?;
            result.insert(name, self.base + function_rva as u64);
        }
        Ok(result)
    }
}
