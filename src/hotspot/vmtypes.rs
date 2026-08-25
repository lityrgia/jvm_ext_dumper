use std::collections::HashMap;

use anyhow::{Context, Result, bail};

use crate::platform::RemoteMemory;

const LIMIT: usize = 100_000;

#[derive(Debug)]
pub struct VmTypes {
    sizes: HashMap<String, u64>,
}

impl VmTypes {
    pub(crate) fn inferred(sizes: HashMap<String, u64>) -> Self {
        Self { sizes }
    }

    pub fn read<M: RemoteMemory>(memory: &M, exports: &HashMap<String, u64>) -> Result<Self> {
        let table = exported(memory, exports, "gHotSpotVMTypes")?;
        let name_off = exported(memory, exports, "gHotSpotVMTypeEntryTypeNameOffset")?;
        let size_off = exported(memory, exports, "gHotSpotVMTypeEntrySizeOffset")?;
        let stride = exported(memory, exports, "gHotSpotVMTypeEntryArrayStride")?;
        if table == 0 || !(24..=256).contains(&stride) {
            bail!("invalid VMTypes layout");
        }
        let mut sizes = HashMap::new();
        for index in 0..LIMIT {
            let row = table + index as u64 * stride;
            let name = memory.read_u64(row + name_off)?;
            if name == 0 {
                return Ok(Self { sizes });
            }
            sizes.insert(
                memory.read_c_string(name, 512)?,
                memory.read_u64(row + size_off)?,
            );
        }
        bail!("VMTypes safety limit exceeded")
    }

    pub fn size(&self, name: &str) -> Result<u64> {
        self.sizes
            .get(name)
            .copied()
            .with_context(|| format!("VMTypes has no size for {name}"))
    }
}

fn exported<M: RemoteMemory>(
    memory: &M,
    exports: &HashMap<String, u64>,
    name: &str,
) -> Result<u64> {
    memory.read_u64(
        *exports
            .get(name)
            .with_context(|| format!("jvm.dll does not export {name}"))?,
    )
}
