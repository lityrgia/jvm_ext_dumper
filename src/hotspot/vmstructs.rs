use std::collections::HashMap;

use anyhow::{Context, Result, bail};

use crate::platform::RemoteMemory;

const MAX_VM_STRUCTS: usize = 100_000;

#[derive(Debug, Clone)]
pub struct VmStructEntry {
    pub type_name: String,
    pub field_name: String,
    pub offset: u64,
    pub address: u64,
}

#[derive(Debug)]
pub struct VmStructTable {
    pub entries: Vec<VmStructEntry>,
}

#[derive(Debug)]
struct Layout {
    type_name: u64,
    field_name: u64,
    type_string: u64,
    is_static: u64,
    offset: u64,
    address: u64,
    stride: u64,
}

impl VmStructTable {
    pub(crate) fn inferred(entries: Vec<VmStructEntry>) -> Self {
        Self { entries }
    }

    pub fn read<M: RemoteMemory>(memory: &M, exports: &HashMap<String, u64>) -> Result<Self> {
        let table = read_export_u64(memory, exports, "gHotSpotVMStructs")?;
        let layout = Layout {
            type_name: read_export_u64(memory, exports, "gHotSpotVMStructEntryTypeNameOffset")?,
            field_name: read_export_u64(memory, exports, "gHotSpotVMStructEntryFieldNameOffset")?,
            type_string: read_export_u64(memory, exports, "gHotSpotVMStructEntryTypeStringOffset")?,
            is_static: read_export_u64(memory, exports, "gHotSpotVMStructEntryIsStaticOffset")?,
            offset: read_export_u64(memory, exports, "gHotSpotVMStructEntryOffsetOffset")?,
            address: read_export_u64(memory, exports, "gHotSpotVMStructEntryAddressOffset")?,
            stride: read_export_u64(memory, exports, "gHotSpotVMStructEntryArrayStride")?,
        };
        if table == 0 || !(32..=256).contains(&layout.stride) {
            bail!("invalid VMStructs table layout");
        }

        let mut entries = Vec::new();
        for index in 0..MAX_VM_STRUCTS {
            let row = table + index as u64 * layout.stride;
            let type_name_ptr = memory.read_u64(row + layout.type_name)?;
            if type_name_ptr == 0 {
                return Ok(Self { entries });
            }
            let field_name_ptr = memory.read_u64(row + layout.field_name)?;
            if field_name_ptr == 0 {
                bail!("VMStructs entry #{index} has no field name");
            }
            let type_string_ptr = memory.read_u64(row + layout.type_string)?;
            if type_string_ptr != 0 {
                memory.read_c_string(type_string_ptr, 512)?;
            }
            entries.push(VmStructEntry {
                type_name: memory.read_c_string(type_name_ptr, 512)?,
                field_name: memory.read_c_string(field_name_ptr, 512)?,
                // Reading the marker is part of validating the exported row,
                // even though reconstruction only needs offset and address.
                offset: memory.read_u64(row + layout.offset)?,
                address: memory.read_u64(row + layout.address)?,
            });
            memory.read_u32(row + layout.is_static)?;
        }
        bail!("VMStructs table exceeds safety limit")
    }

    pub fn find(&self, type_name: &str, field_name: &str) -> Option<&VmStructEntry> {
        self.entries
            .iter()
            .find(|entry| entry.type_name == type_name && entry.field_name == field_name)
    }
}

fn read_export_u64<M: RemoteMemory>(
    memory: &M,
    exports: &HashMap<String, u64>,
    name: &str,
) -> Result<u64> {
    let address = exports
        .get(name)
        .copied()
        .with_context(|| format!("jvm.dll does not export {name}"))?;
    memory
        .read_u64(address)
        .with_context(|| format!("cannot read exported value {name}"))
}
