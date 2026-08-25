use std::collections::HashSet;

use anyhow::{Context, Result, bail};

use crate::platform::RemoteMemory;

use super::vmstructs::VmStructTable;

const MAX_BUCKETS: usize = 1_000_000;
const MAX_ENTRIES: usize = 10_000_000;

#[derive(Debug, Clone)]
pub struct DiscoveredClass {
    pub klass: u64,
    pub internal_name: String,
}

pub fn walk<M: RemoteMemory>(
    memory: &M,
    dictionary: u64,
    vm: &VmStructTable,
) -> Result<Vec<DiscoveredClass>> {
    if dictionary == 0 {
        bail!("SystemDictionary::_dictionary is null");
    }
    let table_size_off = offset(vm, "BasicHashtable<mtInternal>", "_table_size")?;
    let buckets_off = offset(vm, "BasicHashtable<mtInternal>", "_buckets")?;
    let bucket_entry_off = offset(vm, "HashtableBucket<mtInternal>", "_entry")?;
    let next_off = offset(vm, "BasicHashtableEntry<mtInternal>", "_next")?;
    let literal_off = offset(vm, "IntptrHashtableEntry", "_literal")?;
    let klass_name_off = offset(vm, "Klass", "_name")?;
    let symbol_length_off = offset(vm, "Symbol", "_length")?;
    let symbol_body_off = offset(vm, "Symbol", "_body")?;

    let table_size = memory.read_u32(dictionary + table_size_off)? as usize;
    let buckets = memory.read_u64(dictionary + buckets_off)?;
    if table_size == 0 || table_size > MAX_BUCKETS || buckets == 0 {
        bail!("invalid Dictionary layout: table_size={table_size}, buckets=0x{buckets:016x}");
    }

    let mut visited_entries = HashSet::new();
    let mut visited_klasses = HashSet::new();
    let mut classes = Vec::new();
    for bucket in 0..table_size {
        let bucket_address = buckets + bucket as u64 * 8;
        let mut entry = memory.read_u64(bucket_address + bucket_entry_off)? & !1_u64;
        while entry != 0 {
            if !visited_entries.insert(entry) {
                break;
            }
            if visited_entries.len() > MAX_ENTRIES {
                bail!("Dictionary entry safety limit exceeded");
            }
            let klass = memory.read_u64(entry + literal_off)?;
            if klass != 0
                && visited_klasses.insert(klass)
                && let Ok(name) = read_klass_name(
                    memory,
                    klass,
                    klass_name_off,
                    symbol_length_off,
                    symbol_body_off,
                )
            {
                classes.push(DiscoveredClass {
                    klass,
                    internal_name: name,
                });
            }
            entry = memory.read_u64(entry + next_off)? & !1_u64;
        }
    }
    classes.sort_unstable_by(|left, right| left.internal_name.cmp(&right.internal_name));
    Ok(classes)
}

fn read_klass_name<M: RemoteMemory>(
    memory: &M,
    klass: u64,
    name_off: u64,
    length_off: u64,
    body_off: u64,
) -> Result<String> {
    let symbol = memory.read_u64(klass + name_off)?;
    if symbol == 0 {
        bail!("null Klass::_name");
    }
    let length = memory.read_u16(symbol + length_off)? as usize;
    if length == 0 || length > 65_535 {
        bail!("invalid Symbol length");
    }
    let mut bytes = vec![0; length];
    memory.read_exact(symbol + body_off, &mut bytes)?;
    String::from_utf8(bytes).context("class Symbol is not modified UTF-8 compatible ASCII/UTF-8")
}

fn offset(vm: &VmStructTable, type_name: &str, field_name: &str) -> Result<u64> {
    vm.find(type_name, field_name)
        .map(|entry| entry.offset)
        .with_context(|| format!("VMStructs has no {type_name}::{field_name}"))
}
