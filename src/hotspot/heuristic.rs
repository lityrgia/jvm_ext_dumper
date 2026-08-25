use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};

use crate::platform::RemoteMemory;

use super::{
    vmstructs::{VmStructEntry, VmStructTable},
    vmtypes::VmTypes,
};

const PAGE_SIZE: usize = 0x1000;
const VMSTRUCT_STRIDE: u64 = 48;
const VMTYPE_STRIDE: u64 = 40;
const MAX_ROWS: usize = 100_000;

pub struct InferredLayout {
    pub structs: VmStructTable,
    pub types: VmTypes,
}

struct Page {
    base: u64,
    bytes: Vec<u8>,
}

struct ModuleImage {
    pages: Vec<Page>,
}

impl ModuleImage {
    fn capture<M: RemoteMemory>(memory: &M, base: u64, size: usize) -> Result<Self> {
        if size == 0 || size > 512 * 1024 * 1024 {
            bail!("unreasonable jvm.dll image size")
        }
        let mut pages = Vec::new();
        for offset in (0..size).step_by(PAGE_SIZE) {
            let length = PAGE_SIZE.min(size - offset);
            let mut bytes = vec![0; length];
            if memory.read_exact(base + offset as u64, &mut bytes).is_ok() {
                pages.push(Page {
                    base: base + offset as u64,
                    bytes,
                });
            }
        }
        if pages.is_empty() {
            bail!("no readable pages in jvm.dll")
        }
        Ok(Self { pages })
    }

    fn find_c_strings(&self, value: &str) -> Vec<u64> {
        let mut needle = value.as_bytes().to_vec();
        needle.push(0);
        let mut result = Vec::new();
        for page in &self.pages {
            for (offset, window) in page.bytes.windows(needle.len()).enumerate() {
                if window == needle {
                    result.push(page.base + offset as u64);
                }
            }
        }
        result
    }

    fn aligned_pointer_locations(&self, wanted: &HashSet<u64>) -> Vec<(u64, u64)> {
        let mut result = Vec::new();
        for page in &self.pages {
            let first = ((8 - (page.base as usize & 7)) & 7).min(page.bytes.len());
            for offset in (first..page.bytes.len().saturating_sub(7)).step_by(8) {
                let value = u64::from_le_bytes(page.bytes[offset..offset + 8].try_into().unwrap());
                if wanted.contains(&value) {
                    result.push((page.base + offset as u64, value));
                }
            }
        }
        result
    }
}

pub fn infer<M: RemoteMemory>(
    memory: &M,
    module_base: u64,
    module_size: usize,
) -> Result<InferredLayout> {
    let image = ModuleImage::capture(memory, module_base, module_size)?;
    let structs = infer_vmstructs(memory, &image)?;
    let types = infer_vmtypes(memory, &image)?;
    Ok(InferredLayout { structs, types })
}

fn infer_vmstructs<M: RemoteMemory>(memory: &M, image: &ModuleImage) -> Result<VmStructTable> {
    let type_addresses = image.find_c_strings("SystemDictionary");
    let field_addresses = image.find_c_strings("_dictionary");
    if type_addresses.is_empty() || field_addresses.is_empty() {
        bail!("VMStruct anchor strings are absent")
    }
    let wanted = type_addresses.iter().copied().collect::<HashSet<_>>();
    let field_addresses = field_addresses.into_iter().collect::<HashSet<_>>();
    let mut best: Option<(usize, Vec<VmStructEntry>)> = None;

    for (row, _) in image.aligned_pointer_locations(&wanted) {
        if !field_addresses.contains(&memory.read_u64(row + 8).unwrap_or(0)) {
            continue;
        }
        if let Ok(entries) = parse_vmstruct_table(memory, row) {
            let score = vmstruct_score(&entries);
            if best.as_ref().is_none_or(|(old, _)| score > *old) {
                best = Some((score, entries));
            }
        }
    }

    let (score, entries) = best.context("could not locate a valid internal VMStructs table")?;
    if score < REQUIRED_VMSTRUCTS.len() {
        bail!(
            "internal VMStructs candidate failed validation ({score}/{} required fields)",
            REQUIRED_VMSTRUCTS.len()
        )
    }
    Ok(VmStructTable::inferred(entries))
}

fn parse_vmstruct_table<M: RemoteMemory>(memory: &M, anchor: u64) -> Result<Vec<VmStructEntry>> {
    let mut start = anchor;
    for _ in 0..MAX_ROWS {
        let Some(previous) = start.checked_sub(VMSTRUCT_STRIDE) else {
            break;
        };
        if read_vmstruct_row(memory, previous)?.is_none() {
            break;
        }
        start = previous;
    }

    let mut entries = Vec::new();
    for index in 0..MAX_ROWS {
        let row = start + index as u64 * VMSTRUCT_STRIDE;
        match read_vmstruct_row(memory, row)? {
            Some(entry) => entries.push(entry),
            None => break,
        }
    }
    if entries.len() < 100 {
        bail!("VMStructs candidate is too short")
    }
    Ok(entries)
}

fn read_vmstruct_row<M: RemoteMemory>(memory: &M, row: u64) -> Result<Option<VmStructEntry>> {
    let type_ptr = memory.read_u64(row)?;
    if type_ptr == 0 {
        return Ok(None);
    }
    let field_ptr = memory.read_u64(row + 8)?;
    if field_ptr == 0 {
        bail!("invalid VMStruct field pointer")
    }
    let type_string_ptr = memory.read_u64(row + 16)?;
    let is_static = memory.read_u32(row + 24)?;
    if is_static > 1 {
        bail!("invalid VMStruct static marker")
    }
    let offset = memory.read_u64(row + 32)?;
    let address = memory.read_u64(row + 40)?;
    if is_static == 0 && offset > 0x10_000 {
        bail!("implausible VMStruct offset")
    }
    let type_name = read_table_string(memory, type_ptr)?;
    let field_name = read_table_string(memory, field_ptr)?;
    if type_string_ptr != 0 {
        read_table_string(memory, type_string_ptr)?;
    }
    Ok(Some(VmStructEntry {
        type_name,
        field_name,
        offset,
        address,
    }))
}

fn infer_vmtypes<M: RemoteMemory>(memory: &M, image: &ModuleImage) -> Result<VmTypes> {
    let names = image.find_c_strings("ConstantPool");
    if names.is_empty() {
        bail!("VMTypes anchor string is absent")
    }
    let wanted = names.iter().copied().collect::<HashSet<_>>();
    let mut best: Option<(usize, HashMap<String, u64>)> = None;
    for (row, _) in image.aligned_pointer_locations(&wanted) {
        if let Ok(sizes) = parse_vmtype_table(memory, row) {
            let score = REQUIRED_TYPES
                .iter()
                .filter(|name| sizes.contains_key(**name))
                .count();
            if best.as_ref().is_none_or(|(old, _)| score > *old) {
                best = Some((score, sizes));
            }
        }
    }
    let (score, sizes) = best.context("could not locate a valid internal VMTypes table")?;
    if score != REQUIRED_TYPES.len() {
        bail!("internal VMTypes candidate failed validation")
    }
    Ok(VmTypes::inferred(sizes))
}

fn parse_vmtype_table<M: RemoteMemory>(memory: &M, anchor: u64) -> Result<HashMap<String, u64>> {
    let mut start = anchor;
    for _ in 0..MAX_ROWS {
        let Some(previous) = start.checked_sub(VMTYPE_STRIDE) else {
            break;
        };
        if read_vmtype_row(memory, previous)?.is_none() {
            break;
        }
        start = previous;
    }
    let mut sizes = HashMap::new();
    for index in 0..MAX_ROWS {
        let row = start + index as u64 * VMTYPE_STRIDE;
        let Some((name, size)) = read_vmtype_row(memory, row)? else {
            break;
        };
        sizes.insert(name, size);
    }
    if sizes.len() < 50 {
        bail!("VMTypes candidate is too short")
    }
    Ok(sizes)
}

fn read_vmtype_row<M: RemoteMemory>(memory: &M, row: u64) -> Result<Option<(String, u64)>> {
    let name_ptr = memory.read_u64(row)?;
    if name_ptr == 0 {
        return Ok(None);
    }
    let super_ptr = memory.read_u64(row + 8)?;
    for offset in [16, 20, 24] {
        if memory.read_u32(row + offset)? > 1 {
            bail!("invalid VMType boolean")
        }
    }
    let size = memory.read_u64(row + 32)?;
    if size == 0 || size > 0x10_000 {
        bail!("implausible VMType size")
    }
    let name = read_table_string(memory, name_ptr)?;
    if super_ptr != 0 {
        read_table_string(memory, super_ptr)?;
    }
    Ok(Some((name, size)))
}

fn read_table_string<M: RemoteMemory>(memory: &M, address: u64) -> Result<String> {
    let value = memory.read_c_string(address, 512)?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
    {
        bail!("invalid table string")
    }
    Ok(value)
}

fn vmstruct_score(entries: &[VmStructEntry]) -> usize {
    REQUIRED_VMSTRUCTS
        .iter()
        .filter(|(ty, field)| {
            entries
                .iter()
                .any(|entry| entry.type_name == *ty && entry.field_name == *field)
        })
        .count()
}

const REQUIRED_TYPES: &[&str] = &[
    "ConstantPool",
    "ConstMethod",
    "ConstantPoolCache",
    "ConstantPoolCacheEntry",
];

const REQUIRED_VMSTRUCTS: &[(&str, &str)] = &[
    ("SystemDictionary", "_dictionary"),
    ("BasicHashtable<mtInternal>", "_table_size"),
    ("BasicHashtable<mtInternal>", "_buckets"),
    ("HashtableBucket<mtInternal>", "_entry"),
    ("BasicHashtableEntry<mtInternal>", "_next"),
    ("IntptrHashtableEntry", "_literal"),
    ("Klass", "_name"),
    ("Klass", "_super"),
    ("Klass", "_access_flags"),
    ("Symbol", "_length"),
    ("Symbol", "_body"),
    ("InstanceKlass", "_constants"),
    ("InstanceKlass", "_fields"),
    ("InstanceKlass", "_methods"),
    ("ConstantPool", "_tags"),
    ("ConstantPool", "_length"),
    ("Method", "_constMethod"),
    ("ConstMethod", "_code_size"),
];
