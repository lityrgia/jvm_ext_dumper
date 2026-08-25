use std::collections::HashMap;

use anyhow::{Context, Result, bail};

use crate::platform::RemoteMemory;

use crate::hotspot::{
    vmstructs::{VmStructEntry, VmStructTable},
    vmtypes::VmTypes,
};

pub(super) const OBJECT_NAME: &[u8] = b"java/lang/Object";

pub(super) mod offsets {
    pub const KLASS_SUPER: u64 = 0x78;
    pub const KLASS_ACCESS_FLAGS: u64 = 0xa4;

    pub const IK_GENERIC_SIGNATURE_INDEX: u64 = 0xf8;
    pub const IK_JAVA_FIELDS_COUNT: u64 = 0xfe;
    pub const IK_MINOR_VERSION: u64 = 0x10a;
    pub const IK_MAJOR_VERSION: u64 = 0x10c;
    pub const IK_METHODS: u64 = 0x178;
    pub const IK_LOCAL_INTERFACES: u64 = 0x188;
    pub const IK_FIELDS: u64 = 0x1a8;

    pub const CP_CACHE: u64 = 0x18;
    pub const CP_OPERANDS: u64 = 0x28;
    pub const CP_REFERENCE_MAP: u64 = 0x38;

    pub const METHOD_CONST_METHOD: u64 = 0x08;
    pub const METHOD_ACCESS_FLAGS: u64 = 0x28;

    pub const CONST_METHOD_CONSTANT_POOL: u64 = 0x08;
    pub const CONST_METHOD_STACKMAP_DATA: u64 = 0x10;
    pub const CONST_METHOD_SIZE: u64 = 0x18;
    pub const CONST_METHOD_FLAGS: u64 = 0x1c;
    pub const CONST_METHOD_CODE_SIZE: u64 = 0x20;
    pub const CONST_METHOD_NAME_INDEX: u64 = 0x22;
    pub const CONST_METHOD_SIGNATURE_INDEX: u64 = 0x24;
    pub const CONST_METHOD_MAX_STACK: u64 = 0x28;
    pub const CONST_METHOD_MAX_LOCALS: u64 = 0x2a;
}

#[derive(Clone, Copy, Debug)]
pub(super) struct CoreLayout {
    pub klass_name: u64,
    pub ik_constants: u64,
    pub cp_tags: u64,
    pub cp_holder: u64,
    pub cp_length: u64,
    pub cp_size: u64,
}

pub(super) fn infer_core_layout<M: RemoteMemory>(
    memory: &M,
    klass: u64,
    klass_name: u64,
    jvm_base: u64,
    jvm_end: u64,
) -> Result<CoreLayout> {
    if !valid_symbol_at(
        memory,
        memory.read_u64(klass + klass_name)?,
        Some(OBJECT_NAME),
    ) {
        bail!("Klass name does not point to Object Symbol")
    }
    for ik_constants in (0x80_u64..=0x200).step_by(8) {
        let Ok(cp) = memory.read_u64(klass + ik_constants) else {
            continue;
        };
        if cp == 0 {
            continue;
        }
        let Ok(vtable) = memory.read_u64(cp) else {
            continue;
        };
        if !(jvm_base..jvm_end).contains(&vtable) {
            continue;
        }
        for cp_holder in (8_u64..=0x50).step_by(8) {
            if memory.read_u64(cp + cp_holder).ok() != Some(klass) {
                continue;
            }
            for cp_tags in (8_u64..=0x40).step_by(8) {
                let Ok(tags) = memory.read_u64(cp + cp_tags) else {
                    continue;
                };
                let Ok(tag_length) = memory.read_u32(tags) else {
                    continue;
                };
                if !(2..65_535).contains(&tag_length) {
                    continue;
                }
                for cp_length in (0x20_u64..=0x60).step_by(4) {
                    if memory.read_u32(cp + cp_length).ok() != Some(tag_length) {
                        continue;
                    }
                    if let Some(cp_size) = infer_cp_size(memory, cp, tags, tag_length as usize) {
                        return Ok(CoreLayout {
                            klass_name,
                            ik_constants,
                            cp_tags,
                            cp_holder,
                            cp_length,
                            cp_size,
                        });
                    }
                }
            }
        }
    }
    bail!("no self-consistent ConstantPool was found from Object InstanceKlass")
}

fn infer_cp_size<M: RemoteMemory>(memory: &M, cp: u64, tags: u64, length: usize) -> Option<u64> {
    let sample = length.min(512);
    let mut tag_bytes = vec![0; sample];
    memory.read_exact(tags + 4, &mut tag_bytes).ok()?;
    let utf8_count = tag_bytes.iter().filter(|tag| **tag == 1).count();
    if utf8_count < 4 {
        return None;
    }
    let mut best = None;
    for size in (0x38_u64..=0xa0).step_by(8) {
        let mut good = 0;
        for (index, tag) in tag_bytes.iter().enumerate() {
            if *tag != 1 {
                continue;
            }
            let Ok(symbol) = memory.read_u64(cp + size + index as u64 * 8) else {
                continue;
            };
            if valid_symbol_at(memory, symbol, None) {
                good += 1;
            }
        }
        if good == utf8_count && best.is_none_or(|(_, old_good)| good > old_good) {
            best = Some((size, good));
        }
    }
    best.map(|(size, _)| size)
}

pub(super) fn validate_jdk8_profile<M: RemoteMemory>(
    memory: &M,
    object: u64,
    core: &CoreLayout,
    jvm_base: u64,
    jvm_end: u64,
) -> usize {
    let mut score = 0;
    if core.klass_name == 0x10 {
        score += 1;
    }
    if core.ik_constants == 0xd0 {
        score += 1;
    }
    if memory.read_u64(object + offsets::KLASS_SUPER).ok() == Some(0) {
        score += 1;
    }
    if memory
        .read_u32(object + offsets::KLASS_ACCESS_FLAGS)
        .ok()
        .is_some_and(|flags| flags & 0xffff == 0x21)
    {
        score += 1;
    }
    if memory.read_u16(object + offsets::IK_MAJOR_VERSION).ok() == Some(52) {
        score += 1;
    }
    let Some(methods) = memory
        .read_u64(object + offsets::IK_METHODS)
        .ok()
        .filter(|pointer| *pointer != 0)
    else {
        return score;
    };
    let Some(count) = memory
        .read_u32(methods)
        .ok()
        .filter(|count| (4..=256).contains(count))
    else {
        return score;
    };
    let cp = memory.read_u64(object + core.ik_constants).unwrap_or(0);
    let tags = memory.read_u64(cp + core.cp_tags).unwrap_or(0);
    let cp_len = memory.read_u32(cp + core.cp_length).unwrap_or(0);
    let mut valid = 0;
    for index in 0..count.min(12) {
        let method = memory.read_u64(methods + 8 + index as u64 * 8).unwrap_or(0);
        let vtable = memory.read_u64(method).unwrap_or(0);
        let const_method = memory
            .read_u64(method + offsets::METHOD_CONST_METHOD)
            .unwrap_or(0);
        if !(jvm_base..jvm_end).contains(&vtable)
            || memory
                .read_u64(const_method + offsets::CONST_METHOD_CONSTANT_POOL)
                .ok()
                != Some(cp)
        {
            continue;
        }
        let name = memory
            .read_u16(const_method + offsets::CONST_METHOD_NAME_INDEX)
            .unwrap_or(u16::MAX) as u32;
        let signature = memory
            .read_u16(const_method + offsets::CONST_METHOD_SIGNATURE_INDEX)
            .unwrap_or(u16::MAX) as u32;
        if name < cp_len
            && signature < cp_len
            && read_u8(memory, tags + 4 + name as u64) == Some(1)
            && read_u8(memory, tags + 4 + signature as u64) == Some(1)
        {
            valid += 1;
        }
    }
    if valid >= 4 {
        score += 2;
    }
    score
}

pub(super) fn valid_symbol_at<M: RemoteMemory>(
    memory: &M,
    symbol: u64,
    expected: Option<&[u8]>,
) -> bool {
    if symbol == 0 {
        return false;
    }
    let Ok(length) = memory.read_u16(symbol) else {
        return false;
    };
    if length == 0 || length > 4096 {
        return false;
    }
    let mut body = vec![0; length as usize];
    if memory.read_exact(symbol + 8, &mut body).is_err() {
        return false;
    }
    expected.map_or_else(|| body.iter().all(|byte| *byte != 0), |value| body == value)
}

pub(super) fn read_symbol<M: RemoteMemory>(memory: &M, symbol: u64) -> Result<String> {
    let length = memory.read_u16(symbol)? as usize;
    if length == 0 || length > 4096 {
        bail!("invalid Symbol length")
    }
    let mut bytes = vec![0; length];
    memory.read_exact(symbol + 8, &mut bytes)?;
    String::from_utf8(bytes).context("class name Symbol is not UTF-8")
}

fn read_u8<M: RemoteMemory>(memory: &M, address: u64) -> Option<u8> {
    let mut byte = [0];
    memory.read_exact(address, &mut byte).ok()?;
    Some(byte[0])
}

pub(super) fn profile_vmstructs(core: CoreLayout) -> VmStructTable {
    let mut entries = Vec::new();
    let mut add = |ty: &str, field: &str, offset: u64| {
        entries.push(VmStructEntry {
            type_name: ty.to_owned(),
            field_name: field.to_owned(),
            offset,
            address: 0,
        });
    };
    add("Klass", "_name", core.klass_name);
    add("Klass", "_super", offsets::KLASS_SUPER);
    add("Klass", "_access_flags", offsets::KLASS_ACCESS_FLAGS);
    add("Symbol", "_length", 0);
    add("Symbol", "_body", 8);
    add("InstanceKlass", "_constants", core.ik_constants);
    add("InstanceKlass", "_fields", offsets::IK_FIELDS);
    add(
        "InstanceKlass",
        "_java_fields_count",
        offsets::IK_JAVA_FIELDS_COUNT,
    );
    add("InstanceKlass", "_methods", offsets::IK_METHODS);
    add(
        "InstanceKlass",
        "_local_interfaces",
        offsets::IK_LOCAL_INTERFACES,
    );
    add("InstanceKlass", "_major_version", offsets::IK_MAJOR_VERSION);
    add("InstanceKlass", "_minor_version", offsets::IK_MINOR_VERSION);
    add(
        "InstanceKlass",
        "_generic_signature_index",
        offsets::IK_GENERIC_SIGNATURE_INDEX,
    );
    add("ConstantPool", "_tags", core.cp_tags);
    add("ConstantPool", "_length", core.cp_length);
    add("ConstantPool", "_cache", offsets::CP_CACHE);
    add("ConstantPool", "_reference_map", offsets::CP_REFERENCE_MAP);
    add("ConstantPool", "_operands", offsets::CP_OPERANDS);
    add("Array<Klass*>", "_length", 0);
    add("Array<Klass*>", "_data[0]", 8);
    add("Method", "_constMethod", offsets::METHOD_CONST_METHOD);
    add("Method", "_access_flags", offsets::METHOD_ACCESS_FLAGS);
    add(
        "ConstMethod",
        "_name_index",
        offsets::CONST_METHOD_NAME_INDEX,
    );
    add(
        "ConstMethod",
        "_signature_index",
        offsets::CONST_METHOD_SIGNATURE_INDEX,
    );
    add("ConstMethod", "_flags", offsets::CONST_METHOD_FLAGS);
    add("ConstMethod", "_code_size", offsets::CONST_METHOD_CODE_SIZE);
    add(
        "ConstMethod",
        "_constMethod_size",
        offsets::CONST_METHOD_SIZE,
    );
    add("ConstMethod", "_max_stack", offsets::CONST_METHOD_MAX_STACK);
    add(
        "ConstMethod",
        "_max_locals",
        offsets::CONST_METHOD_MAX_LOCALS,
    );
    add(
        "ConstMethod",
        "_stackmap_data",
        offsets::CONST_METHOD_STACKMAP_DATA,
    );
    add("ConstantPoolCache", "_length", 0);
    add("ConstantPoolCacheEntry", "_indices", 0);
    VmStructTable::inferred(entries)
}

pub(super) fn profile_vmtypes(cp_size: u64) -> VmTypes {
    VmTypes::inferred(HashMap::from([
        ("ConstantPool".to_owned(), cp_size),
        ("ConstMethod".to_owned(), 0x30),
        ("ConstantPoolCache".to_owned(), 0x10),
        ("ConstantPoolCacheEntry".to_owned(), 0x20),
    ]))
}
