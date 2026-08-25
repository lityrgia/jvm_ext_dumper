mod layout;
mod scan;

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use spdlog::info;

use crate::platform::{MemoryRegion, RemoteMemory, TargetProcess};

use self::{
    layout::{
        CoreLayout, OBJECT_NAME, infer_core_layout, offsets, profile_vmstructs, profile_vmtypes,
        read_symbol, validate_jdk8_profile,
    },
    scan::{scan_symbols, scan_u64},
};
use super::{dictionary::DiscoveredClass, vmstructs::VmStructTable, vmtypes::VmTypes};

const MAX_ANCHOR_HITS: usize = 64;
const MAX_POINTER_HITS: usize = 100_000;
const MAX_CLASSES: usize = 1_000_000;

#[derive(Debug)]
pub struct StructuralDiscovery {
    pub structs: VmStructTable,
    pub types: VmTypes,
    pub classes: Vec<DiscoveredClass>,
    pub object_symbol: u64,
    pub object_klass: u64,
    pub constant_pool_vtable: u64,
    pub constant_pool_size: u64,
    pub scanned_bytes: u64,
}

#[derive(Clone, Copy)]
struct AnchorCandidate {
    score: usize,
    symbol: u64,
    klass: u64,
    layout: CoreLayout,
}

pub fn discover(
    process: &TargetProcess,
    jvm_base: u64,
    jvm_size: usize,
) -> Result<StructuralDiscovery> {
    let regions = process.readable_regions()?;
    let scanned_bytes = regions.iter().map(|region| region.size as u64).sum();
    if regions.is_empty() {
        bail!("the target has no readable committed memory regions")
    }
    info!(
        "stripped HotSpot fallback: scanning {} readable regions ({} MiB)",
        regions.len(),
        scanned_bytes / 1024 / 1024
    );

    let symbols = scan_symbols(process, &regions, OBJECT_NAME, MAX_ANCHOR_HITS)?;
    if symbols.is_empty() {
        bail!("java/lang/Object was found, but no occurrence has a valid JDK 8 Symbol header")
    }
    info!(
        "structural anchors: {} valid java/lang/Object Symbol candidates",
        symbols.len()
    );

    let module_end = jvm_base
        .checked_add(jvm_size as u64)
        .context("jvm.dll address overflow")?;
    let (best, klass_candidates, core_graphs) =
        find_best_anchor(process, &regions, &symbols, jvm_base, module_end)?;
    info!(
        "structural candidates: klass-vtable={} self-consistent CP graphs={}",
        klass_candidates, core_graphs
    );

    let object_cp = process.read_u64(best.klass + best.layout.ik_constants)?;
    let constant_pool_vtable = process.read_u64(object_cp)?;
    info!(
        "structural layout: Symbol=0x{:016x} InstanceKlass=0x{:016x} name=0x{:x} constants=0x{:x} CP.tags=0x{:x} CP.size=0x{:x} profile-score={}/7",
        best.symbol,
        best.klass,
        best.layout.klass_name,
        best.layout.ik_constants,
        best.layout.cp_tags,
        best.layout.cp_size,
        best.score,
    );

    let mut classes = enumerate_constant_pools(
        process,
        &regions,
        constant_pool_vtable,
        &best.layout,
        jvm_base,
        module_end,
    )?;
    validate_anchor_set(process, &classes, &best.layout)?;
    classes.sort_unstable_by(|left, right| left.internal_name.cmp(&right.internal_name));
    info!(
        "structural ConstantPool traversal: {} validated classes",
        classes.len()
    );

    Ok(StructuralDiscovery {
        structs: profile_vmstructs(best.layout),
        types: profile_vmtypes(best.layout.cp_size),
        classes,
        object_symbol: best.symbol,
        object_klass: best.klass,
        constant_pool_vtable,
        constant_pool_size: best.layout.cp_size,
        scanned_bytes,
    })
}

fn find_best_anchor(
    process: &TargetProcess,
    regions: &[MemoryRegion],
    symbols: &[u64],
    jvm_base: u64,
    jvm_end: u64,
) -> Result<(AnchorCandidate, usize, usize)> {
    let mut best = None;
    let mut klass_candidates = 0usize;
    let mut core_graphs = 0usize;
    for &symbol in symbols {
        let references = scan_u64(process, regions, symbol, MAX_POINTER_HITS)?;
        info!(
            "Object Symbol candidate 0x{symbol:016x}: {} aligned references",
            references.len()
        );
        for location in references {
            for name_offset in (8_u64..=0x80).step_by(8) {
                let Some(klass) = location.checked_sub(name_offset) else {
                    continue;
                };
                let Ok(vtable) = process.read_u64(klass) else {
                    continue;
                };
                if !(jvm_base..jvm_end).contains(&vtable) {
                    continue;
                }
                klass_candidates += 1;
                let Ok(layout) = infer_core_layout(process, klass, name_offset, jvm_base, jvm_end)
                else {
                    continue;
                };
                core_graphs += 1;
                let candidate = AnchorCandidate {
                    score: validate_jdk8_profile(process, klass, &layout, jvm_base, jvm_end),
                    symbol,
                    klass,
                    layout,
                };
                if best
                    .as_ref()
                    .is_none_or(|old: &AnchorCandidate| candidate.score > old.score)
                {
                    best = Some(candidate);
                }
            }
        }
    }
    let best = best.with_context(|| {
        format!(
            "could not connect java/lang/Object Symbol to an InstanceKlass/ConstantPool graph (klass-vtable candidates={klass_candidates}, CP graphs={core_graphs})"
        )
    })?;
    Ok((best, klass_candidates, core_graphs))
}

fn enumerate_constant_pools(
    process: &TargetProcess,
    regions: &[MemoryRegion],
    cp_vtable: u64,
    core: &CoreLayout,
    jvm_base: u64,
    jvm_end: u64,
) -> Result<Vec<DiscoveredClass>> {
    let candidates = scan_u64(process, regions, cp_vtable, MAX_CLASSES + 1)?;
    if candidates.len() > MAX_CLASSES {
        bail!("ConstantPool candidate safety limit exceeded")
    }
    let mut seen = HashSet::new();
    let mut classes = Vec::new();
    for cp in candidates {
        let Ok(klass) = process.read_u64(cp + core.cp_holder) else {
            continue;
        };
        if klass == 0 || !seen.insert(klass) {
            continue;
        }
        let Ok(vtable) = process.read_u64(klass) else {
            continue;
        };
        if !(jvm_base..jvm_end).contains(&vtable)
            || process.read_u64(klass + core.ik_constants).ok() != Some(cp)
        {
            continue;
        }
        let Ok(tags) = process.read_u64(cp + core.cp_tags) else {
            continue;
        };
        let Ok(length) = process.read_u32(cp + core.cp_length) else {
            continue;
        };
        if !(2..65_535).contains(&length) || process.read_u32(tags).ok() != Some(length) {
            continue;
        }
        let Ok(symbol) = process.read_u64(klass + core.klass_name) else {
            continue;
        };
        let Ok(name) = read_symbol(process, symbol) else {
            continue;
        };
        if !valid_internal_name(&name) {
            continue;
        }
        classes.push(DiscoveredClass {
            klass,
            internal_name: name,
        });
    }
    Ok(classes)
}

fn validate_anchor_set<M: RemoteMemory>(
    memory: &M,
    classes: &[DiscoveredClass],
    core: &CoreLayout,
) -> Result<()> {
    let object = classes
        .iter()
        .find(|class| class.internal_name == "java/lang/Object")
        .context("enumeration lost java/lang/Object")?;
    for name in ["java/lang/String", "java/lang/Class", "java/lang/System"] {
        let class = classes
            .iter()
            .find(|class| class.internal_name == name)
            .with_context(|| format!("structural validation did not find {name}"))?;
        if memory.read_u64(class.klass + offsets::KLASS_SUPER)? != object.klass {
            bail!("{name} does not have java/lang/Object at inferred Klass::_super")
        }
        if memory.read_u16(class.klass + offsets::IK_MAJOR_VERSION)? != 52 {
            bail!("{name} is not a Java 8 class at inferred version offsets")
        }
        let cp = memory.read_u64(class.klass + core.ik_constants)?;
        if memory.read_u64(cp + core.cp_holder)? != class.klass {
            bail!("{name} failed ConstantPool::_pool_holder cross-check")
        }
    }
    Ok(())
}

fn valid_internal_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 4096
        && !name.starts_with('[')
        && !name.bytes().any(|byte| byte == 0 || byte <= 0x20)
}

#[cfg(test)]
mod tests {
    use super::valid_internal_name;

    #[test]
    fn internal_name_filter_rejects_arrays_and_controls() {
        assert!(valid_internal_name("java/lang/Object"));
        assert!(!valid_internal_name("[Ljava/lang/Object;"));
        assert!(!valid_internal_name("bad\nname"));
    }
}
