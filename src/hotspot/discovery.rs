use crate::platform::{RemoteMemory, TargetProcess};
use anyhow::{Context, Result};
use std::path::Path;

use super::{
    dictionary::{self, DiscoveredClass},
    heuristic,
    pe::RemotePe,
    reconstruct, structural,
    vmstructs::VmStructTable,
    vmtypes::VmTypes,
};

const ANCHOR_CLASSES: &[&str] = &[
    "java/lang/Object",
    "java/lang/Class",
    "java/lang/String",
    "java/lang/Short",
];

#[derive(Debug)]
pub struct DiscoveryReport {
    pub jvm_module_base: u64,
    pub jvm_module_size: usize,
    pub anchors: &'static [&'static str],
    pub next_step: &'static str,
    pub vmstruct_count: usize,
    pub layout_source: String,
    pub scanned_bytes: Option<u64>,
    pub structural_anchors: Option<StructuralAnchors>,
    pub system_dictionary_storage: Option<u64>,
    pub system_dictionary: Option<u64>,
    pub classes: Vec<DiscoveredClass>,
    pub classfiles_written: usize,
    pub classfiles_failed: usize,
    pub classfile_failures: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct StructuralAnchors {
    pub object_symbol: u64,
    pub object_klass: u64,
    pub constant_pool_vtable: u64,
    pub constant_pool_size: u64,
}

struct LocatedMetadata {
    vmstructs: VmStructTable,
    vmtypes: VmTypes,
    classes: Vec<DiscoveredClass>,
    system_dictionary_storage: Option<u64>,
    system_dictionary: Option<u64>,
    layout_source: String,
    scanned_bytes: Option<u64>,
    structural_anchors: Option<StructuralAnchors>,
}

pub fn locate_hotspot(process: &TargetProcess, output: &Path) -> Result<DiscoveryReport> {
    let module = process
        .modules()?
        .into_iter()
        .find(|module| module.name.eq_ignore_ascii_case("jvm.dll"))
        .ok_or_else(|| anyhow::anyhow!("jvm.dll is not loaded in PID {}", process.pid()))?;

    let exports = RemotePe::new(process, module.base).exports()?;
    let exported = VmStructTable::read(process, &exports)
        .and_then(|structs| VmTypes::read(process, &exports).map(|types| (structs, types)));
    let located = match exported {
        Ok((structs, types)) => {
            let (storage, dictionary, classes) = walk_dictionary(process, &structs)?;
            LocatedMetadata {
                vmstructs: structs,
                vmtypes: types,
                classes,
                system_dictionary_storage: storage,
                system_dictionary: dictionary,
                layout_source: "exported gHotSpotVMStructs/gHotSpotVMTypes".to_owned(),
                scanned_bytes: None,
                structural_anchors: None,
            }
        }
        Err(export_error) => match heuristic::infer(process, module.base, module.size) {
            Ok(inferred) => {
                let (storage, dictionary, classes) = walk_dictionary(process, &inferred.structs)?;
                LocatedMetadata {
                    vmstructs: inferred.structs,
                    vmtypes: inferred.types,
                    classes,
                    system_dictionary_storage: storage,
                    system_dictionary: dictionary,
                    layout_source: format!(
                        "internal VM tables (exports unavailable: {export_error:#})"
                    ),
                    scanned_bytes: None,
                    structural_anchors: None,
                }
            }
            Err(table_error) => {
                let found = structural::discover(process, module.base, module.size)
                    .with_context(|| {
                        format!(
                            "HotSpot exports failed ({export_error:#}); internal tables failed ({table_error:#}); structural fallback failed"
                        )
                    })?;
                LocatedMetadata {
                    vmstructs: found.structs,
                    vmtypes: found.types,
                    classes: found.classes,
                    system_dictionary_storage: None,
                    system_dictionary: None,
                    layout_source: "validated x64 HotSpot 8 structural profile".to_owned(),
                    scanned_bytes: Some(found.scanned_bytes),
                    structural_anchors: Some(StructuralAnchors {
                        object_symbol: found.object_symbol,
                        object_klass: found.object_klass,
                        constant_pool_vtable: found.constant_pool_vtable,
                        constant_pool_size: found.constant_pool_size,
                    }),
                }
            }
        },
    };
    let dump = reconstruct::dump_all(
        process,
        &located.classes,
        &located.vmstructs,
        &located.vmtypes,
        output,
    );

    let next_step = "optional debug and annotation attributes";
    Ok(DiscoveryReport {
        jvm_module_base: module.base,
        jvm_module_size: module.size,
        anchors: ANCHOR_CLASSES,
        next_step,
        vmstruct_count: located.vmstructs.entries.len(),
        layout_source: located.layout_source,
        scanned_bytes: located.scanned_bytes,
        structural_anchors: located.structural_anchors,
        system_dictionary_storage: located.system_dictionary_storage,
        system_dictionary: located.system_dictionary,
        classes: located.classes,
        classfiles_written: dump.written,
        classfiles_failed: dump.failed,
        classfile_failures: dump.failures,
    })
}

fn walk_dictionary(
    process: &TargetProcess,
    vmstructs: &VmStructTable,
) -> Result<(Option<u64>, Option<u64>, Vec<DiscoveredClass>)> {
    let storage = vmstructs
        .find("SystemDictionary", "_dictionary")
        .map(|entry| entry.address);
    let dictionary = match storage {
        Some(address) => Some(process.read_u64(address)?),
        None => None,
    };
    let classes = match dictionary {
        Some(dictionary) if dictionary != 0 => dictionary::walk(process, dictionary, vmstructs)?,
        _ => Vec::new(),
    };
    Ok((storage, dictionary, classes))
}

#[cfg(test)]
mod tests {
    use super::ANCHOR_CLASSES;
    #[test]
    fn bootstrap_anchors_use_internal_names() {
        assert!(ANCHOR_CLASSES.iter().all(|name| name.contains('/')));
    }
}
