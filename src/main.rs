mod app;
mod hotspot;
mod platform;

use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result};
use spdlog::prelude::*;

use crate::{
    app::{ConnectionMode, prompt_config},
    platform::TargetProcess,
};

fn main() {
    let exit_code = if let Err(error) = run() {
        error!("{error:#}");
        1
    } else {
        0
    };
    pause_before_exit();
    std::process::exit(exit_code);
}

fn run() -> Result<()> {
    spdlog::default_logger()
        .set_level_filter(spdlog::LevelFilter::MoreSevereEqual(spdlog::Level::Info));
    platform::ensure_elevated()?;

    let config = prompt_config()?;
    info!(
        "connection={} pid={}",
        config.connection.label(),
        config.pid
    );
    std::fs::create_dir_all(&config.output)
        .with_context(|| format!("cannot create {}", config.output.display()))?;

    let process = match config.connection {
        ConnectionMode::OpenProcess => {
            let process = TargetProcess::open_read_only(config.pid)?;
            info!("attached with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ");
            process
        }
        ConnectionMode::ExistingHandle => {
            let raw = config
                .existing_handle
                .context("existing HANDLE was not supplied")?;
            let process = TargetProcess::from_existing_handle(config.pid, raw)?;
            info!("attached through validated duplicate of supplied HANDLE");
            process
        }
    };

    let report = hotspot::inspect(&process, &config)?;
    info!(
        "HotSpot module: base=0x{:016x}, size={} KiB",
        report.jvm_module_base,
        report.jvm_module_size / 1024
    );
    info!("bootstrap anchors: {}", report.anchors.join(", "));
    info!("VMStructs: {} entries", report.vmstruct_count);
    info!("layout source: {}", report.layout_source);
    if let Some(bytes) = report.scanned_bytes {
        info!(
            "structural scan: {} MiB readable memory",
            bytes / 1024 / 1024
        );
    }
    if let Some(anchors) = report.structural_anchors {
        info!(
            "anchors: Object Symbol=0x{:016x} Klass=0x{:016x} CP.vtable=0x{:016x} CP.size=0x{:x}",
            anchors.object_symbol,
            anchors.object_klass,
            anchors.constant_pool_vtable,
            anchors.constant_pool_size,
        );
    }
    if let (Some(storage), Some(dictionary)) =
        (report.system_dictionary_storage, report.system_dictionary)
    {
        info!("SystemDictionary::_dictionary: storage=0x{storage:016x} value=0x{dictionary:016x}");
    } else {
        info!("class source: validated ConstantPool -> InstanceKlass graph");
    }
    let index = report
        .classes
        .iter()
        .map(|class| format!("0x{:016x} {}\n", class.klass, class.internal_name))
        .collect::<String>();
    std::fs::write(config.output.join("classes.txt"), index)?;
    info!(
        "discovered classes: {} (index written to classes.txt)",
        report.classes.len()
    );
    info!(
        "classfiles: written={} failed={}",
        report.classfiles_written, report.classfiles_failed
    );
    for failure in &report.classfile_failures {
        warn!("classfile skipped: {failure}");
    }
    if config.make_jar && report.classfiles_written > 0 {
        info!(
            "JAR written to {}",
            config.output.join("classes.jar").display()
        );
    }
    info!("next: {}", report.next_step);
    info!(
        "output={} jar={}",
        config.output.display(),
        if config.make_jar { "yes" } else { "no" }
    );
    info!("external metadata traversal completed");
    Ok(())
}

fn pause_before_exit() {
    if cfg!(windows) && io::stdin().is_terminal() {
        print!("\nPress Enter to exit...");
        let _ = io::stdout().flush();
        let mut input = String::new();
        let _ = io::stdin().read_line(&mut input);
    }
}
