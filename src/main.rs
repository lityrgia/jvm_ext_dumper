mod app;
mod hotspot;
mod platform;

use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result};
use spdlog::{
    formatter::{PatternFormatter, pattern},
    prelude::*,
};

use crate::{app::prompt_config, platform::TargetProcess};

fn main() {
    configure_logging();
    let exit_code = if let Err(error) = run() {
        error!("{error:#}");
        1
    } else {
        0
    };
    pause_before_exit();
    std::process::exit(exit_code);
}

fn configure_logging() {
    spdlog::default_logger()
        .set_level_filter(spdlog::LevelFilter::MoreSevereEqual(spdlog::Level::Info));
    let formatter = Box::new(PatternFormatter::new(pattern!(
        "[{time}.{millisecond}] [{^{level}}] {payload}{eol}"
    )));
    for sink in spdlog::default_logger().sinks() {
        sink.set_formatter(formatter.clone());
    }
}

fn run() -> Result<()> {
    platform::ensure_elevated()?;

    let config = prompt_config()?;
    info!("connection=OpenProcess (read-only) pid={}", config.pid);
    std::fs::create_dir_all(&config.output)
        .with_context(|| format!("cannot create {}", config.output.display()))?;

    let process = TargetProcess::open_read_only(config.pid)?;
    info!("attached with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ");

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
        "classfiles: archived={} failed={}",
        report.classfiles_written, report.classfiles_failed
    );
    for failure in &report.classfile_failures {
        warn!("classfile skipped: {failure}");
    }
    info!(
        "JAR written to {} ({} case-sensitive entries, {} exact-name duplicates skipped)",
        config.output.join("classes.jar").display(),
        report.classfiles_written,
        report.archive_duplicates,
    );
    if report.archive_duplicates > 0 {
        warn!(
            "exact-name duplicates from different class loaders skipped: {}",
            report.archive_duplicates
        );
    }
    info!("next: {}", report.next_step);
    info!("output={}", config.output.display());
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
