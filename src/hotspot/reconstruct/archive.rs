use std::{
    fs,
    io::{Seek, Write},
    path::{Path, PathBuf},
};

use anyhow::Result;

pub fn make_jar(output: &Path) -> Result<PathBuf> {
    let path = output.join("classes.jar");
    let file = fs::File::create(&path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    add_directory_to_jar(&mut zip, output, output, options)?;
    zip.finish()?;
    Ok(path)
}

fn add_directory_to_jar<W: Write + Seek>(
    zip: &mut zip::ZipWriter<W>,
    root: &Path,
    current: &Path,
    options: zip::write::SimpleFileOptions,
) -> Result<()> {
    for item in fs::read_dir(current)? {
        let path = item?.path();
        if path.is_dir() {
            add_directory_to_jar(zip, root, &path, options)?;
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("class") {
            continue;
        }
        let name = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        zip.start_file(name, options)?;
        zip.write_all(&fs::read(path)?)?;
    }
    Ok(())
}
