use std::{collections::HashSet, fs, io::Write, path::Path};

use anyhow::Result;

use super::validate_class_name;

pub(super) struct JarArchive {
    writer: zip::ZipWriter<fs::File>,
    entries: HashSet<String>,
}

impl JarArchive {
    pub(super) fn create(output: &Path) -> Result<Self> {
        let file = fs::File::create(output.join("classes.jar"))?;
        Ok(Self {
            writer: zip::ZipWriter::new(file),
            entries: HashSet::new(),
        })
    }

    /// Adds the reconstructed bytes under the JVM's case-sensitive name,
    /// without routing the entry through a Windows filesystem path.
    pub(super) fn add_class(&mut self, name: &str, bytes: &[u8]) -> Result<bool> {
        validate_class_name(name)?;
        let entry = format!("{name}.class");
        if !self.entries.insert(entry.clone()) {
            return Ok(false);
        }
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        self.writer.start_file(entry, options)?;
        self.writer.write_all(bytes)?;
        Ok(true)
    }

    pub(super) fn finish(self) -> Result<()> {
        self.writer.finish()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use super::JarArchive;

    #[test]
    fn jar_preserves_case_distinct_class_names() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let output = std::env::temp_dir().join(format!(
            "jvm-ext-dumper-archive-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&output).unwrap();

        let names = ["example/muA", "example/mUa", "example/Mua", "example/mUA"];
        let mut archive = JarArchive::create(&output).unwrap();
        for (index, name) in names.iter().enumerate() {
            assert!(archive.add_class(name, &[index as u8]).unwrap());
        }
        archive.finish().unwrap();

        let file = fs::File::open(output.join("classes.jar")).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        assert_eq!(zip.len(), names.len());
        for name in names {
            assert!(zip.by_name(&format!("{name}.class")).is_ok());
        }

        fs::remove_dir_all(output).unwrap();
    }
}
