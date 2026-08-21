use std::{fs, path::Path};

use crate::{Error, Result};

#[cfg(windows)]
pub(super) fn is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(super) fn is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
pub(super) fn reject_reparse_points_in_existing_chain(path: &Path) -> Result<()> {
    for candidate in path.ancestors() {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if is_symlink_or_reparse(&metadata) => {
                return Err(Error::PolicyRefused(format!(
                    "refusing Windows reparse point in migration path: {}",
                    candidate.display()
                )));
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(Error::ReadFile {
                    path: candidate.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn reject_reparse_points_in_existing_chain(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::ReadFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}
