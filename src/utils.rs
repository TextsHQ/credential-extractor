use std::path::{Path, PathBuf};

use dirs::home_dir;

use crate::error::{ExtractorError, ExtractorResult};

pub fn format_home_path<P: AsRef<Path>>(sub: &P) -> ExtractorResult<PathBuf> {
    let mut p = home_dir()
        .ok_or(ExtractorError::CannotFindHomeDirectory)?
        .join(["Library", "Messages"].iter().collect::<PathBuf>());

    p.push(sub);

    Ok(p)
}
