use std::path::PathBuf;

use serde::Deserialize;

use crate::error::ExtractorResult;

#[cfg(target_os = "windows")]
mod win;
