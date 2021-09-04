use std::path::PathBuf;

use dirs::data_local_dir;

use security_framework::os::macos::keychain::SecKeychain;

use crate::browsers::Credential;
use crate::error::{ExtractorResult, ExtractorError};

const KNOWN_BROWSER_PATHS: &[&str] = &[
    "Google/Chrome",
    // "Google/Chrome SxS",
    "Chromium",
    "BraveSoftware/Brave-Browser",
    "Vivaldi",
];

fn browser_directories() -> ExtractorResult<Vec<PathBuf>> {
    let local_data_dir = data_local_dir().ok_or(ExtractorError::CannotFindLocalDataDirectory)?;

    let mut existing_paths = Vec::new();

    for known_path in KNOWN_BROWSER_PATHS {
        let dir = local_data_dir.join(known_path);

        if dir.exists() {
            existing_paths.push(dir.join("User Data"));
        }
    }

    Ok(existing_paths)
}

fn encryption_key() -> ExtractorResult<Vec<u8>> {

}

pub fn search_login_credentials(url: &str) -> ExtractorResult<Vec<Credential>> {
    let mut credentials = Vec::new();

    for path in browser_directories()? {

    }

    Ok(credentials)
}
