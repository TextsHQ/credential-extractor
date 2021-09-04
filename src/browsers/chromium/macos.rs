use std::path::PathBuf;

use dirs::data_local_dir;

use aes::Aes128;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use security_framework::os::macos::keychain::SecKeychain;

use rusqlite::{Connection, OpenFlags};

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
            existing_paths.push(dir);
        }
    }

    Ok(existing_paths)
}

pub fn search_login_credentials(url: &str) -> ExtractorResult<Vec<Credential>> {
    let mut credentials = Vec::new();

    let keychain = SecKeychain::default()?;

    let encryption_key = keychain.find_generic_password("Chrome Safe Storage", "Chrome")?.0.to_owned();

    for path in browser_directories()? {
        let login_data = Connection::open_with_flags(
            path.join(["Default", "Login Data"].iter().collect::<PathBuf>()),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        let mut stmt = login_data.prepare_cached(
            "SELECT origin_url, username_value, password_value FROM logins WHERE origin_url = ?",
        )?;

        let mut rows = stmt.query(&[&url])?;

        while let Some(row) = rows.next()? {
            let origin_url = row.get::<_, String>(0)?;
            let username_value = row.get::<_, String>(1)?;
            let password_value = row.get::<_, Vec<u8>>(2)?;

        }
    }

    Ok(credentials)
}
