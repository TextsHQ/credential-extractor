use std::env::temp_dir;
use std::path::PathBuf;

use serde::Deserialize;

#[cfg(target_os = "linux")]
use dirs::config_dir;
#[cfg(not(target_os = "linux"))]
use dirs::data_local_dir;

use rusqlite::{Connection, OpenFlags};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod win;

mod browsers;
use browsers::KNOWN_BROWSER;

use super::{Credential, Password};

use crate::error::{ExtractorError, ExtractorResult};

const TEMP_FILE: &str = "extractor.chromium.data";

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

pub fn login_credentials(url: &str) -> ExtractorResult<Vec<Credential>> {
    #[cfg(not(target_os = "linux"))]
    let local_data_dir = data_local_dir().ok_or(ExtractorError::CannotFindLocalDataDirectory)?;
    #[cfg(target_os = "linux")]
    let local_data_dir = config_dir().ok_or(ExtractorError::CannotFindLocalDataDirectory)?;

    let tmp_chromium_data = temp_dir().join(TEMP_FILE);

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

        std::fs::copy(&dir, &tmp_chromium_data)?;

        {
            let login_data = Connection::open_with_flags(
                &tmp_chromium_data,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;

            let mut stmt = login_data
                .prepare_cached("SELECT origin_url, username_element, username_value, password_element, password_value FROM logins WHERE origin_url LIKE '%' || ? || '%'")?;

            let mut rows = stmt.query(&[url])?;

            while let Some(row) = rows.next()? {
                let origin_url = row.get::<_, String>(0)?;
                let username_element = row.get::<_, String>(1)?;
                let username_value = row.get::<_, String>(2)?;
                let password_element = row.get::<_, String>(3)?;
                let password_value = row.get::<_, Vec<u8>>(4)?;

                credentials.push(Credential {
                    browser: browser.name.to_string(),
                    url: origin_url,
                    username: if username_value.is_empty() {
                        None
                    } else {
                        Some(username_value)
                    },
                    password: Password::Encrypted(password_value),
                    username_element: if username_element.is_empty() {
                        None
                    } else {
                        Some(username_element)
                    },
                    password_element: if password_element.is_empty() {
                        None
                    } else {
                        Some(password_element)
                    },
                });
            }
        }

        std::fs::remove_file(&tmp_chromium_data)?;
    }

    Ok(credentials)
}

pub fn decrypt_credential(credential: Credential) -> ExtractorResult<String> {
    match credential.password {
        Password::Encrypted(ref encrypted_password) => {
            let chromium_browser = KNOWN_BROWSER
                .iter()
                .find(|b| b.name == credential.browser)
                .ok_or(ExtractorError::InvalidBrowser)?;

            #[cfg(target_os = "windows")]
            return win::decrypt_credential(chromium_browser, encrypted_password);

            #[cfg(target_os = "macos")]
            return macos::decrypt_credential(chromium_browser, encrypted_password);

            #[cfg(target_os = "linux")]
            return linux::decrypt_credential(chromium_browser, encrypted_password);
        }
        Password::Plaintext(password) => {
            return Ok(password);
        }
    }
}
