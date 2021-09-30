use std::path::PathBuf;
use std::fs::{read_dir, read_to_string};

use dirs::data_local_dir;

use serde_json::from_str;

use rusqlite::{Connection, OpenFlags};

mod browsers;
use browsers::KNOWN_BROWSER;

mod logins;
use logins::LoginsFile;

use super::{Credential, Password};

use crate::error::{ExtractorError, ExtractorResult};

pub fn login_credentials(url: &str) -> ExtractorResult<Vec<Credential>> {
    let mut credentials = Vec::new();

    for profile in firefox_profiles()? {
        let key4 = profile.join("key4.db");
        let logins = profile.join("logins.json");

        let key4_db = Connection::open_with_flags(
            &key4,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        let logins: LoginsFile = from_str(&read_to_string(logins)?)?;
    }

    Ok(credentials)
}

fn firefox_profiles() -> ExtractorResult<Vec<PathBuf>> {
    let local_data_dir = data_local_dir().ok_or(ExtractorError::CannotFindLocalDataDirectory)?;

    let mut profiles = Vec::new();

    for browser in KNOWN_BROWSER {
        let profile_dir = local_data_dir.join(browser.paths.iter().collect::<PathBuf>());

        for entry in read_dir(&profile_dir)? {
            if let Ok(entry) = entry {
                let path = entry.path();

                if path.is_dir() {
                    let key4 = path.join("key4.db");
                    let logins = path.join("logins.json");

                    if key4.exists() && logins.exists() {
                        profiles.push(path);
                    }
                }
            }
        }
    }

    Ok(profiles)
}
