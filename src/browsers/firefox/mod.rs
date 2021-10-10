use std::fs::{read_dir, read_to_string};
use std::path::PathBuf;

use aes::Aes256;

use des::TdesEde3;

use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Cbc};

use sha1::Sha1;
use ring::pbkdf2::PBKDF2_HMAC_SHA256;

use dirs::preference_dir;

use serde_json::from_str;

use rusqlite::{Connection, OpenFlags};

use der_parser::ber::BerObject;

mod browsers;
use browsers::KNOWN_BROWSER;

mod logins;
use logins::{Login, LoginsFile};

use super::{Credential, Password};

use crate::error::{ExtractorError, ExtractorResult};

type Aes256Cbc = Cbc<Aes256, NoPadding>;
type TripleDesCbc = Cbc<TdesEde3, NoPadding>;

static CKA_ID: &[u8; 16] = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";

pub fn login_credentials(url: &str) -> ExtractorResult<Vec<Credential>> {
    let mut credentials = Vec::new();

    for profile in firefox_profiles()? {
        let key4 = profile.join("key4.db");
        let logins = profile.join("logins.json");

        let key4_db = Connection::open_with_flags(
            &key4,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        let (global_salt, item2_der) = key4_db.query_row(
            "SELECT item1, item2 from metadata WHERE id = 'password'",
            [],
            |row| {
                let global_salt: Vec<u8> = row.get(0)?;
                let item2_der: Vec<u8> = row.get(1)?;

                Ok((global_salt, item2_der))
            },
        )?;

        let check_password = get_clear_value(&item2_der, &global_salt)?;

        if check_password != b"password-check\x02\x02" {
            return Err(ExtractorError::MalformedData);
        }

        let (a11, a102) = key4_db.query_row("SELECT a11, a102 FROM nssPrivate", [], |row| {
            let a11: Vec<u8> = row.get(0)?;
            let a102: Vec<u8> = row.get(1)?;

            Ok((a11, a102))
        })?;

        let key = if a102 == CKA_ID {
            get_clear_value(&a11, &global_salt)?
        } else {
            return Err(ExtractorError::MalformedData);
        };

        let logins: LoginsFile = from_str(&read_to_string(logins)?)?;

        for login in logins.logins {
            if !login.hostname.contains(&url) {
                continue;
            }

            match decrypt_login(&login, &key) {
                Ok((username, password)) => {
                    credentials.push(Credential {
                        browser: "Firefox".to_string(), // TODO: Check if this is sufficient
                        url: login.hostname,
                        username: Some(username),
                        password: Password::Plaintext(password),
                        username_element: login.username_field,
                        password_element: login.password_field,
                    });
                }
                Err(_) => continue,
            }
        }
    }

    Ok(credentials)
}

fn decrypt_login(login: &Login, key: &[u8]) -> ExtractorResult<(String, String)> {
    let encrypted_username_raw = base64::decode(&login.encrypted_username)?;
    let encrypted_password_raw = base64::decode(&login.encrypted_password)?;

    let (_, enc_user) = der_parser::ber::parse_ber(&encrypted_username_raw)?;
    let (_, enc_pass) = der_parser::ber::parse_ber(&encrypted_password_raw)?;

    let username = String::from_utf8(decrypt_3des(&enc_user, key)?)?;
    let password = String::from_utf8(decrypt_3des(&enc_pass, key)?)?;

    Ok((username, password))
}

fn firefox_profiles() -> ExtractorResult<Vec<PathBuf>> {
    let local_data_dir = preference_dir().ok_or(ExtractorError::CannotFindLocalDataDirectory)?;

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

fn decrypt_3des(decoded_item: &BerObject, key: &[u8]) -> ExtractorResult<Vec<u8>> {
    if decoded_item[1][0].as_oid()?.to_id_string() == "1.2.840.113549.3.7" {
        let iv = decoded_item[1][1].as_slice()?;
        let enc_data = decoded_item[2].as_slice()?;

        let cipher = TripleDesCbc::new_from_slices(&key[0..24], iv)?;

        let mut raw_clear_data = cipher
            .decrypt_vec(enc_data)
            .map_err(|_| ExtractorError::MalformedData)?;

        if let Some(&last) = raw_clear_data.last() {
            let last = usize::from(last);
            raw_clear_data.truncate(raw_clear_data.len().saturating_sub(last));
            Ok(raw_clear_data)
        } else {
            Err(ExtractorError::MalformedData)
        }
    } else {
        Err(ExtractorError::MalformedData)
    }
}

fn get_clear_value(raw_ber: &[u8], global_salt: &[u8]) -> ExtractorResult<Vec<u8>> {
    let (_, item2_decoded) = der_parser::der::parse_der(raw_ber)?;

    let algorithm = item2_decoded[0][0].as_oid().unwrap().to_id_string();

    if algorithm == "1.2.840.113549.1.5.13" {
        get_value_pbes2(&item2_decoded, &global_salt)
    } else {
        Err(ExtractorError::MalformedData)
    }
}

fn get_value_pbes2(decoded_item: &BerObject, global_salt: &[u8]) -> ExtractorResult<Vec<u8>> {
    let entry_salt = decoded_item[0][1][0][1][0]
        .as_slice()
        .map_err(|_| ExtractorError::MalformedData)?;

    let iteration_count = decoded_item[0][1][0][1][1]
        .as_u32()
        .map_err(|_| ExtractorError::MalformedData)?;

    let key_length = decoded_item[0][1][0][1][2]
        .as_u32()
        .map_err(|_| ExtractorError::MalformedData)?;

    let cipher_txt = decoded_item[1]
        .as_slice()
        .map_err(|_| ExtractorError::MalformedData)?;

    let iv_body = decoded_item[0][1][1][1]
        .as_slice()
        .map_err(|_| ExtractorError::MalformedData)?;

    if key_length == 32 {
        let mut k_hasher = Sha1::new();
        k_hasher.update(global_salt);

        // we know the key is 32 bytes in advance
        let mut key = vec![0u8; 32];

        let k = k_hasher.digest().bytes();
        ring::pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(iteration_count).ok_or(ExtractorError::MalformedData)?,
            entry_salt,
            &k,
            &mut key,
        );

        let iv_header = [0x04, 0x0e];
        let mut iv = Vec::with_capacity(iv_header.len() + iv_body.len());
        iv.extend_from_slice(&iv_header);
        iv.extend_from_slice(iv_body);

        let key_cipher = Aes256Cbc::new_from_slices(&key, &iv)?;
        let value = key_cipher.decrypt_vec(&cipher_txt)?;

        Ok(value)
    } else {
        Err(ExtractorError::MalformedData)
    }
}
