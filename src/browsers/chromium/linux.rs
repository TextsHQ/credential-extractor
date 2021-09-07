use std::path::PathBuf;

use dirs::data_local_dir;

use aes::Aes128;

use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;
use crypto::sha1::Sha1;

use keyring::Keyring;

use super::browsers::ChromiumBrowser;

use crate::browsers::Credential;
use crate::error::{ExtractorError, ExtractorResult};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub fn decrypt_credential(
    chromium_browser: &ChromiumBrowser,
    credential: &mut Credential,
) -> ExtractorResult<String> {
    let mut path = data_local_dir().ok_or(ExtractorError::CannotFindLocalDataDirectory)?;
    path.push(chromium_browser.paths.iter().collect::<PathBuf>());

    let encryption_key = Keyring::new(
        chromium_browser.service_name,
        chromium_browser.linux_secret_application,
    )
    .get_password()?;

    // derived key is used to decrypt the encrypted data
    let mut dk = [0u8; 16];

    let mut mac = Hmac::new(Sha1::new(), encryption_key.as_bytes());

    pbkdf2(&mut mac, b"saltysalt", 1, &mut dk);

    let mut iv = [0u8; 16];

    // IV 16 bytes of space " "
    for i in 0..16 {
        iv[i] = b' ';
    }

    let cipher = Aes128Cbc::new_from_slices(&dk, &iv)?;

    Ok(
        std::str::from_utf8(cipher.decrypt(&mut credential.encrypted_password[3..])?)
            .map_err(|_| ExtractorError::AESCBCCannotDecryptPassword)?
            .to_owned(),
    )
}
