use std::path::PathBuf;

use dirs::data_local_dir;

use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;

mod bindings {
    windows::include_bindings!();
}

use bindings::Windows::Win32::Security::CryptUnprotectData;
use bindings::Windows::Win32::Security::Cryptography::Core::CRYPTOAPI_BLOB;

use super::{LocalState, KNOWN_BROWSER};

use crate::browsers::Credential;
use crate::error::{ExtractorError, ExtractorResult};

pub fn decrypt_credential(credential: &Credential) -> ExtractorResult<String> {
    let chromium_browser = KNOWN_BROWSER.iter().find(|b| b.name == credential.browser)
        .ok_or(ExtractorError::InvalidBrowser)?;

    let mut path = data_local_dir().ok_or(ExtractorError::CannotFindLocalDataDirectory)?;
    path.push(chromium_browser.paths.iter().collect::<PathBuf>());
    path.push("User Data");

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

    // Prefix "v10" is used for AES-GCM encrypted passwords w/ length of 3
    // https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_win.cc;l=33
    //
    // Current nonce length is 96/8
    // https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_win.cc;l=30
    //
    // 3 + (96/8) = 15
    let nonce = GenericArray::from_slice(&credential.encrypted_password[3..15]);

    Ok(String::from_utf8(cipher
        .decrypt(nonce, &credential.encrypted_password[15..])
        .map_err(|_| ExtractorError::AESGCMCannotDecryptPassword)?)
        .map_err(|_| ExtractorError::AESGCMCannotDecryptPassword)?)
}
