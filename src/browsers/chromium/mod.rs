use crate::error::ExtractorResult;

use super::Credential;

#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "macos")]
mod macos;

pub fn login_credentials() -> ExtractorResult<Vec<Credential>> {
    #[cfg(target_os = "windows")]
    return win::login_credentials();

    #[cfg(target_os = "macos")]
    return macos::login_credentials();
}
