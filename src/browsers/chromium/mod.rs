use crate::error::ExtractorResult;

use super::Credential;

#[cfg(target_os = "windows")]
mod win;

// #[cfg(target_os = "macos")]
mod macos;

pub fn search_login_credentials(url: &str) -> ExtractorResult<Vec<Credential>> {
    #[cfg(target_os = "windows")]
    return win::search_login_credentials(url);

    #[cfg(target_os = "macos")]
    return macos::search_login_credentials(url);
}
