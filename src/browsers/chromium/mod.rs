use crate::error::ExtractorResult;

use super::Credential;

#[cfg(target_os = "windows")]
mod win;

pub fn search_login_credentials(url: &str) -> ExtractorResult<Vec<Credential>> {
    #[cfg(target_os = "windows")]
    win::search_login_credentials(url)
}
