use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
use security_framework::os::macos::passwords::{SecAuthenticationType, SecProtocolType};

use super::{Credential, Password};

use crate::error::{ExtractorError, ExtractorResult};

pub fn login_credentials(url: &str) -> ExtractorResult<Vec<Credential>> {
    let keychain = SecKeychain::open("/Users/fishy/Library/Keychains/69B91C84-F00B-57E6-B353-DE6449586193/keychain-2.db")?;

    let password = keychain.find_internet_password(
        url,
        None,
        "{{}}",
        "",
        None,
        SecProtocolType::Any,
        SecAuthenticationType::Any,
    );

    panic!("{:?}", password);

    let credentials = Vec::new();

    Ok(credentials)
}
