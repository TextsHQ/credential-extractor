use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExtractorError {
    #[cfg(target_os = "windows")]
    #[error("Unable to decode base64")]
    Base64Error(#[from] base64::DecodeError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[cfg(target_os = "macos")]
    #[error("Mac security error: {0}")]
    MacOSSecurityError(#[from] security_framework::base::Error),

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[error("Invalid key IV length: {0}")]
    InvalidKeyIvLength(#[from] block_modes::InvalidKeyIvLength),

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[error("Block mode error: {0}")]
    BlockMode(#[from] block_modes::BlockModeError),

    #[cfg(target_os = "windows")]
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Sqlite error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("Cannot find local data directory")]
    CannotFindLocalDataDirectory,

    #[cfg(target_os = "windows")]
    #[error("Win32 cannot decrypt key")]
    Win32CannotDecryptKey,

    #[cfg(target_os = "windows")]
    #[error("Unable to decrypt key using AES-GCM")]
    AESGCMCannotDecryptPassword,

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[error("Unable to decrypt key using AES-CBC")]
    AESCBCCannotDecryptPassword,

    #[error("Invalid browser provided to decryptor")]
    InvalidBrowser,
}

pub type ExtractorResult<T> = std::result::Result<T, ExtractorError>;
