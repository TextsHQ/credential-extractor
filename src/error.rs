use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExtractorError {
    #[cfg(target_os = "windows")]
    #[error("Unable to decode base64")]
    Base64Error(#[from] base64::DecodeError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[cfg(target_os = "macos")]
    #[error("Security framework error: {0}")]
    SecurityFramework(#[from] security_framework::base::Error),

    #[cfg(target_os = "linux")]
    #[error("Linux secret service error: {0}")]
    LinuxSecretService(#[from] secret_service::Error),

    #[cfg(target_os = "linux")]
    #[error("Cannot find secret service item")]
    CannotFindSecretServiceItem,

    #[error("Invalid key IV length: {0}")]
    InvalidKeyIvLength(#[from] block_modes::InvalidKeyIvLength),

    #[error("Block mode error: {0}")]
    BlockMode(#[from] block_modes::BlockModeError),

    #[cfg(target_os = "windows")]
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Sqlite error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("ASN1 Ber error: {0}")]
    BerError(#[from] der_parser::error::BerError),

    #[error("Ber error: {0}")]
    BerErrorNom(#[from] der_parser::nom::Err<der_parser::error::BerError>),

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

    #[error("Malformed data")]
    MalformedData,
}

pub type ExtractorResult<T> = std::result::Result<T, ExtractorError>;
