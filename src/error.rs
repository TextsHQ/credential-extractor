use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExtractorError {
    #[error("Unable to decode base64")]
    Base64Error(#[from] base64::DecodeError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Sqlite error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("Cannot find home directory")]
    CannotFindHomeDirectory,

    #[error("Cannot find local data directory")]
    CannotFindLocalDataDirectory,

    #[error("Win32 cannot decrypt key")]
    Win32CannotDecryptKey,

    #[error("Unable to decrypt key using AES-GCM")]
    AESGCMCannotDecryptPassword,
}

pub type ExtractorResult<T> = std::result::Result<T, ExtractorError>;
