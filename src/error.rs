use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExtractorError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Sqlite error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("Cannot find home directory")]
    CannotFindHomeDirectory,
}

pub type ExtractorResult<T> = std::result::Result<T, ExtractorError>;
