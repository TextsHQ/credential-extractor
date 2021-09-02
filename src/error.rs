use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExtractorError {
    #[error("Cannot find home directory")]
    CannotFindHomeDirectory,
}

pub type ExtractorResult<T> = std::result::Result<T, ExtractorError>;
