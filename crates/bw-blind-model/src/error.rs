use std::{io, path::PathBuf};

use thiserror::Error;

/// Errors returned when a public blind-pack document violates its contract.
#[derive(Debug, Error)]
pub enum BlindModelError {
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("invalid TOML: {0}")]
    InvalidToml(#[from] toml::de::Error),

    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid blind public model: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, BlindModelError>;

pub(crate) fn validation(message: impl Into<String>) -> BlindModelError {
    BlindModelError::Validation(message.into())
}
