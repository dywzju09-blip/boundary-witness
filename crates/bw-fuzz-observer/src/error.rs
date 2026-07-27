use thiserror::Error;

/// Observer failures are tool errors, not vulnerability findings.
#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct ObserverError {
    code: &'static str,
    message: String,
}

impl ObserverError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}
