use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{code}: {message}")]
pub struct RuntimeError {
    code: &'static str,
    message: String,
}

impl RuntimeError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub(crate) fn sink_io(context: &str, error: std::io::Error) -> Self {
        Self::new("BW-RUNTIME-SINK-IO", format!("{context}: {error}"))
    }
}
