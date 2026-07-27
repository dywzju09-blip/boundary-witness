use std::{fmt, io};

pub const SUCCESS: u8 = 0;
pub const FINDING: u8 = 1;
pub const INPUT_ERROR: u8 = 2;
pub const INTERNAL_ERROR: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandStatus {
    Success,
    Finding,
}

impl CommandStatus {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => SUCCESS,
            Self::Finding => FINDING,
        }
    }
}

#[derive(Debug)]
pub enum CliError {
    Input { code: String, message: String },
    Internal { message: String },
}

impl CliError {
    #[must_use]
    pub fn input(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Input {
            code: code.into(),
            message: message.into(),
        }
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Input { code, .. } => code,
            Self::Internal { .. } => "BW-INTERNAL",
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Input { message, .. } | Self::Internal { message } => message,
        }
    }

    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Input { .. } => INPUT_ERROR,
            Self::Internal { .. } => INTERNAL_ERROR,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for CliError {}

impl From<bw_model::ModelError> for CliError {
    fn from(error: bw_model::ModelError) -> Self {
        Self::input(error.code(), error.to_string())
    }
}

impl From<bw_oracle::OracleError> for CliError {
    fn from(error: bw_oracle::OracleError) -> Self {
        Self::input(error.code(), error.to_string())
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::input("BW-IO", error.to_string())
    }
}
