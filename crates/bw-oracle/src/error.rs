use thiserror::Error;

/// 已校验输入之间缺少必要对应关系，或 Oracle 状态迁移不成立。
#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct OracleError {
    code: &'static str,
    message: String,
}

impl OracleError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}
