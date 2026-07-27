use std::{io, path::Path};

use thiserror::Error;

/// 输入事实、证据或 schema 不满足模型约束。
#[derive(Debug, Error)]
pub enum ModelError {
    /// JSON 语法或字段结构无效。
    #[error("JSON 结构无效: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// TOML 语法或字段结构无效。
    #[error("TOML 结构无效: {0}")]
    InvalidToml(#[from] toml::de::Error),

    /// 输入使用了当前工具不支持的 schema 版本。
    #[error("不支持 schema {found}，当前要求 {expected}")]
    UnsupportedSchema {
        expected: &'static str,
        found: String,
    },

    /// 文件读取或压缩流解码失败。
    #[error("{operation}失败: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    /// 单条 JSONL 记录超过配置上限。
    #[error("JSONL 行至少有 {observed_at_least} 字节，超过上限 {max_bytes} 字节")]
    LineTooLong {
        max_bytes: usize,
        observed_at_least: usize,
    },

    /// 版本化证据内部引用或顺序不合法。
    #[error("{message}")]
    Validation { code: &'static str, message: String },

    /// 为底层错误补充文件路径。
    #[error("{}: {source}", path.display())]
    AtPath {
        path: std::path::PathBuf,
        #[source]
        source: Box<Self>,
    },

    /// 为底层错误补充文件路径和物理行号。
    #[error("{}:{line}: {source}", path.display())]
    AtLine {
        path: std::path::PathBuf,
        line: usize,
        #[source]
        source: Box<Self>,
    },
}

impl ModelError {
    /// 返回供脚本和实验汇总使用的稳定错误码。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidJson(_) => "BW-JSON-INVALID",
            Self::InvalidToml(_) => "BW-TOML-INVALID",
            Self::UnsupportedSchema { .. } => "BW-SCHEMA-UNSUPPORTED",
            Self::Io { .. } => "BW-IO",
            Self::LineTooLong { .. } => "BW-JSONL-LINE-TOO-LONG",
            Self::Validation { code, .. } => code,
            Self::AtPath { source, .. } | Self::AtLine { source, .. } => source.code(),
        }
    }

    /// 返回错误关联的输入路径。
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::AtPath { path, .. } | Self::AtLine { path, .. } => Some(path),
            _ => None,
        }
    }

    /// 返回错误关联的 JSONL 物理行号。
    #[must_use]
    pub fn line(&self) -> Option<usize> {
        match self {
            Self::AtLine { line, .. } => Some(*line),
            _ => None,
        }
    }

    pub(crate) fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    pub(crate) fn validation(code: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn at_path(self, path: impl Into<std::path::PathBuf>) -> Self {
        Self::AtPath {
            path: path.into(),
            source: Box::new(self),
        }
    }

    pub(crate) fn at_line(self, path: impl Into<std::path::PathBuf>, line: usize) -> Self {
        Self::AtLine {
            path: path.into(),
            line,
            source: Box::new(self),
        }
    }
}
