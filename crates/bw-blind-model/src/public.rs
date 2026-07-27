use std::{collections::BTreeSet, path::Path};

use crate::{BlindCaseId, BlindModelError, Result, error::validation};

pub const BLIND_PUBLIC_SCHEMA_V01: &str = "boundary-witness.blind-public/0.1";

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BlindSplit {
    Gate,
    Evaluation,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindCommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindPublicCase {
    pub case_id: BlindCaseId,
    pub case_root: String,
    pub case_sha256: String,
    pub command: BlindCommandSpec,
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindPublicManifest {
    pub schema_version: String,
    pub suite_id: String,
    pub split: BlindSplit,
    pub method_commit: String,
    pub policy_sha256: String,
    pub cases: Vec<BlindPublicCase>,
}

impl BlindPublicManifest {
    pub fn parse_json(input: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(input)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let input = std::fs::read_to_string(path).map_err(|source| BlindModelError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_json(&input)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != BLIND_PUBLIC_SCHEMA_V01 {
            return Err(validation("unsupported blind public schema_version"));
        }
        if !is_suite_id(&self.suite_id) {
            return Err(validation(
                "suite_id must use ASCII alphanumeric, '-', '_', or '.'",
            ));
        }
        if !is_lower_hex(&self.method_commit, 40) {
            return Err(validation(
                "method_commit must be 40 lowercase hexadecimal characters",
            ));
        }
        if !is_lower_hex(&self.policy_sha256, 64) {
            return Err(validation(
                "policy_sha256 must be 64 lowercase hexadecimal characters",
            ));
        }

        let mut case_ids = BTreeSet::new();
        let mut case_roots = BTreeSet::new();
        for case in &self.cases {
            BlindCaseId::parse(case.case_id.as_str())?;
            if !is_relative_slash_path(&case.case_root) {
                return Err(validation(
                    "case_root must be a non-empty relative slash path",
                ));
            }
            if case.case_root != format!("cases/{}", case.case_id) {
                return Err(validation("case_root must equal cases/<case_id>"));
            }
            if !is_lower_hex(&case.case_sha256, 64) {
                return Err(validation(
                    "case_sha256 must be 64 lowercase hexadecimal characters",
                ));
            }
            if !is_relative_slash_path(&case.command.program) {
                return Err(validation(
                    "command program must be a non-empty relative slash path",
                ));
            }
            if case.timeout_seconds == 0 {
                return Err(validation("timeout_seconds must be non-zero"));
            }
            if !case_ids.insert(case.case_id.clone()) {
                return Err(validation("case IDs must be unique"));
            }
            if !case_roots.insert(&case.case_root) {
                return Err(validation("case roots must be unique"));
            }
        }
        Ok(())
    }
}

pub(crate) fn is_suite_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_relative_slash_path(value: &str) -> bool {
    !value.is_empty()
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.contains('\\')
        })
}
