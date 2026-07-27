use std::path::Path;

use crate::{BlindModelError, Result, error::validation};

pub const BLIND_POLICY_SCHEMA_V01: &str = "boundary-witness.blind-policy/0.1";
pub const MANDATORY_FORBIDDEN_PUBLIC_TOKENS: &[&str] = &[
    "ground-truth",
    "ground_truth",
    "cve-",
    "ghsa-",
    "advisory",
    "poc",
    "proof-of-concept",
    "proof_of_concept",
    "expected-result",
    "expected_result",
    "expected result",
    "private",
];

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindPolicy {
    pub schema_version: String,
    pub minimum_replay_attempts: u32,
    pub gate_minimum_confirmed_cases: u32,
    pub forbidden_public_filename_tokens: Vec<String>,
}

impl BlindPolicy {
    pub fn parse_toml(input: &str) -> Result<Self> {
        let policy: Self = toml::from_str(input)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let input = std::fs::read_to_string(path).map_err(|source| BlindModelError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_toml(&input)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != BLIND_POLICY_SCHEMA_V01 {
            return Err(validation("unsupported blind policy schema_version"));
        }
        if self.minimum_replay_attempts == 0 || self.gate_minimum_confirmed_cases == 0 {
            return Err(validation("policy numeric fields must be non-zero"));
        }
        if self
            .forbidden_public_filename_tokens
            .iter()
            .any(|token| token.is_empty())
        {
            return Err(validation("forbidden filename tokens must be non-empty"));
        }
        for mandatory in MANDATORY_FORBIDDEN_PUBLIC_TOKENS {
            if !self
                .forbidden_public_filename_tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case(mandatory))
            {
                return Err(validation(format!(
                    "policy is missing mandatory forbidden public token: {mandatory}"
                )));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn find_forbidden_public_token<'a>(&'a self, value: &str) -> Option<&'a str> {
        let lowercase = value.to_lowercase();
        MANDATORY_FORBIDDEN_PUBLIC_TOKENS
            .iter()
            .copied()
            .find(|token| contains_forbidden_token(&lowercase, token))
            .or_else(|| {
                self.forbidden_public_filename_tokens
                    .iter()
                    .map(String::as_str)
                    .find(|token| contains_forbidden_token(&lowercase, &token.to_lowercase()))
            })
    }
}

fn contains_forbidden_token(value: &str, token: &str) -> bool {
    if token == "poc" {
        return contains_bounded_poc(value);
    }
    value.contains(token)
}

fn contains_bounded_poc(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(3).enumerate().any(|(index, window)| {
        if window != b"poc" {
            return false;
        }
        let before_is_word = index
            .checked_sub(1)
            .and_then(|before| bytes.get(before))
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
        let after_is_word = bytes
            .get(index + 3)
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
        !before_is_word && !after_is_word
    })
}
