use arbitrary::{Arbitrary, Unstructured};
use serde::{Deserialize, Serialize};

use crate::{ExperimentError, Result};

pub const D1_ACTION_SCHEMA_V01: &str = "boundary-witness.d1-actions/0.1";
pub const D1_MAX_ACTIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKind {
    UpdateHook,
    CreateScalarFunction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlOp {
    Insert,
    Update,
    Delete,
    SelectScalar,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FuzzAction {
    OpenConnection,
    CreateTable,
    CreateBorrowedState,
    RegisterBorrowed { api: ApiKind },
    RegisterOwned { api: ApiKind },
    Unregister { api: ApiKind },
    EndOwnerScope,
    ExecuteSql { op: SqlOp },
    CloseConnection,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDecoderMetadata {
    pub source: String,
    pub input_len: usize,
    pub truncated: bool,
}

impl Default for ActionDecoderMetadata {
    fn default() -> Self {
        Self {
            source: "manual".to_owned(),
            input_len: 0,
            truncated: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedProvenance {
    pub kind: String,
    pub name: String,
}

impl SeedProvenance {
    #[must_use]
    pub fn initial_corpus(name: impl Into<String>) -> Self {
        Self {
            kind: "initial_corpus".to_owned(),
            name: name.into(),
        }
    }

    #[must_use]
    pub fn decoded_bytes(name: impl Into<String>) -> Self {
        Self {
            kind: "decoded_bytes".to_owned(),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSequence {
    pub schema_version: String,
    pub actions: Vec<FuzzAction>,
    pub decoder: ActionDecoderMetadata,
    pub provenance: SeedProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionDecodeOptions {
    pub max_actions: usize,
    pub source: String,
}

impl Default for ActionDecodeOptions {
    fn default() -> Self {
        Self {
            max_actions: D1_MAX_ACTIONS,
            source: "libfuzzer".to_owned(),
        }
    }
}

impl ActionSequence {
    pub fn from_json_str(input: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(input)?;
        reject_forbidden_answer_label_keys(&value)?;
        let sequence = serde_json::from_value::<Self>(value)?;
        sequence.validate()?;
        Ok(sequence)
    }

    #[must_use]
    pub fn decode_bytes(input: &[u8], options: ActionDecodeOptions) -> Self {
        let max_actions = options.max_actions.min(D1_MAX_ACTIONS);
        let mut bytes = Unstructured::new(input);
        let mut actions = Vec::new();

        while actions.len() < max_actions && !bytes.is_empty() {
            let tag = u8::arbitrary(&mut bytes).unwrap_or_default();
            let action = match tag % 9 {
                0 => FuzzAction::OpenConnection,
                1 => FuzzAction::CreateTable,
                2 => FuzzAction::CreateBorrowedState,
                3 => FuzzAction::RegisterBorrowed {
                    api: decode_api(&mut bytes),
                },
                4 => FuzzAction::RegisterOwned {
                    api: decode_api(&mut bytes),
                },
                5 => FuzzAction::Unregister {
                    api: decode_api(&mut bytes),
                },
                6 => FuzzAction::EndOwnerScope,
                7 => FuzzAction::ExecuteSql {
                    op: decode_sql_op(&mut bytes),
                },
                _ => FuzzAction::CloseConnection,
            };
            actions.push(action);
        }

        let truncated = actions.len() == max_actions && !bytes.is_empty();
        Self {
            schema_version: D1_ACTION_SCHEMA_V01.to_owned(),
            actions,
            decoder: ActionDecoderMetadata {
                source: options.source,
                input_len: input.len(),
                truncated,
            },
            provenance: SeedProvenance::decoded_bytes(format!("sha256:{}", short_digest(input))),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != D1_ACTION_SCHEMA_V01 {
            return Err(ExperimentError::InvalidInput(format!(
                "unsupported d1 action schema_version: {}",
                self.schema_version
            )));
        }
        if self.actions.len() > D1_MAX_ACTIONS {
            return Err(ExperimentError::InvalidInput(format!(
                "action sequence exceeds max length: {} > {D1_MAX_ACTIONS}",
                self.actions.len()
            )));
        }
        if self.decoder.source.trim().is_empty() {
            return Err(ExperimentError::InvalidInput(
                "decoder.source must not be empty".to_owned(),
            ));
        }
        if self.provenance.kind.trim().is_empty() || self.provenance.name.trim().is_empty() {
            return Err(ExperimentError::InvalidInput(
                "seed provenance kind/name must not be empty".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn encode_seed_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        for action in &self.actions {
            match action {
                FuzzAction::OpenConnection => output.push(0),
                FuzzAction::CreateTable => output.push(1),
                FuzzAction::CreateBorrowedState => output.push(2),
                FuzzAction::RegisterBorrowed { api } => {
                    output.push(3);
                    output.push(encode_api(*api));
                }
                FuzzAction::RegisterOwned { api } => {
                    output.push(4);
                    output.push(encode_api(*api));
                }
                FuzzAction::Unregister { api } => {
                    output.push(5);
                    output.push(encode_api(*api));
                }
                FuzzAction::EndOwnerScope => output.push(6),
                FuzzAction::ExecuteSql { op } => {
                    output.push(7);
                    output.push(encode_sql_op(*op));
                }
                FuzzAction::CloseConnection => output.push(8),
            }
        }
        output
    }
}

fn decode_api(bytes: &mut Unstructured<'_>) -> ApiKind {
    match u8::arbitrary(bytes).unwrap_or_default() % 2 {
        0 => ApiKind::UpdateHook,
        _ => ApiKind::CreateScalarFunction,
    }
}

fn encode_api(api: ApiKind) -> u8 {
    match api {
        ApiKind::UpdateHook => 0,
        ApiKind::CreateScalarFunction => 1,
    }
}

fn decode_sql_op(bytes: &mut Unstructured<'_>) -> SqlOp {
    match u8::arbitrary(bytes).unwrap_or_default() % 4 {
        0 => SqlOp::Insert,
        1 => SqlOp::Update,
        2 => SqlOp::Delete,
        _ => SqlOp::SelectScalar,
    }
}

fn encode_sql_op(op: SqlOp) -> u8 {
    match op {
        SqlOp::Insert => 0,
        SqlOp::Update => 1,
        SqlOp::Delete => 2,
        SqlOp::SelectScalar => 3,
    }
}

fn reject_forbidden_answer_label_keys(value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            for (key, nested) in object {
                if is_forbidden_answer_label(key) {
                    return Err(ExperimentError::InvalidInput(format!(
                        "forbidden answer label field in d1 action input: {key}"
                    )));
                }
                reject_forbidden_answer_label_keys(nested)?;
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                reject_forbidden_answer_label_keys(nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_forbidden_answer_label(key: &str) -> bool {
    matches!(
        key,
        "cve"
            | "vulnerable"
            | "fixed"
            | "expected"
            | "crate_version"
            | "vulnerable_version"
            | "fixed_version"
    )
}

fn short_digest(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(input);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
