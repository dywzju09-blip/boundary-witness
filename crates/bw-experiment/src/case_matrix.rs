use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{ExperimentError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D0CaseMatrix {
    pub schema_version: String,
    pub suite_id: String,
    pub repetitions: u32,
    pub timeout_ms: u64,
    pub compile_timeout_ms: u64,
    pub cases: Vec<D0Case>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D0Case {
    pub case_id: String,
    pub api: CallbackApi,
    pub operation: CaseOperation,
    pub static_facts: Option<PathBuf>,
    pub executable: Option<PathBuf>,
    pub source: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOperation {
    Run,
    CompileCheck,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D0GroundTruth {
    pub schema_version: String,
    pub suite_id: String,
    pub cases: Vec<GroundTruthCase>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundTruthCase {
    pub case_id: String,
    pub api: CallbackApi,
    pub scenario: CaseScenario,
    pub expectation: CaseExpectation,
    pub cves: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackApi {
    UpdateHook,
    CreateScalarFunction,
}

impl std::fmt::Display for CallbackApi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UpdateHook => "update_hook",
            Self::CreateScalarFunction => "create_scalar_function",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseScenario {
    VulnerableBorrowed,
    SafeMove,
    UnregisterBeforeDrop,
    NoTrigger,
    FixedRunnable,
    FixedBorrowedCompileRejection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseExpectation {
    ConfirmedViolation,
    Clean,
    ExposureOnly,
    CompileRejection,
}

impl D0CaseMatrix {
    pub fn parse_toml(input: &str) -> Result<Self> {
        let matrix = toml::from_str::<Self>(input).map_err(|error| {
            ExperimentError::InvalidInput(format!("invalid d0 case matrix toml: {error}"))
        })?;
        matrix.validate()?;
        Ok(matrix)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|error| ExperimentError::io(path, error))?;
        Self::parse_toml(&input)
    }

    #[must_use]
    pub fn case(&self, case_id: &str) -> Option<&D0Case> {
        self.cases.iter().find(|case| case.case_id == case_id)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != "boundary-witness.d0-cases/0.1" {
            return Err(ExperimentError::InvalidInput(format!(
                "unsupported d0 case matrix schema_version: {}",
                self.schema_version
            )));
        }
        if self.repetitions == 0 {
            return Err(ExperimentError::InvalidInput(
                "repetitions must be greater than zero".to_owned(),
            ));
        }
        if self.timeout_ms == 0 || self.compile_timeout_ms == 0 {
            return Err(ExperimentError::InvalidInput(
                "timeouts must be greater than zero".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for case in &self.cases {
            validate_case_id(&case.case_id)?;
            if !seen.insert(case.case_id.clone()) {
                return Err(ExperimentError::InvalidInput(format!(
                    "duplicate matrix case_id: {}",
                    case.case_id
                )));
            }
            match case.operation {
                CaseOperation::Run => {
                    require_present(&case.static_facts, &case.case_id, "static_facts")?;
                    require_present(&case.executable, &case.case_id, "executable")?;
                    require_absent(&case.source, &case.case_id, "source")?;
                }
                CaseOperation::CompileCheck => {
                    require_present(&case.source, &case.case_id, "source")?;
                    require_absent(&case.static_facts, &case.case_id, "static_facts")?;
                    require_absent(&case.executable, &case.case_id, "executable")?;
                }
            }
        }
        Ok(())
    }
}

impl D0GroundTruth {
    pub fn parse_toml(input: &str) -> Result<Self> {
        let ground_truth = toml::from_str::<Self>(input).map_err(|error| {
            ExperimentError::InvalidInput(format!("invalid d0 ground truth toml: {error}"))
        })?;
        ground_truth.validate()?;
        Ok(ground_truth)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|error| ExperimentError::io(path, error))?;
        Self::parse_toml(&input)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != "boundary-witness.d0-ground-truth/0.1" {
            return Err(ExperimentError::InvalidInput(format!(
                "unsupported d0 ground truth schema_version: {}",
                self.schema_version
            )));
        }
        let mut seen = BTreeSet::new();
        for case in &self.cases {
            validate_case_id(&case.case_id)?;
            if !seen.insert(case.case_id.clone()) {
                return Err(ExperimentError::InvalidInput(format!(
                    "duplicate ground truth case_id: {}",
                    case.case_id
                )));
            }
        }
        Ok(())
    }
}

pub fn validate_d0_matrix_against_ground_truth(
    matrix: &D0CaseMatrix,
    ground_truth: &D0GroundTruth,
) -> Result<()> {
    if matrix.suite_id != ground_truth.suite_id {
        return Err(ExperimentError::InvalidInput(format!(
            "suite_id mismatch: matrix={} ground_truth={}",
            matrix.suite_id, ground_truth.suite_id
        )));
    }

    let matrix_cases = matrix
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let ground_truth_cases = ground_truth
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();

    for case_id in matrix_cases.keys() {
        if !ground_truth_cases.contains_key(case_id) {
            return Err(ExperimentError::InvalidInput(format!(
                "matrix case has no ground truth: {case_id}"
            )));
        }
    }
    for (case_id, truth) in &ground_truth_cases {
        let Some(matrix_case) = matrix_cases.get(case_id) else {
            return Err(ExperimentError::InvalidInput(format!(
                "ground truth case missing from matrix: {case_id}"
            )));
        };
        let expected_operation = match truth.scenario {
            CaseScenario::FixedBorrowedCompileRejection => CaseOperation::CompileCheck,
            _ => CaseOperation::Run,
        };
        if matrix_case.operation != expected_operation {
            return Err(ExperimentError::InvalidInput(format!(
                "case {case_id} operation mismatch: matrix={:?} expected={:?}",
                matrix_case.operation, expected_operation
            )));
        }
        if matrix_case.api != truth.api {
            return Err(ExperimentError::InvalidInput(format!(
                "case {case_id} api mismatch: matrix={:?} ground_truth={:?}",
                matrix_case.api, truth.api
            )));
        }
    }

    Ok(())
}

fn validate_case_id(case_id: &str) -> Result<()> {
    if case_id.is_empty()
        || !case_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(ExperimentError::InvalidInput(format!(
            "unsafe case_id: {case_id}"
        )));
    }
    Ok(())
}

fn require_present(value: &Option<PathBuf>, case_id: &str, field: &str) -> Result<()> {
    if value.is_none() {
        return Err(ExperimentError::InvalidInput(format!(
            "case {case_id} requires field {field}"
        )));
    }
    Ok(())
}

fn require_absent(value: &Option<PathBuf>, case_id: &str, field: &str) -> Result<()> {
    if value.is_some() {
        return Err(ExperimentError::InvalidInput(format!(
            "case {case_id} must not set field {field}"
        )));
    }
    Ok(())
}
