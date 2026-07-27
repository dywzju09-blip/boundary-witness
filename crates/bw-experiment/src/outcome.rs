use bw_model::{ExecutionEvidence, ExecutionResult, PrimaryOutcome};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeFacts {
    pub has_contract_finding: bool,
    pub has_asan_evidence: bool,
    pub has_native_crash: bool,
    pub has_panic: bool,
    pub has_timeout: bool,
    pub invalid_input: bool,
    pub tool_error: bool,
}

#[must_use]
pub fn classify_outcome(facts: &OutcomeFacts) -> ExecutionResult {
    let primary_outcome = if facts.has_timeout {
        PrimaryOutcome::Timeout
    } else if facts.invalid_input {
        PrimaryOutcome::InvalidInput
    } else if facts.tool_error {
        PrimaryOutcome::ToolError
    } else if facts.has_contract_finding {
        PrimaryOutcome::ContractFinding
    } else if facts.has_asan_evidence {
        PrimaryOutcome::Asan
    } else if facts.has_native_crash {
        PrimaryOutcome::NativeCrash
    } else if facts.has_panic {
        PrimaryOutcome::Panic
    } else {
        PrimaryOutcome::NoFinding
    };

    ExecutionResult {
        primary_outcome,
        evidence: ExecutionEvidence {
            has_contract_finding: facts.has_contract_finding,
            has_asan_evidence: facts.has_asan_evidence,
            has_native_crash: facts.has_native_crash,
            has_panic: facts.has_panic,
            has_timeout: facts.has_timeout,
        },
    }
}
