use std::{collections::BTreeSet, fs, path::PathBuf};

use bw_experiment::{
    CallbackApi, CaseOperation, CaseScenario, D0CaseMatrix, D0GroundTruth,
    validate_d0_matrix_against_ground_truth,
};

#[test]
fn d0_matrix_has_required_cases_and_keeps_labels_in_ground_truth_only() {
    let matrix = D0CaseMatrix::parse_toml(&fixture("experiments/configs/d0-cases.toml")).unwrap();
    let ground_truth =
        D0GroundTruth::parse_toml(&fixture("experiments/ground-truth/d0-cases.toml")).unwrap();
    validate_d0_matrix_against_ground_truth(&matrix, &ground_truth).unwrap();

    assert_eq!(matrix.repetitions, 20);
    assert_eq!(matrix.timeout_ms, 5000);
    assert!(matrix.compile_timeout_ms >= matrix.timeout_ms);
    assert_eq!(matrix.cases.len(), 12);
    assert_eq!(ground_truth.cases.len(), 12);

    let required = BTreeSet::from([
        CaseScenario::VulnerableBorrowed,
        CaseScenario::SafeMove,
        CaseScenario::UnregisterBeforeDrop,
        CaseScenario::NoTrigger,
        CaseScenario::FixedRunnable,
        CaseScenario::FixedBorrowedCompileRejection,
    ]);

    for api in [CallbackApi::UpdateHook, CallbackApi::CreateScalarFunction] {
        let scenarios = ground_truth
            .cases
            .iter()
            .filter(|case| case.api == api)
            .map(|case| case.scenario.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(scenarios, required, "missing scenario for api {api:?}");
    }

    for case in &ground_truth.cases {
        let matrix_case = matrix.case(case.case_id.as_str()).unwrap();
        assert_eq!(matrix_case.api, case.api);
        match case.scenario {
            CaseScenario::FixedBorrowedCompileRejection => {
                assert_eq!(matrix_case.operation, CaseOperation::CompileCheck);
            }
            _ => {
                assert_eq!(matrix_case.operation, CaseOperation::Run);
            }
        }
    }
}

#[test]
fn runner_config_rejects_answer_leaking_fields() {
    for forbidden in ["vulnerable", "fixed", "expected", "cve"] {
        let bad = format!(
            r#"
schema_version = "boundary-witness.d0-cases/0.1"
suite_id = "d0-rusqlite-callbacks"
repetitions = 20
timeout_ms = 5000
compile_timeout_ms = 120000

[[cases]]
case_id = "bad-case"
api = "update_hook"
operation = "run"
static_facts = "experiments/artifacts/d0/static/bad.jsonl"
executable = "experiments/artifacts/d0/bin/bad"
{forbidden} = true
"#
        );
        let error = D0CaseMatrix::parse_toml(&bad).unwrap_err().to_string();
        assert!(
            error.contains("unknown field") || error.contains(forbidden),
            "forbidden field {forbidden} was not rejected clearly: {error}"
        );
    }
}

fn fixture(relative: &str) -> String {
    let path = repo_root().join(relative);
    fs::read_to_string(path).unwrap()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
