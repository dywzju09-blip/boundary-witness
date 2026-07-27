use rusqlite_lab_shared::blind_runner::{
    parse_ground_truth, parse_runner_config, plan_cases, verify_against_ground_truth,
    GroundTruthSet, ObservedCaseResult, ObservedOutcome,
};

#[test]
fn runner_config_rejects_ground_truth_label_fields() {
    for forbidden_field in [
        "vulnerable = true",
        "fixed = true",
        "cve = \"CVE-2021-32737\"",
        "expected = \"confirmed_violation\"",
    ] {
        let config = format!(
            r#"
schema_version = "bw.rusqlite-runner/0.1"
suite_id = "suite:rusqlite-m12"
build_id = "build:test"
contract = "contracts/callback-retention/contract.toml"
bw_binary = "target/debug/bw"
output_dir = "target/blind-run"

[[cases]]
static_facts = "facts/static.jsonl"
executable = "target/debug/case"
{forbidden_field}
"#
        );

        let error = parse_runner_config(&config)
            .expect_err("runner config must not deserialize embedded labels");
        assert!(
            error.to_string().contains("unknown field"),
            "unexpected error for {forbidden_field}: {error}"
        );
    }
}

#[test]
fn runner_assigns_stable_opaque_case_ids_and_isolates_outputs() {
    let config = parse_runner_config(
        r#"
schema_version = "bw.rusqlite-runner/0.1"
suite_id = "suite:rusqlite-m12"
build_id = "build:test"
contract = "contracts/callback-retention/contract.toml"
bw_binary = "target/debug/bw"
output_dir = "target/blind-run"

[[cases]]
static_facts = "facts/update/static-facts.jsonl"
executable = "target/debug/update_case"
args = ["--seed", "1"]

[[cases]]
static_facts = "facts/scalar/static-facts.jsonl"
executable = "target/debug/scalar_case"
"#,
    )
    .expect("label-free config should parse");

    let planned = plan_cases(&config).expect("cases should be materialized");

    assert_eq!(planned.len(), 2);
    assert_eq!(planned[0].case_id.as_str(), "case-0001");
    assert_eq!(planned[1].case_id.as_str(), "case-0002");
    assert!(planned[0].trace_dir.ends_with("case-0001/trace"));
    assert!(planned[0].stdout_log.ends_with("case-0001/stdout.log"));
    assert!(planned[0].stderr_log.ends_with("case-0001/stderr.log"));
    assert!(planned[0]
        .findings_path
        .ends_with("case-0001/findings.jsonl"));
    assert_eq!(planned[0].args, ["--seed", "1"]);
}

#[test]
fn verifier_joins_ground_truth_only_after_observed_results_exist() {
    let ground_truth = parse_ground_truth(
        r#"
schema_version = "bw.rusqlite-ground-truth/0.1"
suite_id = "suite:rusqlite-m12"

[[cases]]
case_id = "case-0001"
expectation = "confirmed_violation"
family = "update_hook"
notes = "borrowed callback invoked after object drop"

[[cases]]
case_id = "case-0002"
expectation = "clean"
family = "create_scalar_function"
notes = "owned capture"
"#,
    )
    .expect("ground truth should parse separately");

    let report = verify_against_ground_truth(
        &[
            ObservedCaseResult {
                case_id: "case-0001".to_owned(),
                outcome: ObservedOutcome::ConfirmedViolation,
                finding_rule_ids: vec!["BW-LIFE-002".to_owned()],
                child_exit_code: Some(0),
                analyze_exit_code: Some(1),
            },
            ObservedCaseResult {
                case_id: "case-0002".to_owned(),
                outcome: ObservedOutcome::Clean,
                finding_rule_ids: Vec::new(),
                child_exit_code: Some(0),
                analyze_exit_code: Some(0),
            },
        ],
        &GroundTruthSet {
            cases: ground_truth.cases,
        },
    )
    .expect("observed results should match ground truth");

    assert_eq!(report.total_cases, 2);
    assert_eq!(report.mismatches.len(), 0);
}

#[test]
fn repository_m12_config_and_ground_truth_use_matching_opaque_ids() {
    let config = parse_runner_config(include_str!(
        "../../../../../experiments/configs/rusqlite-m12-cases.toml"
    ))
    .expect("repository M12 runner config should parse");
    let planned = plan_cases(&config).expect("repository cases should materialize");
    let ground_truth = parse_ground_truth(include_str!(
        "../../../../../experiments/ground-truth/rusqlite-m12.toml"
    ))
    .expect("repository M12 ground truth should parse");

    let planned_ids = planned
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<Vec<_>>();
    let expected_ids = ground_truth
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(planned_ids, expected_ids);
    assert_eq!(planned_ids.len(), 10);
}
