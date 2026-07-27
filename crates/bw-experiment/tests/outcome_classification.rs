use std::{fs, path::PathBuf};

use bw_experiment::{OutcomeFacts, PrimaryOutcome, classify_outcome};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OutcomeFixture {
    name: String,
    facts: OutcomeFacts,
    expected_primary_outcome: PrimaryOutcome,
    expected_evidence: ExpectedEvidence,
}

#[derive(Debug, Deserialize)]
struct ExpectedEvidence {
    has_contract_finding: bool,
    has_asan_evidence: bool,
    has_native_crash: bool,
    has_panic: bool,
    has_timeout: bool,
}

#[test]
fn fixtures_classify_to_unique_primary_outcome_without_losing_independent_evidence() {
    for fixture in load_fixtures() {
        let result = classify_outcome(&fixture.facts);

        assert_eq!(
            result.primary_outcome, fixture.expected_primary_outcome,
            "fixture {} primary outcome mismatch",
            fixture.name
        );
        assert_eq!(
            result.evidence.has_contract_finding, fixture.expected_evidence.has_contract_finding,
            "fixture {} contract evidence mismatch",
            fixture.name
        );
        assert_eq!(
            result.evidence.has_asan_evidence, fixture.expected_evidence.has_asan_evidence,
            "fixture {} asan evidence mismatch",
            fixture.name
        );
        assert_eq!(
            result.evidence.has_native_crash, fixture.expected_evidence.has_native_crash,
            "fixture {} native crash evidence mismatch",
            fixture.name
        );
        assert_eq!(
            result.evidence.has_panic, fixture.expected_evidence.has_panic,
            "fixture {} panic evidence mismatch",
            fixture.name
        );
        assert_eq!(
            result.evidence.has_timeout, fixture.expected_evidence.has_timeout,
            "fixture {} timeout evidence mismatch",
            fixture.name
        );

        if fixture.name == "finding_and_asan" {
            assert_eq!(result.primary_outcome, PrimaryOutcome::ContractFinding);
            assert!(result.evidence.has_contract_finding);
            assert!(result.evidence.has_asan_evidence);
        }
    }
}

fn load_fixtures() -> Vec<OutcomeFixture> {
    let fixture_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/experiment/outcomes");
    let mut paths = fs::read_dir(&fixture_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("invalid fixture {}: {error}", path.display()))
        })
        .collect()
}
