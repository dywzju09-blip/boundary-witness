use bw_blind_model::{
    BlindCaseId, BlindCaseObservation, BlindCaseStatus, BlindObservedFinding, BlindSplit,
    BlindWitnessEvidence,
};
use bw_model::FindingClassification;

fn completed_observation() -> BlindCaseObservation {
    BlindCaseObservation {
        schema_version: "boundary-witness.blind-observed/0.1".to_owned(),
        suite_id: "suite-2026-001".to_owned(),
        split: BlindSplit::Gate,
        case_id: BlindCaseId::parse("blind-8f34a923d01c77ab").expect("valid opaque case ID"),
        method_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        public_manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        status: BlindCaseStatus::Completed,
        findings: vec![BlindObservedFinding {
            rule_id: "synthetic-rule".to_owned(),
            classification: FindingClassification::ConfirmedViolation,
            normalized_signature:
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            evidence_complete: true,
        }],
        witness: Some(BlindWitnessEvidence {
            artifact_path: "artifacts/witness.json".to_owned(),
            artifact_sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_owned(),
            replay_attempts: 20,
            replay_successes: 20,
        }),
    }
}

#[test]
fn completed_confirmed_observation_validates() {
    completed_observation()
        .validate(20)
        .expect("complete 20/20 confirmed observation should validate");
}

#[test]
fn observation_contract_rejects_invalid_evidence_and_status_combinations() {
    let mut observation = completed_observation();
    observation
        .witness
        .as_mut()
        .expect("witness")
        .replay_attempts = 19;
    assert!(
        observation
            .validate(20)
            .expect_err("19 attempts should fail")
            .to_string()
            .contains("witness replay_attempts must meet minimum policy")
    );

    let mut observation = completed_observation();
    observation.witness = None;
    assert!(
        observation
            .validate(20)
            .expect_err("missing witness should fail")
            .to_string()
            .contains("confirmed violations require a witness")
    );

    let mut observation = completed_observation();
    observation.findings[0].evidence_complete = false;
    assert!(
        observation
            .validate(20)
            .expect_err("incomplete evidence should fail")
            .to_string()
            .contains("confirmed violations require complete evidence")
    );

    let mut observation = completed_observation();
    observation.findings.push(observation.findings[0].clone());
    assert!(
        observation
            .validate(20)
            .expect_err("duplicate finding should fail")
            .to_string()
            .contains("finding rule_id and normalized_signature pairs must be unique")
    );

    let mut observation = completed_observation();
    observation.witness.as_mut().expect("witness").artifact_path = "../escape".to_owned();
    assert!(
        observation
            .validate(20)
            .expect_err("unsafe artifact path should fail")
            .to_string()
            .contains("artifact_path must be a non-empty relative slash path")
    );

    let mut observation = completed_observation();
    observation.status = BlindCaseStatus::ToolError;
    assert!(
        observation
            .validate(20)
            .expect_err("tool errors cannot retain findings")
            .to_string()
            .contains("non-completed observations must not include findings or witness")
    );
}

#[test]
fn observation_round_trips_and_rejects_unknown_fields() {
    let observation = completed_observation();
    let json = serde_json::to_string(&observation).expect("serialize observation");
    let parsed = BlindCaseObservation::parse_json(&json).expect("parse observation");
    parsed.validate(20).expect("parsed observation validates");
    assert_eq!(parsed, observation);

    let with_unknown_field = json.replace("\"suite_id\":", "\"cve\":\"synthetic\",\"suite_id\":");
    assert!(BlindCaseObservation::parse_json(&with_unknown_field).is_err());
}

#[test]
fn observation_schema_disallows_unknown_fields_at_every_object_layer() {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../experiments/schemas/blind-observation.schema.json"
    );
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(schema_path).expect("schema should be readable"),
    )
    .expect("schema should be JSON");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["$defs"]["finding"]["additionalProperties"], false);
    assert_eq!(schema["$defs"]["witness"]["additionalProperties"], false);
}

#[test]
fn observation_schema_rejects_parent_directory_path_components() {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../experiments/schemas/blind-observation.schema.json"
    );
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(schema_path).expect("schema should be readable"),
    )
    .expect("schema should be JSON");
    let artifact_path = &schema["$defs"]["witness"]["properties"]["artifact_path"];
    let path_pattern = regex::Regex::new(
        artifact_path["pattern"]
            .as_str()
            .expect("artifact_path should have a pattern"),
    )
    .expect("artifact_path pattern should compile");
    let rejected_component = regex::Regex::new(
        artifact_path["not"]["pattern"]
            .as_str()
            .expect("artifact_path should explicitly reject parent components"),
    )
    .expect("parent-component pattern should compile");

    for path in ["..", "../escape", "artifacts/../witness.json"] {
        assert!(
            !(path_pattern.is_match(path) && !rejected_component.is_match(path)),
            "schema should reject parent-directory component {path:?}"
        );
    }
    assert!(
        path_pattern.is_match("artifacts/witness.json")
            && !rejected_component.is_match("artifacts/witness.json")
    );
}
