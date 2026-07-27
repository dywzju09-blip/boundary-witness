mod common;

use bw_model::EvidenceSourceKind;
use bw_oracle::normalize_finding;

use common::sample_finding;

#[test]
fn renaming_runtime_ids_does_not_change_signature() {
    let first =
        normalize_finding(&sample_finding("first")).expect("first finding should normalize");
    let renumbered = normalize_finding(&sample_finding("renumbered"))
        .expect("renumbered finding should normalize");

    assert_eq!(first, renumbered);
    assert_eq!(first.signature.len(), 64);
}

#[test]
fn normalized_finding_excludes_runtime_identity_and_message() {
    let normalized =
        normalize_finding(&sample_finding("private-id")).expect("finding should normalize");
    let json = serde_json::to_string(&normalized).expect("normalized finding should serialize");

    assert!(!json.contains("private-id"));
    assert!(!json.contains("仅供阅读"));
    assert!(json.contains("clause:borrow-outlives-retention"));
    assert!(json.contains("BW-EVIDENCE-CAPTURE-BIND"));
}

#[test]
fn confirmed_finding_without_contract_source_is_rejected() {
    let mut incomplete = sample_finding("incomplete");
    incomplete
        .evidence
        .retain(|reference| reference.source_kind != EvidenceSourceKind::ContractClause);

    let error = normalize_finding(&incomplete).expect_err("incomplete evidence must fail");
    assert_eq!(error.code(), "BW-ORACLE-EVIDENCE-INCOMPLETE");
}
