use std::path::PathBuf;

use bw_model::{
    Located, V3_2_BOUNDARY_INDEX_SCHEMA_V1, V3_2_CANDIDATE_SCHEMA_V1, V32BoundaryEvidenceKind,
    V32BoundaryEvidenceRef, V32BoundaryIndexRecord, V32BoundaryKind, V32CandidateConfidence,
    V32CandidateRecord, V32PatternFamily, V32RecommendedNextStep, candidate_from_boundary,
    validate_v3_2_candidates,
};

#[test]
fn candidate_from_boundary_skips_negative_summary() {
    let negative = V32BoundaryIndexRecord {
        schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
        run_id: "v3-2-candidate-test".to_owned(),
        crate_id: "crate:plain:0.1.0".to_owned(),
        boundary_id: "boundary:plain:negative-summary".to_owned(),
        boundary_kind: V32BoundaryKind::NegativeSummary,
        api_path: None,
        evidence_refs: vec![manifest_ref("Cargo.toml")],
        confidence: "high".to_owned(),
        notes: Vec::new(),
    };
    assert!(candidate_from_boundary(&negative, "v3-2-candidate-test").is_none());
}

#[test]
fn candidate_from_boundary_maps_callback_registration() {
    let boundary = V32BoundaryIndexRecord {
        schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
        run_id: "v3-2-boundary-test".to_owned(),
        crate_id: "crate:ffi-wrapper:0.1.0".to_owned(),
        boundary_id: "boundary:ffi-wrapper:callback-registration:0001".to_owned(),
        boundary_kind: V32BoundaryKind::CallbackRegistration,
        api_path: Some("ffi_wrapper::register_callback".to_owned()),
        evidence_refs: vec![source_ref("src/lib.rs", 12, 12)],
        confidence: "high".to_owned(),
        notes: Vec::new(),
    };
    let candidate =
        candidate_from_boundary(&boundary, "v3-2-candidate-test").expect("candidate should exist");
    assert_eq!(candidate.schema_version, V3_2_CANDIDATE_SCHEMA_V1);
    assert_eq!(
        candidate.candidate_id,
        "candidate:ffi-wrapper:callback-registration:0001"
    );
    assert_eq!(
        candidate.pattern_family,
        V32PatternFamily::RetainedBorrowedCallback
    );
    assert_eq!(
        candidate.confidence,
        V32CandidateConfidence::NeedsDynamicValidation
    );
    assert_eq!(
        candidate.recommended_next_step,
        V32RecommendedNextStep::GenerateLifecycleSubgraph
    );
}

#[test]
fn candidate_from_boundary_maps_static_lifecycle_boundaries_to_neutral_patterns() {
    let returned = V32BoundaryIndexRecord {
        schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
        run_id: "v3-2-boundary-test".to_owned(),
        crate_id: "crate:lifecycle-neutral:0.1.0".to_owned(),
        boundary_id: "boundary:lifecycle:return:0001".to_owned(),
        boundary_kind: V32BoundaryKind::ReturnedBorrow,
        api_path: Some("lifecycle_neutral::borrowed_view".to_owned()),
        evidence_refs: vec![source_ref("src/lib.rs", 5, 5)],
        confidence: "medium".to_owned(),
        notes: Vec::new(),
    };
    let external = V32BoundaryIndexRecord {
        boundary_id: "boundary:lifecycle:buffer:0001".to_owned(),
        boundary_kind: V32BoundaryKind::ExternalBuffer,
        api_path: Some("lifecycle_neutral::external_slice".to_owned()),
        evidence_refs: vec![source_ref("src/lib.rs", 12, 12)],
        ..returned.clone()
    };

    let returned_candidate =
        candidate_from_boundary(&returned, "v3-2-candidate-test").expect("candidate should exist");
    let external_candidate =
        candidate_from_boundary(&external, "v3-2-candidate-test").expect("candidate should exist");

    assert_eq!(
        returned_candidate.pattern_family,
        V32PatternFamily::ReturnedBorrowView
    );
    assert_eq!(
        external_candidate.pattern_family,
        V32PatternFamily::ExternalBufferView
    );
    assert_eq!(
        returned_candidate.confidence,
        V32CandidateConfidence::StaticOnly
    );
    assert_eq!(
        external_candidate.confidence,
        V32CandidateConfidence::StaticOnly
    );
    assert!(
        returned_candidate
            .notes
            .contains(&"source_boundary_kind=returned_borrow".to_owned())
    );
    assert!(
        external_candidate
            .notes
            .contains(&"source_boundary_kind=external_buffer".to_owned())
    );
}

#[test]
fn candidate_validation_counts_confidence_buckets() {
    let records = vec![
        located(V32CandidateRecord {
            schema_version: V3_2_CANDIDATE_SCHEMA_V1.to_owned(),
            run_id: "v3-2-candidate-test".to_owned(),
            candidate_id: "candidate:a:1".to_owned(),
            crate_id: "crate:a:0.1.0".to_owned(),
            boundary_id: "boundary:a:1".to_owned(),
            pattern_family: V32PatternFamily::RetainedBorrowedCallback,
            confidence: V32CandidateConfidence::NeedsDynamicValidation,
            evidence_refs: vec![source_ref("src/lib.rs", 1, 1)],
            api_path: Some("a::register".to_owned()),
            recommended_next_step: V32RecommendedNextStep::GenerateLifecycleSubgraph,
            notes: vec!["candidate is not a vulnerability conclusion".to_owned()],
        }),
        located(V32CandidateRecord {
            schema_version: V3_2_CANDIDATE_SCHEMA_V1.to_owned(),
            run_id: "v3-2-candidate-test".to_owned(),
            candidate_id: "candidate:b:1".to_owned(),
            crate_id: "crate:b:0.1.0".to_owned(),
            boundary_id: "boundary:b:1".to_owned(),
            pattern_family: V32PatternFamily::NativeLibraryBoundary,
            confidence: V32CandidateConfidence::StaticOnly,
            evidence_refs: vec![source_ref("src/lib.rs", 2, 2)],
            api_path: Some("extern".to_owned()),
            recommended_next_step: V32RecommendedNextStep::GenerateLifecycleSubgraph,
            notes: vec!["candidate is not a vulnerability conclusion".to_owned()],
        }),
    ];
    let summary = validate_v3_2_candidates(records).expect("candidates should validate");
    assert_eq!(summary.record_count, 2);
    assert_eq!(summary.needs_dynamic_validation_count, 1);
    assert_eq!(summary.static_only_count, 1);
}

fn located(value: V32CandidateRecord) -> Located<V32CandidateRecord> {
    Located {
        path: PathBuf::from("candidate.jsonl"),
        line: 1,
        value,
    }
}

fn source_ref(path: &str, line_start: u64, line_end: u64) -> V32BoundaryEvidenceRef {
    V32BoundaryEvidenceRef {
        kind: V32BoundaryEvidenceKind::SourceSpan,
        path: path.to_owned(),
        line_start: Some(line_start),
        line_end: Some(line_end),
    }
}

fn manifest_ref(path: &str) -> V32BoundaryEvidenceRef {
    V32BoundaryEvidenceRef {
        kind: V32BoundaryEvidenceKind::Manifest,
        path: path.to_owned(),
        line_start: None,
        line_end: None,
    }
}
