use std::path::PathBuf;

use bw_model::{
    Located, V3_2_BOUNDARY_INDEX_SCHEMA_V1, V32BoundaryEvidenceKind, V32BoundaryEvidenceRef,
    V32BoundaryIndexRecord, V32BoundaryKind, validate_v3_2_boundary_index,
};

#[test]
fn boundary_index_roundtrips_and_counts_negative_summary_separately() {
    let records = vec![
        located(V32BoundaryIndexRecord {
            schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
            run_id: "v3-2-boundary-test".to_owned(),
            crate_id: "crate:ffi-wrapper:0.1.0".to_owned(),
            boundary_id: "boundary:ffi-wrapper:callback-registration:0001".to_owned(),
            boundary_kind: V32BoundaryKind::CallbackRegistration,
            api_path: Some("ffi_wrapper::register_callback".to_owned()),
            evidence_refs: vec![source_ref("src/lib.rs", 12, 12)],
            confidence: "high".to_owned(),
            notes: vec!["function-like token contains register and callback/user_data".to_owned()],
        }),
        located(V32BoundaryIndexRecord {
            schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
            run_id: "v3-2-boundary-test".to_owned(),
            crate_id: "crate:plain:0.1.0".to_owned(),
            boundary_id: "boundary:plain:negative-summary".to_owned(),
            boundary_kind: V32BoundaryKind::NegativeSummary,
            api_path: None,
            evidence_refs: vec![manifest_ref("Cargo.toml")],
            confidence: "high".to_owned(),
            notes: vec!["no supported boundary pattern found in scanned Rust sources".to_owned()],
        }),
    ];

    let json = serde_json::to_string(&records[0].value).expect("record should serialize");
    assert_eq!(
        serde_json::from_str::<V32BoundaryIndexRecord>(&json).expect("record should parse"),
        records[0].value
    );

    let summary = validate_v3_2_boundary_index(records).expect("records should validate");
    assert_eq!(summary.record_count, 2);
    assert_eq!(summary.boundary_count, 1);
    assert_eq!(summary.negative_count, 1);
}

#[test]
fn boundary_index_rejects_duplicate_boundary_ids() {
    let duplicate = "boundary:ffi-wrapper:callback-registration:0001";
    let records = vec![
        located(V32BoundaryIndexRecord {
            schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
            run_id: "v3-2-boundary-test".to_owned(),
            crate_id: "crate:ffi-wrapper:0.1.0".to_owned(),
            boundary_id: duplicate.to_owned(),
            boundary_kind: V32BoundaryKind::CallbackRegistration,
            api_path: Some("ffi_wrapper::register_callback".to_owned()),
            evidence_refs: vec![source_ref("src/lib.rs", 12, 12)],
            confidence: "high".to_owned(),
            notes: Vec::new(),
        }),
        located(V32BoundaryIndexRecord {
            schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
            run_id: "v3-2-boundary-test".to_owned(),
            crate_id: "crate:ffi-wrapper:0.1.0".to_owned(),
            boundary_id: duplicate.to_owned(),
            boundary_kind: V32BoundaryKind::CallbackUnregistration,
            api_path: Some("ffi_wrapper::unregister_callback".to_owned()),
            evidence_refs: vec![source_ref("src/lib.rs", 18, 18)],
            confidence: "medium".to_owned(),
            notes: Vec::new(),
        }),
    ];

    let err = validate_v3_2_boundary_index(records).expect_err("duplicate IDs must fail");
    assert_eq!(err.code(), "BW-BOUNDARY-ID-DUPLICATE");
}

fn located(value: V32BoundaryIndexRecord) -> Located<V32BoundaryIndexRecord> {
    Located {
        path: PathBuf::from("boundary-index.jsonl"),
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
