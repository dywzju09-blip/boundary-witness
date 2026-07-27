use std::path::PathBuf;

use bw_model::{
    Located, V3_2_ADAPTER_EFFORT_SCHEMA_V1, V3_2_BOUNDARY_INDEX_SCHEMA_V1,
    V3_2_BUILDABILITY_SCHEMA_V1, V32AdapterEffortRecord, V32AdapterKind, V32BoundaryEvidenceKind,
    V32BoundaryEvidenceRef, V32BoundaryIndexRecord, V32BoundaryKind, V32BuildabilityRecord,
    V32BuildabilityStatus, V32EffortClass, V32FailureClass, V32PatternFamily, V32TaxonomyStage,
    build_failure_taxonomy, validate_v3_2_failure_taxonomy,
};

#[test]
fn taxonomy_covers_build_failure_negative_and_deferred() {
    let buildability = vec![
        buildable("crate:ok:0.1.0"),
        failed(
            "crate:dep:0.1.0",
            V32BuildabilityStatus::RequiresSystemDependency,
            Some("requires_system_dependency"),
        ),
    ];
    let boundary = vec![
        boundary(
            "crate:ok:0.1.0",
            "boundary:ok:native:0001",
            V32BoundaryKind::NativeLibrary,
            Some("extern"),
        ),
        boundary(
            "crate:neg:0.1.0",
            "boundary:neg:negative-summary",
            V32BoundaryKind::NegativeSummary,
            None,
        ),
    ];
    let adapter = vec![
        effort("candidate:ok:native", "crate:ok:0.1.0", true),
        effort("candidate:ok:deferred", "crate:ok:0.1.0", false),
    ];
    let records = build_failure_taxonomy("v3-2-tax-test", &buildability, &boundary, &adapter);
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .any(|r| r.failure_class == V32FailureClass::RequiresSystemDependency)
    );
    assert!(
        records
            .iter()
            .any(|r| r.failure_class == V32FailureClass::NoSupportedBoundaryPattern)
    );
    assert!(
        records
            .iter()
            .any(|r| r.failure_class == V32FailureClass::DeferredStaticOnly
                && r.stage == V32TaxonomyStage::DynamicPrep)
    );
    assert!(records.iter().all(|r| !r.is_method_negative));

    let summary =
        validate_v3_2_failure_taxonomy(records.into_iter().enumerate().map(|(index, value)| {
            Located {
                path: PathBuf::from("taxonomy.jsonl"),
                line: index + 1,
                value,
            }
        }))
        .expect("taxonomy should validate");
    assert_eq!(summary.record_count, 3);
    assert_eq!(summary.build_failure_count, 1);
    assert_eq!(summary.no_boundary_count, 1);
    assert_eq!(summary.deferred_count, 1);
    assert_eq!(summary.method_negative_count, 0);
}

fn buildable(crate_id: &str) -> V32BuildabilityRecord {
    V32BuildabilityRecord {
        schema_version: V3_2_BUILDABILITY_SCHEMA_V1.to_owned(),
        run_id: "precheck".to_owned(),
        crate_id: crate_id.to_owned(),
        status: V32BuildabilityStatus::Buildable,
        toolchain: "cargo test".to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
        native_dependencies: Vec::new(),
        elapsed_ms: 1,
        log_ref: "build/ok.log".to_owned(),
        failure_class: None,
        original_status: Some(V32BuildabilityStatus::Buildable),
        original_failure_class: None,
        fallback_status: None,
        fallback_failure_class: None,
        fallback_rustflags: None,
    }
}

fn failed(
    crate_id: &str,
    status: V32BuildabilityStatus,
    failure_class: Option<&str>,
) -> V32BuildabilityRecord {
    V32BuildabilityRecord {
        schema_version: V3_2_BUILDABILITY_SCHEMA_V1.to_owned(),
        run_id: "precheck".to_owned(),
        crate_id: crate_id.to_owned(),
        status,
        toolchain: "cargo test".to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
        native_dependencies: Vec::new(),
        elapsed_ms: 1,
        log_ref: "build/fail.log".to_owned(),
        failure_class: failure_class.map(str::to_owned),
        original_status: Some(status),
        original_failure_class: failure_class.map(str::to_owned),
        fallback_status: None,
        fallback_failure_class: None,
        fallback_rustflags: None,
    }
}

fn boundary(
    crate_id: &str,
    boundary_id: &str,
    kind: V32BoundaryKind,
    api_path: Option<&str>,
) -> V32BoundaryIndexRecord {
    V32BoundaryIndexRecord {
        schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
        run_id: "boundary".to_owned(),
        crate_id: crate_id.to_owned(),
        boundary_id: boundary_id.to_owned(),
        boundary_kind: kind,
        api_path: api_path.map(str::to_owned),
        evidence_refs: vec![V32BoundaryEvidenceRef {
            kind: if api_path.is_some() {
                V32BoundaryEvidenceKind::SourceSpan
            } else {
                V32BoundaryEvidenceKind::Manifest
            },
            path: if api_path.is_some() {
                "src/lib.rs".to_owned()
            } else {
                "Cargo.toml".to_owned()
            },
            line_start: api_path.map(|_| 1),
            line_end: api_path.map(|_| 1),
        }],
        confidence: "high".to_owned(),
        notes: Vec::new(),
    }
}

fn effort(candidate_id: &str, crate_id: &str, needed: bool) -> V32AdapterEffortRecord {
    if needed {
        V32AdapterEffortRecord {
            schema_version: V3_2_ADAPTER_EFFORT_SCHEMA_V1.to_owned(),
            run_id: "adapter".to_owned(),
            candidate_id: candidate_id.to_owned(),
            crate_id: crate_id.to_owned(),
            pattern_family: V32PatternFamily::NativeLibraryBoundary,
            rank: 1,
            score: 25,
            adapter_needed: true,
            adapter_kind: V32AdapterKind::MinimalHarness,
            effort_class: V32EffortClass::LightManual,
            manual_minutes: 30,
            generated_lines: 100,
            manual_lines: 10,
            blocked_reason: None,
            notes: vec!["adapter must not become a hidden answer channel".to_owned()],
        }
    } else {
        V32AdapterEffortRecord {
            schema_version: V3_2_ADAPTER_EFFORT_SCHEMA_V1.to_owned(),
            run_id: "adapter".to_owned(),
            candidate_id: candidate_id.to_owned(),
            crate_id: crate_id.to_owned(),
            pattern_family: V32PatternFamily::NativeLibraryBoundary,
            rank: 2,
            score: 12,
            adapter_needed: false,
            adapter_kind: V32AdapterKind::None,
            effort_class: V32EffortClass::Deferred,
            manual_minutes: 0,
            generated_lines: 0,
            manual_lines: 0,
            blocked_reason: Some("static_only_deferred".to_owned()),
            notes: vec!["adapter must not become a hidden answer channel".to_owned()],
        }
    }
}
