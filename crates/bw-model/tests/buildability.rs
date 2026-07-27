use std::path::PathBuf;

use bw_model::{
    Located, V3_2_BUILDABILITY_SCHEMA_V1, V32BuildabilityRecord, V32BuildabilityStatus,
    validate_v3_2_buildability,
};

#[test]
fn buildability_accepts_compat_fallback_attribution() {
    let summary = validate_v3_2_buildability([Located {
        path: PathBuf::from("buildability.jsonl"),
        line: 1,
        value: compat_fallback_record(),
    }])
    .expect("compat fallback attribution should validate");

    assert_eq!(summary.record_count, 1);
    assert_eq!(summary.buildable_count, 1);
}

#[test]
fn buildability_rejects_fallback_status_without_rustflags() {
    let mut record = compat_fallback_record();
    record.fallback_rustflags = None;

    let error = validate_v3_2_buildability([Located {
        path: PathBuf::from("buildability.jsonl"),
        line: 1,
        value: record,
    }])
    .expect_err("fallback_status must carry fallback_rustflags");

    assert_eq!(error.code(), "BW-BUILDABILITY-FALLBACK-RUSTFLAGS-MISSING");
}

fn compat_fallback_record() -> V32BuildabilityRecord {
    V32BuildabilityRecord {
        schema_version: V3_2_BUILDABILITY_SCHEMA_V1.to_owned(),
        run_id: "run:buildability".to_owned(),
        crate_id: "crate:ascii-legacy".to_owned(),
        status: V32BuildabilityStatus::Buildable,
        toolchain: "cargo 1.99.0-test".to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
        native_dependencies: Vec::new(),
        elapsed_ms: 10,
        log_ref: "build/crate_ascii-legacy.log".to_owned(),
        failure_class: None,
        original_status: Some(V32BuildabilityStatus::NotBuildable),
        original_failure_class: Some("legacy_lint_requires_compat_rustflags".to_owned()),
        fallback_status: Some(V32BuildabilityStatus::Buildable),
        fallback_failure_class: None,
        fallback_rustflags: Some(
            "-A useless_deprecated -A dangerous_implicit_autorefs -A bindings_with_variant_name"
                .to_owned(),
        ),
    }
}
