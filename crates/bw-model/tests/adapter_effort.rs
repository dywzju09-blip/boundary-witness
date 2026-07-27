use std::path::PathBuf;

use bw_model::{
    Located, V3_2_RANKED_CANDIDATE_SCHEMA_V1, V32AdapterKind, V32EffortClass, V32PatternFamily,
    V32RankedCandidateRecord, V32RiskFeatures, V32ScoreBreakdown, adapter_effort_from_ranked,
    validate_v3_2_adapter_effort,
};

#[test]
fn high_score_callback_requires_adapter_effort() {
    let ranked = sample_ranked(
        "candidate:a:callback",
        V32PatternFamily::RetainedBorrowedCallback,
        45,
        V32RiskFeatures {
            foreign_retention_without_owned_anchor: true,
            missing_unregister_before_drop: true,
            cross_language_alias: true,
            opaque_handle_without_owner: false,
            callback_retained_across_drop: true,
        },
    );
    let effort = adapter_effort_from_ranked(&ranked, "v3-2-adapter-test");
    assert!(effort.adapter_needed);
    assert_eq!(effort.adapter_kind, V32AdapterKind::HeavyManualAnalysis);
    assert_eq!(effort.effort_class, V32EffortClass::HeavyManual);
    assert!(effort.manual_minutes > 0);
    assert!(effort.blocked_reason.is_none());
    assert!(
        effort
            .notes
            .iter()
            .any(|note| note.contains("hidden answer channel"))
    );
}

#[test]
fn static_only_native_library_is_deferred() {
    let ranked = sample_ranked(
        "candidate:b:native",
        V32PatternFamily::NativeLibraryBoundary,
        12,
        V32RiskFeatures {
            foreign_retention_without_owned_anchor: false,
            missing_unregister_before_drop: false,
            cross_language_alias: true,
            opaque_handle_without_owner: false,
            callback_retained_across_drop: false,
        },
    );
    let effort = adapter_effort_from_ranked(&ranked, "v3-2-adapter-test");
    assert!(!effort.adapter_needed);
    assert_eq!(effort.adapter_kind, V32AdapterKind::None);
    assert_eq!(effort.effort_class, V32EffortClass::Deferred);
    assert_eq!(
        effort.blocked_reason.as_deref(),
        Some("static_only_deferred")
    );
}

#[test]
fn adapter_effort_validation_counts_needed_and_deferred() {
    let needed = adapter_effort_from_ranked(
        &sample_ranked(
            "candidate:a:callback",
            V32PatternFamily::RetainedBorrowedCallback,
            45,
            V32RiskFeatures {
                foreign_retention_without_owned_anchor: true,
                missing_unregister_before_drop: true,
                cross_language_alias: true,
                opaque_handle_without_owner: false,
                callback_retained_across_drop: true,
            },
        ),
        "v3-2-adapter-test",
    );
    let deferred = adapter_effort_from_ranked(
        &sample_ranked(
            "candidate:b:native",
            V32PatternFamily::NativeLibraryBoundary,
            12,
            V32RiskFeatures {
                foreign_retention_without_owned_anchor: false,
                missing_unregister_before_drop: false,
                cross_language_alias: true,
                opaque_handle_without_owner: false,
                callback_retained_across_drop: false,
            },
        ),
        "v3-2-adapter-test",
    );
    let summary = validate_v3_2_adapter_effort([
        Located {
            path: PathBuf::from("adapter-effort.jsonl"),
            line: 1,
            value: needed,
        },
        Located {
            path: PathBuf::from("adapter-effort.jsonl"),
            line: 2,
            value: deferred,
        },
    ])
    .expect("records should validate");
    assert_eq!(summary.record_count, 2);
    assert_eq!(summary.adapter_needed_count, 1);
    assert_eq!(summary.deferred_count, 1);
    assert!(summary.total_manual_minutes > 0);
}

fn sample_ranked(
    candidate_id: &str,
    pattern_family: V32PatternFamily,
    score: u32,
    risk_features: V32RiskFeatures,
) -> V32RankedCandidateRecord {
    V32RankedCandidateRecord {
        schema_version: V3_2_RANKED_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: "v3-2-adapter-test".to_owned(),
        rank: 1,
        candidate_id: candidate_id.to_owned(),
        crate_id: "crate:sample:0.1.0".to_owned(),
        pattern_family,
        score,
        score_breakdown: V32ScoreBreakdown {
            foreign_retention_without_owned_anchor: 0,
            missing_unregister_before_drop: 0,
            cross_language_alias: 0,
            opaque_handle_without_owner: 0,
            callback_retained_across_drop: 0,
            confidence_bonus: 0,
        },
        risk_features,
        lifecycle_graph_path: "lifecycle-graphs/sample.json".to_owned(),
        ranking_reason: format!("score={score}"),
        notes: vec!["ranking is not a vulnerability conclusion".to_owned()],
    }
}
