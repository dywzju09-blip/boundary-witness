use bw_model::{
    Located, RevealStaticRankingInput, V3_2_5_PRIVATE_GROUND_TRUTH_SCHEMA_V1,
    V3_2_BUILDABILITY_SCHEMA_V1, V3_2_RANKED_CANDIDATE_SCHEMA_V1, V32BuildabilityRecord,
    V32BuildabilityStatus, V32CandidateConfidence, V32PatternFamily, V32RankedCandidateRecord,
    V32RiskFeatures, V32ScoreBreakdown, V325ExpectedPatternFamily, V325PrivateGroundTruthRecord,
    V325SampleRole, reveal_static_ranking, validate_v3_2_5_private_ground_truth,
};

fn gt(
    sample_id: &str,
    crate_id: &str,
    role: V325SampleRole,
    paired: &[&str],
    patterns: &[V32PatternFamily],
) -> V325PrivateGroundTruthRecord {
    V325PrivateGroundTruthRecord {
        schema_version: V3_2_5_PRIVATE_GROUND_TRUTH_SCHEMA_V1.to_owned(),
        suite_id: "suite.v3-2-5.nday.smoke.sample".to_owned(),
        sample_id: sample_id.to_owned(),
        public_crate_id: crate_id.to_owned(),
        role,
        paired_with: paired.iter().map(|s| (*s).to_owned()).collect(),
        expected_pattern_families: patterns
            .iter()
            .copied()
            .map(V325ExpectedPatternFamily::from_public_pattern)
            .collect(),
        expected_api_substrings: Vec::new(),
        expected_path_substrings: Vec::new(),
        root_cause_key: "opaque".to_owned(),
        vulnerability_identity: None,
        notes: vec!["synthetic".to_owned()],
    }
}

#[test]
fn private_ground_truth_accepts_v3_3_pure_rust_expected_families() {
    let line = r#"{"schema_version":"v3.2.5.private_ground_truth.1","suite_id":"suite.v3-3.sealed.r2","sample_id":"sample-v33-r2-009","public_crate_id":"crate:ascii:0.9.2","role":"vulnerable","paired_with":[],"expected_pattern_families":["mutable_slice_view_conversion","checked_view_invariant"],"expected_api_substrings":["AsciiStr"],"expected_path_substrings":["src/ascii_str.rs"],"root_cause_key":"ascii-mut-view-conversion-invariant-break","vulnerability_identity":"GHSA-mrrw-grhq-86gf; RUSTSEC-2023-0015","notes":["synthetic private r2 record"]}"#;
    let record = serde_json::from_str::<V325PrivateGroundTruthRecord>(line).unwrap();
    let summary = validate_v3_2_5_private_ground_truth([Located {
        path: "ground-truth.jsonl".into(),
        line: 1,
        value: record,
    }])
    .unwrap();
    assert_eq!(summary.record_count, 1);
    assert_eq!(summary.vulnerable_count, 1);
}

fn gt_with_root_cause(
    sample_id: &str,
    crate_id: &str,
    role: V325SampleRole,
    paired: &[&str],
    patterns: &[V32PatternFamily],
    root_cause_key: &str,
) -> V325PrivateGroundTruthRecord {
    let mut record = gt(sample_id, crate_id, role, paired, patterns);
    record.root_cause_key = root_cause_key.to_owned();
    record
}

fn ranked(
    crate_id: &str,
    rank: u32,
    pattern: V32PatternFamily,
    score: u32,
) -> V32RankedCandidateRecord {
    V32RankedCandidateRecord {
        schema_version: V3_2_RANKED_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: "run".to_owned(),
        rank,
        candidate_id: format!("candidate:{crate_id}:{rank}"),
        crate_id: crate_id.to_owned(),
        pattern_family: pattern,
        score,
        score_breakdown: V32ScoreBreakdown {
            foreign_retention_without_owned_anchor: 0,
            missing_unregister_before_drop: 0,
            cross_language_alias: 10,
            opaque_handle_without_owner: 0,
            callback_retained_across_drop: 0,
            confidence_bonus: 5,
        },
        risk_features: V32RiskFeatures {
            foreign_retention_without_owned_anchor: false,
            missing_unregister_before_drop: false,
            cross_language_alias: true,
            opaque_handle_without_owner: false,
            callback_retained_across_drop: false,
        },
        lifecycle_graph_path: "graph.json".to_owned(),
        ranking_reason: "test".to_owned(),
        notes: Vec::new(),
    }
}

fn buildable(crate_id: &str, ok: bool) -> V32BuildabilityRecord {
    V32BuildabilityRecord {
        schema_version: V3_2_BUILDABILITY_SCHEMA_V1.to_owned(),
        run_id: "run".to_owned(),
        crate_id: crate_id.to_owned(),
        status: if ok {
            V32BuildabilityStatus::Buildable
        } else {
            V32BuildabilityStatus::RequiresSystemDependency
        },
        toolchain: "test".to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
        native_dependencies: Vec::new(),
        elapsed_ms: 1,
        log_ref: "log".to_owned(),
        failure_class: if ok {
            None
        } else {
            Some("requires_system_dependency".to_owned())
        },
        original_status: Some(if ok {
            V32BuildabilityStatus::Buildable
        } else {
            V32BuildabilityStatus::RequiresSystemDependency
        }),
        original_failure_class: if ok {
            None
        } else {
            Some("requires_system_dependency".to_owned())
        },
        fallback_status: None,
        fallback_failure_class: None,
        fallback_rustflags: None,
    }
}

#[test]
fn private_ground_truth_fixture_validates() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/v3-2-5/private-ground-truth.sample.jsonl"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let records = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(index, line)| Located {
            path: path.into(),
            line: index + 1,
            value: serde_json::from_str::<V325PrivateGroundTruthRecord>(line).unwrap(),
        })
        .collect::<Vec<_>>();
    let summary = validate_v3_2_5_private_ground_truth(records).unwrap();
    assert_eq!(summary.record_count, 3);
    assert_eq!(summary.vulnerable_count, 1);
    assert_eq!(summary.control_count, 1);
}

#[test]
fn reveal_counts_top1_hit_and_clean_control() {
    let ground = vec![
        gt(
            "v1",
            "crate:alpha:1.0.0",
            V325SampleRole::Vulnerable,
            &["c1"],
            &[V32PatternFamily::RetainedBorrowedCallback],
        ),
        gt(
            "c1",
            "crate:alpha:1.0.1",
            V325SampleRole::FixedControl,
            &["v1"],
            &[V32PatternFamily::RetainedBorrowedCallback],
        ),
    ];
    let ranked_list = vec![ranked(
        "crate:alpha:1.0.0",
        1,
        V32PatternFamily::RetainedBorrowedCallback,
        45,
    )];
    let buildability = vec![
        buildable("crate:alpha:1.0.0", true),
        buildable("crate:alpha:1.0.1", true),
    ];
    let ranked_sha = "a".repeat(64);
    let ground_sha = "b".repeat(64);
    let (summary, details) = reveal_static_ranking(RevealStaticRankingInput {
        run_id: "run-test",
        ranked_candidates_sha256: &ranked_sha,
        ground_truth_sha256: &ground_sha,
        top_k_values: &[1, 5, 10],
        control_false_positive_min_score: 20,
        ground_truth: &ground,
        ranked: &ranked_list,
        buildability: &buildability,
        boundary_index: &[],
    })
    .unwrap();

    assert_eq!(summary.metrics.vulnerable_sample_count, 1);
    assert_eq!(summary.metrics.top1_hit_count, 1);
    assert_eq!(summary.metrics.top5_hit_count, 1);
    assert_eq!(summary.metrics.paired_control_clean_count, 1);
    assert_eq!(summary.metrics.false_positive_control_count, 0);
    assert_eq!(details.len(), 2);
    let _ = V32CandidateConfidence::NeedsDynamicValidation;
}

#[test]
fn reveal_treats_external_buffer_view_as_returned_borrow_lifetime_match() {
    let ground = vec![gt_with_root_cause(
        "v1",
        "crate:openssl:0.10.69",
        V325SampleRole::Vulnerable,
        &[],
        &[V32PatternFamily::ForeignRetainedPointer],
        "returned-borrowed-lifetime-mismatch",
    )];
    let ranked_list = vec![
        ranked(
            "crate:openssl:0.10.69",
            6,
            V32PatternFamily::ExternalBufferView,
            10,
        ),
        ranked(
            "crate:openssl:0.10.69",
            751,
            V32PatternFamily::ForeignRetainedPointer,
            0,
        ),
    ];
    let ranked_sha = "a".repeat(64);
    let ground_sha = "b".repeat(64);
    let (summary, details) = reveal_static_ranking(RevealStaticRankingInput {
        run_id: "run-test",
        ranked_candidates_sha256: &ranked_sha,
        ground_truth_sha256: &ground_sha,
        top_k_values: &[1, 5, 10],
        control_false_positive_min_score: 20,
        ground_truth: &ground,
        ranked: &ranked_list,
        buildability: &[],
        boundary_index: &[],
    })
    .unwrap();

    assert_eq!(summary.metrics.top10_hit_count, 1);
    assert_eq!(summary.metrics.ranking_miss_count, 0);
    assert_eq!(
        details[0].matched_pattern_family,
        Some(V32PatternFamily::ExternalBufferView)
    );
}
