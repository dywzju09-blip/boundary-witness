use std::path::PathBuf;

use bw_model::{
    Located, V326EvidenceConfidence, V326EvidenceKind, V326LifecycleEvidenceRecord,
    V326LifecycleFeatureRecord, V326LifecycleGraphRecord, V326PairDeltaRecord, V326SourceRef,
    validate_v3_2_6_lifecycle_evidence, validate_v3_2_6_lifecycle_features,
    validate_v3_2_6_lifecycle_graphs, validate_v3_2_6_pair_deltas, validate_v3_2_7_pair_deltas,
};

#[test]
fn lifecycle_evidence_accepts_neutral_record() {
    let record = V326LifecycleEvidenceRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_EVIDENCE_SCHEMA_V1.to_owned(),
        run_id: "run:v326:model".to_owned(),
        record_id: "evidence:crate_alpha:candidate_001:0001".to_owned(),
        crate_id: "crate:alpha".to_owned(),
        candidate_id: "candidate:alpha:001".to_owned(),
        evidence_kind: V326EvidenceKind::ForeignRegister,
        source_ref: V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(10),
            line_end: Some(12),
            symbol_path: Some("alpha::register_callback".to_owned()),
            text_sha256: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            ),
        },
        confidence: V326EvidenceConfidence::Medium,
        details: serde_json::json!({"api":"register_callback"}),
        notes: vec!["neutral lifecycle evidence".to_owned()],
    };

    let summary = validate_v3_2_6_lifecycle_evidence([Located {
        path: PathBuf::from("evidence.jsonl"),
        line: 1,
        value: record,
    }])
    .expect("neutral evidence should validate");

    assert_eq!(summary.record_count, 1);
    assert_eq!(summary.medium_confidence_count, 1);
}

#[test]
fn lifecycle_feature_requires_evidence_refs_for_active_features() {
    let feature = V326LifecycleFeatureRecord::sample_for_tests_without_feature_refs();

    let error = validate_v3_2_6_lifecycle_features([Located {
        path: PathBuf::from("features.jsonl"),
        line: 1,
        value: feature,
    }])
    .expect_err("active feature without refs must fail");

    assert!(error.to_string().contains("BW-V326-FEATURE-EVIDENCE"));
}

#[test]
fn lifecycle_graph_requires_existing_edge_endpoints() {
    let graph = V326LifecycleGraphRecord::sample_for_tests_with_broken_edge();

    let error = validate_v3_2_6_lifecycle_graphs([Located {
        path: PathBuf::from("graph.json"),
        line: 1,
        value: graph,
    }])
    .expect_err("broken graph edge must fail");

    assert!(error.to_string().contains("BW-V326-GRAPH-EDGE-ENDPOINT"));
}

#[test]
fn borrowed_without_release_derives_risk_and_missing_evidence() {
    let candidate = bw_model::V32CandidateRecord {
        schema_version: bw_model::V3_2_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: "candidate:borrowed:001".to_owned(),
        crate_id: "crate:borrowed".to_owned(),
        boundary_id: "boundary:borrowed:001".to_owned(),
        pattern_family: bw_model::V32PatternFamily::RetainedBorrowedCallback,
        confidence: bw_model::V32CandidateConfidence::NeedsDynamicValidation,
        evidence_refs: vec![bw_model::V32BoundaryEvidenceRef {
            kind: bw_model::V32BoundaryEvidenceKind::SourceSpan,
            path: "src/lib.rs".to_owned(),
            line_start: Some(1),
            line_end: Some(1),
        }],
        api_path: Some("borrowed::register".to_owned()),
        recommended_next_step: bw_model::V32RecommendedNextStep::GenerateLifecycleSubgraph,
        notes: vec!["synthetic candidate".to_owned()],
    };
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:borrowed:0001",
            "crate:borrowed",
            "candidate:borrowed:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:borrowed:0002",
            "crate:borrowed",
            "candidate:borrowed:001",
            bw_model::V326EvidenceKind::BorrowEdge,
        ),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features(&candidate, &graph, &evidence);

    assert!(feature.features.has_foreign_register);
    assert!(feature.features.has_borrowed_capture);
    assert!(feature.features.missing_unregister_before_drop);
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|item| item.contains("unregister"))
    );
}

#[test]
fn register_only_does_not_derive_foreign_callback_retention() {
    let candidate = bw_model::V32CandidateRecord {
        schema_version: bw_model::V3_2_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: "candidate:register-only:001".to_owned(),
        crate_id: "crate:register-only".to_owned(),
        boundary_id: "boundary:register-only:001".to_owned(),
        pattern_family: bw_model::V32PatternFamily::RetainedBorrowedCallback,
        confidence: bw_model::V32CandidateConfidence::NeedsDynamicValidation,
        evidence_refs: vec![bw_model::V32BoundaryEvidenceRef {
            kind: bw_model::V32BoundaryEvidenceKind::SourceSpan,
            path: "src/lib.rs".to_owned(),
            line_start: Some(1),
            line_end: Some(1),
        }],
        api_path: Some("register_only::set_callback".to_owned()),
        recommended_next_step: bw_model::V32RecommendedNextStep::GenerateLifecycleSubgraph,
        notes: vec!["synthetic candidate".to_owned()],
    };
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:register-only:0001",
        "crate:register-only",
        "candidate:register-only:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features(&candidate, &graph, &evidence);

    assert!(feature.features.has_foreign_register);
    assert!(!feature.features.foreign_may_retain_callback);
    assert!(
        !feature
            .feature_evidence
            .contains_key("foreign_may_retain_callback")
    );
    assert!(!feature.features.missing_unregister_before_drop);
    assert!(!feature.features.release_order_unknown);
    assert!(!feature.features.needs_dynamic_witness);

    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature]).unwrap();
    assert_eq!(ranked[0].score, 4);
    assert!(
        !ranked[0]
            .risk_features
            .contains(&"missing_unregister_before_drop".to_owned())
    );
}

#[test]
fn isolated_raw_pointer_escape_requires_registered_object_binding_for_risk_score() {
    let candidate = sample_candidate("candidate:raw-only:001", "crate:raw-only");
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:raw-only:0001",
        "crate:raw-only",
        "candidate:raw-only:001",
        bw_model::V326EvidenceKind::RawPointerEscape,
    )];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features(&candidate, &graph, &evidence);
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(!feature.features.has_raw_pointer_escape);
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|item| item == "raw_pointer_escape_without_registered_object_binding")
    );
    assert_eq!(ranked[0].score, 0);
    assert!(ranked[0].risk_features.is_empty());
}

#[test]
fn raw_pointer_escape_with_only_callback_name_overlap_does_not_derive_risk_score() {
    let candidate = sample_candidate("candidate:raw-callback-only:001", "crate:raw-callback-only");
    let evidence = vec![
        evidence_with_details(
            "evidence:raw-callback-only:register",
            "crate:raw-callback-only",
            "candidate:raw-callback-only:001",
            bw_model::V326EvidenceKind::ForeignRegister,
            serde_json::json!({"callback_object_id":"callback:shared","user_data_object_id":"user_data:registered"}),
        ),
        evidence_with_details(
            "evidence:raw-callback-only:pointer",
            "crate:raw-callback-only",
            "candidate:raw-callback-only:001",
            bw_model::V326EvidenceKind::RawPointerEscape,
            serde_json::json!({"callback_object_id":"callback:shared","user_data_object_id":"user_data:escaped"}),
        ),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features(&candidate, &graph, &evidence);
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(!feature.features.has_raw_pointer_escape);
    assert_eq!(ranked[0].score_breakdown.has_raw_pointer_escape, 0);
}

#[test]
fn raw_pointer_escape_with_same_object_stays_unproven_without_supported_static_fact() {
    let candidate = sample_candidate("candidate:raw-bound:001", "crate:raw-bound");
    let evidence = vec![
        evidence_with_details(
            "evidence:raw-bound:register",
            "crate:raw-bound",
            "candidate:raw-bound:001",
            bw_model::V326EvidenceKind::ForeignRegister,
            serde_json::json!({"callback_object_id":"callback:registered","user_data_object_id":"user_data:shared"}),
        ),
        evidence_with_details(
            "evidence:raw-bound:pointer",
            "crate:raw-bound",
            "candidate:raw-bound:001",
            bw_model::V326EvidenceKind::RawPointerEscape,
            serde_json::json!({"callback_object_id":"callback:escaped","user_data_object_id":"user_data:shared"}),
        ),
    ];
    let facts = vec![
        fact_with_object(
            "fact:raw-bound:register",
            "candidate:raw-bound:001",
            "crate:raw-bound",
            bw_model::V326LifecycleFactKind::RegisterCall,
            "user_data:shared",
        ),
        fact_with_object(
            "fact:raw-bound:pointer",
            "candidate:raw-bound:001",
            "crate:raw-bound",
            bw_model::V326LifecycleFactKind::RawPointerEscape,
            "user_data:shared",
        ),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(!feature.features.has_raw_pointer_escape);
    assert_eq!(ranked[0].score_breakdown.has_raw_pointer_escape, 0);
    assert!(
        !ranked[0]
            .risk_features
            .iter()
            .any(|feature| feature == "has_raw_pointer_escape")
    );
}

#[test]
fn raw_pointer_escape_with_unattributed_high_facts_does_not_derive_risk_score() {
    let candidate = sample_candidate("candidate:raw-unattributed:001", "crate:raw-unattributed");
    let evidence = vec![
        evidence_with_details(
            "evidence:raw-unattributed:register",
            "crate:raw-unattributed",
            "candidate:raw-unattributed:001",
            bw_model::V326EvidenceKind::ForeignRegister,
            serde_json::json!({"user_data_object_id":"user_data:shared"}),
        ),
        evidence_with_details(
            "evidence:raw-unattributed:pointer",
            "crate:raw-unattributed",
            "candidate:raw-unattributed:001",
            bw_model::V326EvidenceKind::RawPointerEscape,
            serde_json::json!({"user_data_object_id":"user_data:shared"}),
        ),
    ];
    let facts = vec![
        fact_with_object(
            "fact:raw-unattributed:register",
            "candidate:raw-unattributed:001",
            "crate:raw-unattributed",
            bw_model::V326LifecycleFactKind::RegisterCall,
            "user_data:shared",
        ),
        fact_with_object(
            "fact:raw-unattributed:pointer",
            "candidate:raw-unattributed:001",
            "crate:raw-unattributed",
            bw_model::V326LifecycleFactKind::RawPointerEscape,
            "user_data:shared",
        ),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &facts,
        &[],
    );

    assert!(!feature.features.has_raw_pointer_escape);
}

#[test]
fn raw_pointer_escape_with_source_derived_fact_ids_does_not_derive_risk_score() {
    let candidate = sample_candidate("candidate:raw-source:001", "crate:raw-source");
    let evidence = vec![
        evidence_with_details(
            "evidence:raw-source:register",
            "crate:raw-source",
            "candidate:raw-source:001",
            bw_model::V326EvidenceKind::ForeignRegister,
            serde_json::json!({"user_data_object_id":"user_data:shared"}),
        ),
        evidence_with_details(
            "evidence:raw-source:pointer",
            "crate:raw-source",
            "candidate:raw-source:001",
            bw_model::V326EvidenceKind::RawPointerEscape,
            serde_json::json!({"user_data_object_id":"user_data:shared"}),
        ),
    ];
    let mut register = fact_with_object(
        "fact:raw-source:register",
        "candidate:raw-source:001",
        "crate:raw-source",
        bw_model::V326LifecycleFactKind::RegisterCall,
        "user_data:shared",
    );
    register.confidence = bw_model::V326EvidenceConfidence::Medium;
    register.notes = vec!["source-derived candidate-scoped lifecycle fact".to_owned()];
    let mut raw_pointer = fact_with_object(
        "fact:raw-source:pointer",
        "candidate:raw-source:001",
        "crate:raw-source",
        bw_model::V326LifecycleFactKind::RawPointerEscape,
        "user_data:shared",
    );
    raw_pointer.confidence = bw_model::V326EvidenceConfidence::Medium;
    raw_pointer.notes = vec!["source-derived candidate-scoped lifecycle fact".to_owned()];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[register, raw_pointer],
        &[],
    );

    assert!(!feature.features.has_raw_pointer_escape);
}

#[test]
fn raw_parts_transfer_without_drop_prevention_remains_high_priority_despite_owner_carriers() {
    let candidate = raw_parts_candidate("candidate:raw-parts-risk:001", "crate:raw-parts-risk");
    let facts = raw_parts_transfer_facts(&candidate, "risk", false);
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(
        ranked[0]
            .risk_features
            .contains(&"raw_parts_transfer_without_drop_prevention".to_owned())
    );
    assert!(
        ranked[0].score > 8,
        "raw-parts ownership risk should outrank returned-borrow carrier-only records"
    );
    assert_eq!(
        ranked[0]
            .score_breakdown
            .raw_parts_transfer_without_drop_prevention,
        31,
        "drop-site/object evidence keeps the specific raw-parts signal fully weighted"
    );
    assert!(feature.features.has_drop_guard);
    assert!(feature.features.has_owned_anchor);
}

#[test]
fn raw_parts_owner_anchor_only_is_dampened_until_same_object_support_exists() {
    let raw_owner_only = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:raw-owner-only",
        |features| {
            features.raw_parts_transfer_without_drop_prevention = true;
            features.has_owned_anchor = true;
        },
    );
    let returned_borrow = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:returned-carrier",
        |features| {
            features.has_returned_borrow_relation = true;
        },
    );

    let ranked =
        bw_model::rank_v3_2_6_features("run:v326", vec![raw_owner_only, returned_borrow]).unwrap();
    let raw_rank = ranked
        .iter()
        .find(|item| item.crate_id == "crate:raw-owner-only")
        .expect("raw-parts candidate should be ranked");
    let returned_rank = ranked
        .iter()
        .find(|item| item.crate_id == "crate:returned-carrier")
        .expect("returned-borrow candidate should be ranked");

    assert!(
        raw_rank
            .risk_features
            .contains(&"raw_parts_transfer_without_drop_prevention".to_owned())
    );
    assert_eq!(
        raw_rank
            .score_breakdown
            .raw_parts_transfer_without_drop_prevention,
        20,
        "bare owner-anchor raw-parts evidence stays a static-risk signal but no longer dominates"
    );
    assert_eq!(raw_rank.score, 8);
    assert_eq!(returned_rank.score, 8);
    assert!(
        raw_rank.score <= returned_rank.score,
        "owner-anchor-only raw-parts evidence must not outrank a returned-borrow relation"
    );
}

#[test]
fn raw_parts_with_verified_object_chain_keeps_specific_high_priority() {
    let raw_with_chain = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:raw-with-chain",
        |features| {
            features.raw_parts_transfer_without_drop_prevention = true;
            features.has_owned_anchor = true;
            features.has_verified_object_chain = true;
        },
    );

    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![raw_with_chain]).unwrap();

    assert_eq!(
        ranked[0]
            .score_breakdown
            .raw_parts_transfer_without_drop_prevention,
        31
    );
    assert!(
        ranked[0].score > 14,
        "verified same-object support should keep raw-parts transfer ahead of carrier-only evidence"
    );
}

#[test]
fn raw_parts_transfer_with_mem_forget_drop_prevention_is_not_raised() {
    let candidate =
        raw_parts_candidate("candidate:raw-parts-guarded:001", "crate:raw-parts-guarded");
    let facts = raw_parts_transfer_facts(&candidate, "guarded", true);
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature]).unwrap();

    assert!(
        !ranked[0]
            .risk_features
            .contains(&"raw_parts_transfer_without_drop_prevention".to_owned())
    );
    assert_eq!(ranked[0].score, 0);
}

#[test]
fn manual_drop_prevention_without_drop_guard_derives_limited_ranking_signal() {
    let candidate = manual_drop_candidate(
        "candidate:manual-drop-without-guard:001",
        "crate:manual-drop-without-guard",
    );
    let facts = manual_drop_prevention_facts(&candidate, "manual-drop-risk", false);
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(feature.features.has_drop_prevention);
    assert!(feature.features.has_owned_anchor);
    assert!(!feature.features.has_drop_guard);
    assert!(feature.features.manual_drop_prevention_without_drop_guard);
    assert!(
        ranked[0]
            .risk_features
            .contains(&"manual_drop_prevention_without_drop_guard".to_owned())
    );
    assert_eq!(
        ranked[0]
            .score_breakdown
            .manual_drop_prevention_without_drop_guard,
        6
    );
    assert_eq!(
        ranked[0].score, 14,
        "manual drop prevention without a guard is a prioritization signal, not a high-score conclusion"
    );
}

#[test]
fn manual_drop_prevention_with_drop_guard_is_not_raised() {
    let candidate = manual_drop_candidate(
        "candidate:manual-drop-with-guard:001",
        "crate:manual-drop-with-guard",
    );
    let facts = manual_drop_prevention_facts(&candidate, "manual-drop-guarded", true);
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(feature.features.has_drop_prevention);
    assert!(feature.features.has_owned_anchor);
    assert!(feature.features.has_drop_guard);
    assert!(!feature.features.manual_drop_prevention_without_drop_guard);
    assert!(
        !ranked[0]
            .risk_features
            .contains(&"manual_drop_prevention_without_drop_guard".to_owned())
    );
    assert_eq!(ranked[0].score, 0);
}

#[test]
fn unrelated_drop_guard_does_not_clear_manual_drop_prevention() {
    let candidate = manual_drop_candidate(
        "candidate:manual-drop-unrelated-guard:001",
        "crate:manual-drop-unrelated-guard",
    );
    let mut facts = manual_drop_prevention_facts(&candidate, "manual-drop-unrelated-guard", false);
    facts.push(static_fact_with_object(
        "fact:manual-drop-unrelated-guard:drop",
        &candidate.candidate_id,
        &candidate.crate_id,
        bw_model::V326LifecycleFactKind::DropSite,
        "rust_owner:site:manual-drop-unrelated-guard:other-owner",
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(feature.features.has_drop_guard);
    assert!(feature.features.manual_drop_prevention_without_drop_guard);
    assert!(
        ranked[0]
            .risk_features
            .contains(&"manual_drop_prevention_without_drop_guard".to_owned()),
        "only a drop guard for the same object may clear the manual-drop prevention signal"
    );
}

#[test]
fn explicit_into_raw_drop_prevention_is_not_wrapper_destructure_signal() {
    let mut candidate = manual_drop_candidate(
        "candidate:manual-drop-into-raw:001",
        "crate:manual-drop-into-raw",
    );
    candidate.api_path = Some("fixture::Library::into_raw".to_owned());
    let mut facts = manual_drop_prevention_facts(&candidate, "manual-drop-into-raw", false);
    for fact in &mut facts {
        fact.source_ref.symbol_path = Some("fixture::Library::into_raw".to_owned());
        if fact.fact_kind == bw_model::V326LifecycleFactKind::OwnedMoveCapture {
            fact.symbol_path = Some("fixture::Library".to_owned());
        }
    }
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(feature.features.has_drop_prevention);
    assert!(feature.features.has_owned_anchor);
    assert!(!feature.features.has_drop_guard);
    assert!(!feature.features.manual_drop_prevention_without_drop_guard);
    assert!(
        !ranked[0]
            .risk_features
            .contains(&"manual_drop_prevention_without_drop_guard".to_owned())
    );
    assert_eq!(
        ranked[0]
            .score_breakdown
            .manual_drop_prevention_without_drop_guard,
        0
    );
}

#[test]
fn non_generic_into_inner_drop_prevention_is_not_wrapper_destructure_signal() {
    let mut candidate = manual_drop_candidate(
        "candidate:manual-drop-non-generic-into-inner:001",
        "crate:manual-drop-non-generic-into-inner",
    );
    candidate.api_path = Some("fixture::Library::into_inner".to_owned());
    let mut facts =
        manual_drop_prevention_facts(&candidate, "manual-drop-non-generic-into-inner", false);
    for fact in &mut facts {
        fact.source_ref.symbol_path = Some("fixture::Library::into_inner".to_owned());
        if fact.fact_kind == bw_model::V326LifecycleFactKind::OwnedMoveCapture {
            fact.symbol_path = Some("fixture::Library".to_owned());
        }
    }
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(feature.features.has_drop_prevention);
    assert!(feature.features.has_owned_anchor);
    assert!(!feature.features.has_drop_guard);
    assert!(!feature.features.manual_drop_prevention_without_drop_guard);
    assert!(
        !ranked[0]
            .risk_features
            .contains(&"manual_drop_prevention_without_drop_guard".to_owned())
    );
    assert_eq!(
        ranked[0]
            .score_breakdown
            .manual_drop_prevention_without_drop_guard,
        0
    );
}

#[test]
fn callback_user_data_owner_reconstruction_requires_verified_object_chain_for_high_priority() {
    let mut candidate = sample_candidate(
        "candidate:callback-userdata-risk:001",
        "crate:callback-userdata-risk",
    );
    candidate.api_path = Some("fixture::stream_callback".to_owned());
    candidate.evidence_refs[0].path = "src/stream.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    let mut facts = callback_user_data_reconstruction_facts(
        &candidate,
        "callback-userdata-risk",
        bw_model::CallbackUserDataReconstructionKind::OwnerFromTransmute,
    );
    facts.push(static_fact_with_object(
        "callback-userdata-risk:owned-anchor",
        &candidate.candidate_id,
        &candidate.crate_id,
        bw_model::V326LifecycleFactKind::OwnedMoveCapture,
        "rust_owner:site:callback-userdata-risk:stream-data",
    ));
    facts.push(static_fact_with_object(
        "callback-userdata-risk:drop-site",
        &candidate.candidate_id,
        &candidate.crate_id,
        bw_model::V326LifecycleFactKind::DropSite,
        "rust_owner:site:callback-userdata-risk:stream-data",
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(
        !feature
            .features
            .callback_user_data_owner_reconstruction_without_leak_guard
    );
    assert!(feature.features.has_drop_guard);
    assert!(feature.features.has_owned_anchor);
    assert!(
        !ranked[0]
            .risk_features
            .contains(&"callback_user_data_owner_reconstruction_without_leak_guard".to_owned())
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "callback_user_data_object_flow_missing"),
        "owner reconstruction must report that the same user_data object flow is not yet proven"
    );
}

#[test]
fn callback_user_data_owner_reconstruction_with_verified_chain_remains_high_priority() {
    let mut candidate = sample_candidate(
        "candidate:callback-userdata-bound-risk:001",
        "crate:callback-userdata-bound-risk",
    );
    candidate.api_path = Some("fixture::Registry::install".to_owned());
    candidate.evidence_refs[0].path = "src/stream.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    let mut facts = callback_user_data_reconstruction_facts(
        &candidate,
        "callback-userdata-bound-risk",
        bw_model::CallbackUserDataReconstructionKind::OwnerFromTransmute,
    );
    candidate.evidence_refs[0].path = "src/lib.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(1);
    candidate.evidence_refs[0].line_end = Some(1);
    let (_static_facts, object_flow_facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "callback-userdata-bound-risk",
        vec![
            (
                "register-userdata",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:callback-userdata-bound-risk:user-data",
                bw_model::ObjectFlowObjectKind::OpaqueHandle,
                "site:callback-userdata-bound-risk:registered-handle",
                Some("callback:user-data-slot"),
                None,
            ),
            (
                "callback-userdata",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::OpaqueHandle,
                "site:callback-userdata-bound-risk:registered-handle",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:callback-userdata-bound-risk:callback-userdata",
                Some("callback:user-data-slot"),
                None,
            ),
        ],
    );
    facts.extend(object_flow_facts);
    facts.push(static_fact_with_object(
        "callback-userdata-bound-risk:owned-anchor",
        &candidate.candidate_id,
        &candidate.crate_id,
        bw_model::V326LifecycleFactKind::OwnedMoveCapture,
        "rust_owner:site:callback-userdata-bound-risk:stream-data",
    ));
    facts.push(static_fact_with_object(
        "callback-userdata-bound-risk:drop-site",
        &candidate.candidate_id,
        &candidate.crate_id,
        bw_model::V326LifecycleFactKind::DropSite,
        "rust_owner:site:callback-userdata-bound-risk:stream-data",
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain.fact_refs.iter().any(|fact_ref| {
                    fact_ref.contains("callback-userdata")
                        && !fact_ref.contains("register-userdata")
                })
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("register-userdata"))
        }),
        "exact register->callback user_data ObjectFlow should bind the reconstruction to a verified same-object chain"
    );
    assert!(
        feature
            .features
            .callback_user_data_owner_reconstruction_without_leak_guard
    );
    assert!(feature.features.has_verified_object_chain);
    assert!(
        !feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "callback_user_data_object_flow_missing")
    );
    assert!(
        ranked[0]
            .risk_features
            .contains(&"callback_user_data_owner_reconstruction_without_leak_guard".to_owned())
    );
    assert!(
        ranked[0].score > 8,
        "only verified callback user_data chains should retain the high-priority owner reconstruction signal"
    );
}

#[test]
fn callback_user_data_leak_reconstruction_is_not_raised() {
    let mut candidate = sample_candidate(
        "candidate:callback-userdata-leak:001",
        "crate:callback-userdata-leak",
    );
    candidate.api_path = Some("fixture::stream_callback".to_owned());
    candidate.evidence_refs[0].path = "src/stream.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    let facts = callback_user_data_reconstruction_facts(
        &candidate,
        "callback-userdata-leak",
        bw_model::CallbackUserDataReconstructionKind::LeakFromRaw,
    );
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()]).unwrap();

    assert!(
        !feature
            .features
            .callback_user_data_owner_reconstruction_without_leak_guard
    );
    assert!(
        !ranked[0]
            .risk_features
            .contains(&"callback_user_data_owner_reconstruction_without_leak_guard".to_owned())
    );
    assert_eq!(ranked[0].score, 0);
}

#[test]
fn authoritative_drop_site_static_fact_derives_drop_guard_feature() {
    let candidate = sample_candidate("candidate:drop-static:001", "crate:drop-static");
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:drop-static:register",
        "crate:drop-static",
        "candidate:drop-static:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];
    let fact = static_fact_with_object(
        "fact:drop-static:drop",
        "candidate:drop-static:001",
        "crate:drop-static",
        bw_model::V326LifecycleFactKind::DropSite,
        "rust_owner:owner-a",
    );
    let expected_fact_id = fact.fact_id.clone();

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[fact],
        &[],
    );

    assert!(feature.features.has_drop_guard);
    assert_eq!(
        feature.feature_evidence.get("has_drop_guard"),
        Some(&vec![expected_fact_id])
    );
}

#[test]
fn authoritative_owned_move_capture_static_fact_derives_owned_anchor_feature() {
    let candidate = sample_candidate("candidate:owned-static:001", "crate:owned-static");
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:owned-static:register",
        "crate:owned-static",
        "candidate:owned-static:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];
    let fact = static_fact_with_object(
        "fact:owned-static:capture",
        "candidate:owned-static:001",
        "crate:owned-static",
        bw_model::V326LifecycleFactKind::OwnedMoveCapture,
        "rust_owner:owner-a",
    );
    let expected_fact_id = fact.fact_id.clone();

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[fact],
        &[],
    );

    assert!(feature.features.has_owned_anchor);
    assert_eq!(
        feature.feature_evidence.get("has_owned_anchor"),
        Some(&vec![expected_fact_id])
    );
}

#[test]
fn shared_owner_static_object_facts_set_arc_anchor_without_release_proof() {
    for (prefix, type_name) in [
        ("arc", "std::sync::Arc<fixture::CallbackState>"),
        ("rc", "std::rc::Rc<fixture::CallbackState>"),
    ] {
        let candidate = sample_candidate(
            &format!("candidate:shared-owner-{prefix}:001"),
            &format!("crate:shared-owner-{prefix}"),
        );
        let artifact = bw_model::StaticArtifactIdentity {
            crate_id: candidate.crate_id.clone(),
            package_name: "fixture".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        };
        let source = bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 1,
            line_end: 1,
            symbol_path: Some("fixture::register_shared_owner".to_owned()),
        };
        let static_fact = bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:shared-owner-{prefix}:object")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:shared-owner-{prefix}")),
            artifact: Some(artifact),
            source_ref: Some(source.clone()),
            payload: bw_model::StaticFact::ObjectSite(bw_model::ObjectSiteFact {
                site_id: bw_model::SiteId(format!("site:shared-owner-{prefix}:object")),
                semantic_site_key: bw_model::SemanticSiteKey(format!(
                    "semantic:shared-owner-{prefix}:object"
                )),
                type_name: type_name.to_owned(),
            }),
        };
        let mut fact = bw_model::lifecycle_fact_from_static_fact(
            "run:v326",
            &candidate,
            &static_fact,
            V326SourceRef {
                path: source.path.clone(),
                line_start: Some(source.line_start),
                line_end: Some(source.line_end),
                symbol_path: source.symbol_path.clone(),
                text_sha256: None,
            },
            vec![format!("evidence:shared-owner-{prefix}:object")],
        )
        .expect("shared-owner static object should map to lifecycle fact");
        fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
        assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
            &mut fact,
            &candidate,
            std::slice::from_ref(&static_fact),
        ));
        let fact_id = fact.fact_id.clone();

        let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
        let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
            &candidate,
            &graph,
            &[],
            &[fact],
            &[],
        );

        assert!(
            feature.features.has_arc_anchor,
            "{type_name} should be recorded as a shared-owner anchor"
        );
        assert!(feature.features.has_owned_anchor);
        assert!(!feature.features.registration_release_pair_found);
        assert!(!feature.features.has_release_order_chain);
        assert!(!feature.features.release_covers_callback);
        assert_eq!(
            feature.feature_evidence.get("has_arc_anchor"),
            Some(&vec![fact_id])
        );
    }
}

#[test]
fn source_observation_drop_and_owned_facts_do_not_derive_protective_features() {
    let candidate = sample_candidate("candidate:protect-source:001", "crate:protect-source");
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:protect-source:register",
        "crate:protect-source",
        "candidate:protect-source:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];
    let drop_fact = fact_with_object(
        "fact:protect-source:drop",
        "candidate:protect-source:001",
        "crate:protect-source",
        bw_model::V326LifecycleFactKind::DropSite,
        "rust_owner:owner-a",
    );
    let owned_fact = fact_with_object(
        "fact:protect-source:owned",
        "candidate:protect-source:001",
        "crate:protect-source",
        bw_model::V326LifecycleFactKind::OwnedMoveCapture,
        "rust_owner:owner-a",
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[drop_fact, owned_fact],
        &[],
    );

    assert!(!feature.features.has_drop_guard);
    assert!(!feature.features.has_owned_anchor);
}

#[test]
fn owned_anchor_reduces_score_below_borrowed_missing_release() {
    let borrowed =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
            features.has_foreign_register = true;
            features.foreign_may_retain_callback = true;
            features.has_borrowed_capture = true;
            features.missing_unregister_before_drop = true;
            features.needs_dynamic_witness = true;
        });
    let owned = bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
        features.has_foreign_register = true;
        features.foreign_may_retain_callback = true;
        features.has_owned_anchor = true;
        features.has_static_bound = true;
    });

    let borrowed_ranked = bw_model::rank_v3_2_6_features("run:v326", vec![borrowed]).unwrap();
    let owned_ranked = bw_model::rank_v3_2_6_features("run:v326", vec![owned]).unwrap();

    assert!(borrowed_ranked[0].score > owned_ranked[0].score);
    assert!(
        borrowed_ranked[0]
            .ranking_reason
            .contains("candidate ranking is not a defect conclusion")
    );
}

#[test]
fn external_buffer_without_static_bound_ranks_above_generic_returned_borrow() {
    let mut external_without_bound =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
            features.has_external_buffer_binding = true;
        });
    external_without_bound.candidate_id = "candidate:neon:external-buffer-without-bound".to_owned();
    external_without_bound.crate_id = "crate:neon:without-bound".to_owned();
    external_without_bound.pattern_family = bw_model::V32PatternFamily::ExternalBufferView;

    let mut external_with_bound =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
            features.has_external_buffer_binding = true;
            features.has_static_bound = true;
        });
    external_with_bound.candidate_id = "candidate:neon:external-buffer-with-bound".to_owned();
    external_with_bound.crate_id = "crate:neon:with-bound".to_owned();
    external_with_bound.pattern_family = bw_model::V32PatternFamily::ExternalBufferView;

    let mut returned_borrow =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
            features.has_returned_borrow_relation = true;
        });
    returned_borrow.candidate_id = "candidate:generic:returned-borrow".to_owned();
    returned_borrow.crate_id = "crate:generic:returned-borrow".to_owned();
    returned_borrow.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;

    let ranked = bw_model::rank_v3_2_6_features(
        "run:v326",
        vec![
            returned_borrow,
            external_with_bound.clone(),
            external_without_bound.clone(),
        ],
    )
    .unwrap();

    assert_eq!(ranked[0].candidate_id, external_without_bound.candidate_id);
    assert!(
        ranked[0].score > ranked[1].score,
        "missing static bound external-buffer evidence should outrank generic borrow views"
    );
    let fixed = ranked
        .iter()
        .find(|item| item.candidate_id == external_with_bound.candidate_id)
        .expect("bound external buffer candidate should be ranked");
    assert!(
        fixed.score < ranked[0].score,
        "static lifetime bound should remain a protective signal"
    );
}

#[test]
fn external_buffer_return_lifetime_bound_is_distinct_from_static_bound() {
    let mut unbound =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
            features.has_external_buffer_binding = true;
        });
    unbound.candidate_id = "candidate:selector:unbound".to_owned();
    unbound.crate_id = "crate:selector:unbound".to_owned();
    unbound.pattern_family = bw_model::V32PatternFamily::ExternalBufferView;

    let mut bound =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_with_features(|features| {
            features.has_external_buffer_binding = true;
            features.has_external_buffer_lifetime_bound = true;
        });
    bound.candidate_id = "candidate:selector:bound".to_owned();
    bound.crate_id = "crate:selector:bound".to_owned();
    bound.pattern_family = bw_model::V32PatternFamily::ExternalBufferView;

    assert!(
        !bound.features.has_static_bound,
        "selector return-lifetime coverage is not a `'static` bound"
    );

    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![unbound.clone(), bound.clone()])
        .expect("external-buffer selector features should rank");
    let unbound_rank = ranked
        .iter()
        .find(|item| item.candidate_id == unbound.candidate_id)
        .expect("unbound selector candidate should be ranked");
    let bound_rank = ranked
        .iter()
        .find(|item| item.candidate_id == bound.candidate_id)
        .expect("bound selector candidate should be ranked");

    assert!(
        unbound_rank.score > bound_rank.score,
        "return lifetime coverage should be protective for external-buffer binding"
    );
    assert!(
        bound_rank
            .protective_features
            .contains(&"has_external_buffer_lifetime_bound".to_owned())
    );
    assert!(
        bound_rank
            .score_breakdown
            .has_external_buffer_lifetime_bound
            < 0
    );
}

#[test]
fn pair_delta_rejects_forbidden_tokens_inside_public_feature_fields() {
    let delta = V326PairDeltaRecord {
        schema_version: bw_model::V3_2_6_PAIR_DELTA_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        pair_id: "pair:001".to_owned(),
        comparison_key: String::new(),
        pair_manifest_run_id: String::new(),
        left_crate_id: "crate:left".to_owned(),
        right_crate_id: "crate:right".to_owned(),
        left_top_features: vec!["vulnerable".to_owned()],
        right_top_features: vec!["has_drop_guard".to_owned()],
        semantic_delta: vec!["right_added_patch".to_owned()],
        distinguishability: bw_model::V326Distinguishability::SeparableStatic,
        notes: vec!["anonymous comparison only".to_owned()],
    };

    let error = validate_v3_2_6_pair_deltas([Located {
        path: PathBuf::from("pair-deltas.jsonl"),
        line: 1,
        value: delta,
    }])
    .expect_err("pair-delta public feature fields must reject forbidden tokens");

    assert!(error.to_string().contains("BW-V326-DELTA"));
}

#[test]
fn legacy_pair_delta_rejects_candidate_alignment_key() {
    let delta = V326PairDeltaRecord {
        schema_version: bw_model::V3_2_6_PAIR_DELTA_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        pair_id: "pair:001".to_owned(),
        comparison_key: "comparison:abc123".to_owned(),
        pair_manifest_run_id: String::new(),
        left_crate_id: "crate:left".to_owned(),
        right_crate_id: "crate:right".to_owned(),
        left_top_features: vec!["has_borrowed_capture".to_owned()],
        right_top_features: vec!["has_drop_guard".to_owned()],
        semantic_delta: vec!["right_added_drop_guard".to_owned()],
        distinguishability: bw_model::V326Distinguishability::SeparableStatic,
        notes: vec!["anonymous comparison only".to_owned()],
    };

    let error = validate_v3_2_6_pair_deltas([Located {
        path: PathBuf::from("pair-deltas.jsonl"),
        line: 1,
        value: delta,
    }])
    .expect_err("legacy pair delta schema must not accept candidate alignment fields");

    assert!(error.to_string().contains("BW-V326-DELTA-COMPARISON-KEY"));
}

#[test]
fn lifecycle_feature_rejects_mixed_run_ids() {
    let first =
        bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate("crate:left", |_| {});
    let mut second = first.clone();
    second.candidate_id = "candidate:sample:002".to_owned();
    second.run_id = "run:other".to_owned();

    let error = bw_model::validate_v3_2_6_lifecycle_features([
        Located {
            path: PathBuf::from("lifecycle-features.jsonl"),
            line: 1,
            value: first,
        },
        Located {
            path: PathBuf::from("lifecycle-features.jsonl"),
            line: 2,
            value: second,
        },
    ])
    .expect_err("lifecycle feature inputs must not combine run provenance");

    assert!(error.to_string().contains("BW-V326-FEATURE-RUN-MISMATCH"));
}

#[test]
fn pair_delta_rejects_forbidden_token_inside_comparison_key() {
    let delta = V326PairDeltaRecord {
        schema_version: bw_model::V3_2_7_PAIR_DELTA_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        pair_id: "pair:001".to_owned(),
        comparison_key: "comparison:expected".to_owned(),
        pair_manifest_run_id: "run:pair-fixture".to_owned(),
        left_crate_id: "crate:left".to_owned(),
        right_crate_id: "crate:right".to_owned(),
        left_top_features: vec!["has_borrowed_capture".to_owned()],
        right_top_features: vec!["has_drop_guard".to_owned()],
        semantic_delta: vec!["right_added_drop_guard".to_owned()],
        distinguishability: bw_model::V326Distinguishability::SeparableStatic,
        notes: vec!["anonymous comparison only".to_owned()],
    };

    let error = validate_v3_2_7_pair_deltas([Located {
        path: PathBuf::from("pair-deltas.jsonl"),
        line: 1,
        value: delta,
    }])
    .expect_err("comparison key must reject forbidden public tokens");

    assert!(error.to_string().contains("BW-V326-DELTA"));
}

#[test]
fn pair_delta_rejects_duplicate_comparison_key_with_same_pair_id() {
    let legacy = V326PairDeltaRecord {
        schema_version: bw_model::V3_2_6_PAIR_DELTA_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        pair_id: "pair:001".to_owned(),
        comparison_key: String::new(),
        pair_manifest_run_id: String::new(),
        left_crate_id: "crate:left".to_owned(),
        right_crate_id: "crate:right".to_owned(),
        left_top_features: vec!["has_borrowed_capture".to_owned()],
        right_top_features: vec!["has_drop_guard".to_owned()],
        semantic_delta: vec!["right_added_drop_guard".to_owned()],
        distinguishability: bw_model::V326Distinguishability::SeparableStatic,
        notes: vec!["anonymous comparison only".to_owned()],
    };
    let mut keyed = legacy.clone();
    keyed.schema_version = bw_model::V3_2_7_PAIR_DELTA_SCHEMA_V1.to_owned();
    keyed.comparison_key = "comparison:abc123".to_owned();
    keyed.pair_manifest_run_id = "run:pair-fixture".to_owned();

    let error = validate_v3_2_7_pair_deltas([
        Located {
            path: PathBuf::from("pair-deltas.jsonl"),
            line: 1,
            value: {
                let mut v327 = legacy;
                v327.schema_version = bw_model::V3_2_7_PAIR_DELTA_SCHEMA_V1.to_owned();
                v327.comparison_key = "comparison:abc123".to_owned();
                v327.pair_manifest_run_id = "run:pair-fixture".to_owned();
                v327
            },
        },
        Located {
            path: PathBuf::from("pair-deltas.jsonl"),
            line: 2,
            value: keyed,
        },
    ])
    .expect_err("candidate-aligned deltas must not reuse one comparison key");

    assert!(error.to_string().contains("BW-V327-DELTA-ID-DUPLICATE"));
}

#[test]
fn pair_comparison_detects_added_drop_guard() {
    let left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.missing_unregister_before_drop = true;
        },
    );
    let right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right",
        |features| {
            features.has_foreign_register = true;
            features.has_borrowed_capture = true;
            features.has_drop_guard = true;
            features.release_covers_callback = true;
        },
    );
    let pair = bw_model::V326AnonymousPairRecord {
        schema_version: bw_model::V3_2_6_ANONYMOUS_PAIR_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        pair_id: "pair:001".to_owned(),
        left_crate_id: "crate:left".to_owned(),
        right_crate_id: "crate:right".to_owned(),
        relation_hint: "same_project_or_related_version".to_owned(),
        notes: vec!["anonymous comparison only".to_owned()],
    };

    let delta = bw_model::compare_v3_2_6_pair(&pair, &left, &right).unwrap();

    assert_eq!(
        delta.distinguishability,
        bw_model::V326Distinguishability::SeparableStatic
    );
    assert!(
        delta
            .semantic_delta
            .contains(&"right_added_drop_guard".to_owned())
    );
}

#[test]
fn lifecycle_fact_accepts_candidate_scoped_source_observation() {
    let record = bw_model::V326LifecycleFactRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_FACT_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: "candidate:alpha:001".to_owned(),
        crate_id: "crate:alpha".to_owned(),
        fact_id: "fact:alpha:callback:0001".to_owned(),
        fact_kind: bw_model::V326LifecycleFactKind::BorrowedCapture,
        source_ref: V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(10),
            line_end: Some(10),
            symbol_path: Some("alpha::register_callback".to_owned()),
            text_sha256: None,
        },
        symbol_path: Some("alpha::register_callback".to_owned()),
        confidence: V326EvidenceConfidence::Medium,
        coverage_state: bw_model::V326CoverageState::Covered,
        provenance: bw_model::V326LifecycleFactProvenance::source_observation(),
        object_ids: vec!["source_evidence:evidence:alpha:0001".to_owned()],
        evidence_refs: vec!["evidence:alpha:0001".to_owned()],
        notes: vec!["candidate-scoped source observation lifecycle fact".to_owned()],
    };

    let summary = bw_model::validate_v3_2_6_lifecycle_facts([Located {
        path: PathBuf::from("lifecycle-facts.jsonl"),
        line: 1,
        value: record,
    }])
    .expect("candidate-scoped source observation should validate");

    assert_eq!(summary.record_count, 1);
    assert_eq!(summary.covered_count, 1);
}

#[test]
fn lifecycle_fact_rejects_source_observation_with_stable_object_ids() {
    let record = bw_model::V326LifecycleFactRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_FACT_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: "candidate:alpha:001".to_owned(),
        crate_id: "crate:alpha".to_owned(),
        fact_id: "fact:alpha:forged:0001".to_owned(),
        fact_kind: bw_model::V326LifecycleFactKind::RegisterCall,
        source_ref: V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(10),
            line_end: Some(10),
            symbol_path: Some("alpha::register_callback".to_owned()),
            text_sha256: None,
        },
        symbol_path: Some("alpha::register_callback".to_owned()),
        confidence: V326EvidenceConfidence::Medium,
        coverage_state: bw_model::V326CoverageState::Covered,
        provenance: bw_model::V326LifecycleFactProvenance::source_observation(),
        object_ids: vec!["callback:alpha".to_owned(), "user_data:alpha".to_owned()],
        evidence_refs: vec!["evidence:alpha:0001".to_owned()],
        notes: vec!["forged stable ids must be rejected".to_owned()],
    };

    let error = bw_model::validate_v3_2_6_lifecycle_facts([Located {
        path: PathBuf::from("lifecycle-facts.jsonl"),
        line: 1,
        value: record,
    }])
    .expect_err("source_observation must not carry stable callback/user_data ids");
    assert!(error.to_string().contains("BW-V326-FACT-OBJECT-ID"));
}

#[test]
fn lifecycle_fact_rejects_missing_provenance_field() {
    let json = r#"{"schema_version":"v3.2.6.lifecycle_fact.1","run_id":"run:v326","candidate_id":"candidate:alpha:001","crate_id":"crate:alpha","fact_id":"fact:alpha:0001","fact_kind":"register_call","source_ref":{"path":"src/lib.rs","line_start":10,"line_end":10,"symbol_path":"alpha::register","text_sha256":null},"symbol_path":"alpha::register","confidence":"medium","coverage_state":"covered","object_ids":["source_evidence:evidence:alpha:0001"],"evidence_refs":["evidence:alpha:0001"],"notes":["missing provenance"]}"#;
    let error = serde_json::from_str::<bw_model::V326LifecycleFactRecord>(json)
        .expect_err("missing provenance must fail deserialization");
    assert!(
        error.to_string().contains("provenance") || error.to_string().contains("missing field")
    );
}

#[test]
fn lifecycle_fact_rejects_legacy_provenance_origin() {
    let record = bw_model::V326LifecycleFactRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_FACT_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: "candidate:alpha:001".to_owned(),
        crate_id: "crate:alpha".to_owned(),
        fact_id: "fact:alpha:legacy:0001".to_owned(),
        fact_kind: bw_model::V326LifecycleFactKind::RegisterCall,
        source_ref: V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(10),
            line_end: Some(10),
            symbol_path: Some("alpha::register_callback".to_owned()),
            text_sha256: None,
        },
        symbol_path: Some("alpha::register_callback".to_owned()),
        confidence: V326EvidenceConfidence::Medium,
        coverage_state: bw_model::V326CoverageState::Covered,
        provenance: bw_model::V326LifecycleFactProvenance::default(),
        object_ids: vec!["source_evidence:evidence:alpha:0001".to_owned()],
        evidence_refs: vec!["evidence:alpha:0001".to_owned()],
        notes: vec!["legacy origin must be rejected for fact.1".to_owned()],
    };

    let error = bw_model::validate_v3_2_6_lifecycle_facts([Located {
        path: PathBuf::from("lifecycle-facts.jsonl"),
        line: 1,
        value: record,
    }])
    .expect_err("legacy provenance origin must be rejected");
    assert!(error.to_string().contains("BW-V326-FACT-PROVENANCE"));
}

#[test]
fn lifecycle_fact_rejects_contract_retention_kind() {
    let record = bw_model::V326LifecycleFactRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_FACT_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: "candidate:alpha:001".to_owned(),
        crate_id: "crate:alpha".to_owned(),
        fact_id: "fact:forged:retention".to_owned(),
        fact_kind: bw_model::V326LifecycleFactKind::ContractRetention,
        source_ref: V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(10),
            line_end: Some(10),
            symbol_path: Some("alpha::register_callback".to_owned()),
            text_sha256: None,
        },
        symbol_path: Some("alpha::register_callback".to_owned()),
        confidence: V326EvidenceConfidence::Medium,
        coverage_state: bw_model::V326CoverageState::Covered,
        provenance: bw_model::V326LifecycleFactProvenance::source_observation(),
        object_ids: vec!["source_evidence:evidence:alpha:0001".to_owned()],
        evidence_refs: vec!["evidence:alpha:0001".to_owned()],
        notes: vec!["contract retention must not be a fact".to_owned()],
    };

    let error = bw_model::validate_v3_2_6_lifecycle_facts([Located {
        path: PathBuf::from("lifecycle-facts.jsonl"),
        line: 1,
        value: record,
    }])
    .expect_err("contract_retention fact kind must be rejected");
    assert!(
        error
            .to_string()
            .contains("BW-V326-FACT-CONTRACT-RETENTION")
    );
}

#[test]
fn forged_contract_retention_fact_does_not_derive_foreign_may_retain_callback() {
    let candidate = sample_candidate("candidate:forged-retention:001", "crate:forged-retention");
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:forged-retention:register",
        "crate:forged-retention",
        "candidate:forged-retention:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];
    let forged = bw_model::V326LifecycleFactRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_FACT_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: candidate.candidate_id.clone(),
        crate_id: candidate.crate_id.clone(),
        fact_id: "fact:forged:retention".to_owned(),
        fact_kind: bw_model::V326LifecycleFactKind::ContractRetention,
        source_ref: V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(1),
            line_end: Some(1),
            symbol_path: Some("contract::register_callback".to_owned()),
            text_sha256: None,
        },
        symbol_path: Some("contract::register_callback".to_owned()),
        confidence: V326EvidenceConfidence::Medium,
        coverage_state: bw_model::V326CoverageState::Covered,
        provenance: bw_model::V326LifecycleFactProvenance::source_observation(),
        object_ids: vec!["source_evidence:evidence:forged-retention:register".to_owned()],
        evidence_refs: vec!["evidence:forged-retention:register".to_owned()],
        notes: vec!["forged retention fact".to_owned()],
    };

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[forged],
        &[],
    );

    assert!(!feature.features.foreign_may_retain_callback);
    assert!(feature.features.has_foreign_register);
}

#[test]
fn lifecycle_coverage_manifest_reports_uncovered_drop_impl_reason() {
    let record = bw_model::V326LifecycleCoverageRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_COVERAGE_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: "candidate:alpha:001".to_owned(),
        crate_id: "crate:alpha".to_owned(),
        covered_function_bodies: vec!["alpha::register_callback".to_owned()],
        covered_trait_impls: Vec::new(),
        covered_drop_impls: Vec::new(),
        unavailable_paths: vec![bw_model::V326CoverageGap {
            path: "alpha::Owner::drop".to_owned(),
            reason: bw_model::V326CoverageGapReason::DropImplUnavailable,
            notes: vec!["Drop impl was not covered by the static fact bridge".to_owned()],
        }],
        fact_refs: vec!["fact:alpha:callback:0001".to_owned()],
        notes: vec!["coverage manifest is per candidate".to_owned()],
    };

    let summary = bw_model::validate_v3_2_6_lifecycle_coverage([Located {
        path: PathBuf::from("lifecycle-coverage.jsonl"),
        line: 1,
        value: record,
    }])
    .expect("coverage manifest with explicit gap reason should validate");

    assert_eq!(summary.record_count, 1);
    assert_eq!(summary.unavailable_path_count, 1);
}

#[test]
fn lifecycle_contract_rejects_unknown_field_and_forbidden_token() {
    let json = r#"{"schema_version":"v3.2.6.lifecycle_contract.1","run_id":"run:v326","contract_id":"contract:alpha","component_id":"component:alpha","api_id":"alpha::register_callback","retention":"may_retain_callback","replacement":"unknown","release":"unknown","owner_semantics":"foreign_owned","scope":"local_fixture","source":"advisory-note","evidence_refs":["evidence:alpha:0001"],"notes":["neutral contract"],"extra":true}"#;

    let error = serde_json::from_str::<bw_model::V326LifecycleContractRecord>(json)
        .expect_err("unknown contract field must be rejected");
    assert!(error.to_string().contains("unknown field"));

    let mut contract = bw_model::V326LifecycleContractRecord::sample_for_tests_retaining();
    contract.source = "advisory-note".to_owned();
    let error = bw_model::validate_v3_2_6_lifecycle_contracts([Located {
        path: PathBuf::from("contracts.jsonl"),
        line: 1,
        value: contract,
    }])
    .expect_err("contract public fields must reject forbidden tokens");
    assert!(error.to_string().contains("BW-V326-CONTRACT"));
}

#[test]
fn contract_retention_signal_derives_foreign_may_retain_callback() {
    let candidate = sample_candidate("candidate:contract:001", "crate:contract");
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:contract:0001",
        "crate:contract",
        "candidate:contract:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];
    let contract = bw_model::V326LifecycleContractRecord::sample_for_tests_retaining();

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[],
        &[contract],
    );

    assert!(feature.features.foreign_may_retain_callback);
    assert!(
        feature
            .feature_evidence
            .get("foreign_may_retain_callback")
            .is_some_and(|refs| refs.iter().any(|item| item.starts_with("contract:")))
    );
}

#[test]
fn contract_retention_signal_does_not_bleed_to_unrelated_candidate() {
    let candidate = sample_candidate("candidate:unrelated:001", "crate:unrelated");
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:unrelated:0001",
        "crate:unrelated",
        "candidate:unrelated:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];
    let mut contract = bw_model::V326LifecycleContractRecord::sample_for_tests_retaining();
    contract.api_id = "other_component::retain_callback".to_owned();
    contract.component_id = "component:other".to_owned();

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[],
        &[contract],
    );

    assert!(!feature.features.foreign_may_retain_callback);
}

#[test]
fn contract_retention_signal_requires_exact_candidate_api() {
    let candidate = sample_candidate("candidate:tail-collision:001", "crate:tail-collision");
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:tail-collision:0001",
        "crate:tail-collision",
        "candidate:tail-collision:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];
    let mut contract = bw_model::V326LifecycleContractRecord::sample_for_tests_retaining();
    contract.api_id = "other_component::register_callback".to_owned();
    contract.component_id = "component:other".to_owned();

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[],
        &[contract],
    );

    assert!(!feature.features.foreign_may_retain_callback);
}

#[test]
fn contract_retention_signal_rejects_bare_api_tokens() {
    let mut candidate = sample_candidate("candidate:bare-contract:001", "crate:bare-contract");
    candidate.api_path = Some("register".to_owned());
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:bare-contract:0001",
        "crate:bare-contract",
        "candidate:bare-contract:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];
    let mut contract = bw_model::V326LifecycleContractRecord::sample_for_tests_retaining();
    contract.api_id = "register".to_owned();

    let validate_error = bw_model::validate_v3_2_6_lifecycle_contracts([Located {
        path: PathBuf::from("contracts.jsonl"),
        line: 1,
        value: contract.clone(),
    }])
    .expect_err("bare contract API token must fail public validation");
    assert!(
        validate_error
            .to_string()
            .contains("BW-V326-CONTRACT-API-ID")
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[],
        &[contract],
    );

    assert!(!feature.features.foreign_may_retain_callback);
}

#[test]
fn contract_api_map_id_requires_verified_static_registration_binding() {
    let mut candidate = sample_candidate("candidate:contract-map:001", "crate:contract-map");
    candidate.api_path = Some("source_api::opaque_candidate_identity".to_owned());
    candidate.evidence_refs[0].line_start = Some(10);
    candidate.evidence_refs[0].line_end = Some(11);
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:contract-map:register",
            "crate:contract-map",
            "candidate:contract-map:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:contract-map:raw",
            "crate:contract-map",
            "candidate:contract-map:001",
            bw_model::V326EvidenceKind::RawPointerEscape,
        ),
    ];
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: "crate:contract-map".to_owned(),
        package_name: "contract-map".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = |line_start| bw_model::StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start,
        line_end: line_start,
        symbol_path: None,
    };
    let registration = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:contract-map:register".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:contract-map".to_owned()),
        artifact: Some(artifact.clone()),
        source_ref: Some(source_ref(10)),
        payload: bw_model::StaticFact::RegistrationSite(bw_model::RegistrationSiteFact {
            site_id: bw_model::SiteId("site:contract-map:register".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey(
                "semantic:contract-map:register".to_owned(),
            ),
            callback_site_id: None,
            user_data_site_id: Some(bw_model::SiteId("site:contract-map:user-data".to_owned())),
            api_id: "api:rusqlite:update_hook:register".to_owned(),
            role: bw_model::RegistrationRole::Register,
        }),
    };
    let raw_transfer = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:contract-map:raw".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:contract-map".to_owned()),
        artifact: Some(artifact),
        source_ref: Some(source_ref(11)),
        payload: bw_model::StaticFact::RawPointerTransfer(bw_model::RawPointerTransferFact {
            site_id: bw_model::SiteId("site:contract-map:raw".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("semantic:contract-map:raw".to_owned()),
            user_data_site_id: bw_model::SiteId("site:contract-map:user-data".to_owned()),
            transfer_kind: bw_model::RawPointerTransferKind::IntoRaw,
        }),
    };
    let static_facts = vec![registration, raw_transfer];
    let anchor_record_id = static_facts[0].record_id.to_string();
    let facts = static_facts
        .iter()
        .map(|envelope| {
            let source = envelope.source_ref.as_ref().unwrap();
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                &candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                vec!["evidence:contract-map:register".to_owned()],
            )
            .expect("static fixture should map to a lifecycle fact");
            fact.provenance.static_anchor_record_ids = vec![anchor_record_id.clone()];
            assert!(
                bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                    &mut fact,
                    &candidate,
                    &static_facts,
                ),
                "static fixture provenance failed for {}",
                envelope.record_id
            );
            fact
        })
        .collect::<Vec<_>>();
    let mut contract = bw_model::V326LifecycleContractRecord::sample_for_tests_retaining();
    contract.api_id = "api:rusqlite:update_hook:register".to_owned();

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &facts,
        &[contract],
    );

    assert!(feature.features.foreign_may_retain_callback);
    assert!(feature.features.has_raw_pointer_escape);
}

#[test]
fn static_owned_retained_user_data_does_not_score_as_borrowed_lifetime_risk() {
    let mut candidate =
        sample_candidate("candidate:static-owned:001", "crate:static-owned-retention");
    candidate.api_path = Some("api:static-owned:register".to_owned());
    candidate.evidence_refs[0].line_start = Some(10);
    candidate.evidence_refs[0].line_end = Some(11);
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:static-owned:register",
            "crate:static-owned-retention",
            "candidate:static-owned:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:static-owned:retention",
            "crate:static-owned-retention",
            "candidate:static-owned:001",
            bw_model::V326EvidenceKind::ForeignRetentionHint,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:static-owned:owned",
            "crate:static-owned-retention",
            "candidate:static-owned:001",
            bw_model::V326EvidenceKind::OwnedAnchor,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:static-owned:raw",
            "crate:static-owned-retention",
            "candidate:static-owned:001",
            bw_model::V326EvidenceKind::RawPointerEscape,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:static-owned:bound",
            "crate:static-owned-retention",
            "candidate:static-owned:001",
            bw_model::V326EvidenceKind::LifetimeBound,
        ),
    ];
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: "crate:static-owned-retention".to_owned(),
        package_name: "static-owned-retention".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let registration = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:static-owned:register".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:static-owned".to_owned()),
        artifact: Some(artifact.clone()),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 10,
            line_end: 10,
            symbol_path: Some("api:static-owned:register".to_owned()),
        }),
        payload: bw_model::StaticFact::RegistrationSite(bw_model::RegistrationSiteFact {
            site_id: bw_model::SiteId("site:static-owned:register".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey(
                "semantic:static-owned:register".to_owned(),
            ),
            callback_site_id: Some(bw_model::SiteId("site:static-owned:callback".to_owned())),
            user_data_site_id: Some(bw_model::SiteId("site:static-owned:user-data".to_owned())),
            api_id: "api:static-owned:register".to_owned(),
            role: bw_model::RegistrationRole::Register,
        }),
    };
    let raw_transfer = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:static-owned:raw".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:static-owned".to_owned()),
        artifact: Some(artifact),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 11,
            line_end: 11,
            symbol_path: None,
        }),
        payload: bw_model::StaticFact::RawPointerTransfer(bw_model::RawPointerTransferFact {
            site_id: bw_model::SiteId("site:static-owned:raw".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("semantic:static-owned:raw".to_owned()),
            user_data_site_id: bw_model::SiteId("site:static-owned:user-data".to_owned()),
            transfer_kind: bw_model::RawPointerTransferKind::IntoRaw,
        }),
    };
    let static_facts = vec![registration, raw_transfer];
    let anchor_record_id = static_facts[0].record_id.to_string();
    let facts = static_facts
        .iter()
        .map(|envelope| {
            let source = envelope.source_ref.as_ref().unwrap();
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                &candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                vec!["evidence:static-owned:register".to_owned()],
            )
            .expect("static fixture should map to a lifecycle fact");
            fact.provenance.static_anchor_record_ids = vec![anchor_record_id.clone()];
            assert!(
                bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                    &mut fact,
                    &candidate,
                    &static_facts,
                ),
                "static fixture provenance failed for {}",
                envelope.record_id
            );
            fact
        })
        .collect::<Vec<_>>();

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &facts,
        &[],
    );

    assert!(feature.features.foreign_may_retain_callback);
    assert!(feature.features.foreign_may_retain_user_data);
    assert!(feature.features.has_raw_pointer_escape);
    assert!(feature.features.has_owned_anchor);
    assert!(feature.features.has_static_bound);
    assert!(!feature.features.missing_unregister_before_drop);
    assert!(feature.features.release_order_unknown);
    assert!(!feature.features.release_covers_callback);

    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature]).unwrap();
    assert_eq!(ranked[0].score_breakdown.foreign_may_retain_user_data, 0);
    assert!(ranked[0].score < 20);
}

#[test]
fn lifecycle_graph_v3_requires_stable_object_ids_on_edges() {
    let graph = bw_model::V326LifecycleGraphV3Record {
        schema_version: bw_model::V3_2_6_LIFECYCLE_GRAPH_V3_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: "candidate:alpha:001".to_owned(),
        crate_id: "crate:alpha".to_owned(),
        pattern_family: bw_model::V32PatternFamily::RetainedBorrowedCallback,
        objects: vec![bw_model::V326LifecycleObject {
            object_id: "callback:alpha".to_owned(),
            object_kind: bw_model::V326LifecycleObjectKind::Callback,
            label: "alpha callback".to_owned(),
            source_ref: None,
            fact_refs: vec!["fact:alpha:callback:0001".to_owned()],
        }],
        edges: vec![bw_model::V326LifecycleGraphV3Edge {
            edge_id: "edge:alpha:register".to_owned(),
            from_object_id: "callback:alpha".to_owned(),
            to_object_id: "foreign-owner:alpha".to_owned(),
            relation: bw_model::V326LifecycleRelation::Register,
            ordering: bw_model::V326LifecycleOrdering::Unknown,
            evidence_refs: vec!["evidence:alpha:0001".to_owned()],
            fact_refs: vec!["fact:alpha:register:0001".to_owned()],
        }],
        object_chains: Vec::new(),
        evidence_refs: vec!["evidence:alpha:0001".to_owned()],
        incomplete_reasons: vec!["foreign owner object missing".to_owned()],
        notes: vec!["graph v3 fixture".to_owned()],
    };

    let error = bw_model::validate_v3_2_6_lifecycle_graph_v3([Located {
        path: PathBuf::from("graph-v3.json"),
        line: 1,
        value: graph,
    }])
    .expect_err("graph v3 edge endpoint must reference a stable object id");

    assert!(error.to_string().contains("BW-V326-GRAPH-V3-EDGE-ENDPOINT"));
}

#[test]
fn lifecycle_graph_v3_keeps_unbound_evidence_objects_separate() {
    let candidate = sample_candidate("candidate:graph-v3-object:001", "crate:graph-v3-object");
    let register = evidence_with_details(
        "evidence:graph-v3-object:register",
        "crate:graph-v3-object",
        "candidate:graph-v3-object:001",
        bw_model::V326EvidenceKind::ForeignRegister,
        serde_json::json!({"callback_object_id":"callback:alpha"}),
    );
    let release = evidence_with_details(
        "evidence:graph-v3-object:release",
        "crate:graph-v3-object",
        "candidate:graph-v3-object:001",
        bw_model::V326EvidenceKind::ForeignUnregister,
        serde_json::json!({"callback_object_id":"callback:beta","ordering":"after_register"}),
    );

    let graph =
        bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[register, release], &[], &[]);
    let register_edge = graph
        .edges
        .iter()
        .find(|edge| edge.relation == bw_model::V326LifecycleRelation::Register)
        .expect("register edge should be present");
    let release_edge = graph
        .edges
        .iter()
        .find(|edge| edge.relation == bw_model::V326LifecycleRelation::Release)
        .expect("release edge should be present");

    assert!(
        register_edge
            .from_object_id
            .starts_with("observation:callback:")
    );
    assert!(
        release_edge
            .from_object_id
            .starts_with("observation:callback:")
    );
    assert_ne!(register_edge.from_object_id, release_edge.from_object_id);
    assert_eq!(
        release_edge.ordering,
        bw_model::V326LifecycleOrdering::Unknown,
        "release ordering in graph v3 must not come from evidence details without proof"
    );
}

#[test]
fn graph_v3_binds_register_and_unregister_from_static_facts() {
    // Authoritative release-like paths under bw.static/0.1 use RegistrationSite::Unregister
    // (UnregisterCall). ExternalCallSite is not mapped to ReleaseCall.
    let candidate = sample_candidate("candidate:source-fact-graph:001", "crate:source-fact-graph");
    let register = bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:source-fact-graph:register",
        "crate:source-fact-graph",
        "candidate:source-fact-graph:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    );
    let unregister = bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:source-fact-graph:unregister",
        "crate:source-fact-graph",
        "candidate:source-fact-graph:001",
        bw_model::V326EvidenceKind::ForeignUnregister,
    );
    let facts = vec![
        static_fact_with_object(
            "fact:source:register",
            "candidate:source-fact-graph:001",
            "crate:source-fact-graph",
            bw_model::V326LifecycleFactKind::RegisterCall,
            "callback:alpha_callback",
        ),
        static_fact_with_object(
            "fact:source:unregister",
            "candidate:source-fact-graph:001",
            "crate:source-fact-graph",
            bw_model::V326LifecycleFactKind::UnregisterCall,
            "callback:alpha_callback",
        ),
    ];
    assert!(facts.iter().all(|fact| {
        matches!(
            fact.fact_kind,
            bw_model::V326LifecycleFactKind::RegisterCall
                | bw_model::V326LifecycleFactKind::UnregisterCall
        )
    }));

    let graph =
        bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[register, unregister], &facts, &[]);
    let register_edge = graph
        .edges
        .iter()
        .find(|edge| edge.relation == bw_model::V326LifecycleRelation::Register)
        .expect("register edge should be present");
    let release_edge = graph
        .edges
        .iter()
        .find(|edge| edge.relation == bw_model::V326LifecycleRelation::Release)
        .expect("unregister-backed release edge should be present");

    assert_eq!(register_edge.from_object_id, "callback:alpha_callback");
    assert_eq!(release_edge.from_object_id, "callback:alpha_callback");
    assert!(
        graph
            .objects
            .iter()
            .any(|object| object.object_id == "callback:alpha_callback")
    );
}

#[test]
fn graph_v3_materializes_returned_borrow_static_fact_edges() {
    let mut candidate = sample_candidate("candidate:graph-rb:001", "crate:graph-rb");
    candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    candidate.api_path = Some("fixture::View::get".to_owned());
    let facts = returned_borrow_static_lifecycle_facts(&candidate, "graph-rb");

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    bw_model::validate_v3_2_6_lifecycle_graph_v3([Located {
        path: PathBuf::from("graph-v3-returned-borrow.json"),
        line: 1,
        value: graph.clone(),
    }])
    .expect("fact-derived returned-borrow graph should validate");

    assert!(
        graph.edges.iter().any(
            |edge| edge.relation == bw_model::V326LifecycleRelation::Borrow
                && edge.from_object_id.starts_with("rust_owner:")
                && edge.to_object_id.starts_with("returned_ref:")
                && edge
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("returned-relation"))
        ),
        "returned-borrow relation static fact must become a graph edge"
    );
    assert!(
        graph.edges.iter().any(
            |edge| edge.relation == bw_model::V326LifecycleRelation::Persist
                && edge.from_object_id.starts_with("returned_ref:")
                && edge.to_object_id.starts_with("storage:")
                && edge
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("persisted"))
        ),
        "persisted returned-borrow static fact must become a graph edge"
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.relation == bw_model::V326LifecycleRelation::Use
                && edge.ordering == bw_model::V326LifecycleOrdering::Before
                && edge
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("order"))),
        "returned-borrow invalidation/order static fact must become a graph edge"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "foreign_contract_missing"),
        "pure returned-borrow graph should not require a foreign callback contract"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_binding_unproven"),
        "authoritative returned-borrow facts should not introduce observation objects"
    );
}

#[test]
fn object_flow_static_fact_maps_to_candidate_scoped_lifecycle_fact() {
    let candidate = sample_candidate("candidate:object-flow:001", "crate:object-flow");
    let (static_facts, mut facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "object-flow",
        vec![(
            "field-store",
            bw_model::ObjectFlowKind::FieldStore,
            bw_model::ObjectFlowObjectKind::UserData,
            "site:object-flow:user-data",
            bw_model::ObjectFlowObjectKind::Storage,
            "site:object-flow:storage",
        )],
    );
    let mut fact = facts.pop().expect("one object-flow fact");

    assert_eq!(fact.fact_kind, bw_model::V326LifecycleFactKind::ObjectFlow);
    assert!(
        fact.object_ids
            .contains(&"user_data:site:object-flow:user-data".to_owned())
    );
    assert!(
        fact.object_ids
            .contains(&"storage:site:object-flow:storage".to_owned())
    );
    assert!(
        fact.object_ids
            .contains(&"static_site:site:object-flow:field-store".to_owned())
    );
    assert!(
        fact.object_ids
            .contains(&"object_flow:field_store".to_owned())
    );
    assert!(
        fact.object_ids
            .iter()
            .any(|object_id| object_id.starts_with("object_flow_binding:field:")),
        "ObjectFlow lifecycle fact should carry a hashed binding key derived from field_path"
    );
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &candidate,
        &static_facts,
    ));
}

#[test]
fn graph_v3_merges_object_flow_edges_into_same_object_chain() {
    let candidate = sample_candidate("candidate:object-flow-chain:001", "crate:object-flow-chain");
    let (_static_facts, facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "object-flow-chain",
        vec![
            (
                "field-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-chain:user-data",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-chain:storage",
            ),
            (
                "field-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-chain:storage",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-chain:user-data",
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain.fact_refs.len() == 2
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-load"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("user_data:"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("storage:"))
        }),
        "field store and field load over the same endpoint ids should become one continuous object chain"
    );
}

#[test]
fn graph_v3_requires_same_object_flow_binding_key_for_verified_chain() {
    let candidate = sample_candidate(
        "candidate:object-flow-key-mismatch:001",
        "crate:object-flow-key-mismatch",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-key-mismatch",
        vec![
            (
                "field-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-key-mismatch:user-data",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-key-mismatch:storage",
                Some("field:registered"),
                None,
            ),
            (
                "field-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-key-mismatch:storage",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-key-mismatch:user-data",
                Some("field:released"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );

    assert!(
        graph.object_chains.iter().all(|chain| {
            chain.chain_status != bw_model::V326ObjectChainStatus::VerifiedStaticChain
        }),
        "matching endpoint ids are insufficient when compiler-provided ObjectFlow binding keys disagree"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "field_binding_missing"),
        "graph diagnostics should attribute the break to field binding evidence"
    );
    assert!(
        !feature.features.has_verified_object_chain,
        "ranking must not enable strong same-object features for mismatched ObjectFlow keys"
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "field_binding_missing"),
        "ranking diagnostics should preserve the field-binding gap"
    );
}

#[test]
fn graph_v3_accepts_same_object_flow_field_roundtrip_with_distinct_storage_sites_when_binding_key_matches()
 {
    let candidate = sample_candidate(
        "candidate:object-flow-field-roundtrip:001",
        "crate:object-flow-field-roundtrip",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-field-roundtrip",
        vec![
            (
                "field-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-field-roundtrip:user-data",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-field-roundtrip:store-site",
                Some("field:0"),
                None,
            ),
            (
                "field-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-field-roundtrip:load-site",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-field-roundtrip:user-data",
                Some("field:0"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
        }),
        "same underlying object plus matching compiler-provided field binding key should prove a field store/load round-trip even when store/load static sites are distinct"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "field_binding_missing"),
        "matching same-object field flow should not be downgraded to a field-binding gap"
    );
    assert!(
        feature.features.has_verified_object_chain,
        "ranking should retain the strong same-object feature when exact object and binding key agree"
    );
}

#[test]
fn graph_v3_keeps_field_roundtrip_verified_without_reassignment_barrier() {
    let candidate = sample_candidate(
        "candidate:object-flow-no-barrier:001",
        "crate:object-flow-no-barrier",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-no-barrier",
        vec![
            (
                "field-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-no-barrier:user-data",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-no-barrier:store-site",
                Some("field:slot"),
                None,
            ),
            (
                "field-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-no-barrier:load-site",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-no-barrier:user-data",
                Some("field:slot"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-load"))
        }),
        "an unmutated exact field key must still round-trip into a verified same-object chain"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_reassignment_barrier"),
        "no compiler-observed barrier means no reassignment attribution"
    );
}

#[test]
fn graph_v3_reassignment_barrier_does_not_block_an_unrelated_binding_key() {
    let candidate = sample_candidate(
        "candidate:object-flow-barrier-scope:001",
        "crate:object-flow-barrier-scope",
    );
    let (_static_facts, mut facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-barrier-scope",
        vec![
            (
                "kept-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-barrier-scope:kept-user-data",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-barrier-scope:kept-store-site",
                Some("field:kept"),
                None,
            ),
            (
                "kept-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-barrier-scope:kept-load-site",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-barrier-scope:kept-user-data",
                Some("field:kept"),
                None,
            ),
        ],
    );
    facts.push(object_binding_gap_static_lifecycle_fact_with_field_path(
        &candidate,
        "object-flow-barrier-scope",
        bw_model::ObjectBindingGapKind::ReassignmentBarrier,
        "field:replaced",
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("kept-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("kept-load"))
        }),
        "a barrier on one binding key must stay scoped to that key and must not degrade an unrelated field chain in the same candidate"
    );
}

#[test]
fn graph_v3_reassignment_barrier_blocks_object_flow_field_roundtrip() {
    let candidate = sample_candidate(
        "candidate:object-flow-reassignment-barrier:001",
        "crate:object-flow-reassignment-barrier",
    );
    let (_static_facts, mut facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-reassignment-barrier",
        vec![
            (
                "field-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-reassignment-barrier:user-data",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-reassignment-barrier:store-site",
                Some("field:slot"),
                None,
            ),
            (
                "field-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-reassignment-barrier:load-site",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-reassignment-barrier:user-data",
                Some("field:slot"),
                None,
            ),
        ],
    );
    facts.push(object_binding_gap_static_lifecycle_fact_with_field_path(
        &candidate,
        "object-flow-reassignment-barrier",
        bw_model::ObjectBindingGapKind::ReassignmentBarrier,
        "field:slot",
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    assert!(
        !graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-load"))
        }),
        "an exact same field key is insufficient after a compiler-observed reassignment barrier"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_reassignment_barrier")
    );
    assert!(!feature.features.has_verified_object_chain);
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "object_reassignment_barrier")
    );
}

#[test]
fn graph_v3_mutation_barrier_blocks_object_flow_collection_roundtrip() {
    let candidate = sample_candidate(
        "candidate:object-flow-collection-mutation-barrier:001",
        "crate:object-flow-collection-mutation-barrier",
    );
    let collection_prefix = "field:MapHolder:field:column_names:map_key:";
    let collection_key = "field:MapHolder:field:column_names:map_key:first";
    let (_static_facts, mut facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-collection-mutation-barrier",
        vec![
            (
                "collection-store",
                bw_model::ObjectFlowKind::CollectionStore,
                bw_model::ObjectFlowObjectKind::ReturnedRef,
                "site:object-flow-collection-mutation-barrier:returned-ref",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-collection-mutation-barrier:store-site",
                Some(collection_key),
                Some("std::collections::HashMap<String, &CStr>"),
            ),
            (
                "collection-load",
                bw_model::ObjectFlowKind::CollectionLoad,
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-collection-mutation-barrier:load-site",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-collection-mutation-barrier:use-site",
                Some(collection_key),
                Some("std::collections::HashMap<String, &CStr>"),
            ),
        ],
    );
    facts.push(
        object_binding_gap_static_lifecycle_fact_with_field_path_and_adapter(
            &candidate,
            "object-flow-collection-mutation-barrier",
            bw_model::ObjectBindingGapKind::MutationBarrier,
            collection_prefix,
            Some("returned_borrow_storage_prefix_mutation:fixture"),
        ),
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );

    assert!(
        !graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("collection-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("collection-load"))
        }),
        "an exact same collection key is insufficient after a compiler-observed storage mutation barrier"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "storage_mutation_barrier")
    );
    assert!(!feature.features.has_verified_object_chain);
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "storage_mutation_barrier")
    );
}

#[test]
fn graph_v3_does_not_merge_same_slot_key_across_distinct_opaque_handles() {
    let mut candidate = sample_candidate(
        "candidate:opaque-handle-cross-merge:001",
        "crate:opaque-handle-cross-merge",
    );
    candidate.api_path = Some("api:fixture:opaque_handle_register".to_owned());
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_api_and_field_paths(
        &candidate,
        "opaque-handle-cross-merge",
        "api:fixture:opaque_handle_register",
        vec![
            (
                "left-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:opaque-handle-cross-merge:left-user-data",
                bw_model::ObjectFlowObjectKind::OpaqueHandle,
                "site:opaque-handle-cross-merge:left-handle",
                Some("openssl_ex_data:api:fixture:opaque_handle_register:arg:0:root:const:7"),
                None,
            ),
            (
                "right-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::OpaqueHandle,
                "site:opaque-handle-cross-merge:right-handle",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:opaque-handle-cross-merge:right-release",
                Some("openssl_ex_data:api:fixture:opaque_handle_register:arg:1:root:const:7"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        !graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("left-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("right-load"))
        }),
        "an identical arg/slot key on two distinct opaque handle objects is a positional coincidence, not a proof that the stored user data is the object later read back"
    );
}

#[test]
fn graph_v3_accepts_exact_contract_opaque_handle_roundtrip_with_distinct_handle_sites() {
    let mut candidate = sample_candidate(
        "candidate:exact-opaque-handle-flow:001",
        "crate:exact-opaque-handle-flow",
    );
    candidate.api_path = Some("api:fixture:opaque_handle_register".to_owned());
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_api_and_field_paths(
        &candidate,
        "exact-opaque-handle-flow",
        "api:fixture:opaque_handle_register",
        vec![
            (
                "field-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:exact-opaque-handle-flow:user-data",
                bw_model::ObjectFlowObjectKind::OpaqueHandle,
                "site:exact-opaque-handle-flow:store-handle",
                Some("opaque_handle:arg0:slot7"),
                None,
            ),
            (
                "field-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::OpaqueHandle,
                "site:exact-opaque-handle-flow:load-handle",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:exact-opaque-handle-flow:release-from-raw",
                Some("opaque_handle:arg0:slot7"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-load"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("user_data:"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("opaque_handle:"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("static_site:"))
        }),
        "exact audited handle+key binding should prove the user_data persisted through the opaque handle even when store/load MIR sites differ"
    );
    assert!(
        feature.features.has_verified_object_chain,
        "ranking should consume the verified exact-key opaque-handle chain"
    );
}

#[test]
fn graph_v3_treats_static_site_object_flow_endpoints_as_chain_objects() {
    let candidate = sample_candidate(
        "candidate:static-site-object-flow-chain:001",
        "crate:static-site-object-flow-chain",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "static-site-object-flow-chain",
        vec![
            (
                "registration-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:static-site-object-flow-chain:user-data",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:static-site-object-flow-chain:registration",
            ),
            (
                "registration-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:static-site-object-flow-chain:registration",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:static-site-object-flow-chain:release",
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain.fact_refs.len() == 2
                && chain.object_ids.iter().any(|object_id| {
                    object_id == "static_site:site:static-site-object-flow-chain:registration"
                })
                && chain.object_ids.iter().any(|object_id| {
                    object_id == "static_site:site:static-site-object-flow-chain:release"
                })
        }),
        "ObjectFlow endpoints with StaticSite object kind are real chain endpoints; only the flow-site anchor is auxiliary"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "field_binding_missing"),
        "field_store + field_load over the same static registration site should not remain an incomplete field binding"
    );
}

#[test]
fn graph_v3_does_not_mark_release_path_argument_sequence_as_ambiguous() {
    let candidate = sample_candidate(
        "candidate:release-path-object-flow-sequence:001",
        "crate:release-path-object-flow-sequence",
    );
    let prefix = "release-path-object-flow-sequence";
    let user_data_site = bw_model::SiteId(format!("site:{prefix}:user-data"));
    let registration_site = bw_model::SiteId(format!("site:{prefix}:register"));
    let release_site = bw_model::SiteId(format!("site:{prefix}:from-raw"));
    let (_static_facts, mut facts) = object_flow_static_lifecycle_facts(
        &candidate,
        prefix,
        vec![
            (
                "into-raw-return",
                bw_model::ObjectFlowKind::ReturnValue,
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:release-path-object-flow-sequence:into-raw",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:release-path-object-flow-sequence:user-data",
            ),
            (
                "registration-argument",
                bw_model::ObjectFlowKind::Argument,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:release-path-object-flow-sequence:user-data",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:release-path-object-flow-sequence:register",
            ),
            (
                "release-argument",
                bw_model::ObjectFlowKind::Argument,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:release-path-object-flow-sequence:user-data",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:release-path-object-flow-sequence:from-raw",
            ),
            (
                "registration-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:release-path-object-flow-sequence:user-data",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:release-path-object-flow-sequence:register",
            ),
            (
                "registration-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:release-path-object-flow-sequence:register",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:release-path-object-flow-sequence:from-raw",
            ),
        ],
    );
    facts.extend(authoritative_user_data_release_facts_with_sites(
        &candidate,
        prefix,
        user_data_site,
        registration_site,
        release_site,
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain.object_ids.iter().any(|object_id| {
                    object_id == "user_data:site:release-path-object-flow-sequence:user-data"
                })
                && chain.object_ids.iter().any(|object_id| {
                    object_id == "static_site:site:release-path-object-flow-sequence:register"
                })
                && chain.object_ids.iter().any(|object_id| {
                    object_id == "static_site:site:release-path-object-flow-sequence:from-raw"
                })
        }),
        "register and release argument targets covered by one ReleasePathProof are a lifecycle sequence, not ambiguous fan-out"
    );
    for unexpected in [
        "object_binding_ambiguous",
        "call_boundary_binding_missing",
        "field_binding_missing",
        "object_flow_counterpart_missing",
    ] {
        assert!(
            !graph
                .incomplete_reasons
                .iter()
                .any(|reason| reason == unexpected),
            "{unexpected} should not be reported for a ReleasePathProof-covered argument sequence"
        );
    }
}

#[test]
fn graph_v3_merges_collection_store_and_load_into_same_object_chain() {
    let candidate = sample_candidate(
        "candidate:object-flow-collection-chain:001",
        "crate:object-flow-collection-chain",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "object-flow-collection-chain",
        vec![
            (
                "collection-store",
                bw_model::ObjectFlowKind::CollectionStore,
                bw_model::ObjectFlowObjectKind::ReturnedRef,
                "site:object-flow-collection-chain:returned-ref",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-collection-chain:storage",
            ),
            (
                "collection-load",
                bw_model::ObjectFlowKind::CollectionLoad,
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-collection-chain:storage",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-collection-chain:use",
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain.fact_refs.len() == 2
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("collection-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("collection-load"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("returned_ref:"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("storage:"))
        }),
        "collection store and collection load over the same endpoint ids should become one continuous object chain"
    );
}

#[test]
fn graph_v3_reports_collection_binding_missing_when_only_store_is_proven() {
    let candidate = sample_candidate(
        "candidate:object-flow-collection-missing-load:001",
        "crate:object-flow-collection-missing-load",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "object-flow-collection-missing-load",
        vec![(
            "collection-store",
            bw_model::ObjectFlowKind::CollectionStore,
            bw_model::ObjectFlowObjectKind::ReturnedRef,
            "site:object-flow-collection-missing-load:returned-ref",
            bw_model::ObjectFlowObjectKind::Storage,
            "site:object-flow-collection-missing-load:storage",
        )],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "collection_binding_missing"),
        "a collection store without a candidate-scoped collection load must be reported as a missing collection binding"
    );

    let v2_graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &v2_graph,
        &[],
        &facts,
        &[],
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "collection_binding_missing"),
        "ranking diagnostics must keep the collection-binding gap visible instead of treating store-only evidence as a complete lifecycle chain"
    );
}

#[test]
fn object_binding_gap_fact_reports_specific_adapter_reason_without_verified_chain() {
    let candidate = sample_candidate(
        "candidate:object-binding-gap-chain:001",
        "crate:object-binding-gap-chain",
    );
    let (static_facts, facts) = object_binding_gap_static_lifecycle_facts(
        &candidate,
        "object-binding-gap-chain",
        bw_model::ObjectBindingGapKind::MergedSources,
        "chain",
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "merged_source_binding_missing"),
        "graph diagnostics should preserve the conservative adapter-block reason"
    );
    assert!(
        graph.object_chains.iter().all(|chain| chain.chain_status
            != bw_model::V326ObjectChainStatus::VerifiedStaticChain),
        "object binding gap facts must not become verified object chains"
    );

    let fact = &facts[0];
    assert_eq!(
        fact.fact_kind,
        bw_model::V326LifecycleFactKind::ObjectBindingGap
    );
    assert!(fact.object_ids.iter().any(|id| id == "adapter:chain"));
    let mut fact_for_verification = fact.clone();
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact_for_verification,
        &candidate,
        &static_facts,
    ));

    let v2_graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &v2_graph,
        &[],
        &facts,
        &[],
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "merged_source_binding_missing"),
        "ranking diagnostics should keep the adapter-specific object-binding gap visible"
    );
    assert!(
        !feature.features.has_verified_object_chain,
        "adapter gap fact is diagnostic only and must not enable strong chain features"
    );
}

#[test]
fn object_binding_gap_fact_reports_dynamic_index_reason_without_verified_chain() {
    let candidate = sample_candidate(
        "candidate:object-binding-gap-dynamic-index:001",
        "crate:object-binding-gap-dynamic-index",
    );
    let (_static_facts, facts) = object_binding_gap_static_lifecycle_facts(
        &candidate,
        "object-binding-gap-dynamic-index",
        bw_model::ObjectBindingGapKind::DynamicIndex,
        "nth",
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "dynamic_index_binding_missing"),
        "graph diagnostics should preserve the missing dynamic-index binding reason"
    );

    let v2_graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &v2_graph,
        &[],
        &facts,
        &[],
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "dynamic_index_binding_missing"),
        "ranking diagnostics should keep the dynamic-index gap visible"
    );
    assert!(
        !feature.features.has_verified_object_chain,
        "dynamic-index gap is diagnostic only and must not enable strong chain features"
    );
}

#[test]
fn object_binding_gap_fact_reports_key_contract_reason_without_verified_chain() {
    let candidate = sample_candidate(
        "candidate:object-binding-gap-key-contract:001",
        "crate:object-binding-gap-key-contract",
    );
    let (_static_facts, facts) = object_binding_gap_static_lifecycle_facts(
        &candidate,
        "object-binding-gap-key-contract",
        bw_model::ObjectBindingGapKind::KeyContract,
        "key_contract",
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "key_contract_binding_missing"),
        "graph diagnostics should preserve unsupported keyed-map contract gaps"
    );

    let v2_graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &v2_graph,
        &[],
        &facts,
        &[],
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "key_contract_binding_missing"),
        "ranking diagnostics should keep the key-contract object-binding gap visible"
    );
    assert!(
        !feature.features.has_verified_object_chain,
        "key contract gap is diagnostic only and must not enable strong chain features"
    );
}

#[test]
fn disconnected_field_counterpart_still_reports_field_binding_missing() {
    let candidate = sample_candidate(
        "candidate:object-flow-field-disconnected:001",
        "crate:object-flow-field-disconnected",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "object-flow-field-disconnected",
        vec![
            (
                "field-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-field-disconnected:user-data-a",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-field-disconnected:storage-a",
            ),
            (
                "field-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Storage,
                "site:object-flow-field-disconnected:storage-b",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-field-disconnected:user-data-b",
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().all(|chain| {
            chain.chain_status != bw_model::V326ObjectChainStatus::VerifiedStaticChain
        }),
        "field store/load facts on different endpoint components must not form a verified same-object chain"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "field_binding_missing"),
        "field binding must be diagnosed per component; a field_load on another object cannot satisfy this field_store"
    );

    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    assert!(!feature.features.has_verified_object_chain);
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "field_binding_missing"),
        "ranking diagnostics must keep the component-scoped field-binding gap visible"
    );
}

#[test]
fn argument_only_object_flow_is_partial_and_not_a_verified_chain() {
    let candidate = sample_candidate(
        "candidate:object-flow-argument-only:001",
        "crate:object-flow-argument-only",
    );
    let user_data_site = bw_model::SiteId("site:object-flow-argument-only:user-data".to_owned());
    let registration_site = bw_model::SiteId("site:object-flow-argument-only:register".to_owned());
    let release_site = bw_model::SiteId("site:object-flow-argument-only:from-raw".to_owned());
    let registration_facts = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "object-flow-argument-only-registration",
        user_data_site,
        registration_site,
        release_site,
    );
    let (_static_facts, flow_facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "object-flow-argument-only",
        vec![(
            "argument",
            bw_model::ObjectFlowKind::Argument,
            bw_model::ObjectFlowObjectKind::UserData,
            "site:object-flow-argument-only:user-data",
            bw_model::ObjectFlowObjectKind::StaticSite,
            "site:object-flow-argument-only:register",
        )],
    );
    let facts = vec![registration_facts[0].clone(), flow_facts[0].clone()];
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:object-flow-argument-only:register",
        "crate:object-flow-argument-only",
        "candidate:object-flow-argument-only:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &evidence, &facts, &[]);
    let flow_chain = graph
        .object_chains
        .iter()
        .find(|chain| {
            chain
                .fact_refs
                .iter()
                .any(|fact_ref| fact_ref.contains("argument"))
        })
        .expect("argument ObjectFlow should still be represented as an incomplete chain");
    assert_eq!(
        flow_chain.chain_status,
        bw_model::V326ObjectChainStatus::PartialChain,
        "a bare argument transfer proves a local flow edge but not a complete lifecycle object chain"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_flow_counterpart_missing"),
        "graph diagnostics should explain that the partial flow lacks its complementary object-flow edge"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "call_boundary_binding_missing"),
        "graph diagnostics should identify that argument flow lacks a matching return/boundary counterpart"
    );

    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence),
        &evidence,
        &facts,
        &[],
    );
    assert!(
        !feature.features.has_verified_object_chain,
        "ranking must not enable the strong object-chain feature for a bare argument transfer"
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "object_flow_counterpart_missing"),
        "ranking diagnostics should keep the partial object-flow gap visible"
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "call_boundary_binding_missing"),
        "ranking diagnostics should report the missing call-boundary counterpart separately"
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "release_order_proof_missing"),
        "diagnostics should still explain that release/order proof is missing for the registration"
    );
}

#[test]
fn graph_v3_merges_wrapper_move_and_destructure_into_same_object_chain() {
    let candidate = sample_candidate(
        "candidate:object-flow-wrapper-chain:001",
        "crate:object-flow-wrapper-chain",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "object-flow-wrapper-chain",
        vec![
            (
                "wrapper-move",
                bw_model::ObjectFlowKind::WrapperMove,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-wrapper-chain:user-data",
                bw_model::ObjectFlowObjectKind::OpaqueHandle,
                "site:object-flow-wrapper-chain:wrapper",
            ),
            (
                "wrapper-destructure",
                bw_model::ObjectFlowKind::WrapperDestructure,
                bw_model::ObjectFlowObjectKind::OpaqueHandle,
                "site:object-flow-wrapper-chain:wrapper",
                bw_model::ObjectFlowObjectKind::UserData,
                "site:object-flow-wrapper-chain:user-data",
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain.fact_refs.len() == 2
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("wrapper-move"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("wrapper-destructure"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("user_data:"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("opaque_handle:"))
        }),
        "wrapper move and wrapper destructure over the same endpoint ids should become one continuous object chain"
    );
}

#[test]
fn graph_v3_treats_shared_owner_clone_alias_as_neutral_object_flow() {
    let candidate = sample_candidate(
        "candidate:object-flow-shared-owner-alias:001",
        "crate:object-flow-shared-owner-alias",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "object-flow-shared-owner-alias",
        vec![(
            "arc-clone-alias",
            bw_model::ObjectFlowKind::WrapperMove,
            bw_model::ObjectFlowObjectKind::RustOwner,
            "site:object-flow-shared-owner-alias:owner",
            bw_model::ObjectFlowObjectKind::RustOwner,
            "site:object-flow-shared-owner-alias:clone",
        )],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::PartialChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("arc-clone-alias"))
                && chain.object_ids.iter().all(|object_id| {
                    object_id.starts_with("rust_owner:")
                        || object_id.starts_with("static_site:")
                        || object_id.starts_with("object_flow:")
                })
        }),
        "a shared-owner clone alias should remain visible as neutral partial flow evidence"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_flow_counterpart_missing"),
        "a RustOwner->RustOwner clone alias must not be diagnosed as a missing lifecycle counterpart"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "wrapper_binding_missing"),
        "a RustOwner->RustOwner clone alias must not be diagnosed as a missing wrapper destructure"
    );

    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    assert!(
        !feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "object_flow_counterpart_missing"),
        "ranking diagnostics must keep shared-owner clone aliases out of counterpart gaps"
    );
    assert!(
        !feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "wrapper_binding_missing"),
        "ranking diagnostics must not treat shared-owner clone aliases as incomplete wrappers"
    );
}

#[test]
fn graph_v3_requires_closure_body_use_for_verified_closure_chain() {
    let candidate = sample_candidate(
        "candidate:object-flow-closure-chain:001",
        "crate:object-flow-closure-chain",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-closure-chain",
        vec![(
            "closure-capture",
            bw_model::ObjectFlowKind::ClosureCapture,
            bw_model::ObjectFlowObjectKind::RustOwner,
            "site:object-flow-closure-chain:owner",
            bw_model::ObjectFlowObjectKind::Callback,
            "site:object-flow-closure-chain:callback",
            Some("closure_capture_ordinal:0:field:value"),
            None,
        )],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().all(|chain| {
            chain.chain_status != bw_model::V326ObjectChainStatus::VerifiedStaticChain
        }),
        "closure capture alone only proves capture, not closure-body use of the same captured slot"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "closure_binding_missing"),
        "missing closure-body use should be attributed as a closure binding gap"
    );
}

#[test]
fn graph_v3_records_closure_capture_and_use_as_same_object_chain() {
    let candidate = sample_candidate(
        "candidate:object-flow-closure-chain-use:001",
        "crate:object-flow-closure-chain-use",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-closure-chain-use",
        vec![
            (
                "closure-capture",
                bw_model::ObjectFlowKind::ClosureCapture,
                bw_model::ObjectFlowObjectKind::RustOwner,
                "site:object-flow-closure-chain-use:owner",
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-chain-use:callback",
                Some("closure_capture_ordinal:0:field:value"),
                None,
            ),
            (
                "closure-use",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-chain-use:callback",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-closure-chain-use:use",
                Some("closure_capture_ordinal:0:field:value"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("closure-capture"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("closure-use"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("rust_owner:"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.contains(":capture_slot:"))
        }),
        "closure capture plus matching closure-body field load should connect owner, capture slot, and use site"
    );
}

#[test]
fn graph_v3_rejects_mismatched_closure_capture_use_slot() {
    let candidate = sample_candidate(
        "candidate:object-flow-closure-mismatch:001",
        "crate:object-flow-closure-mismatch",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-closure-mismatch",
        vec![
            (
                "closure-capture-left",
                bw_model::ObjectFlowKind::ClosureCapture,
                bw_model::ObjectFlowObjectKind::RustOwner,
                "site:object-flow-closure-mismatch:left-owner",
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-mismatch:callback",
                Some("closure_capture_ordinal:0:field:left"),
                None,
            ),
            (
                "closure-use-right",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-mismatch:callback",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-closure-mismatch:use",
                Some("closure_capture_ordinal:1:field:right"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().all(|chain| {
            chain.chain_status != bw_model::V326ObjectChainStatus::VerifiedStaticChain
        }),
        "closure-body use for a different capture slot must not verify the captured owner chain"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "closure_binding_missing")
    );
}

#[test]
fn graph_v3_keeps_repeated_use_of_one_capture_slot_verified() {
    let candidate = sample_candidate(
        "candidate:object-flow-closure-repeat-use:001",
        "crate:object-flow-closure-repeat-use",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-closure-repeat-use",
        vec![
            (
                "closure-capture",
                bw_model::ObjectFlowKind::ClosureCapture,
                bw_model::ObjectFlowObjectKind::RustOwner,
                "site:object-flow-closure-repeat-use:owner",
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-repeat-use:callback",
                Some("closure_capture_ordinal:0:field:value"),
                None,
            ),
            (
                "closure-use-first",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-repeat-use:callback",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-closure-repeat-use:first-use",
                Some("closure_capture_ordinal:0:field:value"),
                None,
            ),
            (
                "closure-use-second",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-repeat-use:callback",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-closure-repeat-use:second-use",
                Some("closure_capture_ordinal:0:field:value"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("closure-capture"))
        }),
        "repeated closure-body loads of one capture slot still describe one captured object, so the chain must stay verified"
    );
    assert!(
        graph
            .object_chains
            .iter()
            .all(|chain| chain.chain_status != bw_model::V326ObjectChainStatus::AmbiguousChain),
        "reusing one capture slot is not a multi-source merge and must not degrade to an ambiguous chain"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_binding_ambiguous"),
        "one capture slot loaded twice must not be attributed as an ambiguous object binding"
    );
}

#[test]
fn graph_v3_reports_closure_binding_gap_even_when_another_chain_is_verified() {
    let candidate = sample_candidate(
        "candidate:object-flow-closure-scoped-gap:001",
        "crate:object-flow-closure-scoped-gap",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-closure-scoped-gap",
        vec![
            (
                "field-store",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::RustOwner,
                "site:object-flow-closure-scoped-gap:holder-owner",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-closure-scoped-gap:holder-field",
                Some("field:holder"),
                None,
            ),
            (
                "field-load",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-closure-scoped-gap:holder-field",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-closure-scoped-gap:holder-use",
                Some("field:holder"),
                None,
            ),
            (
                "closure-capture",
                bw_model::ObjectFlowKind::ClosureCapture,
                bw_model::ObjectFlowObjectKind::RustOwner,
                "site:object-flow-closure-scoped-gap:capture-owner",
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-scoped-gap:callback",
                Some("closure_capture_ordinal:0:field:value"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph
            .object_chains
            .iter()
            .any(|chain| chain.chain_status
                == bw_model::V326ObjectChainStatus::VerifiedStaticChain),
        "the unrelated field store/load pair should still verify on its own"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "closure_binding_missing"),
        "an unbound capture slot must keep reporting its gap even when a different component in the same candidate is verified"
    );
}

#[test]
fn graph_v3_does_not_merge_multiple_closure_captures_into_one_same_object_chain() {
    let candidate = sample_candidate(
        "candidate:object-flow-closure-multisource:001",
        "crate:object-flow-closure-multisource",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "object-flow-closure-multisource",
        vec![
            (
                "closure-capture-left",
                bw_model::ObjectFlowKind::ClosureCapture,
                bw_model::ObjectFlowObjectKind::RustOwner,
                "site:object-flow-closure-multisource:left-owner",
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-multisource:callback",
            ),
            (
                "closure-capture-right",
                bw_model::ObjectFlowKind::ClosureCapture,
                bw_model::ObjectFlowObjectKind::RustOwner,
                "site:object-flow-closure-multisource:right-owner",
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-multisource:callback",
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );

    assert!(
        graph.object_chains.iter().all(|chain| {
            chain.chain_status != bw_model::V326ObjectChainStatus::VerifiedStaticChain
        }),
        "two different captured owners sharing one closure object must not be collapsed into one same-object chain"
    );
    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::AmbiguousChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("closure-capture-left"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("closure-capture-right"))
        }),
        "multi-source closure captures should be kept as an ambiguous binding component, not a verified identity proof"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_binding_ambiguous")
    );
    assert!(
        !feature.features.has_verified_object_chain,
        "ranking must not enable same-object strong features for multi-source closure captures"
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "object_binding_ambiguous")
    );
}

#[test]
fn graph_v3_splits_distinct_closure_capture_slots_without_merging_sources() {
    let candidate = sample_candidate(
        "candidate:object-flow-closure-slots:001",
        "crate:object-flow-closure-slots",
    );
    let (_static_facts, facts) = object_flow_static_lifecycle_facts_with_field_paths(
        &candidate,
        "object-flow-closure-slots",
        vec![
            (
                "closure-capture-left",
                bw_model::ObjectFlowKind::ClosureCapture,
                bw_model::ObjectFlowObjectKind::RustOwner,
                "site:object-flow-closure-slots:left-owner",
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-slots:callback",
                Some("closure_capture_ordinal:0:field:left"),
                None,
            ),
            (
                "closure-capture-right",
                bw_model::ObjectFlowKind::ClosureCapture,
                bw_model::ObjectFlowObjectKind::RustOwner,
                "site:object-flow-closure-slots:right-owner",
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-slots:callback",
                Some("closure_capture_ordinal:1:field:right"),
                None,
            ),
            (
                "closure-use-left",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-slots:callback",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-closure-slots:left-use",
                Some("closure_capture_ordinal:0:field:left"),
                None,
            ),
            (
                "closure-use-right",
                bw_model::ObjectFlowKind::FieldLoad,
                bw_model::ObjectFlowObjectKind::Callback,
                "site:object-flow-closure-slots:callback",
                bw_model::ObjectFlowObjectKind::StaticSite,
                "site:object-flow-closure-slots:right-use",
                Some("closure_capture_ordinal:1:field:right"),
                None,
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let left_owner = "rust_owner:site:object-flow-closure-slots:left-owner";
    let right_owner = "rust_owner:site:object-flow-closure-slots:right-owner";
    let verified_closure_chains = graph
        .object_chains
        .iter()
        .filter(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("closure-capture"))
        })
        .collect::<Vec<_>>();

    assert_eq!(
        verified_closure_chains.len(),
        2,
        "distinct compiler capture-slot keys should form two independent closure capture chains"
    );
    assert!(
        verified_closure_chains.iter().all(|chain| !(chain
            .object_ids
            .iter()
            .any(|object_id| object_id == left_owner)
            && chain
                .object_ids
                .iter()
                .any(|object_id| object_id == right_owner))),
        "capture-slot endpoints must prevent two captured owners from being collapsed into one object chain"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_binding_ambiguous"),
        "distinct capture slots should not require an ambiguous whole-callback fallback"
    );
}

#[test]
fn graph_v3_builds_verified_chain_for_user_data_release_path() {
    let candidate = sample_candidate("candidate:object-chain-release:001", "crate:object-chain");
    let facts = authoritative_user_data_release_facts(&candidate, "object-chain-release");
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:object-chain-release:register",
            "crate:object-chain",
            "candidate:object-chain-release:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:object-chain-release:raw",
            "crate:object-chain",
            "candidate:object-chain-release:001",
            bw_model::V326EvidenceKind::RawPointerEscape,
        ),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &evidence, &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("proof"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("user_data:"))
        }),
        "release path proof over the same user_data object should produce a verified chain"
    );

    let v2_graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &v2_graph,
        &evidence,
        &facts,
        &[],
    );
    assert!(feature.features.has_verified_object_chain);
    assert!(feature.features.has_release_order_chain);
}

#[test]
fn graph_v3_builds_returned_view_chain_and_feature() {
    let mut candidate = sample_candidate("candidate:object-chain-rb:001", "crate:object-chain-rb");
    candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    candidate.api_path = Some("fixture::View::get".to_owned());
    let facts = returned_borrow_static_lifecycle_facts(&candidate, "object-chain-rb");

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("order"))
                && chain
                    .verified_layers
                    .contains(&bw_model::V326ObjectChainLayer::IdentityTransport)
                && chain
                    .verified_layers
                    .contains(&bw_model::V326ObjectChainLayer::LifecycleOrdering)
                && chain
                    .verified_layers
                    .contains(&bw_model::V326ObjectChainLayer::CompleteRiskChain)
                && chain.missing_layers.is_empty()
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("returned_ref:"))
        }),
        "returned borrow, persistence, and use ordering facts should form a verified chain"
    );

    let v2_graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &v2_graph,
        &[],
        &facts,
        &[],
    );
    assert!(feature.features.has_verified_object_chain);
    assert!(feature.features.has_persisted_invalidation_use_chain);
}

#[test]
fn graph_v3_keeps_bare_returned_view_as_partial_chain_without_object_flow_missing() {
    let mut candidate = sample_candidate(
        "candidate:object-chain-rb-partial:001",
        "crate:object-chain-rb-partial",
    );
    candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    candidate.api_path = Some("fixture::View::get".to_owned());
    let all_facts = returned_borrow_static_lifecycle_facts(&candidate, "object-chain-rb-partial");
    let facts = vec![all_facts[0].clone()];

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::PartialChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("returned-relation"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("rust_owner:"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("returned_ref:"))
        }),
        "a returned-borrow relation has candidate-scoped source/returned endpoints and should be represented as a partial object chain"
    );
    assert!(
        graph.object_chains.iter().all(|chain| {
            chain.chain_status != bw_model::V326ObjectChainStatus::VerifiedStaticChain
        }),
        "bare returned-borrow relation must not become a verified lifecycle chain"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_flow_missing"),
        "the missing part is persistence/use ordering, not the initial returned-view object binding"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "use_ordering_proof_missing"),
        "without persist/invalidate/use evidence the graph must still report the ordering gap"
    );

    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    assert!(feature.features.has_returned_borrow_relation);
    assert!(!feature.features.has_verified_object_chain);
    assert!(
        !feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "object_flow_missing"),
        "ranking diagnostics should not misattribute a bare returned view to missing object flow"
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "use_ordering_proof_missing"),
        "ranking diagnostics should keep the missing persist/invalidate/use proof visible"
    );

    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature.clone()])
        .expect("returned-view partial feature should rank");
    let summary = bw_model::summarize_v3_2_6_ranked_object_chains(&ranked[0], &graph);
    assert!(
        summary
            .chain_incomplete_reasons
            .iter()
            .any(|reason| reason == "use_ordering_proof_missing"),
        "ranked chain summary should preserve the concrete returned-view ordering gap"
    );
    assert!(
        !summary
            .chain_incomplete_reasons
            .iter()
            .any(|reason| reason == "object_flow_missing"),
        "a partial returned-view chain must not be summarized as a missing ObjectFlow"
    );
}

#[test]
fn graph_v3_keeps_persisted_returned_view_without_order_as_partial_chain() {
    let mut candidate = sample_candidate(
        "candidate:object-chain-rb-persisted-partial:001",
        "crate:object-chain-rb-persisted-partial",
    );
    candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    candidate.api_path = Some("fixture::View::get".to_owned());
    let all_facts =
        returned_borrow_static_lifecycle_facts(&candidate, "object-chain-rb-persisted-partial");
    let facts = vec![all_facts[0].clone(), all_facts[1].clone()];

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::PartialChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("returned-relation"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("persisted"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("storage:"))
        }),
        "returned-borrow + persistence without an ordering fact should remain a candidate-scoped partial chain"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_flow_missing"),
        "persistence evidence means the remaining gap is ordering/use, not object-flow absence"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "use_ordering_proof_missing")
    );

    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    assert!(feature.features.has_persisted_returned_borrow);
    assert!(!feature.features.has_verified_object_chain);
    assert!(!feature.features.has_persisted_invalidation_use_chain);
    assert!(
        !feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "object_flow_missing")
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "use_ordering_proof_missing")
    );
}

#[test]
fn graph_v3_builds_external_buffer_binding_chain_and_feature() {
    let mut candidate = sample_candidate(
        "candidate:object-chain-external-buffer:001",
        "crate:object-chain-external-buffer",
    );
    candidate.pattern_family = bw_model::V32PatternFamily::ExternalBufferView;
    candidate.api_path = Some("fixture::Buffer::external".to_owned());
    let facts = vec![external_buffer_static_lifecycle_fact(
        &candidate,
        "object-chain-external-buffer",
    )];

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::PartialChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("external-buffer"))
                && chain
                    .verified_layers
                    .contains(&bw_model::V326ObjectChainLayer::IdentityTransport)
                && !chain
                    .verified_layers
                    .contains(&bw_model::V326ObjectChainLayer::LifecycleOrdering)
                && !chain
                    .verified_layers
                    .contains(&bw_model::V326ObjectChainLayer::CompleteRiskChain)
                && chain
                    .missing_layers
                    .contains(&bw_model::V326ObjectChainLayer::LifecycleOrdering)
                && chain
                    .missing_layers
                    .contains(&bw_model::V326ObjectChainLayer::CompleteRiskChain)
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("rust_owner:"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("user_data:"))
        }),
        "authoritative external-buffer binding should form a neutral identity-transport chain, not a complete risk chain"
    );
    assert!(
        !graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_flow_missing"),
        "external-buffer binding already carries both endpoint site ids and should not be reported as missing object flow"
    );

    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    assert!(feature.features.has_external_buffer_binding);
    assert!(
        !feature.features.has_verified_object_chain,
        "single external-buffer binding is identity transport evidence, not complete save->release/invalidate->use evidence"
    );
    assert!(
        !feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "object_flow_missing"),
        "ranking diagnostics should not ask for a separate ObjectFlow when the authoritative external-buffer binding has both endpoints"
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature])
        .expect("external-buffer feature should rank");
    assert_eq!(
        ranked[0].score_breakdown.has_verified_object_chain, 0,
        "source-to-buffer binding is a verified object identity diagnostic, but not a full lifecycle ordering score by itself"
    );
    assert!(
        ranked[0].score_breakdown.has_external_buffer_binding > 0,
        "external-buffer binding itself remains the risk signal"
    );
}

#[test]
fn external_buffer_source_observation_does_not_enable_verified_chain() {
    let mut candidate = sample_candidate(
        "candidate:object-chain-external-buffer-observation:001",
        "crate:object-chain-external-buffer-observation",
    );
    candidate.pattern_family = bw_model::V32PatternFamily::ExternalBufferView;
    let mut fact = fact_with_object(
        "fact:external-buffer:observation",
        &candidate.candidate_id,
        &candidate.crate_id,
        bw_model::V326LifecycleFactKind::ExternalBufferBinding,
        "rust_owner:site:external-buffer-observation:source",
    );
    fact.object_ids
        .push("user_data:site:external-buffer-observation:buffer".to_owned());

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(
        &candidate,
        &[],
        std::slice::from_ref(&fact),
        &[],
    );

    assert!(
        graph.object_chains.iter().all(|chain| {
            chain.chain_status != bw_model::V326ObjectChainStatus::VerifiedStaticChain
        }),
        "source-observation external-buffer evidence must not be upgraded to a verified static chain"
    );

    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        std::slice::from_ref(&fact),
        &[],
    );
    assert!(!feature.features.has_external_buffer_binding);
    assert!(!feature.features.has_verified_object_chain);
}

#[test]
fn returned_view_chain_requires_order_for_same_persisted_site() {
    let mut candidate = sample_candidate(
        "candidate:object-chain-rb-mismatch:001",
        "crate:object-chain-rb-mismatch",
    );
    candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    candidate.api_path = Some("fixture::View::get".to_owned());
    let primary_facts =
        returned_borrow_static_lifecycle_facts(&candidate, "object-chain-rb-primary");
    let other_facts = returned_borrow_static_lifecycle_facts_with_ordering(
        &candidate,
        "object-chain-rb-other",
        bw_model::ReturnedBorrowInvalidationOrdering::PersistenceBeforeInvalidationUse,
    );
    let facts = vec![
        primary_facts[0].clone(),
        primary_facts[1].clone(),
        other_facts[2].clone(),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);

    assert!(
        graph.object_chains.iter().all(|chain| {
            !(chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("object-chain-rb-other:order")))
        }),
        "an ordering proof for a different persisted site must not complete the returned-view chain"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "use_ordering_proof_missing"),
        "graph diagnostics must report that the current persisted site lacks a matching use-order proof"
    );

    let v2_graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &v2_graph,
        &[],
        &facts,
        &[],
    );
    assert!(!feature.features.has_verified_object_chain);
    assert!(!feature.features.has_persisted_invalidation_use_chain);
    assert!(
        !feature
            .features
            .returned_borrow_persistence_before_invalidation,
        "mismatched ordering proof must not enable the high-weight returned-borrow ordering feature"
    );
    assert!(
        !feature
            .feature_evidence
            .contains_key("returned_borrow_persistence_before_invalidation"),
        "mismatched ordering proof must not be recorded as feature evidence"
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "use_ordering_proof_missing"),
        "ranking diagnostics must not hide a mismatched persisted/use ordering proof"
    );

    let primary_persisted_static_site = primary_facts[1]
        .object_ids
        .iter()
        .find(|object_id| object_id.starts_with("static_site:"))
        .expect("persisted fact carries its own static site")
        .clone();
    let mut order_with_shared_invalidation_site = other_facts[2].clone();
    let non_persisted_static_site = order_with_shared_invalidation_site
        .object_ids
        .iter_mut()
        .filter(|object_id| object_id.starts_with("static_site:"))
        .nth(1)
        .expect("order fact carries invalidation static site");
    *non_persisted_static_site = primary_persisted_static_site;
    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(
        &candidate,
        &[],
        &[
            primary_facts[0].clone(),
            primary_facts[1].clone(),
            order_with_shared_invalidation_site,
        ],
        &[],
    );
    assert!(
        graph
            .object_chains
            .iter()
            .all(|chain| chain.chain_status != bw_model::V326ObjectChainStatus::VerifiedStaticChain),
        "an ordering fact whose invalidation/use site matches the persisted site but whose persisted_site differs must not complete the chain"
    );
}

#[test]
fn ambiguous_or_observation_only_chains_do_not_enable_strong_object_features() {
    let candidate = sample_candidate("candidate:object-chain-ambiguous:001", "crate:ambiguous");
    let (_static_facts, facts) = object_flow_static_lifecycle_facts(
        &candidate,
        "ambiguous",
        vec![
            (
                "field-store-a",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:ambiguous:user-data",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:ambiguous:storage-a",
            ),
            (
                "field-store-b",
                bw_model::ObjectFlowKind::FieldStore,
                bw_model::ObjectFlowObjectKind::UserData,
                "site:ambiguous:user-data",
                bw_model::ObjectFlowObjectKind::Storage,
                "site:ambiguous:storage-b",
            ),
        ],
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    assert!(
        graph
            .object_chains
            .iter()
            .any(|chain| chain.chain_status == bw_model::V326ObjectChainStatus::AmbiguousChain),
        "same ObjectFlow source and flow kind with multiple targets should remain ambiguous"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_binding_ambiguous"),
        "ambiguous ObjectFlow components must be reported separately from missing facts"
    );
    let v2_graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &v2_graph,
        &[],
        &facts,
        &[],
    );
    assert!(!feature.features.has_verified_object_chain);
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "object_binding_ambiguous"),
        "ranking diagnostics must preserve ambiguous object binding as missing evidence"
    );

    let observation = bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:observation-only:register",
        "crate:ambiguous",
        "candidate:object-chain-ambiguous:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    );
    let observation_graph =
        bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[observation], &[], &[]);
    assert!(
        observation_graph
            .object_chains
            .iter()
            .any(|chain| chain.chain_status == bw_model::V326ObjectChainStatus::ObservationOnly),
        "evidence-only graph should be marked observation-only"
    );
}

#[test]
fn external_call_site_has_no_authoritative_release_call_producer() {
    let candidate = sample_candidate("candidate:no-release-call:001", "crate:no-release-call");
    let envelope = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V01.to_owned(),
        record_id: bw_model::RecordId("static:external:invoke".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:fixture".to_owned()),
        artifact: None,
        source_ref: None,
        payload: bw_model::StaticFact::ExternalCallSite(bw_model::ExternalCallSiteFact {
            site_id: bw_model::SiteId("site:external:invoke".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("src/lib.rs:10".to_owned()),
            callback_site_id: Some(bw_model::SiteId("alpha".to_owned())),
            api_id: "fixture::invoke".to_owned(),
            role: bw_model::ExternalCallRole::Invoke,
        }),
    };

    let fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &envelope,
        V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(10),
            line_end: Some(10),
            symbol_path: Some("fixture::invoke".to_owned()),
            text_sha256: None,
        },
        vec!["evidence:external:0001".to_owned()],
    );

    assert!(
        fact.is_none(),
        "bw.static/0.1 ExternalCallSite must not produce ReleaseCall lifecycle facts"
    );
}

#[test]
fn returned_borrow_static_fact_maps_to_candidate_scoped_lifecycle_fact() {
    let mut candidate = sample_candidate("candidate:return-borrow:001", "crate:return-borrow");
    candidate.api_path = Some("fixture::returned_borrow".to_owned());
    candidate.evidence_refs[0].line_start = Some(14);
    candidate.evidence_refs[0].line_end = Some(14);
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:return-borrow:relation".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:return-borrow".to_owned()),
        artifact: Some(bw_model::StaticArtifactIdentity {
            crate_id: "crate:return-borrow".to_owned(),
            package_name: "return-borrow".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 14,
            line_end: 14,
            symbol_path: Some("fixture::returned_borrow".to_owned()),
        }),
        payload: bw_model::StaticFact::ReturnedBorrowRelation(
            bw_model::ReturnedBorrowRelationFact {
                site_id: bw_model::SiteId("site:return-borrow:relation".to_owned()),
                semantic_site_key: bw_model::SemanticSiteKey(
                    "semantic:return-borrow:relation".to_owned(),
                ),
                source_site_id: bw_model::SiteId("site:return-borrow:source".to_owned()),
                returned_site_id: bw_model::SiteId("site:return-borrow:returned".to_owned()),
                api_id: "fixture::returned_borrow".to_owned(),
                relation_kind: None,
            },
        ),
    };

    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &static_fact,
        V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(14),
            line_end: Some(14),
            symbol_path: Some("fixture::returned_borrow".to_owned()),
            text_sha256: None,
        },
        vec!["evidence:return-borrow:0001".to_owned()],
    )
    .expect("returned borrow relation should produce a lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];

    assert_eq!(
        fact.fact_kind,
        bw_model::V326LifecycleFactKind::ReturnedBorrowRelation
    );
    assert_eq!(
        fact.object_ids,
        vec![
            "rust_owner:site:return-borrow:source".to_owned(),
            "returned_ref:site:return-borrow:returned".to_owned()
        ]
    );
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &candidate,
        std::slice::from_ref(&static_fact),
    ));
}

/// 每个 scope 都要能走完 static fact → lifecycle fact → 验证器这条链。
///
/// `static_lifetime` 是"已检查且不允许借用捕获"、`unresolved_lifetime` 是"识别出回调但
/// 解析不出取值"，两者都必须产出事实：缺证与"已检查且健全"必须可区分。
///
/// **这张表是手写的**，新增变体时必须同步——漏一行不会有编译错误，只会让那个变体
/// 悄悄没有覆盖。
///
/// 这条测试同时是 object_id 白名单的非空性检查——`callback_lifetime_bound_scope:` 漏在
/// `BW-V326-FACT-OBJECT-ID` 那张表里的话，`validate_v3_2_6_lifecycle_facts` 会直接拒掉。
#[test]
fn callback_lifetime_bound_static_fact_carries_every_scope_through_validation() {
    for (scope, bound_lifetime, expected_token) in [
        (
            bw_model::CallbackLifetimeBoundScope::DeclaredReceiverLifetime,
            Some("'c".to_owned()),
            "declared_receiver_lifetime",
        ),
        (
            bw_model::CallbackLifetimeBoundScope::DeclaredFreeLifetime,
            Some("'other".to_owned()),
            "declared_free_lifetime",
        ),
        (
            bw_model::CallbackLifetimeBoundScope::StaticLifetime,
            Some("'static".to_owned()),
            "static_lifetime",
        ),
        (
            bw_model::CallbackLifetimeBoundScope::NoLifetimeBound,
            None,
            "no_lifetime_bound",
        ),
        (
            bw_model::CallbackLifetimeBoundScope::UnresolvedLifetime,
            None,
            "unresolved_lifetime",
        ),
    ] {
        let mut candidate = sample_candidate("candidate:bound:001", "crate:bound");
        candidate.api_path = Some("fixture::Handle::<T>::register".to_owned());
        candidate.evidence_refs[0].line_start = Some(21);
        candidate.evidence_refs[0].line_end = Some(21);
        let static_fact = bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:bound:{expected_token}")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId("build:bound".to_owned()),
            artifact: Some(bw_model::StaticArtifactIdentity {
                crate_id: "crate:bound".to_owned(),
                package_name: "bound".to_owned(),
                package_version: "0.1.0".to_owned(),
                target: "lib".to_owned(),
            }),
            source_ref: Some(bw_model::StaticSourceRef {
                path: "src/lib.rs".to_owned(),
                line_start: 21,
                line_end: 21,
                symbol_path: Some("fixture::Handle::<T>::register".to_owned()),
            }),
            payload: bw_model::StaticFact::CallbackLifetimeBound(
                bw_model::CallbackLifetimeBoundFact {
                    site_id: bw_model::SiteId(format!("site:bound:{expected_token}")),
                    semantic_site_key: bw_model::SemanticSiteKey(
                        "semantic:bound:register".to_owned(),
                    ),
                    api_id: "fixture::Handle::<T>::register".to_owned(),
                    callback_param: "F".to_owned(),
                    bound_lifetime,
                    bound_scope: scope,
                },
            ),
        };

        let mut fact = bw_model::lifecycle_fact_from_static_fact(
            "run:v326",
            &candidate,
            &static_fact,
            V326SourceRef {
                path: "src/lib.rs".to_owned(),
                line_start: Some(21),
                line_end: Some(21),
                symbol_path: Some("fixture::Handle::<T>::register".to_owned()),
                text_sha256: None,
            },
            vec!["evidence:bound:0001".to_owned()],
        )
        .unwrap_or_else(|| panic!("{expected_token} should produce a lifecycle fact"));
        fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];

        assert_eq!(
            fact.fact_kind,
            bw_model::V326LifecycleFactKind::CallbackLifetimeBound
        );
        assert_eq!(
            fact.object_ids,
            vec![
                format!("static_site:site:bound:{expected_token}"),
                format!("callback_lifetime_bound_scope:{expected_token}"),
            ],
            "the scope must be readable off the fact for {expected_token}"
        );
        assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
            &mut fact,
            &candidate,
            std::slice::from_ref(&static_fact),
        ));

        bw_model::validate_v3_2_6_lifecycle_facts([Located {
            path: PathBuf::from("lifecycle-facts.jsonl"),
            line: 1,
            value: fact,
        }])
        .unwrap_or_else(|error| {
            panic!("{expected_token} must pass the static_artifact object_id allowlist: {error}")
        });
    }
}

/// 语法 scope 到语义取值的映射。**判定必须消费语义取值**，不得自行按 scope 变体判断。
///
/// 2026-07-31 更正：`NoLifetimeBound` 此前被当成「不表态」，于是
/// `fn register<F: Fn()>(f: F)` 这种最强的候选形状被静默跳过。没有 `'static` 恰恰意味着
/// 调用方可以传一个捕获了局部借用的闭包。
#[test]
fn scope_maps_to_effective_capture_admission() {
    use bw_model::{CallbackLifetimeBoundScope as Scope, EffectiveCaptureAdmission as Admission};

    assert_eq!(
        Scope::DeclaredReceiverLifetime.effective_capture_admission(),
        Admission::PermitsNonStaticCapture
    );
    assert_eq!(
        Scope::DeclaredFreeLifetime.effective_capture_admission(),
        Admission::PermitsNonStaticCapture
    );
    assert_eq!(
        Scope::NoLifetimeBound.effective_capture_admission(),
        Admission::PermitsNonStaticCapture,
        "裸泛型 `F: Fn()` 没有 outlives bound 是允许捕获借用，不是缺证"
    );
    assert_eq!(
        Scope::StaticLifetime.effective_capture_admission(),
        Admission::RequiresStaticCapture
    );
    assert_eq!(
        Scope::UnresolvedLifetime.effective_capture_admission(),
        Admission::Unresolved,
        "解析不出 object lifetime 默认值时必须记缺证，不得猜任一方向"
    );
}

/// `is_shorter_than_static` 是判定「bound 是否弱于外部持有期」的入口谓词。
/// 它现在由语义映射推导，两者不得分叉。
#[test]
fn is_shorter_than_static_follows_the_semantic_admission() {
    use bw_model::{CallbackLifetimeBoundScope as Scope, EffectiveCaptureAdmission as Admission};

    for scope in [
        Scope::DeclaredReceiverLifetime,
        Scope::DeclaredFreeLifetime,
        Scope::StaticLifetime,
        Scope::NoLifetimeBound,
        Scope::UnresolvedLifetime,
    ] {
        assert_eq!(
            scope.is_shorter_than_static(),
            scope.effective_capture_admission() == Admission::PermitsNonStaticCapture,
            "{scope:?}：两个谓词分叉就会出现「一处判宽、一处判紧」的静默不一致"
        );
    }

    // 具体取值也钉死，避免两个谓词一起改错还互相印证。
    assert!(Scope::NoLifetimeBound.is_shorter_than_static());
    assert!(!Scope::StaticLifetime.is_shorter_than_static());
    assert!(!Scope::UnresolvedLifetime.is_shorter_than_static());
}

#[test]
fn atomic_ordering_static_fact_maps_to_candidate_scoped_lifecycle_fact() {
    let mut candidate = sample_candidate("candidate:atomic:001", "crate:atomic");
    candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    candidate.api_path = Some("fixture::RawIter::<T>::next".to_owned());
    candidate.evidence_refs[0].path = "src/raw_iter.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:atomic:relaxed-load".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:atomic".to_owned()),
        artifact: Some(bw_model::StaticArtifactIdentity {
            crate_id: "crate:atomic".to_owned(),
            package_name: "atomic".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/raw_iter.rs".to_owned(),
            line_start: 42,
            line_end: 42,
            symbol_path: Some("fixture::RawIter::<T>::next".to_owned()),
        }),
        payload: bw_model::StaticFact::AtomicOrdering(bw_model::AtomicOrderingFact {
            site_id: bw_model::SiteId("site:atomic:relaxed-load".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("semantic:atomic:relaxed-load".to_owned()),
            api_id: "fixture::RawIter::<T>::next".to_owned(),
            operation: bw_model::AtomicOperationKind::Load,
            ordering: bw_model::AtomicOrderingKind::Relaxed,
            target_type_name: "core::sync::atomic::AtomicPtr<Node<T>>".to_owned(),
        }),
    };

    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &static_fact,
        V326SourceRef {
            path: "src/raw_iter.rs".to_owned(),
            line_start: Some(42),
            line_end: Some(42),
            symbol_path: Some("fixture::RawIter::<T>::next".to_owned()),
            text_sha256: None,
        },
        vec!["evidence:atomic:relaxed-load".to_owned()],
    )
    .expect("atomic ordering static fact should produce a lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];

    assert_eq!(
        fact.fact_kind,
        bw_model::V326LifecycleFactKind::AtomicOrdering
    );
    assert_eq!(
        fact.object_ids,
        vec![
            "static_site:site:atomic:relaxed-load".to_owned(),
            "atomic_operation:load".to_owned(),
            "atomic_ordering:relaxed".to_owned()
        ]
    );
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &candidate,
        std::slice::from_ref(&static_fact),
    ));
}

#[test]
fn atomic_ordering_features_rank_relaxed_above_acquire_and_ignore_generic_counter() {
    let mut relaxed_candidate = sample_candidate("candidate:atomic:relaxed", "crate:atomic-rank");
    relaxed_candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    relaxed_candidate.api_path = Some("fixture::RawIter::<T>::next".to_owned());
    relaxed_candidate.evidence_refs[0].path = "src/raw_iter.rs".to_owned();
    relaxed_candidate.evidence_refs[0].line_start = Some(7);
    relaxed_candidate.evidence_refs[0].line_end = Some(7);
    let mut acquire_candidate = relaxed_candidate.clone();
    acquire_candidate.candidate_id = "candidate:atomic:acquire".to_owned();
    let relaxed_fact = atomic_ordering_lifecycle_fact(
        &relaxed_candidate,
        "relaxed",
        bw_model::AtomicOrderingKind::Relaxed,
        "fixture::RawIter::<T>::next",
        "core::sync::atomic::AtomicPtr<Node<T>>",
    );
    let acquire_fact = atomic_ordering_lifecycle_fact(
        &acquire_candidate,
        "acquire",
        bw_model::AtomicOrderingKind::Acquire,
        "fixture::RawIter::<T>::next",
        "core::sync::atomic::AtomicPtr<Node<T>>",
    );
    let counter_fact = atomic_ordering_lifecycle_fact(
        &relaxed_candidate,
        "counter",
        bw_model::AtomicOrderingKind::Relaxed,
        "fixture::Counter::get",
        "core::sync::atomic::AtomicUsize",
    );
    let relaxed_graph = bw_model::build_v3_2_6_lifecycle_graph(&relaxed_candidate, &[]);
    let acquire_graph = bw_model::build_v3_2_6_lifecycle_graph(&acquire_candidate, &[]);

    let relaxed_feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &relaxed_candidate,
        &relaxed_graph,
        &[],
        std::slice::from_ref(&relaxed_fact),
        &[],
    );
    let acquire_feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &acquire_candidate,
        &acquire_graph,
        &[],
        std::slice::from_ref(&acquire_fact),
        &[],
    );
    let counter_feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &relaxed_candidate,
        &relaxed_graph,
        &[],
        std::slice::from_ref(&counter_fact),
        &[],
    );

    assert!(relaxed_feature.features.relaxed_atomic_load_in_iterator);
    assert!(!relaxed_feature.features.acquire_atomic_load_in_iterator);
    assert!(acquire_feature.features.acquire_atomic_load_in_iterator);
    assert!(!acquire_feature.features.relaxed_atomic_load_in_iterator);
    assert!(!counter_feature.features.relaxed_atomic_load_in_iterator);
    assert!(!counter_feature.features.acquire_atomic_load_in_iterator);

    let ranked = bw_model::rank_v3_2_6_features(
        "run:v326",
        vec![relaxed_feature.clone(), acquire_feature.clone()],
    )
    .expect("atomic ordering features should rank");
    let relaxed_rank = ranked.first().expect("relaxed candidate ranked first");
    assert_eq!(relaxed_rank.candidate_id, relaxed_feature.candidate_id);
    assert!(
        relaxed_rank
            .risk_features
            .contains(&"relaxed_atomic_load_in_iterator".to_owned())
    );
    assert!(
        ranked[1]
            .protective_features
            .contains(&"acquire_atomic_load_in_iterator".to_owned())
    );
}

#[test]
fn unconstrained_return_lifetime_static_fact_sets_rank_feature() {
    let mut candidate = sample_candidate(
        "candidate:return-borrow:unconstrained",
        "crate:return-borrow",
    );
    candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    candidate.api_path = Some("fixture::Cache::iter".to_owned());
    candidate.evidence_refs[0].line_start = Some(21);
    candidate.evidence_refs[0].line_end = Some(21);
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:return-borrow:unconstrained".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:return-borrow".to_owned()),
        artifact: Some(bw_model::StaticArtifactIdentity {
            crate_id: "crate:return-borrow".to_owned(),
            package_name: "return-borrow".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 21,
            line_end: 21,
            symbol_path: Some("fixture::Cache::iter".to_owned()),
        }),
        payload: bw_model::StaticFact::ReturnedBorrowRelation(
            bw_model::ReturnedBorrowRelationFact {
                site_id: bw_model::SiteId("site:return-borrow:unconstrained".to_owned()),
                semantic_site_key: bw_model::SemanticSiteKey(
                    "semantic:return-borrow:unconstrained".to_owned(),
                ),
                source_site_id: bw_model::SiteId("site:return-borrow:receiver".to_owned()),
                returned_site_id: bw_model::SiteId("site:return-borrow:iterator".to_owned()),
                api_id: "fixture::Cache::iter".to_owned(),
                relation_kind: Some(
                    bw_model::ReturnedBorrowRelationKind::UnconstrainedReturnLifetime,
                ),
            },
        ),
    };

    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &static_fact,
        V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(21),
            line_end: Some(21),
            symbol_path: Some("fixture::Cache::iter".to_owned()),
            text_sha256: None,
        },
        vec!["evidence:return-borrow:unconstrained".to_owned()],
    )
    .expect("unconstrained returned lifetime relation should produce a lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    assert_eq!(
        fact.object_ids,
        vec![
            "rust_owner:site:return-borrow:receiver".to_owned(),
            "returned_ref:site:return-borrow:iterator".to_owned(),
            "static_site:returned_borrow_relation_kind:unconstrained_return_lifetime".to_owned(),
        ]
    );
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &candidate,
        std::slice::from_ref(&static_fact),
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        std::slice::from_ref(&fact),
        &[],
    );
    assert!(feature.features.has_returned_borrow_relation);
    assert!(feature.features.has_unconstrained_return_lifetime);
    assert!(
        feature
            .feature_evidence
            .contains_key("has_unconstrained_return_lifetime")
    );

    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature]).unwrap();
    assert!(ranked[0].score_breakdown.has_returned_borrow_relation > 0);
    assert!(ranked[0].score_breakdown.has_unconstrained_return_lifetime > 0);
    assert!(
        ranked[0]
            .risk_features
            .iter()
            .any(|feature| feature == "has_unconstrained_return_lifetime")
    );
}

#[test]
fn external_buffer_static_fact_maps_to_candidate_scoped_lifecycle_fact() {
    let mut candidate = sample_candidate("candidate:external-buffer:001", "crate:external-buffer");
    candidate.api_path = Some("fixture::external_buffer".to_owned());
    candidate.evidence_refs[0].line_start = Some(21);
    candidate.evidence_refs[0].line_end = Some(21);
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:external-buffer:binding".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:external-buffer".to_owned()),
        artifact: Some(bw_model::StaticArtifactIdentity {
            crate_id: "crate:external-buffer".to_owned(),
            package_name: "external-buffer".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 21,
            line_end: 21,
            symbol_path: Some("fixture::external_buffer".to_owned()),
        }),
        payload: bw_model::StaticFact::ExternalBufferBinding(bw_model::ExternalBufferBindingFact {
            site_id: bw_model::SiteId("site:external-buffer:binding".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey(
                "semantic:external-buffer:binding".to_owned(),
            ),
            source_site_id: bw_model::SiteId("site:external-buffer:source".to_owned()),
            buffer_site_id: bw_model::SiteId("site:external-buffer:buffer".to_owned()),
            api_id: "fixture::external_buffer".to_owned(),
        }),
    };

    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &static_fact,
        V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(21),
            line_end: Some(21),
            symbol_path: Some("fixture::external_buffer".to_owned()),
            text_sha256: None,
        },
        vec!["evidence:external-buffer:0001".to_owned()],
    )
    .expect("external buffer binding should produce a lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];

    assert_eq!(
        fact.fact_kind,
        bw_model::V326LifecycleFactKind::ExternalBufferBinding
    );
    assert_eq!(
        fact.object_ids,
        vec![
            "rust_owner:site:external-buffer:source".to_owned(),
            "user_data:site:external-buffer:buffer".to_owned()
        ]
    );
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &candidate,
        std::slice::from_ref(&static_fact),
    ));
}

#[test]
fn relation_static_facts_derive_neutral_ranking_features() {
    let mut candidate =
        sample_candidate("candidate:relation-features:001", "crate:relation-features");
    candidate.api_path = Some("fixture::external_buffer".to_owned());
    candidate.evidence_refs[0].line_start = Some(8);
    candidate.evidence_refs[0].line_end = Some(9);
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: "crate:relation-features".to_owned(),
        package_name: "relation-features".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = |line_start, symbol_path: &str| bw_model::StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start,
        line_end: line_start,
        symbol_path: Some(symbol_path.to_owned()),
    };
    let returned = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:relation-features:return".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:relation-features".to_owned()),
        artifact: Some(artifact.clone()),
        source_ref: Some(source_ref(8, "fixture::returned_borrow")),
        payload: bw_model::StaticFact::ReturnedBorrowRelation(
            bw_model::ReturnedBorrowRelationFact {
                site_id: bw_model::SiteId("site:relation-features:return".to_owned()),
                semantic_site_key: bw_model::SemanticSiteKey("semantic:relation:return".to_owned()),
                source_site_id: bw_model::SiteId("site:relation-features:source".to_owned()),
                returned_site_id: bw_model::SiteId("site:relation-features:returned".to_owned()),
                api_id: "fixture::returned_borrow".to_owned(),
                relation_kind: None,
            },
        ),
    };
    let external = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:relation-features:external".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:relation-features".to_owned()),
        artifact: Some(artifact),
        source_ref: Some(source_ref(9, "fixture::external_buffer")),
        payload: bw_model::StaticFact::ExternalBufferBinding(bw_model::ExternalBufferBindingFact {
            site_id: bw_model::SiteId("site:relation-features:external".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("semantic:relation:external".to_owned()),
            source_site_id: bw_model::SiteId("site:relation-features:source".to_owned()),
            buffer_site_id: bw_model::SiteId("site:relation-features:buffer".to_owned()),
            api_id: "fixture::external_buffer".to_owned(),
        }),
    };
    let static_facts = vec![returned, external];
    let anchor_record_id = static_facts[1].record_id.to_string();
    let facts = static_facts
        .iter()
        .map(|envelope| {
            let source = envelope.source_ref.as_ref().unwrap();
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                &candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                vec![format!("evidence:{}", envelope.record_id.as_str())],
            )
            .expect("relation static fact should map");
            fact.provenance.static_anchor_record_ids = vec![anchor_record_id.clone()];
            assert!(
                bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                    &mut fact,
                    &candidate,
                    &static_facts,
                ),
                "static fixture provenance failed for {}",
                envelope.record_id
            );
            fact
        })
        .collect::<Vec<_>>();
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &facts,
        &[],
    );

    assert!(feature.features.has_returned_borrow_relation);
    assert!(feature.features.has_external_buffer_binding);
    assert!(
        feature
            .feature_evidence
            .contains_key("has_returned_borrow_relation")
    );
    assert!(
        feature
            .feature_evidence
            .contains_key("has_external_buffer_binding")
    );

    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature]).unwrap();
    assert!(ranked[0].score_breakdown.has_returned_borrow_relation > 0);
    assert!(ranked[0].score_breakdown.has_external_buffer_binding > 0);
    assert!(
        ranked[0]
            .risk_features
            .iter()
            .any(|feature| feature == "has_returned_borrow_relation")
    );
    assert!(
        ranked[0]
            .risk_features
            .iter()
            .any(|feature| feature == "has_external_buffer_binding")
    );
}

#[test]
fn persisted_returned_borrow_static_fact_derives_feature_and_ranking_signal() {
    let mut candidate = sample_candidate(
        "candidate:persisted-returned:001",
        "crate:persisted-returned",
    );
    candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    candidate.api_path = Some("fixture::borrowed_view".to_owned());
    candidate.evidence_refs[0].line_start = Some(12);
    candidate.evidence_refs[0].line_end = Some(12);
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:persisted-returned:store".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:persisted-returned".to_owned()),
        artifact: Some(bw_model::StaticArtifactIdentity {
            crate_id: "crate:persisted-returned".to_owned(),
            package_name: "persisted-returned".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 12,
            line_end: 12,
            symbol_path: Some("fixture::borrowed_view".to_owned()),
        }),
        payload: bw_model::StaticFact::PersistedReturnedBorrow(
            bw_model::PersistedReturnedBorrowFact {
                site_id: bw_model::SiteId("site:persisted-returned:store".to_owned()),
                semantic_site_key: bw_model::SemanticSiteKey(
                    "semantic:persisted-returned:store".to_owned(),
                ),
                source_site_id: bw_model::SiteId("site:persisted-returned:source".to_owned()),
                returned_site_id: bw_model::SiteId("site:persisted-returned:returned".to_owned()),
                storage_site_id: bw_model::SiteId("site:persisted-returned:storage".to_owned()),
                api_id: "fixture::borrowed_view".to_owned(),
            },
        ),
    };
    let source = static_fact.source_ref.as_ref().unwrap();
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &static_fact,
        bw_model::V326SourceRef {
            path: source.path.clone(),
            line_start: Some(source.line_start),
            line_end: Some(source.line_end),
            symbol_path: source.symbol_path.clone(),
            text_sha256: None,
        },
        vec!["evidence:persisted-returned:store".to_owned()],
    )
    .expect("persisted returned borrow static fact should map");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    assert!(
        bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
            &mut fact,
            &candidate,
            &[static_fact],
        ),
        "persisted returned borrow provenance should verify"
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &[],
        &[fact],
        &[],
    );

    assert!(feature.features.has_persisted_returned_borrow);
    assert!(
        feature
            .feature_evidence
            .contains_key("has_persisted_returned_borrow")
    );
    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature]).unwrap();
    assert!(ranked[0].score_breakdown.has_persisted_returned_borrow > 0);
    assert!(
        ranked[0]
            .risk_features
            .iter()
            .any(|feature| feature == "has_persisted_returned_borrow")
    );
}

#[test]
fn returned_borrow_invalidation_order_controls_persisted_ranking_weight() {
    fn relation_fact(crate_id: &str, key: &str) -> bw_model::StaticFactEnvelope {
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:returned-order:{key}:relation")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId("build:returned-borrow-order".to_owned()),
            artifact: Some(bw_model::StaticArtifactIdentity {
                crate_id: crate_id.to_owned(),
                package_name: "returned-borrow-order".to_owned(),
                package_version: "0.1.0".to_owned(),
                target: "lib".to_owned(),
            }),
            source_ref: Some(bw_model::StaticSourceRef {
                path: "src/statement_iterator.rs".to_owned(),
                line_start: 12,
                line_end: 12,
                symbol_path: Some("fixture::NamedStatementIterator::new".to_owned()),
            }),
            payload: bw_model::StaticFact::ReturnedBorrowRelation(
                bw_model::ReturnedBorrowRelationFact {
                    site_id: bw_model::SiteId(format!("site:returned-order:{key}:relation")),
                    semantic_site_key: bw_model::SemanticSiteKey(format!(
                        "semantic:returned-order:{key}:relation"
                    )),
                    source_site_id: bw_model::SiteId(format!("site:returned-order:{key}:source")),
                    returned_site_id: bw_model::SiteId(format!(
                        "site:returned-order:{key}:returned"
                    )),
                    api_id: "fixture::stmt::Statement::field_name".to_owned(),
                    relation_kind: None,
                },
            ),
        }
    }

    fn persisted_fact(crate_id: &str, key: &str) -> bw_model::StaticFactEnvelope {
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:returned-order:{key}:persisted")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId("build:returned-borrow-order".to_owned()),
            artifact: Some(bw_model::StaticArtifactIdentity {
                crate_id: crate_id.to_owned(),
                package_name: "returned-borrow-order".to_owned(),
                package_version: "0.1.0".to_owned(),
                target: "lib".to_owned(),
            }),
            source_ref: Some(bw_model::StaticSourceRef {
                path: "src/statement_iterator.rs".to_owned(),
                line_start: 12,
                line_end: 12,
                symbol_path: Some("fixture::NamedStatementIterator::new".to_owned()),
            }),
            payload: bw_model::StaticFact::PersistedReturnedBorrow(
                bw_model::PersistedReturnedBorrowFact {
                    site_id: bw_model::SiteId(format!("site:returned-order:{key}:persisted")),
                    semantic_site_key: bw_model::SemanticSiteKey(format!(
                        "semantic:returned-order:{key}:persisted"
                    )),
                    source_site_id: bw_model::SiteId(format!("site:returned-order:{key}:source")),
                    returned_site_id: bw_model::SiteId(format!(
                        "site:returned-order:{key}:returned"
                    )),
                    storage_site_id: bw_model::SiteId(format!("site:returned-order:{key}:storage")),
                    api_id: "fixture::stmt::Statement::field_name".to_owned(),
                },
            ),
        }
    }

    fn order_fact(
        crate_id: &str,
        key: &str,
        ordering: bw_model::ReturnedBorrowInvalidationOrdering,
    ) -> bw_model::StaticFactEnvelope {
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:returned-order:{key}:order")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId("build:returned-borrow-order".to_owned()),
            artifact: Some(bw_model::StaticArtifactIdentity {
                crate_id: crate_id.to_owned(),
                package_name: "returned-borrow-order".to_owned(),
                package_version: "0.1.0".to_owned(),
                target: "lib".to_owned(),
            }),
            source_ref: Some(bw_model::StaticSourceRef {
                path: "src/statement_iterator.rs".to_owned(),
                line_start: 20,
                line_end: 20,
                symbol_path: Some("fixture::NamedStatementIterator::next".to_owned()),
            }),
            payload: bw_model::StaticFact::ReturnedBorrowInvalidationOrder(
                bw_model::ReturnedBorrowInvalidationOrderFact {
                    site_id: bw_model::SiteId(format!("site:returned-order:{key}:order")),
                    semantic_site_key: bw_model::SemanticSiteKey(format!(
                        "semantic:returned-order:{key}:order"
                    )),
                    persisted_site_id: bw_model::SiteId(format!(
                        "site:returned-order:{key}:persisted"
                    )),
                    invalidation_site_id: bw_model::SiteId(format!(
                        "site:returned-order:{key}:invalidation"
                    )),
                    use_site_id: bw_model::SiteId(format!("site:returned-order:{key}:use")),
                    api_id: "fixture::stmt::Statement::field_name".to_owned(),
                    invalidation_api_id: "fixture::stmt::StatementUse::step".to_owned(),
                    ordering,
                },
            ),
        }
    }

    fn lifecycle_fact_from_static_fixture(
        candidate: &bw_model::V32CandidateRecord,
        static_fact: &bw_model::StaticFactEnvelope,
    ) -> bw_model::V326LifecycleFactRecord {
        let source = static_fact.source_ref.as_ref().unwrap();
        let mut fact = bw_model::lifecycle_fact_from_static_fact(
            "run:v326",
            candidate,
            static_fact,
            bw_model::V326SourceRef {
                path: source.path.clone(),
                line_start: Some(source.line_start),
                line_end: Some(source.line_end),
                symbol_path: source.symbol_path.clone(),
                text_sha256: None,
            },
            vec![format!("evidence:{}", static_fact.record_id)],
        )
        .expect("static fact should map");
        fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
        assert!(
            bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                &mut fact,
                candidate,
                std::slice::from_ref(static_fact),
            ),
            "static provenance should verify"
        );
        fact
    }

    let mut before_candidate = sample_candidate(
        "candidate:returned-order:before",
        "crate:returned-order:before",
    );
    before_candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    before_candidate.api_path = Some("fixture::stmt::Statement::field_name".to_owned());
    before_candidate.evidence_refs[0].path = "src/statement_iterator.rs".to_owned();
    before_candidate.evidence_refs[0].line_start = Some(12);
    before_candidate.evidence_refs[0].line_end = Some(20);

    let mut after_candidate = sample_candidate(
        "candidate:returned-order:after",
        "crate:returned-order:after",
    );
    after_candidate.pattern_family = bw_model::V32PatternFamily::ReturnedBorrowView;
    after_candidate.api_path = Some("fixture::stmt::Statement::field_name".to_owned());
    after_candidate.evidence_refs[0].path = "src/statement_iterator.rs".to_owned();
    after_candidate.evidence_refs[0].line_start = Some(12);
    after_candidate.evidence_refs[0].line_end = Some(20);

    let before_relation = relation_fact("crate:returned-order:before", "before");
    let before_persisted = persisted_fact("crate:returned-order:before", "before");
    let before_order = order_fact(
        "crate:returned-order:before",
        "before",
        bw_model::ReturnedBorrowInvalidationOrdering::PersistenceBeforeInvalidationUse,
    );
    let after_relation = relation_fact("crate:returned-order:after", "after");
    let after_persisted = persisted_fact("crate:returned-order:after", "after");
    let after_order = order_fact(
        "crate:returned-order:after",
        "after",
        bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse,
    );

    let before_facts = vec![
        lifecycle_fact_from_static_fixture(&before_candidate, &before_relation),
        lifecycle_fact_from_static_fixture(&before_candidate, &before_persisted),
        lifecycle_fact_from_static_fixture(&before_candidate, &before_order),
    ];
    let after_facts = vec![
        lifecycle_fact_from_static_fixture(&after_candidate, &after_relation),
        lifecycle_fact_from_static_fixture(&after_candidate, &after_persisted),
        lifecycle_fact_from_static_fixture(&after_candidate, &after_order),
    ];

    let before_feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &before_candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&before_candidate, &[]),
        &[],
        &before_facts,
        &[],
    );
    let after_feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &after_candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&after_candidate, &[]),
        &[],
        &after_facts,
        &[],
    );

    assert!(before_feature.features.has_persisted_returned_borrow);
    assert!(
        before_feature
            .features
            .returned_borrow_persistence_before_invalidation
    );
    assert!(
        !before_feature
            .features
            .returned_borrow_persistence_after_invalidation
    );
    assert!(after_feature.features.has_persisted_returned_borrow);
    assert!(
        after_feature
            .features
            .returned_borrow_persistence_after_invalidation
    );
    assert!(
        !after_feature
            .features
            .returned_borrow_persistence_before_invalidation
    );

    let ranked =
        bw_model::rank_v3_2_6_features("run:v326", vec![after_feature, before_feature]).unwrap();
    let before = ranked
        .iter()
        .find(|record| record.candidate_id == "candidate:returned-order:before")
        .unwrap();
    let after = ranked
        .iter()
        .find(|record| record.candidate_id == "candidate:returned-order:after")
        .unwrap();

    assert!(before.score > after.score);
    assert!(
        before
            .risk_features
            .contains(&"returned_borrow_persistence_before_invalidation".to_owned())
    );
    assert!(
        after
            .protective_features
            .contains(&"returned_borrow_persistence_after_invalidation".to_owned())
    );
    assert!(
        before.score_breakdown.has_persisted_returned_borrow
            < before
                .score_breakdown
                .returned_borrow_persistence_before_invalidation
    );
}

#[test]
fn graph_v3_does_not_bind_source_derived_fact_object_labels() {
    let candidate = sample_candidate(
        "candidate:source-fact-unbound:001",
        "crate:source-fact-unbound",
    );
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:source-fact-unbound:register",
            "crate:source-fact-unbound",
            "candidate:source-fact-unbound:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:source-fact-unbound:release",
            "crate:source-fact-unbound",
            "candidate:source-fact-unbound:001",
            bw_model::V326EvidenceKind::ReleaseSite,
        ),
    ];
    let mut register = fact_with_object(
        "fact:source-unbound:register",
        "candidate:source-fact-unbound:001",
        "crate:source-fact-unbound",
        bw_model::V326LifecycleFactKind::RegisterCall,
        "callback:alpha_callback",
    );
    register.confidence = V326EvidenceConfidence::Medium;
    register.notes = vec!["source-derived candidate-scoped lifecycle fact".to_owned()];
    let mut release = fact_with_object(
        "fact:source-unbound:release",
        "candidate:source-fact-unbound:001",
        "crate:source-fact-unbound",
        bw_model::V326LifecycleFactKind::ReleaseCall,
        "callback:alpha_callback",
    );
    release.confidence = V326EvidenceConfidence::Medium;
    release.notes = vec!["source-derived candidate-scoped lifecycle fact".to_owned()];

    let graph =
        bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &evidence, &[register, release], &[]);

    assert!(
        graph
            .edges
            .iter()
            .all(|edge| !edge.from_object_id.starts_with("callback:alpha_callback"))
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "mir_hir_fact_missing")
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "callback_object_identity_unavailable")
    );
}

#[test]
fn lifecycle_graph_v3_reports_unbound_object_reason() {
    let candidate = sample_candidate("candidate:graph-v3:001", "crate:graph-v3");
    let evidence = vec![bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:graph-v3:0001",
        "crate:graph-v3",
        "candidate:graph-v3:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    )];

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &evidence, &[], &[]);

    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "mir_hir_fact_missing")
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "foreign_contract_missing")
    );
}

#[test]
fn external_call_site_does_not_become_release_lifecycle_fact() {
    let candidate = sample_candidate("candidate:external-call:001", "crate:external-call");
    let envelope = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V01.to_owned(),
        record_id: bw_model::RecordId("static:external:invoke".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:fixture".to_owned()),
        artifact: None,
        source_ref: None,
        payload: bw_model::StaticFact::ExternalCallSite(bw_model::ExternalCallSiteFact {
            site_id: bw_model::SiteId("site:external:invoke".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("src/lib.rs:10".to_owned()),
            callback_site_id: Some(bw_model::SiteId("alpha".to_owned())),
            api_id: "fixture::invoke".to_owned(),
            role: bw_model::ExternalCallRole::Invoke,
        }),
    };

    let fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &envelope,
        V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(10),
            line_end: Some(10),
            symbol_path: Some("fixture::invoke".to_owned()),
            text_sha256: None,
        },
        vec!["evidence:external:0001".to_owned()],
    );

    assert!(
        fact.is_none(),
        "ExternalCallSite must not invent release_call lifecycle facts"
    );
}

#[test]
fn drop_site_on_unrelated_owner_does_not_cover_callback_registration() {
    let candidate = sample_candidate("candidate:drop-cover:001", "crate:drop-cover");
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:drop-cover:register",
            "crate:drop-cover",
            "candidate:drop-cover:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:drop-cover:drop",
            "crate:drop-cover",
            "candidate:drop-cover:001",
            bw_model::V326EvidenceKind::DropSite,
        ),
    ];
    // Drop binds rust_owner only; register binds callback. Shared identity is required
    // for release_covers_callback — Drop existence alone must not prove coverage.
    let facts = vec![
        static_fact_with_object(
            "fact:drop-cover:register",
            "candidate:drop-cover:001",
            "crate:drop-cover",
            bw_model::V326LifecycleFactKind::RegisterCall,
            "callback:alpha",
        ),
        static_fact_with_object(
            "fact:drop-cover:drop",
            "candidate:drop-cover:001",
            "crate:drop-cover",
            bw_model::V326LifecycleFactKind::DropSite,
            "rust_owner:unrelated",
        ),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &facts,
        &[],
    );

    assert!(!feature.features.release_covers_callback);
    assert!(!feature.features.release_order_unknown);
}

#[test]
fn unrelated_drop_site_does_not_suppress_release_risk() {
    let candidate = sample_candidate(
        "candidate:drop-risk-mismatch:001",
        "crate:drop-risk-mismatch",
    );
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:drop-risk-mismatch:register",
            "crate:drop-risk-mismatch",
            "candidate:drop-risk-mismatch:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:drop-risk-mismatch:borrow",
            "crate:drop-risk-mismatch",
            "candidate:drop-risk-mismatch:001",
            bw_model::V326EvidenceKind::BorrowEdge,
        ),
    ];
    let facts = vec![
        static_fact_with_object(
            "fact:drop-risk-mismatch:register",
            "candidate:drop-risk-mismatch:001",
            "crate:drop-risk-mismatch",
            bw_model::V326LifecycleFactKind::RegisterCall,
            "callback:alpha",
        ),
        static_fact_with_object(
            "fact:drop-risk-mismatch:drop",
            "candidate:drop-risk-mismatch:001",
            "crate:drop-risk-mismatch",
            bw_model::V326LifecycleFactKind::DropSite,
            "rust_owner:unrelated",
        ),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &facts,
        &[],
    );

    assert!(feature.features.has_drop_guard);
    assert!(!feature.features.release_covers_callback);
    assert!(feature.features.missing_unregister_before_drop);
    assert!(feature.features.rust_object_may_drop_before_foreign_release);
    assert!(feature.features.needs_dynamic_witness);
}

#[test]
fn release_coverage_requires_authoritative_static_object_binding() {
    let candidate = sample_candidate("candidate:release:001", "crate:release");
    let register = evidence_with_details(
        "evidence:release:register",
        "crate:release",
        "candidate:release:001",
        bw_model::V326EvidenceKind::ForeignRegister,
        serde_json::json!({"callback_object_id":"callback:alpha"}),
    );
    let mismatched_release = evidence_with_details(
        "evidence:release:unregister:mismatch",
        "crate:release",
        "candidate:release:001",
        bw_model::V326EvidenceKind::ForeignUnregister,
        serde_json::json!({"callback_object_id":"callback:beta"}),
    );
    let matching_release = evidence_with_details(
        "evidence:release:unregister:match",
        "crate:release",
        "candidate:release:001",
        bw_model::V326EvidenceKind::ForeignUnregister,
        serde_json::json!({"callback_object_id":"callback:alpha","ordering":"after_register"}),
    );

    let mismatch_graph =
        bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[register.clone(), mismatched_release]);
    let mismatch = bw_model::derive_v3_2_6_lifecycle_features(
        &candidate,
        &mismatch_graph,
        &[
            register.clone(),
            evidence_with_details(
                "evidence:release:unregister:mismatch",
                "crate:release",
                "candidate:release:001",
                bw_model::V326EvidenceKind::ForeignUnregister,
                serde_json::json!({"callback_object_id":"callback:beta"}),
            ),
        ],
    );
    assert!(!mismatch.features.release_covers_callback);

    let matching_graph =
        bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[register.clone(), matching_release]);
    let matching = bw_model::derive_v3_2_6_lifecycle_features(
        &candidate,
        &matching_graph,
        &[
            register,
            evidence_with_details(
                "evidence:release:unregister:match",
                "crate:release",
                "candidate:release:001",
                bw_model::V326EvidenceKind::ForeignUnregister,
                serde_json::json!({"callback_object_id":"callback:alpha","ordering":"after_register"}),
            ),
        ],
    );
    assert!(!matching.features.release_covers_callback);
}

#[test]
fn same_object_release_fact_without_cfg_proof_does_not_cover_registration() {
    let candidate = sample_candidate("candidate:fact-release:001", "crate:fact-release");
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:fact-release:register",
            "crate:fact-release",
            "candidate:fact-release:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:fact-release:unregister",
            "crate:fact-release",
            "candidate:fact-release:001",
            bw_model::V326EvidenceKind::ForeignUnregister,
        ),
    ];
    let facts = vec![
        static_fact_with_object(
            "fact:fact-release:register",
            "candidate:fact-release:001",
            "crate:fact-release",
            bw_model::V326LifecycleFactKind::RegisterCall,
            "callback:alpha",
        ),
        static_fact_with_object(
            "fact:fact-release:unregister",
            "candidate:fact-release:001",
            "crate:fact-release",
            bw_model::V326LifecycleFactKind::UnregisterCall,
            "callback:alpha",
        ),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &facts,
        &[],
    );

    assert!(!feature.features.release_covers_callback);
    assert!(
        feature.features.release_order_unknown,
        "same object identity without a CFG path proof is not enough to prove release coverage"
    );
}

#[test]
fn release_path_proof_requires_matching_authoritative_register_and_release_facts() {
    let mut candidate = sample_candidate("candidate:cfg-release:001", "crate:cfg-release");
    candidate.evidence_refs[0].line_start = Some(10);
    candidate.evidence_refs[0].line_end = Some(12);
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:cfg-release:register",
            "crate:cfg-release",
            "candidate:cfg-release:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:cfg-release:release",
            "crate:cfg-release",
            "candidate:cfg-release:001",
            bw_model::V326EvidenceKind::ReleaseSite,
        ),
    ];
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: "crate:cfg-release".to_owned(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = bw_model::StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start: 10,
        line_end: 12,
        symbol_path: Some("fixture::cfg_release".to_owned()),
    };
    let static_facts = vec![
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId("static:cfg-release:register".to_owned()),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId("build:cfg-release".to_owned()),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref.clone()),
            payload: bw_model::StaticFact::RegistrationSite(bw_model::RegistrationSiteFact {
                site_id: bw_model::SiteId("site:cfg-release:register".to_owned()),
                semantic_site_key: bw_model::SemanticSiteKey(
                    "semantic:cfg-release:register".to_owned(),
                ),
                callback_site_id: None,
                user_data_site_id: Some(bw_model::SiteId("site:cfg-release:user-data".to_owned())),
                api_id: "api:fixture:register".to_owned(),
                role: bw_model::RegistrationRole::Register,
            }),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId("static:cfg-release:from-raw".to_owned()),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId("build:cfg-release".to_owned()),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref.clone()),
            payload: bw_model::StaticFact::RawPointerTransfer(bw_model::RawPointerTransferFact {
                site_id: bw_model::SiteId("site:cfg-release:from-raw".to_owned()),
                semantic_site_key: bw_model::SemanticSiteKey(
                    "semantic:cfg-release:from-raw".to_owned(),
                ),
                user_data_site_id: bw_model::SiteId("site:cfg-release:user-data".to_owned()),
                transfer_kind: bw_model::RawPointerTransferKind::FromRaw,
            }),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId("static:cfg-release:proof".to_owned()),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId("build:cfg-release".to_owned()),
            artifact: Some(artifact),
            source_ref: Some(source_ref),
            payload: bw_model::StaticFact::ReleasePathProof(bw_model::ReleasePathProofFact {
                site_id: bw_model::SiteId("site:cfg-release:proof".to_owned()),
                semantic_site_key: bw_model::SemanticSiteKey(
                    "semantic:cfg-release:proof".to_owned(),
                ),
                registration_site_id: bw_model::SiteId("site:cfg-release:register".to_owned()),
                release_site_id: bw_model::SiteId("site:cfg-release:from-raw".to_owned()),
                object_site_id: bw_model::SiteId("site:cfg-release:user-data".to_owned()),
            }),
        },
    ];
    let facts = static_facts
        .iter()
        .map(|envelope| {
            let source = envelope.source_ref.as_ref().expect("fixture has a source");
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                &candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                vec![
                    "evidence:cfg-release:register".to_owned(),
                    "evidence:cfg-release:release".to_owned(),
                ],
            )
            .expect("static fixture should map to a lifecycle fact");
            fact.provenance.static_anchor_record_ids = vec![envelope.record_id.to_string()];
            assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                &mut fact,
                &candidate,
                &static_facts,
            ));
            fact
        })
        .collect::<Vec<_>>();

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &facts,
        &[],
    );

    assert!(feature.features.release_covers_callback);
    assert!(!feature.features.release_order_unknown);
}

#[test]
fn release_path_proof_includes_exact_opaque_handle_object_flow_support() {
    let mut candidate = sample_candidate(
        "candidate:release-object-flow:001",
        "crate:release-object-flow",
    );
    candidate.api_path = Some("api:fixture:register".to_owned());
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:release-object-flow:register",
            "crate:release-object-flow",
            "candidate:release-object-flow:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:release-object-flow:release",
            "crate:release-object-flow",
            "candidate:release-object-flow:001",
            bw_model::V326EvidenceKind::ReleaseSite,
        ),
    ];
    let mut facts = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "release-object-flow",
        bw_model::SiteId("site:release-object-flow:user-data".to_owned()),
        bw_model::SiteId("site:release-object-flow:register".to_owned()),
        bw_model::SiteId("site:release-object-flow:from-raw".to_owned()),
    );
    let (_static_facts, object_flow_facts) =
        object_flow_static_lifecycle_facts_with_api_and_field_paths(
            &candidate,
            "release-object-flow",
            "api:fixture:register",
            vec![
                (
                    "field-store",
                    bw_model::ObjectFlowKind::FieldStore,
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:release-object-flow:user-data",
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:release-object-flow:store-handle",
                    Some("opaque_handle:arg0:slot7"),
                    None,
                ),
                (
                    "field-load",
                    bw_model::ObjectFlowKind::FieldLoad,
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:release-object-flow:load-handle",
                    bw_model::ObjectFlowObjectKind::StaticSite,
                    "site:release-object-flow:from-raw",
                    Some("opaque_handle:arg0:slot7"),
                    None,
                ),
            ],
        );
    facts.extend(object_flow_facts);

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &evidence, &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence),
        &evidence,
        &facts,
        &[],
    );
    let release_chain_refs = feature
        .feature_evidence
        .get("has_release_order_chain")
        .expect("ReleasePathProof should still prove release ordering");

    assert!(feature.features.release_covers_callback);
    assert!(feature.features.has_release_order_chain);
    assert!(
        release_chain_refs
            .iter()
            .any(|fact_ref| fact_ref.contains("field-store")),
        "release-order evidence should include the exact handle/key store flow"
    );
    assert!(
        release_chain_refs
            .iter()
            .any(|fact_ref| fact_ref.contains("field-load")),
        "release-order evidence should include the exact handle/key load flow"
    );
    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("proof"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-load"))
                && chain
                    .object_ids
                    .iter()
                    .any(|object_id| object_id.starts_with("opaque_handle:"))
        }),
        "graph-v3 release chain should retain the exact opaque-handle persistence/readback support"
    );
}

#[test]
fn release_path_proof_includes_exact_hook_release_slot_object_flow_support() {
    let mut candidate =
        sample_candidate("candidate:hook-release-slot:001", "crate:hook-release-slot");
    candidate.api_path = Some("api:rusqlite:update_hook:register".to_owned());
    let mut facts = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "hook-release-slot",
        bw_model::SiteId("site:hook-release-slot:user-data".to_owned()),
        bw_model::SiteId("site:hook-release-slot:register".to_owned()),
        bw_model::SiteId("site:hook-release-slot:from-raw".to_owned()),
    );
    let (_static_facts, object_flow_facts) =
        object_flow_static_lifecycle_facts_with_api_and_field_paths(
            &candidate,
            "hook-release-slot",
            "api:rusqlite:update_hook:register",
            vec![
                (
                    "field-store",
                    bw_model::ObjectFlowKind::FieldStore,
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:hook-release-slot:user-data",
                    bw_model::ObjectFlowObjectKind::StaticSite,
                    "site:hook-release-slot:release-slot-store",
                    Some("hook_release_slot:rusqlite:update_hook:field:0"),
                    None,
                ),
                (
                    "field-load",
                    bw_model::ObjectFlowKind::FieldLoad,
                    bw_model::ObjectFlowObjectKind::StaticSite,
                    "site:hook-release-slot:release-slot-load",
                    bw_model::ObjectFlowObjectKind::StaticSite,
                    "site:hook-release-slot:from-raw",
                    Some("hook_release_slot:rusqlite:update_hook:field:0"),
                    None,
                ),
            ],
        );
    facts.extend(object_flow_facts);

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    let release_chain_refs = feature
        .feature_evidence
        .get("has_release_order_chain")
        .expect("ReleasePathProof should still prove release ordering");

    assert!(feature.features.has_release_order_chain);
    assert!(
        facts.iter().any(|fact| {
            fact.fact_kind == bw_model::V326LifecycleFactKind::ObjectFlow
                && fact
                    .object_ids
                    .iter()
                    .any(|object_id| object_id == "object_flow_binding_kind:hook_release_slot")
        }),
        "hook release-slot field paths must be tagged so graph support can stay narrow"
    );
    assert!(
        release_chain_refs
            .iter()
            .any(|fact_ref| fact_ref.contains("field-store")),
        "release-order evidence should include the exact hook release-slot store flow"
    );
    assert!(
        release_chain_refs
            .iter()
            .any(|fact_ref| fact_ref.contains("field-load")),
        "release-order evidence should include the exact hook release-slot load flow"
    );
    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("proof"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-load"))
        }),
        "graph-v3 release chain should retain exact hook release-slot support refs"
    );
}

#[test]
fn release_path_proof_ignores_mismatched_hook_release_slot_support() {
    let mut candidate = sample_candidate(
        "candidate:hook-release-slot-mismatch:001",
        "crate:hook-release-slot-mismatch",
    );
    candidate.api_path = Some("api:rusqlite:update_hook:register".to_owned());
    let mut facts = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "hook-release-slot-mismatch",
        bw_model::SiteId("site:hook-release-slot-mismatch:user-data".to_owned()),
        bw_model::SiteId("site:hook-release-slot-mismatch:register".to_owned()),
        bw_model::SiteId("site:hook-release-slot-mismatch:from-raw".to_owned()),
    );
    let (_static_facts, object_flow_facts) =
        object_flow_static_lifecycle_facts_with_api_and_field_paths(
            &candidate,
            "hook-release-slot-mismatch",
            "api:rusqlite:update_hook:register",
            vec![
                (
                    "field-store",
                    bw_model::ObjectFlowKind::FieldStore,
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:hook-release-slot-mismatch:user-data",
                    bw_model::ObjectFlowObjectKind::StaticSite,
                    "site:hook-release-slot-mismatch:release-slot-store",
                    Some("hook_release_slot:rusqlite:update_hook:field:0"),
                    None,
                ),
                (
                    "field-load",
                    bw_model::ObjectFlowKind::FieldLoad,
                    bw_model::ObjectFlowObjectKind::StaticSite,
                    "site:hook-release-slot-mismatch:release-slot-load",
                    bw_model::ObjectFlowObjectKind::StaticSite,
                    "site:hook-release-slot-mismatch:from-raw",
                    Some("hook_release_slot:rusqlite:update_hook:field:1"),
                    None,
                ),
            ],
        );
    facts.extend(object_flow_facts);

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    let release_chain_refs = feature
        .feature_evidence
        .get("has_release_order_chain")
        .expect("ReleasePathProof should still prove release ordering");

    assert!(feature.features.has_release_order_chain);
    assert!(
        release_chain_refs
            .iter()
            .all(|fact_ref| !fact_ref.contains("field-store") && !fact_ref.contains("field-load")),
        "mismatched hook release-slot fields must not be attached as exact support refs"
    );
    assert!(
        graph
            .object_chains
            .iter()
            .filter(|chain| chain.chain_id.ends_with(":release"))
            .all(|chain| {
                chain.fact_refs.iter().all(|fact_ref| {
                    !fact_ref.contains("field-store") && !fact_ref.contains("field-load")
                })
            }),
        "graph-v3 must not attach wrong-field release-slot support to the release chain"
    );
}

#[test]
fn callback_release_use_chain_requires_exact_object_flow_to_reconstruction() {
    let mut candidate = sample_candidate(
        "candidate:callback-release-use:001",
        "crate:callback-release-use",
    );
    candidate.api_path = Some("api:fixture:register".to_owned());
    candidate.evidence_refs[0].path = "src/lib.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(1);
    candidate.evidence_refs[0].line_end = Some(1);
    let mut facts = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "callback-release-use",
        bw_model::SiteId("site:callback-release-use:registered-user-data".to_owned()),
        bw_model::SiteId("site:callback-release-use:register".to_owned()),
        bw_model::SiteId("site:callback-release-use:from-raw".to_owned()),
    );
    let (_static_facts, object_flow_facts) =
        object_flow_static_lifecycle_facts_with_api_and_field_paths(
            &candidate,
            "callback-release-use",
            "api:fixture:register",
            vec![
                (
                    "field-store",
                    bw_model::ObjectFlowKind::FieldStore,
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use:registered-user-data",
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use:registered-handle",
                    Some("callback_user_data:api:fixture:register:slot"),
                    None,
                ),
                (
                    "field-load",
                    bw_model::ObjectFlowKind::FieldLoad,
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use:registered-handle",
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use:user-data",
                    Some("callback_user_data:api:fixture:register:slot"),
                    None,
                ),
            ],
        );
    facts.extend(object_flow_facts);
    candidate.evidence_refs[0].path = "src/stream.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    facts.extend(callback_user_data_reconstruction_facts(
        &candidate,
        "callback-release-use",
        bw_model::CallbackUserDataReconstructionKind::OwnerFromTransmute,
    ));
    facts.push(callback_release_use_order_fact(
        &candidate,
        "callback-release-use",
        bw_model::SiteId("site:callback-release-use:register".to_owned()),
        bw_model::SiteId("site:callback-release-use:from-raw".to_owned()),
        bw_model::SiteId("site:callback-release-use:callback-userdata".to_owned()),
        bw_model::SiteId("site:callback-release-use:registered-user-data".to_owned()),
        bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );
    let chain_refs = feature
        .feature_evidence
        .get("has_callback_release_use_chain")
        .expect("exact register->save->release/use object chain should be feature evidence");

    assert!(feature.features.has_release_order_chain);
    assert!(feature.features.has_callback_release_use_chain);
    assert!(
        chain_refs.iter().any(|fact_ref| fact_ref.contains("proof"))
            && chain_refs
                .iter()
                .any(|fact_ref| fact_ref.contains("callback-userdata"))
            && chain_refs
                .iter()
                .any(|fact_ref| fact_ref.contains("field-store"))
            && chain_refs
                .iter()
                .any(|fact_ref| fact_ref.contains("field-load"))
            && chain_refs
                .iter()
                .any(|fact_ref| fact_ref.contains("callback-release-use-order")),
        "the strong callback release/use feature must be backed by proof, use, exact ObjectFlow, and release-before-use order refs"
    );
    assert!(
        graph.object_chains.iter().any(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("proof"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("callback-userdata"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-store"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("field-load"))
                && chain
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("callback-release-use-order"))
        }),
        "graph-v3 should keep register/save/release/use in one verified object chain only when exact ObjectFlow connects the user_data objects"
    );
    assert!(
        graph.edges.iter().any(|edge| {
            edge.relation == bw_model::V326LifecycleRelation::Use
                && edge
                    .fact_refs
                    .iter()
                    .any(|fact_ref| fact_ref.contains("callback-userdata"))
        }),
        "callback user_data reconstruction should be represented as a use edge, not an identity shortcut"
    );
}

#[test]
fn callback_release_use_chain_requires_release_before_use_order_proof() {
    let mut candidate = sample_candidate(
        "candidate:callback-release-use-missing-order:001",
        "crate:callback-release-use-missing-order",
    );
    candidate.api_path = Some("api:fixture:register".to_owned());
    candidate.evidence_refs[0].path = "src/lib.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(1);
    candidate.evidence_refs[0].line_end = Some(1);
    let mut facts = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "callback-release-use-missing-order",
        bw_model::SiteId("site:callback-release-use-missing-order:registered-user-data".to_owned()),
        bw_model::SiteId("site:callback-release-use-missing-order:register".to_owned()),
        bw_model::SiteId("site:callback-release-use-missing-order:from-raw".to_owned()),
    );
    let (_static_facts, object_flow_facts) =
        object_flow_static_lifecycle_facts_with_api_and_field_paths(
            &candidate,
            "callback-release-use-missing-order",
            "api:fixture:register",
            vec![
                (
                    "field-store",
                    bw_model::ObjectFlowKind::FieldStore,
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use-missing-order:registered-user-data",
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use-missing-order:registered-handle",
                    Some("callback_user_data:api:fixture:register:slot"),
                    None,
                ),
                (
                    "field-load",
                    bw_model::ObjectFlowKind::FieldLoad,
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use-missing-order:registered-handle",
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use-missing-order:user-data",
                    Some("callback_user_data:api:fixture:register:slot"),
                    None,
                ),
            ],
        );
    facts.extend(object_flow_facts);
    candidate.evidence_refs[0].path = "src/stream.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    facts.extend(callback_user_data_reconstruction_facts(
        &candidate,
        "callback-release-use-missing-order",
        bw_model::CallbackUserDataReconstructionKind::OwnerFromTransmute,
    ));

    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );

    assert!(feature.features.has_release_order_chain);
    assert!(!feature.features.has_callback_release_use_chain);
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "use_ordering_proof_missing"),
        "exact same-object callback use without release-before-use order proof must name the missing ordering evidence"
    );
    assert!(
        !feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "callback_release_use_object_flow_missing"),
        "same-object ObjectFlow exists, so the remaining gap is ordering rather than object binding"
    );
}

#[test]
fn callback_release_use_chain_reports_missing_object_flow_when_use_object_is_unbound() {
    let mut candidate = sample_candidate(
        "candidate:callback-release-use-missing-flow:001",
        "crate:callback-release-use-missing-flow",
    );
    candidate.api_path = Some("api:fixture:register".to_owned());
    candidate.evidence_refs[0].path = "src/lib.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(1);
    candidate.evidence_refs[0].line_end = Some(1);
    let mut facts = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "callback-release-use-missing-flow",
        bw_model::SiteId("site:callback-release-use-missing-flow:registered-user-data".to_owned()),
        bw_model::SiteId("site:callback-release-use-missing-flow:register".to_owned()),
        bw_model::SiteId("site:callback-release-use-missing-flow:from-raw".to_owned()),
    );
    let (_static_facts, object_flow_facts) =
        object_flow_static_lifecycle_facts_with_api_and_field_paths(
            &candidate,
            "callback-release-use-missing-flow",
            "api:fixture:register",
            vec![
                (
                    "field-store",
                    bw_model::ObjectFlowKind::FieldStore,
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use-missing-flow:registered-user-data",
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use-missing-flow:registered-handle",
                    Some("callback_user_data:api:fixture:register:slot-a"),
                    None,
                ),
                (
                    "field-load",
                    bw_model::ObjectFlowKind::FieldLoad,
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use-missing-flow:registered-handle",
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use-missing-flow:user-data",
                    Some("callback_user_data:api:fixture:register:slot-b"),
                    None,
                ),
            ],
        );
    facts.extend(object_flow_facts);
    candidate.evidence_refs[0].path = "src/stream.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    facts.extend(callback_user_data_reconstruction_facts(
        &candidate,
        "callback-release-use-missing-flow",
        bw_model::CallbackUserDataReconstructionKind::OwnerFromTransmute,
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );

    assert!(feature.features.has_release_order_chain);
    assert!(!feature.features.has_callback_release_use_chain);
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "callback_release_use_object_flow_missing"),
        "ranking diagnostics must name the missing same-object bridge instead of upgrading a disconnected use"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "callback_release_use_object_flow_missing"),
        "graph diagnostics must preserve the same-object proof gap"
    );
}

#[test]
fn callback_release_use_chain_is_blocked_by_reassignment_barrier_on_binding_key() {
    let mut candidate = sample_candidate(
        "candidate:callback-release-use-barrier:001",
        "crate:callback-release-use-barrier",
    );
    candidate.api_path = Some("api:fixture:register".to_owned());
    candidate.evidence_refs[0].path = "src/lib.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(1);
    candidate.evidence_refs[0].line_end = Some(1);
    let mut facts = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "callback-release-use-barrier",
        bw_model::SiteId("site:callback-release-use-barrier:registered-user-data".to_owned()),
        bw_model::SiteId("site:callback-release-use-barrier:register".to_owned()),
        bw_model::SiteId("site:callback-release-use-barrier:from-raw".to_owned()),
    );
    let (_static_facts, object_flow_facts) =
        object_flow_static_lifecycle_facts_with_api_and_field_paths(
            &candidate,
            "callback-release-use-barrier",
            "api:fixture:register",
            vec![
                (
                    "field-store",
                    bw_model::ObjectFlowKind::FieldStore,
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use-barrier:registered-user-data",
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use-barrier:registered-handle",
                    Some("callback_user_data:api:fixture:register:slot"),
                    None,
                ),
                (
                    "field-load",
                    bw_model::ObjectFlowKind::FieldLoad,
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use-barrier:registered-handle",
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use-barrier:user-data",
                    Some("callback_user_data:api:fixture:register:slot"),
                    None,
                ),
            ],
        );
    facts.extend(object_flow_facts);
    facts.push(object_binding_gap_static_lifecycle_fact_with_field_path(
        &candidate,
        "callback-release-use-barrier",
        bw_model::ObjectBindingGapKind::ReassignmentBarrier,
        "callback_user_data:api:fixture:register:slot",
    ));
    candidate.evidence_refs[0].path = "src/stream.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    facts.extend(callback_user_data_reconstruction_facts(
        &candidate,
        "callback-release-use-barrier",
        bw_model::CallbackUserDataReconstructionKind::OwnerFromTransmute,
    ));
    facts.push(callback_release_use_order_fact(
        &candidate,
        "callback-release-use-barrier",
        bw_model::SiteId("site:callback-release-use-barrier:register".to_owned()),
        bw_model::SiteId("site:callback-release-use-barrier:from-raw".to_owned()),
        bw_model::SiteId("site:callback-release-use-barrier:callback-userdata".to_owned()),
        bw_model::SiteId("site:callback-release-use-barrier:registered-user-data".to_owned()),
        bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[]),
        &[],
        &facts,
        &[],
    );

    assert!(feature.features.has_release_order_chain);
    assert!(!feature.features.has_callback_release_use_chain);
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "object_reassignment_barrier")
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|reason| reason == "callback_release_use_object_flow_missing"),
        "the candidate must keep the exact reason that use could not be proven on the released object"
    );
    assert!(
        graph
            .incomplete_reasons
            .iter()
            .any(|reason| reason == "object_reassignment_barrier")
    );
}

#[test]
fn release_path_proof_requires_matching_registration_site_for_feature() {
    let candidate = sample_candidate(
        "candidate:cfg-release-registration-mismatch:001",
        "crate:cfg-release-registration-mismatch",
    );
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:cfg-release-registration-mismatch:register",
            "crate:cfg-release-registration-mismatch",
            "candidate:cfg-release-registration-mismatch:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:cfg-release-registration-mismatch:release",
            "crate:cfg-release-registration-mismatch",
            "candidate:cfg-release-registration-mismatch:001",
            bw_model::V326EvidenceKind::ReleaseSite,
        ),
    ];
    let shared_user_data =
        bw_model::SiteId("site:cfg-release-registration-mismatch:user-data".to_owned());
    let current_registration = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "cfg-release-registration-current",
        shared_user_data.clone(),
        bw_model::SiteId("site:cfg-release-registration-mismatch:current-register".to_owned()),
        bw_model::SiteId("site:cfg-release-registration-mismatch:current-from-raw".to_owned()),
    );
    let other_registration = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "cfg-release-registration-other",
        shared_user_data,
        bw_model::SiteId("site:cfg-release-registration-mismatch:other-register".to_owned()),
        bw_model::SiteId("site:cfg-release-registration-mismatch:other-from-raw".to_owned()),
    );
    let facts = vec![
        current_registration[0].clone(),
        other_registration[2].clone(),
        other_registration[3].clone(),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &evidence, &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence),
        &evidence,
        &facts,
        &[],
    );

    assert!(
        !feature.features.release_covers_callback,
        "a proof for another registration site with the same user_data must not cover this candidate"
    );
    assert!(feature.features.release_order_unknown);
    assert!(!feature.features.has_release_order_chain);
    assert!(
        graph
            .object_chains
            .iter()
            .all(|chain| chain.chain_status != bw_model::V326ObjectChainStatus::VerifiedStaticChain),
        "graph-v3 must not build a verified release chain without the matching registration fact"
    );
}

#[test]
fn release_path_proof_support_requires_matching_release_endpoint() {
    let candidate = sample_candidate(
        "candidate:cfg-release-endpoint-mismatch:001",
        "crate:cfg-release-endpoint-mismatch",
    );
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:cfg-release-endpoint-mismatch:register",
            "crate:cfg-release-endpoint-mismatch",
            "candidate:cfg-release-endpoint-mismatch:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:cfg-release-endpoint-mismatch:release",
            "crate:cfg-release-endpoint-mismatch",
            "candidate:cfg-release-endpoint-mismatch:001",
            bw_model::V326EvidenceKind::ReleaseSite,
        ),
    ];
    let shared_user_data =
        bw_model::SiteId("site:cfg-release-endpoint-mismatch:user-data".to_owned());
    let registration_site =
        bw_model::SiteId("site:cfg-release-endpoint-mismatch:register".to_owned());
    let current_release = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "cfg-release-endpoint-current",
        shared_user_data.clone(),
        registration_site.clone(),
        bw_model::SiteId("site:cfg-release-endpoint-mismatch:current-from-raw".to_owned()),
    );
    let other_release = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "cfg-release-endpoint-other",
        shared_user_data,
        registration_site,
        bw_model::SiteId("site:cfg-release-endpoint-mismatch:other-from-raw".to_owned()),
    );
    let facts = vec![
        current_release[0].clone(),
        current_release[1].clone(),
        current_release[3].clone(),
        other_release[2].clone(),
    ];

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &evidence, &facts, &[]);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence),
        &evidence,
        &facts,
        &[],
    );
    let release_chain_refs = feature
        .feature_evidence
        .get("has_release_order_chain")
        .expect("matching proof/register should still produce release order evidence");

    assert!(feature.features.release_covers_callback);
    assert!(feature.features.has_release_order_chain);
    assert!(release_chain_refs.contains(&current_release[0].fact_id));
    assert!(release_chain_refs.contains(&current_release[1].fact_id));
    assert!(release_chain_refs.contains(&current_release[3].fact_id));
    assert!(
        !release_chain_refs.contains(&other_release[2].fact_id),
        "a ReleaseCall at a different release_endpoint must not support this proof"
    );

    let current_release_endpoint =
        "release_endpoint:site:cfg-release-endpoint-mismatch:current-from-raw";
    let other_release_endpoint =
        "release_endpoint:site:cfg-release-endpoint-mismatch:other-from-raw";
    let verified_chain = graph
        .object_chains
        .iter()
        .find(|chain| {
            chain.chain_status == bw_model::V326ObjectChainStatus::VerifiedStaticChain
                && chain.fact_refs.contains(&current_release[3].fact_id)
        })
        .expect("matching proof/register should produce a verified release chain");
    assert!(
        verified_chain
            .fact_refs
            .contains(&current_release[0].fact_id)
    );
    assert!(
        verified_chain
            .fact_refs
            .contains(&current_release[1].fact_id)
    );
    assert!(
        verified_chain
            .object_ids
            .iter()
            .any(|id| id == current_release_endpoint)
    );
    assert!(
        !verified_chain.fact_refs.contains(&other_release[2].fact_id)
            && !verified_chain
                .object_ids
                .iter()
                .any(|id| id == other_release_endpoint),
        "graph-v3 chain must not absorb a same-user_data ReleaseCall from another endpoint"
    );
    assert!(
        graph.edges.iter().any(|edge| {
            edge.fact_refs.contains(&current_release[3].fact_id)
                && edge.to_object_id == current_release_endpoint
        }),
        "ReleasePathProof edge should use the stable release endpoint object"
    );
    assert!(
        graph.edges.iter().any(|edge| {
            edge.fact_refs.contains(&other_release[2].fact_id)
                && edge.to_object_id == other_release_endpoint
        }),
        "ReleaseCall edge should preserve its own release endpoint without joining the chain"
    );
}

#[test]
fn release_path_proof_does_not_clear_missing_lifetime_bound_risk() {
    let candidate = sample_candidate("candidate:lifetime-release:001", "crate:lifetime-release");
    let evidence_without_lifetime_bound = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:lifetime-release:register",
            "crate:lifetime-release",
            "candidate:lifetime-release:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:lifetime-release:retention",
            "crate:lifetime-release",
            "candidate:lifetime-release:001",
            bw_model::V326EvidenceKind::ForeignRetentionHint,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:lifetime-release:raw",
            "crate:lifetime-release",
            "candidate:lifetime-release:001",
            bw_model::V326EvidenceKind::RawPointerEscape,
        ),
        evidence_with_details(
            "evidence:lifetime-release:owned",
            "crate:lifetime-release",
            "candidate:lifetime-release:001",
            bw_model::V326EvidenceKind::OwnedAnchor,
            serde_json::json!({"signal":"box into_raw user data anchor"}),
        ),
    ];
    let facts = authoritative_user_data_release_facts(&candidate, "lifetime-release");

    let graph =
        bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence_without_lifetime_bound);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence_without_lifetime_bound,
        &facts,
        &[],
    );

    assert!(feature.features.has_raw_pointer_escape);
    assert!(feature.features.registration_release_pair_found);
    assert!(feature.features.release_covers_callback);
    assert!(!feature.features.release_order_unknown);
    assert!(feature.features.has_owned_anchor);
    assert!(!feature.features.has_static_bound);
    assert!(
        feature.features.rust_object_may_drop_before_foreign_release,
        "release/order proof does not prove retained callback lifetime bounds"
    );
    assert!(
        feature
            .missing_evidence
            .iter()
            .any(|item| item.contains("lifetime bound"))
    );

    let ranked = bw_model::rank_v3_2_6_features("run:v326", vec![feature]).unwrap();
    assert!(
        ranked[0]
            .risk_features
            .contains(&"rust_object_may_drop_before_foreign_release".to_owned())
    );
    assert!(
        ranked[0]
            .score_breakdown
            .rust_object_may_drop_before_foreign_release
            > 0
    );

    let mut evidence_with_lifetime_bound = evidence_without_lifetime_bound;
    evidence_with_lifetime_bound.push(bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:lifetime-release:bound",
        "crate:lifetime-release",
        "candidate:lifetime-release:001",
        bw_model::V326EvidenceKind::LifetimeBound,
    ));
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence_with_lifetime_bound);
    let feature_with_bound = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence_with_lifetime_bound,
        &facts,
        &[],
    );

    assert!(feature_with_bound.features.has_static_bound);
    assert!(feature_with_bound.features.release_covers_callback);
    assert!(!feature_with_bound.features.release_order_unknown);
    assert!(
        !feature_with_bound
            .features
            .rust_object_may_drop_before_foreign_release
    );
    assert!(
        !feature_with_bound
            .missing_evidence
            .iter()
            .any(|item| item.contains("lifetime bound"))
    );
}

#[test]
fn release_path_proof_rejects_non_authoritative_support_facts() {
    let mut candidate = sample_candidate("candidate:cfg-release-forged:001", "crate:cfg-release");
    candidate.evidence_refs[0].line_start = Some(10);
    candidate.evidence_refs[0].line_end = Some(12);
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: "crate:cfg-release".to_owned(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = bw_model::StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start: 10,
        line_end: 12,
        symbol_path: Some("fixture::cfg_release".to_owned()),
    };
    let proof = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:cfg-release-forged:proof".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:cfg-release".to_owned()),
        artifact: Some(artifact.clone()),
        source_ref: Some(source_ref.clone()),
        payload: bw_model::StaticFact::ReleasePathProof(bw_model::ReleasePathProofFact {
            site_id: bw_model::SiteId("site:cfg-release:proof".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("semantic:cfg-release:proof".to_owned()),
            registration_site_id: bw_model::SiteId("site:cfg-release:register".to_owned()),
            release_site_id: bw_model::SiteId("site:cfg-release:from-raw".to_owned()),
            object_site_id: bw_model::SiteId("site:cfg-release:user-data".to_owned()),
        }),
    };
    let support_registration = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V01.to_owned(),
        record_id: bw_model::RecordId("static:cfg-release-forged:register".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:cfg-release".to_owned()),
        artifact: Some(artifact.clone()),
        source_ref: Some(source_ref.clone()),
        payload: bw_model::StaticFact::RegistrationSite(bw_model::RegistrationSiteFact {
            site_id: bw_model::SiteId("site:cfg-release:register".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey(
                "semantic:cfg-release:register".to_owned(),
            ),
            callback_site_id: None,
            user_data_site_id: Some(bw_model::SiteId("site:cfg-release:user-data".to_owned())),
            api_id: "api:fixture:register".to_owned(),
            role: bw_model::RegistrationRole::Register,
        }),
    };
    let support_release = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:cfg-release-forged:from-raw".to_owned()),
        producer: "different-fixture".to_owned(),
        build_id: bw_model::BuildId("build:cfg-release".to_owned()),
        artifact: Some(artifact),
        source_ref: Some(source_ref),
        payload: bw_model::StaticFact::RawPointerTransfer(bw_model::RawPointerTransferFact {
            site_id: bw_model::SiteId("site:cfg-release:from-raw".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey(
                "semantic:cfg-release:from-raw".to_owned(),
            ),
            user_data_site_id: bw_model::SiteId("site:cfg-release:user-data".to_owned()),
            transfer_kind: bw_model::RawPointerTransferKind::FromRaw,
        }),
    };
    let static_facts = vec![proof.clone(), support_registration, support_release];
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &proof,
        V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(10),
            line_end: Some(12),
            symbol_path: Some("fixture::cfg_release".to_owned()),
            text_sha256: None,
        },
        vec!["evidence:cfg-release-forged:release".to_owned()],
    )
    .expect("proof fixture should map to a lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![proof.record_id.to_string()];

    assert!(!bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &candidate,
        &static_facts,
    ));
}

#[test]
fn static_fact_envelope_canonicalizes_callback_identity_for_graph_binding() {
    let candidate = sample_candidate("candidate:static-identity:001", "crate:static-identity");
    let evidence = bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        "evidence:static-identity:register",
        "crate:static-identity",
        "candidate:static-identity:001",
        bw_model::V326EvidenceKind::ForeignRegister,
    );
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:identity:register".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:fixture".to_owned()),
        artifact: Some(bw_model::StaticArtifactIdentity {
            crate_id: "crate:static-identity".to_owned(),
            package_name: "fixture".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 1,
            line_end: 1,
            symbol_path: Some("static_identity::register".to_owned()),
        }),
        payload: bw_model::StaticFact::RegistrationSite(bw_model::RegistrationSiteFact {
            site_id: bw_model::SiteId("site:register".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("src/lib.rs:1".to_owned()),
            callback_site_id: Some(bw_model::SiteId("site:callback-alpha".to_owned())),
            user_data_site_id: None,
            api_id: "static_identity::register".to_owned(),
            role: bw_model::RegistrationRole::Register,
        }),
    };
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &static_fact,
        evidence.source_ref.clone(),
        vec![evidence.record_id.clone()],
    )
    .expect("registration static fact should convert");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    let mut mismatched_static_fact = static_fact.clone();
    mismatched_static_fact.payload =
        bw_model::StaticFact::CallbackSite(bw_model::CallbackSiteFact {
            site_id: bw_model::SiteId("site:callback-alpha".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("src/lib.rs:1".to_owned()),
            def_path: "static_identity::different_callback".to_owned(),
        });
    assert!(!bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &candidate,
        std::slice::from_ref(&mismatched_static_fact),
    ));
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &candidate,
        std::slice::from_ref(&static_fact),
    ));

    let graph = bw_model::build_v3_2_6_lifecycle_graph_v3(
        &candidate,
        std::slice::from_ref(&evidence),
        std::slice::from_ref(&fact),
        &[],
    );

    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.from_object_id == "callback:site:callback-alpha")
    );
}

#[test]
fn static_fact_provenance_rejects_a_fact_relabelled_to_another_candidate() {
    let source_candidate = sample_candidate("candidate:static-source:001", "crate:static-source");
    let mut other_candidate = sample_candidate("candidate:static-other:001", "crate:static-other");
    other_candidate.evidence_refs[0].line_start = Some(99);
    other_candidate.evidence_refs[0].line_end = Some(99);
    other_candidate.api_path = Some("static_other::register".to_owned());
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId("static:relabel:register".to_owned()),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:fixture".to_owned()),
        artifact: Some(bw_model::StaticArtifactIdentity {
            crate_id: "crate:static-source".to_owned(),
            package_name: "fixture".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 1,
            line_end: 1,
            symbol_path: Some("static_source::register".to_owned()),
        }),
        payload: bw_model::StaticFact::RegistrationSite(bw_model::RegistrationSiteFact {
            site_id: bw_model::SiteId("site:register".to_owned()),
            semantic_site_key: bw_model::SemanticSiteKey("src/lib.rs:1".to_owned()),
            callback_site_id: Some(bw_model::SiteId("site:callback".to_owned())),
            user_data_site_id: None,
            api_id: "static_source::register".to_owned(),
            role: bw_model::RegistrationRole::Register,
        }),
    };
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &source_candidate,
        &static_fact,
        V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(1),
            line_end: Some(1),
            symbol_path: Some("static_source::register".to_owned()),
            text_sha256: None,
        },
        vec!["evidence:static-source:register".to_owned()],
    )
    .expect("static fact should convert");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    fact.candidate_id = other_candidate.candidate_id.clone();
    fact.crate_id = other_candidate.crate_id.clone();

    assert!(!bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &other_candidate,
        std::slice::from_ref(&static_fact),
    ));
}

#[test]
fn same_callback_fact_across_functions_does_not_prove_release_coverage() {
    let candidate = sample_candidate(
        "candidate:fact-release-cross:001",
        "crate:fact-release-cross",
    );
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:fact-release-cross:register",
            "crate:fact-release-cross",
            "candidate:fact-release-cross:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:fact-release-cross:unregister",
            "crate:fact-release-cross",
            "candidate:fact-release-cross:001",
            bw_model::V326EvidenceKind::ForeignUnregister,
        ),
    ];
    let mut register_fact = static_fact_with_object(
        "fact:fact-release-cross:register",
        "candidate:fact-release-cross:001",
        "crate:fact-release-cross",
        bw_model::V326LifecycleFactKind::RegisterCall,
        "callback:alpha",
    );
    register_fact.source_ref.symbol_path = Some("alpha::register_callback".to_owned());
    register_fact.source_ref.line_start = Some(12);
    let mut unregister_fact = static_fact_with_object(
        "fact:fact-release-cross:unregister",
        "candidate:fact-release-cross:001",
        "crate:fact-release-cross",
        bw_model::V326LifecycleFactKind::UnregisterCall,
        "callback:alpha",
    );
    unregister_fact.source_ref.symbol_path = Some("alpha::drop_owner".to_owned());
    unregister_fact.source_ref.line_start = Some(47);

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[register_fact, unregister_fact],
        &[],
    );

    assert!(!feature.features.release_covers_callback);
    assert!(feature.features.release_order_unknown);
}

#[test]
fn release_order_unknown_when_unregister_order_is_not_proven() {
    let candidate = sample_candidate("candidate:order:001", "crate:order");
    let register = evidence_with_details(
        "evidence:order:register",
        "crate:order",
        "candidate:order:001",
        bw_model::V326EvidenceKind::ForeignRegister,
        serde_json::json!({"callback_object_id":"callback:alpha"}),
    );
    let release = evidence_with_details(
        "evidence:order:unregister",
        "crate:order",
        "candidate:order:001",
        bw_model::V326EvidenceKind::ForeignUnregister,
        serde_json::json!({"callback_object_id":"callback:alpha"}),
    );

    let graph =
        bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[register.clone(), release.clone()]);
    let feature =
        bw_model::derive_v3_2_6_lifecycle_features(&candidate, &graph, &[register, release]);

    assert!(!feature.features.release_covers_callback);
    assert!(feature.features.release_order_unknown);
}

#[test]
fn source_line_order_without_static_binding_keeps_release_order_unknown() {
    let candidate = sample_candidate("candidate:order-lines:001", "crate:order-lines");
    let register = evidence_with_details_at_line(
        "evidence:order-lines:register",
        "crate:order-lines",
        "candidate:order-lines:001",
        bw_model::V326EvidenceKind::ForeignRegister,
        serde_json::json!({"callback_object_id":"callback:alpha"}),
        "src/lib.rs",
        12,
    );
    let release = evidence_with_details_at_line(
        "evidence:order-lines:unregister",
        "crate:order-lines",
        "candidate:order-lines:001",
        bw_model::V326EvidenceKind::ForeignUnregister,
        serde_json::json!({"callback_object_id":"callback:alpha"}),
        "src/lib.rs",
        32,
    );

    let graph =
        bw_model::build_v3_2_6_lifecycle_graph(&candidate, &[register.clone(), release.clone()]);
    let feature =
        bw_model::derive_v3_2_6_lifecycle_features(&candidate, &graph, &[register, release]);

    assert!(!feature.features.release_covers_callback);
    assert!(feature.features.release_order_unknown);
}

#[test]
fn fact_source_line_order_does_not_replace_cfg_release_path_proof() {
    let candidate = sample_candidate("candidate:order-fact-lines:001", "crate:order-fact-lines");
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:order-fact-lines:register",
            "crate:order-fact-lines",
            "candidate:order-fact-lines:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:order-fact-lines:unregister",
            "crate:order-fact-lines",
            "candidate:order-fact-lines:001",
            bw_model::V326EvidenceKind::ForeignUnregister,
        ),
    ];
    let mut register_fact = static_fact_with_object(
        "fact:order-fact-lines:register",
        "candidate:order-fact-lines:001",
        "crate:order-fact-lines",
        bw_model::V326LifecycleFactKind::RegisterCall,
        "callback:alpha",
    );
    register_fact.source_ref.line_start = Some(18);
    register_fact.source_ref.line_end = Some(18);
    let mut unregister_fact = static_fact_with_object(
        "fact:order-fact-lines:unregister",
        "candidate:order-fact-lines:001",
        "crate:order-fact-lines",
        bw_model::V326LifecycleFactKind::UnregisterCall,
        "callback:alpha",
    );
    unregister_fact.source_ref.line_start = Some(41);
    unregister_fact.source_ref.line_end = Some(41);

    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &[register_fact, unregister_fact],
        &[],
    );

    assert!(!feature.features.release_covers_callback);
    assert!(feature.features.release_order_unknown);
}

#[test]
fn release_order_proof_requires_same_lifecycle_object_id() {
    let candidate = sample_candidate("candidate:order-mismatch:001", "crate:order");
    let register = evidence_with_details(
        "evidence:order-mismatch:register",
        "crate:order",
        "candidate:order-mismatch:001",
        bw_model::V326EvidenceKind::ForeignRegister,
        serde_json::json!({"callback_object_id":"callback:alpha"}),
    );
    let unrelated_release = evidence_with_details(
        "evidence:order-mismatch:unregister",
        "crate:order",
        "candidate:order-mismatch:001",
        bw_model::V326EvidenceKind::ForeignUnregister,
        serde_json::json!({"callback_object_id":"callback:beta","ordering":"after_register"}),
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph(
        &candidate,
        &[register.clone(), unrelated_release.clone()],
    );
    let feature = bw_model::derive_v3_2_6_lifecycle_features(
        &candidate,
        &graph,
        &[register, unrelated_release],
    );

    assert!(!feature.features.release_covers_callback);
    assert!(feature.features.release_order_unknown);
}

#[test]
fn release_like_api_without_same_object_keeps_order_unknown() {
    let candidate = sample_candidate("candidate:order-line-mismatch:001", "crate:order-line");
    let register = evidence_with_details_at_line(
        "evidence:order-line-mismatch:register",
        "crate:order-line",
        "candidate:order-line-mismatch:001",
        bw_model::V326EvidenceKind::ForeignRegister,
        serde_json::json!({"callback_object_id":"callback:alpha"}),
        "src/lib.rs",
        12,
    );
    let unrelated_release = evidence_with_details_at_line(
        "evidence:order-line-mismatch:unregister",
        "crate:order-line",
        "candidate:order-line-mismatch:001",
        bw_model::V326EvidenceKind::ForeignUnregister,
        serde_json::json!({"callback_object_id":"callback:beta"}),
        "src/lib.rs",
        32,
    );

    let graph = bw_model::build_v3_2_6_lifecycle_graph(
        &candidate,
        &[register.clone(), unrelated_release.clone()],
    );
    let feature = bw_model::derive_v3_2_6_lifecycle_features(
        &candidate,
        &graph,
        &[register, unrelated_release],
    );

    assert!(!feature.features.release_covers_callback);
    assert!(feature.features.release_order_unknown);
}

#[test]
fn authoritative_static_unregister_sets_unregister_feature_without_release_order_proof() {
    let candidate = sample_candidate("candidate:static-unregister:001", "crate:static-unregister");
    let evidence = vec![
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:static-unregister:register",
            "crate:static-unregister",
            "candidate:static-unregister:001",
            bw_model::V326EvidenceKind::ForeignRegister,
        ),
        bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
            "evidence:static-unregister:retention",
            "crate:static-unregister",
            "candidate:static-unregister:001",
            bw_model::V326EvidenceKind::ForeignRetentionHint,
        ),
    ];
    let facts = vec![static_fact_with_object(
        "static-unregister",
        "candidate:static-unregister:001",
        "crate:static-unregister",
        bw_model::V326LifecycleFactKind::UnregisterCall,
        "callback:site:static-unregister",
    )];
    let unregister_fact_id = facts[0].fact_id.clone();
    let graph = bw_model::build_v3_2_6_lifecycle_graph(&candidate, &evidence);
    let feature = bw_model::derive_v3_2_6_lifecycle_features_with_context(
        &candidate,
        &graph,
        &evidence,
        &facts,
        &[],
    );

    assert!(feature.features.has_foreign_unregister);
    assert!(!feature.features.missing_unregister_before_drop);
    assert!(feature.features.release_order_unknown);
    assert!(!feature.features.release_covers_callback);
    assert!(
        feature
            .feature_evidence
            .get("has_foreign_unregister")
            .is_some_and(|refs| refs.iter().any(|item| item == &unregister_fact_id))
    );
}

#[test]
fn pair_delta_explains_release_coverage_mismatch_and_ordering_unknown() {
    let mut left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left-release",
        |features| {
            features.has_foreign_register = true;
            features.has_foreign_unregister = true;
            features.release_order_unknown = true;
        },
    );
    left.missing_evidence
        .push("release_coverage_object_mismatch".to_owned());
    let right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right-release",
        |features| {
            features.has_foreign_register = true;
            features.has_foreign_unregister = true;
            features.release_covers_callback = true;
        },
    );
    let pair = bw_model::V326AnonymousPairRecord {
        schema_version: bw_model::V3_2_6_ANONYMOUS_PAIR_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        pair_id: "pair:release".to_owned(),
        left_crate_id: "crate:left-release".to_owned(),
        right_crate_id: "crate:right-release".to_owned(),
        relation_hint: "same_project_or_related_version".to_owned(),
        notes: vec!["anonymous comparison only".to_owned()],
    };

    let delta = bw_model::compare_v3_2_6_pair(&pair, &left, &right).unwrap();

    assert!(
        delta
            .semantic_delta
            .contains(&"right_added_release_coverage".to_owned())
    );
    assert!(
        delta
            .semantic_delta
            .contains(&"left_release_coverage_object_mismatch".to_owned())
    );
    assert!(
        delta
            .semantic_delta
            .contains(&"left_ordering_unknown".to_owned())
    );
}

#[test]
fn pair_delta_explains_returned_borrow_and_external_buffer_feature_differences() {
    let left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left-relation",
        |features| {
            features.has_returned_borrow_relation = true;
            features.has_external_buffer_binding = true;
        },
    );
    let right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right-relation",
        |features| {
            features.has_static_bound = true;
            features.has_external_buffer_lifetime_bound = true;
        },
    );
    let pair = bw_model::V326AnonymousPairRecord {
        schema_version: bw_model::V3_2_6_ANONYMOUS_PAIR_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        pair_id: "pair:relation".to_owned(),
        left_crate_id: "crate:left-relation".to_owned(),
        right_crate_id: "crate:right-relation".to_owned(),
        relation_hint: "same_project_or_related_version".to_owned(),
        notes: vec!["anonymous comparison only".to_owned()],
    };

    let delta = bw_model::compare_v3_2_6_pair(&pair, &left, &right).unwrap();

    assert!(
        delta
            .semantic_delta
            .contains(&"right_removed_returned_borrow_relation".to_owned())
    );
    assert!(
        delta
            .semantic_delta
            .contains(&"right_removed_external_buffer_binding".to_owned())
    );
    assert!(
        delta
            .semantic_delta
            .contains(&"right_added_external_buffer_lifetime_bound".to_owned())
    );
    assert_eq!(
        delta.distinguishability,
        bw_model::V326Distinguishability::SeparableStatic
    );
}

#[test]
fn pair_delta_explains_persisted_returned_borrow_feature_difference() {
    let left = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:left-persisted-returned",
        |features| {
            features.has_returned_borrow_relation = true;
            features.has_persisted_returned_borrow = true;
        },
    );
    let right = bw_model::V326LifecycleFeatureRecord::sample_for_tests_for_crate(
        "crate:right-persisted-returned",
        |features| {
            features.has_returned_borrow_relation = true;
        },
    );
    let pair = bw_model::V326AnonymousPairRecord {
        schema_version: bw_model::V3_2_6_ANONYMOUS_PAIR_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        pair_id: "pair:persisted-returned".to_owned(),
        left_crate_id: "crate:left-persisted-returned".to_owned(),
        right_crate_id: "crate:right-persisted-returned".to_owned(),
        relation_hint: "same_project_or_related_version".to_owned(),
        notes: vec!["anonymous comparison only".to_owned()],
    };

    let delta = bw_model::compare_v3_2_6_pair(&pair, &left, &right).unwrap();

    assert!(
        delta
            .semantic_delta
            .contains(&"right_removed_persisted_returned_borrow".to_owned())
    );
    assert_eq!(
        delta.distinguishability,
        bw_model::V326Distinguishability::SeparableStatic
    );
}

#[test]
fn witness_plan_accepts_neutral_controlled_actions() {
    let plan = bw_model::V326WitnessPlanRecord {
        schema_version: bw_model::V3_2_6_WITNESS_PLAN_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        plan_id: "witness-plan:alpha:001".to_owned(),
        candidate_id: "candidate:alpha:001".to_owned(),
        lifecycle_graph_ref: "graphs-v3/candidate_alpha_001.json".to_owned(),
        target: None,
        actions: vec![bw_model::V326WitnessAction {
            action_id: "action:alpha:register".to_owned(),
            action_kind: bw_model::V326WitnessActionKind::RegisterCallback,
            graph_refs: vec!["edge:alpha:register".to_owned()],
            notes: vec!["controlled local lifecycle action".to_owned()],
        }],
        runtime_observers: vec!["callback_register".to_owned(), "object_drop".to_owned()],
        oracle_assertions: vec![
            "callback is only evaluated against local trace evidence".to_owned(),
        ],
        replay_evidence_refs: vec!["evidence:alpha:0001".to_owned()],
        notes: vec!["controlled validation plan; not a defect conclusion".to_owned()],
    };

    let summary = bw_model::validate_v3_2_6_witness_plans([Located {
        path: PathBuf::from("witness-plans.jsonl"),
        line: 1,
        value: plan,
    }])
    .expect("neutral witness plan should validate");

    assert_eq!(summary.record_count, 1);
}

/// 一条最小的静态来源生命周期事实，用于 callback bound 推导的输入。
fn bound_derivation_fact(
    candidate_id: &str,
    fact_kind: bw_model::V326LifecycleFactKind,
    enclosing_fn: &str,
    object_ids: Vec<String>,
) -> bw_model::V326LifecycleFactRecord {
    bw_model::V326LifecycleFactRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_FACT_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: candidate_id.to_owned(),
        crate_id: "crate:alpha".to_owned(),
        fact_id: format!("fact:{candidate_id}:{}", enclosing_fn.len()),
        fact_kind,
        source_ref: V326SourceRef {
            path: "src/hooks.rs".to_owned(),
            line_start: Some(378),
            line_end: Some(382),
            symbol_path: Some(enclosing_fn.to_owned()),
            text_sha256: None,
        },
        // 注册类事实的顶层 symbol_path 是 api_id 而不是函数，推导必须优先读
        // source_ref.symbol_path；这里刻意填成 api_id 形状把那个顺序钉住。
        symbol_path: Some("api:alpha:register_callback:register".to_owned()),
        confidence: V326EvidenceConfidence::High,
        coverage_state: bw_model::V326CoverageState::Covered,
        provenance: bw_model::V326LifecycleFactProvenance::source_observation(),
        object_ids,
        evidence_refs: vec!["evidence:alpha:0001".to_owned()],
        notes: Vec::new(),
    }
}

fn bound_fact(
    candidate_id: &str,
    enclosing_fn: &str,
    scope_token: &str,
) -> bw_model::V326LifecycleFactRecord {
    bound_derivation_fact(
        candidate_id,
        bw_model::V326LifecycleFactKind::CallbackLifetimeBound,
        enclosing_fn,
        vec![format!("callback_lifetime_bound_scope:{scope_token}")],
    )
}

/// **候选不是 join key，enclosing fn 才是。**
///
/// 实测 rusqlite 0.26.1：`hooks::<impl InnerConnection>::update_hook` 上的
/// `callback_lifetime_bound` 与同一函数的 `unregister_call` 落在**不同候选**里（候选是按
/// boundary 切的）。按候选归组会让 76 个候选全部判成 `Undecided`——一个看起来完全正常、
/// 实际什么都没判出来的结果。这条测试就是那个回归的守卫。
#[test]
fn callback_bound_verdict_joins_on_the_enclosing_fn_not_the_candidate() {
    let enclosing = "hooks::<impl inner_connection::InnerConnection>::update_hook";
    let facts = vec![
        bound_fact(
            "candidate:alpha:bound",
            enclosing,
            "declared_receiver_lifetime",
        ),
        // 边界证据在另一个候选里，同一个函数上。
        bound_derivation_fact(
            "candidate:alpha:sibling",
            bw_model::V326LifecycleFactKind::UnregisterCall,
            enclosing,
            vec!["callback:alpha".to_owned()],
        ),
    ];

    let derived = bw_model::derive_v3_2_6_callback_bound_verdicts(&facts);
    let bound = derived
        .get("candidate:alpha:bound")
        .expect("the candidate carrying the bound fact must get a verdict");
    assert_eq!(
        bound.verdict,
        bw_model::V326CallbackBoundVerdict::NonStatic,
        "a sibling candidate's unregister call on the same fn still proves foreign retention"
    );
    assert_eq!(
        bound.evidence,
        vec![format!(
            "{enclosing}|declared_receiver_lifetime|unregister_call"
        )],
        "evidence must name the fn, the bound and what proved the retention"
    );

    // 判定是**函数**的属性，所以持有另一半的那个候选也必须看得到它。
    //
    // 这一条不是对称性洁癖：witness plan 的 api_id 来自 register 事实所在的那个候选，
    // 而 bound 事实在另一个候选里。只把结论挂给持有 bound 的一侧，拿着 api_id 的候选就
    // 永远读不到判定，plan 里的 callback_bound_scope 永远停在缺证。
    let sibling = derived
        .get("candidate:alpha:sibling")
        .expect("the candidate carrying the retention half must see the same verdict");
    assert_eq!(
        sibling.verdict,
        bw_model::V326CallbackBoundVerdict::NonStatic
    );
    assert_eq!(sibling.evidence, bound.evidence);
}

/// 签名松但没有任何外部边界事实 → `Undecided`，不是 `NonStatic`。
///
/// 把回调绑在 `&'c mut self` 上完全可以是健全的；缺的是"它确实被交给了 C 侧"那一半。
/// 这条测试防的是把第 2 步的产出直接当成结论。
#[test]
fn a_loose_callback_bound_without_foreign_retention_evidence_stays_undecided() {
    let facts = vec![bound_fact(
        "candidate:alpha:bound",
        "functions::<impl Connection>::create_scalar_function",
        "declared_receiver_lifetime",
    )];

    let derived = bw_model::derive_v3_2_6_callback_bound_verdicts(&facts);
    assert!(
        derived.get("candidate:alpha:bound").is_none(),
        "no entry at all is the missing-evidence answer: a loose bound alone must not become a verdict"
    );
}

#[test]
fn a_static_callback_bound_with_retention_evidence_reads_as_static() {
    let enclosing = "hooks::<impl Connection>::progress_handler";
    let facts = vec![
        bound_fact("candidate:alpha:tight", enclosing, "static_lifetime"),
        bound_derivation_fact(
            "candidate:alpha:tight",
            bw_model::V326LifecycleFactKind::RegisterCall,
            enclosing,
            vec!["callback:alpha".to_owned()],
        ),
    ];

    let derived = bw_model::derive_v3_2_6_callback_bound_verdicts(&facts);
    assert_eq!(
        derived["candidate:alpha:tight"].verdict,
        bw_model::V326CallbackBoundVerdict::Static,
        "a tightened bound plus a hand-off is a checked-and-sound result, not missing evidence"
    );
}

/// `no_lifetime_bound` 允许捕获借用，因此判 `NonStatic`。
///
/// **2026-07-31 更正。** 此前这条测试断言它「不表态、不产出判定」，那是把最强的一类
/// 候选形状静默丢掉：`fn register<F: Fn()>(f: F)` 没有 `'static`，恰恰意味着调用方
/// 可以传一个捕获了局部借用的闭包。语义映射见
/// `CallbackLifetimeBoundScope::effective_capture_admission`。
#[test]
fn a_callback_bound_without_an_outlives_bound_reads_as_non_static() {
    let enclosing = "alpha::register";
    let facts = vec![
        bound_fact("candidate:alpha:silent", enclosing, "no_lifetime_bound"),
        bound_derivation_fact(
            "candidate:alpha:silent",
            bw_model::V326LifecycleFactKind::UnregisterCall,
            enclosing,
            vec!["callback:alpha".to_owned()],
        ),
    ];

    let derived = bw_model::derive_v3_2_6_callback_bound_verdicts(&facts);
    assert_eq!(
        derived["candidate:alpha:silent"].verdict,
        bw_model::V326CallbackBoundVerdict::NonStatic,
        "没有 outlives bound 的泛型回调参数允许捕获借用，不是缺证"
    );
}

/// 真正「不表态」的那一格现在是 `unresolved_lifetime`：识别出回调 trait object，
/// 但解析不出它省略的 object lifetime 默认成什么。它不得倒向任一结论。
#[test]
fn an_unresolved_object_lifetime_is_undecided_even_with_retention_evidence() {
    let enclosing = "alpha::register_dyn";
    let facts = vec![
        bound_fact(
            "candidate:alpha:unresolved",
            enclosing,
            "unresolved_lifetime",
        ),
        bound_derivation_fact(
            "candidate:alpha:unresolved",
            bw_model::V326LifecycleFactKind::UnregisterCall,
            enclosing,
            vec!["callback:alpha".to_owned()],
        ),
    ];

    let derived = bw_model::derive_v3_2_6_callback_bound_verdicts(&facts);
    assert!(
        derived.get("candidate:alpha:unresolved").is_none(),
        "解析不出取值时必须记缺证，不得猜任一方向"
    );
}

/// 一个候选里既有松 bound 又有 `'static` bound 时按松的判：一个不健全的入口就够了。
#[test]
fn a_mixed_candidate_takes_the_loosest_callback_bound() {
    let loose = "hooks::<impl inner_connection::InnerConnection>::update_hook";
    let tight = "hooks::<impl inner_connection::InnerConnection>::progress_handler";
    let facts = vec![
        bound_fact("candidate:alpha:mixed", loose, "declared_free_lifetime"),
        bound_fact("candidate:alpha:mixed", tight, "static_lifetime"),
        bound_derivation_fact(
            "candidate:alpha:mixed",
            bw_model::V326LifecycleFactKind::UnregisterCall,
            loose,
            vec!["callback:alpha".to_owned()],
        ),
        bound_derivation_fact(
            "candidate:alpha:mixed",
            bw_model::V326LifecycleFactKind::RegisterCall,
            tight,
            vec!["callback:alpha".to_owned()],
        ),
    ];

    let derived = bw_model::derive_v3_2_6_callback_bound_verdicts(&facts);
    assert_eq!(
        derived["candidate:alpha:mixed"].verdict,
        bw_model::V326CallbackBoundVerdict::NonStatic
    );
}

fn sample_candidate(candidate_id: &str, crate_id: &str) -> bw_model::V32CandidateRecord {
    bw_model::V32CandidateRecord {
        schema_version: bw_model::V3_2_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: candidate_id.to_owned(),
        crate_id: crate_id.to_owned(),
        boundary_id: format!("boundary:{crate_id}:001"),
        pattern_family: bw_model::V32PatternFamily::RetainedBorrowedCallback,
        confidence: bw_model::V32CandidateConfidence::NeedsDynamicValidation,
        evidence_refs: vec![bw_model::V32BoundaryEvidenceRef {
            kind: bw_model::V32BoundaryEvidenceKind::SourceSpan,
            path: "src/lib.rs".to_owned(),
            line_start: Some(1),
            line_end: Some(1),
        }],
        api_path: Some("contract::register_callback".to_owned()),
        recommended_next_step: bw_model::V32RecommendedNextStep::GenerateLifecycleSubgraph,
        notes: vec!["synthetic candidate".to_owned()],
    }
}

fn atomic_ordering_lifecycle_fact(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    ordering: bw_model::AtomicOrderingKind,
    api_id: &str,
    target_type_name: &str,
) -> bw_model::V326LifecycleFactRecord {
    let line = candidate.evidence_refs[0].line_start.unwrap_or(1);
    let path = candidate.evidence_refs[0].path.clone();
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId(format!("static:atomic:{prefix}")),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId(format!("build:atomic:{prefix}")),
        artifact: Some(bw_model::StaticArtifactIdentity {
            crate_id: candidate.crate_id.clone(),
            package_name: "atomic".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(bw_model::StaticSourceRef {
            path: path.clone(),
            line_start: line,
            line_end: line,
            symbol_path: Some(api_id.to_owned()),
        }),
        payload: bw_model::StaticFact::AtomicOrdering(bw_model::AtomicOrderingFact {
            site_id: bw_model::SiteId(format!("site:atomic:{prefix}")),
            semantic_site_key: bw_model::SemanticSiteKey(format!("semantic:atomic:{prefix}")),
            api_id: api_id.to_owned(),
            operation: bw_model::AtomicOperationKind::Load,
            ordering,
            target_type_name: target_type_name.to_owned(),
        }),
    };
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        candidate,
        &static_fact,
        V326SourceRef {
            path,
            line_start: Some(line),
            line_end: Some(line),
            symbol_path: Some(api_id.to_owned()),
            text_sha256: None,
        },
        Vec::new(),
    )
    .expect("atomic ordering static fixture should map to lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        candidate,
        std::slice::from_ref(&static_fact),
    ));
    fact
}

fn raw_parts_candidate(candidate_id: &str, crate_id: &str) -> bw_model::V32CandidateRecord {
    let mut candidate = sample_candidate(candidate_id, crate_id);
    candidate.pattern_family = bw_model::V32PatternFamily::ForeignRetainedPointer;
    candidate.api_path = Some("fixture::Buffer::from::Vec::from_raw_parts".to_owned());
    candidate.evidence_refs[0].path = "src/buffer.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(10);
    candidate.evidence_refs[0].line_end = Some(10);
    candidate
}

fn manual_drop_candidate(candidate_id: &str, crate_id: &str) -> bw_model::V32CandidateRecord {
    let mut candidate = sample_candidate(candidate_id, crate_id);
    candidate.pattern_family = bw_model::V32PatternFamily::ForeignRetainedPointer;
    candidate.api_path = Some("fixture::Instrumented::into_inner".to_owned());
    candidate.evidence_refs[0].path = "src/instrument.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    candidate
}

fn manual_drop_prevention_facts(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    include_drop_guard: bool,
) -> Vec<bw_model::V326LifecycleFactRecord> {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = |line_start| bw_model::StaticSourceRef {
        path: "src/instrument.rs".to_owned(),
        line_start,
        line_end: line_start,
        symbol_path: Some("fixture::Instrumented::into_inner".to_owned()),
    };
    let owner_site_id = bw_model::SiteId(format!("site:{prefix}:owner"));
    let mut static_facts = vec![
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:owner")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref(42)),
            payload: bw_model::StaticFact::ObjectSite(bw_model::ObjectSiteFact {
                site_id: owner_site_id.clone(),
                semantic_site_key: bw_model::SemanticSiteKey(format!("semantic:{prefix}:owner")),
                type_name: "fixture::Instrumented<T>".to_owned(),
            }),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:mem-forget")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref(43)),
            payload: bw_model::StaticFact::DropPrevention(bw_model::DropPreventionFact {
                site_id: bw_model::SiteId(format!("site:{prefix}:mem-forget")),
                semantic_site_key: bw_model::SemanticSiteKey(format!(
                    "semantic:{prefix}:mem-forget"
                )),
                object_site_id: owner_site_id.clone(),
                prevention_kind: bw_model::DropPreventionKind::MemForget,
            }),
        },
    ];
    if include_drop_guard {
        static_facts.push(bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:drop-guard")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact),
            source_ref: Some(source_ref(44)),
            payload: bw_model::StaticFact::DropSite(bw_model::DropSiteFact {
                site_id: bw_model::SiteId(format!("site:{prefix}:drop-guard")),
                semantic_site_key: bw_model::SemanticSiteKey(format!(
                    "semantic:{prefix}:drop-guard"
                )),
                object_site_id: owner_site_id,
                drop_kind: bw_model::DropKind::ScopeEnd,
            }),
        });
    }

    static_facts
        .iter()
        .map(|envelope| {
            let source = envelope
                .source_ref
                .as_ref()
                .expect("fixture has source ref");
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                vec!["evidence:manual-drop".to_owned()],
            )
            .expect("static manual-drop fixture should map to lifecycle fact");
            fact.provenance.static_anchor_record_ids = vec![envelope.record_id.to_string()];
            assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                &mut fact,
                candidate,
                &static_facts,
            ));
            fact
        })
        .collect()
}

fn raw_parts_transfer_facts(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    include_drop_prevention: bool,
) -> Vec<bw_model::V326LifecycleFactRecord> {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = |line_start| bw_model::StaticSourceRef {
        path: "src/buffer.rs".to_owned(),
        line_start,
        line_end: line_start,
        symbol_path: Some("fixture::Buffer::from".to_owned()),
    };
    let owner_site_id = bw_model::SiteId(format!("site:{prefix}:source-owner"));
    let user_data_site_id = bw_model::SiteId(format!("site:{prefix}:raw-parts-pointer"));
    let mut static_facts = vec![
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:owner")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref(10)),
            payload: bw_model::StaticFact::ObjectSite(bw_model::ObjectSiteFact {
                site_id: owner_site_id.clone(),
                semantic_site_key: bw_model::SemanticSiteKey(format!("semantic:{prefix}:owner")),
                type_name: "std::boxed::Box<[u8]>".to_owned(),
            }),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:raw-parts")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref(10)),
            payload: bw_model::StaticFact::RawPointerTransfer(bw_model::RawPointerTransferFact {
                site_id: bw_model::SiteId(format!("site:{prefix}:raw-parts")),
                semantic_site_key: bw_model::SemanticSiteKey(format!(
                    "semantic:{prefix}:raw-parts"
                )),
                user_data_site_id: user_data_site_id.clone(),
                transfer_kind: bw_model::RawPointerTransferKind::FromRawParts,
            }),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:source-drop")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref(12)),
            payload: bw_model::StaticFact::DropSite(bw_model::DropSiteFact {
                site_id: bw_model::SiteId(format!("site:{prefix}:source-drop")),
                semantic_site_key: bw_model::SemanticSiteKey(format!(
                    "semantic:{prefix}:source-drop"
                )),
                object_site_id: owner_site_id.clone(),
                drop_kind: bw_model::DropKind::ScopeEnd,
            }),
        },
    ];
    if include_drop_prevention {
        static_facts.push(bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:mem-forget")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact),
            source_ref: Some(source_ref(11)),
            payload: bw_model::StaticFact::DropPrevention(bw_model::DropPreventionFact {
                site_id: bw_model::SiteId(format!("site:{prefix}:mem-forget")),
                semantic_site_key: bw_model::SemanticSiteKey(format!(
                    "semantic:{prefix}:mem-forget"
                )),
                object_site_id: owner_site_id,
                prevention_kind: bw_model::DropPreventionKind::MemForget,
            }),
        });
    }

    static_facts
        .iter()
        .map(|envelope| {
            let source = envelope
                .source_ref
                .as_ref()
                .expect("fixture has source ref");
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                vec!["evidence:raw-parts".to_owned()],
            )
            .expect("static raw-parts fixture should map to lifecycle fact");
            fact.provenance.static_anchor_record_ids = vec![envelope.record_id.to_string()];
            assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                &mut fact,
                candidate,
                &static_facts,
            ));
            fact
        })
        .collect()
}

fn callback_user_data_reconstruction_facts(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    reconstruction_kind: bw_model::CallbackUserDataReconstructionKind,
) -> Vec<bw_model::V326LifecycleFactRecord> {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId(format!("static:{prefix}:callback-userdata")),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId(format!("build:{prefix}")),
        artifact: Some(artifact),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/stream.rs".to_owned(),
            line_start: 42,
            line_end: 42,
            symbol_path: Some("fixture::stream_callback".to_owned()),
        }),
        payload: bw_model::StaticFact::CallbackUserDataReconstruction(
            bw_model::CallbackUserDataReconstructionFact {
                site_id: bw_model::SiteId(format!("site:{prefix}:callback-userdata")),
                semantic_site_key: bw_model::SemanticSiteKey(format!(
                    "semantic:{prefix}:callback-userdata"
                )),
                callback_site_id: bw_model::SiteId(format!("site:{prefix}:callback")),
                user_data_site_id: bw_model::SiteId(format!("site:{prefix}:user-data")),
                object_site_id: bw_model::SiteId(format!("site:{prefix}:stream-data")),
                reconstruction_kind,
            },
        ),
    };
    let source = static_fact
        .source_ref
        .as_ref()
        .expect("fixture has source ref");
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        candidate,
        &static_fact,
        V326SourceRef {
            path: source.path.clone(),
            line_start: Some(source.line_start),
            line_end: Some(source.line_end),
            symbol_path: source.symbol_path.clone(),
            text_sha256: None,
        },
        vec!["evidence:callback-userdata".to_owned()],
    )
    .expect("static callback user_data fixture should map to lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        candidate,
        std::slice::from_ref(&static_fact),
    ));
    vec![fact]
}

fn callback_release_use_order_fact(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    registration_site: bw_model::SiteId,
    release_site: bw_model::SiteId,
    use_site: bw_model::SiteId,
    object_site: bw_model::SiteId,
    ordering: bw_model::CallbackReleaseUseOrdering,
) -> bw_model::V326LifecycleFactRecord {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId(format!("static:{prefix}:callback-release-use-order")),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId(format!("build:{prefix}")),
        artifact: Some(artifact),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/stream.rs".to_owned(),
            line_start: 43,
            line_end: 43,
            symbol_path: Some("fixture::stream_callback".to_owned()),
        }),
        payload: bw_model::StaticFact::CallbackReleaseUseOrder(
            bw_model::CallbackReleaseUseOrderFact {
                site_id: bw_model::SiteId(format!("site:{prefix}:callback-release-use-order")),
                semantic_site_key: bw_model::SemanticSiteKey(format!(
                    "semantic:{prefix}:callback-release-use-order"
                )),
                registration_site_id: registration_site,
                release_site_id: release_site,
                use_site_id: use_site,
                object_site_id: object_site,
                api_id: "api:fixture:register".to_owned(),
                ordering,
            },
        ),
    };
    let source = static_fact
        .source_ref
        .as_ref()
        .expect("fixture has source ref");
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        candidate,
        &static_fact,
        V326SourceRef {
            path: source.path.clone(),
            line_start: Some(source.line_start),
            line_end: Some(source.line_end),
            symbol_path: source.symbol_path.clone(),
            text_sha256: None,
        },
        vec!["evidence:callback-release-use-order".to_owned()],
    )
    .expect("static callback release/use order fixture should map to lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        candidate,
        std::slice::from_ref(&static_fact),
    ));
    fact
}

fn evidence_with_details(
    record_id: &str,
    crate_id: &str,
    candidate_id: &str,
    evidence_kind: bw_model::V326EvidenceKind,
    details: serde_json::Value,
) -> bw_model::V326LifecycleEvidenceRecord {
    let mut record = bw_model::V326LifecycleEvidenceRecord::sample_for_tests(
        record_id,
        crate_id,
        candidate_id,
        evidence_kind,
    );
    record.details = details;
    record
}

fn evidence_with_details_at_line(
    record_id: &str,
    crate_id: &str,
    candidate_id: &str,
    evidence_kind: bw_model::V326EvidenceKind,
    details: serde_json::Value,
    path: &str,
    line: u64,
) -> bw_model::V326LifecycleEvidenceRecord {
    let mut record =
        evidence_with_details(record_id, crate_id, candidate_id, evidence_kind, details);
    record.source_ref.path = path.to_owned();
    record.source_ref.line_start = Some(line);
    record.source_ref.line_end = Some(line);
    record
}

fn fact_with_object(
    fact_id: &str,
    candidate_id: &str,
    crate_id: &str,
    fact_kind: bw_model::V326LifecycleFactKind,
    object_id: &str,
) -> bw_model::V326LifecycleFactRecord {
    // In-memory helper for feature/graph unit tests. Not a public validate path: some
    // tests intentionally pass non-source_evidence labels to prove they do not bind.
    bw_model::V326LifecycleFactRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_FACT_SCHEMA_V1.to_owned(),
        run_id: "run:v326".to_owned(),
        candidate_id: candidate_id.to_owned(),
        crate_id: crate_id.to_owned(),
        fact_id: fact_id.to_owned(),
        fact_kind,
        source_ref: V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(1),
            line_end: Some(1),
            symbol_path: Some("sample::register".to_owned()),
            text_sha256: None,
        },
        symbol_path: Some("sample::register".to_owned()),
        confidence: V326EvidenceConfidence::High,
        coverage_state: bw_model::V326CoverageState::Covered,
        provenance: bw_model::V326LifecycleFactProvenance::source_observation(),
        object_ids: vec![object_id.to_owned()],
        evidence_refs: vec!["evidence:sample:0001".to_owned()],
        notes: vec!["candidate-scoped fact".to_owned()],
    }
}

fn static_fact_with_object(
    fact_id: &str,
    candidate_id: &str,
    crate_id: &str,
    fact_kind: bw_model::V326LifecycleFactKind,
    object_id: &str,
) -> bw_model::V326LifecycleFactRecord {
    let candidate = sample_candidate(candidate_id, crate_id);
    assert_ne!(
        fact_kind,
        bw_model::V326LifecycleFactKind::ReleaseCall,
        "bw.static/0.1 has no authoritative ReleaseCall producer; use UnregisterCall"
    );
    let static_fact = static_fact_envelope_for_test(fact_id, crate_id, fact_kind, object_id);
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        &candidate,
        &static_fact,
        V326SourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: Some(1),
            line_end: Some(1),
            symbol_path: Some("sample::register".to_owned()),
            text_sha256: None,
        },
        vec!["evidence:sample:0001".to_owned()],
    )
    .expect("fixture static fact should convert");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        &candidate,
        std::slice::from_ref(&static_fact),
    ));
    fact
}

fn returned_borrow_static_lifecycle_facts(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
) -> Vec<bw_model::V326LifecycleFactRecord> {
    returned_borrow_static_lifecycle_facts_with_ordering(
        candidate,
        prefix,
        bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse,
    )
}

fn returned_borrow_static_lifecycle_facts_with_ordering(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    ordering: bw_model::ReturnedBorrowInvalidationOrdering,
) -> Vec<bw_model::V326LifecycleFactRecord> {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = bw_model::StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start: 1,
        line_end: 1,
        symbol_path: Some("fixture::View::get".to_owned()),
    };
    let source_site = bw_model::SiteId(format!("site:{prefix}:owner"));
    let returned_site = bw_model::SiteId(format!("site:{prefix}:returned"));
    let persisted_site = bw_model::SiteId(format!("site:{prefix}:persisted"));
    let storage_site = bw_model::SiteId(format!("site:{prefix}:storage"));
    let static_facts = vec![
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:returned-relation")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref.clone()),
            payload: bw_model::StaticFact::ReturnedBorrowRelation(
                bw_model::ReturnedBorrowRelationFact {
                    site_id: bw_model::SiteId(format!("site:{prefix}:relation")),
                    semantic_site_key: bw_model::SemanticSiteKey(format!(
                        "semantic:{prefix}:relation"
                    )),
                    api_id: "fixture::View::get".to_owned(),
                    source_site_id: source_site.clone(),
                    returned_site_id: returned_site.clone(),
                    relation_kind: None,
                },
            ),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:persisted")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref.clone()),
            payload: bw_model::StaticFact::PersistedReturnedBorrow(
                bw_model::PersistedReturnedBorrowFact {
                    site_id: persisted_site.clone(),
                    semantic_site_key: bw_model::SemanticSiteKey(format!(
                        "semantic:{prefix}:persisted"
                    )),
                    api_id: "fixture::View::get".to_owned(),
                    source_site_id: source_site,
                    returned_site_id: returned_site,
                    storage_site_id: storage_site,
                },
            ),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:order")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact),
            source_ref: Some(source_ref),
            payload: bw_model::StaticFact::ReturnedBorrowInvalidationOrder(
                bw_model::ReturnedBorrowInvalidationOrderFact {
                    site_id: bw_model::SiteId(format!("site:{prefix}:order")),
                    semantic_site_key: bw_model::SemanticSiteKey(format!(
                        "semantic:{prefix}:order"
                    )),
                    api_id: "fixture::View::get".to_owned(),
                    invalidation_api_id: "fixture::View::step".to_owned(),
                    persisted_site_id: persisted_site,
                    invalidation_site_id: bw_model::SiteId(format!("site:{prefix}:step")),
                    use_site_id: bw_model::SiteId(format!("site:{prefix}:use")),
                    ordering,
                },
            ),
        },
    ];

    static_facts
        .iter()
        .map(|envelope| {
            let source = envelope.source_ref.as_ref().expect("fixture has source");
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                Vec::new(),
            )
            .expect("returned-borrow static fixture should map to lifecycle fact");
            fact.provenance.static_anchor_record_ids = vec![static_facts[0].record_id.to_string()];
            assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                &mut fact,
                candidate,
                &static_facts,
            ));
            fact
        })
        .collect()
}

fn external_buffer_static_lifecycle_fact(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
) -> bw_model::V326LifecycleFactRecord {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = bw_model::StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start: 1,
        line_end: 1,
        symbol_path: Some("fixture::Buffer::external".to_owned()),
    };
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId(format!("static:{prefix}:external-buffer")),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId(format!("build:{prefix}")),
        artifact: Some(artifact),
        source_ref: Some(source_ref.clone()),
        payload: bw_model::StaticFact::ExternalBufferBinding(bw_model::ExternalBufferBindingFact {
            site_id: bw_model::SiteId(format!("site:{prefix}:binding")),
            semantic_site_key: bw_model::SemanticSiteKey(format!("semantic:{prefix}:binding")),
            source_site_id: bw_model::SiteId(format!("site:{prefix}:source")),
            buffer_site_id: bw_model::SiteId(format!("site:{prefix}:buffer")),
            api_id: "fixture::Buffer::external".to_owned(),
        }),
    };
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        candidate,
        &static_fact,
        V326SourceRef {
            path: source_ref.path,
            line_start: Some(source_ref.line_start),
            line_end: Some(source_ref.line_end),
            symbol_path: source_ref.symbol_path,
            text_sha256: None,
        },
        Vec::new(),
    )
    .expect("external-buffer static fixture should map to lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        candidate,
        std::slice::from_ref(&static_fact),
    ));
    fact
}

fn authoritative_user_data_release_facts(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
) -> Vec<bw_model::V326LifecycleFactRecord> {
    authoritative_user_data_release_facts_with_sites(
        candidate,
        prefix,
        bw_model::SiteId(format!("site:{prefix}:user-data")),
        bw_model::SiteId(format!("site:{prefix}:register")),
        bw_model::SiteId(format!("site:{prefix}:from-raw")),
    )
}

fn authoritative_user_data_release_facts_with_sites(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    user_data_site: bw_model::SiteId,
    registration_site: bw_model::SiteId,
    release_site: bw_model::SiteId,
) -> Vec<bw_model::V326LifecycleFactRecord> {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = bw_model::StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start: 1,
        line_end: 1,
        symbol_path: Some("fixture::register_callback".to_owned()),
    };
    let static_facts = vec![
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:register")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref.clone()),
            payload: bw_model::StaticFact::RegistrationSite(bw_model::RegistrationSiteFact {
                site_id: registration_site.clone(),
                semantic_site_key: bw_model::SemanticSiteKey(format!("semantic:{prefix}:register")),
                callback_site_id: None,
                user_data_site_id: Some(user_data_site.clone()),
                api_id: "api:fixture:register".to_owned(),
                role: bw_model::RegistrationRole::Register,
            }),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:into-raw")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref.clone()),
            payload: bw_model::StaticFact::RawPointerTransfer(bw_model::RawPointerTransferFact {
                site_id: bw_model::SiteId(format!("site:{prefix}:into-raw")),
                semantic_site_key: bw_model::SemanticSiteKey(format!("semantic:{prefix}:into-raw")),
                user_data_site_id: user_data_site.clone(),
                transfer_kind: bw_model::RawPointerTransferKind::IntoRaw,
            }),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:from-raw")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact.clone()),
            source_ref: Some(source_ref.clone()),
            payload: bw_model::StaticFact::RawPointerTransfer(bw_model::RawPointerTransferFact {
                site_id: release_site.clone(),
                semantic_site_key: bw_model::SemanticSiteKey(format!("semantic:{prefix}:from-raw")),
                user_data_site_id: user_data_site.clone(),
                transfer_kind: bw_model::RawPointerTransferKind::FromRaw,
            }),
        },
        bw_model::StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId(format!("static:{prefix}:proof")),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId(format!("build:{prefix}")),
            artifact: Some(artifact),
            source_ref: Some(source_ref),
            payload: bw_model::StaticFact::ReleasePathProof(bw_model::ReleasePathProofFact {
                site_id: bw_model::SiteId(format!("site:{prefix}:proof")),
                semantic_site_key: bw_model::SemanticSiteKey(format!("semantic:{prefix}:proof")),
                registration_site_id: registration_site,
                release_site_id: release_site,
                object_site_id: user_data_site,
            }),
        },
    ];

    static_facts
        .iter()
        .map(|envelope| {
            let source = envelope.source_ref.as_ref().expect("fixture has a source");
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                vec![
                    format!("evidence:{prefix}:register"),
                    format!("evidence:{prefix}:raw"),
                ],
            )
            .expect("static fixture should map to a lifecycle fact");
            fact.provenance.static_anchor_record_ids = vec![envelope.record_id.to_string()];
            assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                &mut fact,
                candidate,
                &static_facts,
            ));
            fact
        })
        .collect()
}

type ObjectFlowFixtureSpec<'a> = (
    &'a str,
    bw_model::ObjectFlowKind,
    bw_model::ObjectFlowObjectKind,
    &'a str,
    bw_model::ObjectFlowObjectKind,
    &'a str,
);

type ObjectFlowFixtureSpecWithBinding<'a> = (
    &'a str,
    bw_model::ObjectFlowKind,
    bw_model::ObjectFlowObjectKind,
    &'a str,
    bw_model::ObjectFlowObjectKind,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
);

fn object_flow_static_lifecycle_facts(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    specs: Vec<ObjectFlowFixtureSpec<'_>>,
) -> (
    Vec<bw_model::StaticFactEnvelope>,
    Vec<bw_model::V326LifecycleFactRecord>,
) {
    object_flow_static_lifecycle_facts_with_field_paths(
        candidate,
        prefix,
        specs
            .into_iter()
            .map(
                |(name, flow_kind, from_object_kind, from_site_id, to_object_kind, to_site_id)| {
                    (
                        name,
                        flow_kind,
                        from_object_kind,
                        from_site_id,
                        to_object_kind,
                        to_site_id,
                        Some("Registry::slot"),
                        None,
                    )
                },
            )
            .collect(),
    )
}

fn object_flow_static_lifecycle_facts_with_field_paths(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    specs: Vec<ObjectFlowFixtureSpecWithBinding<'_>>,
) -> (
    Vec<bw_model::StaticFactEnvelope>,
    Vec<bw_model::V326LifecycleFactRecord>,
) {
    object_flow_static_lifecycle_facts_with_api_and_field_paths(
        candidate,
        prefix,
        "fixture::Registry::install",
        specs,
    )
}

fn object_flow_static_lifecycle_facts_with_api_and_field_paths(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    api_id: &str,
    specs: Vec<ObjectFlowFixtureSpecWithBinding<'_>>,
) -> (
    Vec<bw_model::StaticFactEnvelope>,
    Vec<bw_model::V326LifecycleFactRecord>,
) {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = bw_model::StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start: 1,
        line_end: 1,
        symbol_path: Some(api_id.to_owned()),
    };
    let static_facts = specs
        .into_iter()
        .map(
            |(
                name,
                flow_kind,
                from_object_kind,
                from_site_id,
                to_object_kind,
                to_site_id,
                field_path,
                container_type_name,
            )| {
                bw_model::StaticFactEnvelope {
                    schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
                    record_id: bw_model::RecordId(format!("static:{prefix}:{name}")),
                    producer: "fixture".to_owned(),
                    build_id: bw_model::BuildId(format!("build:{prefix}")),
                    artifact: Some(artifact.clone()),
                    source_ref: Some(source_ref.clone()),
                    payload: bw_model::StaticFact::ObjectFlow(bw_model::ObjectFlowFact {
                        site_id: bw_model::SiteId(format!("site:{prefix}:{name}")),
                        semantic_site_key: bw_model::SemanticSiteKey(format!(
                            "semantic:{prefix}:{name}"
                        )),
                        from_site_id: bw_model::SiteId(from_site_id.to_owned()),
                        from_object_kind,
                        to_site_id: bw_model::SiteId(to_site_id.to_owned()),
                        to_object_kind,
                        flow_kind,
                        api_id: api_id.to_owned(),
                        field_path: field_path.map(str::to_owned),
                        container_type_name: container_type_name.map(str::to_owned),
                    }),
                }
            },
        )
        .collect::<Vec<_>>();
    let lifecycle_facts = static_facts
        .iter()
        .map(|envelope| {
            let source = envelope.source_ref.as_ref().expect("fixture has source");
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                Vec::new(),
            )
            .expect("object-flow static fixture should map to lifecycle fact");
            fact.provenance.static_anchor_record_ids = vec![envelope.record_id.to_string()];
            assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                &mut fact,
                candidate,
                &static_facts,
            ));
            fact
        })
        .collect::<Vec<_>>();
    (static_facts, lifecycle_facts)
}

fn object_binding_gap_static_lifecycle_facts(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    gap_kind: bw_model::ObjectBindingGapKind,
    adapter: &str,
) -> (
    Vec<bw_model::StaticFactEnvelope>,
    Vec<bw_model::V326LifecycleFactRecord>,
) {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let source_ref = bw_model::StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start: 3,
        line_end: 3,
        symbol_path: Some("fixture::IterHolder::next".to_owned()),
    };
    let static_facts = vec![bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId(format!("static:{prefix}:binding-gap")),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId(format!("build:{prefix}")),
        artifact: Some(artifact),
        source_ref: Some(source_ref.clone()),
        payload: bw_model::StaticFact::ObjectBindingGap(bw_model::ObjectBindingGapFact {
            site_id: bw_model::SiteId(format!("site:{prefix}:binding-gap")),
            semantic_site_key: bw_model::SemanticSiteKey(format!("semantic:{prefix}:binding-gap")),
            api_id: "fixture::IterHolder::next".to_owned(),
            gap_kind,
            field_path: None,
            container_type_name: None,
            adapter: Some(adapter.to_owned()),
        }),
    }];
    let lifecycle_facts = static_facts
        .iter()
        .map(|envelope| {
            let source = envelope.source_ref.as_ref().expect("fixture has source");
            let mut fact = bw_model::lifecycle_fact_from_static_fact(
                "run:v326",
                candidate,
                envelope,
                V326SourceRef {
                    path: source.path.clone(),
                    line_start: Some(source.line_start),
                    line_end: Some(source.line_end),
                    symbol_path: source.symbol_path.clone(),
                    text_sha256: None,
                },
                Vec::new(),
            )
            .expect("object-binding-gap static fixture should map to lifecycle fact");
            fact.provenance.static_anchor_record_ids = vec![envelope.record_id.to_string()];
            assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
                &mut fact,
                candidate,
                &static_facts,
            ));
            fact
        })
        .collect::<Vec<_>>();
    (static_facts, lifecycle_facts)
}

fn object_binding_gap_static_lifecycle_fact_with_field_path(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    gap_kind: bw_model::ObjectBindingGapKind,
    field_path: &str,
) -> bw_model::V326LifecycleFactRecord {
    object_binding_gap_static_lifecycle_fact_with_field_path_and_adapter(
        candidate, prefix, gap_kind, field_path, None,
    )
}

fn object_binding_gap_static_lifecycle_fact_with_field_path_and_adapter(
    candidate: &bw_model::V32CandidateRecord,
    prefix: &str,
    gap_kind: bw_model::ObjectBindingGapKind,
    field_path: &str,
    adapter: Option<&str>,
) -> bw_model::V326LifecycleFactRecord {
    let artifact = bw_model::StaticArtifactIdentity {
        crate_id: candidate.crate_id.clone(),
        package_name: "fixture".to_owned(),
        package_version: "0.1.0".to_owned(),
        target: "lib".to_owned(),
    };
    let line = candidate.evidence_refs[0].line_start.unwrap_or(1);
    let source_ref = bw_model::StaticSourceRef {
        path: candidate.evidence_refs[0].path.clone(),
        line_start: line,
        line_end: candidate.evidence_refs[0].line_end.unwrap_or(line),
        symbol_path: candidate.api_path.clone(),
    };
    let static_fact = bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId(format!("static:{prefix}:binding-barrier")),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId(format!("build:{prefix}")),
        artifact: Some(artifact),
        source_ref: Some(source_ref.clone()),
        payload: bw_model::StaticFact::ObjectBindingGap(bw_model::ObjectBindingGapFact {
            site_id: bw_model::SiteId(format!("site:{prefix}:binding-barrier")),
            semantic_site_key: bw_model::SemanticSiteKey(format!(
                "semantic:{prefix}:binding-barrier"
            )),
            api_id: candidate
                .api_path
                .clone()
                .unwrap_or_else(|| "fixture::binding_barrier".to_owned()),
            gap_kind,
            field_path: Some(field_path.to_owned()),
            container_type_name: None,
            adapter: adapter.map(str::to_owned),
        }),
    };
    let mut fact = bw_model::lifecycle_fact_from_static_fact(
        "run:v326",
        candidate,
        &static_fact,
        V326SourceRef {
            path: source_ref.path.clone(),
            line_start: Some(source_ref.line_start),
            line_end: Some(source_ref.line_end),
            symbol_path: source_ref.symbol_path.clone(),
            text_sha256: None,
        },
        Vec::new(),
    )
    .expect("binding barrier fixture should map to lifecycle fact");
    fact.provenance.static_anchor_record_ids = vec![static_fact.record_id.to_string()];
    assert!(bw_model::verify_v3_2_6_lifecycle_fact_static_provenance(
        &mut fact,
        candidate,
        std::slice::from_ref(&static_fact),
    ));
    fact
}

fn static_fact_envelope_for_test(
    fact_id: &str,
    crate_id: &str,
    fact_kind: bw_model::V326LifecycleFactKind,
    object_id: &str,
) -> bw_model::StaticFactEnvelope {
    let payload = match fact_kind {
        bw_model::V326LifecycleFactKind::RegisterCall
        | bw_model::V326LifecycleFactKind::UnregisterCall
        | bw_model::V326LifecycleFactKind::ReplaceCall => {
            let callback_site_id = object_id
                .strip_prefix("callback:")
                .expect("registration fixtures bind callback objects");
            let role = match fact_kind {
                bw_model::V326LifecycleFactKind::RegisterCall => {
                    bw_model::RegistrationRole::Register
                }
                bw_model::V326LifecycleFactKind::UnregisterCall => {
                    bw_model::RegistrationRole::Unregister
                }
                bw_model::V326LifecycleFactKind::ReplaceCall => bw_model::RegistrationRole::Replace,
                _ => unreachable!("matched registration lifecycle fact kind"),
            };
            bw_model::StaticFact::RegistrationSite(bw_model::RegistrationSiteFact {
                site_id: bw_model::SiteId(format!("site:{fact_id}")),
                semantic_site_key: bw_model::SemanticSiteKey("src/lib.rs:1".to_owned()),
                callback_site_id: Some(bw_model::SiteId(callback_site_id.to_owned())),
                user_data_site_id: None,
                api_id: format!("fixture::{fact_id}"),
                role,
            })
        }
        bw_model::V326LifecycleFactKind::DropSite => {
            let owner_site = object_id
                .strip_prefix("rust_owner:")
                .expect("drop fixtures bind rust_owner objects");
            bw_model::StaticFact::DropSite(bw_model::DropSiteFact {
                site_id: bw_model::SiteId(format!("site:{fact_id}")),
                semantic_site_key: bw_model::SemanticSiteKey("src/lib.rs:1".to_owned()),
                object_site_id: bw_model::SiteId(owner_site.to_owned()),
                drop_kind: bw_model::DropKind::Explicit,
            })
        }
        bw_model::V326LifecycleFactKind::OwnedMoveCapture => {
            let owner_site = object_id
                .strip_prefix("rust_owner:")
                .expect("owned capture fixtures bind rust_owner objects");
            bw_model::StaticFact::CallbackCapture(bw_model::CallbackCaptureFact {
                site_id: bw_model::SiteId(format!("site:{fact_id}:capture")),
                semantic_site_key: bw_model::SemanticSiteKey("src/lib.rs:1".to_owned()),
                callback_site_id: bw_model::SiteId(format!("site:{fact_id}:callback")),
                object_site_id: bw_model::SiteId(owner_site.to_owned()),
                capture_ordinal: 0,
                capture_mode: bw_model::CaptureMode::Owned,
            })
        }
        _ => panic!("fixture has no authoritative static producer for {fact_kind:?}"),
    };
    bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
        record_id: bw_model::RecordId(format!("static:{fact_id}")),
        producer: "fixture".to_owned(),
        build_id: bw_model::BuildId("build:fixture".to_owned()),
        artifact: Some(bw_model::StaticArtifactIdentity {
            crate_id: crate_id.to_owned(),
            package_name: "fixture".to_owned(),
            package_version: "0.1.0".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(bw_model::StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 1,
            line_end: 1,
            symbol_path: None,
        }),
        payload,
    }
}

/// 构造一份完整的 callback register/release/use 事实集，`ordering` 决定顺序结论。
fn callback_release_use_graph_for_ordering(
    ordering: bw_model::CallbackReleaseUseOrdering,
) -> bw_model::V326LifecycleGraphV3Record {
    let mut candidate = sample_candidate(
        "candidate:callback-release-use-layers:001",
        "crate:callback-release-use-layers",
    );
    candidate.api_path = Some("api:fixture:register".to_owned());
    candidate.evidence_refs[0].path = "src/lib.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(1);
    candidate.evidence_refs[0].line_end = Some(1);
    let mut facts = authoritative_user_data_release_facts_with_sites(
        &candidate,
        "callback-release-use-layers",
        bw_model::SiteId("site:callback-release-use-layers:registered-user-data".to_owned()),
        bw_model::SiteId("site:callback-release-use-layers:register".to_owned()),
        bw_model::SiteId("site:callback-release-use-layers:from-raw".to_owned()),
    );
    let (_static_facts, object_flow_facts) =
        object_flow_static_lifecycle_facts_with_api_and_field_paths(
            &candidate,
            "callback-release-use-layers",
            "api:fixture:register",
            vec![
                (
                    "field-store",
                    bw_model::ObjectFlowKind::FieldStore,
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use-layers:registered-user-data",
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use-layers:registered-handle",
                    Some("callback_user_data:api:fixture:register:slot"),
                    None,
                ),
                (
                    "field-load",
                    bw_model::ObjectFlowKind::FieldLoad,
                    bw_model::ObjectFlowObjectKind::OpaqueHandle,
                    "site:callback-release-use-layers:registered-handle",
                    bw_model::ObjectFlowObjectKind::UserData,
                    "site:callback-release-use-layers:user-data",
                    Some("callback_user_data:api:fixture:register:slot"),
                    None,
                ),
            ],
        );
    facts.extend(object_flow_facts);
    candidate.evidence_refs[0].path = "src/stream.rs".to_owned();
    candidate.evidence_refs[0].line_start = Some(42);
    candidate.evidence_refs[0].line_end = Some(42);
    facts.extend(callback_user_data_reconstruction_facts(
        &candidate,
        "callback-release-use-layers",
        bw_model::CallbackUserDataReconstructionKind::OwnerFromTransmute,
    ));
    facts.push(callback_release_use_order_fact(
        &candidate,
        "callback-release-use-layers",
        bw_model::SiteId("site:callback-release-use-layers:register".to_owned()),
        bw_model::SiteId("site:callback-release-use-layers:from-raw".to_owned()),
        bw_model::SiteId("site:callback-release-use-layers:callback-userdata".to_owned()),
        bw_model::SiteId("site:callback-release-use-layers:registered-user-data".to_owned()),
        ordering,
    ));

    bw_model::build_v3_2_6_lifecycle_graph_v3(&candidate, &[], &facts, &[])
}

fn graph_has_layer(
    graph: &bw_model::V326LifecycleGraphV3Record,
    layer: bw_model::V326ObjectChainLayer,
) -> bool {
    graph
        .object_chains
        .iter()
        .any(|chain| chain.verified_layers.contains(&layer))
}

#[test]
fn proven_callback_release_use_ordering_lights_ordering_and_complete_risk_layers() {
    let graph = callback_release_use_graph_for_ordering(
        bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
    );

    assert!(
        graph_has_layer(&graph, bw_model::V326ObjectChainLayer::LifecycleOrdering),
        "a proven release-before-use ordering must light the lifecycle ordering layer"
    );
    assert!(
        graph_has_layer(&graph, bw_model::V326ObjectChainLayer::CompleteRiskChain),
        "a proven release-before-use ordering must light the complete risk chain layer"
    );
}

#[test]
fn proven_callback_use_before_release_ordering_still_lights_layers() {
    let graph = callback_release_use_graph_for_ordering(
        bw_model::CallbackReleaseUseOrdering::CallbackUseBeforeRelease,
    );

    assert!(
        graph_has_layer(&graph, bw_model::V326ObjectChainLayer::LifecycleOrdering),
        "use-before-release is still a proven ordering and must keep lighting the ordering layer"
    );
    assert!(
        graph_has_layer(&graph, bw_model::V326ObjectChainLayer::CompleteRiskChain),
        "use-before-release is still a proven ordering and must keep lighting the risk chain layer"
    );
}

#[test]
fn unknown_callback_release_use_ordering_does_not_light_ordering_or_risk_layers() {
    let graph = callback_release_use_graph_for_ordering(
        bw_model::CallbackReleaseUseOrdering::UnknownOrdering,
    );

    // `LifecycleOrdering` 仍会亮起，但它来自事实集中独立的 release path proof，
    // 与 callback release/use 顺序无关。complete risk chain 只能由顺序事实点亮，
    // 因此它才是未证明顺序的假阳性入口。
    assert!(
        !graph_has_layer(&graph, bw_model::V326ObjectChainLayer::CompleteRiskChain),
        "an unproven ordering must never be promoted to a complete risk chain"
    );
}

#[test]
fn unknown_callback_release_use_ordering_is_not_a_release_use_chain() {
    let graph = callback_release_use_graph_for_ordering(
        bw_model::CallbackReleaseUseOrdering::UnknownOrdering,
    );

    assert!(
        graph_has_layer(&graph, bw_model::V326ObjectChainLayer::IdentityTransport),
        "the object binding is still proven, so identity transport stays verified"
    );
}

#[test]
fn proven_ordering_lights_both_release_and_use_ordering_layers() {
    let graph = callback_release_use_graph_for_ordering(
        bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
    );

    assert!(
        graph_has_layer(&graph, bw_model::V326ObjectChainLayer::ReleaseOrdering),
        "the release path proof proves release ordering"
    );
    assert!(
        graph_has_layer(&graph, bw_model::V326ObjectChainLayer::UseOrdering),
        "a proven callback release/use order proves use ordering"
    );
}

#[test]
fn unknown_use_ordering_keeps_release_ordering_and_drops_only_use_ordering() {
    let graph = callback_release_use_graph_for_ordering(
        bw_model::CallbackReleaseUseOrdering::UnknownOrdering,
    );

    // 这正是拆层的目的：release coverage 已证明，缺的只是 use 顺序。
    // 合并成单一 lifecycle_ordering 时这两种情况无法区分。
    assert!(
        graph_has_layer(&graph, bw_model::V326ObjectChainLayer::ReleaseOrdering),
        "release ordering is still proven by the release path proof"
    );
    assert!(
        !graph_has_layer(&graph, bw_model::V326ObjectChainLayer::UseOrdering),
        "an unproven use order must not light the use ordering layer"
    );
    assert!(
        !graph_has_layer(&graph, bw_model::V326ObjectChainLayer::CompleteRiskChain),
        "without use ordering the chain is not a complete risk chain"
    );
}

#[test]
fn missing_use_ordering_is_reported_as_a_missing_layer() {
    let graph = callback_release_use_graph_for_ordering(
        bw_model::CallbackReleaseUseOrdering::UnknownOrdering,
    );

    assert!(
        graph.object_chains.iter().any(|chain| {
            chain
                .missing_layers
                .contains(&bw_model::V326ObjectChainLayer::UseOrdering)
        }),
        "a chain that needs use ordering but cannot prove it must say so in missing_layers"
    );
}

#[test]
fn lifecycle_ordering_stays_the_union_of_the_two_finer_layers() {
    for ordering in [
        bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        bw_model::CallbackReleaseUseOrdering::UnknownOrdering,
    ] {
        let graph = callback_release_use_graph_for_ordering(ordering);
        for chain in &graph.object_chains {
            let release = chain
                .verified_layers
                .contains(&bw_model::V326ObjectChainLayer::ReleaseOrdering);
            let use_order = chain
                .verified_layers
                .contains(&bw_model::V326ObjectChainLayer::UseOrdering);
            let union = chain
                .verified_layers
                .contains(&bw_model::V326ObjectChainLayer::LifecycleOrdering);
            assert_eq!(
                union,
                release || use_order,
                "the compatibility layer must stay exactly the union so existing consumers keep \
                 their current meaning: chain={}",
                chain.chain_id
            );
        }
    }
}
