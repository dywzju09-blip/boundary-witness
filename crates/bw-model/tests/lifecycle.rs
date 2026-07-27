use std::path::PathBuf;

use bw_model::{
    Located, V3_2_CANDIDATE_SCHEMA_V1, V32BoundaryEvidenceKind, V32BoundaryEvidenceRef,
    V32CandidateConfidence, V32CandidateRecord, V32PatternFamily, V32RecommendedNextStep,
    lifecycle_graph_from_candidate, ranking_reason, score_lifecycle_graph,
    validate_v3_2_lifecycle_graphs, validate_v3_2_ranked_candidates,
};

#[test]
fn retained_callback_graph_has_high_risk_features_and_score() {
    let candidate = sample_candidate(
        "candidate:a:callback",
        V32PatternFamily::RetainedBorrowedCallback,
        V32CandidateConfidence::NeedsDynamicValidation,
    );
    let graph = lifecycle_graph_from_candidate(&candidate, "v3-2-lifecycle-test");
    assert!(!graph.nodes.is_empty());
    assert!(!graph.edges.is_empty());
    assert!(graph.risk_features.foreign_retention_without_owned_anchor);
    assert!(graph.risk_features.callback_retained_across_drop);

    let (score, breakdown) = score_lifecycle_graph(&graph, candidate.confidence);
    assert!(score >= 40);
    assert_eq!(breakdown.confidence_bonus, 5);
    let reason = ranking_reason(score, &graph.risk_features, breakdown.confidence_bonus);
    assert!(reason.contains("score="));
    assert!(reason.contains("active_risk_features="));

    let count = validate_v3_2_lifecycle_graphs([Located {
        path: PathBuf::from("graph.json"),
        line: 1,
        value: graph,
    }])
    .expect("graph should validate");
    assert_eq!(count, 1);
}

#[test]
fn ranked_candidates_require_contiguous_ranks() {
    let candidate = sample_candidate(
        "candidate:a:native",
        V32PatternFamily::NativeLibraryBoundary,
        V32CandidateConfidence::StaticOnly,
    );
    let graph = lifecycle_graph_from_candidate(&candidate, "v3-2-lifecycle-test");
    let (score, breakdown) = score_lifecycle_graph(&graph, candidate.confidence);
    let ranking_reason = ranking_reason(score, &graph.risk_features, breakdown.confidence_bonus);
    let ranked = bw_model::V32RankedCandidateRecord {
        schema_version: bw_model::V3_2_RANKED_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: "v3-2-lifecycle-test".to_owned(),
        rank: 1,
        candidate_id: candidate.candidate_id,
        crate_id: candidate.crate_id,
        pattern_family: candidate.pattern_family,
        score,
        score_breakdown: breakdown.clone(),
        risk_features: graph.risk_features.clone(),
        lifecycle_graph_path: "lifecycle-graphs/candidate_a_native.json".to_owned(),
        ranking_reason,
        notes: vec!["ranking is not a vulnerability conclusion".to_owned()],
    };
    let summary = validate_v3_2_ranked_candidates([Located {
        path: PathBuf::from("ranked.jsonl"),
        line: 1,
        value: ranked,
    }])
    .expect("ranked candidate should validate");
    assert_eq!(summary.ranked_count, 1);
    assert_eq!(summary.max_score, score);
}

fn sample_candidate(
    candidate_id: &str,
    pattern_family: V32PatternFamily,
    confidence: V32CandidateConfidence,
) -> V32CandidateRecord {
    V32CandidateRecord {
        schema_version: V3_2_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: "v3-2-lifecycle-test".to_owned(),
        candidate_id: candidate_id.to_owned(),
        crate_id: "crate:sample:0.1.0".to_owned(),
        boundary_id: "boundary:sample:0001".to_owned(),
        pattern_family,
        confidence,
        evidence_refs: vec![V32BoundaryEvidenceRef {
            kind: V32BoundaryEvidenceKind::SourceSpan,
            path: "src/lib.rs".to_owned(),
            line_start: Some(10),
            line_end: Some(10),
        }],
        api_path: Some("sample::api".to_owned()),
        recommended_next_step: V32RecommendedNextStep::GenerateLifecycleSubgraph,
        notes: vec!["candidate is not a vulnerability conclusion".to_owned()],
    }
}
