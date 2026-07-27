use std::{collections::BTreeSet, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    Located, ModelError, V32BoundaryEvidenceRef, V32CandidateConfidence, V32CandidateRecord,
    V32PatternFamily, public_tokens::reject_public_forbidden_token,
};

pub const V3_2_LIFECYCLE_GRAPH_SCHEMA_V1: &str = "v3.2.lifecycle_graph.1";
pub const V3_2_RANKED_CANDIDATE_SCHEMA_V1: &str = "v3.2.ranked_candidate.1";

const SCORE_FOREIGN_RETENTION: u32 = 10;
const SCORE_MISSING_UNREGISTER: u32 = 10;
const SCORE_CROSS_LANGUAGE_ALIAS: u32 = 10;
const SCORE_OPAQUE_HANDLE: u32 = 8;
const SCORE_CALLBACK_ACROSS_DROP: u32 = 10;
const SCORE_NEEDS_DYNAMIC: u32 = 5;
const SCORE_STATIC_ONLY: u32 = 2;
const SCORE_LOW_PRIORITY: u32 = 0;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32LifecycleGraph {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_lifecycle_graph_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub candidate_id: String,
    pub crate_id: String,
    pub pattern_family: V32PatternFamily,
    pub nodes: Vec<V32LifecycleNode>,
    pub edges: Vec<V32LifecycleEdge>,
    pub risk_features: V32RiskFeatures,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32LifecycleNode {
    pub node_id: String,
    pub node_kind: V32LifecycleNodeKind,
    pub label: String,
    pub lifetime_role: V32LifetimeRole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32LifecycleNodeKind {
    RustObject,
    RustBorrow,
    ForeignApi,
    ForeignOwner,
    CallbackSite,
    OpaqueHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32LifetimeRole {
    Owned,
    Borrowed,
    ExternalRetained,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32LifecycleEdge {
    pub from: String,
    pub to: String,
    pub edge_kind: V32LifecycleEdgeKind,
    pub evidence_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V32LifecycleEdgeKind {
    RegisteredIntoForeignApi,
    ForeignRetains,
    ForeignInvokes,
    UnregisterPath,
    DropRustObject,
    AliasAcrossLanguages,
    HandleTransfer,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32RiskFeatures {
    pub foreign_retention_without_owned_anchor: bool,
    pub missing_unregister_before_drop: bool,
    pub cross_language_alias: bool,
    pub opaque_handle_without_owner: bool,
    pub callback_retained_across_drop: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32RankedCandidateRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_ranked_candidate_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub rank: u32,
    pub candidate_id: String,
    pub crate_id: String,
    pub pattern_family: V32PatternFamily,
    pub score: u32,
    pub score_breakdown: V32ScoreBreakdown,
    pub risk_features: V32RiskFeatures,
    pub lifecycle_graph_path: String,
    pub ranking_reason: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V32ScoreBreakdown {
    pub foreign_retention_without_owned_anchor: u32,
    pub missing_unregister_before_drop: u32,
    pub cross_language_alias: u32,
    pub opaque_handle_without_owner: u32,
    pub callback_retained_across_drop: u32,
    pub confidence_bonus: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V32LifecycleSummary {
    pub graph_count: u64,
    pub ranked_count: u64,
    pub max_score: u32,
}

pub fn lifecycle_graph_from_candidate(
    candidate: &V32CandidateRecord,
    run_id: &str,
) -> V32LifecycleGraph {
    let evidence_ref = first_evidence_ref(&candidate.evidence_refs);
    let api_label = candidate
        .api_path
        .clone()
        .unwrap_or_else(|| "unknown_api".to_owned());
    let (nodes, edges, risk_features) =
        template_for_pattern(candidate.pattern_family, &api_label, &evidence_ref);

    V32LifecycleGraph {
        schema_version: V3_2_LIFECYCLE_GRAPH_SCHEMA_V1.to_owned(),
        run_id: run_id.to_owned(),
        candidate_id: candidate.candidate_id.clone(),
        crate_id: candidate.crate_id.clone(),
        pattern_family: candidate.pattern_family,
        nodes,
        edges,
        risk_features,
        notes: vec![
            "lifecycle graph tracks boundary-related objects only".to_owned(),
            "graph is not a vulnerability conclusion".to_owned(),
            format!(
                "source_confidence={}",
                confidence_slug(candidate.confidence)
            ),
        ],
    }
}

fn confidence_slug(confidence: V32CandidateConfidence) -> &'static str {
    match confidence {
        V32CandidateConfidence::NeedsDynamicValidation => "needs_dynamic_validation",
        V32CandidateConfidence::StaticOnly => "static_only",
        V32CandidateConfidence::LowPriority => "low_priority",
    }
}

pub fn score_lifecycle_graph(
    graph: &V32LifecycleGraph,
    confidence: V32CandidateConfidence,
) -> (u32, V32ScoreBreakdown) {
    let features = &graph.risk_features;
    let breakdown = V32ScoreBreakdown {
        foreign_retention_without_owned_anchor: if features.foreign_retention_without_owned_anchor {
            SCORE_FOREIGN_RETENTION
        } else {
            0
        },
        missing_unregister_before_drop: if features.missing_unregister_before_drop {
            SCORE_MISSING_UNREGISTER
        } else {
            0
        },
        cross_language_alias: if features.cross_language_alias {
            SCORE_CROSS_LANGUAGE_ALIAS
        } else {
            0
        },
        opaque_handle_without_owner: if features.opaque_handle_without_owner {
            SCORE_OPAQUE_HANDLE
        } else {
            0
        },
        callback_retained_across_drop: if features.callback_retained_across_drop {
            SCORE_CALLBACK_ACROSS_DROP
        } else {
            0
        },
        confidence_bonus: match confidence {
            V32CandidateConfidence::NeedsDynamicValidation => SCORE_NEEDS_DYNAMIC,
            V32CandidateConfidence::StaticOnly => SCORE_STATIC_ONLY,
            V32CandidateConfidence::LowPriority => SCORE_LOW_PRIORITY,
        },
    };
    let score = breakdown.foreign_retention_without_owned_anchor
        + breakdown.missing_unregister_before_drop
        + breakdown.cross_language_alias
        + breakdown.opaque_handle_without_owner
        + breakdown.callback_retained_across_drop
        + breakdown.confidence_bonus;
    (score, breakdown)
}

pub fn ranking_reason(score: u32, features: &V32RiskFeatures, confidence_bonus: u32) -> String {
    let mut active = Vec::<&str>::new();
    if features.foreign_retention_without_owned_anchor {
        active.push("foreign_retention_without_owned_anchor");
    }
    if features.missing_unregister_before_drop {
        active.push("missing_unregister_before_drop");
    }
    if features.cross_language_alias {
        active.push("cross_language_alias");
    }
    if features.opaque_handle_without_owner {
        active.push("opaque_handle_without_owner");
    }
    if features.callback_retained_across_drop {
        active.push("callback_retained_across_drop");
    }
    let active_text = if active.is_empty() {
        "none".to_owned()
    } else {
        active.join(",")
    };
    format!(
        "score={score}; active_risk_features={active_text}; confidence_bonus={confidence_bonus}"
    )
}

pub fn validate_v3_2_lifecycle_graphs<I>(graphs: I) -> Result<u64, ModelError>
where
    I: IntoIterator<Item = Located<V32LifecycleGraph>>,
{
    let mut count = 0_u64;
    let mut ids = BTreeSet::<String>::new();
    for located in graphs {
        let graph = &located.value;
        validate_required_text_graph(&located, "run_id", &graph.run_id)?;
        validate_required_text_graph(&located, "candidate_id", &graph.candidate_id)?;
        validate_required_text_graph(&located, "crate_id", &graph.crate_id)?;
        reject_private_tokens_graph(&located, "run_id", &graph.run_id)?;
        reject_private_tokens_graph(&located, "candidate_id", &graph.candidate_id)?;
        reject_private_tokens_graph(&located, "crate_id", &graph.crate_id)?;
        for note in &graph.notes {
            reject_private_tokens_graph(&located, "notes", note)?;
        }
        if graph.nodes.is_empty() {
            return Err(at_graph(
                &located,
                "BW-LIFECYCLE-NODES-EMPTY",
                "lifecycle graph 必须至少包含一个 node",
            ));
        }
        if graph.edges.is_empty() {
            return Err(at_graph(
                &located,
                "BW-LIFECYCLE-EDGES-EMPTY",
                "lifecycle graph 必须至少包含一个 edge",
            ));
        }
        let node_ids = graph
            .nodes
            .iter()
            .map(|node| node.node_id.as_str())
            .collect::<BTreeSet<_>>();
        if node_ids.len() != graph.nodes.len() {
            return Err(at_graph(
                &located,
                "BW-LIFECYCLE-NODE-ID-DUPLICATE",
                "lifecycle graph node_id 不能重复",
            ));
        }
        for node in &graph.nodes {
            validate_required_text_graph(&located, "nodes.node_id", &node.node_id)?;
            validate_required_text_graph(&located, "nodes.label", &node.label)?;
            reject_private_tokens_graph(&located, "nodes.node_id", &node.node_id)?;
            reject_private_tokens_graph(&located, "nodes.label", &node.label)?;
        }
        for edge in &graph.edges {
            if !node_ids.contains(edge.from.as_str()) || !node_ids.contains(edge.to.as_str()) {
                return Err(at_graph(
                    &located,
                    "BW-LIFECYCLE-EDGE-ENDPOINT",
                    format!("edge {} -> {} 引用了不存在的 node_id", edge.from, edge.to),
                ));
            }
            validate_required_text_graph(&located, "edges.evidence_ref", &edge.evidence_ref)?;
            reject_private_tokens_graph(&located, "edges.from", &edge.from)?;
            reject_private_tokens_graph(&located, "edges.to", &edge.to)?;
            reject_private_tokens_graph(&located, "edges.evidence_ref", &edge.evidence_ref)?;
        }
        if !ids.insert(graph.candidate_id.clone()) {
            return Err(at_graph(
                &located,
                "BW-LIFECYCLE-CANDIDATE-DUPLICATE",
                format!(
                    "candidate_id {} 的 lifecycle graph 重复",
                    graph.candidate_id
                ),
            ));
        }
        count += 1;
    }
    Ok(count)
}

pub fn validate_v3_2_ranked_candidates<I>(records: I) -> Result<V32LifecycleSummary, ModelError>
where
    I: IntoIterator<Item = Located<V32RankedCandidateRecord>>,
{
    let mut summary = V32LifecycleSummary::default();
    let mut run_id: Option<String> = None;
    let mut ranks = BTreeSet::<u32>::new();
    let mut candidate_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text_ranked(&located, "run_id", &record.run_id)?;
        validate_required_text_ranked(&located, "candidate_id", &record.candidate_id)?;
        validate_required_text_ranked(&located, "crate_id", &record.crate_id)?;
        validate_required_text_ranked(
            &located,
            "lifecycle_graph_path",
            &record.lifecycle_graph_path,
        )?;
        validate_required_text_ranked(&located, "ranking_reason", &record.ranking_reason)?;
        reject_private_tokens_ranked(&located, "run_id", &record.run_id)?;
        reject_private_tokens_ranked(&located, "candidate_id", &record.candidate_id)?;
        reject_private_tokens_ranked(&located, "crate_id", &record.crate_id)?;
        reject_private_tokens_ranked(
            &located,
            "lifecycle_graph_path",
            &record.lifecycle_graph_path,
        )?;
        reject_private_tokens_ranked(&located, "ranking_reason", &record.ranking_reason)?;
        for note in &record.notes {
            reject_private_tokens_ranked(&located, "notes", note)?;
        }
        validate_relative_path_ranked(&located, &record.lifecycle_graph_path)?;

        if record.rank == 0 {
            return Err(at_ranked(&located, "BW-RANK-ZERO", "rank 必须从 1 开始"));
        }
        if !ranks.insert(record.rank) {
            return Err(at_ranked(
                &located,
                "BW-RANK-DUPLICATE",
                format!("rank {} 重复", record.rank),
            ));
        }
        if !candidate_ids.insert(record.candidate_id.clone()) {
            return Err(at_ranked(
                &located,
                "BW-RANK-CANDIDATE-DUPLICATE",
                format!("candidate_id {} 重复", record.candidate_id),
            ));
        }
        if let Some(expected) = &run_id {
            if expected != &record.run_id {
                return Err(at_ranked(
                    &located,
                    "BW-RANK-RUN-MISMATCH",
                    format!(
                        "同一 ranked candidates 文件出现 run_id {expected} 和 {}",
                        record.run_id
                    ),
                ));
            }
        } else {
            run_id = Some(record.run_id.clone());
        }

        let recomputed = recompute_score(&record.score_breakdown);
        if recomputed != record.score {
            return Err(at_ranked(
                &located,
                "BW-RANK-SCORE-MISMATCH",
                format!(
                    "score {} 与 score_breakdown 之和 {recomputed} 不一致",
                    record.score
                ),
            ));
        }
        summary.max_score = summary.max_score.max(record.score);
        summary.ranked_count += 1;
    }

    if !ranks.is_empty() {
        let expected = (1..=summary.ranked_count as u32).collect::<BTreeSet<_>>();
        if ranks != expected {
            return Err(ModelError::validation(
                "BW-RANK-SEQUENCE",
                "rank 必须是从 1 开始的连续编号",
            ));
        }
    }
    summary.graph_count = summary.ranked_count;
    Ok(summary)
}

fn template_for_pattern(
    pattern: V32PatternFamily,
    api_label: &str,
    evidence_ref: &str,
) -> (
    Vec<V32LifecycleNode>,
    Vec<V32LifecycleEdge>,
    V32RiskFeatures,
) {
    match pattern {
        V32PatternFamily::RetainedBorrowedCallback => (
            vec![
                node(
                    "n1",
                    V32LifecycleNodeKind::RustObject,
                    "callback-capture-object",
                    V32LifetimeRole::Borrowed,
                ),
                node(
                    "n2",
                    V32LifecycleNodeKind::ForeignApi,
                    api_label,
                    V32LifetimeRole::ExternalRetained,
                ),
                node(
                    "n3",
                    V32LifecycleNodeKind::ForeignOwner,
                    "external-owner",
                    V32LifetimeRole::ExternalRetained,
                ),
                node(
                    "n4",
                    V32LifecycleNodeKind::CallbackSite,
                    "callback-invoke-site",
                    V32LifetimeRole::Unknown,
                ),
            ],
            vec![
                edge(
                    "n1",
                    "n2",
                    V32LifecycleEdgeKind::RegisteredIntoForeignApi,
                    evidence_ref,
                ),
                edge(
                    "n2",
                    "n3",
                    V32LifecycleEdgeKind::ForeignRetains,
                    evidence_ref,
                ),
                edge(
                    "n3",
                    "n4",
                    V32LifecycleEdgeKind::ForeignInvokes,
                    evidence_ref,
                ),
                edge(
                    "n1",
                    "n1",
                    V32LifecycleEdgeKind::DropRustObject,
                    evidence_ref,
                ),
            ],
            V32RiskFeatures {
                foreign_retention_without_owned_anchor: true,
                missing_unregister_before_drop: true,
                cross_language_alias: true,
                opaque_handle_without_owner: false,
                callback_retained_across_drop: true,
            },
        ),
        V32PatternFamily::CallbackLifecycleRelease => (
            vec![
                node(
                    "n1",
                    V32LifecycleNodeKind::RustObject,
                    "callback-capture-object",
                    V32LifetimeRole::Borrowed,
                ),
                node(
                    "n2",
                    V32LifecycleNodeKind::ForeignApi,
                    api_label,
                    V32LifetimeRole::ExternalRetained,
                ),
                node(
                    "n3",
                    V32LifecycleNodeKind::ForeignOwner,
                    "external-owner",
                    V32LifetimeRole::ExternalRetained,
                ),
            ],
            vec![
                edge(
                    "n1",
                    "n2",
                    V32LifecycleEdgeKind::RegisteredIntoForeignApi,
                    evidence_ref,
                ),
                edge(
                    "n2",
                    "n3",
                    V32LifecycleEdgeKind::ForeignRetains,
                    evidence_ref,
                ),
                edge(
                    "n2",
                    "n1",
                    V32LifecycleEdgeKind::UnregisterPath,
                    evidence_ref,
                ),
            ],
            V32RiskFeatures {
                foreign_retention_without_owned_anchor: false,
                missing_unregister_before_drop: false,
                cross_language_alias: true,
                opaque_handle_without_owner: false,
                callback_retained_across_drop: false,
            },
        ),
        V32PatternFamily::ForeignRetainedPointer => (
            vec![
                node(
                    "n1",
                    V32LifecycleNodeKind::RustObject,
                    "rust-buffer-or-object",
                    V32LifetimeRole::Borrowed,
                ),
                node(
                    "n2",
                    V32LifecycleNodeKind::ForeignApi,
                    api_label,
                    V32LifetimeRole::ExternalRetained,
                ),
                node(
                    "n3",
                    V32LifecycleNodeKind::ForeignOwner,
                    "foreign-retained-pointer",
                    V32LifetimeRole::ExternalRetained,
                ),
            ],
            vec![
                edge(
                    "n1",
                    "n2",
                    V32LifecycleEdgeKind::AliasAcrossLanguages,
                    evidence_ref,
                ),
                edge(
                    "n2",
                    "n3",
                    V32LifecycleEdgeKind::ForeignRetains,
                    evidence_ref,
                ),
                edge(
                    "n1",
                    "n1",
                    V32LifecycleEdgeKind::DropRustObject,
                    evidence_ref,
                ),
            ],
            V32RiskFeatures {
                foreign_retention_without_owned_anchor: true,
                missing_unregister_before_drop: false,
                cross_language_alias: true,
                opaque_handle_without_owner: false,
                callback_retained_across_drop: false,
            },
        ),
        V32PatternFamily::OpaqueHandleTransfer => (
            vec![
                node(
                    "n1",
                    V32LifecycleNodeKind::RustObject,
                    "rust-owner-context",
                    V32LifetimeRole::Owned,
                ),
                node(
                    "n2",
                    V32LifecycleNodeKind::OpaqueHandle,
                    api_label,
                    V32LifetimeRole::Unknown,
                ),
                node(
                    "n3",
                    V32LifecycleNodeKind::ForeignApi,
                    "foreign-handle-consumer",
                    V32LifetimeRole::ExternalRetained,
                ),
            ],
            vec![
                edge(
                    "n1",
                    "n2",
                    V32LifecycleEdgeKind::HandleTransfer,
                    evidence_ref,
                ),
                edge(
                    "n2",
                    "n3",
                    V32LifecycleEdgeKind::AliasAcrossLanguages,
                    evidence_ref,
                ),
            ],
            V32RiskFeatures {
                foreign_retention_without_owned_anchor: false,
                missing_unregister_before_drop: false,
                cross_language_alias: true,
                opaque_handle_without_owner: true,
                callback_retained_across_drop: false,
            },
        ),
        V32PatternFamily::NativeLibraryBoundary => (
            vec![
                node(
                    "n1",
                    V32LifecycleNodeKind::RustObject,
                    "rust-wrapper-state",
                    V32LifetimeRole::Owned,
                ),
                node(
                    "n2",
                    V32LifecycleNodeKind::ForeignApi,
                    api_label,
                    V32LifetimeRole::Unknown,
                ),
            ],
            vec![edge(
                "n1",
                "n2",
                V32LifecycleEdgeKind::AliasAcrossLanguages,
                evidence_ref,
            )],
            V32RiskFeatures {
                foreign_retention_without_owned_anchor: false,
                missing_unregister_before_drop: false,
                cross_language_alias: true,
                opaque_handle_without_owner: false,
                callback_retained_across_drop: false,
            },
        ),
        V32PatternFamily::ReturnedBorrowView => (
            vec![
                node(
                    "n1",
                    V32LifecycleNodeKind::RustObject,
                    "borrow-source",
                    V32LifetimeRole::Borrowed,
                ),
                node(
                    "n2",
                    V32LifecycleNodeKind::RustObject,
                    api_label,
                    V32LifetimeRole::Unknown,
                ),
            ],
            vec![edge(
                "n1",
                "n2",
                V32LifecycleEdgeKind::AliasAcrossLanguages,
                evidence_ref,
            )],
            V32RiskFeatures {
                foreign_retention_without_owned_anchor: false,
                missing_unregister_before_drop: false,
                cross_language_alias: false,
                opaque_handle_without_owner: false,
                callback_retained_across_drop: false,
            },
        ),
        V32PatternFamily::ExternalBufferView => (
            vec![
                node(
                    "n1",
                    V32LifecycleNodeKind::RustObject,
                    "buffer-source",
                    V32LifetimeRole::Borrowed,
                ),
                node(
                    "n2",
                    V32LifecycleNodeKind::ForeignApi,
                    api_label,
                    V32LifetimeRole::Unknown,
                ),
            ],
            vec![edge(
                "n1",
                "n2",
                V32LifecycleEdgeKind::AliasAcrossLanguages,
                evidence_ref,
            )],
            V32RiskFeatures {
                foreign_retention_without_owned_anchor: false,
                missing_unregister_before_drop: false,
                cross_language_alias: true,
                opaque_handle_without_owner: false,
                callback_retained_across_drop: false,
            },
        ),
    }
}

fn node(
    id: &str,
    kind: V32LifecycleNodeKind,
    label: &str,
    role: V32LifetimeRole,
) -> V32LifecycleNode {
    V32LifecycleNode {
        node_id: id.to_owned(),
        node_kind: kind,
        label: label.to_owned(),
        lifetime_role: role,
    }
}

fn edge(from: &str, to: &str, kind: V32LifecycleEdgeKind, evidence_ref: &str) -> V32LifecycleEdge {
    V32LifecycleEdge {
        from: from.to_owned(),
        to: to.to_owned(),
        edge_kind: kind,
        evidence_ref: evidence_ref.to_owned(),
    }
}

fn first_evidence_ref(refs: &[V32BoundaryEvidenceRef]) -> String {
    refs.first()
        .map(|evidence| match (evidence.line_start, evidence.line_end) {
            (Some(start), Some(end)) if start == end => format!("{}:{start}", evidence.path),
            (Some(start), Some(end)) => format!("{}:{start}-{end}", evidence.path),
            _ => evidence.path.clone(),
        })
        .unwrap_or_else(|| "evidence:unknown".to_owned())
}

fn recompute_score(breakdown: &V32ScoreBreakdown) -> u32 {
    breakdown.foreign_retention_without_owned_anchor
        + breakdown.missing_unregister_before_drop
        + breakdown.cross_language_alias
        + breakdown.opaque_handle_without_owner
        + breakdown.callback_retained_across_drop
        + breakdown.confidence_bonus
}

fn validate_required_text_graph(
    located: &Located<V32LifecycleGraph>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at_graph(
            located,
            "BW-LIFECYCLE-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_required_text_ranked(
    located: &Located<V32RankedCandidateRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at_ranked(
            located,
            "BW-RANK-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_relative_path_ranked(
    located: &Located<V32RankedCandidateRecord>,
    value: &str,
) -> Result<(), ModelError> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(at_ranked(
            located,
            "BW-RANK-PATH",
            "lifecycle_graph_path 必须是相对路径，不能是绝对路径或包含 ..",
        ));
    }
    Ok(())
}

fn reject_private_tokens_graph(
    located: &Located<V32LifecycleGraph>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_private(field, value)
        .map_err(|message| at_graph(located, "BW-LIFECYCLE-PRIVATE-TOKEN", message))
}

fn reject_private_tokens_ranked(
    located: &Located<V32RankedCandidateRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_private(field, value)
        .map_err(|message| at_ranked(located, "BW-RANK-PRIVATE-TOKEN", message))
}

fn reject_private(field: &'static str, value: &str) -> Result<(), String> {
    reject_public_forbidden_token(field, value)
}

fn at_graph(
    located: &Located<V32LifecycleGraph>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, message).at_line(located.path.clone(), located.line)
}

fn at_ranked(
    located: &Located<V32RankedCandidateRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, message).at_line(located.path.clone(), located.line)
}
