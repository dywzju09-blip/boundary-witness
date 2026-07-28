//! V3.2.6 证据驱动生命周期分析与排序模型。
//!
//! 本模块只描述中性生命周期证据、特征与匿名 pair 可分性结论，
//! 不把 candidate 表述为真实缺陷结论。

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AtomicOperationKind, AtomicOrderingKind, Located, ModelError, ObjectBindingGapKind,
    ObjectFlowKind, ObjectFlowObjectKind, ReturnedBorrowInvalidationOrdering,
    ReturnedBorrowRelationKind, StaticFact, StaticFactEnvelope, V32BoundaryEvidenceKind,
    V32CandidateRecord, V32PatternFamily,
};

pub const V3_2_6_LIFECYCLE_EVIDENCE_SCHEMA_V1: &str = "v3.2.6.lifecycle_evidence.1";
pub const V3_2_6_LIFECYCLE_FACT_SCHEMA_V1: &str = "v3.2.6.lifecycle_fact.1";
pub const V3_2_6_LIFECYCLE_COVERAGE_SCHEMA_V1: &str = "v3.2.6.lifecycle_coverage.1";
pub const V3_2_6_LIFECYCLE_FEATURE_SCHEMA_V1: &str = "v3.2.6.lifecycle_feature.1";
pub const V3_2_6_LIFECYCLE_GRAPH_SCHEMA_V1: &str = "v3.2.6.lifecycle_graph_v2.1";
pub const V3_2_6_LIFECYCLE_GRAPH_V3_SCHEMA_V1: &str = "v3.2.6.lifecycle_graph_v3.1";
pub const V3_2_6_RANKED_CANDIDATE_SCHEMA_V1: &str = "v3.2.6.ranked_candidate_v2.1";
pub const V3_2_6_ANONYMOUS_PAIR_SCHEMA_V1: &str = "v3.2.6.anonymous_pair.1";
pub const V3_2_6_PAIR_DELTA_SCHEMA_V1: &str = "v3.2.6.pair_delta.1";
pub const V3_2_7_PAIR_DELTA_SCHEMA_V1: &str = "v3.2.7.pair_delta.1";
pub const V3_2_6_LIFECYCLE_CONTRACT_SCHEMA_V1: &str = "v3.2.6.lifecycle_contract.1";
pub const V3_2_6_WITNESS_PLAN_SCHEMA_V1: &str = "v3.2.6.witness_plan.1";

const SCORE_HAS_FOREIGN_REGISTER: i32 = 4;
const SCORE_FOREIGN_MAY_RETAIN_CALLBACK: i32 = 8;
const SCORE_FOREIGN_MAY_RETAIN_USER_DATA: i32 = 8;
const SCORE_HAS_BORROWED_CAPTURE: i32 = 10;
const SCORE_HAS_RAW_POINTER_ESCAPE: i32 = 10;
const SCORE_RAW_PARTS_TRANSFER_WITHOUT_DROP_PREVENTION: i32 = 31;
const SCORE_RAW_PARTS_TRANSFER_WITHOUT_DROP_PREVENTION_OWNER_ANCHOR_ONLY: i32 = 20;
const SCORE_HAS_DROP_PREVENTION: i32 = 20;
const SCORE_MANUAL_DROP_PREVENTION_WITHOUT_DROP_GUARD: i32 = 6;
const SCORE_CALLBACK_USER_DATA_OWNER_RECONSTRUCTION_WITHOUT_LEAK_GUARD: i32 = 34;
const SCORE_HAS_RETURNED_BORROW_RELATION: i32 = 8;
const SCORE_HAS_UNCONSTRAINED_RETURN_LIFETIME: i32 = 6;
const SCORE_HAS_PERSISTED_RETURNED_BORROW: i32 = 4;
const SCORE_RETURNED_BORROW_PERSISTENCE_BEFORE_INVALIDATION: i32 = 14;
const SCORE_RETURNED_BORROW_PERSISTENCE_AFTER_INVALIDATION: i32 = -12;
const SCORE_HAS_EXTERNAL_BUFFER_BINDING: i32 = 8;
const SCORE_EXTERNAL_BUFFER_WITHOUT_STATIC_BOUND: i32 = 10;
const SCORE_HAS_EXTERNAL_BUFFER_LIFETIME_BOUND: i32 = -6;
const SCORE_RELAXED_ATOMIC_LOAD_IN_ITERATOR: i32 = 12;
const SCORE_ACQUIRE_ATOMIC_LOAD_IN_ITERATOR: i32 = -6;
const SCORE_HAS_VERIFIED_OBJECT_CHAIN: i32 = 4;
const SCORE_HAS_RELEASE_ORDER_CHAIN: i32 = -4;
const SCORE_HAS_PERSISTED_INVALIDATION_USE_CHAIN: i32 = 6;
const SCORE_HAS_CALLBACK_RELEASE_USE_CHAIN: i32 = 8;
const SCORE_RUST_OBJECT_MAY_DROP_BEFORE_FOREIGN_RELEASE: i32 = 15;
const SCORE_MISSING_UNREGISTER_BEFORE_DROP: i32 = 10;
const SCORE_RELEASE_ORDER_UNKNOWN: i32 = 5;
const SCORE_OPAQUE_HANDLE_WITHOUT_OWNER: i32 = 8;
const SCORE_NEEDS_DYNAMIC_WITNESS: i32 = 5;
const SCORE_HAS_OWNED_ANCHOR: i32 = -12;
const SCORE_HAS_DROP_GUARD: i32 = -10;
const SCORE_REGISTRATION_RELEASE_PAIR_FOUND: i32 = -8;
const SCORE_HAS_STATIC_BOUND: i32 = -6;
const SCORE_HAS_ARC_ANCHOR: i32 = -8;
const SCORE_RELEASE_COVERS_CALLBACK: i32 = -8;
pub const V3_2_6_EXTERNAL_BUFFER_RETURN_LIFETIME_SIGNAL: &str =
    "return lifetime covers external buffer inputs";
const PUBLIC_FORBIDDEN_TOKENS: [&str; 9] = [
    "vulnerable",
    "fixed",
    "cve",
    "ghsa",
    "expected",
    "patch",
    "advisory",
    "poc",
    "exploit",
];

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleEvidenceRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_lifecycle_evidence_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub record_id: String,
    pub crate_id: String,
    pub candidate_id: String,
    pub evidence_kind: V326EvidenceKind,
    pub source_ref: V326SourceRef,
    pub confidence: V326EvidenceConfidence,
    #[serde(default)]
    pub details: serde_json::Value,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326SourceRef {
    pub path: String,
    pub line_start: Option<u64>,
    pub line_end: Option<u64>,
    pub symbol_path: Option<String>,
    pub text_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326EvidenceKind {
    CallbackCandidate,
    ObjectCandidate,
    CaptureEdge,
    BorrowEdge,
    MoveEdge,
    RawPointerEscape,
    ForeignRegister,
    ForeignUnregister,
    ForeignReplace,
    ForeignRetentionHint,
    DropSite,
    DropGuard,
    ReleaseSite,
    OwnedAnchor,
    LifetimeBound,
    OpaqueHandleTransfer,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326EvidenceConfidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326LifecycleEvidenceSummary {
    pub record_count: u64,
    pub high_confidence_count: u64,
    pub medium_confidence_count: u64,
    pub low_confidence_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleGraphRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_lifecycle_graph_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub candidate_id: String,
    pub crate_id: String,
    pub pattern_family: V32PatternFamily,
    pub nodes: Vec<V326LifecycleNode>,
    pub edges: Vec<V326LifecycleEdge>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub incomplete_evidence: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleNode {
    pub node_id: String,
    pub node_kind: V326LifecycleNodeKind,
    pub label: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326LifecycleNodeKind {
    RustObject,
    Callback,
    Borrow,
    RawPointer,
    ForeignApi,
    ForeignOwner,
    DropGuard,
    ReleaseApi,
    OpaqueHandle,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleEdge {
    pub from: String,
    pub to: String,
    pub edge_kind: V326LifecycleEdgeKind,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326LifecycleEdgeKind {
    Captures,
    Borrows,
    MovesInto,
    RawPointerEscape,
    RegisteredInto,
    ForeignRetains,
    ReleasedBy,
    GuardedByDrop,
    DropsBeforeRelease,
    UnknownOrder,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleFeatureRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_lifecycle_feature_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub candidate_id: String,
    pub crate_id: String,
    pub pattern_family: V32PatternFamily,
    pub features: V326FeatureSet,
    pub feature_evidence: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub missing_evidence: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326FeatureSet {
    pub has_foreign_register: bool,
    pub foreign_may_retain_callback: bool,
    pub foreign_may_retain_user_data: bool,
    pub has_borrowed_capture: bool,
    pub has_raw_pointer_escape: bool,
    #[serde(default)]
    pub raw_parts_transfer_without_drop_prevention: bool,
    #[serde(default)]
    pub has_drop_prevention: bool,
    #[serde(default)]
    pub manual_drop_prevention_without_drop_guard: bool,
    #[serde(default)]
    pub callback_user_data_owner_reconstruction_without_leak_guard: bool,
    #[serde(default)]
    pub has_returned_borrow_relation: bool,
    #[serde(default)]
    pub has_unconstrained_return_lifetime: bool,
    #[serde(default)]
    pub has_persisted_returned_borrow: bool,
    #[serde(default)]
    pub returned_borrow_persistence_before_invalidation: bool,
    #[serde(default)]
    pub returned_borrow_persistence_after_invalidation: bool,
    #[serde(default)]
    pub has_external_buffer_binding: bool,
    #[serde(default)]
    pub has_external_buffer_lifetime_bound: bool,
    #[serde(default)]
    pub relaxed_atomic_load_in_iterator: bool,
    #[serde(default)]
    pub acquire_atomic_load_in_iterator: bool,
    #[serde(default)]
    pub has_verified_object_chain: bool,
    #[serde(default)]
    pub has_release_order_chain: bool,
    #[serde(default)]
    pub has_persisted_invalidation_use_chain: bool,
    #[serde(default)]
    pub has_callback_release_use_chain: bool,
    pub rust_object_may_drop_before_foreign_release: bool,
    pub missing_unregister_before_drop: bool,
    pub release_order_unknown: bool,
    pub opaque_handle_without_owner: bool,
    pub needs_dynamic_witness: bool,
    pub has_foreign_unregister: bool,
    pub registration_release_pair_found: bool,
    pub has_drop_guard: bool,
    pub has_owned_anchor: bool,
    pub has_static_bound: bool,
    pub has_box_into_raw: bool,
    pub has_box_from_raw: bool,
    pub has_arc_anchor: bool,
    pub release_covers_callback: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326LifecycleFeatureSummary {
    pub record_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326RankedCandidateRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_ranked_candidate_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub rank: u32,
    pub score: u32,
    pub score_breakdown: V326ScoreBreakdown,
    pub candidate_id: String,
    pub crate_id: String,
    pub pattern_family: V32PatternFamily,
    pub risk_features: Vec<String>,
    pub protective_features: Vec<String>,
    pub feature_evidence_refs: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub missing_evidence: Vec<String>,
    pub lifecycle_graph_path: String,
    #[serde(default)]
    pub chain_summary: V326RankedChainSummary,
    pub ranking_reason: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326RankedChainSummary {
    #[serde(default)]
    pub top_chain_id: Option<String>,
    #[serde(default)]
    pub top_chain_status: Option<V326ObjectChainStatus>,
    #[serde(default)]
    pub verified_chain_count: u32,
    #[serde(default)]
    pub partial_chain_count: u32,
    #[serde(default)]
    pub ambiguous_chain_count: u32,
    #[serde(default)]
    pub observation_only_chain_count: u32,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub identity_transport_chain_count: u32,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub release_ordering_chain_count: u32,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub use_ordering_chain_count: u32,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub lifecycle_ordering_chain_count: u32,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub complete_risk_chain_count: u32,
    #[serde(default)]
    pub chain_fact_refs: Vec<String>,
    #[serde(default)]
    pub chain_incomplete_reasons: Vec<String>,
    #[serde(default)]
    pub recommended_witness_route: V326WitnessRoute,
}

impl Default for V326RankedChainSummary {
    fn default() -> Self {
        Self {
            top_chain_id: None,
            top_chain_status: None,
            verified_chain_count: 0,
            partial_chain_count: 0,
            ambiguous_chain_count: 0,
            observation_only_chain_count: 0,
            identity_transport_chain_count: 0,
            release_ordering_chain_count: 0,
            use_ordering_chain_count: 0,
            lifecycle_ordering_chain_count: 0,
            complete_risk_chain_count: 0,
            chain_fact_refs: Vec::new(),
            chain_incomplete_reasons: Vec::new(),
            recommended_witness_route: V326WitnessRoute::ManualReviewOnly,
        }
    }
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326WitnessRoute {
    CallbackLifecycle,
    ReturnedViewMiri,
    ExternalBufferLifetime,
    #[default]
    ManualReviewOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326ScoreBreakdown {
    pub has_foreign_register: i32,
    pub foreign_may_retain_callback: i32,
    pub foreign_may_retain_user_data: i32,
    pub has_borrowed_capture: i32,
    pub has_raw_pointer_escape: i32,
    #[serde(default)]
    pub raw_parts_transfer_without_drop_prevention: i32,
    #[serde(default)]
    pub has_drop_prevention: i32,
    #[serde(default)]
    pub manual_drop_prevention_without_drop_guard: i32,
    #[serde(default)]
    pub callback_user_data_owner_reconstruction_without_leak_guard: i32,
    #[serde(default)]
    pub has_returned_borrow_relation: i32,
    #[serde(default)]
    pub has_unconstrained_return_lifetime: i32,
    #[serde(default)]
    pub has_persisted_returned_borrow: i32,
    #[serde(default)]
    pub returned_borrow_persistence_before_invalidation: i32,
    #[serde(default)]
    pub returned_borrow_persistence_after_invalidation: i32,
    #[serde(default)]
    pub has_external_buffer_binding: i32,
    #[serde(default)]
    pub has_external_buffer_lifetime_bound: i32,
    #[serde(default)]
    pub relaxed_atomic_load_in_iterator: i32,
    #[serde(default)]
    pub acquire_atomic_load_in_iterator: i32,
    #[serde(default)]
    pub has_verified_object_chain: i32,
    #[serde(default)]
    pub has_release_order_chain: i32,
    #[serde(default)]
    pub has_persisted_invalidation_use_chain: i32,
    #[serde(default)]
    pub has_callback_release_use_chain: i32,
    pub rust_object_may_drop_before_foreign_release: i32,
    pub missing_unregister_before_drop: i32,
    pub release_order_unknown: i32,
    pub opaque_handle_without_owner: i32,
    pub needs_dynamic_witness: i32,
    pub has_owned_anchor: i32,
    pub has_drop_guard: i32,
    pub registration_release_pair_found: i32,
    pub has_static_bound: i32,
    pub has_arc_anchor: i32,
    pub release_covers_callback: i32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326RankedCandidateSummary {
    pub ranked_count: u64,
    pub max_score: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326AnonymousPairRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_anonymous_pair_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub pair_id: String,
    pub left_crate_id: String,
    pub right_crate_id: String,
    pub relation_hint: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326Distinguishability {
    SeparableStatic,
    IndistinguishableStaticOnly,
    InsufficientEvidence,
    Unpaired,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326PairDeltaRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_pair_delta_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub pair_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comparison_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pair_manifest_run_id: String,
    pub left_crate_id: String,
    pub right_crate_id: String,
    pub left_top_features: Vec<String>,
    pub right_top_features: Vec<String>,
    pub semantic_delta: Vec<String>,
    pub distinguishability: V326Distinguishability,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleFactRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_lifecycle_fact_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub candidate_id: String,
    pub crate_id: String,
    pub fact_id: String,
    pub fact_kind: V326LifecycleFactKind,
    pub source_ref: V326SourceRef,
    pub symbol_path: Option<String>,
    pub confidence: V326EvidenceConfidence,
    pub coverage_state: V326CoverageState,
    /// Required for `v3.2.6.lifecycle_fact.1`. Missing fields fail deserialization
    /// rather than defaulting to `legacy` and silently accepting unauthenticated facts.
    pub provenance: V326LifecycleFactProvenance,
    #[serde(default)]
    pub object_ids: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326LifecycleFactOrigin {
    #[default]
    Legacy,
    SourceObservation,
    StaticArtifact,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleFactProvenance {
    #[serde(default)]
    pub origin: V326LifecycleFactOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_fact_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_build_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_producer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_anchor_record_ids: Vec<String>,
    #[serde(skip)]
    static_artifact_verified: bool,
}

impl V326LifecycleFactProvenance {
    pub fn source_observation() -> Self {
        Self {
            origin: V326LifecycleFactOrigin::SourceObservation,
            ..Self::default()
        }
    }

    pub fn static_artifact(envelope: &StaticFactEnvelope) -> Self {
        Self {
            origin: V326LifecycleFactOrigin::StaticArtifact,
            static_fact_record_id: Some(envelope.record_id.to_string()),
            static_build_id: Some(envelope.build_id.to_string()),
            static_producer: Some(envelope.producer.clone()),
            static_anchor_record_ids: Vec::new(),
            static_artifact_verified: false,
        }
    }

    fn is_verified_static_artifact(&self) -> bool {
        self.origin == V326LifecycleFactOrigin::StaticArtifact && self.static_artifact_verified
    }
}

pub fn verify_v3_2_6_lifecycle_fact_static_provenance(
    fact: &mut V326LifecycleFactRecord,
    candidate: &V32CandidateRecord,
    static_facts: &[StaticFactEnvelope],
) -> bool {
    fact.provenance.static_artifact_verified = false;
    if fact.provenance.origin != V326LifecycleFactOrigin::StaticArtifact {
        return false;
    }

    if fact.candidate_id != candidate.candidate_id || fact.crate_id != candidate.crate_id {
        return false;
    }

    let verified = static_facts
        .iter()
        .find(|envelope| {
            fact.provenance.static_fact_record_id.as_deref() == Some(envelope.record_id.as_str())
                && fact.provenance.static_build_id.as_deref() == Some(envelope.build_id.as_str())
                && fact.provenance.static_producer.as_deref() == Some(envelope.producer.as_str())
                && static_fact_matches_candidate_artifact(envelope, candidate)
        })
        .is_some_and(|envelope| {
            let Some((fact_kind, symbol_path, object_ids)) = lifecycle_static_fact_fields(envelope)
            else {
                return false;
            };
            fact.fact_kind == fact_kind
                && fact.symbol_path == symbol_path
                && fact.object_ids == object_ids
                && static_fact_source_ref_matches(envelope, &fact.source_ref)
                && static_release_path_proof_is_consistent(envelope, static_facts)
                && static_fact_provenance_is_anchored_to_candidate(
                    &fact.provenance,
                    candidate,
                    envelope,
                    static_facts,
                )
        });
    fact.provenance.static_artifact_verified = verified;
    verified
}

fn static_fact_provenance_is_anchored_to_candidate(
    provenance: &V326LifecycleFactProvenance,
    candidate: &V32CandidateRecord,
    envelope: &StaticFactEnvelope,
    static_facts: &[StaticFactEnvelope],
) -> bool {
    if !static_fact_matches_candidate_artifact(envelope, candidate) {
        return false;
    }
    if provenance.static_anchor_record_ids.is_empty() {
        return false;
    }
    let anchors = provenance
        .static_anchor_record_ids
        .iter()
        .filter_map(|record_id| {
            static_facts.iter().find(|candidate_envelope| {
                candidate_envelope.record_id.as_str() == record_id
                    && static_fact_same_static_artifact(candidate_envelope, envelope)
            })
        })
        .collect::<Vec<_>>();
    if anchors.len() != provenance.static_anchor_record_ids.len()
        || anchors
            .iter()
            .any(|anchor| !static_fact_is_candidate_anchor(anchor, candidate))
    {
        return false;
    }

    static_fact_reachable_from_anchors(envelope, &anchors, static_facts)
}

fn static_fact_is_candidate_anchor(
    envelope: &StaticFactEnvelope,
    candidate: &V32CandidateRecord,
) -> bool {
    if !static_fact_matches_candidate_artifact(envelope, candidate) {
        return false;
    }
    let source_ref = static_fact_source_ref(envelope);
    let source_span_matches = source_ref.line_start.is_some_and(|source_start| {
        let source_end = source_ref.line_end.unwrap_or(source_start);
        candidate.evidence_refs.iter().any(|reference| {
            reference.kind == V32BoundaryEvidenceKind::SourceSpan
                && normalize_static_path(&reference.path) == source_ref.path
                && reference.line_start.is_some_and(|candidate_start| {
                    reference.line_end.is_some_and(|candidate_end| {
                        source_range_matches_candidate_span(
                            source_start,
                            source_end,
                            candidate_start,
                            candidate_end,
                        )
                    })
                })
        })
    });
    source_span_matches
        || candidate_source_api_matches_static_fact(candidate, envelope)
        || (!candidate_has_source_span(candidate)
            && candidate.api_path.as_deref().is_some_and(|candidate_api| {
                let candidate_api = candidate_api.trim();
                static_fact_api_or_symbol(envelope)
                    .is_some_and(|fact_api| candidate_api.eq_ignore_ascii_case(fact_api.trim()))
            }))
}

fn source_range_matches_candidate_span(
    source_start: u64,
    source_end: u64,
    candidate_start: u64,
    candidate_end: u64,
) -> bool {
    let (source_start, source_end) = ordered_range(source_start, source_end);
    let (candidate_start, candidate_end) = ordered_range(candidate_start, candidate_end);
    source_start <= candidate_end.saturating_add(3)
        && source_end >= candidate_start.saturating_sub(3)
}

fn ordered_range(start: u64, end: u64) -> (u64, u64) {
    if start <= end {
        (start, end)
    } else {
        (end, start)
    }
}

fn candidate_has_source_span(candidate: &V32CandidateRecord) -> bool {
    candidate.evidence_refs.iter().any(|reference| {
        reference.kind == V32BoundaryEvidenceKind::SourceSpan
            && reference.line_start.is_some()
            && reference.line_end.is_some()
    })
}

fn candidate_source_api_matches_static_fact(
    candidate: &V32CandidateRecord,
    envelope: &StaticFactEnvelope,
) -> bool {
    candidate.api_path.as_deref().is_some_and(|candidate_api| {
        let candidate_api = candidate_api.trim();
        is_source_api_alias(candidate_api)
            && static_fact_source_api_aliases(envelope)
                .iter()
                .any(|alias| candidate_api.eq_ignore_ascii_case(alias))
    })
}

fn is_source_api_alias(api_path: &str) -> bool {
    api_path.trim().starts_with("source_api::")
}

fn static_fact_reachable_from_anchors(
    envelope: &StaticFactEnvelope,
    anchors: &[&StaticFactEnvelope],
    static_facts: &[StaticFactEnvelope],
) -> bool {
    const MAX_STATIC_SITE_HOPS: usize = 2;
    let mut reachable_record_ids = anchors
        .iter()
        .map(|anchor| anchor.record_id.to_string())
        .collect::<BTreeSet<_>>();
    let mut linked_sites = anchors
        .iter()
        .flat_map(|anchor| static_fact_site_ids(anchor))
        .collect::<BTreeSet<_>>();

    for _ in 0..MAX_STATIC_SITE_HOPS {
        let next = static_facts
            .iter()
            .filter(|candidate_envelope| {
                static_fact_same_static_artifact(candidate_envelope, envelope)
            })
            .filter(|candidate_envelope| {
                static_fact_site_ids(candidate_envelope)
                    .iter()
                    .any(|site_id| linked_sites.contains(site_id))
            })
            .collect::<Vec<_>>();
        let mut changed = false;
        for next_envelope in next {
            changed |= reachable_record_ids.insert(next_envelope.record_id.to_string());
            linked_sites.extend(static_fact_site_ids(next_envelope));
        }
        if !changed {
            break;
        }
    }

    reachable_record_ids.contains(envelope.record_id.as_str())
}

fn static_fact_same_static_artifact(left: &StaticFactEnvelope, right: &StaticFactEnvelope) -> bool {
    left.producer == right.producer
        && left.build_id == right.build_id
        && left.artifact == right.artifact
}

fn static_fact_source_ref_matches(
    envelope: &StaticFactEnvelope,
    source_ref: &V326SourceRef,
) -> bool {
    let expected = static_fact_source_ref(envelope);
    expected.path == normalize_static_path(&source_ref.path)
        && expected.line_start.is_some()
        && expected.line_start == source_ref.line_start
        && expected.line_end == source_ref.line_end
}

fn static_fact_source_ref(envelope: &StaticFactEnvelope) -> V326SourceRef {
    let source_ref = envelope
        .source_ref
        .as_ref()
        .expect("authoritative static facts always carry source_ref");
    V326SourceRef {
        path: normalize_static_path(&source_ref.path),
        line_start: Some(source_ref.line_start),
        line_end: Some(source_ref.line_end),
        symbol_path: source_ref
            .symbol_path
            .clone()
            .or_else(|| static_fact_api_or_symbol(envelope)),
        text_sha256: None,
    }
}

fn static_fact_matches_candidate_artifact(
    envelope: &StaticFactEnvelope,
    candidate: &V32CandidateRecord,
) -> bool {
    envelope.is_authoritative_lifecycle_binding()
        && envelope
            .artifact
            .as_ref()
            .is_some_and(|artifact| artifact.crate_id == candidate.crate_id)
}

fn static_fact_api_or_symbol(envelope: &StaticFactEnvelope) -> Option<String> {
    match &envelope.payload {
        StaticFact::ObjectSite(fact) => Some(fact.type_name.clone()),
        StaticFact::CallbackSite(fact) => Some(fact.def_path.clone()),
        StaticFact::RegistrationSite(fact) => Some(fact.api_id.clone()),
        StaticFact::ExternalCallSite(fact) => Some(fact.api_id.clone()),
        StaticFact::ReturnedBorrowRelation(fact) => Some(fact.api_id.clone()),
        StaticFact::PersistedReturnedBorrow(fact) => Some(fact.api_id.clone()),
        StaticFact::ReturnedBorrowInvalidationOrder(fact) => Some(fact.api_id.clone()),
        StaticFact::ExternalBufferBinding(fact) => Some(fact.api_id.clone()),
        StaticFact::AtomicOrdering(fact) => Some(fact.api_id.clone()),
        StaticFact::ObjectBindingGap(fact) => Some(fact.api_id.clone()),
        StaticFact::ObjectFlow(fact) => Some(fact.api_id.clone()),
        StaticFact::CallbackReleaseUseOrder(fact) => Some(fact.api_id.clone()),
        StaticFact::CallbackCapture(_)
        | StaticFact::DropSite(_)
        | StaticFact::DropPrevention(_)
        | StaticFact::CallbackUserDataReconstruction(_)
        | StaticFact::RawPointerTransfer(_)
        | StaticFact::ReleasePathProof(_) => None,
    }
}

fn static_fact_site_ids(envelope: &StaticFactEnvelope) -> Vec<String> {
    match &envelope.payload {
        StaticFact::ObjectSite(fact) => vec![fact.site_id.to_string()],
        StaticFact::CallbackSite(fact) => vec![fact.site_id.to_string()],
        StaticFact::CallbackCapture(fact) => vec![
            fact.site_id.to_string(),
            fact.callback_site_id.to_string(),
            fact.object_site_id.to_string(),
        ],
        StaticFact::DropSite(fact) => {
            vec![fact.site_id.to_string(), fact.object_site_id.to_string()]
        }
        StaticFact::DropPrevention(fact) => {
            vec![fact.site_id.to_string(), fact.object_site_id.to_string()]
        }
        StaticFact::CallbackUserDataReconstruction(fact) => vec![
            fact.site_id.to_string(),
            fact.callback_site_id.to_string(),
            fact.user_data_site_id.to_string(),
            fact.object_site_id.to_string(),
        ],
        StaticFact::RegistrationSite(fact) => fact
            .callback_site_id
            .iter()
            .map(ToString::to_string)
            .chain(fact.user_data_site_id.iter().map(ToString::to_string))
            .chain(std::iter::once(fact.site_id.to_string()))
            .collect(),
        StaticFact::RawPointerTransfer(fact) => {
            vec![fact.site_id.to_string(), fact.user_data_site_id.to_string()]
        }
        StaticFact::ReleasePathProof(fact) => vec![
            fact.site_id.to_string(),
            fact.registration_site_id.to_string(),
            fact.release_site_id.to_string(),
            fact.object_site_id.to_string(),
        ],
        StaticFact::CallbackReleaseUseOrder(fact) => vec![
            fact.site_id.to_string(),
            fact.registration_site_id.to_string(),
            fact.release_site_id.to_string(),
            fact.use_site_id.to_string(),
            fact.object_site_id.to_string(),
        ],
        StaticFact::ExternalCallSite(fact) => fact
            .callback_site_id
            .iter()
            .map(ToString::to_string)
            .chain(std::iter::once(fact.site_id.to_string()))
            .collect(),
        StaticFact::ReturnedBorrowRelation(fact) => vec![
            fact.site_id.to_string(),
            fact.source_site_id.to_string(),
            fact.returned_site_id.to_string(),
        ],
        StaticFact::PersistedReturnedBorrow(fact) => vec![
            fact.site_id.to_string(),
            fact.source_site_id.to_string(),
            fact.returned_site_id.to_string(),
            fact.storage_site_id.to_string(),
        ],
        StaticFact::ReturnedBorrowInvalidationOrder(fact) => vec![
            fact.site_id.to_string(),
            fact.persisted_site_id.to_string(),
            fact.invalidation_site_id.to_string(),
            fact.use_site_id.to_string(),
        ],
        StaticFact::ExternalBufferBinding(fact) => vec![
            fact.site_id.to_string(),
            fact.source_site_id.to_string(),
            fact.buffer_site_id.to_string(),
        ],
        StaticFact::AtomicOrdering(fact) => vec![fact.site_id.to_string()],
        StaticFact::ObjectBindingGap(fact) => vec![fact.site_id.to_string()],
        StaticFact::ObjectFlow(fact) => vec![
            fact.site_id.to_string(),
            fact.from_site_id.to_string(),
            fact.to_site_id.to_string(),
        ],
    }
}

fn normalize_static_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn static_fact_source_api_aliases(envelope: &StaticFactEnvelope) -> BTreeSet<String> {
    let Some(source_ref) = envelope.source_ref.as_ref() else {
        return BTreeSet::new();
    };
    let Some(source_scope) = source_api_scope_from_path(&source_ref.path) else {
        return BTreeSet::new();
    };
    source_ref
        .symbol_path
        .iter()
        .chain(static_fact_api_or_symbol(envelope).iter())
        .flat_map(|symbol_path| source_api_symbol_tails(symbol_path))
        .map(|symbol| source_api_alias(&source_scope, &symbol))
        .collect()
}

fn source_api_scope_from_path(path: &str) -> Option<String> {
    let normalized = normalize_static_path(path);
    let scoped_path = normalized.strip_prefix("./").unwrap_or(normalized.as_str());
    let scoped_path = scoped_path
        .find("/src/")
        .map(|index| &scoped_path[index + 1..])
        .unwrap_or(scoped_path);
    let source_scope = scoped_path
        .trim_end_matches(".rs")
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>()
        .join("::");
    (!source_scope.is_empty()).then_some(source_scope)
}

fn source_api_symbol_tails(symbol_path: &str) -> BTreeSet<String> {
    let mut tails = BTreeSet::new();
    let segments = symbol_path
        .split("::")
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    for segment in segments.iter().rev() {
        if segment.starts_with("{closure") {
            continue;
        }
        if let Some(symbol) = source_api_symbol_from_segment(segment) {
            tails.insert(symbol);
            break;
        }
    }
    tails
}

fn source_api_symbol_from_segment(segment: &str) -> Option<String> {
    let raw_symbol = segment.split('<').next().unwrap_or(segment).trim();
    let symbol = raw_symbol
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect::<String>();
    if symbol.is_empty() || symbol.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        None
    } else {
        Some(symbol)
    }
}

fn source_api_alias(source_scope: &str, symbol: &str) -> String {
    let source_identity = format!("{source_scope}::{symbol}");
    format!(
        "source_api::{:x}",
        Sha256::digest(source_identity.as_bytes())
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326LifecycleFactKind {
    CallbackDefinition,
    BorrowedCapture,
    OwnedMoveCapture,
    DropImpl,
    DropSite,
    DropPrevention,
    CallbackUserDataReconstruction,
    RawPointerEscape,
    UnsafeCast,
    TraitImpl,
    RegisterCall,
    UnregisterCall,
    ReplaceCall,
    ReleaseCall,
    ReleasePathProof,
    CallbackReleaseUseOrder,
    ContractRetention,
    ReturnedBorrowRelation,
    PersistedReturnedBorrow,
    ReturnedBorrowInvalidationOrder,
    ExternalBufferBinding,
    AtomicOrdering,
    ObjectBindingGap,
    ObjectFlow,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326CoverageState {
    Covered,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleCoverageRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_lifecycle_coverage_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub candidate_id: String,
    pub crate_id: String,
    #[serde(default)]
    pub covered_function_bodies: Vec<String>,
    #[serde(default)]
    pub covered_trait_impls: Vec<String>,
    #[serde(default)]
    pub covered_drop_impls: Vec<String>,
    #[serde(default)]
    pub unavailable_paths: Vec<V326CoverageGap>,
    #[serde(default)]
    pub fact_refs: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326CoverageGap {
    pub path: String,
    pub reason: V326CoverageGapReason,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326CoverageGapReason {
    MacroExpansion,
    MissingDependency,
    CompileCfg,
    InsufficientSpan,
    SourceOnlyFallback,
    StaticFactsMissing,
    DropImplUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleContractRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_lifecycle_contract_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub contract_id: String,
    pub component_id: String,
    pub api_id: String,
    pub retention: V326ContractRetention,
    pub replacement: V326ContractReplacement,
    pub release: V326ContractRelease,
    pub owner_semantics: V326ForeignOwnerSemantics,
    pub scope: String,
    pub source: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326ContractRetention {
    MayRetainCallback,
    DoesNotRetainCallback,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326ContractReplacement {
    ReplacesPriorRegistration,
    DoesNotReplacePriorRegistration,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326ContractRelease {
    CoversCallbackAndUserData,
    CallbackOnly,
    UserDataOnly,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326ForeignOwnerSemantics {
    ForeignOwned,
    RustOwned,
    Shared,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleGraphV3Record {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_lifecycle_graph_v3_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub candidate_id: String,
    pub crate_id: String,
    pub pattern_family: V32PatternFamily,
    pub objects: Vec<V326LifecycleObject>,
    pub edges: Vec<V326LifecycleGraphV3Edge>,
    #[serde(default)]
    pub object_chains: Vec<V326ObjectChain>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub incomplete_reasons: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleObject {
    pub object_id: String,
    pub object_kind: V326LifecycleObjectKind,
    pub label: String,
    pub source_ref: Option<V326SourceRef>,
    #[serde(default)]
    pub fact_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326LifecycleObjectKind {
    Callback,
    UserData,
    RustOwner,
    ReturnedRef,
    Storage,
    StaticSite,
    ForeignOwner,
    ReleaseEndpoint,
    OpaqueHandle,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326LifecycleGraphV3Edge {
    pub edge_id: String,
    pub from_object_id: String,
    pub to_object_id: String,
    pub relation: V326LifecycleRelation,
    pub ordering: V326LifecycleOrdering,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub fact_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326ObjectChain {
    pub chain_id: String,
    #[serde(default)]
    pub object_ids: Vec<String>,
    #[serde(default)]
    pub edge_ids: Vec<String>,
    #[serde(default)]
    pub fact_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_layers: Vec<V326ObjectChainLayer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_layers: Vec<V326ObjectChainLayer>,
    pub chain_status: V326ObjectChainStatus,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326ObjectChainStatus {
    VerifiedStaticChain,
    PartialChain,
    AmbiguousChain,
    ObservationOnly,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326ObjectChainLayer {
    IdentityTransport,
    /// release 相对 register 的顺序已证明。
    ReleaseOrdering,
    /// 对象在 release 之后的 use 顺序已证明。
    UseOrdering,
    /// [`V326ObjectChainLayer::ReleaseOrdering`] 与 [`V326ObjectChainLayer::UseOrdering`]
    /// 的并集。保留为兼容层，新消费者应读取更细的两层以区分缺的是哪一种顺序。
    LifecycleOrdering,
    CompleteRiskChain,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326LifecycleRelation {
    Register,
    Retain,
    Replace,
    Release,
    Drop,
    Borrow,
    Persist,
    Invalidate,
    Use,
    Move,
    RawEscape,
    CallbackTrigger,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326LifecycleOrdering {
    Before,
    After,
    SameSite,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326WitnessPlanRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_6_witness_plan_schema")]
    pub schema_version: String,
    pub run_id: String,
    pub plan_id: String,
    pub candidate_id: String,
    pub lifecycle_graph_ref: String,
    pub actions: Vec<V326WitnessAction>,
    #[serde(default)]
    pub runtime_observers: Vec<String>,
    #[serde(default)]
    pub oracle_assertions: Vec<String>,
    #[serde(default)]
    pub replay_evidence_refs: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V326WitnessAction {
    pub action_id: String,
    pub action_kind: V326WitnessActionKind,
    #[serde(default)]
    pub graph_refs: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V326WitnessActionKind {
    SetupControlledFixture,
    RegisterCallback,
    ReplaceOrUnregister,
    DropRustOwner,
    PersistReturnedView,
    InvalidateOwner,
    UseReturnedView,
    RunMiriCheck,
    TriggerCallbackInLocalHarness,
    CollectOracleEvidence,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326AnonymousPairSummary {
    pub record_count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326PairDeltaSummary {
    pub record_count: u64,
    pub separable_static_count: u64,
    pub indistinguishable_static_only_count: u64,
    pub insufficient_evidence_count: u64,
    pub unpaired_count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326LifecycleFactSummary {
    pub record_count: u64,
    pub covered_count: u64,
    pub partial_count: u64,
    pub unavailable_count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326LifecycleCoverageSummary {
    pub record_count: u64,
    pub unavailable_path_count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326LifecycleContractSummary {
    pub record_count: u64,
    pub retention_contract_count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326LifecycleGraphV3Summary {
    pub graph_count: u64,
    pub incomplete_graph_count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V326WitnessPlanSummary {
    pub record_count: u64,
}

impl V326LifecycleContractRecord {
    #[must_use]
    pub fn sample_for_tests_retaining() -> Self {
        Self {
            schema_version: V3_2_6_LIFECYCLE_CONTRACT_SCHEMA_V1.to_owned(),
            run_id: "run:v326".to_owned(),
            contract_id: "contract:retaining-callback".to_owned(),
            component_id: "component:sample".to_owned(),
            api_id: "contract::register_callback".to_owned(),
            retention: V326ContractRetention::MayRetainCallback,
            replacement: V326ContractReplacement::Unknown,
            release: V326ContractRelease::Unknown,
            owner_semantics: V326ForeignOwnerSemantics::ForeignOwned,
            scope: "local_fixture".to_owned(),
            source: "manual_lifecycle_contract".to_owned(),
            evidence_refs: vec!["evidence:contract:0001".to_owned()],
            notes: vec!["neutral lifecycle contract".to_owned()],
        }
    }
}

impl V326LifecycleEvidenceRecord {
    #[must_use]
    pub fn sample_for_tests(
        record_id: &str,
        crate_id: &str,
        candidate_id: &str,
        evidence_kind: V326EvidenceKind,
    ) -> Self {
        Self {
            schema_version: V3_2_6_LIFECYCLE_EVIDENCE_SCHEMA_V1.to_owned(),
            run_id: "run:v326".to_owned(),
            record_id: record_id.to_owned(),
            crate_id: crate_id.to_owned(),
            candidate_id: candidate_id.to_owned(),
            evidence_kind,
            source_ref: V326SourceRef {
                path: "src/lib.rs".to_owned(),
                line_start: Some(1),
                line_end: Some(1),
                symbol_path: None,
                text_sha256: None,
            },
            confidence: V326EvidenceConfidence::Medium,
            details: serde_json::json!({}),
            notes: vec!["neutral lifecycle evidence".to_owned()],
        }
    }
}

impl V326LifecycleFeatureRecord {
    #[must_use]
    pub fn sample_for_tests_without_feature_refs() -> Self {
        Self {
            schema_version: V3_2_6_LIFECYCLE_FEATURE_SCHEMA_V1.to_owned(),
            run_id: "run:v326".to_owned(),
            candidate_id: "candidate:sample:001".to_owned(),
            crate_id: "crate:sample".to_owned(),
            pattern_family: V32PatternFamily::RetainedBorrowedCallback,
            features: V326FeatureSet {
                has_foreign_register: true,
                ..V326FeatureSet::default()
            },
            feature_evidence: BTreeMap::new(),
            missing_evidence: Vec::new(),
            notes: vec!["active feature intentionally missing evidence refs".to_owned()],
        }
    }

    #[must_use]
    pub fn sample_for_tests_with_features(mut configure: impl FnMut(&mut V326FeatureSet)) -> Self {
        let mut features = V326FeatureSet::default();
        configure(&mut features);
        let mut feature_evidence = BTreeMap::new();
        for (name, active) in features.active_flags() {
            if active {
                feature_evidence.insert(name.to_owned(), vec![format!("evidence:sample:{name}")]);
            }
        }
        Self {
            schema_version: V3_2_6_LIFECYCLE_FEATURE_SCHEMA_V1.to_owned(),
            run_id: "run:v326".to_owned(),
            candidate_id: "candidate:sample:001".to_owned(),
            crate_id: "crate:sample".to_owned(),
            pattern_family: V32PatternFamily::RetainedBorrowedCallback,
            features,
            feature_evidence,
            missing_evidence: Vec::new(),
            notes: vec!["candidate ranking is not a defect conclusion".to_owned()],
        }
    }

    #[must_use]
    pub fn sample_for_tests_for_crate(
        crate_id: &str,
        mut configure: impl FnMut(&mut V326FeatureSet),
    ) -> Self {
        let mut record = Self::sample_for_tests_with_features(&mut configure);
        record.crate_id = crate_id.to_owned();
        record.candidate_id = format!("candidate:{crate_id}:001");
        record
    }
}

impl V326LifecycleGraphRecord {
    #[must_use]
    pub fn sample_for_tests_with_broken_edge() -> Self {
        Self {
            schema_version: V3_2_6_LIFECYCLE_GRAPH_SCHEMA_V1.to_owned(),
            run_id: "run:v326".to_owned(),
            candidate_id: "candidate:sample:001".to_owned(),
            crate_id: "crate:sample".to_owned(),
            pattern_family: V32PatternFamily::RetainedBorrowedCallback,
            nodes: vec![V326LifecycleNode {
                node_id: "candidate".to_owned(),
                node_kind: V326LifecycleNodeKind::RustObject,
                label: "candidate node".to_owned(),
            }],
            edges: vec![V326LifecycleEdge {
                from: "candidate".to_owned(),
                to: "missing_node".to_owned(),
                edge_kind: V326LifecycleEdgeKind::RegisteredInto,
                evidence_refs: vec!["evidence:sample:0001".to_owned()],
            }],
            evidence_refs: vec!["evidence:sample:0001".to_owned()],
            incomplete_evidence: Vec::new(),
            notes: vec!["broken edge fixture".to_owned()],
        }
    }
}

impl V326FeatureSet {
    fn active_flags(&self) -> [(&'static str, bool); 36] {
        [
            ("has_foreign_register", self.has_foreign_register),
            (
                "foreign_may_retain_callback",
                self.foreign_may_retain_callback,
            ),
            (
                "foreign_may_retain_user_data",
                self.foreign_may_retain_user_data,
            ),
            ("has_borrowed_capture", self.has_borrowed_capture),
            ("has_raw_pointer_escape", self.has_raw_pointer_escape),
            (
                "raw_parts_transfer_without_drop_prevention",
                self.raw_parts_transfer_without_drop_prevention,
            ),
            ("has_drop_prevention", self.has_drop_prevention),
            (
                "manual_drop_prevention_without_drop_guard",
                self.manual_drop_prevention_without_drop_guard,
            ),
            (
                "callback_user_data_owner_reconstruction_without_leak_guard",
                self.callback_user_data_owner_reconstruction_without_leak_guard,
            ),
            (
                "has_returned_borrow_relation",
                self.has_returned_borrow_relation,
            ),
            (
                "has_unconstrained_return_lifetime",
                self.has_unconstrained_return_lifetime,
            ),
            (
                "has_persisted_returned_borrow",
                self.has_persisted_returned_borrow,
            ),
            (
                "returned_borrow_persistence_before_invalidation",
                self.returned_borrow_persistence_before_invalidation,
            ),
            (
                "returned_borrow_persistence_after_invalidation",
                self.returned_borrow_persistence_after_invalidation,
            ),
            (
                "has_external_buffer_binding",
                self.has_external_buffer_binding,
            ),
            (
                "has_external_buffer_lifetime_bound",
                self.has_external_buffer_lifetime_bound,
            ),
            (
                "relaxed_atomic_load_in_iterator",
                self.relaxed_atomic_load_in_iterator,
            ),
            (
                "acquire_atomic_load_in_iterator",
                self.acquire_atomic_load_in_iterator,
            ),
            ("has_verified_object_chain", self.has_verified_object_chain),
            ("has_release_order_chain", self.has_release_order_chain),
            (
                "has_persisted_invalidation_use_chain",
                self.has_persisted_invalidation_use_chain,
            ),
            (
                "has_callback_release_use_chain",
                self.has_callback_release_use_chain,
            ),
            (
                "rust_object_may_drop_before_foreign_release",
                self.rust_object_may_drop_before_foreign_release,
            ),
            (
                "missing_unregister_before_drop",
                self.missing_unregister_before_drop,
            ),
            ("release_order_unknown", self.release_order_unknown),
            (
                "opaque_handle_without_owner",
                self.opaque_handle_without_owner,
            ),
            ("needs_dynamic_witness", self.needs_dynamic_witness),
            ("has_foreign_unregister", self.has_foreign_unregister),
            (
                "registration_release_pair_found",
                self.registration_release_pair_found,
            ),
            ("has_drop_guard", self.has_drop_guard),
            ("has_owned_anchor", self.has_owned_anchor),
            ("has_static_bound", self.has_static_bound),
            ("has_box_into_raw", self.has_box_into_raw),
            ("has_box_from_raw", self.has_box_from_raw),
            ("has_arc_anchor", self.has_arc_anchor),
            ("release_covers_callback", self.release_covers_callback),
        ]
    }

    #[must_use]
    pub fn has_any_active(&self) -> bool {
        self.active_flags().iter().any(|(_, active)| *active)
    }
}

pub fn validate_v3_2_6_lifecycle_evidence<I>(
    records: I,
) -> Result<V326LifecycleEvidenceSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326LifecycleEvidenceRecord>>,
{
    let mut summary = V326LifecycleEvidenceSummary::default();
    let mut record_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text_evidence(&located, "run_id", &record.run_id)?;
        validate_required_text_evidence(&located, "record_id", &record.record_id)?;
        validate_required_text_evidence(&located, "crate_id", &record.crate_id)?;
        validate_required_text_evidence(&located, "candidate_id", &record.candidate_id)?;
        validate_required_text_evidence(&located, "source_ref.path", &record.source_ref.path)?;
        reject_private_tokens_evidence(&located, "run_id", &record.run_id)?;
        reject_private_tokens_evidence(&located, "record_id", &record.record_id)?;
        reject_private_tokens_evidence(&located, "crate_id", &record.crate_id)?;
        reject_private_tokens_evidence(&located, "candidate_id", &record.candidate_id)?;
        reject_private_tokens_evidence(&located, "source_ref.path", &record.source_ref.path)?;
        if let Some(symbol_path) = &record.source_ref.symbol_path {
            reject_private_tokens_evidence(&located, "source_ref.symbol_path", symbol_path)?;
        }
        if let Some(text_sha256) = &record.source_ref.text_sha256 {
            reject_private_tokens_evidence(&located, "source_ref.text_sha256", text_sha256)?;
        }
        reject_private_tokens_json_evidence(&located, "details", &record.details)?;
        for note in &record.notes {
            reject_private_tokens_evidence(&located, "notes", note)?;
        }
        if !record_ids.insert(record.record_id.clone()) {
            return Err(at_evidence(
                &located,
                "BW-V326-EVIDENCE-ID-DUPLICATE",
                format!("record_id {} 重复", record.record_id),
            ));
        }
        match record.confidence {
            V326EvidenceConfidence::High => summary.high_confidence_count += 1,
            V326EvidenceConfidence::Medium => summary.medium_confidence_count += 1,
            V326EvidenceConfidence::Low => summary.low_confidence_count += 1,
        }
        summary.record_count += 1;
    }
    Ok(summary)
}

pub fn validate_v3_2_6_lifecycle_features<I>(
    records: I,
) -> Result<V326LifecycleFeatureSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326LifecycleFeatureRecord>>,
{
    let mut summary = V326LifecycleFeatureSummary::default();
    let mut candidate_ids = BTreeSet::<String>::new();
    let mut run_id: Option<String> = None;

    for located in records {
        let record = &located.value;
        validate_required_text_feature(&located, "run_id", &record.run_id)?;
        validate_required_text_feature(&located, "candidate_id", &record.candidate_id)?;
        validate_required_text_feature(&located, "crate_id", &record.crate_id)?;
        reject_private_tokens_feature(&located, "run_id", &record.run_id)?;
        reject_private_tokens_feature(&located, "candidate_id", &record.candidate_id)?;
        reject_private_tokens_feature(&located, "crate_id", &record.crate_id)?;
        if let Some(expected) = &run_id {
            if expected != &record.run_id {
                return Err(at_feature(
                    &located,
                    "BW-V326-FEATURE-RUN-MISMATCH",
                    format!(
                        "同一 lifecycle feature 输入出现 run_id {expected} 和 {}",
                        record.run_id
                    ),
                ));
            }
        } else {
            run_id = Some(record.run_id.clone());
        }
        for note in &record.notes {
            reject_private_tokens_feature(&located, "notes", note)?;
        }

        for (name, active) in record.features.active_flags() {
            if !active {
                continue;
            }
            let refs = record.feature_evidence.get(name);
            let empty = match refs {
                Some(values) => {
                    values.is_empty() || values.iter().any(|item| item.trim().is_empty())
                }
                None => true,
            };
            if empty {
                return Err(at_feature(
                    &located,
                    "BW-V326-FEATURE-EVIDENCE",
                    format!("active feature `{name}` 必须包含至少一条 evidence ref"),
                ));
            }
        }

        if !candidate_ids.insert(record.candidate_id.clone()) {
            return Err(at_feature(
                &located,
                "BW-V326-FEATURE-CANDIDATE-DUPLICATE",
                format!("candidate_id {} 重复", record.candidate_id),
            ));
        }
        summary.record_count += 1;
    }
    Ok(summary)
}

pub fn validate_v3_2_6_lifecycle_graphs<I>(records: I) -> Result<u64, ModelError>
where
    I: IntoIterator<Item = Located<V326LifecycleGraphRecord>>,
{
    let mut count = 0_u64;
    let mut candidate_ids = BTreeSet::<String>::new();

    for located in records {
        let graph = &located.value;
        validate_required_text_graph(&located, "run_id", &graph.run_id)?;
        validate_required_text_graph(&located, "candidate_id", &graph.candidate_id)?;
        validate_required_text_graph(&located, "crate_id", &graph.crate_id)?;
        reject_private_tokens_graph(&located, "run_id", &graph.run_id)?;
        reject_private_tokens_graph(&located, "candidate_id", &graph.candidate_id)?;
        reject_private_tokens_graph(&located, "crate_id", &graph.crate_id)?;

        if graph.nodes.is_empty() {
            return Err(at_graph(
                &located,
                "BW-V326-GRAPH-NODES-EMPTY",
                "lifecycle graph v2 必须至少包含一个 node",
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
                "BW-V326-GRAPH-NODE-ID-DUPLICATE",
                "lifecycle graph v2 node_id 不能重复",
            ));
        }
        for node in &graph.nodes {
            validate_required_text_graph(&located, "nodes.node_id", &node.node_id)?;
            validate_required_text_graph(&located, "nodes.label", &node.label)?;
        }
        for edge in &graph.edges {
            if !node_ids.contains(edge.from.as_str()) || !node_ids.contains(edge.to.as_str()) {
                return Err(at_graph(
                    &located,
                    "BW-V326-GRAPH-EDGE-ENDPOINT",
                    format!("edge {} -> {} 引用了不存在的 node_id", edge.from, edge.to),
                ));
            }
            if edge.evidence_refs.is_empty()
                || edge.evidence_refs.iter().any(|item| item.trim().is_empty())
            {
                return Err(at_graph(
                    &located,
                    "BW-V326-GRAPH-EDGE-EVIDENCE",
                    "edge.evidence_refs 不能为空",
                ));
            }
        }
        if !candidate_ids.insert(graph.candidate_id.clone()) {
            return Err(at_graph(
                &located,
                "BW-V326-GRAPH-CANDIDATE-DUPLICATE",
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

pub fn validate_v3_2_6_ranked_candidates<I>(
    records: I,
) -> Result<V326RankedCandidateSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326RankedCandidateRecord>>,
{
    let mut summary = V326RankedCandidateSummary::default();
    let mut ranks = BTreeSet::<u32>::new();
    let mut candidate_ids = BTreeSet::<String>::new();
    let mut run_id: Option<String> = None;

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
        validate_relative_path_ranked(&located, &record.lifecycle_graph_path)?;
        validate_public_string_list_ranked(&located, "risk_features", &record.risk_features)?;
        validate_public_string_list_ranked(
            &located,
            "protective_features",
            &record.protective_features,
        )?;
        validate_public_string_list_ranked(&located, "missing_evidence", &record.missing_evidence)?;
        validate_public_string_list_ranked(&located, "notes", &record.notes)?;
        for (feature, refs) in &record.feature_evidence_refs {
            validate_required_text_ranked(&located, "feature_evidence_refs.key", feature)?;
            reject_private_tokens_ranked(&located, "feature_evidence_refs.key", feature)?;
            validate_public_string_list_ranked(&located, "feature_evidence_refs", refs)?;
        }
        validate_ranked_chain_summary(&located, &record.chain_summary)?;

        if record.rank == 0 {
            return Err(at_ranked(
                &located,
                "BW-V326-RANK-ZERO",
                "rank 必须从 1 开始",
            ));
        }
        if !ranks.insert(record.rank) {
            return Err(at_ranked(
                &located,
                "BW-V326-RANK-DUPLICATE",
                format!("rank {} 重复", record.rank),
            ));
        }
        if !candidate_ids.insert(record.candidate_id.clone()) {
            return Err(at_ranked(
                &located,
                "BW-V326-RANK-CANDIDATE-DUPLICATE",
                format!("candidate_id {} 重复", record.candidate_id),
            ));
        }
        if let Some(expected) = &run_id {
            if expected != &record.run_id {
                return Err(at_ranked(
                    &located,
                    "BW-V326-RANK-RUN-MISMATCH",
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
                "BW-V326-RANK-SCORE-MISMATCH",
                format!(
                    "score {} 与 score_breakdown 计算结果 {recomputed} 不一致",
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
                "BW-V326-RANK-SEQUENCE",
                "rank 必须是从 1 开始的连续编号",
            ));
        }
    }
    Ok(summary)
}

pub fn validate_v3_2_6_anonymous_pairs<I>(
    records: I,
) -> Result<V326AnonymousPairSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326AnonymousPairRecord>>,
{
    let mut summary = V326AnonymousPairSummary::default();
    let mut pair_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text_pair(&located, "run_id", &record.run_id)?;
        validate_required_text_pair(&located, "pair_id", &record.pair_id)?;
        validate_required_text_pair(&located, "left_crate_id", &record.left_crate_id)?;
        validate_required_text_pair(&located, "right_crate_id", &record.right_crate_id)?;
        validate_required_text_pair(&located, "relation_hint", &record.relation_hint)?;
        reject_private_tokens_pair(&located, "run_id", &record.run_id)?;
        reject_private_tokens_pair(&located, "pair_id", &record.pair_id)?;
        reject_private_tokens_pair(&located, "left_crate_id", &record.left_crate_id)?;
        reject_private_tokens_pair(&located, "right_crate_id", &record.right_crate_id)?;
        reject_private_tokens_pair(&located, "relation_hint", &record.relation_hint)?;
        reject_pair_role_tokens(&located, "relation_hint", &record.relation_hint)?;
        for note in &record.notes {
            reject_private_tokens_pair(&located, "notes", note)?;
            reject_pair_role_tokens(&located, "notes", note)?;
        }
        if record.left_crate_id == record.right_crate_id {
            return Err(at_pair(
                &located,
                "BW-V326-PAIR-SAME-SIDE",
                "left_crate_id 与 right_crate_id 不能相同",
            ));
        }
        if !pair_ids.insert(record.pair_id.clone()) {
            return Err(at_pair(
                &located,
                "BW-V326-PAIR-ID-DUPLICATE",
                format!("pair_id {} 重复", record.pair_id),
            ));
        }
        summary.record_count += 1;
    }
    Ok(summary)
}

pub fn validate_v3_2_6_pair_deltas<I>(records: I) -> Result<V326PairDeltaSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326PairDeltaRecord>>,
{
    let mut summary = V326PairDeltaSummary::default();
    let mut pair_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_pair_delta_public_fields(&located, record, V3_2_6_PAIR_DELTA_SCHEMA_V1, false)?;
        if !pair_ids.insert(record.pair_id.clone()) {
            return Err(at_delta(
                &located,
                "BW-V326-DELTA-ID-DUPLICATE",
                format!("pair_id {} 重复", record.pair_id),
            ));
        }
        count_pair_delta(&mut summary, record);
    }
    Ok(summary)
}

pub fn validate_v3_2_7_pair_deltas<I>(records: I) -> Result<V326PairDeltaSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326PairDeltaRecord>>,
{
    let mut summary = V326PairDeltaSummary::default();
    let mut pair_keys = BTreeSet::<(String, String)>::new();
    let mut pair_identities = BTreeMap::<String, (String, String, String)>::new();

    for located in records {
        let record = &located.value;
        validate_pair_delta_public_fields(&located, record, V3_2_7_PAIR_DELTA_SCHEMA_V1, true)?;
        if let Some((run_id, left_crate_id, right_crate_id)) = pair_identities.get(&record.pair_id)
        {
            if run_id != &record.run_id
                || left_crate_id != &record.left_crate_id
                || right_crate_id != &record.right_crate_id
            {
                return Err(at_delta(
                    &located,
                    "BW-V327-DELTA-PAIR-MISMATCH",
                    format!(
                        "pair_id {} 的 run_id 或 left/right crate_id 不一致",
                        record.pair_id
                    ),
                ));
            }
        } else {
            pair_identities.insert(
                record.pair_id.clone(),
                (
                    record.run_id.clone(),
                    record.left_crate_id.clone(),
                    record.right_crate_id.clone(),
                ),
            );
        }
        if !pair_keys.insert((record.pair_id.clone(), record.comparison_key.clone())) {
            return Err(at_delta(
                &located,
                "BW-V327-DELTA-ID-DUPLICATE",
                format!(
                    "pair_id {} 与 comparison_key {} 重复",
                    record.pair_id, record.comparison_key
                ),
            ));
        }
        count_pair_delta(&mut summary, record);
    }
    Ok(summary)
}

fn validate_pair_delta_public_fields(
    located: &Located<V326PairDeltaRecord>,
    record: &V326PairDeltaRecord,
    expected_schema: &str,
    comparison_key_required: bool,
) -> Result<(), ModelError> {
    if record.schema_version != expected_schema {
        return Err(at_delta(
            located,
            "BW-V326-DELTA-SCHEMA",
            format!(
                "pair delta schema {} 不匹配当前校验入口 {expected_schema}",
                record.schema_version
            ),
        ));
    }
    validate_required_text_delta(located, "run_id", &record.run_id)?;
    validate_required_text_delta(located, "pair_id", &record.pair_id)?;
    validate_required_text_delta(located, "left_crate_id", &record.left_crate_id)?;
    validate_required_text_delta(located, "right_crate_id", &record.right_crate_id)?;
    reject_private_tokens_delta(located, "run_id", &record.run_id)?;
    reject_private_tokens_delta(located, "pair_id", &record.pair_id)?;
    reject_private_tokens_delta(located, "left_crate_id", &record.left_crate_id)?;
    reject_private_tokens_delta(located, "right_crate_id", &record.right_crate_id)?;
    if comparison_key_required {
        validate_required_text_delta(located, "comparison_key", &record.comparison_key)?;
        reject_private_tokens_delta(located, "comparison_key", &record.comparison_key)?;
        reject_pair_role_tokens_delta(located, "comparison_key", &record.comparison_key)?;
        validate_required_text_delta(
            located,
            "pair_manifest_run_id",
            &record.pair_manifest_run_id,
        )?;
        reject_private_tokens_delta(
            located,
            "pair_manifest_run_id",
            &record.pair_manifest_run_id,
        )?;
    } else if !record.comparison_key.is_empty() {
        return Err(at_delta(
            located,
            "BW-V326-DELTA-COMPARISON-KEY",
            "v3.2.6 pair delta 不允许 comparison_key；请使用 v3.2.7 schema",
        ));
    } else if !record.pair_manifest_run_id.is_empty() {
        return Err(at_delta(
            located,
            "BW-V326-DELTA-PAIR-MANIFEST-RUN",
            "v3.2.6 pair delta 不允许 pair_manifest_run_id；请使用 v3.2.7 schema",
        ));
    }
    for feature in &record.left_top_features {
        reject_private_tokens_delta(located, "left_top_features", feature)?;
        reject_pair_role_tokens_delta(located, "left_top_features", feature)?;
    }
    for feature in &record.right_top_features {
        reject_private_tokens_delta(located, "right_top_features", feature)?;
        reject_pair_role_tokens_delta(located, "right_top_features", feature)?;
    }
    for delta in &record.semantic_delta {
        reject_private_tokens_delta(located, "semantic_delta", delta)?;
        reject_pair_role_tokens_delta(located, "semantic_delta", delta)?;
    }
    for note in &record.notes {
        reject_private_tokens_delta(located, "notes", note)?;
        reject_pair_role_tokens_delta(located, "notes", note)?;
    }
    Ok(())
}

fn count_pair_delta(summary: &mut V326PairDeltaSummary, record: &V326PairDeltaRecord) {
    match record.distinguishability {
        V326Distinguishability::SeparableStatic => summary.separable_static_count += 1,
        V326Distinguishability::IndistinguishableStaticOnly => {
            summary.indistinguishable_static_only_count += 1;
        }
        V326Distinguishability::InsufficientEvidence => {
            summary.insufficient_evidence_count += 1;
        }
        V326Distinguishability::Unpaired => summary.unpaired_count += 1,
    }
    summary.record_count += 1;
}

pub fn validate_v3_2_6_lifecycle_facts<I>(
    records: I,
) -> Result<V326LifecycleFactSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326LifecycleFactRecord>>,
{
    let mut summary = V326LifecycleFactSummary::default();
    let mut fact_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text_loc(
            &located,
            "BW-V326-FACT-REQUIRED-EMPTY",
            "run_id",
            &record.run_id,
        )?;
        validate_required_text_loc(
            &located,
            "BW-V326-FACT-REQUIRED-EMPTY",
            "candidate_id",
            &record.candidate_id,
        )?;
        validate_required_text_loc(
            &located,
            "BW-V326-FACT-REQUIRED-EMPTY",
            "crate_id",
            &record.crate_id,
        )?;
        validate_required_text_loc(
            &located,
            "BW-V326-FACT-REQUIRED-EMPTY",
            "fact_id",
            &record.fact_id,
        )?;
        validate_required_text_loc(
            &located,
            "BW-V326-FACT-REQUIRED-EMPTY",
            "source_ref.path",
            &record.source_ref.path,
        )?;
        reject_private_tokens_loc(
            &located,
            "BW-V326-FACT-PRIVATE-TOKEN",
            "run_id",
            &record.run_id,
        )?;
        reject_private_tokens_loc(
            &located,
            "BW-V326-FACT-PRIVATE-TOKEN",
            "candidate_id",
            &record.candidate_id,
        )?;
        reject_private_tokens_loc(
            &located,
            "BW-V326-FACT-PRIVATE-TOKEN",
            "crate_id",
            &record.crate_id,
        )?;
        reject_private_tokens_loc(
            &located,
            "BW-V326-FACT-PRIVATE-TOKEN",
            "fact_id",
            &record.fact_id,
        )?;
        reject_private_tokens_source_ref(
            &located,
            "BW-V326-FACT-PRIVATE-TOKEN",
            &record.source_ref,
        )?;
        if let Some(symbol_path) = &record.symbol_path {
            reject_private_tokens_loc(
                &located,
                "BW-V326-FACT-PRIVATE-TOKEN",
                "symbol_path",
                symbol_path,
            )?;
        }
        validate_public_string_list(
            &located,
            "BW-V326-FACT-PRIVATE-TOKEN",
            "object_ids",
            &record.object_ids,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-FACT-PRIVATE-TOKEN",
            "evidence_refs",
            &record.evidence_refs,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-FACT-PRIVATE-TOKEN",
            "notes",
            &record.notes,
        )?;
        validate_lifecycle_fact_provenance(&located, &record.provenance)?;
        validate_lifecycle_fact_object_ids(&located, record)?;
        if record.fact_kind == V326LifecycleFactKind::ContractRetention {
            return Err(at_loc(
                &located,
                "BW-V326-FACT-CONTRACT-RETENTION",
                "contract_retention 不得作为 lifecycle fact 发布；请使用 v3.2.6.lifecycle_contract.1 与 exact API 匹配",
            ));
        }
        if fact_kind_requires_object_id(record.fact_kind) && record.object_ids.is_empty() {
            return Err(at_loc(
                &located,
                "BW-V326-FACT-OBJECT-ID",
                "object-binding fact 必须包含至少一个 lifecycle object id",
            ));
        }
        if record
            .evidence_refs
            .iter()
            .any(|item| item.trim().is_empty())
        {
            return Err(at_loc(
                &located,
                "BW-V326-FACT-EVIDENCE",
                "fact.evidence_refs 不能包含空字符串",
            ));
        }
        if !fact_ids.insert(record.fact_id.clone()) {
            return Err(at_loc(
                &located,
                "BW-V326-FACT-ID-DUPLICATE",
                format!("fact_id {} 重复", record.fact_id),
            ));
        }
        match record.coverage_state {
            V326CoverageState::Covered => summary.covered_count += 1,
            V326CoverageState::Partial => summary.partial_count += 1,
            V326CoverageState::Unavailable => summary.unavailable_count += 1,
        }
        summary.record_count += 1;
    }
    Ok(summary)
}

pub fn validate_v3_2_6_lifecycle_coverage<I>(
    records: I,
) -> Result<V326LifecycleCoverageSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326LifecycleCoverageRecord>>,
{
    let mut summary = V326LifecycleCoverageSummary::default();
    let mut candidate_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        validate_required_text_loc(
            &located,
            "BW-V326-COVERAGE-REQUIRED-EMPTY",
            "run_id",
            &record.run_id,
        )?;
        validate_required_text_loc(
            &located,
            "BW-V326-COVERAGE-REQUIRED-EMPTY",
            "candidate_id",
            &record.candidate_id,
        )?;
        validate_required_text_loc(
            &located,
            "BW-V326-COVERAGE-REQUIRED-EMPTY",
            "crate_id",
            &record.crate_id,
        )?;
        reject_private_tokens_loc(
            &located,
            "BW-V326-COVERAGE-PRIVATE-TOKEN",
            "run_id",
            &record.run_id,
        )?;
        reject_private_tokens_loc(
            &located,
            "BW-V326-COVERAGE-PRIVATE-TOKEN",
            "candidate_id",
            &record.candidate_id,
        )?;
        reject_private_tokens_loc(
            &located,
            "BW-V326-COVERAGE-PRIVATE-TOKEN",
            "crate_id",
            &record.crate_id,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-COVERAGE-PRIVATE-TOKEN",
            "covered_function_bodies",
            &record.covered_function_bodies,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-COVERAGE-PRIVATE-TOKEN",
            "covered_trait_impls",
            &record.covered_trait_impls,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-COVERAGE-PRIVATE-TOKEN",
            "covered_drop_impls",
            &record.covered_drop_impls,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-COVERAGE-PRIVATE-TOKEN",
            "fact_refs",
            &record.fact_refs,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-COVERAGE-PRIVATE-TOKEN",
            "notes",
            &record.notes,
        )?;
        for gap in &record.unavailable_paths {
            validate_required_text_loc(
                &located,
                "BW-V326-COVERAGE-GAP-PATH",
                "unavailable_paths.path",
                &gap.path,
            )?;
            reject_private_tokens_loc(
                &located,
                "BW-V326-COVERAGE-PRIVATE-TOKEN",
                "unavailable_paths.path",
                &gap.path,
            )?;
            validate_public_string_list(
                &located,
                "BW-V326-COVERAGE-PRIVATE-TOKEN",
                "unavailable_paths.notes",
                &gap.notes,
            )?;
            summary.unavailable_path_count += 1;
        }
        if !candidate_ids.insert(record.candidate_id.clone()) {
            return Err(at_loc(
                &located,
                "BW-V326-COVERAGE-CANDIDATE-DUPLICATE",
                format!("candidate_id {} 的 coverage 重复", record.candidate_id),
            ));
        }
        summary.record_count += 1;
    }
    Ok(summary)
}

pub fn validate_v3_2_6_lifecycle_contracts<I>(
    records: I,
) -> Result<V326LifecycleContractSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326LifecycleContractRecord>>,
{
    let mut summary = V326LifecycleContractSummary::default();
    let mut contract_ids = BTreeSet::<String>::new();

    for located in records {
        let record = &located.value;
        for (field, value) in [
            ("run_id", record.run_id.as_str()),
            ("contract_id", record.contract_id.as_str()),
            ("component_id", record.component_id.as_str()),
            ("api_id", record.api_id.as_str()),
            ("scope", record.scope.as_str()),
            ("source", record.source.as_str()),
        ] {
            validate_required_text_loc(&located, "BW-V326-CONTRACT-REQUIRED-EMPTY", field, value)?;
            reject_private_tokens_loc(&located, "BW-V326-CONTRACT-PRIVATE-TOKEN", field, value)?;
        }
        if !is_exact_lifecycle_api_id(&record.api_id) {
            return Err(at_loc(
                &located,
                "BW-V326-CONTRACT-API-ID",
                format!("contract.api_id {} 不是精确 API 身份", record.api_id),
            ));
        }
        validate_public_string_list(
            &located,
            "BW-V326-CONTRACT-PRIVATE-TOKEN",
            "evidence_refs",
            &record.evidence_refs,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-CONTRACT-PRIVATE-TOKEN",
            "notes",
            &record.notes,
        )?;
        if record.evidence_refs.is_empty() {
            return Err(at_loc(
                &located,
                "BW-V326-CONTRACT-EVIDENCE",
                "contract.evidence_refs 不能为空",
            ));
        }
        if !contract_ids.insert(record.contract_id.clone()) {
            return Err(at_loc(
                &located,
                "BW-V326-CONTRACT-ID-DUPLICATE",
                format!("contract_id {} 重复", record.contract_id),
            ));
        }
        if record.retention == V326ContractRetention::MayRetainCallback {
            summary.retention_contract_count += 1;
        }
        summary.record_count += 1;
    }
    Ok(summary)
}

pub fn validate_v3_2_6_lifecycle_graph_v3<I>(
    records: I,
) -> Result<V326LifecycleGraphV3Summary, ModelError>
where
    I: IntoIterator<Item = Located<V326LifecycleGraphV3Record>>,
{
    let mut summary = V326LifecycleGraphV3Summary::default();
    let mut candidate_ids = BTreeSet::<String>::new();

    for located in records {
        let graph = &located.value;
        for (field, value) in [
            ("run_id", graph.run_id.as_str()),
            ("candidate_id", graph.candidate_id.as_str()),
            ("crate_id", graph.crate_id.as_str()),
        ] {
            validate_required_text_loc(&located, "BW-V326-GRAPH-V3-REQUIRED-EMPTY", field, value)?;
            reject_private_tokens_loc(&located, "BW-V326-GRAPH-V3-PRIVATE-TOKEN", field, value)?;
        }
        if graph.objects.is_empty() {
            return Err(at_loc(
                &located,
                "BW-V326-GRAPH-V3-OBJECTS-EMPTY",
                "lifecycle graph v3 必须至少包含一个 object",
            ));
        }
        let mut object_ids = BTreeSet::<String>::new();
        for object in &graph.objects {
            validate_required_text_loc(
                &located,
                "BW-V326-GRAPH-V3-OBJECT-ID",
                "objects.object_id",
                &object.object_id,
            )?;
            validate_required_text_loc(
                &located,
                "BW-V326-GRAPH-V3-OBJECT-LABEL",
                "objects.label",
                &object.label,
            )?;
            reject_private_tokens_loc(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "objects.object_id",
                &object.object_id,
            )?;
            reject_private_tokens_loc(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "objects.label",
                &object.label,
            )?;
            validate_public_string_list(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "objects.fact_refs",
                &object.fact_refs,
            )?;
            if let Some(source_ref) = &object.source_ref {
                reject_private_tokens_source_ref(
                    &located,
                    "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                    source_ref,
                )?;
            }
            if !object_ids.insert(object.object_id.clone()) {
                return Err(at_loc(
                    &located,
                    "BW-V326-GRAPH-V3-OBJECT-DUPLICATE",
                    format!("object_id {} 重复", object.object_id),
                ));
            }
        }
        let mut edge_ids = BTreeSet::<String>::new();
        for edge in &graph.edges {
            for (field, value) in [
                ("edges.edge_id", edge.edge_id.as_str()),
                ("edges.from_object_id", edge.from_object_id.as_str()),
                ("edges.to_object_id", edge.to_object_id.as_str()),
            ] {
                validate_required_text_loc(
                    &located,
                    "BW-V326-GRAPH-V3-EDGE-REQUIRED",
                    field,
                    value,
                )?;
                reject_private_tokens_loc(
                    &located,
                    "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                    field,
                    value,
                )?;
            }
            if !object_ids.contains(&edge.from_object_id)
                || !object_ids.contains(&edge.to_object_id)
            {
                return Err(at_loc(
                    &located,
                    "BW-V326-GRAPH-V3-EDGE-ENDPOINT",
                    format!("edge {} 引用了不存在的 lifecycle object id", edge.edge_id),
                ));
            }
            if !edge_ids.insert(edge.edge_id.clone()) {
                return Err(at_loc(
                    &located,
                    "BW-V326-GRAPH-V3-EDGE-DUPLICATE",
                    format!("edge_id {} 重复", edge.edge_id),
                ));
            }
            if edge.evidence_refs.is_empty() && edge.fact_refs.is_empty() {
                return Err(at_loc(
                    &located,
                    "BW-V326-GRAPH-V3-EDGE-EVIDENCE",
                    "graph v3 edge 必须包含 evidence_refs 或 fact_refs",
                ));
            }
            validate_public_string_list(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "edges.evidence_refs",
                &edge.evidence_refs,
            )?;
            validate_public_string_list(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "edges.fact_refs",
                &edge.fact_refs,
            )?;
        }
        let mut chain_ids = BTreeSet::<String>::new();
        for chain in &graph.object_chains {
            validate_required_text_loc(
                &located,
                "BW-V326-GRAPH-V3-CHAIN-ID",
                "object_chains.chain_id",
                &chain.chain_id,
            )?;
            reject_private_tokens_loc(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "object_chains.chain_id",
                &chain.chain_id,
            )?;
            if !chain_ids.insert(chain.chain_id.clone()) {
                return Err(at_loc(
                    &located,
                    "BW-V326-GRAPH-V3-CHAIN-DUPLICATE",
                    format!("chain_id {} 重复", chain.chain_id),
                ));
            }
            if chain.object_ids.is_empty()
                && chain.edge_ids.is_empty()
                && chain.fact_refs.is_empty()
            {
                return Err(at_loc(
                    &located,
                    "BW-V326-GRAPH-V3-CHAIN-EMPTY",
                    "object_chain 必须包含 object_ids、edge_ids 或 fact_refs",
                ));
            }
            for object_id in &chain.object_ids {
                if !object_ids.contains(object_id) {
                    return Err(at_loc(
                        &located,
                        "BW-V326-GRAPH-V3-CHAIN-OBJECT",
                        format!("chain {} 引用了不存在的 object id", chain.chain_id),
                    ));
                }
            }
            for edge_id in &chain.edge_ids {
                if !edge_ids.contains(edge_id) {
                    return Err(at_loc(
                        &located,
                        "BW-V326-GRAPH-V3-CHAIN-EDGE",
                        format!("chain {} 引用了不存在的 edge id", chain.chain_id),
                    ));
                }
            }
            validate_public_string_list(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "object_chains.object_ids",
                &chain.object_ids,
            )?;
            validate_public_string_list(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "object_chains.edge_ids",
                &chain.edge_ids,
            )?;
            validate_public_string_list(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "object_chains.fact_refs",
                &chain.fact_refs,
            )?;
            validate_public_string_list(
                &located,
                "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
                "object_chains.evidence_refs",
                &chain.evidence_refs,
            )?;
        }
        validate_public_string_list(
            &located,
            "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
            "evidence_refs",
            &graph.evidence_refs,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
            "incomplete_reasons",
            &graph.incomplete_reasons,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-GRAPH-V3-PRIVATE-TOKEN",
            "notes",
            &graph.notes,
        )?;
        if !candidate_ids.insert(graph.candidate_id.clone()) {
            return Err(at_loc(
                &located,
                "BW-V326-GRAPH-V3-CANDIDATE-DUPLICATE",
                format!(
                    "candidate_id {} 的 lifecycle graph v3 重复",
                    graph.candidate_id
                ),
            ));
        }
        if !graph.incomplete_reasons.is_empty() {
            summary.incomplete_graph_count += 1;
        }
        summary.graph_count += 1;
    }
    Ok(summary)
}

pub fn validate_v3_2_6_witness_plans<I>(records: I) -> Result<V326WitnessPlanSummary, ModelError>
where
    I: IntoIterator<Item = Located<V326WitnessPlanRecord>>,
{
    let mut summary = V326WitnessPlanSummary::default();
    let mut plan_ids = BTreeSet::<String>::new();

    for located in records {
        let plan = &located.value;
        for (field, value) in [
            ("run_id", plan.run_id.as_str()),
            ("plan_id", plan.plan_id.as_str()),
            ("candidate_id", plan.candidate_id.as_str()),
            ("lifecycle_graph_ref", plan.lifecycle_graph_ref.as_str()),
        ] {
            validate_required_text_loc(&located, "BW-V326-WITNESS-REQUIRED-EMPTY", field, value)?;
            reject_private_tokens_loc(&located, "BW-V326-WITNESS-PRIVATE-TOKEN", field, value)?;
        }
        validate_relative_path_loc(
            &located,
            "BW-V326-WITNESS-GRAPH-PATH",
            &plan.lifecycle_graph_ref,
        )?;
        if plan.actions.is_empty() {
            return Err(at_loc(
                &located,
                "BW-V326-WITNESS-ACTIONS-EMPTY",
                "witness plan actions 不能为空",
            ));
        }
        for action in &plan.actions {
            validate_required_text_loc(
                &located,
                "BW-V326-WITNESS-ACTION-ID",
                "actions.action_id",
                &action.action_id,
            )?;
            reject_private_tokens_loc(
                &located,
                "BW-V326-WITNESS-PRIVATE-TOKEN",
                "actions.action_id",
                &action.action_id,
            )?;
            validate_public_string_list(
                &located,
                "BW-V326-WITNESS-PRIVATE-TOKEN",
                "actions.graph_refs",
                &action.graph_refs,
            )?;
            validate_public_string_list(
                &located,
                "BW-V326-WITNESS-PRIVATE-TOKEN",
                "actions.notes",
                &action.notes,
            )?;
        }
        if plan.runtime_observers.is_empty() || plan.oracle_assertions.is_empty() {
            return Err(at_loc(
                &located,
                "BW-V326-WITNESS-OBSERVERS",
                "witness plan 必须说明 runtime_observers 和 oracle_assertions",
            ));
        }
        validate_public_string_list(
            &located,
            "BW-V326-WITNESS-PRIVATE-TOKEN",
            "runtime_observers",
            &plan.runtime_observers,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-WITNESS-PRIVATE-TOKEN",
            "oracle_assertions",
            &plan.oracle_assertions,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-WITNESS-PRIVATE-TOKEN",
            "replay_evidence_refs",
            &plan.replay_evidence_refs,
        )?;
        validate_public_string_list(
            &located,
            "BW-V326-WITNESS-PRIVATE-TOKEN",
            "notes",
            &plan.notes,
        )?;
        if !plan_ids.insert(plan.plan_id.clone()) {
            return Err(at_loc(
                &located,
                "BW-V326-WITNESS-ID-DUPLICATE",
                format!("plan_id {} 重复", plan.plan_id),
            ));
        }
        summary.record_count += 1;
    }
    Ok(summary)
}

pub fn build_v3_2_6_lifecycle_graph(
    candidate: &crate::V32CandidateRecord,
    evidence: &[V326LifecycleEvidenceRecord],
) -> V326LifecycleGraphRecord {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let refs = evidence
        .iter()
        .map(|item| item.record_id.clone())
        .collect::<Vec<_>>();

    nodes.push(V326LifecycleNode {
        node_id: "candidate".to_owned(),
        node_kind: V326LifecycleNodeKind::RustObject,
        label: candidate.candidate_id.clone(),
    });
    nodes.push(V326LifecycleNode {
        node_id: "foreign_api".to_owned(),
        node_kind: V326LifecycleNodeKind::ForeignApi,
        label: candidate
            .api_path
            .clone()
            .unwrap_or_else(|| "unknown_api".to_owned()),
    });

    if has_evidence(evidence, V326EvidenceKind::ForeignRegister) {
        edges.push(V326LifecycleEdge {
            from: "candidate".to_owned(),
            to: "foreign_api".to_owned(),
            edge_kind: V326LifecycleEdgeKind::RegisteredInto,
            evidence_refs: refs_for(evidence, V326EvidenceKind::ForeignRegister),
        });
    }
    if has_evidence(evidence, V326EvidenceKind::BorrowEdge) {
        nodes.push(V326LifecycleNode {
            node_id: "borrow".to_owned(),
            node_kind: V326LifecycleNodeKind::Borrow,
            label: "borrowed object evidence".to_owned(),
        });
        edges.push(V326LifecycleEdge {
            from: "borrow".to_owned(),
            to: "foreign_api".to_owned(),
            edge_kind: V326LifecycleEdgeKind::Borrows,
            evidence_refs: refs_for(evidence, V326EvidenceKind::BorrowEdge),
        });
    }
    if has_evidence(evidence, V326EvidenceKind::RawPointerEscape) {
        nodes.push(V326LifecycleNode {
            node_id: "raw_pointer".to_owned(),
            node_kind: V326LifecycleNodeKind::RawPointer,
            label: "raw pointer escape evidence".to_owned(),
        });
        edges.push(V326LifecycleEdge {
            from: "raw_pointer".to_owned(),
            to: "foreign_api".to_owned(),
            edge_kind: V326LifecycleEdgeKind::RawPointerEscape,
            evidence_refs: refs_for(evidence, V326EvidenceKind::RawPointerEscape),
        });
    }
    if has_evidence(evidence, V326EvidenceKind::OwnedAnchor) {
        nodes.push(V326LifecycleNode {
            node_id: "owned_anchor".to_owned(),
            node_kind: V326LifecycleNodeKind::RustObject,
            label: "owned anchor evidence".to_owned(),
        });
        edges.push(V326LifecycleEdge {
            from: "owned_anchor".to_owned(),
            to: "candidate".to_owned(),
            edge_kind: V326LifecycleEdgeKind::MovesInto,
            evidence_refs: refs_for(evidence, V326EvidenceKind::OwnedAnchor),
        });
    }
    if has_evidence(evidence, V326EvidenceKind::DropGuard) {
        nodes.push(V326LifecycleNode {
            node_id: "drop_guard".to_owned(),
            node_kind: V326LifecycleNodeKind::DropGuard,
            label: "drop guard evidence".to_owned(),
        });
        edges.push(V326LifecycleEdge {
            from: "candidate".to_owned(),
            to: "drop_guard".to_owned(),
            edge_kind: V326LifecycleEdgeKind::GuardedByDrop,
            evidence_refs: refs_for(evidence, V326EvidenceKind::DropGuard),
        });
    }
    if has_evidence(evidence, V326EvidenceKind::ForeignUnregister)
        || has_evidence(evidence, V326EvidenceKind::ReleaseSite)
    {
        nodes.push(V326LifecycleNode {
            node_id: "release_api".to_owned(),
            node_kind: V326LifecycleNodeKind::ReleaseApi,
            label: "release or unregister evidence".to_owned(),
        });
        let mut release_refs = refs_for(evidence, V326EvidenceKind::ForeignUnregister);
        release_refs.extend(refs_for(evidence, V326EvidenceKind::ReleaseSite));
        edges.push(V326LifecycleEdge {
            from: "foreign_api".to_owned(),
            to: "release_api".to_owned(),
            edge_kind: V326LifecycleEdgeKind::ReleasedBy,
            evidence_refs: release_refs,
        });
    }
    if has_evidence(evidence, V326EvidenceKind::OpaqueHandleTransfer) {
        nodes.push(V326LifecycleNode {
            node_id: "opaque_handle".to_owned(),
            node_kind: V326LifecycleNodeKind::OpaqueHandle,
            label: "opaque handle transfer evidence".to_owned(),
        });
        edges.push(V326LifecycleEdge {
            from: "candidate".to_owned(),
            to: "opaque_handle".to_owned(),
            edge_kind: V326LifecycleEdgeKind::MovesInto,
            evidence_refs: refs_for(evidence, V326EvidenceKind::OpaqueHandleTransfer),
        });
    }

    if edges.is_empty() {
        edges.push(V326LifecycleEdge {
            from: "candidate".to_owned(),
            to: "foreign_api".to_owned(),
            edge_kind: V326LifecycleEdgeKind::UnknownOrder,
            evidence_refs: if refs.is_empty() {
                vec!["evidence:incomplete".to_owned()]
            } else {
                refs.clone()
            },
        });
    }

    let mut incomplete_evidence = Vec::new();
    if has_evidence(evidence, V326EvidenceKind::ForeignRegister)
        && !has_evidence(evidence, V326EvidenceKind::ForeignUnregister)
        && !has_evidence(evidence, V326EvidenceKind::DropGuard)
    {
        incomplete_evidence
            .push("no unregister or drop guard evidence for registered callback".to_owned());
    }
    if has_evidence(evidence, V326EvidenceKind::RawPointerEscape)
        && !has_evidence(evidence, V326EvidenceKind::OwnedAnchor)
    {
        incomplete_evidence.push("raw pointer escape without owned anchor evidence".to_owned());
    }

    V326LifecycleGraphRecord {
        schema_version: V3_2_6_LIFECYCLE_GRAPH_SCHEMA_V1.to_owned(),
        run_id: candidate.run_id.clone(),
        candidate_id: candidate.candidate_id.clone(),
        crate_id: candidate.crate_id.clone(),
        pattern_family: candidate.pattern_family,
        nodes,
        edges,
        evidence_refs: refs,
        incomplete_evidence,
        notes: vec!["graph is evidence-derived and not a defect conclusion".to_owned()],
    }
}

pub fn derive_v3_2_6_lifecycle_features(
    candidate: &crate::V32CandidateRecord,
    graph: &V326LifecycleGraphRecord,
    evidence: &[V326LifecycleEvidenceRecord],
) -> V326LifecycleFeatureRecord {
    derive_v3_2_6_lifecycle_features_with_context(candidate, graph, evidence, &[], &[])
}

pub fn derive_v3_2_6_lifecycle_features_with_context(
    candidate: &crate::V32CandidateRecord,
    graph: &V326LifecycleGraphRecord,
    evidence: &[V326LifecycleEvidenceRecord],
    facts: &[V326LifecycleFactRecord],
    contracts: &[V326LifecycleContractRecord],
) -> V326LifecycleFeatureRecord {
    let scoped_evidence = evidence
        .iter()
        .filter(|item| {
            item.candidate_id == candidate.candidate_id && item.crate_id == candidate.crate_id
        })
        .cloned()
        .collect::<Vec<_>>();
    let evidence = scoped_evidence.as_slice();
    let scoped_facts = facts
        .iter()
        .filter(|item| {
            item.candidate_id == candidate.candidate_id && item.crate_id == candidate.crate_id
        })
        .cloned()
        .collect::<Vec<_>>();
    let facts = scoped_facts.as_slice();
    let mut features = V326FeatureSet::default();
    let mut feature_evidence = BTreeMap::<String, Vec<String>>::new();
    let mut missing_evidence = graph.incomplete_evidence.clone();
    let contracts = contracts
        .iter()
        .filter(|contract| lifecycle_contract_applies_to_candidate(candidate, facts, contract))
        .cloned()
        .collect::<Vec<_>>();

    set_feature(
        &mut features.has_foreign_register,
        &mut feature_evidence,
        "has_foreign_register",
        has_evidence(evidence, V326EvidenceKind::ForeignRegister),
        &refs_for(evidence, V326EvidenceKind::ForeignRegister),
    );
    // Retention is never derived from bare ContractRetention lifecycle facts.
    // Those facts are rejected by the public validator; exact-API contracts and
    // explicit ForeignRetentionHint evidence are the only retention signals.
    set_feature(
        &mut features.foreign_may_retain_callback,
        &mut feature_evidence,
        "foreign_may_retain_callback",
        has_evidence(evidence, V326EvidenceKind::ForeignRetentionHint)
            || has_contract_retention(&contracts),
        &retention_refs(evidence, &contracts),
    );
    set_feature(
        &mut features.foreign_may_retain_user_data,
        &mut feature_evidence,
        "foreign_may_retain_user_data",
        (has_evidence(evidence, V326EvidenceKind::ForeignRetentionHint)
            || has_contract_retention(&contracts))
            && (has_evidence(evidence, V326EvidenceKind::RawPointerEscape)
                || has_evidence(evidence, V326EvidenceKind::BorrowEdge)),
        &retention_refs(evidence, &contracts),
    );
    set_feature(
        &mut features.has_borrowed_capture,
        &mut feature_evidence,
        "has_borrowed_capture",
        has_evidence(evidence, V326EvidenceKind::BorrowEdge),
        &refs_for(evidence, V326EvidenceKind::BorrowEdge),
    );
    let raw_pointer_escape_bound = raw_pointer_escape_is_bound_to_register(&facts);
    let mut raw_pointer_refs = refs_for(evidence, V326EvidenceKind::RawPointerEscape);
    if raw_pointer_escape_bound {
        raw_pointer_refs.extend(refs_for(evidence, V326EvidenceKind::ForeignRegister));
        raw_pointer_refs.extend(raw_pointer_binding_fact_refs(&facts));
        raw_pointer_refs.sort();
        raw_pointer_refs.dedup();
    }
    set_feature(
        &mut features.has_raw_pointer_escape,
        &mut feature_evidence,
        "has_raw_pointer_escape",
        raw_pointer_escape_bound,
        &raw_pointer_refs,
    );
    let raw_parts_transfer_refs = authoritative_raw_parts_transfer_refs(facts);
    let drop_prevention_refs =
        authoritative_fact_refs(facts, &[V326LifecycleFactKind::DropPrevention]);
    let raw_parts_without_drop_prevention =
        !raw_parts_transfer_refs.is_empty() && drop_prevention_refs.is_empty();
    set_feature(
        &mut features.has_drop_prevention,
        &mut feature_evidence,
        "has_drop_prevention",
        !drop_prevention_refs.is_empty(),
        &drop_prevention_refs,
    );
    set_feature(
        &mut features.raw_parts_transfer_without_drop_prevention,
        &mut feature_evidence,
        "raw_parts_transfer_without_drop_prevention",
        raw_parts_without_drop_prevention,
        &raw_parts_transfer_refs,
    );
    if raw_parts_without_drop_prevention
        && !missing_evidence
            .iter()
            .any(|item| item == "raw_parts_transfer_without_drop_prevention")
    {
        missing_evidence.push("raw_parts_transfer_without_drop_prevention".to_owned());
    }
    let unverified_callback_user_data_owner_refs =
        authoritative_callback_user_data_reconstruction_refs(facts, "owner_from_transmute");
    let callback_user_data_owner_refs =
        verified_callback_user_data_reconstruction_refs(facts, "owner_from_transmute");
    let callback_user_data_leak_refs =
        verified_callback_user_data_reconstruction_refs(facts, "leak_from_raw");
    let callback_user_data_owner_without_leak_guard =
        !callback_user_data_owner_refs.is_empty() && callback_user_data_leak_refs.is_empty();
    set_feature(
        &mut features.callback_user_data_owner_reconstruction_without_leak_guard,
        &mut feature_evidence,
        "callback_user_data_owner_reconstruction_without_leak_guard",
        callback_user_data_owner_without_leak_guard,
        &callback_user_data_owner_refs,
    );
    if callback_user_data_owner_without_leak_guard
        && !missing_evidence
            .iter()
            .any(|item| item == "callback_user_data_leak_guard_missing")
    {
        missing_evidence.push("callback_user_data_leak_guard_missing".to_owned());
    }
    if !unverified_callback_user_data_owner_refs.is_empty()
        && callback_user_data_owner_refs.is_empty()
        && !missing_evidence
            .iter()
            .any(|item| item == "callback_user_data_object_flow_missing")
    {
        missing_evidence.push("callback_user_data_object_flow_missing".to_owned());
    }
    let returned_borrow_refs =
        authoritative_fact_refs(facts, &[V326LifecycleFactKind::ReturnedBorrowRelation]);
    set_feature(
        &mut features.has_returned_borrow_relation,
        &mut feature_evidence,
        "has_returned_borrow_relation",
        !returned_borrow_refs.is_empty(),
        &returned_borrow_refs,
    );
    let unconstrained_return_lifetime_refs =
        authoritative_unconstrained_return_lifetime_refs(facts);
    set_feature(
        &mut features.has_unconstrained_return_lifetime,
        &mut feature_evidence,
        "has_unconstrained_return_lifetime",
        !unconstrained_return_lifetime_refs.is_empty(),
        &unconstrained_return_lifetime_refs,
    );
    let persisted_returned_borrow_refs =
        authoritative_fact_refs(facts, &[V326LifecycleFactKind::PersistedReturnedBorrow]);
    set_feature(
        &mut features.has_persisted_returned_borrow,
        &mut feature_evidence,
        "has_persisted_returned_borrow",
        !persisted_returned_borrow_refs.is_empty(),
        &persisted_returned_borrow_refs,
    );
    let persistence_before_invalidation_refs = authoritative_verified_returned_borrow_order_refs(
        facts,
        "persistence_before_invalidation_use",
    );
    set_feature(
        &mut features.returned_borrow_persistence_before_invalidation,
        &mut feature_evidence,
        "returned_borrow_persistence_before_invalidation",
        !persistence_before_invalidation_refs.is_empty(),
        &persistence_before_invalidation_refs,
    );
    let persistence_after_invalidation_refs = authoritative_verified_returned_borrow_order_refs(
        facts,
        "invalidation_before_persistence_use",
    );
    set_feature(
        &mut features.returned_borrow_persistence_after_invalidation,
        &mut feature_evidence,
        "returned_borrow_persistence_after_invalidation",
        !persistence_after_invalidation_refs.is_empty(),
        &persistence_after_invalidation_refs,
    );
    let external_buffer_refs =
        authoritative_fact_refs(facts, &[V326LifecycleFactKind::ExternalBufferBinding]);
    set_feature(
        &mut features.has_external_buffer_binding,
        &mut feature_evidence,
        "has_external_buffer_binding",
        !external_buffer_refs.is_empty(),
        &external_buffer_refs,
    );
    let external_buffer_lifetime_bound_refs = refs_for_external_buffer_lifetime_bound(evidence);
    set_feature(
        &mut features.has_external_buffer_lifetime_bound,
        &mut feature_evidence,
        "has_external_buffer_lifetime_bound",
        !external_buffer_lifetime_bound_refs.is_empty(),
        &external_buffer_lifetime_bound_refs,
    );
    let relaxed_atomic_refs = authoritative_atomic_ordering_refs(facts, "relaxed");
    set_feature(
        &mut features.relaxed_atomic_load_in_iterator,
        &mut feature_evidence,
        "relaxed_atomic_load_in_iterator",
        !relaxed_atomic_refs.is_empty(),
        &relaxed_atomic_refs,
    );
    let acquire_atomic_refs = authoritative_atomic_ordering_refs(facts, "acquire");
    set_feature(
        &mut features.acquire_atomic_load_in_iterator,
        &mut feature_evidence,
        "acquire_atomic_load_in_iterator",
        !acquire_atomic_refs.is_empty(),
        &acquire_atomic_refs,
    );
    let verified_chain_refs = verified_object_chain_refs(facts);
    set_feature(
        &mut features.has_verified_object_chain,
        &mut feature_evidence,
        "has_verified_object_chain",
        !verified_chain_refs.is_empty(),
        &verified_chain_refs,
    );
    let release_chain_refs = release_order_chain_refs(facts);
    set_feature(
        &mut features.has_release_order_chain,
        &mut feature_evidence,
        "has_release_order_chain",
        !release_chain_refs.is_empty(),
        &release_chain_refs,
    );
    let persisted_invalidation_refs = persisted_invalidation_use_chain_refs(facts);
    set_feature(
        &mut features.has_persisted_invalidation_use_chain,
        &mut feature_evidence,
        "has_persisted_invalidation_use_chain",
        !persisted_invalidation_refs.is_empty(),
        &persisted_invalidation_refs,
    );
    let callback_release_use_refs = callback_release_use_chain_refs(facts);
    set_feature(
        &mut features.has_callback_release_use_chain,
        &mut feature_evidence,
        "has_callback_release_use_chain",
        !callback_release_use_refs.is_empty(),
        &callback_release_use_refs,
    );
    if has_evidence(evidence, V326EvidenceKind::RawPointerEscape)
        && !raw_pointer_escape_bound
        && !missing_evidence
            .iter()
            .any(|item| item == "raw_pointer_escape_without_registered_object_binding")
    {
        missing_evidence.push("raw_pointer_escape_without_registered_object_binding".to_owned());
    }
    let owned_anchor_fact_refs =
        authoritative_fact_refs(facts, &[V326LifecycleFactKind::OwnedMoveCapture]);
    let mut owned_anchor_refs = refs_for(evidence, V326EvidenceKind::OwnedAnchor);
    owned_anchor_refs.extend(owned_anchor_fact_refs);
    owned_anchor_refs.sort();
    owned_anchor_refs.dedup();
    set_feature(
        &mut features.has_owned_anchor,
        &mut feature_evidence,
        "has_owned_anchor",
        has_evidence(evidence, V326EvidenceKind::OwnedAnchor) || !owned_anchor_refs.is_empty(),
        &owned_anchor_refs,
    );
    let static_bound_refs = refs_for_static_lifetime_bound(evidence);
    set_feature(
        &mut features.has_static_bound,
        &mut feature_evidence,
        "has_static_bound",
        !static_bound_refs.is_empty(),
        &static_bound_refs,
    );
    let drop_guard_fact_refs = authoritative_fact_refs(facts, &[V326LifecycleFactKind::DropSite]);
    let mut drop_guard_refs = refs_for(evidence, V326EvidenceKind::DropGuard);
    drop_guard_refs.extend(drop_guard_fact_refs);
    drop_guard_refs.sort();
    drop_guard_refs.dedup();
    set_feature(
        &mut features.has_drop_guard,
        &mut feature_evidence,
        "has_drop_guard",
        has_evidence(evidence, V326EvidenceKind::DropGuard) || !drop_guard_refs.is_empty(),
        &drop_guard_refs,
    );
    let manual_drop_prevention_without_guard_refs =
        manual_drop_prevention_without_drop_guard_refs(facts);
    let manual_drop_prevention_without_guard =
        !manual_drop_prevention_without_guard_refs.is_empty();
    set_feature(
        &mut features.manual_drop_prevention_without_drop_guard,
        &mut feature_evidence,
        "manual_drop_prevention_without_drop_guard",
        manual_drop_prevention_without_guard,
        &manual_drop_prevention_without_guard_refs,
    );

    let unregister_fact_refs = authoritative_fact_refs(
        facts,
        &[
            V326LifecycleFactKind::UnregisterCall,
            V326LifecycleFactKind::ReleaseCall,
        ],
    );
    let has_unregister = has_evidence(evidence, V326EvidenceKind::ForeignUnregister)
        || has_evidence(evidence, V326EvidenceKind::ReleaseSite)
        || !unregister_fact_refs.is_empty();
    let mut unregister_refs = refs_for(evidence, V326EvidenceKind::ForeignUnregister);
    unregister_refs.extend(refs_for(evidence, V326EvidenceKind::ReleaseSite));
    unregister_refs.extend(unregister_fact_refs);
    set_feature(
        &mut features.has_foreign_unregister,
        &mut feature_evidence,
        "has_foreign_unregister",
        has_unregister,
        &unregister_refs,
    );

    let has_box_into_raw = evidence.iter().any(|item| {
        item.evidence_kind == V326EvidenceKind::OwnedAnchor
            && item
                .details
                .get("signal")
                .and_then(|value| value.as_str())
                .is_some_and(|signal| signal.contains("box into raw"))
    }) || evidence.iter().any(|item| {
        item.evidence_kind == V326EvidenceKind::OwnedAnchor
            && item
                .details
                .to_string()
                .to_ascii_lowercase()
                .contains("into_raw")
    });
    if has_box_into_raw {
        set_feature(
            &mut features.has_box_into_raw,
            &mut feature_evidence,
            "has_box_into_raw",
            true,
            &refs_for(evidence, V326EvidenceKind::OwnedAnchor),
        );
    }

    let has_box_from_raw = evidence.iter().any(|item| {
        item.evidence_kind == V326EvidenceKind::ReleaseSite
            && item
                .details
                .to_string()
                .to_ascii_lowercase()
                .contains("from_raw")
    });
    if has_box_from_raw {
        set_feature(
            &mut features.has_box_from_raw,
            &mut feature_evidence,
            "has_box_from_raw",
            true,
            &refs_for(evidence, V326EvidenceKind::ReleaseSite),
        );
    }

    let shared_owner_anchor_fact_refs = authoritative_shared_owner_anchor_refs(facts);
    let mut shared_owner_anchor_refs = refs_for(evidence, V326EvidenceKind::OwnedAnchor);
    shared_owner_anchor_refs.extend(shared_owner_anchor_fact_refs);
    shared_owner_anchor_refs.sort();
    shared_owner_anchor_refs.dedup();
    let has_arc = evidence.iter().any(|item| {
        item.evidence_kind == V326EvidenceKind::OwnedAnchor
            && (text_mentions_shared_owner_anchor(&item.details.to_string())
                || item
                    .details
                    .get("signal")
                    .and_then(|value| value.as_str())
                    .is_some_and(text_mentions_shared_owner_anchor))
    }) || !shared_owner_anchor_refs.is_empty();
    if has_arc {
        set_feature(
            &mut features.has_arc_anchor,
            &mut feature_evidence,
            "has_arc_anchor",
            true,
            &shared_owner_anchor_refs,
        );
    }

    set_feature(
        &mut features.registration_release_pair_found,
        &mut feature_evidence,
        "registration_release_pair_found",
        release_covers_same_lifecycle_object(evidence, &facts),
        &release_coverage_refs(evidence, &facts),
    );

    set_feature(
        &mut features.opaque_handle_without_owner,
        &mut feature_evidence,
        "opaque_handle_without_owner",
        has_evidence(evidence, V326EvidenceKind::OpaqueHandleTransfer)
            && !has_evidence(evidence, V326EvidenceKind::OwnedAnchor),
        &refs_for(evidence, V326EvidenceKind::OpaqueHandleTransfer),
    );

    let lifecycle_release_risk_signal = lifecycle_release_risk_signal(&features);
    let static_owned_retention_is_lifetime_protected =
        static_owned_retention_is_lifetime_protected(&features);

    let missing_unregister = features.has_foreign_register
        && lifecycle_release_risk_signal
        && !static_owned_retention_is_lifetime_protected
        && !features.has_foreign_unregister
        && !release_covers_same_lifecycle_object(evidence, &facts);
    set_feature(
        &mut features.missing_unregister_before_drop,
        &mut feature_evidence,
        "missing_unregister_before_drop",
        missing_unregister,
        &refs_for(evidence, V326EvidenceKind::ForeignRegister),
    );
    if missing_unregister
        && !missing_evidence
            .iter()
            .any(|item| item.to_ascii_lowercase().contains("unregister"))
    {
        missing_evidence.push("no unregister evidence found near candidate".to_owned());
    }

    let retained_without_lifetime_bound = features.has_foreign_register
        && (features.foreign_may_retain_callback || features.foreign_may_retain_user_data)
        && features.has_raw_pointer_escape
        && features.has_owned_anchor
        && !features.has_static_bound;
    let borrowed_without_release_guard = features.has_borrowed_capture
        && !features.has_foreign_unregister
        && !release_covers_same_lifecycle_object(evidence, &facts)
        && !features.has_owned_anchor;
    let may_drop_before_release = borrowed_without_release_guard || retained_without_lifetime_bound;
    let mut may_drop_refs = refs_for(evidence, V326EvidenceKind::BorrowEdge);
    may_drop_refs.extend(refs_for(evidence, V326EvidenceKind::ForeignRegister));
    may_drop_refs.extend(refs_for(evidence, V326EvidenceKind::RawPointerEscape));
    may_drop_refs.extend(refs_for(evidence, V326EvidenceKind::OwnedAnchor));
    may_drop_refs.extend(retention_refs(evidence, &contracts));
    may_drop_refs.extend(raw_pointer_binding_fact_refs(facts));
    may_drop_refs.sort();
    may_drop_refs.dedup();
    set_feature(
        &mut features.rust_object_may_drop_before_foreign_release,
        &mut feature_evidence,
        "rust_object_may_drop_before_foreign_release",
        may_drop_before_release,
        &may_drop_refs,
    );
    if retained_without_lifetime_bound
        && !missing_evidence
            .iter()
            .any(|item| item.contains("lifetime bound"))
    {
        missing_evidence.push("retained callback lacks static lifetime bound evidence".to_owned());
    }

    set_feature(
        &mut features.release_covers_callback,
        &mut feature_evidence,
        "release_covers_callback",
        release_covers_same_lifecycle_object(evidence, &facts),
        &release_coverage_refs(evidence, &facts),
    );

    let release_order_unknown = features.has_foreign_register
        && (lifecycle_release_risk_signal || features.has_foreign_unregister)
        && !release_order_is_proven_after_register(evidence, &facts);
    set_feature(
        &mut features.release_order_unknown,
        &mut feature_evidence,
        "release_order_unknown",
        release_order_unknown,
        &release_coverage_refs(evidence, &facts),
    );
    if features.has_foreign_register
        && features.has_foreign_unregister
        && !features.release_covers_callback
        && !missing_evidence
            .iter()
            .any(|item| item == "release_coverage_object_mismatch")
    {
        missing_evidence.push("release_coverage_object_mismatch".to_owned());
    }
    if release_order_unknown
        && !missing_evidence
            .iter()
            .any(|item| item == "release_order_unknown")
    {
        missing_evidence.push("release_order_unknown".to_owned());
    }
    append_feature_incomplete_reasons(&features, facts, &mut missing_evidence);

    let needs_dynamic = features.has_foreign_register
        && (features.missing_unregister_before_drop
            || features.release_order_unknown
            || features.rust_object_may_drop_before_foreign_release
            || evidence
                .iter()
                .all(|item| item.confidence == V326EvidenceConfidence::Low));
    let dynamic_refs = evidence
        .iter()
        .map(|item| item.record_id.clone())
        .collect::<Vec<_>>();
    set_feature(
        &mut features.needs_dynamic_witness,
        &mut feature_evidence,
        "needs_dynamic_witness",
        needs_dynamic,
        &dynamic_refs,
    );

    V326LifecycleFeatureRecord {
        schema_version: V3_2_6_LIFECYCLE_FEATURE_SCHEMA_V1.to_owned(),
        run_id: candidate.run_id.clone(),
        candidate_id: candidate.candidate_id.clone(),
        crate_id: candidate.crate_id.clone(),
        pattern_family: candidate.pattern_family,
        features,
        feature_evidence,
        missing_evidence,
        notes: vec![
            "candidate ranking is not a defect conclusion".to_owned(),
            "features are evidence-derived and not pattern-template defaults".to_owned(),
        ],
    }
}

pub fn rank_v3_2_6_features(
    run_id: &str,
    mut features: Vec<V326LifecycleFeatureRecord>,
) -> Result<Vec<V326RankedCandidateRecord>, ModelError> {
    for feature in &features {
        validate_v3_2_6_lifecycle_features([Located {
            path: std::path::PathBuf::from("rank-input"),
            line: 1,
            value: feature.clone(),
        }])?;
    }
    features.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let mut ranked = features
        .into_iter()
        .map(|feature| ranked_from_feature(run_id, feature))
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.candidate_id.cmp(&right.candidate_id))
    });
    for (index, item) in ranked.iter_mut().enumerate() {
        item.rank = index as u32 + 1;
    }
    Ok(ranked)
}

#[must_use]
pub fn summarize_v3_2_6_ranked_object_chains(
    candidate: &V326RankedCandidateRecord,
    graph: &V326LifecycleGraphV3Record,
) -> V326RankedChainSummary {
    let mut summary = V326RankedChainSummary::default();
    let mut chain_fact_refs = BTreeSet::<String>::new();
    let mut chain_incomplete_reasons = graph
        .incomplete_reasons
        .iter()
        .chain(candidate.missing_evidence.iter())
        .filter(|item| !item.trim().is_empty())
        .cloned()
        .collect::<BTreeSet<_>>();

    for chain in &graph.object_chains {
        match chain.chain_status {
            V326ObjectChainStatus::VerifiedStaticChain => summary.verified_chain_count += 1,
            V326ObjectChainStatus::PartialChain => summary.partial_chain_count += 1,
            V326ObjectChainStatus::AmbiguousChain => summary.ambiguous_chain_count += 1,
            V326ObjectChainStatus::ObservationOnly => summary.observation_only_chain_count += 1,
        }
        if chain
            .verified_layers
            .contains(&V326ObjectChainLayer::IdentityTransport)
        {
            summary.identity_transport_chain_count += 1;
        }
        if chain
            .verified_layers
            .contains(&V326ObjectChainLayer::ReleaseOrdering)
        {
            summary.release_ordering_chain_count += 1;
        }
        if chain
            .verified_layers
            .contains(&V326ObjectChainLayer::UseOrdering)
        {
            summary.use_ordering_chain_count += 1;
        }
        if chain
            .verified_layers
            .contains(&V326ObjectChainLayer::LifecycleOrdering)
        {
            summary.lifecycle_ordering_chain_count += 1;
        }
        if chain
            .verified_layers
            .contains(&V326ObjectChainLayer::CompleteRiskChain)
        {
            summary.complete_risk_chain_count += 1;
        }
        chain_fact_refs.extend(chain.fact_refs.iter().cloned());
        if matches!(
            chain.chain_status,
            V326ObjectChainStatus::PartialChain
                | V326ObjectChainStatus::AmbiguousChain
                | V326ObjectChainStatus::ObservationOnly
        ) {
            chain_incomplete_reasons.insert(chain_status_incomplete_reason(chain));
        }
    }

    if let Some(chain) = top_ranked_object_chain(graph) {
        summary.top_chain_id = Some(chain.chain_id.clone());
        summary.top_chain_status = Some(chain.chain_status);
    }
    summary.chain_fact_refs = chain_fact_refs.into_iter().collect();
    summary.chain_incomplete_reasons = chain_incomplete_reasons.into_iter().collect();
    summary.recommended_witness_route = recommended_witness_route(candidate, graph);
    summary
}

fn top_ranked_object_chain(graph: &V326LifecycleGraphV3Record) -> Option<&V326ObjectChain> {
    graph.object_chains.iter().max_by(|left, right| {
        chain_layer_priority(left)
            .cmp(&chain_layer_priority(right))
            .then_with(|| {
                chain_status_priority(left.chain_status)
                    .cmp(&chain_status_priority(right.chain_status))
            })
            .then_with(|| left.edge_ids.len().cmp(&right.edge_ids.len()))
            .then_with(|| left.fact_refs.len().cmp(&right.fact_refs.len()))
            .then_with(|| right.chain_id.cmp(&left.chain_id))
    })
}

fn chain_layer_priority(chain: &V326ObjectChain) -> u8 {
    if chain
        .verified_layers
        .contains(&V326ObjectChainLayer::CompleteRiskChain)
    {
        return 4;
    }
    if chain
        .verified_layers
        .contains(&V326ObjectChainLayer::LifecycleOrdering)
    {
        return 3;
    }
    if chain
        .verified_layers
        .contains(&V326ObjectChainLayer::IdentityTransport)
    {
        return 2;
    }
    1
}

fn chain_status_priority(status: V326ObjectChainStatus) -> u8 {
    match status {
        V326ObjectChainStatus::VerifiedStaticChain => 4,
        V326ObjectChainStatus::PartialChain => 3,
        V326ObjectChainStatus::AmbiguousChain => 2,
        V326ObjectChainStatus::ObservationOnly => 1,
    }
}

fn chain_status_incomplete_reason(chain: &V326ObjectChain) -> String {
    match chain.chain_status {
        V326ObjectChainStatus::VerifiedStaticChain => "verified_static_chain".to_owned(),
        V326ObjectChainStatus::PartialChain => partial_chain_incomplete_reason(chain).to_owned(),
        V326ObjectChainStatus::AmbiguousChain => "object_binding_ambiguous".to_owned(),
        V326ObjectChainStatus::ObservationOnly => "object_binding_missing".to_owned(),
    }
}

fn partial_chain_incomplete_reason(chain: &V326ObjectChain) -> &'static str {
    if chain.chain_id.contains("returned_view")
        || chain.object_ids.iter().any(|object_id| {
            object_id.starts_with("returned_ref:") || object_id.starts_with("storage:")
        })
    {
        return "use_ordering_proof_missing";
    }
    if chain.chain_id.contains("object_flow") {
        return "object_flow_counterpart_missing";
    }
    if chain.chain_id.contains("external_buffer_binding") {
        return "complete_risk_chain_missing";
    }
    "partial_chain"
}

fn recommended_witness_route(
    candidate: &V326RankedCandidateRecord,
    graph: &V326LifecycleGraphV3Record,
) -> V326WitnessRoute {
    if candidate.pattern_family == V32PatternFamily::ReturnedBorrowView
        || ranked_candidate_has_returned_view_signal(candidate)
        || graph_has_returned_view_signal(graph)
    {
        V326WitnessRoute::ReturnedViewMiri
    } else if candidate.pattern_family == V32PatternFamily::ExternalBufferView
        || ranked_candidate_has_external_buffer_signal(candidate)
    {
        V326WitnessRoute::ExternalBufferLifetime
    } else if matches!(
        candidate.pattern_family,
        V32PatternFamily::RetainedBorrowedCallback
            | V32PatternFamily::CallbackLifecycleRelease
            | V32PatternFamily::ForeignRetainedPointer
            | V32PatternFamily::OpaqueHandleTransfer
    ) || graph_has_callback_signal(graph)
    {
        V326WitnessRoute::CallbackLifecycle
    } else {
        V326WitnessRoute::ManualReviewOnly
    }
}

fn ranked_candidate_has_returned_view_signal(candidate: &V326RankedCandidateRecord) -> bool {
    candidate
        .risk_features
        .iter()
        .chain(candidate.protective_features.iter())
        .any(|feature| {
            matches!(
                feature.as_str(),
                "has_returned_borrow_relation"
                    | "has_persisted_returned_borrow"
                    | "returned_borrow_persistence_before_invalidation"
                    | "returned_borrow_persistence_after_invalidation"
                    | "has_persisted_invalidation_use_chain"
            )
        })
}

fn ranked_candidate_has_external_buffer_signal(candidate: &V326RankedCandidateRecord) -> bool {
    candidate
        .risk_features
        .iter()
        .chain(candidate.protective_features.iter())
        .any(|feature| {
            matches!(
                feature.as_str(),
                "has_external_buffer_binding" | "has_external_buffer_lifetime_bound"
            )
        })
}

fn graph_has_returned_view_signal(graph: &V326LifecycleGraphV3Record) -> bool {
    graph
        .objects
        .iter()
        .any(|object| object.object_kind == V326LifecycleObjectKind::ReturnedRef)
        || graph.edges.iter().any(|edge| {
            matches!(
                edge.relation,
                V326LifecycleRelation::Borrow
                    | V326LifecycleRelation::Persist
                    | V326LifecycleRelation::Invalidate
                    | V326LifecycleRelation::Use
            ) && (edge.from_object_id.starts_with("returned_ref:")
                || edge.to_object_id.starts_with("returned_ref:")
                || edge.from_object_id.starts_with("storage:")
                || edge.to_object_id.starts_with("storage:"))
        })
}

fn graph_has_callback_signal(graph: &V326LifecycleGraphV3Record) -> bool {
    graph.objects.iter().any(|object| {
        matches!(
            object.object_kind,
            V326LifecycleObjectKind::Callback
                | V326LifecycleObjectKind::UserData
                | V326LifecycleObjectKind::ForeignOwner
                | V326LifecycleObjectKind::OpaqueHandle
        )
    }) || graph.edges.iter().any(|edge| {
        matches!(
            edge.relation,
            V326LifecycleRelation::Register
                | V326LifecycleRelation::Retain
                | V326LifecycleRelation::Replace
                | V326LifecycleRelation::Release
                | V326LifecycleRelation::CallbackTrigger
        )
    })
}

pub fn compare_v3_2_6_pair(
    pair: &V326AnonymousPairRecord,
    left: &V326LifecycleFeatureRecord,
    right: &V326LifecycleFeatureRecord,
) -> Result<V326PairDeltaRecord, ModelError> {
    if pair.left_crate_id != left.crate_id || pair.right_crate_id != right.crate_id {
        return Err(ModelError::validation(
            "BW-V326-PAIR-MISMATCH",
            "pair crate ids do not match feature records",
        ));
    }

    if !left.features.has_any_active() || !right.features.has_any_active() {
        return Ok(V326PairDeltaRecord {
            schema_version: V3_2_6_PAIR_DELTA_SCHEMA_V1.to_owned(),
            run_id: pair.run_id.clone(),
            pair_id: pair.pair_id.clone(),
            comparison_key: String::new(),
            pair_manifest_run_id: String::new(),
            left_crate_id: pair.left_crate_id.clone(),
            right_crate_id: pair.right_crate_id.clone(),
            left_top_features: active_feature_names(&left.features),
            right_top_features: active_feature_names(&right.features),
            semantic_delta: Vec::new(),
            distinguishability: V326Distinguishability::InsufficientEvidence,
            notes: vec![
                "pair roles are anonymous; this is not a defect conclusion".to_owned(),
                "at least one side has insufficient lifecycle features".to_owned(),
            ],
        });
    }

    let mut delta = Vec::new();
    if !left.features.has_drop_guard && right.features.has_drop_guard {
        delta.push("right_added_drop_guard".to_owned());
    }
    if left.features.has_drop_guard && !right.features.has_drop_guard {
        delta.push("left_added_drop_guard".to_owned());
    }
    if !left.features.has_foreign_unregister && right.features.has_foreign_unregister {
        delta.push("right_added_unregister_path".to_owned());
    }
    if left.features.has_foreign_unregister && !right.features.has_foreign_unregister {
        delta.push("left_added_unregister_path".to_owned());
    }
    if !left.features.has_owned_anchor && right.features.has_owned_anchor {
        delta.push("right_added_owned_anchor".to_owned());
    }
    if left.features.has_owned_anchor && !right.features.has_owned_anchor {
        delta.push("left_added_owned_anchor".to_owned());
    }
    if !left.features.has_static_bound && right.features.has_static_bound {
        delta.push("right_added_static_bound".to_owned());
    }
    if left.features.has_static_bound && !right.features.has_static_bound {
        delta.push("left_added_static_bound".to_owned());
    }
    if !left.features.has_drop_prevention && right.features.has_drop_prevention {
        delta.push("right_added_drop_prevention".to_owned());
    }
    if left.features.has_drop_prevention && !right.features.has_drop_prevention {
        delta.push("left_added_drop_prevention".to_owned());
    }
    if left.features.manual_drop_prevention_without_drop_guard
        && !right.features.manual_drop_prevention_without_drop_guard
    {
        delta.push("right_removed_manual_drop_prevention_without_drop_guard".to_owned());
    }
    if !left.features.manual_drop_prevention_without_drop_guard
        && right.features.manual_drop_prevention_without_drop_guard
    {
        delta.push("left_removed_manual_drop_prevention_without_drop_guard".to_owned());
    }
    if !left.features.has_external_buffer_lifetime_bound
        && right.features.has_external_buffer_lifetime_bound
    {
        delta.push("right_added_external_buffer_lifetime_bound".to_owned());
    }
    if left.features.has_external_buffer_lifetime_bound
        && !right.features.has_external_buffer_lifetime_bound
    {
        delta.push("left_added_external_buffer_lifetime_bound".to_owned());
    }
    if !left.features.registration_release_pair_found
        && right.features.registration_release_pair_found
    {
        delta.push("right_added_registration_release_pair".to_owned());
    }
    if left.features.registration_release_pair_found
        && !right.features.registration_release_pair_found
    {
        delta.push("left_added_registration_release_pair".to_owned());
    }
    if !left.features.release_covers_callback && right.features.release_covers_callback {
        delta.push("right_added_release_coverage".to_owned());
    }
    if left.features.release_covers_callback && !right.features.release_covers_callback {
        delta.push("left_added_release_coverage".to_owned());
    }
    if left
        .missing_evidence
        .iter()
        .any(|item| item == "release_coverage_object_mismatch")
    {
        delta.push("left_release_coverage_object_mismatch".to_owned());
    }
    if right
        .missing_evidence
        .iter()
        .any(|item| item == "release_coverage_object_mismatch")
    {
        delta.push("right_release_coverage_object_mismatch".to_owned());
    }
    if left.features.release_order_unknown && !right.features.release_order_unknown {
        delta.push("left_ordering_unknown".to_owned());
    }
    if !left.features.release_order_unknown && right.features.release_order_unknown {
        delta.push("right_ordering_unknown".to_owned());
    }
    if left.features.has_raw_pointer_escape && !right.features.has_raw_pointer_escape {
        delta.push("right_removed_raw_pointer_escape".to_owned());
    }
    if !left.features.has_raw_pointer_escape && right.features.has_raw_pointer_escape {
        delta.push("left_removed_raw_pointer_escape".to_owned());
    }
    if left.features.has_returned_borrow_relation && !right.features.has_returned_borrow_relation {
        delta.push("right_removed_returned_borrow_relation".to_owned());
    }
    if !left.features.has_returned_borrow_relation && right.features.has_returned_borrow_relation {
        delta.push("left_removed_returned_borrow_relation".to_owned());
    }
    if left.features.has_unconstrained_return_lifetime
        && !right.features.has_unconstrained_return_lifetime
    {
        delta.push("right_removed_unconstrained_return_lifetime".to_owned());
    }
    if !left.features.has_unconstrained_return_lifetime
        && right.features.has_unconstrained_return_lifetime
    {
        delta.push("left_removed_unconstrained_return_lifetime".to_owned());
    }
    if left.features.has_persisted_returned_borrow && !right.features.has_persisted_returned_borrow
    {
        delta.push("right_removed_persisted_returned_borrow".to_owned());
    }
    if !left.features.has_persisted_returned_borrow && right.features.has_persisted_returned_borrow
    {
        delta.push("left_removed_persisted_returned_borrow".to_owned());
    }
    if left
        .features
        .returned_borrow_persistence_before_invalidation
        && !right
            .features
            .returned_borrow_persistence_before_invalidation
    {
        delta.push("right_removed_persistence_before_invalidation".to_owned());
    }
    if !left
        .features
        .returned_borrow_persistence_before_invalidation
        && right
            .features
            .returned_borrow_persistence_before_invalidation
    {
        delta.push("left_removed_persistence_before_invalidation".to_owned());
    }
    if left.features.returned_borrow_persistence_after_invalidation
        && !right
            .features
            .returned_borrow_persistence_after_invalidation
    {
        delta.push("left_added_persistence_after_invalidation".to_owned());
    }
    if !left.features.returned_borrow_persistence_after_invalidation
        && right
            .features
            .returned_borrow_persistence_after_invalidation
    {
        delta.push("right_added_persistence_after_invalidation".to_owned());
    }
    if left.features.has_external_buffer_binding && !right.features.has_external_buffer_binding {
        delta.push("right_removed_external_buffer_binding".to_owned());
    }
    if !left.features.has_external_buffer_binding && right.features.has_external_buffer_binding {
        delta.push("left_removed_external_buffer_binding".to_owned());
    }
    if left.features.relaxed_atomic_load_in_iterator
        && !right.features.relaxed_atomic_load_in_iterator
    {
        delta.push("right_removed_relaxed_atomic_load_in_iterator".to_owned());
    }
    if !left.features.relaxed_atomic_load_in_iterator
        && right.features.relaxed_atomic_load_in_iterator
    {
        delta.push("left_removed_relaxed_atomic_load_in_iterator".to_owned());
    }
    if !left.features.acquire_atomic_load_in_iterator
        && right.features.acquire_atomic_load_in_iterator
    {
        delta.push("right_added_acquire_atomic_load_in_iterator".to_owned());
    }
    if left.features.acquire_atomic_load_in_iterator
        && !right.features.acquire_atomic_load_in_iterator
    {
        delta.push("left_added_acquire_atomic_load_in_iterator".to_owned());
    }
    if left.features.has_callback_release_use_chain
        && !right.features.has_callback_release_use_chain
    {
        delta.push("right_removed_callback_release_use_chain".to_owned());
    }
    if !left.features.has_callback_release_use_chain
        && right.features.has_callback_release_use_chain
    {
        delta.push("left_removed_callback_release_use_chain".to_owned());
    }
    if left.features.has_borrowed_capture && !right.features.has_borrowed_capture {
        delta.push("right_removed_borrowed_capture".to_owned());
    }
    if !left.features.has_borrowed_capture && right.features.has_borrowed_capture {
        delta.push("left_removed_borrowed_capture".to_owned());
    }

    let distinguishability = if delta.is_empty() {
        V326Distinguishability::IndistinguishableStaticOnly
    } else {
        V326Distinguishability::SeparableStatic
    };

    Ok(V326PairDeltaRecord {
        schema_version: V3_2_6_PAIR_DELTA_SCHEMA_V1.to_owned(),
        run_id: pair.run_id.clone(),
        pair_id: pair.pair_id.clone(),
        comparison_key: String::new(),
        pair_manifest_run_id: String::new(),
        left_crate_id: pair.left_crate_id.clone(),
        right_crate_id: pair.right_crate_id.clone(),
        left_top_features: active_feature_names(&left.features),
        right_top_features: active_feature_names(&right.features),
        semantic_delta: delta,
        distinguishability,
        notes: vec!["pair roles are anonymous; this is not a defect conclusion".to_owned()],
    })
}

pub fn build_v3_2_6_lifecycle_graph_v3(
    candidate: &crate::V32CandidateRecord,
    evidence: &[V326LifecycleEvidenceRecord],
    facts: &[V326LifecycleFactRecord],
    contracts: &[V326LifecycleContractRecord],
) -> V326LifecycleGraphV3Record {
    let mut objects_by_id = BTreeMap::<String, V326LifecycleObject>::new();
    let mut edges = Vec::<V326LifecycleGraphV3Edge>::new();
    let mut incomplete_reasons = Vec::<String>::new();
    let scoped_evidence = evidence
        .iter()
        .filter(|item| {
            item.candidate_id == candidate.candidate_id && item.crate_id == candidate.crate_id
        })
        .cloned()
        .collect::<Vec<_>>();
    let evidence = scoped_evidence.as_slice();
    let scoped_facts = facts
        .iter()
        .filter(|fact| {
            fact.candidate_id == candidate.candidate_id && fact.crate_id == candidate.crate_id
        })
        .cloned()
        .collect::<Vec<_>>();
    let facts = scoped_facts.as_slice();
    let authoritative_facts = facts
        .iter()
        .filter(|fact| is_authoritative_object_binding_fact(fact))
        .cloned()
        .collect::<Vec<_>>();
    let chain_facts = facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact)
                || is_authoritative_object_binding_gap_fact(fact)
        })
        .cloned()
        .collect::<Vec<_>>();
    let contracts = contracts
        .iter()
        .filter(|contract| lifecycle_contract_applies_to_candidate(candidate, facts, contract))
        .cloned()
        .collect::<Vec<_>>();

    let foreign_owner_id = format!(
        "foreign_owner:{}",
        sanitize_id_for_path(
            candidate
                .api_path
                .as_deref()
                .unwrap_or(candidate.candidate_id.as_str())
        )
    );
    add_object(
        &mut objects_by_id,
        foreign_owner_id.clone(),
        V326LifecycleObjectKind::ForeignOwner,
        candidate
            .api_path
            .clone()
            .unwrap_or_else(|| "unknown foreign owner".to_owned()),
        None,
        Vec::new(),
    );

    for fact in &authoritative_facts {
        for object_id in &fact.object_ids {
            add_object(
                &mut objects_by_id,
                object_id.clone(),
                object_kind_from_id(object_id),
                object_id.clone(),
                Some(fact.source_ref.clone()),
                vec![fact.fact_id.clone()],
            );
        }
    }
    for item in evidence {
        match item.evidence_kind {
            V326EvidenceKind::ForeignRegister => {
                let callback_id = callback_object_id_for_evidence(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[V326LifecycleFactKind::RegisterCall],
                );
                edges.push(V326LifecycleGraphV3Edge {
                    edge_id: format!("edge:{}:register", sanitize_id_for_path(&item.record_id)),
                    from_object_id: callback_id.clone(),
                    to_object_id: foreign_owner_id.clone(),
                    relation: V326LifecycleRelation::Register,
                    ordering: ordering_from_evidence(item),
                    evidence_refs: vec![item.record_id.clone()],
                    fact_refs: fact_refs_for_kind_on_object(
                        &authoritative_facts,
                        item,
                        V326LifecycleFactKind::RegisterCall,
                        &callback_id,
                    ),
                });
            }
            V326EvidenceKind::ForeignRetentionHint => {
                // Retention edges are observation-level unless an exact contract later
                // adds a retain edge. Bare ContractRetention facts are not authoritative.
                let callback_id = observation_object_id("callback", &item.record_id);
                add_object(
                    &mut objects_by_id,
                    callback_id.clone(),
                    V326LifecycleObjectKind::Unknown,
                    "callback object binding unproven".to_owned(),
                    Some(item.source_ref.clone()),
                    Vec::new(),
                );
                edges.push(V326LifecycleGraphV3Edge {
                    edge_id: format!("edge:{}:retain", sanitize_id_for_path(&item.record_id)),
                    from_object_id: foreign_owner_id.clone(),
                    to_object_id: callback_id,
                    relation: V326LifecycleRelation::Retain,
                    ordering: V326LifecycleOrdering::Unknown,
                    evidence_refs: vec![item.record_id.clone()],
                    fact_refs: Vec::new(),
                });
            }
            V326EvidenceKind::ForeignUnregister | V326EvidenceKind::ReleaseSite => {
                let callback_id = callback_object_id_for_evidence(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[
                        V326LifecycleFactKind::UnregisterCall,
                        V326LifecycleFactKind::ReleaseCall,
                    ],
                );
                let release_id =
                    format!("release_endpoint:{}", sanitize_id_for_path(&item.record_id));
                add_object(
                    &mut objects_by_id,
                    release_id.clone(),
                    V326LifecycleObjectKind::ReleaseEndpoint,
                    "release endpoint".to_owned(),
                    Some(item.source_ref.clone()),
                    Vec::new(),
                );
                edges.push(V326LifecycleGraphV3Edge {
                    edge_id: format!("edge:{}:release", sanitize_id_for_path(&item.record_id)),
                    from_object_id: callback_id.clone(),
                    to_object_id: release_id,
                    relation: V326LifecycleRelation::Release,
                    ordering: V326LifecycleOrdering::Unknown,
                    evidence_refs: vec![item.record_id.clone()],
                    fact_refs: fact_refs_for_any_kind_on_object(
                        &authoritative_facts,
                        item,
                        &[
                            V326LifecycleFactKind::UnregisterCall,
                            V326LifecycleFactKind::ReleaseCall,
                        ],
                        &callback_id,
                    ),
                });
            }
            V326EvidenceKind::DropGuard | V326EvidenceKind::DropSite => {
                let callback_id = callback_object_id_for_evidence(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[
                        V326LifecycleFactKind::DropImpl,
                        V326LifecycleFactKind::DropSite,
                    ],
                );
                let owner_id = object_id_for_evidence_with_prefix_or_observation(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[
                        V326LifecycleFactKind::DropImpl,
                        V326LifecycleFactKind::DropSite,
                    ],
                    "rust_owner:",
                    "rust_owner",
                    "Rust owner",
                );
                edges.push(V326LifecycleGraphV3Edge {
                    edge_id: format!("edge:{}:drop", sanitize_id_for_path(&item.record_id)),
                    from_object_id: owner_id.clone(),
                    to_object_id: callback_id.clone(),
                    relation: V326LifecycleRelation::Drop,
                    ordering: ordering_from_evidence(item),
                    evidence_refs: vec![item.record_id.clone()],
                    fact_refs: fact_refs_for_any_kind_on_objects(
                        &authoritative_facts,
                        item,
                        &[
                            V326LifecycleFactKind::DropImpl,
                            V326LifecycleFactKind::DropSite,
                        ],
                        &[owner_id.clone(), callback_id],
                    ),
                });
            }
            V326EvidenceKind::BorrowEdge => {
                let callback_id = callback_object_id_for_evidence(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[V326LifecycleFactKind::BorrowedCapture],
                );
                let source_id = object_id_for_evidence_with_prefix_or_observation(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[V326LifecycleFactKind::BorrowedCapture],
                    "rust_owner:",
                    "rust_owner",
                    "borrowed Rust owner",
                );
                edges.push(V326LifecycleGraphV3Edge {
                    edge_id: format!("edge:{}:borrow", sanitize_id_for_path(&item.record_id)),
                    from_object_id: source_id,
                    to_object_id: callback_id.clone(),
                    relation: V326LifecycleRelation::Borrow,
                    ordering: V326LifecycleOrdering::SameSite,
                    evidence_refs: vec![item.record_id.clone()],
                    fact_refs: fact_refs_for_any_kind_on_object(
                        &authoritative_facts,
                        item,
                        &[V326LifecycleFactKind::BorrowedCapture],
                        &callback_id,
                    ),
                });
            }
            V326EvidenceKind::MoveEdge | V326EvidenceKind::OwnedAnchor => {
                let callback_id = callback_object_id_for_evidence(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[V326LifecycleFactKind::OwnedMoveCapture],
                );
                let source_id = object_id_for_evidence_with_prefix_or_observation(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[V326LifecycleFactKind::OwnedMoveCapture],
                    "rust_owner:",
                    "rust_owner",
                    "owned Rust owner",
                );
                edges.push(V326LifecycleGraphV3Edge {
                    edge_id: format!("edge:{}:move", sanitize_id_for_path(&item.record_id)),
                    from_object_id: source_id,
                    to_object_id: callback_id.clone(),
                    relation: V326LifecycleRelation::Move,
                    ordering: V326LifecycleOrdering::SameSite,
                    evidence_refs: vec![item.record_id.clone()],
                    fact_refs: fact_refs_for_any_kind_on_object(
                        &authoritative_facts,
                        item,
                        &[V326LifecycleFactKind::OwnedMoveCapture],
                        &callback_id,
                    ),
                });
            }
            V326EvidenceKind::RawPointerEscape => {
                let source_id = object_id_for_evidence_with_prefix_or_observation(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[V326LifecycleFactKind::RawPointerEscape],
                    "user_data:",
                    "user_data",
                    "raw pointer source",
                );
                edges.push(V326LifecycleGraphV3Edge {
                    edge_id: format!("edge:{}:raw_escape", sanitize_id_for_path(&item.record_id)),
                    from_object_id: source_id.clone(),
                    to_object_id: foreign_owner_id.clone(),
                    relation: V326LifecycleRelation::RawEscape,
                    ordering: V326LifecycleOrdering::SameSite,
                    evidence_refs: vec![item.record_id.clone()],
                    fact_refs: fact_refs_for_any_kind_on_object(
                        &authoritative_facts,
                        item,
                        &[V326LifecycleFactKind::RawPointerEscape],
                        &source_id,
                    ),
                });
            }
            V326EvidenceKind::ForeignReplace => {
                let callback_id = callback_object_id_for_evidence(
                    &mut objects_by_id,
                    item,
                    &authoritative_facts,
                    &[V326LifecycleFactKind::ReplaceCall],
                );
                edges.push(V326LifecycleGraphV3Edge {
                    edge_id: format!("edge:{}:replace", sanitize_id_for_path(&item.record_id)),
                    from_object_id: callback_id.clone(),
                    to_object_id: foreign_owner_id.clone(),
                    relation: V326LifecycleRelation::Replace,
                    ordering: ordering_from_evidence(item),
                    evidence_refs: vec![item.record_id.clone()],
                    fact_refs: fact_refs_for_kind_on_object(
                        &authoritative_facts,
                        item,
                        V326LifecycleFactKind::ReplaceCall,
                        &callback_id,
                    ),
                });
            }
            V326EvidenceKind::CallbackCandidate
            | V326EvidenceKind::ObjectCandidate
            | V326EvidenceKind::CaptureEdge
            | V326EvidenceKind::LifetimeBound
            | V326EvidenceKind::OpaqueHandleTransfer => {}
        }
    }

    append_authoritative_fact_edges(
        &mut objects_by_id,
        &mut edges,
        &foreign_owner_id,
        &authoritative_facts,
    );

    for contract in contracts
        .iter()
        .filter(|contract| contract.retention == V326ContractRetention::MayRetainCallback)
    {
        let callback_id = observation_object_id("callback", &contract.contract_id);
        add_object(
            &mut objects_by_id,
            callback_id.clone(),
            V326LifecycleObjectKind::Unknown,
            "callback object binding unproven".to_owned(),
            None,
            Vec::new(),
        );
        edges.push(V326LifecycleGraphV3Edge {
            edge_id: format!(
                "edge:{}:contract_retain",
                sanitize_id_for_path(&contract.contract_id)
            ),
            from_object_id: foreign_owner_id.clone(),
            to_object_id: callback_id,
            relation: V326LifecycleRelation::Retain,
            ordering: V326LifecycleOrdering::Unknown,
            evidence_refs: contract.evidence_refs.clone(),
            fact_refs: vec![contract.contract_id.clone()],
        });
    }

    if authoritative_facts.is_empty() {
        incomplete_reasons.push("mir_hir_fact_missing".to_owned());
    }
    if contracts.is_empty() && candidate_requires_foreign_contract(candidate, evidence) {
        incomplete_reasons.push("foreign_contract_missing".to_owned());
    }
    if has_evidence(evidence, V326EvidenceKind::ForeignRegister)
        && !has_evidence(evidence, V326EvidenceKind::ForeignUnregister)
        && !has_evidence(evidence, V326EvidenceKind::ReleaseSite)
    {
        incomplete_reasons.push("release_endpoint_missing".to_owned());
    }
    if !release_covers_same_lifecycle_object(evidence, &facts)
        && has_evidence(evidence, V326EvidenceKind::ForeignRegister)
        && (has_evidence(evidence, V326EvidenceKind::ForeignUnregister)
            || has_evidence(evidence, V326EvidenceKind::ReleaseSite))
    {
        incomplete_reasons.push("release_coverage_object_mismatch".to_owned());
    }
    if objects_by_id
        .keys()
        .any(|object_id| object_id.starts_with("observation:"))
    {
        incomplete_reasons.push("object_binding_unproven".to_owned());
    }
    if objects_by_id
        .keys()
        .any(|object_id| object_id.starts_with("observation:callback:"))
    {
        incomplete_reasons.push("callback_object_identity_unavailable".to_owned());
    }
    let object_chains = build_v3_2_6_object_chains(&edges, &chain_facts);
    if !object_chains
        .iter()
        .any(|chain| chain.chain_status == V326ObjectChainStatus::VerifiedStaticChain)
        && !object_chains
            .iter()
            .any(candidate_scoped_static_chain_attempt)
        && (!authoritative_facts.is_empty() || !evidence.is_empty())
    {
        incomplete_reasons.push("object_flow_missing".to_owned());
    }
    append_object_chain_incomplete_reasons(&object_chains, &chain_facts, &mut incomplete_reasons);
    append_object_binding_gap_reasons(facts, &mut incomplete_reasons);
    incomplete_reasons.sort();
    incomplete_reasons.dedup();

    V326LifecycleGraphV3Record {
        schema_version: V3_2_6_LIFECYCLE_GRAPH_V3_SCHEMA_V1.to_owned(),
        run_id: candidate.run_id.clone(),
        candidate_id: candidate.candidate_id.clone(),
        crate_id: candidate.crate_id.clone(),
        pattern_family: candidate.pattern_family,
        objects: objects_by_id.into_values().collect(),
        edges,
        object_chains,
        evidence_refs: evidence.iter().map(|item| item.record_id.clone()).collect(),
        incomplete_reasons,
        notes: vec![
            "graph v3 is object-bound and not a defect conclusion".to_owned(),
            "identity transport, lifecycle ordering, and complete risk-chain evidence are reported separately; candidates still need follow-up validation".to_owned(),
        ],
    }
}

fn build_v3_2_6_object_chains(
    edges: &[V326LifecycleGraphV3Edge],
    facts: &[V326LifecycleFactRecord],
) -> Vec<V326ObjectChain> {
    let mut chains = Vec::new();
    append_callback_release_object_chains(&mut chains, edges, facts);
    append_returned_borrow_object_chains(&mut chains, edges, facts);
    append_external_buffer_object_chains(&mut chains, edges, facts);
    append_object_flow_components(&mut chains, edges, facts);
    if chains.is_empty() && !edges.is_empty() {
        chains.push(observation_only_chain(edges));
    }
    chains.sort_by(|left, right| left.chain_id.cmp(&right.chain_id));
    chains
}

fn append_callback_release_object_chains(
    chains: &mut Vec<V326ObjectChain>,
    edges: &[V326LifecycleGraphV3Edge],
    facts: &[V326LifecycleFactRecord],
) {
    for proof in facts.iter().filter(|fact| {
        fact.fact_kind == V326LifecycleFactKind::ReleasePathProof
            && is_authoritative_object_binding_fact(fact)
    }) {
        let matching_register_refs = facts
            .iter()
            .filter(|register| release_path_proof_matches_register(proof, register))
            .map(|register| register.fact_id.clone())
            .collect::<BTreeSet<_>>();
        if matching_register_refs.is_empty() {
            continue;
        }
        let proof_user_data = fact_user_data_object_ids(proof)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let supporting_refs = facts
            .iter()
            .filter(|fact| {
                is_authoritative_object_binding_fact(fact)
                    && release_path_proof_support_fact_matches(proof, fact, &proof_user_data)
            })
            .map(|fact| fact.fact_id.clone())
            .collect::<BTreeSet<_>>();
        let object_flow_support_refs =
            release_path_proof_object_flow_support_refs(proof, facts, &proof_user_data);
        let callback_use_support_refs =
            release_path_proof_callback_use_support_refs(proof, facts, &proof_user_data);
        let mut fact_refs = matching_register_refs.into_iter().collect::<Vec<_>>();
        fact_refs.extend(supporting_refs);
        fact_refs.extend(object_flow_support_refs);
        fact_refs.extend(callback_use_support_refs);
        fact_refs.push(proof.fact_id.clone());
        fact_refs.sort();
        fact_refs.dedup();
        let edge_ids = edge_ids_for_fact_refs(edges, &fact_refs);
        let evidence_refs = evidence_refs_for_fact_refs(facts, &fact_refs);
        let chain_id = format!("chain:{}:release", sanitize_id_for_path(&proof.fact_id));
        chains.push(object_chain_record(
            chain_id,
            object_ids_for_fact_refs(facts, &fact_refs),
            edge_ids,
            fact_refs,
            evidence_refs,
            V326ObjectChainStatus::VerifiedStaticChain,
            facts,
        ));
    }
}

fn append_external_buffer_object_chains(
    chains: &mut Vec<V326ObjectChain>,
    edges: &[V326LifecycleGraphV3Edge],
    facts: &[V326LifecycleFactRecord],
) {
    for binding in facts.iter().filter(|fact| {
        fact.fact_kind == V326LifecycleFactKind::ExternalBufferBinding
            && is_authoritative_object_binding_fact(fact)
    }) {
        let object_ids = lifecycle_fact_endpoint_object_ids(binding);
        if object_ids.len() < 2 {
            continue;
        }
        let fact_refs = vec![binding.fact_id.clone()];
        let chain_id = format!(
            "chain:{}:external_buffer_binding",
            sanitize_id_for_path(&binding.fact_id)
        );
        chains.push(object_chain_record(
            chain_id,
            object_ids.into_iter().collect(),
            edge_ids_for_fact_refs(edges, &fact_refs),
            fact_refs,
            binding.evidence_refs.clone(),
            V326ObjectChainStatus::PartialChain,
            facts,
        ));
    }
}

fn append_returned_borrow_object_chains(
    chains: &mut Vec<V326ObjectChain>,
    edges: &[V326LifecycleGraphV3Edge],
    facts: &[V326LifecycleFactRecord],
) {
    let relation_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ReturnedBorrowRelation
                && is_authoritative_object_binding_fact(fact)
        })
        .collect::<Vec<_>>();
    let persisted_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::PersistedReturnedBorrow
                && is_authoritative_object_binding_fact(fact)
        })
        .collect::<Vec<_>>();
    let order_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ReturnedBorrowInvalidationOrder
                && is_authoritative_object_binding_fact(fact)
        })
        .collect::<Vec<_>>();
    if relation_facts.is_empty() {
        return;
    }
    for relation in relation_facts {
        let relation_returned = first_fact_object_with_prefixes(relation, &["returned_ref:"]);
        let matching_persisted = facts
            .iter()
            .filter(|fact| {
                persisted_facts
                    .iter()
                    .any(|persisted| persisted.fact_id == fact.fact_id)
            })
            .filter(|fact| {
                relation_returned.as_ref().is_some_and(|returned_ref| {
                    fact.object_ids
                        .iter()
                        .any(|object_id| object_id == returned_ref)
                })
            })
            .collect::<Vec<_>>();
        if matching_persisted.is_empty() {
            append_partial_returned_borrow_object_chain(chains, edges, facts, relation, Vec::new());
            continue;
        }
        let mut completed_chain = false;
        for persisted in &matching_persisted {
            let matching_order_refs =
                returned_borrow_order_refs_for_persisted(persisted, &order_facts);
            if matching_order_refs.is_empty() {
                continue;
            }
            let mut fact_refs = vec![relation.fact_id.clone(), persisted.fact_id.clone()];
            fact_refs.extend(matching_order_refs);
            fact_refs.sort();
            fact_refs.dedup();
            let chain_id = format!(
                "chain:{}:{}:returned_view",
                sanitize_id_for_path(&relation.fact_id),
                sanitize_id_for_path(&persisted.fact_id)
            );
            chains.push(object_chain_record(
                chain_id,
                object_ids_for_fact_refs(facts, &fact_refs),
                edge_ids_for_fact_refs(edges, &fact_refs),
                fact_refs.clone(),
                evidence_refs_for_fact_refs(facts, &fact_refs),
                V326ObjectChainStatus::VerifiedStaticChain,
                facts,
            ));
            completed_chain = true;
        }
        if !completed_chain {
            append_partial_returned_borrow_object_chain(
                chains,
                edges,
                facts,
                relation,
                matching_persisted
                    .into_iter()
                    .map(|persisted| persisted.fact_id.clone())
                    .collect(),
            );
        }
    }
}

fn append_partial_returned_borrow_object_chain(
    chains: &mut Vec<V326ObjectChain>,
    edges: &[V326LifecycleGraphV3Edge],
    facts: &[V326LifecycleFactRecord],
    relation: &V326LifecycleFactRecord,
    persisted_refs: Vec<String>,
) {
    let mut fact_refs = vec![relation.fact_id.clone()];
    fact_refs.extend(persisted_refs);
    fact_refs.sort();
    fact_refs.dedup();
    let object_ids = object_ids_for_fact_refs(facts, &fact_refs);
    if object_ids.len() < 2 {
        return;
    }
    let chain_id = format!(
        "chain:{}:returned_view_partial",
        sanitize_id_for_path(&relation.fact_id)
    );
    chains.push(object_chain_record(
        chain_id,
        object_ids,
        edge_ids_for_fact_refs(edges, &fact_refs),
        fact_refs.clone(),
        evidence_refs_for_fact_refs(facts, &fact_refs),
        V326ObjectChainStatus::PartialChain,
        facts,
    ));
}

fn candidate_scoped_static_chain_attempt(chain: &V326ObjectChain) -> bool {
    chain.chain_status != V326ObjectChainStatus::ObservationOnly && !chain.fact_refs.is_empty()
}

fn returned_borrow_order_refs_for_persisted(
    persisted: &V326LifecycleFactRecord,
    order_facts: &[&V326LifecycleFactRecord],
) -> Vec<String> {
    let Some(persisted_static_site) = first_fact_object_with_prefixes(persisted, &["static_site:"])
    else {
        return Vec::new();
    };
    order_facts
        .iter()
        .filter(|order| {
            returned_borrow_order_persisted_static_site(order)
                == Some(persisted_static_site.as_str())
        })
        .map(|order| order.fact_id.clone())
        .collect()
}

fn returned_borrow_order_persisted_static_site(fact: &V326LifecycleFactRecord) -> Option<&str> {
    if fact.fact_kind != V326LifecycleFactKind::ReturnedBorrowInvalidationOrder {
        return None;
    }
    fact.object_ids
        .iter()
        .find(|object_id| object_id.starts_with("static_site:"))
        .map(String::as_str)
}

fn append_object_flow_components(
    chains: &mut Vec<V326ObjectChain>,
    edges: &[V326LifecycleGraphV3Edge],
    facts: &[V326LifecycleFactRecord],
) {
    let object_flow_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ObjectFlow
                && is_authoritative_object_binding_fact(fact)
        })
        .collect::<Vec<_>>();
    let mut component_edges = BTreeMap::<String, BTreeSet<String>>::new();
    let mut flow_refs_by_object = BTreeMap::<String, BTreeSet<String>>::new();
    let mut ambiguous_flow_refs = BTreeSet::<String>::new();

    for fact in &object_flow_facts {
        let endpoint_ids = lifecycle_fact_endpoint_object_ids(fact);
        if endpoint_ids.is_empty() {
            let fact_refs = vec![fact.fact_id.clone()];
            chains.push(object_chain_record(
                format!("chain:{}:object_flow", sanitize_id_for_path(&fact.fact_id)),
                endpoint_ids.into_iter().collect(),
                edge_ids_for_fact_refs(edges, &fact_refs),
                fact_refs,
                fact.evidence_refs.clone(),
                V326ObjectChainStatus::PartialChain,
                facts,
            ));
            continue;
        }
        if object_flow_endpoint_is_ambiguous(fact, facts) {
            ambiguous_flow_refs.insert(fact.fact_id.clone());
        }
        let endpoints = endpoint_ids.into_iter().collect::<Vec<_>>();
        for endpoint in &endpoints {
            flow_refs_by_object
                .entry(endpoint.clone())
                .or_default()
                .insert(fact.fact_id.clone());
            component_edges.entry(endpoint.clone()).or_default();
        }
        if endpoints.len() < 2 {
            continue;
        }
        if let Some(first) = endpoints.first() {
            for endpoint in endpoints.iter().skip(1) {
                component_edges
                    .entry(first.clone())
                    .or_default()
                    .insert(endpoint.clone());
                component_edges
                    .entry(endpoint.clone())
                    .or_default()
                    .insert(first.clone());
            }
        }
    }
    let barrier_binding_keys = object_binding_barrier_binding_keys(facts);
    connect_compatible_object_flow_sequence_components(
        &object_flow_facts,
        &mut component_edges,
        &barrier_binding_keys,
    );

    let mut visited = BTreeSet::<String>::new();
    for start in component_edges.keys().cloned().collect::<Vec<_>>() {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![start.clone()];
        let mut component_objects = BTreeSet::<String>::new();
        while let Some(object_id) = stack.pop() {
            if !visited.insert(object_id.clone()) {
                continue;
            }
            component_objects.insert(object_id.clone());
            if let Some(neighbors) = component_edges.get(&object_id) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        let mut fact_refs = component_objects
            .iter()
            .filter_map(|object_id| flow_refs_by_object.get(object_id))
            .flat_map(|refs| refs.iter().cloned())
            .collect::<BTreeSet<_>>();
        let support_refs = facts
            .iter()
            .filter(|fact| {
                fact.fact_kind != V326LifecycleFactKind::ObjectFlow
                    && is_authoritative_object_binding_fact(fact)
                    && lifecycle_fact_endpoint_object_ids(fact)
                        .iter()
                        .any(|object_id| component_objects.contains(object_id))
            })
            .map(|fact| fact.fact_id.clone())
            .collect::<BTreeSet<_>>();
        fact_refs.extend(support_refs);
        if fact_refs.is_empty() {
            continue;
        }
        let fact_refs = fact_refs.into_iter().collect::<Vec<_>>();
        let has_complete_flow_chain = object_flow_fact_refs_have_complete_chain(facts, &fact_refs);
        let chain_status = if component_objects.len() < 2 {
            V326ObjectChainStatus::PartialChain
        } else if fact_refs
            .iter()
            .any(|fact_ref| ambiguous_flow_refs.contains(fact_ref))
        {
            V326ObjectChainStatus::AmbiguousChain
        } else if has_complete_flow_chain {
            V326ObjectChainStatus::VerifiedStaticChain
        } else {
            V326ObjectChainStatus::PartialChain
        };
        let chain_anchor = fact_refs
            .iter()
            .find(|fact_ref| {
                fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::ObjectFlow)
            })
            .or_else(|| fact_refs.first())
            .expect("non-empty fact refs");
        let chain_id = format!(
            "chain:{}:object_flow_component",
            sanitize_id_for_path(chain_anchor)
        );
        let evidence_refs = evidence_refs_for_fact_refs(facts, &fact_refs);
        chains.push(object_chain_record(
            chain_id,
            component_objects.into_iter().collect(),
            edge_ids_for_fact_refs(edges, &fact_refs),
            fact_refs,
            evidence_refs,
            chain_status,
            facts,
        ));
    }
}

fn object_chain_record(
    chain_id: String,
    object_ids: Vec<String>,
    edge_ids: Vec<String>,
    fact_refs: Vec<String>,
    evidence_refs: Vec<String>,
    chain_status: V326ObjectChainStatus,
    facts: &[V326LifecycleFactRecord],
) -> V326ObjectChain {
    let verified_layers =
        object_chain_verified_layers(chain_status, &object_ids, &fact_refs, facts);
    let missing_layers =
        object_chain_missing_layers(chain_status, &verified_layers, &fact_refs, facts);
    V326ObjectChain {
        chain_id,
        object_ids,
        edge_ids,
        fact_refs,
        evidence_refs,
        verified_layers,
        missing_layers,
        chain_status,
    }
}

fn object_chain_verified_layers(
    chain_status: V326ObjectChainStatus,
    object_ids: &[String],
    fact_refs: &[String],
    facts: &[V326LifecycleFactRecord],
) -> Vec<V326ObjectChainLayer> {
    if matches!(
        chain_status,
        V326ObjectChainStatus::ObservationOnly | V326ObjectChainStatus::AmbiguousChain
    ) {
        return Vec::new();
    }
    let mut layers = BTreeSet::<V326ObjectChainLayer>::new();
    if object_ids.len() >= 2 && !fact_refs.is_empty() {
        layers.insert(V326ObjectChainLayer::IdentityTransport);
    }
    let has_release_ordering = object_chain_has_release_ordering_fact(fact_refs, facts);
    let has_use_ordering = object_chain_has_use_ordering_fact(fact_refs, facts);
    if has_release_ordering {
        layers.insert(V326ObjectChainLayer::ReleaseOrdering);
    }
    if has_use_ordering {
        layers.insert(V326ObjectChainLayer::UseOrdering);
    }
    if has_release_ordering || has_use_ordering {
        layers.insert(V326ObjectChainLayer::LifecycleOrdering);
    }
    if object_chain_has_complete_risk_fact(fact_refs, facts) {
        layers.insert(V326ObjectChainLayer::CompleteRiskChain);
    }
    layers.into_iter().collect()
}

fn object_chain_missing_layers(
    chain_status: V326ObjectChainStatus,
    verified_layers: &[V326ObjectChainLayer],
    fact_refs: &[String],
    facts: &[V326LifecycleFactRecord],
) -> Vec<V326ObjectChainLayer> {
    if matches!(chain_status, V326ObjectChainStatus::ObservationOnly) {
        return vec![V326ObjectChainLayer::IdentityTransport];
    }
    if matches!(chain_status, V326ObjectChainStatus::AmbiguousChain) {
        return vec![V326ObjectChainLayer::IdentityTransport];
    }
    let verified = verified_layers.iter().copied().collect::<BTreeSet<_>>();
    let mut missing = BTreeSet::<V326ObjectChainLayer>::new();
    if !verified.contains(&V326ObjectChainLayer::IdentityTransport) {
        missing.insert(V326ObjectChainLayer::IdentityTransport);
    }
    let needs_release_ordering = object_chain_needs_release_ordering(fact_refs, facts);
    let needs_use_ordering = object_chain_needs_use_ordering(fact_refs, facts);
    if needs_release_ordering && !verified.contains(&V326ObjectChainLayer::ReleaseOrdering) {
        missing.insert(V326ObjectChainLayer::ReleaseOrdering);
    }
    if needs_use_ordering && !verified.contains(&V326ObjectChainLayer::UseOrdering) {
        missing.insert(V326ObjectChainLayer::UseOrdering);
    }
    if object_chain_needs_lifecycle_ordering(fact_refs, facts)
        && !verified.contains(&V326ObjectChainLayer::LifecycleOrdering)
    {
        missing.insert(V326ObjectChainLayer::LifecycleOrdering);
    }
    if object_chain_needs_complete_risk_chain(fact_refs, facts)
        && !verified.contains(&V326ObjectChainLayer::CompleteRiskChain)
    {
        missing.insert(V326ObjectChainLayer::CompleteRiskChain);
    }
    missing.into_iter().collect()
}

/// 顺序已被证明的 callback release/use 事实 object id。
///
/// `CallbackReleaseUseOrdering` 还包含 `unknown_ordering`，它记录的是"CFG 无法为
/// release 与 callback use 定序"，属于缺证记录而不是顺序证明。缺证记录不得点亮
/// `lifecycle_ordering` 或 `complete_risk_chain`，否则未定序的链会被计入 ranking
/// summary 并因 `chain_layer_priority` 最高权重成为 top-ranked chain。
const PROVEN_CALLBACK_RELEASE_USE_ORDER_OBJECT_IDS: [&str; 2] = [
    "callback_release_use_order:release_before_callback_use",
    "callback_release_use_order:callback_use_before_release",
];

/// 仅当 `fact_ref` 指向顺序已证明的 callback release/use 事实时为真。
fn fact_ref_contains_proven_callback_release_use_order(
    facts: &[V326LifecycleFactRecord],
    fact_ref: &str,
) -> bool {
    facts.iter().any(|fact| {
        fact.fact_id == fact_ref
            && fact.fact_kind == V326LifecycleFactKind::CallbackReleaseUseOrder
            && fact.object_ids.iter().any(|object_id| {
                PROVEN_CALLBACK_RELEASE_USE_ORDER_OBJECT_IDS.contains(&object_id.as_str())
            })
    })
}

/// release 相对 register 的顺序证明：release path proof 证明每条到出口的路径都经过 release。
fn object_chain_has_release_ordering_fact(
    fact_refs: &[String],
    facts: &[V326LifecycleFactRecord],
) -> bool {
    fact_refs.iter().any(|fact_ref| {
        fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::ReleasePathProof)
    })
}

/// release 之后 use 的顺序证明。`unknown_ordering` 记录不计入，见
/// [`PROVEN_CALLBACK_RELEASE_USE_ORDER_OBJECT_IDS`]。
fn object_chain_has_use_ordering_fact(
    fact_refs: &[String],
    facts: &[V326LifecycleFactRecord],
) -> bool {
    fact_refs.iter().any(|fact_ref| {
        fact_ref_contains_proven_callback_release_use_order(facts, fact_ref)
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::ReturnedBorrowInvalidationOrder,
            )
    })
}

fn object_chain_has_complete_risk_fact(
    fact_refs: &[String],
    facts: &[V326LifecycleFactRecord],
) -> bool {
    fact_refs.iter().any(|fact_ref| {
        fact_ref_contains_proven_callback_release_use_order(facts, fact_ref)
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::ReturnedBorrowInvalidationOrder,
            )
    })
}

/// 出现 register/release 事实即意味着这条链应当给出 release 顺序结论。
fn object_chain_needs_release_ordering(
    fact_refs: &[String],
    facts: &[V326LifecycleFactRecord],
) -> bool {
    fact_refs.iter().any(|fact_ref| {
        fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::RegisterCall)
            || fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::ReleaseCall)
            || fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::ReleasePathProof)
    })
}

/// 出现 use 侧事实（callback 重建、returned borrow、external buffer）即意味着这条链
/// 应当给出 use 顺序结论。
fn object_chain_needs_use_ordering(
    fact_refs: &[String],
    facts: &[V326LifecycleFactRecord],
) -> bool {
    fact_refs.iter().any(|fact_ref| {
        fact_ref_contains_kind(
            facts,
            fact_ref,
            V326LifecycleFactKind::CallbackUserDataReconstruction,
        ) || fact_ref_contains_kind(
            facts,
            fact_ref,
            V326LifecycleFactKind::ReturnedBorrowRelation,
        ) || fact_ref_contains_kind(
            facts,
            fact_ref,
            V326LifecycleFactKind::PersistedReturnedBorrow,
        ) || fact_ref_contains_kind(
            facts,
            fact_ref,
            V326LifecycleFactKind::ExternalBufferBinding,
        )
    })
}

fn object_chain_needs_lifecycle_ordering(
    fact_refs: &[String],
    facts: &[V326LifecycleFactRecord],
) -> bool {
    fact_refs.iter().any(|fact_ref| {
        fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::RegisterCall)
            || fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::ReleaseCall)
            || fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::ReleasePathProof)
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::ReturnedBorrowRelation,
            )
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::PersistedReturnedBorrow,
            )
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::ExternalBufferBinding,
            )
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::CallbackUserDataReconstruction,
            )
    })
}

fn object_chain_needs_complete_risk_chain(
    fact_refs: &[String],
    facts: &[V326LifecycleFactRecord],
) -> bool {
    fact_refs.iter().any(|fact_ref| {
        fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::ReleasePathProof)
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::ReturnedBorrowRelation,
            )
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::PersistedReturnedBorrow,
            )
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::ExternalBufferBinding,
            )
            || fact_ref_contains_kind(
                facts,
                fact_ref,
                V326LifecycleFactKind::CallbackUserDataReconstruction,
            )
    })
}

fn observation_only_chain(edges: &[V326LifecycleGraphV3Edge]) -> V326ObjectChain {
    let object_ids = edges
        .iter()
        .flat_map(|edge| [edge.from_object_id.clone(), edge.to_object_id.clone()])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let edge_ids = edges
        .iter()
        .map(|edge| edge.edge_id.clone())
        .collect::<Vec<_>>();
    let evidence_refs = edges
        .iter()
        .flat_map(|edge| edge.evidence_refs.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    V326ObjectChain {
        chain_id: "chain:observation_only".to_owned(),
        object_ids,
        edge_ids,
        fact_refs: Vec::new(),
        evidence_refs,
        verified_layers: Vec::new(),
        missing_layers: vec![V326ObjectChainLayer::IdentityTransport],
        chain_status: V326ObjectChainStatus::ObservationOnly,
    }
}

fn object_flow_fact_refs_have_complete_chain(
    facts: &[V326LifecycleFactRecord],
    fact_refs: &[String],
) -> bool {
    object_flow_fact_refs_have_compatible_pair(facts, fact_refs, "closure_capture", "field_load")
        || object_flow_fact_refs_have_compatible_pair(facts, fact_refs, "return_value", "argument")
        || object_flow_fact_refs_have_compatible_pair(facts, fact_refs, "field_store", "field_load")
        || object_flow_fact_refs_have_compatible_pair(
            facts,
            fact_refs,
            "wrapper_move",
            "wrapper_destructure",
        )
        || object_flow_fact_refs_have_compatible_pair(
            facts,
            fact_refs,
            "collection_store",
            "collection_load",
        )
}

fn object_flow_fact_refs_have_compatible_pair(
    facts: &[V326LifecycleFactRecord],
    fact_refs: &[String],
    first_flow_kind: &str,
    second_flow_kind: &str,
) -> bool {
    let flow_facts = object_flow_facts_for_refs(facts, fact_refs);
    let barrier_binding_keys = object_binding_barrier_binding_keys(facts);
    flow_facts
        .iter()
        .filter(|fact| object_flow_kind_from_fact(fact) == Some(first_flow_kind))
        .any(|first| {
            flow_facts
                .iter()
                .filter(|fact| object_flow_kind_from_fact(fact) == Some(second_flow_kind))
                .any(|second| {
                    !object_flow_pair_blocked_by_barrier(first, second, &barrier_binding_keys)
                        && object_flow_facts_are_compatible_sequence(
                            first,
                            second,
                            first_flow_kind,
                            second_flow_kind,
                        )
                })
        })
}

fn connect_compatible_object_flow_sequence_components(
    object_flow_facts: &[&V326LifecycleFactRecord],
    component_edges: &mut BTreeMap<String, BTreeSet<String>>,
    barrier_binding_keys: &ObjectBindingBarrierKeys,
) {
    for first in object_flow_facts {
        let Some(first_flow_kind) = object_flow_kind_from_fact(first) else {
            continue;
        };
        let first_endpoints = object_flow_endpoint_object_ids_in_order(first);
        if first_endpoints.is_empty() {
            continue;
        }
        for second in object_flow_facts {
            if first.fact_id == second.fact_id {
                continue;
            }
            let Some(second_flow_kind) = object_flow_kind_from_fact(second) else {
                continue;
            };
            if !object_flow_facts_are_compatible_sequence(
                first,
                second,
                first_flow_kind,
                second_flow_kind,
            ) || object_flow_pair_blocked_by_barrier(first, second, barrier_binding_keys)
            {
                continue;
            }
            let second_endpoints = object_flow_endpoint_object_ids_in_order(second);
            if second_endpoints.is_empty() {
                continue;
            }
            connect_component_objects(component_edges, &first_endpoints[0], &second_endpoints[0]);
        }
    }
}

fn connect_component_objects(
    component_edges: &mut BTreeMap<String, BTreeSet<String>>,
    left: &str,
    right: &str,
) {
    component_edges
        .entry(left.to_owned())
        .or_default()
        .insert(right.to_owned());
    component_edges
        .entry(right.to_owned())
        .or_default()
        .insert(left.to_owned());
}

fn object_flow_facts_for_refs<'a>(
    facts: &'a [V326LifecycleFactRecord],
    fact_refs: &[String],
) -> Vec<&'a V326LifecycleFactRecord> {
    facts
        .iter()
        .filter(|fact| fact_refs.iter().any(|fact_ref| fact_ref == &fact.fact_id))
        .filter(|fact| fact.fact_kind == V326LifecycleFactKind::ObjectFlow)
        .collect()
}

fn object_flow_facts_are_compatible_sequence(
    first: &V326LifecycleFactRecord,
    second: &V326LifecycleFactRecord,
    first_flow_kind: &str,
    second_flow_kind: &str,
) -> bool {
    let first_endpoints = object_flow_endpoint_object_ids_in_order(first);
    let second_endpoints = object_flow_endpoint_object_ids_in_order(second);
    if first_endpoints.len() < 2 || second_endpoints.len() < 2 {
        return false;
    }
    if !object_flow_binding_keys_compatible(first, second, "field")
        || !object_flow_binding_keys_compatible(first, second, "container")
    {
        return false;
    }
    if object_flow_endpoints_are_compatible_sequence(
        &first_endpoints,
        &second_endpoints,
        first_flow_kind,
        second_flow_kind,
    ) {
        return true;
    }
    object_flow_facts_have_exact_contract_binding_sequence(
        first,
        second,
        &first_endpoints,
        &second_endpoints,
        first_flow_kind,
        second_flow_kind,
    )
}

fn object_flow_endpoints_are_compatible_sequence(
    first_endpoints: &[String],
    second_endpoints: &[String],
    first_flow_kind: &str,
    second_flow_kind: &str,
) -> bool {
    if first_endpoints[1] == second_endpoints[0] {
        return true;
    }
    matches!(
        (first_flow_kind, second_flow_kind),
        ("field_store", "field_load") | ("wrapper_move", "wrapper_destructure")
    ) && first_endpoints[0] == second_endpoints[1]
}

fn object_flow_binding_keys_compatible(
    first: &V326LifecycleFactRecord,
    second: &V326LifecycleFactRecord,
    scope: &str,
) -> bool {
    let first_keys = object_flow_binding_keys(first, scope);
    let second_keys = object_flow_binding_keys(second, scope);
    if first_keys.is_empty() && second_keys.is_empty() {
        return true;
    }
    !first_keys.is_disjoint(&second_keys)
}

fn object_flow_facts_have_exact_contract_binding_sequence(
    first: &V326LifecycleFactRecord,
    second: &V326LifecycleFactRecord,
    first_endpoints: &[String],
    second_endpoints: &[String],
    first_flow_kind: &str,
    second_flow_kind: &str,
) -> bool {
    if (first_flow_kind, second_flow_kind) != ("field_store", "field_load")
        || first_endpoints.len() < 2
        || second_endpoints.len() < 2
    {
        return false;
    }
    let first_field_keys = object_flow_binding_keys(first, "field");
    let second_field_keys = object_flow_binding_keys(second, "field");
    if first_field_keys.is_empty() || first_field_keys.is_disjoint(&second_field_keys) {
        return false;
    }
    let Some(first_api) = exact_contract_api_map_id_for_fact(first) else {
        return false;
    };
    if exact_contract_api_map_id_for_fact(second) != Some(first_api) {
        return false;
    }
    first_endpoints[0].starts_with("user_data:")
        && first_endpoints[1].starts_with("opaque_handle:")
        && second_endpoints[0].starts_with("opaque_handle:")
        && (second_endpoints[1].starts_with("user_data:")
            || second_endpoints[1].starts_with("static_site:")
            || second_endpoints[1].starts_with("release_endpoint:"))
}

fn exact_contract_api_map_id_for_fact(fact: &V326LifecycleFactRecord) -> Option<&str> {
    let api_id = fact
        .symbol_path
        .as_deref()
        .or(fact.source_ref.symbol_path.as_deref())?
        .trim();
    let suffix = api_id.strip_prefix("api:")?;
    (suffix.split(':').count() >= 2 && !suffix.split(':').any(str::is_empty)).then_some(api_id)
}

fn object_flow_binding_keys(fact: &V326LifecycleFactRecord, scope: &str) -> BTreeSet<String> {
    let prefix = format!("object_flow_binding:{scope}:");
    fact.object_ids
        .iter()
        .filter(|object_id| object_id.starts_with(&prefix))
        .cloned()
        .collect()
}

fn object_flow_has_binding_kind(fact: &V326LifecycleFactRecord, binding_kind: &str) -> bool {
    let expected = object_flow_binding_kind_object_id(binding_kind);
    fact.object_ids
        .iter()
        .any(|object_id| object_id == &expected)
}

fn object_flow_all_binding_keys(fact: &V326LifecycleFactRecord) -> BTreeSet<String> {
    fact.object_ids
        .iter()
        .filter(|object_id| object_id.starts_with("object_flow_binding:"))
        .cloned()
        .collect()
}

#[derive(Default)]
struct ObjectBindingBarrierKeys {
    exact: BTreeSet<String>,
    prefixes: BTreeSet<String>,
}

fn object_binding_barrier_binding_keys(
    facts: &[V326LifecycleFactRecord],
) -> ObjectBindingBarrierKeys {
    let mut keys = ObjectBindingBarrierKeys::default();
    for fact in facts.iter().filter(|fact| {
        fact.fact_kind == V326LifecycleFactKind::ObjectBindingGap
            && is_authoritative_object_binding_gap_fact(fact)
            && object_binding_gap_is_barrier(fact)
    }) {
        keys.exact.extend(object_flow_all_binding_keys(fact));
        keys.prefixes.extend(object_flow_binding_prefix_keys(fact));
    }
    keys
}

fn object_binding_gap_is_barrier(fact: &V326LifecycleFactRecord) -> bool {
    fact.object_ids.iter().any(|object_id| {
        matches!(
            object_id.as_str(),
            "object_binding_gap:reassignment_barrier" | "object_binding_gap:mutation_barrier"
        )
    })
}

fn is_authoritative_object_binding_gap_fact(item: &V326LifecycleFactRecord) -> bool {
    item.fact_kind == V326LifecycleFactKind::ObjectBindingGap
        && item.confidence == V326EvidenceConfidence::High
        && item.provenance.is_verified_static_artifact()
}

fn object_flow_pair_blocked_by_barrier(
    first: &V326LifecycleFactRecord,
    second: &V326LifecycleFactRecord,
    barrier_binding_keys: &ObjectBindingBarrierKeys,
) -> bool {
    let first_keys = object_flow_all_binding_keys(first);
    let second_keys = object_flow_all_binding_keys(second);
    let exact_blocked = !first_keys.is_empty()
        && !second_keys.is_empty()
        && first_keys
            .intersection(&second_keys)
            .any(|key| barrier_binding_keys.exact.contains(key));
    if exact_blocked {
        return true;
    }
    let first_prefixes = object_flow_binding_prefix_member_keys(first);
    let second_prefixes = object_flow_binding_prefix_member_keys(second);
    !first_prefixes.is_empty()
        && !second_prefixes.is_empty()
        && first_prefixes
            .intersection(&second_prefixes)
            .any(|key| barrier_binding_keys.prefixes.contains(key))
}

fn object_flow_binding_prefix_keys(fact: &V326LifecycleFactRecord) -> BTreeSet<String> {
    fact.object_ids
        .iter()
        .filter(|object_id| object_id.starts_with("object_flow_binding_prefix:"))
        .cloned()
        .collect()
}

fn object_flow_binding_prefix_member_keys(fact: &V326LifecycleFactRecord) -> BTreeSet<String> {
    fact.object_ids
        .iter()
        .filter(|object_id| object_id.starts_with("object_flow_binding_member:"))
        .cloned()
        .map(|object_id| {
            object_id.replacen(
                "object_flow_binding_member:",
                "object_flow_binding_prefix:",
                1,
            )
        })
        .collect()
}

fn object_flow_fact_refs_are_only_neutral_aliases(
    facts: &[V326LifecycleFactRecord],
    fact_refs: &[String],
) -> bool {
    let mut seen_object_flow = false;
    for fact in facts
        .iter()
        .filter(|fact| fact_refs.iter().any(|fact_ref| fact_ref == &fact.fact_id))
        .filter(|fact| fact.fact_kind == V326LifecycleFactKind::ObjectFlow)
    {
        seen_object_flow = true;
        if !object_flow_fact_is_neutral_alias(fact) {
            return false;
        }
    }
    seen_object_flow
}

fn object_flow_fact_is_neutral_alias(fact: &V326LifecycleFactRecord) -> bool {
    if fact.fact_kind != V326LifecycleFactKind::ObjectFlow
        || object_flow_kind_from_fact(fact) != Some("wrapper_move")
    {
        return false;
    }
    let endpoints = object_flow_endpoint_object_ids_in_order(fact);
    endpoints.len() == 2
        && endpoints
            .iter()
            .all(|endpoint| endpoint.starts_with("rust_owner:"))
}

fn append_object_chain_incomplete_reasons(
    chains: &[V326ObjectChain],
    facts: &[V326LifecycleFactRecord],
    incomplete_reasons: &mut Vec<String>,
) {
    if chains
        .iter()
        .any(|chain| chain.chain_status == V326ObjectChainStatus::ObservationOnly)
    {
        incomplete_reasons.push("object_flow_missing".to_owned());
    }
    if chains.iter().any(|chain| {
        chain.chain_status == V326ObjectChainStatus::PartialChain
            && chain.fact_refs.iter().any(|fact_ref| {
                fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::ObjectFlow)
            })
            && !object_flow_fact_refs_are_only_neutral_aliases(facts, &chain.fact_refs)
    }) {
        incomplete_reasons.push("object_flow_counterpart_missing".to_owned());
    }
    if chains
        .iter()
        .any(|chain| chain.chain_status == V326ObjectChainStatus::AmbiguousChain)
    {
        incomplete_reasons.push("object_binding_unproven".to_owned());
        incomplete_reasons.push("object_binding_ambiguous".to_owned());
    }
    let has_release_order_chain = chains.iter().any(|chain| {
        chain.chain_status == V326ObjectChainStatus::VerifiedStaticChain
            && chain.fact_refs.iter().any(|fact_ref| {
                fact_ref_contains_kind(facts, fact_ref, V326LifecycleFactKind::ReleasePathProof)
            })
    });
    if has_incomplete_authoritative_object_flow_pair(facts, "argument", "return_value") {
        incomplete_reasons.push("call_boundary_binding_missing".to_owned());
    }
    if has_incomplete_authoritative_object_flow_pair(facts, "field_store", "field_load")
        || has_unverified_authoritative_object_flow_pair(facts, "field_store", "field_load")
    {
        incomplete_reasons.push("field_binding_missing".to_owned());
    }
    if (has_incomplete_authoritative_object_flow_pair(facts, "wrapper_move", "wrapper_destructure")
        || has_unverified_authoritative_object_flow_pair(
            facts,
            "wrapper_move",
            "wrapper_destructure",
        ))
        && !has_release_order_chain
    {
        incomplete_reasons.push("wrapper_binding_missing".to_owned());
    }
    if has_incomplete_authoritative_object_flow_pair(facts, "collection_store", "collection_load")
        || has_unverified_authoritative_object_flow_pair(
            facts,
            "collection_store",
            "collection_load",
        )
    {
        incomplete_reasons.push("collection_binding_missing".to_owned());
    }
    if has_incomplete_closure_capture_component(facts) {
        incomplete_reasons.push("closure_binding_missing".to_owned());
    }
    let has_release_fact = facts.iter().any(|fact| {
        matches!(
            fact.fact_kind,
            V326LifecycleFactKind::RegisterCall
                | V326LifecycleFactKind::UnregisterCall
                | V326LifecycleFactKind::ReleaseCall
        )
    });
    if has_release_fact && !has_release_order_chain {
        incomplete_reasons.push("release_order_proof_missing".to_owned());
    }
    let has_returned_borrow = facts.iter().any(|fact| {
        matches!(
            fact.fact_kind,
            V326LifecycleFactKind::ReturnedBorrowRelation
                | V326LifecycleFactKind::PersistedReturnedBorrow
        )
    });
    if has_returned_borrow && persisted_invalidation_use_chain_refs(facts).is_empty() {
        incomplete_reasons.push("use_ordering_proof_missing".to_owned());
    }
    let has_callback_user_data_use = facts.iter().any(|fact| {
        fact.fact_kind == V326LifecycleFactKind::CallbackUserDataReconstruction
            && is_authoritative_object_binding_fact(fact)
    });
    if has_callback_user_data_use
        && release_path_proof_register_pairs(facts).next().is_some()
        && callback_release_use_chain_refs(facts).is_empty()
    {
        incomplete_reasons.push("callback_release_use_object_flow_missing".to_owned());
    }
}

fn append_object_binding_gap_reasons(
    facts: &[V326LifecycleFactRecord],
    incomplete_reasons: &mut Vec<String>,
) {
    for fact in facts
        .iter()
        .filter(|fact| fact.fact_kind == V326LifecycleFactKind::ObjectBindingGap)
    {
        for object_id in &fact.object_ids {
            let Some(token) = object_id.strip_prefix("object_binding_gap:") else {
                continue;
            };
            if let Some(reason) = object_binding_gap_reason(token)
                && !incomplete_reasons.iter().any(|item| item == reason)
            {
                incomplete_reasons.push(reason.to_owned());
            }
        }
    }
}

fn object_binding_gap_reason(token: &str) -> Option<&'static str> {
    match token {
        "selection_predicate" => Some("selection_predicate_binding_missing"),
        "mapped_value" => Some("mapped_value_binding_missing"),
        "merged_sources" => Some("merged_source_binding_missing"),
        "tuple_projection" => Some("tuple_projection_binding_missing"),
        "cardinality_transform" => Some("cardinality_transform_binding_missing"),
        "dynamic_index" => Some("dynamic_index_binding_missing"),
        "range_or_slice" => Some("range_or_slice_binding_missing"),
        "sequence_length_unknown" => Some("sequence_length_binding_missing"),
        "key_contract" => Some("key_contract_binding_missing"),
        "reassignment_barrier" => Some("object_reassignment_barrier"),
        "mutation_barrier" => Some("storage_mutation_barrier"),
        "call_boundary" => Some("call_boundary_binding_missing"),
        _ => None,
    }
}

fn lifecycle_fact_endpoint_object_ids(fact: &V326LifecycleFactRecord) -> BTreeSet<String> {
    if fact.fact_kind == V326LifecycleFactKind::ObjectFlow {
        return object_flow_endpoint_object_ids_in_order(fact)
            .into_iter()
            .collect();
    }
    fact.object_ids
        .iter()
        .filter(|object_id| !object_flow_auxiliary_object_id(object_id))
        .filter(|object_id| !object_id.starts_with("object_binding_gap:"))
        .filter(|object_id| !object_id.starts_with("adapter:"))
        .filter(|object_id| !object_id.starts_with("returned_borrow_order:"))
        .filter(|object_id| !object_id.starts_with("callback_release_use_order:"))
        .filter(|object_id| !object_id.starts_with("atomic_operation:"))
        .filter(|object_id| !object_id.starts_with("atomic_ordering:"))
        .cloned()
        .collect()
}

fn object_flow_endpoint_object_ids_in_order(fact: &V326LifecycleFactRecord) -> Vec<String> {
    fact.object_ids
        .iter()
        .filter(|object_id| !object_id.starts_with("object_flow:"))
        .filter(|object_id| !object_id.starts_with("object_flow_binding:"))
        .filter(|object_id| !object_id.starts_with("object_flow_binding_member:"))
        .filter(|object_id| !object_id.starts_with("object_flow_binding_prefix:"))
        .filter(|object_id| !object_id.starts_with("object_flow_binding_kind:"))
        .filter(|object_id| !object_id.starts_with("object_binding_gap:"))
        .filter(|object_id| !object_id.starts_with("adapter:"))
        .filter(|object_id| !object_id.starts_with("returned_borrow_order:"))
        .filter(|object_id| !object_id.starts_with("callback_release_use_order:"))
        .filter(|object_id| !object_id.starts_with("atomic_operation:"))
        .filter(|object_id| !object_id.starts_with("atomic_ordering:"))
        .take(2)
        .cloned()
        .collect()
}

fn object_flow_endpoint_is_ambiguous(
    fact: &V326LifecycleFactRecord,
    facts: &[V326LifecycleFactRecord],
) -> bool {
    let from = first_object_flow_endpoint(fact, true);
    let to = first_object_flow_endpoint(fact, false);
    let flow_kind = object_flow_kind_from_fact(fact);
    if flow_kind == Some("closure_capture")
        && to.as_ref().is_some_and(|to| {
            let sources = facts
                .iter()
                .filter(|other| {
                    other.fact_kind == V326LifecycleFactKind::ObjectFlow
                        && is_authoritative_object_binding_fact(other)
                        && object_flow_kind_from_fact(other) == flow_kind
                        && first_object_flow_endpoint(other, false).as_ref() == Some(to)
                })
                .filter_map(|other| first_object_flow_endpoint(other, true))
                .collect::<BTreeSet<_>>();
            sources.len() > 1
        })
    {
        return true;
    }
    if flow_kind == Some("field_load")
        && from
            .as_ref()
            .is_some_and(|from| closure_capture_slot_object_id_is_endpoint(from))
    {
        return false;
    }
    from.as_ref().is_some_and(|from| {
        let targets = facts
            .iter()
            .filter(|other| {
                other.fact_kind == V326LifecycleFactKind::ObjectFlow
                    && is_authoritative_object_binding_fact(other)
                    && object_flow_kind_from_fact(other) == flow_kind
                    && first_object_flow_endpoint(other, true).as_ref() == Some(from)
            })
            .filter_map(|other| first_object_flow_endpoint(other, false))
            .collect::<BTreeSet<_>>();
        targets.len() > 1
            && !object_flow_targets_are_release_path_sequence(from, flow_kind, &targets, facts)
    })
}

fn object_flow_targets_are_release_path_sequence(
    from: &str,
    flow_kind: Option<&str>,
    targets: &BTreeSet<String>,
    facts: &[V326LifecycleFactRecord],
) -> bool {
    if flow_kind != Some("argument") || !from.starts_with("user_data:") {
        return false;
    }
    facts.iter().any(|fact| {
        if fact.fact_kind != V326LifecycleFactKind::ReleasePathProof {
            return false;
        }
        if !fact.object_ids.iter().any(|object_id| object_id == from) {
            return false;
        }
        let mut allowed_targets = BTreeSet::<String>::new();
        for object_id in &fact.object_ids {
            if object_id.starts_with("static_site:") {
                allowed_targets.insert(object_id.clone());
            }
            if let Some(site_id) = object_id.strip_prefix("release_endpoint:") {
                allowed_targets.insert(format!("static_site:{site_id}"));
            }
        }
        targets
            .iter()
            .all(|target| allowed_targets.contains(target))
    })
}

fn closure_capture_slot_object_id_is_endpoint(object_id: &str) -> bool {
    object_id.starts_with("callback:") && object_id.contains(":capture_slot:")
}

fn has_ambiguous_object_flow_binding(facts: &[V326LifecycleFactRecord]) -> bool {
    facts.iter().any(|fact| {
        fact.fact_kind == V326LifecycleFactKind::ObjectFlow
            && is_authoritative_object_binding_fact(fact)
            && object_flow_endpoint_is_ambiguous(fact, facts)
    })
}

fn edge_ids_for_fact_refs(edges: &[V326LifecycleGraphV3Edge], fact_refs: &[String]) -> Vec<String> {
    edges
        .iter()
        .filter(|edge| {
            edge.fact_refs
                .iter()
                .any(|edge_ref| fact_refs.iter().any(|fact_ref| fact_ref == edge_ref))
        })
        .map(|edge| edge.edge_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn object_ids_for_fact_refs(
    facts: &[V326LifecycleFactRecord],
    fact_refs: &[String],
) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| fact_refs.iter().any(|fact_ref| fact_ref == &fact.fact_id))
        .flat_map(lifecycle_fact_endpoint_object_ids)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn evidence_refs_for_fact_refs(
    facts: &[V326LifecycleFactRecord],
    fact_refs: &[String],
) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| fact_refs.iter().any(|fact_ref| fact_ref == &fact.fact_id))
        .flat_map(|fact| fact.evidence_refs.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fact_ref_contains_kind(
    facts: &[V326LifecycleFactRecord],
    fact_ref: &str,
    kind: V326LifecycleFactKind,
) -> bool {
    facts
        .iter()
        .any(|fact| fact.fact_id == fact_ref && fact.fact_kind == kind)
}

pub fn lifecycle_fact_from_static_fact(
    run_id: &str,
    candidate: &crate::V32CandidateRecord,
    envelope: &StaticFactEnvelope,
    source_ref: V326SourceRef,
    evidence_refs: Vec<String>,
) -> Option<V326LifecycleFactRecord> {
    let (fact_kind, symbol_path, object_ids) = lifecycle_static_fact_fields(envelope)?;

    Some(V326LifecycleFactRecord {
        schema_version: V3_2_6_LIFECYCLE_FACT_SCHEMA_V1.to_owned(),
        run_id: run_id.to_owned(),
        candidate_id: candidate.candidate_id.clone(),
        crate_id: candidate.crate_id.clone(),
        fact_id: format!(
            "fact:{}:{}",
            sanitize_id_for_path(&candidate.candidate_id),
            sanitize_id_for_path(envelope.record_id.as_str())
        ),
        fact_kind,
        source_ref,
        symbol_path,
        confidence: V326EvidenceConfidence::High,
        coverage_state: V326CoverageState::Covered,
        provenance: V326LifecycleFactProvenance::static_artifact(envelope),
        object_ids,
        evidence_refs,
        notes: vec!["candidate-scoped static lifecycle fact".to_owned()],
    })
}

fn lifecycle_static_fact_fields(
    envelope: &StaticFactEnvelope,
) -> Option<(V326LifecycleFactKind, Option<String>, Vec<String>)> {
    Some(match &envelope.payload {
        StaticFact::ObjectSite(fact) => (
            V326LifecycleFactKind::OwnedMoveCapture,
            Some(fact.type_name.clone()),
            vec![static_site_object_id(
                "rust_owner",
                &fact.site_id.to_string(),
            )],
        ),
        StaticFact::CallbackSite(fact) => (
            V326LifecycleFactKind::CallbackDefinition,
            Some(fact.def_path.clone()),
            vec![static_site_object_id("callback", &fact.site_id.to_string())],
        ),
        StaticFact::CallbackCapture(fact) => {
            let kind = match fact.capture_mode {
                crate::CaptureMode::Borrowed => V326LifecycleFactKind::BorrowedCapture,
                crate::CaptureMode::Owned => V326LifecycleFactKind::OwnedMoveCapture,
            };
            (
                kind,
                None,
                vec![
                    static_site_object_id("callback", &fact.callback_site_id.to_string()),
                    static_site_object_id("rust_owner", &fact.object_site_id.to_string()),
                ],
            )
        }
        StaticFact::DropSite(fact) => (
            V326LifecycleFactKind::DropSite,
            None,
            vec![static_site_object_id(
                "rust_owner",
                &fact.object_site_id.to_string(),
            )],
        ),
        StaticFact::DropPrevention(fact) => (
            V326LifecycleFactKind::DropPrevention,
            Some(format!("drop_prevention::{:?}", fact.prevention_kind).to_ascii_lowercase()),
            vec![static_site_object_id(
                "rust_owner",
                &fact.object_site_id.to_string(),
            )],
        ),
        StaticFact::CallbackUserDataReconstruction(fact) => (
            V326LifecycleFactKind::CallbackUserDataReconstruction,
            Some(format!(
                "callback_user_data_reconstruction::{}",
                callback_user_data_reconstruction_token(fact.reconstruction_kind)
            )),
            vec![
                static_site_object_id("static_site", &fact.site_id.to_string()),
                static_site_object_id("callback", &fact.callback_site_id.to_string()),
                static_site_object_id("user_data", &fact.user_data_site_id.to_string()),
                static_site_object_id("rust_owner", &fact.object_site_id.to_string()),
            ],
        ),
        StaticFact::RegistrationSite(fact) => {
            let kind = match fact.role {
                crate::RegistrationRole::Register => V326LifecycleFactKind::RegisterCall,
                crate::RegistrationRole::Unregister => V326LifecycleFactKind::UnregisterCall,
                crate::RegistrationRole::Replace => V326LifecycleFactKind::ReplaceCall,
            };
            let mut object_ids = fact
                .callback_site_id
                .as_ref()
                .map(|site_id| vec![static_site_object_id("callback", &site_id.to_string())])
                .unwrap_or_default();
            object_ids.extend(
                fact.user_data_site_id
                    .as_ref()
                    .map(|site_id| static_site_object_id("user_data", &site_id.to_string())),
            );
            object_ids.push(static_site_object_id(
                "static_site",
                &fact.site_id.to_string(),
            ));
            (kind, Some(fact.api_id.clone()), object_ids)
        }
        StaticFact::RawPointerTransfer(fact) => {
            let kind = match fact.transfer_kind {
                crate::RawPointerTransferKind::IntoRaw
                | crate::RawPointerTransferKind::FromRawParts => {
                    V326LifecycleFactKind::RawPointerEscape
                }
                crate::RawPointerTransferKind::FromRaw => V326LifecycleFactKind::ReleaseCall,
            };
            let symbol_path = match fact.transfer_kind {
                crate::RawPointerTransferKind::FromRawParts => {
                    Some("raw_pointer_transfer::from_raw_parts".to_owned())
                }
                crate::RawPointerTransferKind::IntoRaw | crate::RawPointerTransferKind::FromRaw => {
                    None
                }
            };
            let mut object_ids = vec![static_site_object_id(
                "user_data",
                &fact.user_data_site_id.to_string(),
            )];
            if fact.transfer_kind == crate::RawPointerTransferKind::FromRaw {
                object_ids.push(static_site_object_id(
                    "release_endpoint",
                    &fact.site_id.to_string(),
                ));
            }
            (kind, symbol_path, object_ids)
        }
        StaticFact::ReleasePathProof(fact) => (
            V326LifecycleFactKind::ReleasePathProof,
            None,
            vec![
                static_site_object_id("user_data", &fact.object_site_id.to_string()),
                static_site_object_id("static_site", &fact.registration_site_id.to_string()),
                static_site_object_id("release_endpoint", &fact.release_site_id.to_string()),
            ],
        ),
        StaticFact::CallbackReleaseUseOrder(fact) => (
            V326LifecycleFactKind::CallbackReleaseUseOrder,
            Some(fact.api_id.clone()),
            vec![
                static_site_object_id("user_data", &fact.object_site_id.to_string()),
                static_site_object_id("static_site", &fact.registration_site_id.to_string()),
                static_site_object_id("release_endpoint", &fact.release_site_id.to_string()),
                static_site_object_id("static_site", &fact.use_site_id.to_string()),
                format!(
                    "callback_release_use_order:{}",
                    callback_release_use_ordering_token(fact.ordering)
                ),
            ],
        ),
        // ExternalCallSite encodes boundary invoke / generic foreign calls. Mapping every
        // external call to ReleaseCall would invent release coverage. Without an exact
        // unregister/release RegistrationRole or contract-backed release endpoint, skip.
        StaticFact::ExternalCallSite(_) => return None,
        StaticFact::ReturnedBorrowRelation(fact) => {
            let mut object_ids = vec![
                static_site_object_id("rust_owner", &fact.source_site_id.to_string()),
                static_site_object_id("returned_ref", &fact.returned_site_id.to_string()),
            ];
            if fact.relation_kind == Some(ReturnedBorrowRelationKind::UnconstrainedReturnLifetime) {
                object_ids.push(
                    "static_site:returned_borrow_relation_kind:unconstrained_return_lifetime"
                        .to_owned(),
                );
            }
            (
                V326LifecycleFactKind::ReturnedBorrowRelation,
                Some(fact.api_id.clone()),
                object_ids,
            )
        }
        StaticFact::PersistedReturnedBorrow(fact) => (
            V326LifecycleFactKind::PersistedReturnedBorrow,
            Some(fact.api_id.clone()),
            vec![
                static_site_object_id("static_site", &fact.site_id.to_string()),
                static_site_object_id("rust_owner", &fact.source_site_id.to_string()),
                static_site_object_id("returned_ref", &fact.returned_site_id.to_string()),
                static_site_object_id("storage", &fact.storage_site_id.to_string()),
            ],
        ),
        StaticFact::ReturnedBorrowInvalidationOrder(fact) => (
            V326LifecycleFactKind::ReturnedBorrowInvalidationOrder,
            Some(fact.api_id.clone()),
            vec![
                static_site_object_id("static_site", &fact.persisted_site_id.to_string()),
                static_site_object_id("static_site", &fact.invalidation_site_id.to_string()),
                static_site_object_id("static_site", &fact.use_site_id.to_string()),
                format!(
                    "returned_borrow_order:{}",
                    returned_borrow_ordering_token(fact.ordering)
                ),
            ],
        ),
        StaticFact::ExternalBufferBinding(fact) => (
            V326LifecycleFactKind::ExternalBufferBinding,
            Some(fact.api_id.clone()),
            vec![
                static_site_object_id("rust_owner", &fact.source_site_id.to_string()),
                static_site_object_id("user_data", &fact.buffer_site_id.to_string()),
            ],
        ),
        StaticFact::AtomicOrdering(fact) => (
            V326LifecycleFactKind::AtomicOrdering,
            Some(fact.api_id.clone()),
            vec![
                static_site_object_id("static_site", &fact.site_id.to_string()),
                format!(
                    "atomic_operation:{}",
                    atomic_operation_kind_token(fact.operation)
                ),
                format!(
                    "atomic_ordering:{}",
                    atomic_ordering_kind_token(fact.ordering)
                ),
            ],
        ),
        StaticFact::ObjectBindingGap(fact) => (
            V326LifecycleFactKind::ObjectBindingGap,
            Some(fact.api_id.clone()),
            object_binding_gap_object_ids(fact),
        ),
        StaticFact::ObjectFlow(fact) => {
            let from_object_id = static_site_object_id(
                object_flow_object_kind_token(fact.from_object_kind),
                &fact.from_site_id.to_string(),
            );
            let to_object_id = static_site_object_id(
                object_flow_object_kind_token(fact.to_object_kind),
                &fact.to_site_id.to_string(),
            );
            let endpoint_from_object_id = if object_flow_is_closure_capture_slot_load(fact) {
                fact.field_path
                    .as_deref()
                    .map(|field_path| {
                        closure_capture_slot_object_id(&fact.from_site_id.to_string(), field_path)
                    })
                    .unwrap_or_else(|| from_object_id.clone())
            } else {
                from_object_id.clone()
            };
            let endpoint_to_object_id = if fact.flow_kind == ObjectFlowKind::ClosureCapture {
                fact.field_path
                    .as_deref()
                    .map(|field_path| {
                        closure_capture_slot_object_id(&fact.to_site_id.to_string(), field_path)
                    })
                    .unwrap_or_else(|| to_object_id.clone())
            } else {
                to_object_id.clone()
            };
            let mut object_ids = vec![
                endpoint_from_object_id,
                endpoint_to_object_id,
                static_site_object_id("static_site", &fact.site_id.to_string()),
                format!("object_flow:{}", object_flow_kind_token(fact.flow_kind)),
            ];
            if object_flow_is_closure_capture_slot_load(fact)
                && !object_ids
                    .iter()
                    .any(|object_id| object_id == &from_object_id)
            {
                object_ids.push(from_object_id);
            }
            if fact.flow_kind == ObjectFlowKind::ClosureCapture
                && !object_ids
                    .iter()
                    .any(|object_id| object_id == &to_object_id)
            {
                object_ids.push(to_object_id);
            }
            if let Some(field_path) = fact.field_path.as_deref() {
                object_ids.push(object_flow_binding_key_object_id("field", field_path));
                if object_flow_field_path_is_hook_release_slot(field_path) {
                    object_ids.push(object_flow_binding_kind_object_id("hook_release_slot"));
                }
                object_ids.extend(
                    object_flow_collection_binding_prefixes(field_path)
                        .into_iter()
                        .map(|prefix| object_flow_binding_member_object_id("field", &prefix)),
                );
            }
            if let Some(container_type_name) = fact.container_type_name.as_deref() {
                object_ids.push(object_flow_binding_key_object_id(
                    "container",
                    container_type_name,
                ));
            }
            (
                V326LifecycleFactKind::ObjectFlow,
                Some(fact.api_id.clone()),
                object_ids,
            )
        }
    })
}

fn static_site_object_id(role: &str, site_id: &str) -> String {
    format!("{role}:{site_id}")
}

fn closure_capture_slot_object_id(callback_site_id: &str, field_path: &str) -> String {
    format!(
        "callback:{callback_site_id}:capture_slot:{:x}",
        Sha256::digest(field_path.as_bytes())
    )
}

fn object_flow_is_closure_capture_slot_load(fact: &crate::ObjectFlowFact) -> bool {
    fact.flow_kind == ObjectFlowKind::FieldLoad
        && fact.from_object_kind == ObjectFlowObjectKind::Callback
        && fact
            .field_path
            .as_deref()
            .is_some_and(|field_path| field_path.starts_with("closure_capture_ordinal:"))
}

fn returned_borrow_ordering_token(ordering: ReturnedBorrowInvalidationOrdering) -> &'static str {
    match ordering {
        ReturnedBorrowInvalidationOrdering::PersistenceBeforeInvalidationUse => {
            "persistence_before_invalidation_use"
        }
        ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse => {
            "invalidation_before_persistence_use"
        }
    }
}

fn callback_release_use_ordering_token(
    ordering: crate::CallbackReleaseUseOrdering,
) -> &'static str {
    match ordering {
        crate::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse => {
            "release_before_callback_use"
        }
        crate::CallbackReleaseUseOrdering::CallbackUseBeforeRelease => {
            "callback_use_before_release"
        }
        crate::CallbackReleaseUseOrdering::UnknownOrdering => "unknown_ordering",
    }
}

fn atomic_operation_kind_token(operation: AtomicOperationKind) -> &'static str {
    match operation {
        AtomicOperationKind::Load => "load",
    }
}

fn atomic_ordering_kind_token(ordering: AtomicOrderingKind) -> &'static str {
    match ordering {
        AtomicOrderingKind::Relaxed => "relaxed",
        AtomicOrderingKind::Acquire => "acquire",
        AtomicOrderingKind::Release => "release",
        AtomicOrderingKind::AcqRel => "acq_rel",
        AtomicOrderingKind::SeqCst => "seqcst",
    }
}

fn object_binding_gap_object_ids(fact: &crate::ObjectBindingGapFact) -> Vec<String> {
    let mut object_ids = vec![
        static_site_object_id("static_site", &fact.site_id.to_string()),
        format!(
            "object_binding_gap:{}",
            object_binding_gap_kind_token(fact.gap_kind)
        ),
    ];
    if let Some(adapter) = fact.adapter.as_deref().map(sanitize_id_for_path) {
        object_ids.push(format!("adapter:{adapter}"));
    }
    if let Some(field_path) = fact.field_path.as_deref() {
        if object_binding_gap_uses_prefix_binding(fact) {
            object_ids.push(object_flow_binding_prefix_object_id("field", field_path));
        } else {
            object_ids.push(object_flow_binding_key_object_id("field", field_path));
        }
    }
    if let Some(container_type_name) = fact.container_type_name.as_deref() {
        object_ids.push(object_flow_binding_key_object_id(
            "container",
            container_type_name,
        ));
    }
    object_ids
}

fn object_binding_gap_kind_token(kind: ObjectBindingGapKind) -> &'static str {
    match kind {
        ObjectBindingGapKind::SelectionPredicate => "selection_predicate",
        ObjectBindingGapKind::MappedValue => "mapped_value",
        ObjectBindingGapKind::MergedSources => "merged_sources",
        ObjectBindingGapKind::TupleProjection => "tuple_projection",
        ObjectBindingGapKind::CardinalityTransform => "cardinality_transform",
        ObjectBindingGapKind::DynamicIndex => "dynamic_index",
        ObjectBindingGapKind::RangeOrSlice => "range_or_slice",
        ObjectBindingGapKind::SequenceLengthUnknown => "sequence_length_unknown",
        ObjectBindingGapKind::KeyContract => "key_contract",
        ObjectBindingGapKind::ReassignmentBarrier => "reassignment_barrier",
        ObjectBindingGapKind::MutationBarrier => "mutation_barrier",
        ObjectBindingGapKind::CallBoundary => "call_boundary",
    }
}

fn object_flow_kind_token(kind: ObjectFlowKind) -> &'static str {
    match kind {
        ObjectFlowKind::Argument => "argument",
        ObjectFlowKind::ReturnValue => "return_value",
        ObjectFlowKind::FieldStore => "field_store",
        ObjectFlowKind::FieldLoad => "field_load",
        ObjectFlowKind::WrapperMove => "wrapper_move",
        ObjectFlowKind::WrapperDestructure => "wrapper_destructure",
        ObjectFlowKind::CollectionStore => "collection_store",
        ObjectFlowKind::CollectionLoad => "collection_load",
        ObjectFlowKind::ClosureCapture => "closure_capture",
    }
}

fn object_flow_object_kind_token(kind: ObjectFlowObjectKind) -> &'static str {
    match kind {
        ObjectFlowObjectKind::Callback => "callback",
        ObjectFlowObjectKind::UserData => "user_data",
        ObjectFlowObjectKind::RustOwner => "rust_owner",
        ObjectFlowObjectKind::ReturnedRef => "returned_ref",
        ObjectFlowObjectKind::Storage => "storage",
        ObjectFlowObjectKind::OpaqueHandle => "opaque_handle",
        ObjectFlowObjectKind::StaticSite => "static_site",
    }
}

fn object_flow_binding_key_object_id(scope: &str, value: &str) -> String {
    format!(
        "object_flow_binding:{scope}:{:x}",
        Sha256::digest(value.as_bytes())
    )
}

fn object_flow_binding_member_object_id(scope: &str, value: &str) -> String {
    format!(
        "object_flow_binding_member:{scope}:{:x}",
        Sha256::digest(value.as_bytes())
    )
}

fn object_flow_binding_prefix_object_id(scope: &str, value: &str) -> String {
    format!(
        "object_flow_binding_prefix:{scope}:{:x}",
        Sha256::digest(value.as_bytes())
    )
}

fn object_flow_binding_kind_object_id(binding_kind: &str) -> String {
    format!("object_flow_binding_kind:{binding_kind}")
}

fn object_flow_field_path_is_hook_release_slot(field_path: &str) -> bool {
    field_path.starts_with("hook_release_slot:")
}

fn object_flow_collection_binding_prefixes(field_path: &str) -> Vec<String> {
    [":map_key:", ":element_index:"]
        .iter()
        .filter_map(|marker| {
            field_path
                .find(marker)
                .map(|index| field_path[..index + marker.len()].to_owned())
        })
        .collect()
}

fn object_binding_gap_uses_prefix_binding(fact: &crate::ObjectBindingGapFact) -> bool {
    fact.gap_kind == ObjectBindingGapKind::MutationBarrier
        && fact
            .adapter
            .as_deref()
            .is_some_and(|adapter| adapter.starts_with("returned_borrow_storage_prefix_mutation:"))
}

fn callback_user_data_reconstruction_token(
    kind: crate::CallbackUserDataReconstructionKind,
) -> &'static str {
    match kind {
        crate::CallbackUserDataReconstructionKind::OwnerFromTransmute => "owner_from_transmute",
        crate::CallbackUserDataReconstructionKind::OwnerFromRaw => "owner_from_raw",
        crate::CallbackUserDataReconstructionKind::LeakFromRaw => "leak_from_raw",
    }
}

fn ranked_from_feature(
    run_id: &str,
    feature: V326LifecycleFeatureRecord,
) -> V326RankedCandidateRecord {
    let breakdown = score_breakdown_from_feature_record(&feature);
    let score = recompute_score(&breakdown);
    let risk_features = risk_feature_names(&feature.features);
    let protective_features = protective_feature_names(&feature.features);
    let ranking_reason = ranking_reason_v2(score, &risk_features, &protective_features, &feature);
    let lifecycle_graph_path = format!(
        "graphs/{}.json",
        sanitize_id_for_path(&feature.candidate_id)
    );

    V326RankedCandidateRecord {
        schema_version: V3_2_6_RANKED_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: run_id.to_owned(),
        rank: 0,
        score,
        score_breakdown: breakdown,
        candidate_id: feature.candidate_id,
        crate_id: feature.crate_id,
        pattern_family: feature.pattern_family,
        risk_features,
        protective_features,
        feature_evidence_refs: feature.feature_evidence,
        missing_evidence: feature.missing_evidence,
        lifecycle_graph_path,
        chain_summary: V326RankedChainSummary::default(),
        ranking_reason,
        notes: vec!["candidate ranking is not a defect conclusion".to_owned()],
    }
}

fn score_breakdown_from_feature_record(feature: &V326LifecycleFeatureRecord) -> V326ScoreBreakdown {
    let mut breakdown = score_breakdown_from_features(&feature.features);
    if external_buffer_binding_only_chain_is_diagnostic(feature) {
        breakdown.has_verified_object_chain = 0;
    }
    breakdown
}

fn score_breakdown_from_features(features: &V326FeatureSet) -> V326ScoreBreakdown {
    let static_owned_retention_is_lifetime_protected =
        static_owned_retention_is_lifetime_protected(features);
    V326ScoreBreakdown {
        has_foreign_register: flag_score(features.has_foreign_register, SCORE_HAS_FOREIGN_REGISTER),
        foreign_may_retain_callback: flag_score(
            features.foreign_may_retain_callback,
            SCORE_FOREIGN_MAY_RETAIN_CALLBACK,
        ),
        foreign_may_retain_user_data: flag_score(
            features.foreign_may_retain_user_data && !static_owned_retention_is_lifetime_protected,
            SCORE_FOREIGN_MAY_RETAIN_USER_DATA,
        ),
        has_borrowed_capture: flag_score(features.has_borrowed_capture, SCORE_HAS_BORROWED_CAPTURE),
        has_raw_pointer_escape: flag_score(
            features.has_raw_pointer_escape,
            SCORE_HAS_RAW_POINTER_ESCAPE,
        ),
        raw_parts_transfer_without_drop_prevention: flag_score(
            features.raw_parts_transfer_without_drop_prevention,
            raw_parts_transfer_without_drop_prevention_score(features),
        ),
        has_drop_prevention: flag_score(features.has_drop_prevention, SCORE_HAS_DROP_PREVENTION),
        manual_drop_prevention_without_drop_guard: flag_score(
            features.manual_drop_prevention_without_drop_guard,
            SCORE_MANUAL_DROP_PREVENTION_WITHOUT_DROP_GUARD,
        ),
        callback_user_data_owner_reconstruction_without_leak_guard: flag_score(
            features.callback_user_data_owner_reconstruction_without_leak_guard,
            SCORE_CALLBACK_USER_DATA_OWNER_RECONSTRUCTION_WITHOUT_LEAK_GUARD,
        ),
        has_returned_borrow_relation: flag_score(
            features.has_returned_borrow_relation,
            SCORE_HAS_RETURNED_BORROW_RELATION,
        ),
        has_unconstrained_return_lifetime: flag_score(
            features.has_unconstrained_return_lifetime,
            SCORE_HAS_UNCONSTRAINED_RETURN_LIFETIME,
        ),
        has_persisted_returned_borrow: flag_score(
            features.has_persisted_returned_borrow,
            SCORE_HAS_PERSISTED_RETURNED_BORROW,
        ),
        returned_borrow_persistence_before_invalidation: flag_score(
            features.returned_borrow_persistence_before_invalidation,
            SCORE_RETURNED_BORROW_PERSISTENCE_BEFORE_INVALIDATION,
        ),
        returned_borrow_persistence_after_invalidation: flag_score(
            features.returned_borrow_persistence_after_invalidation,
            SCORE_RETURNED_BORROW_PERSISTENCE_AFTER_INVALIDATION,
        ),
        has_external_buffer_binding: flag_score(
            features.has_external_buffer_binding,
            external_buffer_score(features),
        ),
        has_external_buffer_lifetime_bound: flag_score(
            features.has_external_buffer_lifetime_bound,
            SCORE_HAS_EXTERNAL_BUFFER_LIFETIME_BOUND,
        ),
        relaxed_atomic_load_in_iterator: flag_score(
            features.relaxed_atomic_load_in_iterator,
            SCORE_RELAXED_ATOMIC_LOAD_IN_ITERATOR,
        ),
        acquire_atomic_load_in_iterator: flag_score(
            features.acquire_atomic_load_in_iterator,
            SCORE_ACQUIRE_ATOMIC_LOAD_IN_ITERATOR,
        ),
        has_verified_object_chain: flag_score(
            features.has_verified_object_chain,
            SCORE_HAS_VERIFIED_OBJECT_CHAIN,
        ),
        has_release_order_chain: flag_score(
            features.has_release_order_chain,
            SCORE_HAS_RELEASE_ORDER_CHAIN,
        ),
        has_persisted_invalidation_use_chain: flag_score(
            features.has_persisted_invalidation_use_chain,
            SCORE_HAS_PERSISTED_INVALIDATION_USE_CHAIN,
        ),
        has_callback_release_use_chain: flag_score(
            features.has_callback_release_use_chain,
            SCORE_HAS_CALLBACK_RELEASE_USE_CHAIN,
        ),
        rust_object_may_drop_before_foreign_release: flag_score(
            features.rust_object_may_drop_before_foreign_release,
            SCORE_RUST_OBJECT_MAY_DROP_BEFORE_FOREIGN_RELEASE,
        ),
        missing_unregister_before_drop: flag_score(
            features.missing_unregister_before_drop,
            SCORE_MISSING_UNREGISTER_BEFORE_DROP,
        ),
        release_order_unknown: flag_score(
            features.release_order_unknown,
            SCORE_RELEASE_ORDER_UNKNOWN,
        ),
        opaque_handle_without_owner: flag_score(
            features.opaque_handle_without_owner,
            SCORE_OPAQUE_HANDLE_WITHOUT_OWNER,
        ),
        needs_dynamic_witness: flag_score(
            features.needs_dynamic_witness,
            SCORE_NEEDS_DYNAMIC_WITNESS,
        ),
        has_owned_anchor: flag_score(features.has_owned_anchor, SCORE_HAS_OWNED_ANCHOR),
        has_drop_guard: flag_score(features.has_drop_guard, SCORE_HAS_DROP_GUARD),
        registration_release_pair_found: flag_score(
            features.registration_release_pair_found,
            SCORE_REGISTRATION_RELEASE_PAIR_FOUND,
        ),
        has_static_bound: flag_score(features.has_static_bound, SCORE_HAS_STATIC_BOUND),
        has_arc_anchor: flag_score(features.has_arc_anchor, SCORE_HAS_ARC_ANCHOR),
        release_covers_callback: flag_score(
            features.release_covers_callback,
            SCORE_RELEASE_COVERS_CALLBACK,
        ),
    }
}

fn external_buffer_binding_only_chain_is_diagnostic(feature: &V326LifecycleFeatureRecord) -> bool {
    feature.pattern_family == V32PatternFamily::ExternalBufferView
        && feature.features.has_external_buffer_binding
        && feature.features.has_verified_object_chain
        && !feature.features.has_release_order_chain
        && !feature.features.has_persisted_invalidation_use_chain
        && !feature.features.has_returned_borrow_relation
        && !feature.features.has_persisted_returned_borrow
        && !feature.features.has_foreign_register
        && !feature.features.foreign_may_retain_callback
        && !feature.features.foreign_may_retain_user_data
}

fn flag_score(active: bool, weight: i32) -> i32 {
    if active { weight } else { 0 }
}

fn external_buffer_score(features: &V326FeatureSet) -> i32 {
    if features.has_external_buffer_binding
        && !features.has_static_bound
        && !features.has_external_buffer_lifetime_bound
    {
        SCORE_EXTERNAL_BUFFER_WITHOUT_STATIC_BOUND
    } else {
        SCORE_HAS_EXTERNAL_BUFFER_BINDING
    }
}

fn raw_parts_transfer_without_drop_prevention_score(features: &V326FeatureSet) -> i32 {
    if features.raw_parts_transfer_without_drop_prevention
        && features.has_owned_anchor
        && !features.has_drop_guard
        && !features.has_verified_object_chain
        && !features.has_release_order_chain
        && !features.has_persisted_invalidation_use_chain
    {
        SCORE_RAW_PARTS_TRANSFER_WITHOUT_DROP_PREVENTION_OWNER_ANCHOR_ONLY
    } else {
        SCORE_RAW_PARTS_TRANSFER_WITHOUT_DROP_PREVENTION
    }
}

fn lifecycle_release_risk_signal(features: &V326FeatureSet) -> bool {
    features.foreign_may_retain_callback
        || features.foreign_may_retain_user_data
        || features.has_borrowed_capture
        || features.has_raw_pointer_escape
        || features.callback_user_data_owner_reconstruction_without_leak_guard
        || features.has_callback_release_use_chain
        || features.opaque_handle_without_owner
}

fn static_owned_retention_is_lifetime_protected(features: &V326FeatureSet) -> bool {
    features.has_static_bound && features.has_owned_anchor && !features.has_borrowed_capture
}

fn recompute_score(breakdown: &V326ScoreBreakdown) -> u32 {
    let total = breakdown.has_foreign_register
        + breakdown.foreign_may_retain_callback
        + breakdown.foreign_may_retain_user_data
        + breakdown.has_borrowed_capture
        + breakdown.has_raw_pointer_escape
        + breakdown.raw_parts_transfer_without_drop_prevention
        + breakdown.has_drop_prevention
        + breakdown.manual_drop_prevention_without_drop_guard
        + breakdown.callback_user_data_owner_reconstruction_without_leak_guard
        + breakdown.has_returned_borrow_relation
        + breakdown.has_unconstrained_return_lifetime
        + breakdown.has_persisted_returned_borrow
        + breakdown.returned_borrow_persistence_before_invalidation
        + breakdown.returned_borrow_persistence_after_invalidation
        + breakdown.has_external_buffer_binding
        + breakdown.has_external_buffer_lifetime_bound
        + breakdown.relaxed_atomic_load_in_iterator
        + breakdown.acquire_atomic_load_in_iterator
        + breakdown.has_verified_object_chain
        + breakdown.has_release_order_chain
        + breakdown.has_persisted_invalidation_use_chain
        + breakdown.has_callback_release_use_chain
        + breakdown.rust_object_may_drop_before_foreign_release
        + breakdown.missing_unregister_before_drop
        + breakdown.release_order_unknown
        + breakdown.opaque_handle_without_owner
        + breakdown.needs_dynamic_witness
        + breakdown.has_owned_anchor
        + breakdown.has_drop_guard
        + breakdown.registration_release_pair_found
        + breakdown.has_static_bound
        + breakdown.has_arc_anchor
        + breakdown.release_covers_callback;
    total.max(0) as u32
}

fn ranking_reason_v2(
    score: u32,
    risk_features: &[String],
    protective_features: &[String],
    feature: &V326LifecycleFeatureRecord,
) -> String {
    let positive = if risk_features.is_empty() {
        "none".to_owned()
    } else {
        risk_features.join(",")
    };
    let protective = if protective_features.is_empty() {
        "none".to_owned()
    } else {
        protective_features.join(",")
    };
    let missing = if feature.missing_evidence.is_empty() {
        "none".to_owned()
    } else {
        feature.missing_evidence.join(",")
    };
    format!(
        "score={score}; positive={positive}; protective={protective}; missing={missing}; candidate ranking is not a defect conclusion"
    )
}

fn risk_feature_names(features: &V326FeatureSet) -> Vec<String> {
    let mut names = Vec::new();
    if features.has_foreign_register {
        names.push("has_foreign_register".to_owned());
    }
    if features.foreign_may_retain_callback {
        names.push("foreign_may_retain_callback".to_owned());
    }
    if features.foreign_may_retain_user_data {
        names.push("foreign_may_retain_user_data".to_owned());
    }
    if features.has_borrowed_capture {
        names.push("has_borrowed_capture".to_owned());
    }
    if features.has_raw_pointer_escape {
        names.push("has_raw_pointer_escape".to_owned());
    }
    if features.raw_parts_transfer_without_drop_prevention {
        names.push("raw_parts_transfer_without_drop_prevention".to_owned());
    }
    if features.has_drop_prevention {
        names.push("has_drop_prevention".to_owned());
    }
    if features.manual_drop_prevention_without_drop_guard {
        names.push("manual_drop_prevention_without_drop_guard".to_owned());
    }
    if features.callback_user_data_owner_reconstruction_without_leak_guard {
        names.push("callback_user_data_owner_reconstruction_without_leak_guard".to_owned());
    }
    if features.has_returned_borrow_relation {
        names.push("has_returned_borrow_relation".to_owned());
    }
    if features.has_unconstrained_return_lifetime {
        names.push("has_unconstrained_return_lifetime".to_owned());
    }
    if features.has_persisted_returned_borrow {
        names.push("has_persisted_returned_borrow".to_owned());
    }
    if features.returned_borrow_persistence_before_invalidation {
        names.push("returned_borrow_persistence_before_invalidation".to_owned());
    }
    if features.has_external_buffer_binding {
        names.push("has_external_buffer_binding".to_owned());
    }
    if features.relaxed_atomic_load_in_iterator {
        names.push("relaxed_atomic_load_in_iterator".to_owned());
    }
    if features.has_verified_object_chain {
        names.push("has_verified_object_chain".to_owned());
    }
    if features.has_persisted_invalidation_use_chain {
        names.push("has_persisted_invalidation_use_chain".to_owned());
    }
    if features.has_callback_release_use_chain {
        names.push("has_callback_release_use_chain".to_owned());
    }
    if features.rust_object_may_drop_before_foreign_release {
        names.push("rust_object_may_drop_before_foreign_release".to_owned());
    }
    if features.missing_unregister_before_drop {
        names.push("missing_unregister_before_drop".to_owned());
    }
    if features.release_order_unknown {
        names.push("release_order_unknown".to_owned());
    }
    if features.opaque_handle_without_owner {
        names.push("opaque_handle_without_owner".to_owned());
    }
    if features.needs_dynamic_witness {
        names.push("needs_dynamic_witness".to_owned());
    }
    names
}

fn protective_feature_names(features: &V326FeatureSet) -> Vec<String> {
    let mut names = Vec::new();
    if features.has_foreign_unregister {
        names.push("has_foreign_unregister".to_owned());
    }
    if features.registration_release_pair_found {
        names.push("registration_release_pair_found".to_owned());
    }
    if features.has_drop_guard {
        names.push("has_drop_guard".to_owned());
    }
    if features.has_owned_anchor {
        names.push("has_owned_anchor".to_owned());
    }
    if features.has_static_bound {
        names.push("has_static_bound".to_owned());
    }
    if features.has_external_buffer_lifetime_bound {
        names.push("has_external_buffer_lifetime_bound".to_owned());
    }
    if features.acquire_atomic_load_in_iterator {
        names.push("acquire_atomic_load_in_iterator".to_owned());
    }
    if features.has_release_order_chain {
        names.push("has_release_order_chain".to_owned());
    }
    if features.has_box_into_raw {
        names.push("has_box_into_raw".to_owned());
    }
    if features.has_box_from_raw {
        names.push("has_box_from_raw".to_owned());
    }
    if features.has_arc_anchor {
        names.push("has_arc_anchor".to_owned());
    }
    if features.release_covers_callback {
        names.push("release_covers_callback".to_owned());
    }
    if features.returned_borrow_persistence_after_invalidation {
        names.push("returned_borrow_persistence_after_invalidation".to_owned());
    }
    names
}

pub fn active_feature_names(features: &V326FeatureSet) -> Vec<String> {
    features
        .active_flags()
        .into_iter()
        .filter_map(|(name, active)| active.then_some(name.to_owned()))
        .collect()
}

fn has_contract_retention(contracts: &[V326LifecycleContractRecord]) -> bool {
    contracts
        .iter()
        .any(|contract| contract.retention == V326ContractRetention::MayRetainCallback)
}

fn lifecycle_contract_applies_to_candidate(
    candidate: &crate::V32CandidateRecord,
    facts: &[V326LifecycleFactRecord],
    contract: &V326LifecycleContractRecord,
) -> bool {
    candidate
        .api_path
        .as_deref()
        .is_some_and(|api_path| lifecycle_api_matches(api_path, &contract.api_id))
        || facts.iter().any(|fact| {
            is_authoritative_object_binding_fact(fact)
                && fact.fact_kind == V326LifecycleFactKind::RegisterCall
                && fact
                    .symbol_path
                    .as_deref()
                    .is_some_and(|api_path| lifecycle_api_matches(api_path, &contract.api_id))
        })
}

fn lifecycle_api_matches(candidate_api: &str, contract_api: &str) -> bool {
    if !is_exact_lifecycle_api_id(candidate_api) || !is_exact_lifecycle_api_id(contract_api) {
        return false;
    }
    let candidate = candidate_api.trim().to_ascii_lowercase();
    let contract = contract_api.trim().to_ascii_lowercase();
    !candidate.is_empty() && candidate == contract
}

fn is_exact_lifecycle_api_id(value: &str) -> bool {
    let value = value.trim();
    let canonical_rust_path = value.contains("::");
    let canonical_api_map_id = value.strip_prefix("api:").is_some_and(|suffix| {
        suffix.split(':').count() >= 3 && !suffix.split(':').any(str::is_empty)
    });
    !value.is_empty()
        && (canonical_rust_path || canonical_api_map_id)
        && !value.contains('*')
        && !value.split_whitespace().any(|part| part != value)
}

fn static_release_path_proof_is_consistent(
    envelope: &StaticFactEnvelope,
    static_facts: &[StaticFactEnvelope],
) -> bool {
    let StaticFact::ReleasePathProof(proof) = &envelope.payload else {
        return true;
    };
    let registration_exists = static_facts.iter().any(|candidate| {
        static_release_path_support_matches(envelope, candidate)
            && matches!(
                &candidate.payload,
                StaticFact::RegistrationSite(registration)
                    if registration.role == crate::RegistrationRole::Register
                        && registration.site_id == proof.registration_site_id
                        && registration.user_data_site_id.as_ref() == Some(&proof.object_site_id)
            )
    });
    let release_exists = static_facts.iter().any(|candidate| {
        static_release_path_support_matches(envelope, candidate)
            && matches!(
                &candidate.payload,
                StaticFact::RawPointerTransfer(transfer)
                    if transfer.transfer_kind == crate::RawPointerTransferKind::FromRaw
                        && transfer.site_id == proof.release_site_id
                        && transfer.user_data_site_id == proof.object_site_id
            )
    });
    registration_exists && release_exists
}

fn static_release_path_support_matches(
    proof: &StaticFactEnvelope,
    support: &StaticFactEnvelope,
) -> bool {
    support.is_authoritative_lifecycle_binding()
        && support.producer == proof.producer
        && support.build_id == proof.build_id
        && support.artifact == proof.artifact
}

fn raw_pointer_escape_is_bound_to_register(facts: &[V326LifecycleFactRecord]) -> bool {
    let raw_pointer_user_data_ids = facts
        .iter()
        .filter(|item| {
            item.fact_kind == V326LifecycleFactKind::RawPointerEscape
                && is_authoritative_object_binding_fact(item)
        })
        .flat_map(fact_user_data_object_ids)
        .collect::<BTreeSet<_>>();
    if raw_pointer_user_data_ids.is_empty() {
        return false;
    }
    let register_user_data_ids = facts
        .iter()
        .filter(|item| {
            item.fact_kind == V326LifecycleFactKind::RegisterCall
                && is_authoritative_object_binding_fact(item)
        })
        .flat_map(fact_user_data_object_ids)
        .collect::<BTreeSet<_>>();
    raw_pointer_user_data_ids
        .iter()
        .any(|item| register_user_data_ids.contains(item))
}

fn raw_pointer_binding_fact_refs(facts: &[V326LifecycleFactRecord]) -> Vec<String> {
    facts
        .iter()
        .filter(|item| {
            matches!(
                item.fact_kind,
                V326LifecycleFactKind::RawPointerEscape | V326LifecycleFactKind::RegisterCall
            ) && is_authoritative_object_binding_fact(item)
        })
        .map(|item| item.fact_id.clone())
        .collect()
}

fn is_authoritative_object_binding_fact(item: &V326LifecycleFactRecord) -> bool {
    item.fact_kind != V326LifecycleFactKind::ObjectBindingGap
        && item.confidence == V326EvidenceConfidence::High
        && item.provenance.is_verified_static_artifact()
}

fn retention_refs(
    evidence: &[V326LifecycleEvidenceRecord],
    contracts: &[V326LifecycleContractRecord],
) -> Vec<String> {
    let mut refs = refs_for(evidence, V326EvidenceKind::ForeignRetentionHint);
    refs.extend(
        contracts
            .iter()
            .filter(|contract| contract.retention == V326ContractRetention::MayRetainCallback)
            .map(|contract| contract.contract_id.clone()),
    );
    refs.sort();
    refs.dedup();
    refs
}

fn has_evidence(evidence: &[V326LifecycleEvidenceRecord], kind: V326EvidenceKind) -> bool {
    evidence.iter().any(|item| item.evidence_kind == kind)
}

fn refs_for(evidence: &[V326LifecycleEvidenceRecord], kind: V326EvidenceKind) -> Vec<String> {
    evidence
        .iter()
        .filter(|item| item.evidence_kind == kind)
        .map(|item| item.record_id.clone())
        .collect()
}

fn refs_for_static_lifetime_bound(evidence: &[V326LifecycleEvidenceRecord]) -> Vec<String> {
    evidence
        .iter()
        .filter(|item| item.evidence_kind == V326EvidenceKind::LifetimeBound)
        .filter(|item| !is_external_buffer_lifetime_bound_evidence(item))
        .map(|item| item.record_id.clone())
        .collect()
}

fn refs_for_external_buffer_lifetime_bound(
    evidence: &[V326LifecycleEvidenceRecord],
) -> Vec<String> {
    evidence
        .iter()
        .filter(|item| item.evidence_kind == V326EvidenceKind::LifetimeBound)
        .filter(|item| is_external_buffer_lifetime_bound_evidence(item))
        .map(|item| item.record_id.clone())
        .collect()
}

fn is_external_buffer_lifetime_bound_evidence(item: &V326LifecycleEvidenceRecord) -> bool {
    item.details
        .get("signal")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|signal| signal == V3_2_6_EXTERNAL_BUFFER_RETURN_LIFETIME_SIGNAL)
}

fn release_covers_same_lifecycle_object(
    _evidence: &[V326LifecycleEvidenceRecord],
    facts: &[V326LifecycleFactRecord],
) -> bool {
    release_path_proof_register_pairs(facts).next().is_some()
}

fn release_order_is_proven_after_register(
    _evidence: &[V326LifecycleEvidenceRecord],
    facts: &[V326LifecycleFactRecord],
) -> bool {
    release_covers_same_lifecycle_object(&[], facts)
}

fn authoritative_fact_refs(
    facts: &[V326LifecycleFactRecord],
    kinds: &[V326LifecycleFactKind],
) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact) && kinds.contains(&fact.fact_kind)
        })
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn release_path_proof_register_pairs(
    facts: &[V326LifecycleFactRecord],
) -> impl Iterator<Item = (&V326LifecycleFactRecord, &V326LifecycleFactRecord)> {
    facts
        .iter()
        .filter(|proof| {
            proof.fact_kind == V326LifecycleFactKind::ReleasePathProof
                && is_authoritative_object_binding_fact(proof)
        })
        .flat_map(move |proof| {
            facts
                .iter()
                .filter(move |register| release_path_proof_matches_register(proof, register))
                .map(move |register| (proof, register))
        })
}

fn release_path_proof_matches_register(
    proof: &V326LifecycleFactRecord,
    register: &V326LifecycleFactRecord,
) -> bool {
    if proof.fact_kind != V326LifecycleFactKind::ReleasePathProof
        || register.fact_kind != V326LifecycleFactKind::RegisterCall
        || !is_authoritative_object_binding_fact(proof)
        || !is_authoritative_object_binding_fact(register)
    {
        return false;
    }
    let Some(proof_registration_site) = release_path_proof_registration_static_site(proof) else {
        return false;
    };
    let Some(register_site) = registration_fact_static_site(register) else {
        return false;
    };
    if proof_registration_site != register_site {
        return false;
    }
    let proof_user_data = fact_user_data_object_ids(proof)
        .into_iter()
        .collect::<BTreeSet<_>>();
    !proof_user_data.is_empty()
        && fact_user_data_object_ids(register)
            .iter()
            .any(|object_id| proof_user_data.contains(object_id))
}

fn release_path_proof_support_fact_matches(
    proof: &V326LifecycleFactRecord,
    fact: &V326LifecycleFactRecord,
    proof_user_data: &BTreeSet<String>,
) -> bool {
    match fact.fact_kind {
        V326LifecycleFactKind::RawPointerEscape => fact_user_data_object_ids(fact)
            .iter()
            .any(|object_id| proof_user_data.contains(object_id)),
        V326LifecycleFactKind::ReleaseCall => release_path_proof_matches_release_call(proof, fact),
        _ => false,
    }
}

fn release_path_proof_matches_release_call(
    proof: &V326LifecycleFactRecord,
    release_call: &V326LifecycleFactRecord,
) -> bool {
    if proof.fact_kind != V326LifecycleFactKind::ReleasePathProof
        || release_call.fact_kind != V326LifecycleFactKind::ReleaseCall
        || !is_authoritative_object_binding_fact(proof)
        || !is_authoritative_object_binding_fact(release_call)
    {
        return false;
    }
    let Some(proof_release_endpoint) = release_path_proof_release_endpoint(proof) else {
        return false;
    };
    let Some(release_endpoint) = release_call_endpoint(release_call) else {
        return false;
    };
    if proof_release_endpoint != release_endpoint {
        return false;
    }
    let proof_user_data = fact_user_data_object_ids(proof)
        .into_iter()
        .collect::<BTreeSet<_>>();
    !proof_user_data.is_empty()
        && fact_user_data_object_ids(release_call)
            .iter()
            .any(|object_id| proof_user_data.contains(object_id))
}

fn release_path_proof_object_flow_support_refs(
    proof: &V326LifecycleFactRecord,
    facts: &[V326LifecycleFactRecord],
    proof_user_data: &BTreeSet<String>,
) -> Vec<String> {
    let Some(proof_release_static_site) =
        release_path_proof_release_endpoint(proof).map(|release_endpoint| {
            release_endpoint
                .strip_prefix("release_endpoint:")
                .map(|site_id| format!("static_site:{site_id}"))
                .unwrap_or(release_endpoint)
        })
    else {
        return Vec::new();
    };
    object_flow_field_store_load_support_refs(
        facts,
        proof_user_data,
        &BTreeSet::from([proof_release_static_site]),
    )
}

fn release_path_proof_callback_use_support_refs(
    proof: &V326LifecycleFactRecord,
    facts: &[V326LifecycleFactRecord],
    proof_user_data: &BTreeSet<String>,
) -> Vec<String> {
    if proof.fact_kind != V326LifecycleFactKind::ReleasePathProof
        || proof_user_data.is_empty()
        || !is_authoritative_object_binding_fact(proof)
    {
        return Vec::new();
    }
    let mut refs = BTreeSet::<String>::new();
    for reconstruction in facts.iter().filter(|fact| {
        fact.fact_kind == V326LifecycleFactKind::CallbackUserDataReconstruction
            && is_authoritative_object_binding_fact(fact)
    }) {
        let reconstruction_user_data = fact_user_data_object_ids(reconstruction)
            .into_iter()
            .collect::<BTreeSet<_>>();
        if reconstruction_user_data.is_empty() {
            continue;
        }
        let flow_refs = object_flow_field_store_load_support_refs(
            facts,
            proof_user_data,
            &reconstruction_user_data,
        );
        let direct_same_object = reconstruction_user_data
            .iter()
            .any(|object_id| proof_user_data.contains(object_id));
        if !(direct_same_object || !flow_refs.is_empty()) {
            continue;
        }
        let order_refs =
            callback_release_use_order_support_refs(proof, reconstruction, facts, proof_user_data);
        if !order_refs.is_empty() {
            refs.insert(reconstruction.fact_id.clone());
            refs.extend(flow_refs);
            refs.extend(order_refs);
        }
    }
    refs.into_iter().collect()
}

fn callback_release_use_order_support_refs(
    proof: &V326LifecycleFactRecord,
    reconstruction: &V326LifecycleFactRecord,
    facts: &[V326LifecycleFactRecord],
    proof_user_data: &BTreeSet<String>,
) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| {
            callback_release_use_order_matches(proof, reconstruction, fact, proof_user_data)
        })
        .map(|fact| fact.fact_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn callback_release_use_order_matches(
    proof: &V326LifecycleFactRecord,
    reconstruction: &V326LifecycleFactRecord,
    order: &V326LifecycleFactRecord,
    proof_user_data: &BTreeSet<String>,
) -> bool {
    if proof.fact_kind != V326LifecycleFactKind::ReleasePathProof
        || reconstruction.fact_kind != V326LifecycleFactKind::CallbackUserDataReconstruction
        || order.fact_kind != V326LifecycleFactKind::CallbackReleaseUseOrder
        || !is_authoritative_object_binding_fact(proof)
        || !is_authoritative_object_binding_fact(reconstruction)
        || !is_authoritative_object_binding_fact(order)
        || !order
            .object_ids
            .iter()
            .any(|object_id| object_id == "callback_release_use_order:release_before_callback_use")
    {
        return false;
    }
    let Some(proof_registration) = release_path_proof_registration_static_site(proof) else {
        return false;
    };
    let Some(proof_release) = release_path_proof_release_endpoint(proof) else {
        return false;
    };
    let Some(reconstruction_site) = callback_reconstruction_static_site(reconstruction) else {
        return false;
    };
    !proof_user_data.is_empty()
        && order
            .object_ids
            .iter()
            .any(|object_id| object_id == &proof_registration)
        && order
            .object_ids
            .iter()
            .any(|object_id| object_id == &proof_release)
        && order
            .object_ids
            .iter()
            .any(|object_id| object_id == &reconstruction_site)
        && fact_user_data_object_ids(order)
            .iter()
            .any(|object_id| proof_user_data.contains(object_id))
}

fn callback_reconstruction_static_site(fact: &V326LifecycleFactRecord) -> Option<String> {
    if fact.fact_kind != V326LifecycleFactKind::CallbackUserDataReconstruction {
        return None;
    }
    first_fact_object_with_prefixes(fact, &["static_site:"])
}

fn object_flow_field_store_load_support_refs(
    facts: &[V326LifecycleFactRecord],
    from_object_ids: &BTreeSet<String>,
    to_object_ids: &BTreeSet<String>,
) -> Vec<String> {
    if from_object_ids.is_empty() || to_object_ids.is_empty() {
        return Vec::new();
    }
    let object_flow_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ObjectFlow
                && is_authoritative_object_binding_fact(fact)
        })
        .collect::<Vec<_>>();
    let barrier_binding_keys = object_binding_barrier_binding_keys(facts);
    let mut refs = BTreeSet::<String>::new();
    for store in object_flow_facts.iter().filter(|fact| {
        object_flow_kind_from_fact(fact) == Some("field_store")
            && object_flow_endpoint_object_ids_in_order(fact)
                .first()
                .is_some_and(|object_id| from_object_ids.contains(object_id))
    }) {
        for load in object_flow_facts.iter().filter(|fact| {
            object_flow_kind_from_fact(fact) == Some("field_load")
                && object_flow_endpoint_object_ids_in_order(fact)
                    .get(1)
                    .is_some_and(|object_id| to_object_ids.contains(object_id))
        }) {
            if (object_flow_facts_are_compatible_sequence(store, load, "field_store", "field_load")
                || object_flow_facts_have_hook_release_slot_support_sequence(store, load))
                && !object_flow_pair_blocked_by_barrier(store, load, &barrier_binding_keys)
            {
                refs.insert(store.fact_id.clone());
                refs.insert(load.fact_id.clone());
            }
        }
    }
    refs.into_iter().collect()
}

fn object_flow_facts_have_hook_release_slot_support_sequence(
    store: &V326LifecycleFactRecord,
    load: &V326LifecycleFactRecord,
) -> bool {
    if object_flow_kind_from_fact(store) != Some("field_store")
        || object_flow_kind_from_fact(load) != Some("field_load")
        || !object_flow_has_binding_kind(store, "hook_release_slot")
        || !object_flow_has_binding_kind(load, "hook_release_slot")
        || !object_flow_binding_keys_compatible(store, load, "field")
    {
        return false;
    }
    let store_endpoints = object_flow_endpoint_object_ids_in_order(store);
    let load_endpoints = object_flow_endpoint_object_ids_in_order(load);
    store_endpoints.len() >= 2
        && load_endpoints.len() >= 2
        && store_endpoints[0].starts_with("user_data:")
        && store_endpoints[1].starts_with("static_site:")
        && load_endpoints[0].starts_with("static_site:")
        && load_endpoints[1].starts_with("static_site:")
}

fn release_path_proof_registration_static_site(proof: &V326LifecycleFactRecord) -> Option<String> {
    if proof.fact_kind != V326LifecycleFactKind::ReleasePathProof {
        return None;
    }
    first_fact_object_with_prefixes(proof, &["static_site:"])
}

fn release_path_proof_release_endpoint(proof: &V326LifecycleFactRecord) -> Option<String> {
    if proof.fact_kind != V326LifecycleFactKind::ReleasePathProof {
        return None;
    }
    first_fact_object_with_prefixes(proof, &["release_endpoint:"])
}

fn release_call_endpoint(release_call: &V326LifecycleFactRecord) -> Option<String> {
    if release_call.fact_kind != V326LifecycleFactKind::ReleaseCall {
        return None;
    }
    first_fact_object_with_prefixes(release_call, &["release_endpoint:"])
}

fn registration_fact_static_site(register: &V326LifecycleFactRecord) -> Option<String> {
    if register.fact_kind != V326LifecycleFactKind::RegisterCall {
        return None;
    }
    first_fact_object_with_prefixes(register, &["static_site:"])
}

fn authoritative_shared_owner_anchor_refs(facts: &[V326LifecycleFactRecord]) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact)
                && fact.fact_kind == V326LifecycleFactKind::OwnedMoveCapture
                && fact
                    .symbol_path
                    .as_deref()
                    .is_some_and(text_mentions_shared_owner_anchor)
        })
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn text_mentions_shared_owner_anchor(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("sync::arc")
        || lower.contains("std::sync::arc")
        || lower.contains("alloc::sync::arc")
        || lower.contains("arc<")
        || lower.contains("rc::rc")
        || lower.contains("std::rc::rc")
        || lower.contains("alloc::rc::rc")
        || lower.contains("rc<")
}

fn verified_object_chain_refs(facts: &[V326LifecycleFactRecord]) -> Vec<String> {
    let (object_flow_refs, object_flow_endpoints) = authoritative_complete_object_flow_refs(facts);
    let support_refs = verified_object_chain_support_refs(facts, &object_flow_endpoints);
    let mut refs = Vec::new();
    if !object_flow_refs.is_empty() {
        refs.extend(object_flow_refs);
        refs.extend(support_refs);
    }
    refs.extend(release_order_chain_refs(facts));
    refs.extend(callback_release_use_chain_refs(facts));
    refs.extend(persisted_invalidation_use_chain_refs(facts));
    // External-buffer binding is deliberately excluded here: a single binding is
    // identity transport evidence, not a full save -> invalidate/release -> use chain.
    refs.sort();
    refs.dedup();
    refs
}

fn authoritative_complete_object_flow_refs(
    facts: &[V326LifecycleFactRecord],
) -> (Vec<String>, BTreeSet<String>) {
    let object_flow_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ObjectFlow
                && is_authoritative_object_binding_fact(fact)
                && lifecycle_fact_endpoint_object_ids(fact).len() >= 2
                && !object_flow_endpoint_is_ambiguous(fact, facts)
        })
        .collect::<Vec<_>>();
    let mut component_edges = BTreeMap::<String, BTreeSet<String>>::new();
    let mut flow_refs_by_object = BTreeMap::<String, BTreeSet<String>>::new();
    for fact in &object_flow_facts {
        let endpoints = lifecycle_fact_endpoint_object_ids(fact)
            .into_iter()
            .collect::<Vec<_>>();
        for endpoint in &endpoints {
            flow_refs_by_object
                .entry(endpoint.clone())
                .or_default()
                .insert(fact.fact_id.clone());
            component_edges.entry(endpoint.clone()).or_default();
        }
        if let Some(first) = endpoints.first() {
            for endpoint in endpoints.iter().skip(1) {
                component_edges
                    .entry(first.clone())
                    .or_default()
                    .insert(endpoint.clone());
                component_edges
                    .entry(endpoint.clone())
                    .or_default()
                    .insert(first.clone());
            }
        }
    }
    let barrier_binding_keys = object_binding_barrier_binding_keys(facts);
    connect_compatible_object_flow_sequence_components(
        &object_flow_facts,
        &mut component_edges,
        &barrier_binding_keys,
    );

    let mut refs = BTreeSet::<String>::new();
    let mut endpoints = BTreeSet::<String>::new();
    let mut visited = BTreeSet::<String>::new();
    for start in component_edges.keys().cloned().collect::<Vec<_>>() {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![start];
        let mut component_objects = BTreeSet::<String>::new();
        while let Some(object_id) = stack.pop() {
            if !visited.insert(object_id.clone()) {
                continue;
            }
            component_objects.insert(object_id.clone());
            if let Some(neighbors) = component_edges.get(&object_id) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        let component_refs = component_objects
            .iter()
            .filter_map(|object_id| flow_refs_by_object.get(object_id))
            .flat_map(|items| items.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if !object_flow_fact_refs_have_complete_chain(facts, &component_refs) {
            continue;
        }
        refs.extend(component_refs);
        endpoints.extend(component_objects);
    }

    (refs.into_iter().collect(), endpoints)
}

fn has_incomplete_authoritative_object_flow_component(facts: &[V326LifecycleFactRecord]) -> bool {
    let object_flow_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ObjectFlow
                && is_authoritative_object_binding_fact(fact)
                && !object_flow_endpoint_is_ambiguous(fact, facts)
                && !object_flow_fact_is_neutral_alias(fact)
        })
        .collect::<Vec<_>>();
    let mut component_edges = BTreeMap::<String, BTreeSet<String>>::new();
    let mut flow_refs_by_object = BTreeMap::<String, BTreeSet<String>>::new();
    for fact in &object_flow_facts {
        let endpoints = lifecycle_fact_endpoint_object_ids(fact)
            .into_iter()
            .collect::<Vec<_>>();
        if endpoints.len() < 2 {
            return true;
        }
        for endpoint in &endpoints {
            flow_refs_by_object
                .entry(endpoint.clone())
                .or_default()
                .insert(fact.fact_id.clone());
            component_edges.entry(endpoint.clone()).or_default();
        }
        if let Some(first) = endpoints.first() {
            for endpoint in endpoints.iter().skip(1) {
                component_edges
                    .entry(first.clone())
                    .or_default()
                    .insert(endpoint.clone());
                component_edges
                    .entry(endpoint.clone())
                    .or_default()
                    .insert(first.clone());
            }
        }
    }
    let barrier_binding_keys = object_binding_barrier_binding_keys(facts);
    connect_compatible_object_flow_sequence_components(
        &object_flow_facts,
        &mut component_edges,
        &barrier_binding_keys,
    );

    let mut visited = BTreeSet::<String>::new();
    for start in component_edges.keys().cloned().collect::<Vec<_>>() {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![start];
        let mut component_objects = BTreeSet::<String>::new();
        while let Some(object_id) = stack.pop() {
            if !visited.insert(object_id.clone()) {
                continue;
            }
            component_objects.insert(object_id.clone());
            if let Some(neighbors) = component_edges.get(&object_id) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        let component_refs = component_objects
            .iter()
            .filter_map(|object_id| flow_refs_by_object.get(object_id))
            .flat_map(|items| items.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if !component_refs.is_empty()
            && !object_flow_fact_refs_have_complete_chain(facts, &component_refs)
            && !object_flow_fact_refs_are_only_neutral_aliases(facts, &component_refs)
        {
            return true;
        }
    }

    false
}

fn has_incomplete_authoritative_object_flow_pair(
    facts: &[V326LifecycleFactRecord],
    first_token: &str,
    second_token: &str,
) -> bool {
    for tokens in authoritative_object_flow_component_tokens(facts) {
        if tokens.contains(first_token) ^ tokens.contains(second_token) {
            return true;
        }
    }
    false
}

fn has_unverified_authoritative_object_flow_pair(
    facts: &[V326LifecycleFactRecord],
    first_token: &str,
    second_token: &str,
) -> bool {
    authoritative_object_flow_component_fact_refs(facts)
        .into_iter()
        .any(|component_refs| {
            let tokens = object_flow_tokens_for_fact_refs(facts, &component_refs);
            tokens.contains(first_token)
                && tokens.contains(second_token)
                && !object_flow_fact_refs_have_compatible_pair(
                    facts,
                    &component_refs,
                    first_token,
                    second_token,
                )
        })
}

/// Reports whether any authoritative object-flow component captures a closure slot without a
/// matching closure-body load of that same slot.
///
/// This stays component-scoped and asymmetric on purpose. A candidate-global check would let one
/// unrelated verified chain silence the gap for every unbound capture in the same candidate, and
/// the symmetric [`has_incomplete_authoritative_object_flow_pair`] would misreport ordinary
/// `field_load`-only components that never captured anything.
fn has_incomplete_closure_capture_component(facts: &[V326LifecycleFactRecord]) -> bool {
    authoritative_object_flow_component_fact_refs(facts)
        .into_iter()
        .any(|component_refs| {
            let tokens = object_flow_tokens_for_fact_refs(facts, &component_refs);
            if !tokens.contains("closure_capture") {
                return false;
            }
            !tokens.contains("field_load")
                || !object_flow_fact_refs_have_compatible_pair(
                    facts,
                    &component_refs,
                    "closure_capture",
                    "field_load",
                )
        })
}

fn authoritative_object_flow_component_fact_refs(
    facts: &[V326LifecycleFactRecord],
) -> Vec<Vec<String>> {
    let object_flow_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ObjectFlow
                && is_authoritative_object_binding_fact(fact)
                && !object_flow_endpoint_is_ambiguous(fact, facts)
                && !object_flow_fact_is_neutral_alias(fact)
        })
        .collect::<Vec<_>>();
    let mut component_edges = BTreeMap::<String, BTreeSet<String>>::new();
    let mut flow_refs_by_object = BTreeMap::<String, BTreeSet<String>>::new();
    let mut standalone_refs = Vec::<Vec<String>>::new();

    for fact in &object_flow_facts {
        let endpoints = lifecycle_fact_endpoint_object_ids(fact)
            .into_iter()
            .collect::<Vec<_>>();
        if endpoints.is_empty() {
            standalone_refs.push(vec![fact.fact_id.clone()]);
            continue;
        }
        for endpoint in &endpoints {
            flow_refs_by_object
                .entry(endpoint.clone())
                .or_default()
                .insert(fact.fact_id.clone());
            component_edges.entry(endpoint.clone()).or_default();
        }
        if let Some(first) = endpoints.first() {
            for endpoint in endpoints.iter().skip(1) {
                component_edges
                    .entry(first.clone())
                    .or_default()
                    .insert(endpoint.clone());
                component_edges
                    .entry(endpoint.clone())
                    .or_default()
                    .insert(first.clone());
            }
        }
    }
    let barrier_binding_keys = object_binding_barrier_binding_keys(facts);
    connect_compatible_object_flow_sequence_components(
        &object_flow_facts,
        &mut component_edges,
        &barrier_binding_keys,
    );

    let mut components = standalone_refs;
    let mut visited = BTreeSet::<String>::new();
    for start in component_edges.keys().cloned().collect::<Vec<_>>() {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![start];
        let mut component_objects = BTreeSet::<String>::new();
        while let Some(object_id) = stack.pop() {
            if !visited.insert(object_id.clone()) {
                continue;
            }
            component_objects.insert(object_id.clone());
            if let Some(neighbors) = component_edges.get(&object_id) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        let refs = component_objects
            .iter()
            .filter_map(|object_id| flow_refs_by_object.get(object_id))
            .flat_map(|items| items.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if !refs.is_empty() {
            components.push(refs);
        }
    }

    components
}

fn object_flow_tokens_for_fact_refs(
    facts: &[V326LifecycleFactRecord],
    fact_refs: &[String],
) -> BTreeSet<String> {
    facts
        .iter()
        .filter(|fact| fact_refs.iter().any(|fact_ref| fact_ref == &fact.fact_id))
        .flat_map(object_flow_tokens_for_fact)
        .collect()
}

fn authoritative_object_flow_component_tokens(
    facts: &[V326LifecycleFactRecord],
) -> Vec<BTreeSet<String>> {
    let object_flow_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ObjectFlow
                && is_authoritative_object_binding_fact(fact)
                && !object_flow_endpoint_is_ambiguous(fact, facts)
                && !object_flow_fact_is_neutral_alias(fact)
        })
        .collect::<Vec<_>>();
    let mut component_edges = BTreeMap::<String, BTreeSet<String>>::new();
    let mut tokens_by_object = BTreeMap::<String, BTreeSet<String>>::new();
    let mut standalone_tokens = Vec::<BTreeSet<String>>::new();

    for fact in &object_flow_facts {
        let tokens = object_flow_tokens_for_fact(fact);
        let endpoints = lifecycle_fact_endpoint_object_ids(fact)
            .into_iter()
            .collect::<Vec<_>>();
        if endpoints.is_empty() {
            standalone_tokens.push(tokens);
            continue;
        }
        for endpoint in &endpoints {
            tokens_by_object
                .entry(endpoint.clone())
                .or_default()
                .extend(tokens.iter().cloned());
            component_edges.entry(endpoint.clone()).or_default();
        }
        if let Some(first) = endpoints.first() {
            for endpoint in endpoints.iter().skip(1) {
                component_edges
                    .entry(first.clone())
                    .or_default()
                    .insert(endpoint.clone());
                component_edges
                    .entry(endpoint.clone())
                    .or_default()
                    .insert(first.clone());
            }
        }
    }
    let barrier_binding_keys = object_binding_barrier_binding_keys(facts);
    connect_compatible_object_flow_sequence_components(
        &object_flow_facts,
        &mut component_edges,
        &barrier_binding_keys,
    );

    let mut components = standalone_tokens;
    let mut visited = BTreeSet::<String>::new();
    for start in component_edges.keys().cloned().collect::<Vec<_>>() {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![start];
        let mut tokens = BTreeSet::<String>::new();
        while let Some(object_id) = stack.pop() {
            if !visited.insert(object_id.clone()) {
                continue;
            }
            if let Some(object_tokens) = tokens_by_object.get(&object_id) {
                tokens.extend(object_tokens.iter().cloned());
            }
            if let Some(neighbors) = component_edges.get(&object_id) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        if !tokens.is_empty() {
            components.push(tokens);
        }
    }

    components
}

fn object_flow_tokens_for_fact(fact: &V326LifecycleFactRecord) -> BTreeSet<String> {
    fact.object_ids
        .iter()
        .filter_map(|object_id| object_id.strip_prefix("object_flow:"))
        .map(ToOwned::to_owned)
        .collect()
}

fn verified_object_chain_support_refs(
    facts: &[V326LifecycleFactRecord],
    object_flow_endpoints: &BTreeSet<String>,
) -> Vec<String> {
    let mut refs = facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact)
                && matches!(
                    fact.fact_kind,
                    V326LifecycleFactKind::RegisterCall
                        | V326LifecycleFactKind::UnregisterCall
                        | V326LifecycleFactKind::ReleaseCall
                        | V326LifecycleFactKind::ReleasePathProof
                        | V326LifecycleFactKind::RawPointerEscape
                        | V326LifecycleFactKind::ReturnedBorrowRelation
                        | V326LifecycleFactKind::PersistedReturnedBorrow
                        | V326LifecycleFactKind::ReturnedBorrowInvalidationOrder
                        | V326LifecycleFactKind::ExternalBufferBinding
                        | V326LifecycleFactKind::CallbackUserDataReconstruction
                        | V326LifecycleFactKind::CallbackReleaseUseOrder
                )
                && lifecycle_fact_endpoint_object_ids(fact)
                    .iter()
                    .any(|object_id| object_flow_endpoints.contains(object_id))
        })
        .map(|fact| fact.fact_id.clone())
        .collect::<Vec<_>>();
    refs.sort();
    refs.dedup();
    refs
}

fn release_order_chain_refs(facts: &[V326LifecycleFactRecord]) -> Vec<String> {
    let mut refs = BTreeSet::new();
    for (proof, register) in release_path_proof_register_pairs(facts) {
        refs.insert(proof.fact_id.clone());
        refs.insert(register.fact_id.clone());
        let proof_user_data = fact_user_data_object_ids(proof)
            .into_iter()
            .collect::<BTreeSet<_>>();
        refs.extend(
            facts
                .iter()
                .filter(|fact| {
                    is_authoritative_object_binding_fact(fact)
                        && release_path_proof_support_fact_matches(proof, fact, &proof_user_data)
                })
                .map(|fact| fact.fact_id.clone()),
        );
        refs.extend(release_path_proof_object_flow_support_refs(
            proof,
            facts,
            &proof_user_data,
        ));
    }
    refs.into_iter().collect()
}

fn persisted_invalidation_use_chain_refs(facts: &[V326LifecycleFactRecord]) -> Vec<String> {
    let relation_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ReturnedBorrowRelation
                && is_authoritative_object_binding_fact(fact)
        })
        .collect::<Vec<_>>();
    let persisted_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::PersistedReturnedBorrow
                && is_authoritative_object_binding_fact(fact)
        })
        .collect::<Vec<_>>();
    let order_facts = facts
        .iter()
        .filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::ReturnedBorrowInvalidationOrder
                && is_authoritative_object_binding_fact(fact)
        })
        .collect::<Vec<_>>();
    if relation_facts.is_empty() || persisted_facts.is_empty() || order_facts.is_empty() {
        return Vec::new();
    }
    let mut refs = BTreeSet::new();
    for relation in relation_facts {
        let Some(returned_ref) = first_fact_object_with_prefixes(relation, &["returned_ref:"])
        else {
            continue;
        };
        let Some(persisted) = persisted_facts.iter().find(|fact| {
            fact.object_ids
                .iter()
                .any(|object_id| object_id == &returned_ref)
        }) else {
            continue;
        };
        let order_refs = returned_borrow_order_refs_for_persisted(persisted, &order_facts);
        if order_refs.is_empty() {
            continue;
        }
        refs.insert(relation.fact_id.clone());
        refs.insert(persisted.fact_id.clone());
        refs.extend(order_refs);
    }
    refs.into_iter().collect()
}

fn callback_release_use_chain_refs(facts: &[V326LifecycleFactRecord]) -> Vec<String> {
    let mut refs = BTreeSet::new();
    for (proof, register) in release_path_proof_register_pairs(facts) {
        let proof_user_data = fact_user_data_object_ids(proof)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let callback_use_refs =
            release_path_proof_callback_use_support_refs(proof, facts, &proof_user_data);
        if callback_use_refs.is_empty() {
            continue;
        }
        refs.insert(proof.fact_id.clone());
        refs.insert(register.fact_id.clone());
        refs.extend(callback_use_refs);
        refs.extend(release_path_proof_object_flow_support_refs(
            proof,
            facts,
            &proof_user_data,
        ));
        refs.extend(
            facts
                .iter()
                .filter(|fact| {
                    is_authoritative_object_binding_fact(fact)
                        && release_path_proof_support_fact_matches(proof, fact, &proof_user_data)
                })
                .map(|fact| fact.fact_id.clone()),
        );
    }
    refs.into_iter().collect()
}

fn callback_release_use_same_object_support_exists(facts: &[V326LifecycleFactRecord]) -> bool {
    for (proof, _) in release_path_proof_register_pairs(facts) {
        let proof_user_data = fact_user_data_object_ids(proof)
            .into_iter()
            .collect::<BTreeSet<_>>();
        if proof_user_data.is_empty() {
            continue;
        }
        for reconstruction in facts.iter().filter(|fact| {
            fact.fact_kind == V326LifecycleFactKind::CallbackUserDataReconstruction
                && is_authoritative_object_binding_fact(fact)
        }) {
            let reconstruction_user_data = fact_user_data_object_ids(reconstruction)
                .into_iter()
                .collect::<BTreeSet<_>>();
            if reconstruction_user_data.is_empty() {
                continue;
            }
            let direct_same_object = reconstruction_user_data
                .iter()
                .any(|object_id| proof_user_data.contains(object_id));
            if direct_same_object
                || !object_flow_field_store_load_support_refs(
                    facts,
                    &proof_user_data,
                    &reconstruction_user_data,
                )
                .is_empty()
            {
                return true;
            }
        }
    }
    false
}

fn append_feature_incomplete_reasons(
    features: &V326FeatureSet,
    facts: &[V326LifecycleFactRecord],
    missing_evidence: &mut Vec<String>,
) {
    let mut reasons = Vec::new();
    if !features.has_verified_object_chain
        && !has_authoritative_partial_object_chain_evidence(facts)
        && facts
            .iter()
            .any(|fact| is_authoritative_object_binding_fact(fact))
    {
        reasons.push("object_flow_missing");
    }
    if (features.has_foreign_register || features.has_foreign_unregister)
        && !features.has_release_order_chain
    {
        reasons.push("release_order_proof_missing");
    }
    if (features.has_returned_borrow_relation || features.has_persisted_returned_borrow)
        && !features.has_persisted_invalidation_use_chain
    {
        reasons.push("use_ordering_proof_missing");
    }
    if features.has_external_buffer_binding && !features.has_verified_object_chain {
        reasons.push("complete_risk_chain_missing");
    }
    let has_callback_user_data_use = facts.iter().any(|fact| {
        fact.fact_kind == V326LifecycleFactKind::CallbackUserDataReconstruction
            && is_authoritative_object_binding_fact(fact)
    });
    if has_callback_user_data_use
        && features.has_release_order_chain
        && !features.has_callback_release_use_chain
    {
        if callback_release_use_same_object_support_exists(facts) {
            reasons.push("use_ordering_proof_missing");
        } else {
            reasons.push("callback_release_use_object_flow_missing");
        }
    }
    if has_ambiguous_object_flow_binding(facts) {
        reasons.push("object_binding_ambiguous");
    }
    if has_incomplete_authoritative_object_flow_component(facts) {
        reasons.push("object_flow_counterpart_missing");
    }
    if has_incomplete_authoritative_object_flow_pair(facts, "argument", "return_value") {
        reasons.push("call_boundary_binding_missing");
    }
    if has_incomplete_authoritative_object_flow_pair(facts, "field_store", "field_load")
        || has_unverified_authoritative_object_flow_pair(facts, "field_store", "field_load")
    {
        reasons.push("field_binding_missing");
    }
    if (has_incomplete_authoritative_object_flow_pair(facts, "wrapper_move", "wrapper_destructure")
        || has_unverified_authoritative_object_flow_pair(
            facts,
            "wrapper_move",
            "wrapper_destructure",
        ))
        && !features.has_release_order_chain
    {
        reasons.push("wrapper_binding_missing");
    }
    if has_incomplete_authoritative_object_flow_pair(facts, "collection_store", "collection_load")
        || has_unverified_authoritative_object_flow_pair(
            facts,
            "collection_store",
            "collection_load",
        )
    {
        reasons.push("collection_binding_missing");
    }
    if has_incomplete_closure_capture_component(facts) {
        reasons.push("closure_binding_missing");
    }
    append_object_binding_gap_reasons(facts, missing_evidence);
    for reason in reasons {
        if !missing_evidence.iter().any(|item| item == reason) {
            missing_evidence.push(reason.to_owned());
        }
    }
}

fn has_authoritative_partial_object_chain_evidence(facts: &[V326LifecycleFactRecord]) -> bool {
    facts.iter().any(|fact| {
        is_authoritative_object_binding_fact(fact)
            && matches!(
                fact.fact_kind,
                V326LifecycleFactKind::ReturnedBorrowRelation
                    | V326LifecycleFactKind::PersistedReturnedBorrow
                    | V326LifecycleFactKind::ExternalBufferBinding
                    | V326LifecycleFactKind::ObjectFlow
            )
            && lifecycle_fact_endpoint_object_ids(fact).len() >= 2
    })
}

fn authoritative_raw_parts_transfer_refs(facts: &[V326LifecycleFactRecord]) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact)
                && fact.fact_kind == V326LifecycleFactKind::RawPointerEscape
                && fact
                    .symbol_path
                    .as_deref()
                    .is_some_and(|symbol| symbol.ends_with("from_raw_parts"))
        })
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn manual_drop_prevention_without_drop_guard_refs(
    facts: &[V326LifecycleFactRecord],
) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact)
                && fact.fact_kind == V326LifecycleFactKind::DropPrevention
                && fact
                    .symbol_path
                    .as_deref()
                    .is_some_and(|symbol| symbol.ends_with("memforget"))
                && wrapper_destructure_drop_prevention_fact(fact, facts)
                && !matching_drop_guard_fact(fact, facts)
        })
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn matching_drop_guard_fact(
    drop_prevention: &V326LifecycleFactRecord,
    facts: &[V326LifecycleFactRecord],
) -> bool {
    facts.iter().any(|fact| {
        is_authoritative_object_binding_fact(fact)
            && fact.fact_kind == V326LifecycleFactKind::DropSite
            && facts_share_lifecycle_object(drop_prevention, fact)
    })
}

fn wrapper_destructure_drop_prevention_fact(
    drop_fact: &V326LifecycleFactRecord,
    facts: &[V326LifecycleFactRecord],
) -> bool {
    let method_is_wrapper_destructure = drop_fact
        .source_ref
        .symbol_path
        .as_deref()
        .map(source_api_symbol_tails)
        .is_some_and(|tails| {
            tails
                .iter()
                .any(|tail| matches!(tail.as_str(), "into_inner" | "into_parts" | "take_inner"))
        });
    if !method_is_wrapper_destructure {
        return false;
    }

    facts.iter().any(|fact| {
        is_authoritative_object_binding_fact(fact)
            && fact.fact_kind == V326LifecycleFactKind::OwnedMoveCapture
            && facts_share_lifecycle_object(drop_fact, fact)
            && fact
                .symbol_path
                .as_deref()
                .is_some_and(wrapper_owned_anchor_type)
    })
}

fn wrapper_owned_anchor_type(type_name: &str) -> bool {
    let trimmed = type_name.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("core::option::option<")
        || lower.starts_with("std::option::option<")
        || lower.starts_with("core::result::result<")
        || lower.starts_with("std::result::result<")
        || lower == "()"
    {
        return false;
    }

    trimmed.contains('<') && trimmed.contains('>')
}

fn facts_share_lifecycle_object(
    left: &V326LifecycleFactRecord,
    right: &V326LifecycleFactRecord,
) -> bool {
    left.object_ids
        .iter()
        .any(|left_id| right.object_ids.iter().any(|right_id| right_id == left_id))
}

fn authoritative_callback_user_data_reconstruction_refs(
    facts: &[V326LifecycleFactRecord],
    reconstruction_token: &str,
) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact)
                && fact.fact_kind == V326LifecycleFactKind::CallbackUserDataReconstruction
                && fact.symbol_path.as_deref().is_some_and(|symbol| {
                    symbol.to_ascii_lowercase().ends_with(reconstruction_token)
                })
        })
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn verified_callback_user_data_reconstruction_refs(
    facts: &[V326LifecycleFactRecord],
    reconstruction_token: &str,
) -> Vec<String> {
    let verified_chain_refs = verified_object_chain_refs(facts)
        .into_iter()
        .collect::<BTreeSet<_>>();
    authoritative_callback_user_data_reconstruction_refs(facts, reconstruction_token)
        .into_iter()
        .filter(|fact_ref| verified_chain_refs.contains(fact_ref))
        .collect()
}

fn authoritative_returned_borrow_order_refs(
    facts: &[V326LifecycleFactRecord],
    ordering_token: &str,
) -> Vec<String> {
    let object_id = format!("returned_borrow_order:{ordering_token}");
    facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact)
                && fact.fact_kind == V326LifecycleFactKind::ReturnedBorrowInvalidationOrder
                && fact.object_ids.iter().any(|item| item == &object_id)
        })
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn authoritative_verified_returned_borrow_order_refs(
    facts: &[V326LifecycleFactRecord],
    ordering_token: &str,
) -> Vec<String> {
    let verified_chain_refs = persisted_invalidation_use_chain_refs(facts)
        .into_iter()
        .collect::<BTreeSet<_>>();
    authoritative_returned_borrow_order_refs(facts, ordering_token)
        .into_iter()
        .filter(|fact_ref| verified_chain_refs.contains(fact_ref))
        .collect()
}

fn authoritative_unconstrained_return_lifetime_refs(
    facts: &[V326LifecycleFactRecord],
) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact)
                && fact.fact_kind == V326LifecycleFactKind::ReturnedBorrowRelation
                && fact.object_ids.iter().any(|item| {
                    item == "static_site:returned_borrow_relation_kind:unconstrained_return_lifetime"
                })
        })
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn authoritative_atomic_ordering_refs(
    facts: &[V326LifecycleFactRecord],
    ordering_token: &str,
) -> Vec<String> {
    let ordering_object_id = format!("atomic_ordering:{ordering_token}");
    facts
        .iter()
        .filter(|fact| {
            is_authoritative_object_binding_fact(fact)
                && fact.fact_kind == V326LifecycleFactKind::AtomicOrdering
                && fact
                    .object_ids
                    .iter()
                    .any(|item| item == "atomic_operation:load")
                && fact
                    .object_ids
                    .iter()
                    .any(|item| item == &ordering_object_id)
                && lifecycle_static_atomic_symbol_is_iterator_scoped(fact)
        })
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn lifecycle_static_atomic_symbol_is_iterator_scoped(fact: &V326LifecycleFactRecord) -> bool {
    let identity = [
        fact.symbol_path.as_deref(),
        fact.source_ref.symbol_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("::")
    .to_ascii_lowercase();
    !identity.is_empty()
        && (identity.contains("iterator")
            || identity.contains("intoiter")
            || identity.contains("rawiter")
            || identity.contains("thread_local")
            || identity.contains("get_or_try")
            || identity.ends_with("::next")
            || identity.contains("::next::"))
}

fn release_coverage_refs(
    evidence: &[V326LifecycleEvidenceRecord],
    facts: &[V326LifecycleFactRecord],
) -> Vec<String> {
    let mut refs = refs_for(evidence, V326EvidenceKind::ForeignRegister);
    refs.extend(refs_for(evidence, V326EvidenceKind::ForeignUnregister));
    refs.extend(refs_for(evidence, V326EvidenceKind::ReleaseSite));
    refs.extend(refs_for(evidence, V326EvidenceKind::DropGuard));
    refs.extend(refs_for(evidence, V326EvidenceKind::DropSite));
    refs.extend(
        facts
            .iter()
            .filter(|fact| {
                matches!(
                    fact.fact_kind,
                    V326LifecycleFactKind::RegisterCall | V326LifecycleFactKind::ReleasePathProof
                )
            })
            .map(|fact| fact.fact_id.clone()),
    );
    refs.sort();
    refs.dedup();
    refs
}

fn evidence_has_after_register_order(item: &V326LifecycleEvidenceRecord) -> bool {
    ["ordering", "order", "happens_after", "sequence"]
        .iter()
        .filter_map(|key| item.details.get(*key))
        .filter_map(serde_json::Value::as_str)
        .any(|value| {
            let value = value.to_ascii_lowercase();
            value == "after_register"
                || value == "register_then_release"
                || value == "after_registration"
                || value.contains("after register")
        })
}

fn ordering_from_evidence(item: &V326LifecycleEvidenceRecord) -> V326LifecycleOrdering {
    if evidence_has_after_register_order(item) {
        return V326LifecycleOrdering::After;
    }
    ["ordering", "order", "sequence"]
        .iter()
        .filter_map(|key| item.details.get(*key))
        .filter_map(serde_json::Value::as_str)
        .find_map(|value| match value.to_ascii_lowercase().as_str() {
            "before" | "before_register" => Some(V326LifecycleOrdering::Before),
            "same_site" | "same" => Some(V326LifecycleOrdering::SameSite),
            _ => None,
        })
        .unwrap_or(V326LifecycleOrdering::Unknown)
}

fn fact_user_data_object_ids(item: &V326LifecycleFactRecord) -> Vec<String> {
    item.object_ids
        .iter()
        .filter(|object_id| {
            let lower = object_id.to_ascii_lowercase();
            lower.starts_with("user_data:") || lower.starts_with("userdata:")
        })
        .cloned()
        .collect()
}

fn append_authoritative_fact_edges(
    objects: &mut BTreeMap<String, V326LifecycleObject>,
    edges: &mut Vec<V326LifecycleGraphV3Edge>,
    foreign_owner_id: &str,
    facts: &[V326LifecycleFactRecord],
) {
    let mut used_fact_refs = edges
        .iter()
        .flat_map(|edge| edge.fact_refs.iter().cloned())
        .collect::<BTreeSet<_>>();
    for fact in facts {
        if used_fact_refs.contains(&fact.fact_id) {
            continue;
        }
        let Some((from_object_id, to_object_id, relation, ordering, label)) =
            fact_edge_shape(fact, foreign_owner_id, objects)
        else {
            continue;
        };
        edges.push(V326LifecycleGraphV3Edge {
            edge_id: format!(
                "edge:{}:{}",
                sanitize_id_for_path(&fact.fact_id),
                lifecycle_relation_token(relation)
            ),
            from_object_id,
            to_object_id,
            relation,
            ordering,
            evidence_refs: fact.evidence_refs.clone(),
            fact_refs: vec![fact.fact_id.clone()],
        });
        used_fact_refs.insert(fact.fact_id.clone());
        if let Some((object_id, object_kind, object_label)) = label {
            add_object(
                objects,
                object_id,
                object_kind,
                object_label,
                Some(fact.source_ref.clone()),
                vec![fact.fact_id.clone()],
            );
        }
    }
}

type FactEdgeShape = (
    String,
    String,
    V326LifecycleRelation,
    V326LifecycleOrdering,
    Option<(String, V326LifecycleObjectKind, String)>,
);

fn fact_edge_shape(
    fact: &V326LifecycleFactRecord,
    foreign_owner_id: &str,
    objects: &mut BTreeMap<String, V326LifecycleObject>,
) -> Option<FactEdgeShape> {
    match fact.fact_kind {
        V326LifecycleFactKind::RegisterCall => {
            let from = first_fact_object_with_prefixes(fact, &["callback:", "user_data:"])?;
            Some((
                from,
                foreign_owner_id.to_owned(),
                V326LifecycleRelation::Register,
                V326LifecycleOrdering::SameSite,
                None,
            ))
        }
        V326LifecycleFactKind::ReplaceCall => {
            let from = first_fact_object_with_prefixes(fact, &["callback:", "user_data:"])?;
            Some((
                from,
                foreign_owner_id.to_owned(),
                V326LifecycleRelation::Replace,
                V326LifecycleOrdering::SameSite,
                None,
            ))
        }
        V326LifecycleFactKind::UnregisterCall | V326LifecycleFactKind::ReleaseCall => {
            let from = first_fact_object_with_prefixes(fact, &["callback:", "user_data:"])?;
            let release_id = first_fact_object_with_prefixes(fact, &["release_endpoint:"])
                .unwrap_or_else(|| {
                    release_endpoint_object_for_fact(objects, fact, "release endpoint")
                });
            Some((
                from,
                release_id,
                V326LifecycleRelation::Release,
                V326LifecycleOrdering::Unknown,
                None,
            ))
        }
        V326LifecycleFactKind::ReleasePathProof => {
            let from = first_fact_object_with_prefixes(fact, &["user_data:", "callback:"])?;
            let release_id = first_fact_object_with_prefixes(fact, &["release_endpoint:"])
                .unwrap_or_else(|| {
                    release_endpoint_object_for_fact(objects, fact, "release path proof endpoint")
                });
            Some((
                from,
                release_id,
                V326LifecycleRelation::Release,
                V326LifecycleOrdering::After,
                None,
            ))
        }
        V326LifecycleFactKind::BorrowedCapture => {
            let from = first_fact_object_with_prefixes(fact, &["rust_owner:"])?;
            let to = first_fact_object_with_prefixes(fact, &["callback:"])?;
            Some((
                from,
                to,
                V326LifecycleRelation::Borrow,
                V326LifecycleOrdering::SameSite,
                None,
            ))
        }
        V326LifecycleFactKind::OwnedMoveCapture => {
            let from = first_fact_object_with_prefixes(fact, &["rust_owner:"])?;
            let to = first_fact_object_with_prefixes(fact, &["callback:"])?;
            Some((
                from,
                to,
                V326LifecycleRelation::Move,
                V326LifecycleOrdering::SameSite,
                None,
            ))
        }
        V326LifecycleFactKind::DropImpl | V326LifecycleFactKind::DropSite => {
            let from = first_fact_object_with_prefixes(fact, &["rust_owner:"])?;
            let drop_id = release_endpoint_object_for_fact(objects, fact, "drop endpoint");
            Some((
                from,
                drop_id,
                V326LifecycleRelation::Drop,
                V326LifecycleOrdering::Unknown,
                None,
            ))
        }
        V326LifecycleFactKind::CallbackUserDataReconstruction => {
            let from = first_fact_object_with_prefixes(fact, &["user_data:"])?;
            let to = first_fact_object_with_prefixes(fact, &["rust_owner:"])?;
            Some((
                from,
                to,
                V326LifecycleRelation::Use,
                V326LifecycleOrdering::SameSite,
                None,
            ))
        }
        V326LifecycleFactKind::CallbackReleaseUseOrder => {
            let from = first_fact_object_with_prefixes(fact, &["release_endpoint:"])?;
            let to = callback_release_use_order_use_static_site(fact)?;
            Some((
                from,
                to,
                V326LifecycleRelation::Use,
                callback_release_use_ordering_for_edge(fact),
                None,
            ))
        }
        V326LifecycleFactKind::RawPointerEscape => {
            let from = first_fact_object_with_prefixes(fact, &["user_data:"])?;
            Some((
                from,
                foreign_owner_id.to_owned(),
                V326LifecycleRelation::RawEscape,
                V326LifecycleOrdering::SameSite,
                None,
            ))
        }
        V326LifecycleFactKind::ReturnedBorrowRelation => {
            let from = first_fact_object_with_prefixes(fact, &["rust_owner:"])?;
            let to = first_fact_object_with_prefixes(fact, &["returned_ref:"])?;
            Some((
                from,
                to,
                V326LifecycleRelation::Borrow,
                V326LifecycleOrdering::SameSite,
                None,
            ))
        }
        V326LifecycleFactKind::PersistedReturnedBorrow => {
            let from = first_fact_object_with_prefixes(fact, &["returned_ref:"])?;
            let to = first_fact_object_with_prefixes(fact, &["storage:"])?;
            Some((
                from,
                to,
                V326LifecycleRelation::Persist,
                V326LifecycleOrdering::SameSite,
                None,
            ))
        }
        V326LifecycleFactKind::ReturnedBorrowInvalidationOrder => {
            returned_borrow_order_edge_shape(fact)
        }
        V326LifecycleFactKind::ExternalBufferBinding => {
            let from = first_fact_object_with_prefixes(fact, &["rust_owner:"])?;
            let to = first_fact_object_with_prefixes(fact, &["user_data:"])?;
            Some((
                from,
                to,
                V326LifecycleRelation::RawEscape,
                V326LifecycleOrdering::SameSite,
                None,
            ))
        }
        V326LifecycleFactKind::ObjectFlow => object_flow_edge_shape(fact),
        V326LifecycleFactKind::CallbackDefinition
        | V326LifecycleFactKind::ObjectBindingGap
        | V326LifecycleFactKind::DropPrevention
        | V326LifecycleFactKind::AtomicOrdering
        | V326LifecycleFactKind::UnsafeCast
        | V326LifecycleFactKind::TraitImpl
        | V326LifecycleFactKind::ContractRetention => None,
    }
}

fn callback_release_use_order_use_static_site(fact: &V326LifecycleFactRecord) -> Option<String> {
    if fact.fact_kind != V326LifecycleFactKind::CallbackReleaseUseOrder {
        return None;
    }
    fact.object_ids
        .iter()
        .filter(|object_id| object_id.starts_with("static_site:"))
        .nth(1)
        .cloned()
}

fn callback_release_use_ordering_for_edge(fact: &V326LifecycleFactRecord) -> V326LifecycleOrdering {
    if fact
        .object_ids
        .iter()
        .any(|object_id| object_id == "callback_release_use_order:release_before_callback_use")
    {
        V326LifecycleOrdering::After
    } else if fact
        .object_ids
        .iter()
        .any(|object_id| object_id == "callback_release_use_order:callback_use_before_release")
    {
        V326LifecycleOrdering::Before
    } else {
        V326LifecycleOrdering::Unknown
    }
}

fn object_flow_edge_shape(fact: &V326LifecycleFactRecord) -> Option<FactEdgeShape> {
    let flow_kind = object_flow_kind_from_fact(fact)?;
    let from = first_object_flow_endpoint(fact, true)?;
    let to = first_object_flow_endpoint(fact, false)?;
    Some((
        from,
        to,
        relation_from_object_flow_kind(flow_kind),
        V326LifecycleOrdering::SameSite,
        None,
    ))
}

fn object_flow_kind_from_fact(fact: &V326LifecycleFactRecord) -> Option<&str> {
    fact.object_ids
        .iter()
        .find_map(|object_id| object_id.strip_prefix("object_flow:"))
}

fn first_object_flow_endpoint(
    fact: &V326LifecycleFactRecord,
    first_endpoint: bool,
) -> Option<String> {
    object_flow_endpoint_object_ids_in_order(fact)
        .into_iter()
        .nth(usize::from(!first_endpoint))
}

fn object_flow_auxiliary_object_id(object_id: &str) -> bool {
    object_id.starts_with("static_site:")
        || object_id.starts_with("object_flow:")
        || object_id.starts_with("object_flow_binding:")
        || object_id.starts_with("object_flow_binding_member:")
        || object_id.starts_with("object_flow_binding_prefix:")
        || object_id.starts_with("object_flow_binding_kind:")
        || object_id.starts_with("callback_release_use_order:")
}

fn relation_from_object_flow_kind(flow_kind: &str) -> V326LifecycleRelation {
    match flow_kind {
        "field_store" | "collection_store" => V326LifecycleRelation::Persist,
        "closure_capture" => V326LifecycleRelation::Borrow,
        "field_load"
        | "collection_load"
        | "wrapper_destructure"
        | "wrapper_move"
        | "argument"
        | "return_value" => V326LifecycleRelation::Move,
        _ => V326LifecycleRelation::Move,
    }
}

fn returned_borrow_order_edge_shape(fact: &V326LifecycleFactRecord) -> Option<FactEdgeShape> {
    let persisted = first_fact_object_with_prefixes(fact, &["static_site:"])?;
    let static_sites = fact
        .object_ids
        .iter()
        .filter(|object_id| object_id.starts_with("static_site:"))
        .cloned()
        .collect::<Vec<_>>();
    let invalidation = static_sites.get(1)?.clone();
    let use_site = static_sites.get(2)?.clone();
    let invalidation_before_use = fact
        .object_ids
        .iter()
        .any(|object_id| object_id == "returned_borrow_order:invalidation_before_persistence_use");
    let (from, to, relation) = if invalidation_before_use {
        (invalidation, use_site, V326LifecycleRelation::Use)
    } else {
        (persisted, invalidation, V326LifecycleRelation::Invalidate)
    };
    Some((from, to, relation, V326LifecycleOrdering::Before, None))
}

fn first_fact_object_with_prefixes(
    fact: &V326LifecycleFactRecord,
    prefixes: &[&str],
) -> Option<String> {
    prefixes.iter().find_map(|prefix| {
        fact.object_ids
            .iter()
            .find(|object_id| object_id.starts_with(prefix))
            .cloned()
    })
}

fn release_endpoint_object_for_fact(
    objects: &mut BTreeMap<String, V326LifecycleObject>,
    fact: &V326LifecycleFactRecord,
    label: &str,
) -> String {
    let object_id = format!("release_endpoint:{}", sanitize_id_for_path(&fact.fact_id));
    add_object(
        objects,
        object_id.clone(),
        V326LifecycleObjectKind::ReleaseEndpoint,
        label.to_owned(),
        Some(fact.source_ref.clone()),
        vec![fact.fact_id.clone()],
    );
    object_id
}

fn lifecycle_relation_token(relation: V326LifecycleRelation) -> &'static str {
    match relation {
        V326LifecycleRelation::Register => "register",
        V326LifecycleRelation::Retain => "retain",
        V326LifecycleRelation::Replace => "replace",
        V326LifecycleRelation::Release => "release",
        V326LifecycleRelation::Drop => "drop",
        V326LifecycleRelation::Borrow => "borrow",
        V326LifecycleRelation::Persist => "persist",
        V326LifecycleRelation::Invalidate => "invalidate",
        V326LifecycleRelation::Use => "use",
        V326LifecycleRelation::Move => "move",
        V326LifecycleRelation::RawEscape => "raw_escape",
        V326LifecycleRelation::CallbackTrigger => "callback_trigger",
    }
}

fn candidate_requires_foreign_contract(
    candidate: &crate::V32CandidateRecord,
    evidence: &[V326LifecycleEvidenceRecord],
) -> bool {
    has_evidence(evidence, V326EvidenceKind::ForeignRegister)
        || has_evidence(evidence, V326EvidenceKind::ForeignRetentionHint)
        || matches!(
            candidate.pattern_family,
            V32PatternFamily::RetainedBorrowedCallback
                | V32PatternFamily::CallbackLifecycleRelease
                | V32PatternFamily::ExternalBufferView
        )
}

fn add_object(
    objects: &mut BTreeMap<String, V326LifecycleObject>,
    object_id: String,
    object_kind: V326LifecycleObjectKind,
    label: String,
    source_ref: Option<V326SourceRef>,
    fact_refs: Vec<String>,
) {
    objects
        .entry(object_id.clone())
        .and_modify(|object| {
            if object.source_ref.is_none() {
                object.source_ref = source_ref.clone();
            }
            for fact_ref in &fact_refs {
                if !object.fact_refs.contains(fact_ref) {
                    object.fact_refs.push(fact_ref.clone());
                }
            }
        })
        .or_insert(V326LifecycleObject {
            object_id,
            object_kind,
            label,
            source_ref,
            fact_refs,
        });
}

fn object_kind_from_id(object_id: &str) -> V326LifecycleObjectKind {
    let lower = object_id.to_ascii_lowercase();
    if lower.starts_with("callback:") {
        V326LifecycleObjectKind::Callback
    } else if lower.starts_with("user_data:") || lower.starts_with("userdata:") {
        V326LifecycleObjectKind::UserData
    } else if lower.starts_with("rust_owner:") || lower.starts_with("owner:") {
        V326LifecycleObjectKind::RustOwner
    } else if lower.starts_with("returned_ref:") {
        V326LifecycleObjectKind::ReturnedRef
    } else if lower.starts_with("storage:") {
        V326LifecycleObjectKind::Storage
    } else if lower.starts_with("opaque_handle:") {
        V326LifecycleObjectKind::OpaqueHandle
    } else if lower.starts_with("static_site:")
        || lower.starts_with("object_flow:")
        || lower.starts_with("object_flow_binding:")
        || lower.starts_with("object_flow_binding_member:")
        || lower.starts_with("object_flow_binding_prefix:")
        || lower.starts_with("object_binding_gap:")
        || lower.starts_with("adapter:")
        || lower.starts_with("atomic_operation:")
        || lower.starts_with("atomic_ordering:")
    {
        V326LifecycleObjectKind::StaticSite
    } else if lower.starts_with("foreign_owner:") {
        V326LifecycleObjectKind::ForeignOwner
    } else if lower.starts_with("release_endpoint:") || lower.starts_with("release:") {
        V326LifecycleObjectKind::ReleaseEndpoint
    } else if lower.starts_with("opaque:") || lower.starts_with("handle:") {
        V326LifecycleObjectKind::OpaqueHandle
    } else {
        V326LifecycleObjectKind::Unknown
    }
}

fn callback_object_id_for_evidence(
    objects: &mut BTreeMap<String, V326LifecycleObject>,
    item: &V326LifecycleEvidenceRecord,
    facts: &[V326LifecycleFactRecord],
    kinds: &[V326LifecycleFactKind],
) -> String {
    object_id_for_evidence_with_prefix_or_observation(
        objects,
        item,
        facts,
        kinds,
        "callback:",
        "callback",
        "callback object",
    )
}

fn object_id_for_evidence_with_prefix_or_observation(
    objects: &mut BTreeMap<String, V326LifecycleObject>,
    item: &V326LifecycleEvidenceRecord,
    facts: &[V326LifecycleFactRecord],
    kinds: &[V326LifecycleFactKind],
    prefix: &str,
    observation_role: &str,
    observation_label: &str,
) -> String {
    if let Some(object_id) = optional_object_id_for_evidence_with_prefix(item, facts, kinds, prefix)
    {
        return object_id;
    }

    let object_id = observation_object_id(observation_role, &item.record_id);
    add_object(
        objects,
        object_id.clone(),
        V326LifecycleObjectKind::Unknown,
        format!("{observation_label} binding unproven"),
        Some(item.source_ref.clone()),
        Vec::new(),
    );
    object_id
}

fn optional_object_id_for_evidence_with_prefix(
    item: &V326LifecycleEvidenceRecord,
    facts: &[V326LifecycleFactRecord],
    kinds: &[V326LifecycleFactKind],
    prefix: &str,
) -> Option<String> {
    let ids = facts
        .iter()
        .filter(|fact| {
            kinds.contains(&fact.fact_kind) && authoritative_fact_matches_evidence(fact, item)
        })
        .flat_map(|fact| fact.object_ids.iter())
        .filter(|object_id| object_id.starts_with(prefix))
        .cloned()
        .collect::<BTreeSet<_>>();
    (ids.len() == 1).then(|| ids.into_iter().next().expect("single binding id exists"))
}

fn authoritative_fact_matches_evidence(
    fact: &V326LifecycleFactRecord,
    evidence: &V326LifecycleEvidenceRecord,
) -> bool {
    is_authoritative_object_binding_fact(fact)
        && (fact
            .evidence_refs
            .iter()
            .any(|reference| reference == &evidence.record_id)
            || exact_source_ref_match(&fact.source_ref, &evidence.source_ref))
}

fn exact_source_ref_match(left: &V326SourceRef, right: &V326SourceRef) -> bool {
    left.path == right.path
        && left.line_start.is_some()
        && left.line_start == right.line_start
        && left.line_end == right.line_end
}

fn observation_object_id(role: &str, record_id: &str) -> String {
    format!("observation:{role}:{}", sanitize_id_for_path(record_id))
}

fn fact_refs_for_kind_on_object(
    facts: &[V326LifecycleFactRecord],
    evidence: &V326LifecycleEvidenceRecord,
    kind: V326LifecycleFactKind,
    object_id: &str,
) -> Vec<String> {
    fact_refs_for_any_kind_on_object(facts, evidence, &[kind], object_id)
}

fn fact_refs_for_any_kind_on_object(
    facts: &[V326LifecycleFactRecord],
    evidence: &V326LifecycleEvidenceRecord,
    kinds: &[V326LifecycleFactKind],
    object_id: &str,
) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| kinds.contains(&fact.fact_kind))
        .filter(|fact| authoritative_fact_matches_evidence(fact, evidence))
        .filter(|fact| fact.object_ids.iter().any(|item| item == object_id))
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn fact_refs_for_any_kind_on_objects(
    facts: &[V326LifecycleFactRecord],
    evidence: &V326LifecycleEvidenceRecord,
    kinds: &[V326LifecycleFactKind],
    object_ids: &[String],
) -> Vec<String> {
    facts
        .iter()
        .filter(|fact| kinds.contains(&fact.fact_kind))
        .filter(|fact| authoritative_fact_matches_evidence(fact, evidence))
        .filter(|fact| {
            fact.object_ids
                .iter()
                .any(|item| object_ids.iter().any(|object_id| object_id == item))
        })
        .map(|fact| fact.fact_id.clone())
        .collect()
}

fn set_feature(
    target: &mut bool,
    feature_evidence: &mut BTreeMap<String, Vec<String>>,
    name: &str,
    active: bool,
    refs: &[String],
) {
    *target = active;
    if active {
        feature_evidence.insert(name.to_owned(), refs.to_vec());
    }
}

fn sanitize_id_for_path(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn fact_kind_requires_object_id(kind: V326LifecycleFactKind) -> bool {
    !matches!(kind, V326LifecycleFactKind::TraitImpl)
}

fn validate_required_text_loc<T>(
    located: &Located<T>,
    code: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at_loc(located, code, format!("{field} 不能为空")));
    }
    Ok(())
}

fn validate_public_string_list<T>(
    located: &Located<T>,
    code: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), ModelError> {
    for value in values {
        if value.trim().is_empty() {
            return Err(at_loc(located, code, format!("{field} 不能包含空字符串")));
        }
        reject_private_tokens_loc(located, code, field, value)?;
    }
    Ok(())
}

fn validate_lifecycle_fact_provenance<T>(
    located: &Located<T>,
    provenance: &V326LifecycleFactProvenance,
) -> Result<(), ModelError> {
    let static_fields = [
        (
            "provenance.static_fact_record_id",
            &provenance.static_fact_record_id,
        ),
        ("provenance.static_build_id", &provenance.static_build_id),
        ("provenance.static_producer", &provenance.static_producer),
    ];
    match provenance.origin {
        V326LifecycleFactOrigin::Legacy => {
            return Err(at_loc(
                located,
                "BW-V326-FACT-PROVENANCE",
                "v3.2.6.lifecycle_fact.1 不接受 provenance.origin=legacy；请使用 source_observation 或 static_artifact",
            ));
        }
        V326LifecycleFactOrigin::SourceObservation => {
            if static_fields.iter().any(|(_, value)| value.is_some())
                || !provenance.static_anchor_record_ids.is_empty()
            {
                return Err(at_loc(
                    located,
                    "BW-V326-FACT-PROVENANCE",
                    "source_observation provenance 不能携带 static artifact 字段",
                ));
            }
        }
        V326LifecycleFactOrigin::StaticArtifact => {
            for (field, value) in static_fields {
                let Some(value) = value else {
                    return Err(at_loc(
                        located,
                        "BW-V326-FACT-PROVENANCE",
                        format!("{field} 对 static_artifact provenance 为必填"),
                    ));
                };
                validate_required_text_loc(located, "BW-V326-FACT-PROVENANCE", field, value)?;
                reject_private_tokens_loc(located, "BW-V326-FACT-PRIVATE-TOKEN", field, value)?;
            }
            if provenance.static_anchor_record_ids.is_empty() {
                return Err(at_loc(
                    located,
                    "BW-V326-FACT-PROVENANCE",
                    "static_artifact provenance 必须包含候选锚点 static_anchor_record_ids",
                ));
            }
            validate_public_string_list(
                located,
                "BW-V326-FACT-PRIVATE-TOKEN",
                "provenance.static_anchor_record_ids",
                &provenance.static_anchor_record_ids,
            )?;
            let unique_anchor_ids = provenance
                .static_anchor_record_ids
                .iter()
                .collect::<BTreeSet<_>>();
            if unique_anchor_ids.len() != provenance.static_anchor_record_ids.len() {
                return Err(at_loc(
                    located,
                    "BW-V326-FACT-PROVENANCE",
                    "provenance.static_anchor_record_ids 不能重复",
                ));
            }
        }
    }
    Ok(())
}

fn validate_lifecycle_fact_object_ids<T>(
    located: &Located<T>,
    record: &V326LifecycleFactRecord,
) -> Result<(), ModelError> {
    match record.provenance.origin {
        V326LifecycleFactOrigin::SourceObservation | V326LifecycleFactOrigin::Legacy => {
            for object_id in &record.object_ids {
                if !object_id.starts_with("source_evidence:") {
                    return Err(at_loc(
                        located,
                        "BW-V326-FACT-OBJECT-ID",
                        format!(
                            "source_observation object_ids 只能使用 source_evidence:*，拒绝: {object_id}"
                        ),
                    ));
                }
            }
        }
        V326LifecycleFactOrigin::StaticArtifact => {
            for object_id in &record.object_ids {
                let allowed = object_id.starts_with("callback:")
                    || object_id.starts_with("rust_owner:")
                    || object_id.starts_with("returned_ref:")
                    || object_id.starts_with("storage:")
                    || object_id.starts_with("opaque_handle:")
                    || object_id.starts_with("returned_borrow_order:")
                    || object_id.starts_with("object_flow:")
                    || object_id.starts_with("object_flow_binding:")
                    || object_id.starts_with("object_flow_binding_member:")
                    || object_id.starts_with("object_flow_binding_prefix:")
                    || object_id.starts_with("object_binding_gap:")
                    || object_id.starts_with("adapter:")
                    || object_id.starts_with("atomic_operation:")
                    || object_id.starts_with("atomic_ordering:")
                    || object_id.starts_with("static_site:")
                    || object_id.starts_with("release_endpoint:")
                    || object_id.starts_with("foreign_owner:")
                    || object_id.starts_with("user_data:");
                if !allowed {
                    return Err(at_loc(
                        located,
                        "BW-V326-FACT-OBJECT-ID",
                        format!(
                            "static_artifact object_ids 必须使用稳定角色前缀，拒绝: {object_id}"
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn reject_private_tokens_source_ref<T>(
    located: &Located<T>,
    code: &'static str,
    source_ref: &V326SourceRef,
) -> Result<(), ModelError> {
    reject_private_tokens_loc(located, code, "source_ref.path", &source_ref.path)?;
    if let Some(symbol_path) = &source_ref.symbol_path {
        reject_private_tokens_loc(located, code, "source_ref.symbol_path", symbol_path)?;
    }
    if let Some(text_sha256) = &source_ref.text_sha256 {
        reject_private_tokens_loc(located, code, "source_ref.text_sha256", text_sha256)?;
    }
    Ok(())
}

fn reject_private_tokens_loc<T>(
    located: &Located<T>,
    code: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_private(field, value).map_err(|message| at_loc(located, code, message))
}

fn validate_relative_path_loc<T>(
    located: &Located<T>,
    code: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(at_loc(
            located,
            code,
            "路径必须是相对路径，不能是绝对路径或包含 ..",
        ));
    }
    Ok(())
}

fn validate_required_text_evidence(
    located: &Located<V326LifecycleEvidenceRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at_evidence(
            located,
            "BW-V326-EVIDENCE-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_required_text_feature(
    located: &Located<V326LifecycleFeatureRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at_feature(
            located,
            "BW-V326-FEATURE-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_required_text_graph(
    located: &Located<V326LifecycleGraphRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at_graph(
            located,
            "BW-V326-GRAPH-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_required_text_ranked(
    located: &Located<V326RankedCandidateRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at_ranked(
            located,
            "BW-V326-RANK-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_public_string_list_ranked(
    located: &Located<V326RankedCandidateRecord>,
    field: &'static str,
    values: &[String],
) -> Result<(), ModelError> {
    for value in values {
        if value.trim().is_empty() {
            return Err(at_ranked(
                located,
                "BW-V326-RANK-PRIVATE-TOKEN",
                format!("{field} 不能包含空字符串"),
            ));
        }
        reject_private_tokens_ranked(located, field, value)?;
    }
    Ok(())
}

fn validate_ranked_chain_summary(
    located: &Located<V326RankedCandidateRecord>,
    summary: &V326RankedChainSummary,
) -> Result<(), ModelError> {
    match (&summary.top_chain_id, summary.top_chain_status) {
        (Some(chain_id), Some(_)) => {
            validate_required_text_ranked(located, "chain_summary.top_chain_id", chain_id)?;
            reject_private_tokens_ranked(located, "chain_summary.top_chain_id", chain_id)?;
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(at_ranked(
                located,
                "BW-V326-RANK-CHAIN-SUMMARY",
                "chain_summary.top_chain_id 与 top_chain_status 必须同时存在或同时为空",
            ));
        }
        (None, None) => {}
    }
    validate_public_string_list_ranked(
        located,
        "chain_summary.chain_fact_refs",
        &summary.chain_fact_refs,
    )?;
    validate_public_string_list_ranked(
        located,
        "chain_summary.chain_incomplete_reasons",
        &summary.chain_incomplete_reasons,
    )?;
    Ok(())
}

fn validate_required_text_pair(
    located: &Located<V326AnonymousPairRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at_pair(
            located,
            "BW-V326-PAIR-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_required_text_delta(
    located: &Located<V326PairDeltaRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at_delta(
            located,
            "BW-V326-DELTA-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_relative_path_ranked(
    located: &Located<V326RankedCandidateRecord>,
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
            "BW-V326-RANK-PATH",
            "lifecycle_graph_path 必须是相对路径，不能是绝对路径或包含 ..",
        ));
    }
    Ok(())
}

fn reject_private(field: &'static str, value: &str) -> Result<(), String> {
    let lower = value.to_ascii_lowercase();
    if let Some(token) = PUBLIC_FORBIDDEN_TOKENS
        .iter()
        .find(|token| lower.contains(*token))
    {
        return Err(format!(
            "{field} 包含 V3.2.6 public artifact 禁止公开携带的身份线索 token `{token}`"
        ));
    }
    Ok(())
}

fn reject_pair_role(field: &'static str, value: &str) -> Result<(), String> {
    let lower = value.to_ascii_lowercase();
    if let Some(token) = PUBLIC_FORBIDDEN_TOKENS
        .iter()
        .find(|token| lower.contains(*token))
    {
        return Err(format!(
            "{field} 包含匿名 pair 禁止的角色/答案 token `{token}`"
        ));
    }
    Ok(())
}

fn reject_private_tokens_json_evidence(
    located: &Located<V326LifecycleEvidenceRecord>,
    field: &'static str,
    value: &serde_json::Value,
) -> Result<(), ModelError> {
    match value {
        serde_json::Value::String(text) => reject_private_tokens_evidence(located, field, text),
        serde_json::Value::Array(items) => {
            for item in items {
                reject_private_tokens_json_evidence(located, field, item)?;
            }
            Ok(())
        }
        serde_json::Value::Object(entries) => {
            for (key, item) in entries {
                reject_private_tokens_evidence(located, field, key)?;
                reject_private_tokens_json_evidence(located, field, item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn reject_private_tokens_evidence(
    located: &Located<V326LifecycleEvidenceRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_private(field, value)
        .map_err(|message| at_evidence(located, "BW-V326-EVIDENCE-PRIVATE-TOKEN", message))
}

fn reject_private_tokens_feature(
    located: &Located<V326LifecycleFeatureRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_private(field, value)
        .map_err(|message| at_feature(located, "BW-V326-FEATURE-PRIVATE-TOKEN", message))
}

fn reject_private_tokens_graph(
    located: &Located<V326LifecycleGraphRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_private(field, value)
        .map_err(|message| at_graph(located, "BW-V326-GRAPH-PRIVATE-TOKEN", message))
}

fn reject_private_tokens_ranked(
    located: &Located<V326RankedCandidateRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_private(field, value)
        .map_err(|message| at_ranked(located, "BW-V326-RANK-PRIVATE-TOKEN", message))
}

fn reject_private_tokens_pair(
    located: &Located<V326AnonymousPairRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_private(field, value)
        .map_err(|message| at_pair(located, "BW-V326-PAIR-PRIVATE-TOKEN", message))
}

fn reject_pair_role_tokens(
    located: &Located<V326AnonymousPairRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_pair_role(field, value)
        .map_err(|message| at_pair(located, "BW-V326-PAIR-ROLE-TOKEN", message))
}

fn reject_private_tokens_delta(
    located: &Located<V326PairDeltaRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_private(field, value)
        .map_err(|message| at_delta(located, "BW-V326-DELTA-PRIVATE-TOKEN", message))
}

fn reject_pair_role_tokens_delta(
    located: &Located<V326PairDeltaRecord>,
    field: &'static str,
    value: &str,
) -> Result<(), ModelError> {
    reject_pair_role(field, value)
        .map_err(|message| at_delta(located, "BW-V326-DELTA-ROLE-TOKEN", message))
}

fn with_code(code: &'static str, message: impl Into<String>) -> String {
    format!("{code}: {}", message.into())
}

fn at_loc<T>(located: &Located<T>, code: &'static str, message: impl Into<String>) -> ModelError {
    ModelError::validation(code, with_code(code, message))
        .at_line(located.path.clone(), located.line)
}

fn at_evidence(
    located: &Located<V326LifecycleEvidenceRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, with_code(code, message))
        .at_line(located.path.clone(), located.line)
}

fn at_feature(
    located: &Located<V326LifecycleFeatureRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, with_code(code, message))
        .at_line(located.path.clone(), located.line)
}

fn at_graph(
    located: &Located<V326LifecycleGraphRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, with_code(code, message))
        .at_line(located.path.clone(), located.line)
}

fn at_ranked(
    located: &Located<V326RankedCandidateRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, with_code(code, message))
        .at_line(located.path.clone(), located.line)
}

fn at_pair(
    located: &Located<V326AnonymousPairRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, with_code(code, message))
        .at_line(located.path.clone(), located.line)
}

fn at_delta(
    located: &Located<V326PairDeltaRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, with_code(code, message))
        .at_line(located.path.clone(), located.line)
}
