//! BoundaryWitness 的版本化事实与证据模型。

mod adapter_effort;
mod boundary_index;
mod buildability;
mod candidate;
mod compatibility;
mod contract;
mod corpus;
mod error;
mod failure_taxonomy;
mod finding;
mod id;
mod jsonl;
mod lifecycle;
mod lifecycle_v326;
mod public_tokens;
mod run;
mod runtime_event;
mod scanner_freeze;
mod schema;
mod static_fact;
mod static_ranking_reveal;
mod validate;

pub use adapter_effort::{
    V3_2_ADAPTER_EFFORT_SCHEMA_V1, V32AdapterEffortRecord, V32AdapterEffortSummary, V32AdapterKind,
    V32EffortClass, adapter_effort_from_ranked, validate_v3_2_adapter_effort,
};
pub use boundary_index::{
    V3_2_BOUNDARY_INDEX_SCHEMA_V1, V32BoundaryEvidenceKind, V32BoundaryEvidenceRef,
    V32BoundaryIndexRecord, V32BoundaryIndexSummary, V32BoundaryKind, validate_v3_2_boundary_index,
};
pub use buildability::{
    V3_2_BUILDABILITY_SCHEMA_V1, V32BuildabilityRecord, V32BuildabilityStatus,
    V32BuildabilitySummary, validate_v3_2_buildability,
};
pub use candidate::{
    V3_2_CANDIDATE_SCHEMA_V1, V32CandidateConfidence, V32CandidateRecord, V32CandidateSummary,
    V32PatternFamily, V32RecommendedNextStep, candidate_from_boundary, validate_v3_2_candidates,
};
pub use compatibility::{
    CompatibilityVerdict, EvidenceGrade, ForeignBehaviorFact, ForeignClear, ForeignInvocation,
    ForeignPathCompatibility, ForeignRetention, HandOffId, LifetimeSubject, RustContractAssembly,
    RustContractFact, RustContractGap, StaticVerdict, WitnessObligation, WitnessStatus,
    assemble_rust_contract_facts, hand_off_is_incompatible, judge, judge_hand_off,
};
pub use contract::{
    CALLBACK_RETENTION_API_MAP_SCHEMA_V01, CallbackApiEntry, CallbackRetentionApiMap,
    CallbackRetentionApiMapEntry, CallbackRetentionContract, CallbackRetentionRegistry,
    ContractClause, ContractClauseKind, InvokeRole, OpaqueHandleApiRole,
    OpaqueHandleIdentityComponent, ReleaseBehavior, parse_plain_version, plain_version_at_most,
};
pub use corpus::{
    V3_2_CORPUS_MANIFEST_SCHEMA_V1, V32CorpusIntakeStatus, V32CorpusManifestRecord,
    V32CorpusManifestSummary, V32CorpusSelectionReason, V32CorpusSourceKind,
    validate_v3_2_corpus_manifest,
};
pub use error::ModelError;
pub use failure_taxonomy::{
    V3_2_FAILURE_TAXONOMY_SCHEMA_V1, V32FailureClass, V32FailureTaxonomyRecord,
    V32FailureTaxonomySummary, V32TaxonomyStage, V32TaxonomySubjectKind, build_failure_taxonomy,
    validate_v3_2_failure_taxonomy,
};
pub use finding::{
    EvidenceReference, EvidenceSourceKind, Finding, FindingClassification, FindingStateSnapshot,
};
pub use id::{BuildId, InstanceId, RecordId, RunId, SemanticSiteKey, SiteId, TraceId};
pub use jsonl::{JsonlReader, Located};
pub use lifecycle::{
    V3_2_LIFECYCLE_GRAPH_SCHEMA_V1, V3_2_RANKED_CANDIDATE_SCHEMA_V1, V32LifecycleEdge,
    V32LifecycleEdgeKind, V32LifecycleGraph, V32LifecycleNode, V32LifecycleNodeKind,
    V32LifecycleSummary, V32LifetimeRole, V32RankedCandidateRecord, V32RiskFeatures,
    V32ScoreBreakdown, lifecycle_graph_from_candidate, ranking_reason, score_lifecycle_graph,
    validate_v3_2_lifecycle_graphs, validate_v3_2_ranked_candidates,
};
pub use lifecycle_v326::{
    V3_2_6_ANONYMOUS_PAIR_SCHEMA_V1, V3_2_6_EXTERNAL_BUFFER_RETURN_LIFETIME_SIGNAL,
    V3_2_6_LIFECYCLE_CONTRACT_SCHEMA_V1, V3_2_6_LIFECYCLE_COVERAGE_SCHEMA_V1,
    V3_2_6_LIFECYCLE_EVIDENCE_SCHEMA_V1, V3_2_6_LIFECYCLE_FACT_SCHEMA_V1,
    V3_2_6_LIFECYCLE_FEATURE_SCHEMA_V1, V3_2_6_LIFECYCLE_GRAPH_SCHEMA_V1,
    V3_2_6_LIFECYCLE_GRAPH_V3_SCHEMA_V1, V3_2_6_PAIR_DELTA_SCHEMA_V1,
    V3_2_6_RANKED_CANDIDATE_SCHEMA_V1, V3_2_6_WITNESS_PLAN_SCHEMA_V1, V3_2_7_PAIR_DELTA_SCHEMA_V1,
    V326AnonymousPairRecord, V326AnonymousPairSummary, V326CallbackBoundVerdict,
    V326CallbackBoundVerdictSource, V326ContractRelease, V326ContractReplacement,
    V326ContractRetention, V326CoverageGap, V326CoverageGapReason, V326CoverageState,
    V326DerivedCallbackBound, V326Distinguishability, V326EvidenceConfidence, V326EvidenceKind,
    V326FeatureSet, V326ForeignOwnerSemantics, V326LifecycleContractRecord,
    V326LifecycleContractSummary, V326LifecycleCoverageRecord, V326LifecycleCoverageSummary,
    V326LifecycleEdge, V326LifecycleEdgeKind, V326LifecycleEvidenceRecord,
    V326LifecycleEvidenceSummary, V326LifecycleFactKind, V326LifecycleFactOrigin,
    V326LifecycleFactProvenance, V326LifecycleFactRecord, V326LifecycleFactSummary,
    V326LifecycleFeatureRecord, V326LifecycleFeatureSummary, V326LifecycleGraphRecord,
    V326LifecycleGraphV3Edge, V326LifecycleGraphV3Record, V326LifecycleGraphV3Summary,
    V326LifecycleNode, V326LifecycleNodeKind, V326LifecycleObject, V326LifecycleObjectKind,
    V326LifecycleOrdering, V326LifecycleRelation, V326ObjectChain, V326ObjectChainLayer,
    V326ObjectChainStatus, V326PairDeltaRecord, V326PairDeltaSummary, V326RankedCandidateRecord,
    V326RankedCandidateSummary, V326RankedChainSummary, V326ScoreBreakdown, V326SourceRef,
    V326WitnessAction, V326WitnessActionKind, V326WitnessApiCrate, V326WitnessCallbackBoundScope,
    V326WitnessObservedShape, V326WitnessPlanRecord, V326WitnessPlanSummary, V326WitnessRoute,
    V326WitnessTarget, active_feature_names, build_v3_2_6_lifecycle_graph,
    build_v3_2_6_lifecycle_graph_v3, compare_v3_2_6_pair, derive_v3_2_6_callback_bound_verdicts,
    derive_v3_2_6_lifecycle_features, derive_v3_2_6_lifecycle_features_with_context,
    lifecycle_fact_from_static_fact, rank_v3_2_6_features, summarize_v3_2_6_ranked_object_chains,
    validate_v3_2_6_anonymous_pairs, validate_v3_2_6_lifecycle_contracts,
    validate_v3_2_6_lifecycle_coverage, validate_v3_2_6_lifecycle_evidence,
    validate_v3_2_6_lifecycle_facts, validate_v3_2_6_lifecycle_features,
    validate_v3_2_6_lifecycle_graph_v3, validate_v3_2_6_lifecycle_graphs,
    validate_v3_2_6_pair_deltas, validate_v3_2_6_ranked_candidates, validate_v3_2_6_witness_plans,
    validate_v3_2_7_pair_deltas, verify_v3_2_6_lifecycle_fact_static_provenance,
};
pub use run::{ExecutionEvidence, ExecutionResult, PrimaryOutcome, RunManifest, ToolchainVersions};
pub use runtime_event::{
    CallbackInvokeEvent, CallbackRegisterEvent, CallbackReleaseReason, CallbackUnregisterEvent,
    CaptureBindEvent, CheckpointEvent, CheckpointKind, ObjectCreateEvent, ObjectDropEvent,
    ObjectFreeEvent, ObjectKind, ObjectUseEvent, ObjectUseKind, RuntimeEvent, RuntimeEventEnvelope,
    TraceEndEvent, TraceStartEvent,
};
pub use scanner_freeze::{
    V3_3_SCANNER_FREEZE_SCHEMA_V1, V33ScannerFreezeInputs, V33ScannerFreezeMethod,
    V33ScannerFreezeOutputs, V33ScannerFreezeRecord, V33ScannerFreezeSourceIdentityScan,
    V33ScannerFreezeToolchain, validate_v3_3_scanner_freeze,
};
pub use schema::{
    CONTRACT_SCHEMA_V01, FINDING_SCHEMA_V01, RUN_SCHEMA_V01, STATIC_SCHEMA_V01, STATIC_SCHEMA_V02,
    TRACE_SCHEMA_V01,
};
pub use static_fact::{
    AllocationOwnership, AllocationOwnershipFact, AtomicOperationKind, AtomicOrderingFact,
    AtomicOrderingKind, CallbackCaptureFact, CallbackLifetimeBoundFact, CallbackLifetimeBoundScope,
    CallbackReleaseUseOrderFact, CallbackReleaseUseOrdering, CallbackSiteFact,
    CallbackUserDataReconstructionFact, CallbackUserDataReconstructionKind, CaptureMode, DropKind,
    DropPreventionFact, DropPreventionKind, DropSiteFact, EffectiveCaptureAdmission,
    ExternalBufferBindingFact, ExternalCallRole, ExternalCallSiteFact, ObjectBindingGapFact,
    ObjectBindingGapKind, ObjectFlowFact, ObjectFlowKind, ObjectFlowObjectKind, ObjectSiteFact,
    PersistedReturnedBorrowFact, RawPointerTransferFact, RawPointerTransferKind, RegistrationGuard,
    RegistrationGuardFact, RegistrationRole, RegistrationSiteFact, ReleasePathProofFact,
    ReturnedBorrowInvalidationOrderFact, ReturnedBorrowInvalidationOrdering,
    ReturnedBorrowRelationFact, ReturnedBorrowRelationKind, SafeEntryLineage, SafeEntryLineageFact,
    StaticArtifactIdentity, StaticFact, StaticFactEnvelope, StaticSourceRef, UnresolvedReason,
};
pub use static_ranking_reveal::{
    RevealStaticRankingInput, V3_2_5_PRIVATE_GROUND_TRUTH_SCHEMA_V1,
    V3_2_5_STATIC_RANKING_REVEAL_SCHEMA_V1, V325ExpectedPatternFamily, V325MissClass,
    V325PrivateGroundTruthRecord, V325PrivateGroundTruthSummary, V325PrivateMatchDetail,
    V325RevealMetrics, V325SampleRole, V325StaticRankingRevealSummary, reveal_static_ranking,
    validate_v3_2_5_private_ground_truth, validate_v3_2_5_static_ranking_reveal,
};
pub use validate::{RuntimeValidationSummary, validate_runtime_path, validate_runtime_stream};
