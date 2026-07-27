use std::{collections::BTreeMap, path::PathBuf};

use bw_model::{
    CallbackRetentionContract, Finding, StaticFactEnvelope, V32AdapterEffortRecord,
    V32BoundaryIndexRecord, V32BuildabilityRecord, V32CandidateRecord, V32CorpusManifestRecord,
    V32FailureTaxonomyRecord, V32LifecycleGraph, V32RankedCandidateRecord, V33ScannerFreezeRecord,
    V325PrivateGroundTruthRecord, V325StaticRankingRevealSummary, V326AnonymousPairRecord,
    V326LifecycleContractRecord, V326LifecycleCoverageRecord, V326LifecycleEvidenceRecord,
    V326LifecycleFactRecord, V326LifecycleFeatureRecord, V326LifecycleGraphRecord,
    V326LifecycleGraphV3Record, V326PairDeltaRecord, V326RankedCandidateRecord,
    V326WitnessPlanRecord, validate_v3_2_5_private_ground_truth,
    validate_v3_2_5_static_ranking_reveal, validate_v3_2_6_anonymous_pairs,
    validate_v3_2_6_lifecycle_contracts, validate_v3_2_6_lifecycle_coverage,
    validate_v3_2_6_lifecycle_evidence, validate_v3_2_6_lifecycle_facts,
    validate_v3_2_6_lifecycle_features, validate_v3_2_6_lifecycle_graph_v3,
    validate_v3_2_6_lifecycle_graphs, validate_v3_2_6_pair_deltas,
    validate_v3_2_6_ranked_candidates, validate_v3_2_6_witness_plans, validate_v3_2_7_pair_deltas,
    validate_v3_2_adapter_effort, validate_v3_2_boundary_index, validate_v3_2_buildability,
    validate_v3_2_candidates, validate_v3_2_corpus_manifest, validate_v3_2_failure_taxonomy,
    validate_v3_2_lifecycle_graphs, validate_v3_2_ranked_candidates, validate_v3_3_scanner_freeze,
};
use bw_oracle::{StaticFactIndex, normalize_finding};
use clap::{Args, ValueEnum};
use serde::Serialize;

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl_values, read_to_string},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct ValidateArgs {
    #[arg(long, value_enum)]
    kind: ValidateKind,
    path: PathBuf,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ValidateKind {
    Static,
    Trace,
    Contract,
    Finding,
    #[value(name = "v3-2-corpus-manifest")]
    V32CorpusManifest,
    #[value(name = "v3-2-buildability")]
    V32Buildability,
    #[value(name = "v3-2-boundary-index")]
    V32BoundaryIndex,
    #[value(name = "v3-2-candidate")]
    V32Candidate,
    #[value(name = "v3-2-lifecycle-graph")]
    V32LifecycleGraph,
    #[value(name = "v3-2-ranked-candidate")]
    V32RankedCandidate,
    #[value(name = "v3-2-adapter-effort")]
    V32AdapterEffort,
    #[value(name = "v3-2-failure-taxonomy")]
    V32FailureTaxonomy,
    #[value(name = "v3-2-5-private-ground-truth")]
    V325PrivateGroundTruth,
    #[value(name = "v3-2-5-static-ranking-reveal")]
    V325StaticRankingReveal,
    #[value(name = "v3-2-6-lifecycle-evidence")]
    V326LifecycleEvidence,
    #[value(name = "v3-2-6-lifecycle-fact")]
    V326LifecycleFact,
    #[value(name = "v3-2-6-lifecycle-coverage")]
    V326LifecycleCoverage,
    #[value(name = "v3-2-6-lifecycle-contract")]
    V326LifecycleContract,
    #[value(name = "v3-2-6-lifecycle-graph")]
    V326LifecycleGraph,
    #[value(name = "v3-2-6-lifecycle-graph-v3")]
    V326LifecycleGraphV3,
    #[value(name = "v3-2-6-lifecycle-feature")]
    V326LifecycleFeature,
    #[value(name = "v3-2-6-ranked-candidate")]
    V326RankedCandidate,
    #[value(name = "v3-2-6-anonymous-pair")]
    V326AnonymousPair,
    #[value(name = "v3-2-6-pair-delta")]
    V326PairDelta,
    #[value(name = "v3-2-7-pair-delta")]
    V327PairDelta,
    #[value(name = "v3-2-6-witness-plan")]
    V326WitnessPlan,
    #[value(name = "v3-3-scanner-freeze")]
    V33ScannerFreeze,
}

#[derive(Serialize)]
struct ValidateOutput {
    kind: &'static str,
    record_count: u64,
    accepted_count: Option<u64>,
    excluded_count: Option<u64>,
    buildable_count: Option<u64>,
    failed_count: Option<u64>,
    trace_count: Option<u64>,
    object_count: Option<u64>,
    callback_count: Option<u64>,
    boundary_count: Option<u64>,
    negative_count: Option<u64>,
    needs_dynamic_validation_count: Option<u64>,
    static_only_count: Option<u64>,
    low_priority_count: Option<u64>,
    graph_count: Option<u64>,
    ranked_count: Option<u64>,
    max_score: Option<u32>,
    adapter_needed_count: Option<u64>,
    deferred_count: Option<u64>,
    total_manual_minutes: Option<u64>,
    infrastructure_failure_count: Option<u64>,
    build_failure_count: Option<u64>,
    no_boundary_count: Option<u64>,
    vulnerable_sample_count: Option<u64>,
    top5_hit_count: Option<u64>,
}

pub fn run(args: ValidateArgs) -> Result<CommandStatus, CliError> {
    let output = match args.kind {
        ValidateKind::Static => {
            let facts = read_jsonl_values::<StaticFactEnvelope>(&args.path, args.max_line_bytes)?;
            validate_static_facts_by_build(&facts)?;
            ValidateOutput {
                kind: "static",
                record_count: facts.len() as u64,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::Trace => {
            let summary = bw_model::validate_runtime_path(&args.path, args.max_line_bytes)?;
            ValidateOutput {
                kind: "trace",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: Some(summary.trace_count),
                object_count: Some(summary.object_count),
                callback_count: Some(summary.callback_count),
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::Contract => {
            CallbackRetentionContract::from_toml_str(&read_to_string(&args.path)?)?;
            ValidateOutput {
                kind: "contract",
                record_count: 1,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::Finding => {
            let findings = read_jsonl_values::<Finding>(&args.path, args.max_line_bytes)?;
            for finding in &findings {
                normalize_finding(finding)?;
            }
            ValidateOutput {
                kind: "finding",
                record_count: findings.len() as u64,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V32CorpusManifest => {
            let records = crate::commands::read_jsonl::<V32CorpusManifestRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_corpus_manifest(records)?;
            ValidateOutput {
                kind: "v3-2-corpus-manifest",
                record_count: summary.record_count,
                accepted_count: Some(summary.accepted_count),
                excluded_count: Some(summary.excluded_count),
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V32Buildability => {
            let records = crate::commands::read_jsonl::<V32BuildabilityRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_buildability(records)?;
            ValidateOutput {
                kind: "v3-2-buildability",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: Some(summary.buildable_count),
                failed_count: Some(summary.failed_count),
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V32BoundaryIndex => {
            let records = crate::commands::read_jsonl::<V32BoundaryIndexRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_boundary_index(records)?;
            ValidateOutput {
                kind: "v3-2-boundary-index",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: Some(summary.boundary_count),
                negative_count: Some(summary.negative_count),
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V32Candidate => {
            let records =
                crate::commands::read_jsonl::<V32CandidateRecord>(&args.path, args.max_line_bytes)?;
            let summary = validate_v3_2_candidates(records)?;
            ValidateOutput {
                kind: "v3-2-candidate",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: Some(summary.needs_dynamic_validation_count),
                static_only_count: Some(summary.static_only_count),
                low_priority_count: Some(summary.low_priority_count),
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V32LifecycleGraph => {
            let text = read_to_string(&args.path)?;
            let graph: V32LifecycleGraph = serde_json::from_str(&text).map_err(|error| {
                CliError::input("BW-JSON", format!("{}: {}", args.path.display(), error))
            })?;
            let graph_count = validate_v3_2_lifecycle_graphs([bw_model::Located {
                path: args.path.clone(),
                line: 1,
                value: graph,
            }])?;
            ValidateOutput {
                kind: "v3-2-lifecycle-graph",
                record_count: graph_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: Some(graph_count),
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V32RankedCandidate => {
            let records = crate::commands::read_jsonl::<V32RankedCandidateRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_ranked_candidates(records)?;
            ValidateOutput {
                kind: "v3-2-ranked-candidate",
                record_count: summary.ranked_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: Some(summary.graph_count),
                ranked_count: Some(summary.ranked_count),
                max_score: Some(summary.max_score),
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V32AdapterEffort => {
            let records = crate::commands::read_jsonl::<V32AdapterEffortRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_adapter_effort(records)?;
            ValidateOutput {
                kind: "v3-2-adapter-effort",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: Some(summary.adapter_needed_count),
                deferred_count: Some(summary.deferred_count),
                total_manual_minutes: Some(summary.total_manual_minutes),
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V32FailureTaxonomy => {
            let records = crate::commands::read_jsonl::<V32FailureTaxonomyRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_failure_taxonomy(records)?;
            ValidateOutput {
                kind: "v3-2-failure-taxonomy",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: Some(summary.deferred_count),
                total_manual_minutes: None,
                infrastructure_failure_count: Some(summary.infrastructure_failure_count),
                build_failure_count: Some(summary.build_failure_count),
                no_boundary_count: Some(summary.no_boundary_count),
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V325PrivateGroundTruth => {
            let records = crate::commands::read_jsonl::<V325PrivateGroundTruthRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_5_private_ground_truth(records)?;
            ValidateOutput {
                kind: "v3-2-5-private-ground-truth",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: Some(summary.vulnerable_count),
                top5_hit_count: None,
            }
        }
        ValidateKind::V325StaticRankingReveal => {
            let text = read_to_string(&args.path)?;
            let summary: V325StaticRankingRevealSummary =
                serde_json::from_str(&text).map_err(|error| {
                    CliError::input("BW-JSON", format!("{}: {}", args.path.display(), error))
                })?;
            validate_v3_2_5_static_ranking_reveal(&summary)?;
            ValidateOutput {
                kind: "v3-2-5-static-ranking-reveal",
                record_count: 1,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: Some(summary.metrics.vulnerable_sample_count),
                top5_hit_count: Some(summary.metrics.top5_hit_count),
            }
        }
        ValidateKind::V33ScannerFreeze => {
            let text = read_to_string(&args.path)?;
            let freeze: V33ScannerFreezeRecord = serde_json::from_str(&text).map_err(|error| {
                CliError::input("BW-JSON", format!("{}: {}", args.path.display(), error))
            })?;
            validate_v3_3_scanner_freeze(&freeze)?;
            ValidateOutput {
                kind: "v3-3-scanner-freeze",
                record_count: 1,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326LifecycleEvidence => {
            let records = crate::commands::read_jsonl::<V326LifecycleEvidenceRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_6_lifecycle_evidence(records)?;
            ValidateOutput {
                kind: "v3-2-6-lifecycle-evidence",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326LifecycleFact => {
            let records = crate::commands::read_jsonl::<V326LifecycleFactRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_6_lifecycle_facts(records)?;
            ValidateOutput {
                kind: "v3-2-6-lifecycle-fact",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326LifecycleCoverage => {
            let records = crate::commands::read_jsonl::<V326LifecycleCoverageRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_6_lifecycle_coverage(records)?;
            ValidateOutput {
                kind: "v3-2-6-lifecycle-coverage",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326LifecycleContract => {
            let records = crate::commands::read_jsonl::<V326LifecycleContractRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_6_lifecycle_contracts(records)?;
            ValidateOutput {
                kind: "v3-2-6-lifecycle-contract",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326LifecycleGraph => {
            let text = read_to_string(&args.path)?;
            let graph: V326LifecycleGraphRecord = serde_json::from_str(&text).map_err(|error| {
                CliError::input("BW-JSON", format!("{}: {}", args.path.display(), error))
            })?;
            let graph_count = validate_v3_2_6_lifecycle_graphs([bw_model::Located {
                path: args.path.clone(),
                line: 1,
                value: graph,
            }])?;
            ValidateOutput {
                kind: "v3-2-6-lifecycle-graph",
                record_count: graph_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: Some(graph_count),
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326LifecycleGraphV3 => {
            let text = read_to_string(&args.path)?;
            let graph: V326LifecycleGraphV3Record =
                serde_json::from_str(&text).map_err(|error| {
                    CliError::input("BW-JSON", format!("{}: {}", args.path.display(), error))
                })?;
            let summary = validate_v3_2_6_lifecycle_graph_v3([bw_model::Located {
                path: args.path.clone(),
                line: 1,
                value: graph,
            }])?;
            ValidateOutput {
                kind: "v3-2-6-lifecycle-graph-v3",
                record_count: summary.graph_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: Some(summary.graph_count),
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326LifecycleFeature => {
            let records = crate::commands::read_jsonl::<V326LifecycleFeatureRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_6_lifecycle_features(records)?;
            ValidateOutput {
                kind: "v3-2-6-lifecycle-feature",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326RankedCandidate => {
            let records = crate::commands::read_jsonl::<V326RankedCandidateRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_6_ranked_candidates(records)?;
            ValidateOutput {
                kind: "v3-2-6-ranked-candidate",
                record_count: summary.ranked_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: Some(summary.ranked_count),
                max_score: Some(summary.max_score),
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326AnonymousPair => {
            let records = crate::commands::read_jsonl::<V326AnonymousPairRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_6_anonymous_pairs(records)?;
            ValidateOutput {
                kind: "v3-2-6-anonymous-pair",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326PairDelta => {
            let records = crate::commands::read_jsonl::<V326PairDeltaRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_6_pair_deltas(records)?;
            ValidateOutput {
                kind: "v3-2-6-pair-delta",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V327PairDelta => {
            let records = crate::commands::read_jsonl::<V326PairDeltaRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_7_pair_deltas(records)?;
            ValidateOutput {
                kind: "v3-2-7-pair-delta",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
        ValidateKind::V326WitnessPlan => {
            let records = crate::commands::read_jsonl::<V326WitnessPlanRecord>(
                &args.path,
                args.max_line_bytes,
            )?;
            let summary = validate_v3_2_6_witness_plans(records)?;
            ValidateOutput {
                kind: "v3-2-6-witness-plan",
                record_count: summary.record_count,
                accepted_count: None,
                excluded_count: None,
                buildable_count: None,
                failed_count: None,
                trace_count: None,
                object_count: None,
                callback_count: None,
                boundary_count: None,
                negative_count: None,
                needs_dynamic_validation_count: None,
                static_only_count: None,
                low_priority_count: None,
                graph_count: None,
                ranked_count: None,
                max_score: None,
                adapter_needed_count: None,
                deferred_count: None,
                total_manual_minutes: None,
                infrastructure_failure_count: None,
                build_failure_count: None,
                no_boundary_count: None,
                vulnerable_sample_count: None,
                top5_hit_count: None,
            }
        }
    };
    crate::commands::write_json_stdout(&output)?;
    Ok(CommandStatus::Success)
}

fn validate_static_facts_by_build(facts: &[StaticFactEnvelope]) -> Result<(), CliError> {
    let mut facts_by_build = BTreeMap::<String, Vec<StaticFactEnvelope>>::new();
    for fact in facts {
        facts_by_build
            .entry(static_fact_validation_group_key(fact))
            .or_default()
            .push(fact.clone());
    }
    for facts in facts_by_build.into_values() {
        StaticFactIndex::from_envelopes(facts)?;
    }
    Ok(())
}

fn static_fact_validation_group_key(fact: &StaticFactEnvelope) -> String {
    let Some(artifact) = &fact.artifact else {
        return fact.build_id.to_string();
    };
    [
        fact.build_id.to_string(),
        artifact.crate_id.clone(),
        artifact.package_name.clone(),
        artifact.package_version.clone(),
        artifact.target.clone(),
    ]
    .join("\u{1f}")
}
