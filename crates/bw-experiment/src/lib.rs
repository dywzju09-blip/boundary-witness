//! 可审计实验运行目录、manifest 与完整性校验。

pub mod asan;
pub mod case_matrix;
pub mod checksum;
pub mod child;
pub mod d0_runner;
pub mod fuzz;
pub mod layout;
pub mod manifest;
pub mod outcome;
pub mod summary;

use std::{io, path::PathBuf};

pub use asan::{SanitizerKind, SanitizerReport, StackFrame, parse_asan_log};
pub use bw_model::{ExecutionEvidence, ExecutionResult, PrimaryOutcome, ToolchainVersions};
pub use case_matrix::{
    CallbackApi, CaseExpectation, CaseOperation, CaseScenario, D0Case, D0CaseMatrix, D0GroundTruth,
    GroundTruthCase, validate_d0_matrix_against_ground_truth,
};
pub use checksum::verify_run_integrity;
pub use child::{ChildRunResult, ChildRunner, ChildSpec, ChildStatus};
pub use d0_runner::{
    D0CompileCheckRecord, D0ReplayAnalysis, D0RunMode, D0RunOptions, D0RunReport, D0WorkItem,
    D0WorkKind, D0WorkPlan, analyze_d0_replay, plan_d0_work, run_d0,
};
pub use fuzz::{
    ActionDecodeOptions, ActionDecoderMetadata, ActionSequence, ApiKind, CorpusAudit, CorpusPolicy,
    CoverageBaselineConfig, CoverageBaselineRunner, CoverageBaselineSummary, D1_ACTION_SCHEMA_V01,
    D1_ARTIFACT_SCHEMA_V01, D1_CAMPAIGNS_SCHEMA_V01, D1_MAX_ACTIONS, D1_ROLLUP_SCHEMA_V01,
    D1_SUMMARY_SCHEMA_V01, D1ArtifactRecord, D1CampaignConfig, D1CampaignConfigFile,
    D1CampaignOutcome, D1CampaignRecord, D1CampaignSummary, D1Distribution, D1RollupSummary,
    D1RunRollup, D2_BASELINES_SCHEMA_V01, D2_RANDOM_SUMMARY_SCHEMA_V01, D2BaselineConfigFile,
    D2BaselineGroupKind, D2ComparisonConfigDigest, D2ComparisonSummary, D2GroupCampaignRecords,
    D2GroupComparisonResult, D2SharedBudget, FuzzAction, MinimizationReport, MinimizationTarget,
    MinimizedArtifact, ObjectiveClassification, ObjectiveClassifier, ObjectiveKind,
    ObjectiveObservation, ObjectivePolicy, RandomActionGenerator, RandomBaselineConfig,
    RandomBaselineKind, RandomBaselineObservation, RandomBaselineRunner, RandomBaselineSummary,
    ReplayAttempt, ReplayConfig, ReplaySummary, SeedProvenance, SqlOp, StateFeedbackConfig,
    WitnessStages, comparison_summary, comparison_summary_from_group_records,
    comparison_summary_from_record_root, coverage_only_saves_primary_artifact,
    format_d2_config_field, minimize_actions, render_d2_summary_markdown, replay_minimized,
    summarize_d1_campaigns, summarize_d1_run_dirs, verify_d2_budget_equivalence,
};
pub use layout::{FinalizeRun, FinalizedRun, RunDirectory};
pub use manifest::{RunMetadata, generate_run_id};
pub use outcome::{OutcomeFacts, classify_outcome};
pub use summary::{
    EvidenceCounts, ExperimentSummary, OutcomeBucket, ReplayRecord, summarize_replays,
};

pub type Result<T> = std::result::Result<T, ExperimentError>;

#[derive(Debug, thiserror::Error)]
pub enum ExperimentError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("missing required {kind} file: {path}")]
    MissingRequiredFile { kind: &'static str, path: PathBuf },
    #[error("missing checksummed file: {path}")]
    MissingChecksummedFile { path: String },
    #[error("checksum mismatch for {path}: actual={actual} expected={expected}")]
    ChecksumMismatch {
        path: String,
        actual: String,
        expected: String,
    },
    #[error("unchecksummed file exists: {path}")]
    UnchecksummedFile { path: String },
    #[error("unsafe path: {path}")]
    UnsafePath { path: String },
    #[error("unsupported file type: {path}")]
    UnsupportedFileType { path: PathBuf },
    #[error("symlink is not allowed in run directory: {path}")]
    Symlink { path: PathBuf },
    #[error("I/O error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl ExperimentError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
