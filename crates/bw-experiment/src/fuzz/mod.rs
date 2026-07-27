//! D1 结构化 fuzz 的公共 action schema 与 corpus 策略。

mod actions;
mod artifact;
mod campaign;
mod corpus;
mod coverage_baseline;
mod d2_compare;
mod minimize;
mod objective;
mod random_baseline;
mod replay;
mod rollup;
mod state_feedback;

pub use actions::{
    ActionDecodeOptions, ActionDecoderMetadata, ActionSequence, ApiKind, D1_ACTION_SCHEMA_V01,
    D1_MAX_ACTIONS, FuzzAction, SeedProvenance, SqlOp,
};
pub use artifact::{D1_ARTIFACT_SCHEMA_V01, D1ArtifactRecord};
pub use campaign::{
    D1_CAMPAIGNS_SCHEMA_V01, D1_SUMMARY_SCHEMA_V01, D1CampaignConfig, D1CampaignConfigFile,
    D1CampaignOutcome, D1CampaignRecord, D1CampaignSummary, summarize_d1_campaigns,
};
pub use corpus::{CorpusAudit, CorpusPolicy};
pub use coverage_baseline::{
    CoverageBaselineConfig, CoverageBaselineRunner, CoverageBaselineSummary,
    coverage_only_saves_primary_artifact,
};
pub use d2_compare::{
    D2BaselineGroupKind, D2ComparisonConfigDigest, D2ComparisonSummary, D2GroupCampaignRecords,
    D2GroupComparisonResult, D2SharedBudget, comparison_summary,
    comparison_summary_from_group_records, comparison_summary_from_record_root,
    format_d2_config_field, render_d2_summary_markdown, verify_d2_budget_equivalence,
};
pub use minimize::{
    MinimizationReport, MinimizationTarget, MinimizedArtifact, WitnessStages, minimize_actions,
};
pub use objective::{
    ObjectiveClassification, ObjectiveClassifier, ObjectiveKind, ObjectiveObservation,
    ObjectivePolicy,
};
pub use random_baseline::{
    D2_BASELINES_SCHEMA_V01, D2_RANDOM_SUMMARY_SCHEMA_V01, D2BaselineConfigFile,
    RandomActionGenerator, RandomBaselineConfig, RandomBaselineKind, RandomBaselineObservation,
    RandomBaselineRunner, RandomBaselineSummary,
};
pub use replay::{ReplayAttempt, ReplayConfig, ReplaySummary, replay_minimized};
pub use rollup::{
    D1_ROLLUP_SCHEMA_V01, D1Distribution, D1RollupSummary, D1RunRollup, summarize_d1_run_dirs,
};
pub use state_feedback::StateFeedbackConfig;
