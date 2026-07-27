use std::{fs, path::PathBuf};

use bw_experiment::{
    ApiKind, D1CampaignConfigFile, D1CampaignOutcome, D1CampaignRecord, summarize_d1_campaigns,
};

#[test]
fn campaign_config_loads_without_answer_labels() {
    let config = D1CampaignConfigFile::parse_toml(
        &fs::read_to_string(repo_root().join("experiments/configs/d1-campaigns.toml")).unwrap(),
    )
    .unwrap();

    assert_eq!(config.schema_version, "boundary-witness.d1-campaigns/0.1");
    assert!(
        config
            .campaigns
            .iter()
            .any(|campaign| campaign.api == ApiKind::UpdateHook)
    );
    assert!(
        config
            .campaigns
            .iter()
            .any(|campaign| campaign.target == "update_hook_safe_only")
    );

    for forbidden in ["cve", "vulnerable", "fixed", "expected"] {
        let bad = format!(
            r#"
schema_version = "boundary-witness.d1-campaigns/0.1"
suite_id = "d1-bad"

[[campaigns]]
campaign_id = "bad"
api = "update_hook"
target = "update_hook_actions"
cpu_minutes = 30
max_sequence_len = 32
initial_corpus = "experiments/corpus/d1/update-hook/safe-fragments.jsonl"
artifact_dir = "artifacts/d1"
objective_config = "experiments/configs/d1-objectives.toml"
sanitizer = "asan"
replay_repeat_count = 20
seed = 1
{forbidden} = true
"#
        );
        assert!(D1CampaignConfigFile::parse_toml(&bad).is_err());
    }
}

#[test]
fn summary_counts_timeout_in_denominator_and_keeps_objective_kinds_separate() {
    let summary = summarize_d1_campaigns(&[
        campaign(
            "campaign-001",
            D1CampaignOutcome::PrimaryFound,
            100,
            80,
            20,
            3,
            1,
            1,
            Some(12_000),
        ),
        campaign(
            "campaign-002",
            D1CampaignOutcome::Timeout,
            50,
            25,
            25,
            2,
            1,
            0,
            None,
        ),
        campaign(
            "campaign-003",
            D1CampaignOutcome::NoPrimary,
            10,
            10,
            0,
            0,
            0,
            0,
            None,
        ),
    ])
    .unwrap();

    assert_eq!(summary.total_campaigns, 3);
    assert_eq!(summary.primary_success_campaigns, 1);
    assert_eq!(summary.timeout_campaigns, 1);
    assert_eq!(summary.progress_campaigns, 2);
    assert_eq!(summary.secondary_campaigns, 2);
    assert_eq!(summary.total_executions, 160);
    assert_eq!(summary.valid_sequence_count, 115);
    assert_eq!(summary.invalid_sequence_count, 45);
    assert_eq!(summary.valid_sequence_ratio_ppm, 718_750);
    assert_eq!(summary.time_to_first_primary_ms, [12_000]);
    assert_eq!(summary.campaigns.len(), 3);
}

#[test]
fn summary_rejects_duplicate_campaign_ids() {
    let error = summarize_d1_campaigns(&[
        campaign(
            "campaign-001",
            D1CampaignOutcome::NoPrimary,
            1,
            1,
            0,
            0,
            0,
            0,
            None,
        ),
        campaign(
            "campaign-001",
            D1CampaignOutcome::NoPrimary,
            1,
            1,
            0,
            0,
            0,
            0,
            None,
        ),
    ])
    .unwrap_err()
    .to_string();

    assert!(error.contains("duplicate campaign_id"));
}

#[allow(clippy::too_many_arguments)]
fn campaign(
    campaign_id: &str,
    outcome: D1CampaignOutcome,
    executions: u64,
    valid_sequence_count: u64,
    invalid_sequence_count: u64,
    progress_count: u64,
    secondary_count: u64,
    primary_count: u64,
    time_to_first_primary_ms: Option<u64>,
) -> D1CampaignRecord {
    D1CampaignRecord {
        campaign_id: campaign_id.to_owned(),
        api: ApiKind::UpdateHook,
        target: "update_hook_actions".to_owned(),
        seed: 42,
        cpu_minutes: 30,
        executions,
        valid_sequence_count,
        invalid_sequence_count,
        progress_count,
        secondary_count,
        primary_count,
        time_to_first_primary_ms,
        minimized_len: Some(6),
        replay_success_count: Some(20),
        representative_artifact_digest: Some("a".repeat(64)),
        outcome,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
