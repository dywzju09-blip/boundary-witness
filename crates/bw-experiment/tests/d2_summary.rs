use bw_experiment::{
    ApiKind, D1CampaignOutcome, D1CampaignRecord, D2BaselineConfigFile, D2BaselineGroupKind,
    D2GroupCampaignRecords, comparison_summary, comparison_summary_from_group_records,
    comparison_summary_from_record_root, render_d2_summary_markdown,
};

#[test]
fn d2_summary_markdown_lists_groups_without_significance_claims() {
    let config = D2BaselineConfigFile::parse_toml(include_str!(
        "../../../experiments/configs/d2-baselines.toml"
    ))
    .unwrap();
    let summary = comparison_summary(&config).unwrap();
    let markdown = render_d2_summary_markdown(&summary);

    assert!(markdown.contains("random_action"));
    assert!(markdown.contains("coverage_only"));
    assert!(markdown.contains("coverage_state"));
    assert!(markdown.contains("不声明统计显著优势"));
    assert!(!markdown.contains("显著优于"));
}

#[test]
fn d2_summary_roundtrips_from_comparison_json() {
    let config = D2BaselineConfigFile::parse_toml(include_str!(
        "../../../experiments/configs/d2-baselines.toml"
    ))
    .unwrap();
    let summary = comparison_summary(&config).unwrap();
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: bw_experiment::D2ComparisonSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(
        parsed.groups,
        vec![
            D2BaselineGroupKind::RandomAction,
            D2BaselineGroupKind::CoverageOnly,
            D2BaselineGroupKind::CoverageState,
        ]
    );
    assert_eq!(parsed.config_digest, summary.config_digest);
}

#[test]
fn d2_summary_contains_comparable_group_result_fields() {
    let config = D2BaselineConfigFile::parse_toml(include_str!(
        "../../../experiments/configs/d2-baselines.toml"
    ))
    .unwrap();
    let summary = comparison_summary(&config).unwrap();

    assert_eq!(summary.group_results.len(), 3);
    for result in &summary.group_results {
        assert_eq!(result.campaign_count, config.shared_budget.campaign_count);
        assert_eq!(result.cpu_minutes, config.shared_budget.cpu_minutes);
        assert_eq!(result.seed_list, config.shared_budget.seed_list);
        assert_eq!(result.status, "configured");
        assert_eq!(result.primary_success_count, 0);
        assert_eq!(result.secondary_finding_count, 0);
        assert_eq!(result.progress_state_coverage, 0);
        assert!(result.time_to_first_primary_ms.is_none());
        assert!(result.valid_sequence_ratio.is_none());
        assert!(result.minimized_sequence_len.is_none());
        assert!(result.replay_success_count.is_none());
    }

    let markdown = render_d2_summary_markdown(&summary);
    for required in [
        "primary_success_count",
        "time_to_first_primary_ms",
        "valid_sequence_ratio",
        "minimized_sequence_len",
        "progress_state_coverage",
    ] {
        assert!(
            markdown.contains(required),
            "markdown should expose comparable field {required}"
        );
    }
}

#[test]
fn d2_summary_aggregates_three_completed_group_record_sets() {
    let mut config = D2BaselineConfigFile::parse_toml(include_str!(
        "../../../experiments/configs/d2-baselines.toml"
    ))
    .unwrap();
    config.shared_budget.campaign_count = 2;
    config.shared_budget.seed_list = vec![1784401001, 1784401002];

    let summary = comparison_summary_from_group_records(
        &config,
        &[
            group_records(D2BaselineGroupKind::RandomAction, "update_hook_actions", 2),
            group_records(
                D2BaselineGroupKind::CoverageOnly,
                "update_hook_coverage_only",
                1,
            ),
            group_records(
                D2BaselineGroupKind::CoverageState,
                "update_hook_state_feedback",
                5,
            ),
        ],
    )
    .unwrap();

    assert_eq!(summary.group_results.len(), 3);
    let state = summary
        .group_results
        .iter()
        .find(|result| result.group == D2BaselineGroupKind::CoverageState)
        .unwrap();
    assert_eq!(state.status, "completed");
    assert_eq!(state.campaign_count, 2);
    assert_eq!(state.primary_success_count, 1);
    assert_eq!(state.time_to_first_primary_ms, Some(9));
    assert_eq!(state.valid_sequence_ratio, Some(0.75));
    assert_eq!(state.minimized_sequence_len, Some(4));
    assert_eq!(state.replay_success_count, Some(20));
    assert_eq!(state.progress_state_coverage, 5);
    assert_eq!(state.secondary_finding_count, 2);
}

#[test]
fn d2_summary_loads_group_record_jsonl_root() {
    let mut config = D2BaselineConfigFile::parse_toml(include_str!(
        "../../../experiments/configs/d2-baselines.toml"
    ))
    .unwrap();
    config.shared_budget.campaign_count = 2;
    config.shared_budget.seed_list = vec![1784401001, 1784401002];
    let temp = tempfile::tempdir().unwrap();

    for (group, target) in [
        (D2BaselineGroupKind::RandomAction, "update_hook_actions"),
        (
            D2BaselineGroupKind::CoverageOnly,
            "update_hook_coverage_only",
        ),
        (
            D2BaselineGroupKind::CoverageState,
            "update_hook_state_feedback",
        ),
    ] {
        let dir = temp.path().join(group_dir(group));
        std::fs::create_dir_all(&dir).unwrap();
        let records = group_records(group, target, 3);
        let body = records
            .records
            .iter()
            .map(|record| serde_json::to_string(record).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(dir.join("campaign-records.jsonl"), format!("{body}\n")).unwrap();
    }

    let summary = comparison_summary_from_record_root(&config, temp.path()).unwrap();

    assert!(
        summary
            .group_results
            .iter()
            .all(|result| result.status == "completed")
    );
}

fn group_records(
    group: D2BaselineGroupKind,
    target: &str,
    progress_state_coverage: u64,
) -> D2GroupCampaignRecords {
    D2GroupCampaignRecords {
        group,
        progress_state_coverage,
        records: vec![
            record(
                "campaign-1",
                target,
                1784401001,
                D1CampaignOutcome::PrimaryFound,
            ),
            record(
                "campaign-2",
                target,
                1784401002,
                D1CampaignOutcome::NoPrimary,
            ),
        ],
    }
}

fn record(
    campaign_id: &str,
    target: &str,
    seed: u64,
    outcome: D1CampaignOutcome,
) -> D1CampaignRecord {
    let primary = u64::from(outcome == D1CampaignOutcome::PrimaryFound);
    D1CampaignRecord {
        campaign_id: campaign_id.to_owned(),
        api: ApiKind::UpdateHook,
        target: target.to_owned(),
        seed,
        cpu_minutes: 10,
        executions: 4,
        valid_sequence_count: 3,
        invalid_sequence_count: 1,
        progress_count: 1,
        secondary_count: 1,
        primary_count: primary,
        time_to_first_primary_ms: (primary == 1).then_some(9),
        minimized_len: (primary == 1).then_some(4),
        replay_success_count: (primary == 1).then_some(20),
        representative_artifact_digest: (primary == 1).then(|| "a".repeat(64)),
        outcome,
    }
}

fn group_dir(group: D2BaselineGroupKind) -> &'static str {
    match group {
        D2BaselineGroupKind::RandomAction => "random_action",
        D2BaselineGroupKind::CoverageOnly => "coverage_only",
        D2BaselineGroupKind::CoverageState => "coverage_state",
    }
}
