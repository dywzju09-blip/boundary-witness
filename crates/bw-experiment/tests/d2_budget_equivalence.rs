use bw_experiment::{
    D2BaselineConfigFile, D2BaselineGroupKind, format_d2_config_field, verify_d2_budget_equivalence,
};

#[test]
fn repository_d2_config_has_equivalent_budgets_for_all_groups() {
    let config = repository_config();
    let digest = verify_d2_budget_equivalence(&config).unwrap();

    assert_eq!(
        config.groups,
        [
            D2BaselineGroupKind::RandomAction,
            D2BaselineGroupKind::CoverageOnly,
            D2BaselineGroupKind::CoverageState,
        ]
    );
    assert_eq!(digest.group_count, 3);
    assert_eq!(digest.seed_list, config.shared_budget.seed_list);
    assert_eq!(digest.cpu_minutes, config.shared_budget.cpu_minutes);
}

#[test]
fn cpu_budget_mismatch_is_rejected_before_running() {
    let mut config = repository_config();
    config.coverage_only.as_mut().unwrap().cpu_minutes += 1;

    let error = verify_d2_budget_equivalence(&config).unwrap_err();

    assert!(error.to_string().contains("cpu_minutes"));
}

#[test]
fn seed_mismatch_is_rejected_before_running() {
    let mut config = repository_config();
    config.coverage_state.as_mut().unwrap().seed = 42;

    let error = verify_d2_budget_equivalence(&config).unwrap_err();

    assert!(error.to_string().contains("seed"));
}

#[test]
fn seed_list_count_mismatch_is_rejected_before_running() {
    let mut config = repository_config();
    config.shared_budget.campaign_count = config.shared_budget.seed_list.len() as u64 + 1;

    let error = verify_d2_budget_equivalence(&config).unwrap_err();

    assert!(error.to_string().contains("seed_list"));
    assert!(error.to_string().contains("campaign_count"));
}

#[test]
fn shared_budget_digest_is_stable_and_label_free() {
    let config = repository_config();
    let left = verify_d2_budget_equivalence(&config).unwrap();
    let right = verify_d2_budget_equivalence(&config).unwrap();

    assert_eq!(left.config_digest, right.config_digest);
    assert_eq!(left.config_digest.len(), 64);
    let public = format!("{left:?}").to_lowercase();
    for banned in ["cve", "vulnerable", "fixed", "expected"] {
        assert!(
            !public.contains(banned),
            "budget digest leaked answer label {banned}: {public}"
        );
    }
}

#[test]
fn d2_config_field_output_supports_runner_required_fields() {
    let config = repository_config();

    assert_eq!(
        format_d2_config_field(&config, "coverage_state.target").unwrap(),
        "update_hook_state_feedback\n"
    );
    assert_eq!(
        format_d2_config_field(&config, "shared_budget.seed_list").unwrap(),
        "1784401001\n1784401002\n1784401003\n1784401004\n1784401005\n"
    );
}

fn repository_config() -> D2BaselineConfigFile {
    D2BaselineConfigFile::parse_toml(include_str!(
        "../../../experiments/configs/d2-baselines.toml"
    ))
    .unwrap()
}
