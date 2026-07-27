use std::path::PathBuf;

use bw_experiment::{CaseOperation, D0CaseMatrix};
use rusqlite_lab_shared::{
    artifact_staging::{
        d0_staging_plan, m12_staging_plan, CaseStagingInput, StageOptions, StagingLayout,
    },
    blind_runner::{parse_runner_config, plan_cases},
};

#[test]
fn m12_artifact_plan_matches_runner_config_without_label_leaks() {
    let repo = PathBuf::from("");
    let layout = StagingLayout::m12_default(&repo);
    let plan = m12_staging_plan(&layout);
    let config = parse_runner_config(include_str!(
        "../../../../../experiments/configs/rusqlite-m12-cases.toml"
    ))
    .expect("runner config should parse");
    let runner_cases = plan_cases(&config).expect("runner cases should materialize");

    assert_eq!(plan.cases.len(), 10);
    assert_eq!(runner_cases.len(), plan.cases.len());

    for (staged, runner) in plan.cases.iter().zip(runner_cases) {
        assert_eq!(staged.case_id, runner.case_id);
        assert_eq!(staged.public_static_facts, runner.static_facts);
        assert_eq!(staged.public_executable, runner.executable);

        let public = format!(
            "{} {} {}",
            staged.case_id,
            staged.public_static_facts.display(),
            staged.public_executable.display()
        )
        .to_lowercase();
        for banned in ["vulnerable", "fixed", "cve", "expected"] {
            assert!(
                !public.contains(banned),
                "public runner-facing artifact path leaked {banned}: {public}"
            );
        }
    }
}

#[test]
fn staging_plan_uses_isolated_per_case_build_and_analysis_paths() {
    let repo = PathBuf::from("/repo");
    let layout = StagingLayout::m12_default(&repo);
    let plan = m12_staging_plan(&layout);

    for staged in &plan.cases {
        assert!(staged
            .metadata_path
            .ends_with(format!("{}/metadata.json", staged.case_id)));
        assert!(staged.analysis_dir.ends_with(&staged.case_id));
        assert!(staged.target_dir.ends_with(&staged.case_id));
        assert_ne!(staged.analysis_dir, staged.target_dir);
        assert!(staged
            .source_manifest
            .starts_with("/repo/benchmarks/historical-cves/rusqlite"));
    }
}

#[test]
fn m12_artifact_inputs_cover_runtime_cases_but_not_compile_reject_cases() {
    let inputs = CaseStagingInput::m12_cases(PathBuf::from("/repo"));
    let app_crates = inputs
        .iter()
        .map(|case| case.app_crate.as_str())
        .collect::<Vec<_>>();

    assert_eq!(inputs.len(), 10);
    assert!(app_crates.contains(&"bw_rusqlite_update_0261_borrowed"));
    assert!(app_crates.contains(&"bw_rusqlite_scalar_0261_borrowed"));
    assert!(!app_crates
        .iter()
        .any(|crate_name| crate_name.contains("borrowed_reject")));
}

#[test]
fn d0_artifact_plan_matches_d0_case_matrix_including_compile_checks() {
    let repo = PathBuf::from("");
    let layout = StagingLayout::d0_default(&repo);
    let plan = d0_staging_plan(&layout);
    let matrix = D0CaseMatrix::parse_toml(include_str!(
        "../../../../../experiments/configs/d0-cases.toml"
    ))
    .expect("repository D0 matrix should parse");

    assert_eq!(plan.cases.len(), 10);
    assert_eq!(plan.compile_checks.len(), 2);
    assert_eq!(matrix.cases.len(), 12);

    for matrix_case in matrix.cases {
        match matrix_case.operation {
            CaseOperation::Run => {
                let staged = plan
                    .cases
                    .iter()
                    .find(|case| case.case_id == matrix_case.case_id)
                    .expect("run case should have a staged artifact");
                assert_eq!(
                    Some(staged.public_static_facts.clone()),
                    matrix_case.static_facts
                );
                assert_eq!(
                    Some(staged.public_executable.clone()),
                    matrix_case.executable
                );
            }
            CaseOperation::CompileCheck => {
                let staged = plan
                    .compile_checks
                    .iter()
                    .find(|case| case.case_id == matrix_case.case_id)
                    .expect("compile-check case should have staged source");
                assert_eq!(Some(staged.public_source_dir.clone()), matrix_case.source);
            }
        }
    }
}

#[test]
fn d0_artifact_paths_are_opaque_to_runner() {
    let repo = PathBuf::from("");
    let layout = StagingLayout::d0_default(&repo);
    let plan = d0_staging_plan(&layout);

    for public in plan
        .cases
        .iter()
        .flat_map(|case| [&case.public_static_facts, &case.public_executable])
        .chain(
            plan.compile_checks
                .iter()
                .map(|case| &case.public_source_dir),
        )
    {
        let public = public.display().to_string().to_lowercase();
        for banned in [
            "vulnerable",
            "fixed",
            "borrowed",
            "reject",
            "expected",
            "cve",
        ] {
            assert!(
                !public.contains(banned),
                "public D0 artifact path leaked {banned}: {public}"
            );
        }
    }
}

#[test]
fn staging_options_can_pin_the_cargo_toolchain() {
    let options = StageOptions {
        layout: StagingLayout::d0_default(&PathBuf::from("/repo")),
        bw_rustc: PathBuf::from("/repo/compiler/bw-rustc/target/debug/bw-rustc"),
        rustup_toolchain: Some("nightly-2026-07-08".to_owned()),
    };

    assert_eq!(
        options.rustup_toolchain.as_deref(),
        Some("nightly-2026-07-08")
    );
}
