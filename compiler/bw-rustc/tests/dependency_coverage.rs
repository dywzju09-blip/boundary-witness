use std::{collections::BTreeSet, fs, process::Command};

use bw_model::StaticFactEnvelope;

#[test]
fn application_and_path_dependency_are_reported_in_mir_coverage() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/dependency-coverage/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");

    let metadata = Command::new("cargo")
        .args([
            "metadata",
            "--format-version=1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(&fixture)
        .output()
        .expect("cargo metadata should run");
    assert!(
        metadata.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata_path = temp.path().join("metadata.json");
    fs::write(&metadata_path, metadata.stdout).expect("metadata should be written");

    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "metadata_path": metadata_path,
            "allowlist": [
                {
                    "crate_name": "coverage_app",
                    "package_name": "coverage-app",
                    "version": "0.1.0",
                    "target": "lib"
                },
                {
                    "crate_name": "coverage_dep",
                    "package_name": "coverage-dep",
                    "version": "0.1.0",
                    "target": "lib"
                }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .arg("-p")
        .arg("coverage-app")
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let coverage: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(analysis_dir.join("mir-coverage.json"))
            .expect("mir-coverage.json should be written"),
    )
    .expect("coverage should parse as json");

    assert_json_array_contains(
        &coverage["seen_packages"],
        serde_json::json!({"name": "coverage-app", "version": "0.1.0"}),
    );
    assert_json_array_contains(
        &coverage["seen_packages"],
        serde_json::json!({"name": "coverage-dep", "version": "0.1.0"}),
    );
    assert_json_array_contains(
        &coverage["seen_bodies"],
        serde_json::json!({
            "package": "coverage-app",
            "version": "0.1.0",
            "target": "lib",
            "def_path": "app_marker"
        }),
    );
    assert_json_array_contains(
        &coverage["seen_bodies"],
        serde_json::json!({
            "package": "coverage-dep",
            "version": "0.1.0",
            "target": "lib",
            "def_path": "dep_marker"
        }),
    );

    let packages = fs::read_to_string(analysis_dir.join("static-facts.jsonl"))
        .expect("static facts should be written")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<StaticFactEnvelope>(line).expect("fact should parse"))
        .filter_map(|fact| fact.artifact.map(|artifact| artifact.package_name))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        packages,
        BTreeSet::from(["coverage-app".to_owned(), "coverage-dep".to_owned()]),
        "aggregate static facts must retain every allowlisted crate"
    );

    let static_manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(analysis_dir.join("static-facts.manifest.json"))
            .expect("static fact shard manifest should be written"),
    )
    .expect("static fact shard manifest should parse");
    let shard_packages = static_manifest["shards"]
        .as_array()
        .expect("static fact shard manifest must contain shards")
        .iter()
        .filter_map(|shard| shard["artifact"]["package_name"].as_str())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        shard_packages,
        BTreeSet::from(["coverage-app".to_owned(), "coverage-dep".to_owned()]),
        "each allowlisted crate must retain an independent static fact shard"
    );
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn assert_json_array_contains(array: &serde_json::Value, expected: serde_json::Value) {
    let values = array.as_array().expect("value should be an array");
    assert!(
        values.iter().any(|value| value == &expected),
        "expected {expected} in {values:?}"
    );
}
