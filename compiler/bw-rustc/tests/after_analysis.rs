use std::{fs, process::Command};

#[test]
fn allowlisted_crate_records_after_analysis_start() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let src = temp.path().join("main.rs");
    let out_dir = temp.path().join("out");
    let analysis_dir = temp.path().join("analysis");
    fs::create_dir(&out_dir).expect("out dir should be created");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    fs::write(&src, "fn main() {}\n").expect("source should be written");
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                { "crate_name": "allowed_case", "target": "bin" }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let status = Command::new(env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .arg(rustc)
        .args([
            "--crate-name",
            "allowed_case",
            "--crate-type",
            "bin",
            "--edition",
            "2024",
        ])
        .arg(&src)
        .arg("--out-dir")
        .arg(&out_dir)
        .status()
        .expect("wrapper should run");
    assert!(status.success(), "wrapper exit status was {status}");

    let started = fs::read_to_string(analysis_dir.join("analysis-started.json"))
        .expect("analysis-started.json should be written");
    let started: serde_json::Value =
        serde_json::from_str(&started).expect("analysis-started should be json");
    assert_eq!(started["crate_name"], "allowed_case");
    assert_eq!(started["target"], "bin");
}
